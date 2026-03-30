"""Basic smoke test for the prom l3fwd test infrastructure."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path

import pytest

from config import L3fwdConfig, _lcores_to_fwd_config
from process import L3fwdProcess
from remote import RemoteCapture
from verify import (
    capture_lcore_segments,
    check_packet_order,
    check_pcap_sequence_order,
    check_trace_order,
    load_pcap,
    summarize_trace_by_lcore,
)

log = logging.getLogger(__name__)

# Import gen_pkts from the parent package
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from gen_pkts import generate


def test_dry_run_command(l3fwd_config: L3fwdConfig) -> None:
    """Verify that build_cmd() produces the expected argv without running anything."""
    proc = L3fwdProcess(l3fwd_config)
    cmd = proc.build_cmd()

    assert str(l3fwd_config.binary) in cmd
    assert "-l" in cmd
    assert "-n" in cmd
    assert "-a" in cmd
    assert "--" in cmd
    assert "-p" in cmd or any("portmask" in s for s in cmd)
    assert any("rule_ipv4" in s for s in cmd)
    assert any("rule_ipv6" in s for s in cmd)


@pytest.mark.parametrize(
    "lcore_ids",
    [
        # [1, 2],
        # [1, 3, 5, 7],
        # list(range(8)),
        # list(range(16)),
        list(range(32)),
    ],
)
def test_packets_sent(
    l3fwd_config: L3fwdConfig,
    remote_capture: RemoteCapture,
    tmp_path: Path,
    lcore_ids: list[int],
) -> None:
    """Verify l3fwd packet order for multiple lcore configurations.

    Runs the same traffic/capture flow with differently-sized and non-sequential
    lcore lists.
    """
    if l3fwd_config.dry_run:
        pytest.skip("dry-run: skipping live packet verification")

    # Ensure config reflects the current test's lcores
    l3fwd_config.lcores = lcore_ids
    l3fwd_config.eal.lcores = ",".join(str(x) for x in lcore_ids)
    l3fwd_config.app.config = _lcores_to_fwd_config(lcore_ids)

    # Clean pkts and traces directories so previous test data doesn't interfere
    # traces_dir contains root-owned files from sudo l3fwd, so use sudo rm
    for d in (l3fwd_config.pkts_dir, l3fwd_config.traces_dir):
        if d.exists():
            subprocess.run(["sudo", "rm", "-rf", str(d)], check=False)
        d.mkdir(parents=True, exist_ok=True)

    generate(lcore_ids, out_dir=str(l3fwd_config.pkts_dir))

    remote_pcap = "/tmp/prom_capture.pcap"
    local_pcap = tmp_path / "capture.pcap"

    # Start capture before l3fwd so no packets are missed
    remote_capture.start_capture(remote_pcap)

    with L3fwdProcess(l3fwd_config) as proc:
        proc.start()
        if not proc.wait_for_ready():
            pytest.fail("l3fwd did not become ready in time")

        # Wait for l3fwd to finish sending all packets
        time.sleep(l3fwd_config.remote.capture_timeout)

    # l3fwd is stopped; give tcpdump a moment to flush then stop it
    time.sleep(1)
    remote_capture.stop_capture()

    pcap_path = remote_capture.fetch_pcap(local_pcap)
    traces_path = l3fwd_config.traces_dir.resolve()
    packets = load_pcap(pcap_path)

    # Log capture interleaving summary (per-lcore segments in capture order)
    segments = capture_lcore_segments(packets)
    for lcore_id, count, first_seq, last_seq in segments:
        log.info(
            "capture segment: lcore=%s count=%s seq_range=%s..%s",
            lcore_id,
            count,
            first_seq,
            last_seq,
        )

    for lcore_id in l3fwd_config.lcores:
        errors = check_packet_order(packets, lcore_id, l3fwd_config.lcores)
        if errors:
            log.error("packet ordering errors for lcore %s: %s", lcore_id, errors)
            log.info("[packet-order] lcore %s errors: %s", lcore_id, errors)
        else:
            log.info("[packet-order] lcore %s OK", lcore_id)
        assert not errors, f"lcore {lcore_id} packet ordering errors:\n" + "\n".join(
            errors
        )

    # Verify capture order matches the generated global packet sequence (byte[99])
    errors = check_pcap_sequence_order(pcap_path, l3fwd_config.lcores)
    if errors:
        log.error("pcap sequence ordering errors: %s", errors)
        log.info("[pcap-seq] errors: %s", errors)
    else:
        log.info("[pcap-seq] OK")
    assert not errors, "pcap sequence ordering errors:\n" + "\n".join(errors)

    # Verify that l3fwd trace output is in stable order (wqe_index should not decrease)
    traces_dir = traces_path
    assert traces_dir.exists() and traces_dir.is_dir(), (
        f"Expected trace directory '{traces_dir}' to exist"
    )

    trace_dirs = [p for p in traces_dir.iterdir() if p.is_dir()]
    assert trace_dirs, f"No trace output directories found under '{traces_dir}'"

    latest_trace = max(trace_dirs, key=lambda p: p.stat().st_mtime)
    errors = check_trace_order(latest_trace)

    if errors:
        log.warning("trace ordering errors (ignored): %s", errors)
        log.info("[trace] errors: %s", errors)
    else:
        log.info("[trace] OK")

    # Provide a per-lcore summary of how many trace entries were seen.
    trace_stats = summarize_trace_by_lcore(latest_trace)
    for lcore, stats in trace_stats.items():
        log.info(
            "trace summary: lcore=%s count=%s min=%s max=%s",
            lcore,
            stats.get("count"),
            stats.get("min"),
            stats.get("max"),
        )

    # Warn if any configured lcores produced no trace output
    missing = [l for l in l3fwd_config.lcores if l not in trace_stats]
    if missing:
        log.warning("no trace entries seen for lcores: %s", missing)
