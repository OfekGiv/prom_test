"""Basic smoke test for the prom l3fwd test infrastructure."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from config import L3fwdConfig
from process import L3fwdProcess
from remote import RemoteCapture
from verify import check_packet_order, load_pcap

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


def test_packets_sent(l3fwd_config: L3fwdConfig, remote_capture: RemoteCapture, tmp_path: Path) -> None:
    """
    1. Generate packet .bin files
    2. Start remote capture
    3. Start l3fwd — it sends all packets then idles
    4. Stop capture, fetch pcap
    5. Verify packet count, order and content per lcore
    """
    if l3fwd_config.dry_run:
        pytest.skip("dry-run: skipping live packet verification")

    generate(l3fwd_config.lcores, out_dir=str(l3fwd_config.pkts_dir))

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

    # l3fwd is stopped; give tshark a moment to flush then stop it
    time.sleep(1)
    remote_capture.stop_capture()

    pcap_path = remote_capture.fetch_pcap(local_pcap)
    packets = load_pcap(pcap_path)

    for lcore_id in l3fwd_config.lcores:
        errors = check_packet_order(packets, lcore_id)
        assert not errors, (
            f"lcore {lcore_id} packet ordering errors:\n" + "\n".join(errors)
        )
