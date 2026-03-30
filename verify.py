"""Packet verification helpers — no external dependencies (no Scapy)."""

from __future__ import annotations

import re
import struct
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# pcap parsing
# ---------------------------------------------------------------------------
# Global header: magic(4) ver_major(2) ver_minor(2) thiszone(4)
#                sigfigs(4) snaplen(4) network(4)  → 24 bytes
# Per-record:   ts_sec(4) ts_usec(4) incl_len(4) orig_len(4) → 16 bytes
# ---------------------------------------------------------------------------

_PCAP_MAGIC_LE = 0xA1B2C3D4
_PCAP_MAGIC_BE = 0xD4C3B2A1
_GLOBAL_HDR_LEN = 24
_REC_HDR_LEN = 16


def load_pcap(path: Path) -> list[bytes]:
    """
    Parse a pcap file and return a list of raw packet byte strings.
    Supports little-endian and big-endian pcap files.
    """
    data = Path(path).read_bytes()
    if len(data) < _GLOBAL_HDR_LEN:
        raise ValueError(f"File too short to be a pcap: {path}")

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == _PCAP_MAGIC_LE:
        endian = "<"
    elif magic == _PCAP_MAGIC_BE:
        endian = ">"
    else:
        raise ValueError(f"Unknown pcap magic: {magic:#010x}")

    packets: list[bytes] = []
    offset = _GLOBAL_HDR_LEN
    while offset + _REC_HDR_LEN <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(
            f"{endian}IIII", data, offset
        )
        offset += _REC_HDR_LEN
        if offset + incl_len > len(data):
            break
        packets.append(data[offset : offset + incl_len])
        offset += incl_len

    return packets


def capture_lcore_segments(packets: list[bytes]) -> list[tuple[int, int, int, int]]:
    """Summarize the capture order by contiguous lcore segments.

    Returns a list of tuples:
        (lcore_id, packet_count, first_seq, last_seq)
    """
    segments: list[tuple[int, int, int, int]] = []
    if not packets:
        return segments

    def _pkt_meta(p: bytes) -> tuple[int, int]:
        return (p[98], p[99])

    # Skip leading packets that are too short to contain our metadata bytes
    packets = [p for p in packets if len(p) >= 100]
    if not packets:
        return segments

    cur_lcore, cur_seq = _pkt_meta(packets[0])
    start_seq = cur_seq
    count = 1

    for pkt in packets[1:]:
        lcore, seq = _pkt_meta(pkt)
        if lcore == cur_lcore:
            count += 1
            cur_seq = seq
            continue

        segments.append((cur_lcore, count, start_seq, cur_seq))
        cur_lcore, cur_seq = lcore, seq
        start_seq = seq
        count = 1

    segments.append((cur_lcore, count, start_seq, cur_seq))
    return segments


def check_pcap_sequence_order(path: Path, lcore_ids: list[int]) -> list[str]:
    """Verify that the pcap file's packet sequence numbers follow the generation order.

    Packets are generated in blocks of 32 per core, rotating through the configured
    `lcore_ids` list. This check verifies that the capture order matches the
    expected global sequence (byte[99]) and expected core id (byte[98]).
    """

    packets = load_pcap(path)
    errors: list[str] = []

    num_cores = len(lcore_ids)
    for idx, pkt in enumerate(packets):
        if len(pkt) < 100:
            errors.append(f"packet {idx} too short ({len(pkt)} bytes)")
            continue

        expected_seq = idx & 0xFF
        expected_core = lcore_ids[(idx // 32) % num_cores] & 0xFF

        actual_seq = pkt[99]
        actual_core = pkt[98]

        if actual_seq != expected_seq:
            errors.append(
                f"pkt[{idx}] seq expected {expected_seq:#04x}, got {actual_seq:#04x}"
            )
        if actual_core != expected_core:
            errors.append(
                f"pkt[{idx}] core expected {expected_core:#04x}, got {actual_core:#04x}"
            )

    return errors


# ---------------------------------------------------------------------------
# Golden-value formula (mirrors gen_pkts.py)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Golden-value formula (mirrors gen_pkts.py)
# ---------------------------------------------------------------------------


def _expected_byte99(lcore_id: int, seq: int, lcore_ids: list[int]) -> int:
    """Reproduce the packet sequence used by `gen_pkts.generate()`.

    Packets are generated in round-robin blocks of 32 per core:
      core0: 0..31, core1: 32..63, ..., core0: 64..95, etc.

    `seq` is the per-core packet index (0..N-1)."""

    core_idx = lcore_ids.index(lcore_id)
    block, j = divmod(seq, 32)
    return ((block * len(lcore_ids) + core_idx) * 32 + j) & 0xFF


# ---------------------------------------------------------------------------
# Verification helpers
# ---------------------------------------------------------------------------


def check_packet_count(packets: list[bytes], expected: int) -> bool:
    """Return True if the number of packets matches expected."""
    return len(packets) == expected


def check_packet_content(packet: bytes, lcore_id: int, seq: int) -> bool:
    """
    Verify bytes [98] and [99] of a single packet match the expected values
    for the given lcore and sequence number.
    """
    if len(packet) < 100:
        return False
    return packet[98] == (lcore_id & 0xFF) and packet[99] == _expected_byte99(
        lcore_id, seq
    )


def check_packet_order(
    packets: list[bytes], lcore_id: int, lcore_ids: list[int]
) -> list[str]:
    """Filter packets belonging to *lcore_id* (byte[98] == lcore_id) and verify
    that their sequence bytes match the generation order.

    Returns a list of error strings.  Empty list means all checks passed.
    """
    errors: list[str] = []
    lcore_pkts = [p for p in packets if len(p) >= 100 and p[98] == (lcore_id & 0xFF)]

    for idx, pkt in enumerate(lcore_pkts):
        expected = _expected_byte99(lcore_id, idx, lcore_ids)
        actual = pkt[99]
        if actual != expected:
            errors.append(
                f"lcore={lcore_id} seq={idx}: byte[99] expected {expected:#04x}, got {actual:#04x}"
            )
    return errors


_TRACE_WQE_INDEX_RE = re.compile(r"wqe_index\s*=\s*0x([0-9A-Fa-f]+)")
_TRACE_LCORE_RE = re.compile(r"lcore_id\s*=\s*0x([0-9A-Fa-f]+)")


def summarize_trace_by_lcore(trace_dir: Path) -> dict[int, dict[str, int]]:
    """Summarize trace entries by lcore.

    Returns a mapping from lcore id -> stats dict with:
      - count: number of trace lines seen
      - min: minimum wqe_index
      - max: maximum wqe_index
    """

    try:
        raw = subprocess.check_output(
            ["sudo", "babeltrace2", str(trace_dir)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return {}
    except subprocess.CalledProcessError:
        return {}

    stats: dict[int, dict[str, int]] = {}
    for line in raw.splitlines():
        m_lcore = _TRACE_LCORE_RE.search(line)
        m_idx = _TRACE_WQE_INDEX_RE.search(line)
        if not m_lcore or not m_idx:
            continue

        lcore = int(m_lcore.group(1), 16)
        idx = int(m_idx.group(1), 16)

        if lcore not in stats:
            stats[lcore] = {"count": 0, "min": idx, "max": idx}
        stats[lcore]["count"] += 1
        stats[lcore]["min"] = min(stats[lcore]["min"], idx)
        stats[lcore]["max"] = max(stats[lcore]["max"], idx)

    return stats


def check_trace_order(trace_dir: Path) -> list[str]:
    """Verify that babeltrace2 trace entries are ordered per lcore.

    We only require that for each lcore, `wqe_index` is non-decreasing (per-core
    ordering). Global order of entries across different lcores is not enforced.
    """

    try:
        raw = subprocess.check_output(
            ["sudo", "babeltrace2", str(trace_dir)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return ["babeltrace2 not found in PATH"]
    except subprocess.CalledProcessError as e:
        return [f"babeltrace2 failed: {e}"]

    last_idx_by_lcore: dict[int, int] = {}
    seen_any = False
    errors: list[str] = []

    for line in raw.splitlines():
        # Find both lcore_id and wqe_index; ignore lines that don't include both.
        m_lcore = _TRACE_LCORE_RE.search(line)
        m_idx = _TRACE_WQE_INDEX_RE.search(line)
        if not m_lcore or not m_idx:
            continue
        seen_any = True

        lcore = int(m_lcore.group(1), 16)
        idx = int(m_idx.group(1), 16)

        if lcore in last_idx_by_lcore:
            prev = last_idx_by_lcore[lcore]
            if idx < prev:
                errors.append(
                    f"lcore {lcore:#x} wqe_index decreased: {prev:#x} -> {idx:#x}"
                )
        last_idx_by_lcore[lcore] = idx

    if not seen_any:
        return ["no wqe_index entries found in trace"]
    return errors
