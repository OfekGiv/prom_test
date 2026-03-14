"""Packet verification helpers — no external dependencies (no Scapy)."""

from __future__ import annotations

import struct
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


# ---------------------------------------------------------------------------
# Golden-value formula (mirrors gen_pkts.py)
# ---------------------------------------------------------------------------

def _expected_byte99(lcore_id: int, seq: int) -> int:
    """
    Reproduce the original hardcoded logic:
        pkt[99] = 32 * (2*i + lcore_id - 1) + j
    where seq = i * 32 + j.
    """
    i, j = divmod(seq, 32)
    return (32 * (2 * i + lcore_id - 1) + j) & 0xFF


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
    return packet[98] == (lcore_id & 0xFF) and packet[99] == _expected_byte99(lcore_id, seq)


def check_packet_order(packets: list[bytes], lcore_id: int) -> list[str]:
    """
    Filter packets belonging to *lcore_id* (byte[98] == lcore_id) and verify
    that their sequence bytes are monotonically correct.

    Returns a list of error strings.  Empty list means all checks passed.
    """
    errors: list[str] = []
    lcore_pkts = [p for p in packets if len(p) >= 100 and p[98] == (lcore_id & 0xFF)]

    for idx, pkt in enumerate(lcore_pkts):
        expected = _expected_byte99(lcore_id, idx)
        actual = pkt[99]
        if actual != expected:
            errors.append(
                f"lcore={lcore_id} seq={idx}: byte[99] expected {expected:#04x}, got {actual:#04x}"
            )
    return errors
