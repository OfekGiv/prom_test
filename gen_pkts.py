#!/usr/bin/env python3
"""
Generate pkt_lcore_{lcore_id}_seq_{seq}.bin files matching the original
hardcoded pkt_bytes used in lpm_main_loop.

Each file is 100 bytes. Bytes [98] and [99] are set per-lcore/per-sequence
to match the original logic:
  pkt[98] = lcore_id
  pkt[99] = 32 * (2*i + lcore_id - 1) + j   (where seq = i*32 + j)

Usage:
  python3 gen_pkts.py [lcore_id ...]
  python3 gen_pkts.py 1 2 3
"""

import os
import sys

BASE_PKT = bytearray(
    [
        0xD4,
        0xC3,
        0xB2,
        0xA1,
        0x02,
        0x00,
        0x04,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x04,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0xE9,
        0x71,
        0x7A,
        0x69,
        0x1D,
        0x24,
        0x0E,
        0x00,
        0x3C,
        0x00,
        0x00,
        0x00,
        0x3C,
        0x00,
        0x00,
        0x00,
        0xE8,
        0xEB,
        0xD3,
        0x98,
        0x25,
        0x8D,
        0x0C,
        0x42,
        0xA1,
        0x1D,
        0x3A,
        0xFA,
        0x08,
        0x00,
        0x45,
        0x00,
        0x00,
        0x2E,
        0x2F,
        0xF2,
        0x00,
        0x00,
        0x40,
        0x06,
        0x00,
        0x00,
        0x03,
        0x03,
        0x03,
        0x03,
        0x04,
        0x03,
        0x03,
        0x02,
        0x04,
        0xD2,
        0x16,
        0x2E,
        0x00,
        0x01,
        0x23,
        0x78,
        0x00,
        0x01,
        0x23,
        0x90,
        0x50,
        0x10,
        0x20,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        ord("N"),
        ord("u"),
        ord("m"),
        ord(":"),
        0x00,
        0x00,  # [98] = lcore_id, [99] = seq byte
    ]
)

assert len(BASE_PKT) == 100, f"Expected 100 bytes, got {len(BASE_PKT)}"

_DEFAULT_OUT_DIR = os.path.join(os.path.dirname(__file__), "pkts")


def generate(lcore_ids, out_dir: str | None = None):
    out = out_dir or _DEFAULT_OUT_DIR
    os.makedirs(out, exist_ok=True)

    num_cores = len(lcore_ids)
    if num_cores == 0 or (num_cores & (num_cores - 1)) != 0:
        raise ValueError("lcore_ids length must be a power of 2")

    # Generate in a round-robin layout so that sequence numbers are distributed
    # as: core0=0..31, core1=32..63, ..., then core0=64..95, etc.
    for block in range(10):
        for core_idx, lcore_id in enumerate(lcore_ids):
            for j in range(32):
                seq = (block * num_cores + core_idx) * 32 + j
                pkt = bytearray(BASE_PKT)
                pkt[98] = lcore_id & 0xFF
                pkt[99] = seq & 0xFF
                fname = os.path.join(out, f"pkt_lcore_{lcore_id}_seq_{seq}.bin")
                with open(fname, "wb") as f:
                    f.write(pkt)
    print(f"lcores {lcore_ids}: wrote {10 * 32 * num_cores} files to {out}/")


if __name__ == "__main__":
    lcore_ids = [int(x) for x in sys.argv[1:]] if len(sys.argv) > 1 else [1, 2]
    generate(lcore_ids)
    print("Done.")
