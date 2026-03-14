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

BASE_PKT = bytearray([
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xe9, 0x71, 0x7a, 0x69, 0x1d, 0x24, 0x0e, 0x00,
    0x3c, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00,
    0xe8, 0xeb, 0xd3, 0x98, 0x25, 0x8d, 0x0c, 0x42,
    0xa1, 0x1d, 0x3a, 0xfa, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x2e, 0x2f, 0xf2, 0x00, 0x00, 0x40, 0x06,
    0x00, 0x00, 0x03, 0x03, 0x03, 0x03, 0x04, 0x03,
    0x03, 0x02, 0x04, 0xd2, 0x16, 0x2e, 0x00, 0x01,
    0x23, 0x78, 0x00, 0x01, 0x23, 0x90, 0x50, 0x10,
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    ord('N'), ord('u'), ord('m'), ord(':'),
    0x00, 0x00,  # [98] = lcore_id, [99] = seq byte
])

assert len(BASE_PKT) == 100, f"Expected 100 bytes, got {len(BASE_PKT)}"

_DEFAULT_OUT_DIR = os.path.join(os.path.dirname(__file__), "pkts")


def generate(lcore_ids, out_dir: str | None = None):
    out = out_dir or _DEFAULT_OUT_DIR
    os.makedirs(out, exist_ok=True)
    for lcore_id in lcore_ids:
        for i in range(10):
            for j in range(32):
                seq = i * 32 + j
                pkt = bytearray(BASE_PKT)
                pkt[98] = lcore_id & 0xff
                pkt[99] = (32 * (2 * i + lcore_id - 1) + j) & 0xff
                fname = os.path.join(out, f"pkt_lcore_{lcore_id}_seq_{seq}.bin")
                with open(fname, "wb") as f:
                    f.write(pkt)
        print(f"lcore {lcore_id}: wrote {10 * 32} files to {out}/")


if __name__ == "__main__":
    lcore_ids = [int(x) for x in sys.argv[1:]] if len(sys.argv) > 1 else [1, 2]
    generate(lcore_ids)
    print("Done.")
