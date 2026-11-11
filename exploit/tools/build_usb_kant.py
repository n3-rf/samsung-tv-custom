#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Kant-M2 adaptation; see docs/PROVENANCE.md.
"""Compose a two-partition USB image for the Kant-M2 first-root probe.

    p1  exFAT   the crafted trigger (out/p1_kant*.img)
    p2  FAT32   writable proof partition (ROOT_PROOF.txt)

The FAT32 partition is an operator-supplied proof volume. A valid partition
does not guarantee a successful mount or a successful runtime proof write.

Layout: MBR at LBA 0, p1 at LBA 2048 (1 MiB), p2 immediately after p1.
Partition types: 0x07 (exFAT) and 0x0C (FAT32 LBA).
"""
import argparse
import os
import struct


def chs_lba_placeholder():
    return bytes([0xFE, 0xFF, 0xFF])


def entry(status, ptype, lba, sectors):
    return (bytes([status]) + chs_lba_placeholder() + bytes([ptype]) +
            chs_lba_placeholder() + struct.pack("<II", lba, sectors))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p1", required=True)
    ap.add_argument("--p2", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--p1-start", type=int, default=2048)
    ap.add_argument("--total-mb", type=int, default=80)
    ap.add_argument("--p1-type", type=lambda x: int(x, 0), default=0x07,
                    help="MBR type of the first partition (default 0x07 exFAT)")
    ap.add_argument("--p2-type", type=lambda x: int(x, 0), default=0x0C,
                    help="MBR type of the second partition (default 0x0C FAT32)")
    a = ap.parse_args()

    p1 = open(a.p1, "rb").read()
    p2 = open(a.p2, "rb").read()
    if len(p1) % 512 or len(p2) % 512:
        raise SystemExit("partition images must be 512-byte multiples")
    p1_sectors = len(p1) // 512
    p2_sectors = len(p2) // 512
    p2_start = a.p1_start + p1_sectors
    total_sectors = a.total_mb * 1024 * 1024 // 512
    if p2_start + p2_sectors > total_sectors:
        raise SystemExit(
            f"image too small: need {p2_start + p2_sectors} sectors, "
            f"have {total_sectors}")

    mbr = bytearray(512)
    mbr[446:462] = entry(0x00, a.p1_type, a.p1_start, p1_sectors)
    mbr[462:478] = entry(0x00, a.p2_type, p2_start, p2_sectors)
    mbr[510:512] = b"\x55\xaa"

    with open(a.out, "wb") as f:
        f.truncate(total_sectors * 512)
        f.seek(0)
        f.write(mbr)
        f.seek(a.p1_start * 512)
        f.write(p1)
        f.seek(p2_start * 512)
        f.write(p2)

    print(f"wrote {a.out}: {total_sectors*512} bytes")
    print(f"  p1 @ LBA {a.p1_start} type {a.p1_type:#04x}, {p1_sectors} sectors ({len(p1)} bytes)")
    print(f"  p2 @ LBA {p2_start} type {a.p2_type:#04x}, {p2_sectors} sectors ({len(p2)} bytes)")
    # sanity
    data = open(a.out, "rb").read()
    assert data[a.p1_start * 512:a.p1_start * 512 + 11] == p1[:11]
    assert data[p2_start * 512:p2_start * 512 + 11] == p2[:11]


if __name__ == "__main__":
    main()
