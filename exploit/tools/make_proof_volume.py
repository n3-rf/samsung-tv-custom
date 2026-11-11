#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Create a deterministic, empty 64 MiB FAT32 proof volume in a new file."""
import argparse
import struct
from pathlib import Path


def create(path):
    total, reserved, copies = 131072, 32, 2
    fat_sectors = 1
    while True:
        clusters = total - reserved - copies * fat_sectors
        required = ((clusters + 2) * 4 + 511) // 512
        if required <= fat_sectors:
            break
        fat_sectors = required
    clusters = total - reserved - copies * fat_sectors
    assert 65525 <= clusters < 0x0FFFFFF5
    boot = bytearray(512)
    boot[:11] = b'\xeb\x58\x90MSWIN4.1'
    struct.pack_into('<HBHBHHBHHHII', boot, 11,
                     512, 1, reserved, copies, 0, 0, 0xF8, 0, 63, 255, 0, total)
    struct.pack_into('<IHHIHH', boot, 36, fat_sectors, 0, 0, 2, 1, 6)
    struct.pack_into('<BBBI', boot, 64, 0x80, 0, 0x29, 0x4B414E54)
    boot[71:82] = b'ROOTPROOF  '
    boot[82:90] = b'FAT32   '
    boot[510:512] = b'\x55\xaa'
    info = bytearray(512)
    struct.pack_into('<I', info, 0, 0x41615252)
    struct.pack_into('<IIII', info, 484, 0x61417272, clusters - 1, 3, 0)
    struct.pack_into('<I', info, 508, 0xAA550000)
    fat = bytearray(fat_sectors * 512)
    struct.pack_into('<III', fat, 0, 0x0FFFFFF8, 0xFFFFFFFF, 0x0FFFFFFF)
    root = bytearray(512)
    root[:11] = b'ROOTPROOF  '
    root[11] = 0x08
    with Path(path).open('xb') as output:
        output.truncate(total * 512)
        for sector, block in ((0, boot), (1, info), (6, boot), (7, info)):
            output.seek(sector * 512)
            output.write(block)
        for n in range(copies):
            output.seek((reserved + n * fat_sectors) * 512)
            output.write(fat)
        output.seek((reserved + copies * fat_sectors) * 512)
        output.write(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    create(args.output)
    print(f'Created {args.output}: {args.output.stat().st_size} bytes')


if __name__ == '__main__':
    main()
