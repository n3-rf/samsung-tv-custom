#!/usr/bin/env python3
"""Decode the Kant kernel TCP probe packet (kbeacon.bin).

Header layout, 14 little-endian u32 words (56 bytes):

  v1.1 (test 5):  magic, version, sock_create, connect, 7 device/proc
                  diagnostics, trailer
  v1.2 (test 6b): magic, version, sock_create, connect, umh1 (bash A),
                  umh2 (bash B), 7 reserved, trailer
  v1.3 (test 6a): magic, version, sock_create, connect, umh1 (bash A),
                  umh2 (bash B), umh0 (dd probe), 6 reserved, trailer

For umh*_ret: 0 means the helper was *queued* (UMH_NO_WAIT); it does not prove
the command ran. Negative values are errno from call_usermodehelper().
"""
import struct
import sys

FIELDS_V1 = [
    "magic", "version", "sock_create", "connect",
    "filp /dev/sda O_RDONLY", "filp /dev/sda O_WRONLY",
    "filp /dev/sdb O_WRONLY", "filp /dev/sda1 O_WRONLY",
    "filp /dev/sdb1 O_WRONLY", "filp /proc/mounts",
    "mounts_len", "filp /proc/self/comm", "comm_len", "trailer",
]

FIELDS_V2 = [
    "magic", "version", "sock_create", "connect",
    "umh1_ret (bash A)", "umh2_ret (bash B)",
    "reserved6", "reserved7", "reserved8", "reserved9",
    "reserved10", "reserved11", "reserved12", "trailer",
]

FIELDS_V3 = [
    "magic", "version", "sock_create", "connect",
    "umh1_ret (bash A)", "umh2_ret (bash B)", "umh0_ret (dd probe)",
    "reserved7", "reserved8", "reserved9", "reserved10",
    "reserved11", "reserved12", "trailer",
]

ERRNO = {
    1: "EPERM", 2: "ENOENT", 11: "EAGAIN", 12: "ENOMEM", 13: "EACCES",
    22: "EINVAL", 95: "EOPNOTSUPP",
}

RET_FIELDS = {"sock_create", "connect", "umh1_ret (bash A)",
              "umh2_ret (bash B)", "umh0_ret (dd probe)"}


def val(x, name):
    if x >= 0xFFFFF000:
        n = (~x + 1) & 0xFFFFFFFF
        return f"-{n} ({ERRNO.get(n, 'errno')})"
    if name in RET_FIELDS:
        return "0 (success/queued)" if x == 0 else f"{x:#010x}"
    if 0xC0000000 <= x < 0xD0000000:
        return f"{x:#010x} (kernel pointer)"
    return f"{x:#010x}"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "kbeacon.bin"
    d = open(path, "rb").read()
    print(f"file: {path}  bytes: {len(d)}")
    if len(d) < 56:
        print("too short: no complete header")
        if d:
            print("raw:", d.hex())
        return
    w = struct.unpack_from("<14I", d, 0)
    if w[1] == 0x00010003:
        fields, layout = FIELDS_V3, "v1.3 (no kernel patch)"
    elif w[1] == 0x00010002:
        fields, layout = FIELDS_V2, "v1.2 (UEP patch)"
    else:
        fields, layout = FIELDS_V1, "v1.1 (device diagnostics)"
    print(f"layout: {layout} (version {w[1]:#010x})")
    for name, x in zip(fields, w):
        print(f"{name:26s} {val(x, name)}")
    if w[0] != 0x544E414B:
        print("WARNING: magic is not 'KANT'")
    if w[13] != 0x4B42454B:
        print("WARNING: trailer is not 'KBEK'")
    if len(d) > 56:
        print(f"\ntrailing {len(d)-56} bytes: {d[56:56+64]!r}")


if __name__ == "__main__":
    main()
