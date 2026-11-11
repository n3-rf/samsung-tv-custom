#!/usr/bin/env python3
"""Relay for the Kant root shell on TCP 4445.

The TV connects out to the listener host (reverse shell). Raw shell output is
appended to the log file (fsync on every chunk). Any bytes appended to the
command queue are forwarded to the shell, e.g.:

    printf 'id\n' >> /path/to/cmds.txt

Append only after the connection is reported: pre-existing bytes are skipped.
Bind, log and queue paths are explicit arguments.

An initial probe (KANT-RELAY-OK, id, uname, /proc/version) is sent as soon as
the shell connects.
"""
import argparse
import os
import socket
import sys
import threading
import time

PORT = 4445
LOG = None
CMDS = None
BIND = None

PROBE = (
    b"\n"
    b"export PS1='kant# '\n"
    b"echo KANT-RELAY-OK; id; uname -a; cat /proc/version\n"
)


def say(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def handle(conn, addr):
    say(f"shell connection from {addr[0]}:{addr[1]}")
    stop = threading.Event()

    def receive():
        conn.settimeout(2.0)
        while not stop.is_set():
            try:
                b = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError as e:
                say(f"recv error: {e}")
                stop.set()
                return
            if not b:
                say("shell closed")
                stop.set()
                return
            with open(LOG, "ab") as f:
                f.write(b)
                f.flush()
                os.fsync(f.fileno())
            sys.stdout.write(b.decode("utf-8", "replace"))
            sys.stdout.flush()

    t = threading.Thread(target=receive, daemon=True)
    t.start()

    time.sleep(0.7)
    try:
        conn.sendall(PROBE)
    except OSError as e:
        say(f"probe send error: {e}")

    # Never replay an earlier session's command queue after reconnecting.
    pos = os.path.getsize(CMDS) if os.path.exists(CMDS) else 0
    while not stop.is_set():
        try:
            size = os.path.getsize(CMDS)
        except OSError:
            size = pos
        if size > pos:
            with open(CMDS, "rb") as f:
                f.seek(pos)
                data = f.read()
            pos += len(data)
            try:
                conn.sendall(data)
                say(f"sent {len(data)} command bytes")
            except OSError as e:
                say(f"send error: {e}")
                stop.set()
                break
        time.sleep(0.2)

    t.join(timeout=1.0)
    say("handler done")


def main():
    global LOG, CMDS, BIND, PORT
    ap = argparse.ArgumentParser(description="Explicitly bound root-shell relay; never replays old commands")
    ap.add_argument("--bind", required=True, help="listener address on this host")
    ap.add_argument("--port", type=int, default=4445)
    ap.add_argument("--log", required=True)
    ap.add_argument("--commands", required=True)
    args = ap.parse_args()
    LOG, CMDS, BIND, PORT = args.log, args.commands, args.bind, args.port
    with open(LOG, "ab"):
        pass
    with open(CMDS, "ab"):
        pass
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND, PORT))
    srv.listen(4)
    say(f"relay listening on {BIND}:{PORT} -> {LOG} (cmds: {CMDS})")
    while True:
        conn, addr = srv.accept()
        with conn:
            handle(conn, addr)


if __name__ == "__main__":
    main()
