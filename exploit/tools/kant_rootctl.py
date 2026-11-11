#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Client for the Kant-M2 persistent root daemon.

The daemon is installed by persist/install.sh on the TV. It speaks a small
challenge-response protocol over TCP; the token is never transmitted.

Examples:

    python3 tools/kant_rootctl.py --host 192.168.1.2 --token-file token.txt \
        --cmd 'id; uname -a'

    python3 tools/kant_rootctl.py --host 192.168.1.2 --token-file token.txt \
        --shell
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import select
import socket
import sys

DEFAULT_PORT = 5555
MAX_LINE = 2 * 1024 * 1024


def recv_line(sock, buffer):
    while b"\n" not in buffer:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("connection closed while waiting for a reply")
        buffer += chunk
        if len(buffer) > MAX_LINE:
            raise ConnectionError("reply exceeds the line limit")
    line, buffer = buffer.split(b"\n", 1)
    return line.decode("utf-8", "replace"), buffer


def send_line(sock, text):
    sock.sendall(text.encode("utf-8") + b"\n")


def read_token(args):
    token = args.token
    if token is None and args.token_file:
        try:
            token = open(args.token_file, "r", encoding="utf-8").read().strip()
        except OSError as error:
            raise SystemExit(f"cannot read token file: {error}")
    if token is None:
        token = os.environ.get("KANT_ROOT_TOKEN")
    if token is None:
        if sys.stdin.isatty():
            token = getpass.getpass("root token: ").strip()
        else:
            raise SystemExit("provide --token-file, --token or KANT_ROOT_TOKEN")
    token = token.strip()
    if len(token) != 64 or any(c not in "0123456789abcdefABCDEF" for c in token):
        raise SystemExit("token must be 64 hexadecimal characters")
    return token.lower()


class Client:
    def __init__(self, host, port, token, connect_timeout=5.0):
        self.sock = socket.create_connection((host, port), timeout=connect_timeout)
        self.buffer = b""
        try:
            self.sock.settimeout(connect_timeout)
            greeting, self.buffer = recv_line(self.sock, self.buffer)
            fields = greeting.split()
            if len(fields) != 2 or fields[0] != "KANT-ROOT/1":
                raise ConnectionError(f"unexpected greeting: {greeting!r}")
            nonce = fields[1]
            if len(nonce) != 64 or any(c not in "0123456789abcdefABCDEF" for c in nonce):
                raise ConnectionError("invalid nonce in greeting")
            expected = hmac.new(
                bytes.fromhex(token), nonce.encode("ascii"), hashlib.sha256
            ).hexdigest()
            send_line(self.sock, f"AUTH {expected}")
            reply, self.buffer = recv_line(self.sock, self.buffer)
            if reply.split(" ", 1)[0] == "DENY":
                raise ConnectionError("authentication rejected")
            if not reply.startswith("OK"):
                raise ConnectionError(f"unexpected authentication reply: {reply!r}")
            self.sock.settimeout(None)
        except Exception:
            self.close()
            raise
        self._seq = 1

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def ping(self):
        send_line(self.sock, "PING")
        reply, self.buffer = recv_line(self.sock, self.buffer)
        if reply != "PONG":
            raise ConnectionError(f"unexpected ping reply: {reply!r}")

    def execute(self, command, timeout_ms):
        payload = base64.b64encode(command.encode("utf-8")).decode("ascii")
        seq = str(self._seq)
        self._seq += 1
        send_line(self.sock, f"EXEC\t{seq}\t{timeout_ms}\t{payload}")
        while True:
            line, self.buffer = recv_line(self.sock, self.buffer)
            if line.startswith("RESULT\t"):
                fields = line.split("\t")
                if len(fields) != 6:
                    raise ConnectionError(f"malformed result: {line!r}")
                if fields[1] != seq:
                    raise ConnectionError(f"result sequence mismatch: {line!r}")
                return {
                    "exit": int(fields[2]),
                    "timedout": int(fields[3]) == 1,
                    "stdout": base64.b64decode(fields[4]).decode("utf-8", "replace"),
                    "stderr": base64.b64decode(fields[5]).decode("utf-8", "replace"),
                }
            if line.startswith("ERR "):
                raise ConnectionError(line)
            raise ConnectionError(f"unexpected frame: {line!r}")

    _seq = 1

    def shell(self):
        send_line(self.sock, "SHELL")
        stdin = sys.stdin.buffer
        while True:
            watch = [self.sock] if stdin is None else [self.sock, stdin]
            try:
                readable, _, _ = select.select(watch, [], [])
            except (OSError, ValueError):
                return
            if self.sock in readable:
                chunk = self.sock.recv(65536)
                if not chunk:
                    return
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            if stdin is not None and stdin in readable:
                try:
                    chunk = os.read(stdin.fileno(), 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    try:
                        self.sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    stdin = None
                    continue
                self.sock.sendall(chunk)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", required=True, help="TV address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--token-file", help="file containing the 64-hex token")
    parser.add_argument("--token", help="token value (prefer --token-file)")
    parser.add_argument("--cmd", action="append", default=[],
                        help="command to run; repeat for several commands")
    parser.add_argument("--shell", action="store_true",
                        help="open an interactive /bin/bash (no PTY)")
    parser.add_argument("--ping", action="store_true", help="check authentication")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="per-command timeout in seconds (max 120)")
    parser.add_argument("--json", action="store_true",
                        help="print command results as JSON")
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    if not 1 <= args.timeout <= 120:
        parser.error("timeout must be in 1..120 seconds")
    if args.shell and args.cmd:
        parser.error("use either --shell or --cmd, not both")
    if not args.shell and not args.cmd and not args.ping:
        args.shell = True

    token = read_token(args)
    try:
        client = Client(args.host, args.port, token)
    except (OSError, ConnectionError) as error:
        raise SystemExit(f"connection failed: {error}")
    exit_code = 0
    try:
        if args.ping:
            try:
                client.ping()
                print("OK")
            except (OSError, ConnectionError) as error:
                raise SystemExit(f"ping failed: {error}")
        results = []
        for command in args.cmd:
            try:
                result = client.execute(command, int(args.timeout * 1000))
            except (OSError, ConnectionError) as error:
                raise SystemExit(f"command failed: {error}")
            results.append({"command": command, **result})
            if not args.json:
                sys.stdout.write(result["stdout"])
                sys.stdout.flush()
                sys.stderr.write(result["stderr"])
                sys.stderr.flush()
            exit_code = result["exit"] if result["exit"] else exit_code
        if args.json and results:
            print(json.dumps(results, indent=2))
        if args.shell and not args.ping:
            client.shell()
    finally:
        client.close()
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
