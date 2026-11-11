# Persistent root (optional)

This document describes the optional persistent root daemon. It is separate
from the USB exploit: the USB stick is still the way in the first time, but
after `install.sh` runs once the daemon is started at every boot by a vendor
script on the writable `/opt` partition. The stick is no longer required.

> **Validation status:** the installer, daemon and client are covered by
> offline tests (including Node 4.4.3). They have **not** been installed or
> boot-validated on a physical TV yet. Treat the procedure below as a tested
> design, not as a confirmed hardware result.

## Why this works without patching UEP

* `/opt` is a persistent, writable VDFS partition (`/dev/mmcblk0p21`).
* The vendor unit `AT-HUB.service` is enabled at boot and runs
  `ExecStart=/opt/etc/parseinfo.sh &` as root. That path is writable.
* `/usr/bin/node` and `/bin/bash` are signed firmware executables. The daemon
  is a JavaScript file, not an unsigned ELF, so no code-signing gate has to be
  bypassed for it to keep running after a reboot.

The installer only appends one marked block to `parseinfo.sh`; existing vendor
content is preserved and copied to `parseinfo.sh.kant-orig` the first time.

## Files

| Path | Purpose |
|---|---|
| `/opt/kant-root/rootd.js` | daemon (Node 4.4.3 compatible) |
| `/opt/kant-root/token` | 64-hex HMAC key, mode `0600`, generated on the TV |
| `/opt/kant-root/env` | bind address, port, paths, optional SMACK label |
| `/opt/kant-root/boot.sh` | creates the volatile unit and starts the daemon |
| `/opt/kant-root/rootd.log` | daemon log, capped at 512 KiB |
| `/opt/etc/parseinfo.sh` | vendor boot script plus the marked hook block |
| `/opt/etc/parseinfo.sh.kant-orig` | untouched copy made at first install |
| `/run/systemd/system/kant-rootd.service` | recreated at every boot (tmpfs) |
| `/tmp/kant-rootd.pid`, `/tmp/kant-rootd.lock` | runtime state (cleared by reboot) |

`/usr/lib/systemd/system` and `/etc/systemd/system` are read-only on this
firmware, so the unit cannot be installed permanently. `boot.sh` rewrites it in
`/run/systemd/system` on each boot and falls back to `setsid` if systemd
refuses the transient unit.

## Install

Build the self-contained bundle (it embeds `persist/rootd.js`):

```sh
python3 tools/build_persist_bundle.py
```

Output is `out/persist/install.sh`, `out/persist/uninstall.sh` and
`out/persist/manifest.json`. Serve it from the computer that can reach the TV:

```sh
python3 -m http.server 8000 --bind 0.0.0.0 --directory out/persist
```

Get a root shell through the USB procedure in [USB-STICK.md](USB-STICK.md), then
on the TV:

```sh
curl -fsSL http://HOST_IP:8000/install.sh | sh
```

`HOST_IP` is the computer running the HTTP server. The firmware already ships
`/usr/bin/curl`.

The installer:

1. checks that `/usr/bin/node` and the `AT-HUB.service` hook exist, and that
   an existing `parseinfo.sh` starts with a shell shebang;
2. writes the daemon, token, environment, and boot script under
   `/opt/kant-root` (directory mode `0700`, token and env mode `0600`);
3. appends the marked block to `parseinfo.sh` exactly once;
4. starts the daemon through `boot.sh` and reports whether it is running.

If an existing `parseinfo.sh` is not a shell script, the installer stops unless
`--force` is given. Inspect the file before forcing: appending shell syntax to
a binary or to an unknown format would break the vendor boot step.

It prints the token on stdout:

```text
KANT-ROOT-INSTALL-OK
root:  /opt/kant-root
hook:  /opt/etc/parseinfo.sh
bind:  0.0.0.0
port:  5555
start: running
KANT-ROOT-TOKEN=<64 hex characters>
KANT-ROOT-PORT=5555
```

Store the token on the computer, for example in a file readable only by you:

```sh
umask 077
printf '%s\n' 'PASTE_TOKEN_HERE' > ~/.kant-root-token
```

The token is generated on the TV and is never sent over the network. If you
lose it, reinstall with `--token HEX64`, or read
`/opt/kant-root/token` from a root shell.

### Options

| Option | Effect |
|---|---|
| `--bind ADDRESS` | listen address, default `0.0.0.0`; use `127.0.0.1` only if you tunnel |
| `--port PORT` | listen port, default `5555` |
| `--label LABEL` | optional SMACK label applied to commands and the shell |
| `--token HEX64` | reuse a known token instead of generating one |
| `--no-start` | write files but do not start the daemon now |
| `--force` | skip the firmware sanity checks (only with another known hook) |
| `--quiet` | print only the token and final status |

The installer is idempotent: running it again keeps the existing token and does
not duplicate the hook block.

## Use

```sh
python3 tools/kant_rootctl.py --host TV_IP \
  --token-file ~/.kant-root-token --ping

python3 tools/kant_rootctl.py --host TV_IP \
  --token-file ~/.kant-root-token --cmd 'id; uname -a'

python3 tools/kant_rootctl.py --host TV_IP \
  --token-file ~/.kant-root-token --shell
```

`--cmd` may be repeated and supports `--json` for machine-readable output.
`--shell` starts `/bin/bash -i` over the raw socket. There is no PTY: job
control and full-screen programs are not available. Use `--cmd` for scripts
and one-shot operations.

Protocol summary:

```text
server:  KANT-ROOT/1 <nonce hex>
client:  AUTH <HMAC-SHA256(token, nonce) hex>
server:  OK <version> | DENY | BUSY

client:  PING                       server: PONG
client:  EXEC <seq> <ms> <base64>   server: RESULT <seq> <exit> <timedout> <base64 out> <base64 err>
client:  SHELL                      raw bash over the socket
client:  QUIT                       server: BYE
```

Limits: 10 s to authenticate, at most 4 sessions, command timeout 1–120 s,
64 KiB command, 4 MiB captured output per stream, frames up to 1 MiB.

## Verify persistence

1. Immediately after install:

   ```sh
   python3 tools/kant_rootctl.py --host TV_IP --token-file ~/.kant-root-token --ping
   python3 tools/kant_rootctl.py --host TV_IP --token-file ~/.kant-root-token \
     --cmd 'id; cat /opt/kant-root/token | wc -c'
   ```

2. Power off the TV, **remove the USB stick**, and power it on.
3. Wait for the network, then run the same `--ping` and `--cmd 'id'` again.
4. On the TV, `systemctl status kant-rootd.service` and
   `/opt/kant-root/rootd.log` show how the daemon was started.

If the daemon does not come back:

```sh
cat /opt/kant-root/rootd.log
cat /opt/kant-root/rootd.out
systemctl status kant-rootd.service
tail -n 20 /opt/etc/parseinfo.sh
```

## Uninstall

```sh
curl -fsSL http://HOST_IP:8000/uninstall.sh | sh
```

The uninstaller stops the service and daemon, removes the volatile unit and
only the marked block from `parseinfo.sh`. It keeps `/opt/kant-root` by default
so the token can be reused; add `--purge` to delete the directory and token.

After uninstalling, root is again available only by booting with the USB stick.

## Security

* The daemon runs as root. Anyone with the token has root-equivalent command
  execution. Protect the token like an SSH private key.
* The protocol is **not encrypted or authenticated beyond the challenge**:
  commands and output travel in clear text. Use it only on a trusted LAN, or
  forward the port through SSH/VPN. Do not expose `5555` to the internet.
* The binding is `0.0.0.0` by default so the TV is reachable from the LAN. Use
  `--bind 127.0.0.1` plus a tunnel if you want loopback-only access.
* Authentication failures are logged in `/opt/kant-root/rootd.log`; the log
  never contains the token or command output.
* The installer does not write to block devices, kernel memory, or firmware.
  It writes only under `/opt` and `/run`.
* A firmware update can replace `/opt/etc/parseinfo.sh`, wipe `/opt`, or change
  the boot units. Re-check persistence after every firmware update.

## Limits

* Requires a firmware with the signed `/usr/bin/node` runtime and the
  `AT-HUB.service` → `/opt/etc/parseinfo.sh` hook (validated statically on
  T-KTM2DEUC 1400.2).
* Requires `/opt` to be writable and persistent on the target.
* Not yet validated on physical hardware; the offline tests cannot prove the
  boot ordering, SMACK policy, or that the vendor script accepts the appended
  block on a real unit.
* No PTY, no TLS, no per-command privilege separation.
* The USB stick is still required for the first install and for recovery if the
  hook is removed.
