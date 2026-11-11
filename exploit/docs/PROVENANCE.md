# Provenance — Samsung Tizen TV (2018 Kant-M2)

## Device

| | |
|---|---|
| Model | `QE49Q6FNA` (Q6F, 49", 2018) |
| Platform | `18_KANTM2_QTV`, Tizen 4.0, Linux 4.1.10, ARMv7 |
| Installed firmware | `T-KTM2DEUC-1400.2` |
| Kernel load base | `0xc0008000` |

## Firmware acquisition

Downloaded from Samsung's firmware download center:

```text
https://org.downloadcenter.samsung.com/content/FM/202607/20260729103150980/T-KTM2DEUC.zip
```

| Artifact | SHA-256 |
|---|---|
| `T-KTM2DEUC.zip` | `0f30e46098495e88f809b637b977c7f3da55ae1603f3ce71d10bf057ace2ada4` |
| `upgrade.msd` | `d913f5fc7e975dd0e7a3d05876886b57b803db08bad75872a780ce9bcfaae435` |
| decrypted `uImage` | `5a9f1c491e0125836a3c75fec0f56b3064563316b06c0e0ecb6f073a185021f5` |
| extracted `kernel.bin` | `3e370858c18794d262a0595bc10fc4af47a2a036473f2855493e508e9dd17567` |

`info.txt` inside the archive reports version 1400.2, build date 2026-06-05
and key `2018_KANTM2_(A)/(R)`.

## Extraction

The working tree used for the port lives outside this repository:

1. `unixtract` opens the `MSDU11` container and yields the partitions.
2. `vdfs-unpack` extracts the Samsung VDFS4 `platform.img` rootfs.
3. The Linux kernel is taken from the decrypted `uImage` and the `.text` is
   extracted as `kernel.bin` at base `0xc0008000`.

The exFAT modules are extracted from the same firmware:

| Module | SHA-256 |
|---|---|
| `exfat_core.ko` | `22f43de04d7ee4ff4183e99474e4b3c0a02a3690f1aa0636961daceebfe602cf` |
| `exfat_fs.ko` | `e86e85c54e7b8feeb1f8bc56ca3ef877bb9bac09da65d8a3b020d76f964f5a90` |

`exfat_core.ko` is byte-identical to the artifact published for this firmware
family. Address re-derivation uses an `inputs/kernel.bin`; that file is not
distributed here. Firmware, modules, decrypted images and device dumps must be
obtained separately and kept out of Git.

## Upstream

Project: <https://github.com/Luminger/samsung-tv-usb-root>

Reference commit: `223f1cd6cca185f93fe7db53ef71eb52963a7086`.

`tools/mk_trigger.py` is copied byte-for-byte from that commit. Its SHA-256 is
`b2dfdd3edf94098c6b5c8c1245ffd186de2a41dfdbd567e523c2ff2b9078b355`.
The upstream LICENSE is retained without modification.

The Kant-M2 work adapts the upstream exFAT entry overflow and fixed-cave
chain. Frame geometry and gadget addresses were checked against the Kant-M2
firmware artifacts listed above. It does not extend upstream's hardware
validation to this target automatically.

## Local changes

* Kant-M2 frame offsets, gadgets and kernel entry points.
* UEP gate at `0xc01cdecc` and the `call_usermodehelper` stage.
* Independent trigger verifier and two-partition USB composer.
* Deterministic FAT32 proof-volume generator.
* Host-side relay and kernel report decoder.
* Optional persistent root daemon for the writable `/opt` partition, started by
  the vendor `AT-HUB.service` → `/opt/etc/parseinfo.sh` hook, plus its
  installer, uninstaller, challenge-response client and offline tests.

The exploit-stage logic is retained as used in the hardware experiments. The
FAT32 generator, build wrapper and persistence tooling are packaging additions,
not a new hardware validation. The persistence path is implemented and tested
offline only; the upstream project's post-exploitation notes and the
`AT-HUB.service` hook found in the T-KTM2DEUC rootfs motivated the design, but
no upstream persistent-daemon code is copied.

## License

This is derivative work distributed under AGPL-3.0-only. Luminger's
attribution and license must be preserved. Special thanks to Luminger and the
researchers credited by the upstream project.
