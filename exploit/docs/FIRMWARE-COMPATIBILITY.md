# Firmware and model compatibility

## Validated target

| Target | Evidence |
|---|---|
| QE49Q6FNA / 18_KANTM2_QTV / T-KTM2DEUC 1400.2 | Interactive root Bash observed on one device |
| Other Kant-M2 models on T-KTM2DEUC | Same exFAT driver path; kernel constants not checked per image |
| Other Kant-M2 firmware releases | Kernel addresses must be re-derived unless the kernel is identical |
| Upstream Muse-M / T-MSMDEUC targets | Outside this port; use the upstream project |

This is a port for the Kant-M2 platform, not for a single TV. The exFAT
`num_ext` overflow lives in the shipped `exfat_core.ko` and is present in the
Kant-M2 driver. The module is byte-identical to the artifact published for
this firmware family, so the vulnerability and the injection geometry carry
across Kant-M2 models that ship the same driver.

The kernel chain is different: the cave address, gadget addresses, UEP gate
and usermode-helper symbol are read from a specific `kernel.bin`. A different
firmware release can change any of them. Matching a version string does not
establish that another device's kernel is identical. Re-derive the constants
from the target image before building for another release.

## Firmware artifacts used for this port

| Artifact | SHA-256 |
|---|---|
| T-KTM2DEUC.zip | `0f30e46098495e88f809b637b977c7f3da55ae1603f3ce71d10bf057ace2ada4` |
| upgrade.msd | `d913f5fc7e975dd0e7a3d05876886b57b803db08bad75872a780ce9bcfaae435` |
| decrypted uImage | `5a9f1c491e0125836a3c75fec0f56b3064563316b06c0e0ecb6f073a185021f5` |
| extracted kernel.bin | `3e370858c18794d262a0595bc10fc4af47a2a036473f2855493e508e9dd17567` |
| exfat_core.ko | `22f43de04d7ee4ff4183e99474e4b3c0a02a3690f1aa0636961daceebfe602cf` |
| exfat_fs.ko | `e86e85c54e7b8feeb1f8bc56ca3ef877bb9bac09da65d8a3b020d76f964f5a90` |

Archive reference:

```text
https://org.downloadcenter.samsung.com/content/FM/202607/20260729103150980/T-KTM2DEUC.zip
```

Firmware and extracted vendor files are not redistributed. The `info.txt`
inside the archive reports version 1400.2, build date 2026-06-05 and key
`2018_KANTM2_(A)/(R)`.

## Operational limits

Without the optional persistent install, the USB stick is required at every
cold boot and root does not survive a restart. The persistent daemon described
in [PERSISTENCE.md](PERSISTENCE.md) removes that requirement, but it has only
been tested offline and depends on the signed `/usr/bin/node` runtime and the
`AT-HUB.service` → `/opt/etc/parseinfo.sh` boot hook. It has not been
boot-validated on a TV. Leaving the stick inserted across several boots
produced a reboot loop on the validated unit.

Static compatibility is not permission to use an image on another set. A wrong
address can hang or reboot the TV.
