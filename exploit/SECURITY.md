# Security / responsible use

This repository contains a working kernel exploit for one Samsung TV firmware
family. Use it only on hardware you own or are explicitly authorized to test.

The port was hardware-tested only on QE49Q6FNA with T-KTM2DEUC 1400.2. The
exFAT bug is present across the Kant-M2 platform, but the kernel addresses are
specific to the kernel image. A mismatch can hang or reboot the TV. Static
compatibility is not permission to use an image on another set.

Before testing:

* keep the official firmware recovery image available;
* verify the generated image checksum and the destination block device;
* keep the USB stick inserted for every cold boot unless you have installed
  and verified the optional [persistent daemon](docs/PERSISTENCE.md);
* understand that a failed p1 trigger can require a power cycle.

The persistent daemon is a root service with a plain-TCP protocol. The token is
generated on the TV and never transmitted, but commands and output are not
encrypted. Anyone with the token has root-equivalent access. Use the daemon
only on a trusted LAN, or forward it through SSH/VPN; never expose its port to
the internet. Protect `/opt/kant-root/token` like an SSH private key and remove
the daemon with `uninstall.sh` when it is no longer needed.

Do not submit device-private certificates, keys, serial numbers, live
inventory, or proprietary firmware/modules to this repository. Never commit an
installed token, daemon log, or device dump.

For security-sensitive contact, open a minimal GitHub issue requesting a
private channel; do not attach secrets or affected third-party data.
