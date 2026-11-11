# Payload

The current payload is generated as ARM assembly by the kernel-stage tools.
UMH variants embed a Bash command and require an explicit listener address.
There is no separately shipped SSH server or bootstrap binary in this port.

The optional persistent root in [`../persist/`](../persist/) is a JavaScript
daemon run by the signed `/usr/bin/node`, not an unsigned kernel payload. It is
installed from the root shell after the USB boot and is not part of the USB
image. See [../docs/PERSISTENCE.md](../docs/PERSISTENCE.md).

Upstream's Dropbear-based payload is not copied here. Its functionality and
validation must not be inferred from the upstream directory layout.
