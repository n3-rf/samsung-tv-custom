# Persistence sources

`rootd.js` is the daemon installed on the TV. `install.sh.in` is the installer
template; `tools/build_persist_bundle.py` embeds the daemon and writes the
self-contained `out/persist/install.sh`. `uninstall.sh` removes the hook and,
optionally, the installed directory.

The installer and daemon use only files and executables already present on the
firmware:

* `/usr/bin/node` to run the daemon;
* `/bin/bash` for commands and the optional shell;
* `/bin/sh` for `boot.sh`;
* `openssl` or `dd`/`od` to generate the token at install time.

Nothing here is an unsigned ELF that must pass the UEP verifier. The daemon
survives reboot because the vendor boot script on the writable `/opt` partition
starts it again.

See [../docs/PERSISTENCE.md](../docs/PERSISTENCE.md) for the operator procedure
and the security model. Offline checks live in
[`../tests/test_persistence.py`](../tests/test_persistence.py).
