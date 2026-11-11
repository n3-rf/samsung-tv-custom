# Host-side tools

`decode_kbeacon.py` decodes saved kernel report packets. Its report must be
interpreted alongside device-side evidence: a queued helper is not proof
that a root command executed.

`relay_shell_4445.py` is the Bash relay used during the UMH experiments. It
requires explicit listener and output paths:

```sh
python lab/relay_shell_4445.py --bind 0.0.0.0 --port 4445 \
  --log out/root_shell.log --commands out/cmds.txt
```

Create `out/` first and bind to an address the TV can reach. This starts a
network listener and is not part of the offline build. Append commands only
after a shell connection is reported. On reconnect, existing queue bytes are
skipped so old commands are not replayed. Output is appended rather than
silently truncated. Session logs and command queues are local operator files
and must not be committed.

No QEMU lab, proprietary kernel modules or firmware image is shipped here.
The upstream project documents its own vendor-kernel lab.
