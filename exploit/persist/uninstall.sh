#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Remove the Kant-M2 persistent root hook and daemon.
set -u

PREFIX=${KANT_PREFIX:-}
PURGE=0
QUIET=0
MARK_BEGIN="# >>> kant-root >>>"
MARK_END="# <<< kant-root <<<"

usage() {
    cat <<'EOF'
Usage: uninstall.sh [options]

  --prefix DIR   uninstall from DIR (offline tests only)
  --purge        also delete /opt/kant-root (token, logs and daemon)
  --quiet        print only the final status
  --help         show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) [ $# -ge 2 ] || { echo "missing value for --prefix" >&2; exit 2; }; PREFIX=$2; shift 2 ;;
        --purge) PURGE=1; shift ;;
        --quiet) QUIET=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

ROOT="$PREFIX/opt/kant-root"
HOOK="$PREFIX/opt/etc/parseinfo.sh"
UNIT="$PREFIX/run/systemd/system/kant-rootd.service"

# Stop the volatile unit before removing it.
if [ -z "$PREFIX" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl stop kant-rootd.service >/dev/null 2>&1 || true
fi
for pidfile in /tmp/kant-rootd.pid "$ROOT/rootd.pid"; do
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            sleep 1
            kill -9 "$pid" 2>/dev/null || true
        fi
    fi
done
rm -f /tmp/kant-rootd.pid /tmp/kant-rootd.lock
rm -f "$UNIT" 2>/dev/null || true
if [ -z "$PREFIX" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Remove only our marked block; leave any vendor content untouched.
if [ -f "$HOOK" ] && grep -q "$MARK_BEGIN" "$HOOK"; then
    tmp="$HOOK.kant-uninstall.$$"
    awk -v begin="$MARK_BEGIN" -v end="$MARK_END" '
        $0 == begin { skip = 1; next }
        $0 == end   { skip = 0; next }
        !skip       { print }
    ' "$HOOK" > "$tmp" && mv "$tmp" "$HOOK"
    chmod 755 "$HOOK" 2>/dev/null || true
fi

# If the installer created parseinfo.sh and nothing else remains, remove it.
if [ -f "$ROOT/hook-created" ] && [ -f "$HOOK" ]; then
    body=$(grep -v '^#!/bin/sh$' "$HOOK" | tr -d ' \t\r\n')
    if [ -z "$body" ]; then rm -f "$HOOK"; fi
fi

if [ "$PURGE" = "1" ]; then
    rm -rf "$ROOT"
fi

if [ "$QUIET" != "1" ]; then
    echo "KANT-ROOT-UNINSTALL-OK"
    echo "hook: $HOOK"
    if [ "$PURGE" = "1" ]; then
        echo "root: removed"
    else
        echo "root: kept (use --purge to delete $ROOT)"
    fi
fi
