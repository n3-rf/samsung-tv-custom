#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Build the self-contained persistence installer.

The TV side needs a single file that can be fetched over HTTP or transferred
through the relay. This tool embeds persist/rootd.js into persist/install.sh.in
and writes out/persist/install.sh plus the standalone uninstaller and a
manifest. It never contacts a TV or a disk device.
"""
import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PERSIST = ROOT / 'persist'
PLACEHOLDER = '@@KANT_ROOTD@@'
DELIMITER = 'KANT_ROOTD_JS_EOF'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', type=Path, default=ROOT / 'out' / 'persist')
    args = parser.parse_args()
    output = args.out_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)

    template = (PERSIST / 'install.sh.in').read_text()
    daemon = (PERSIST / 'rootd.js').read_text()
    if template.count(PLACEHOLDER) != 1:
        raise SystemExit(f'{PERSIST / "install.sh.in"}: expected exactly one {PLACEHOLDER}')
    if any(line == DELIMITER for line in daemon.splitlines()):
        raise SystemExit(f'{PERSIST / "rootd.js"}: contains the heredoc delimiter')
    installer = template.replace(PLACEHOLDER, daemon.rstrip('\n'))
    if PLACEHOLDER in installer:
        raise SystemExit('placeholder was not fully replaced')

    install_path = output / 'install.sh'
    install_path.write_text(installer)
    install_path.chmod(0o755)
    shutil.copy2(PERSIST / 'uninstall.sh', output / 'uninstall.sh')
    (output / 'uninstall.sh').chmod(0o755)

    files = {}
    for path in (install_path, output / 'uninstall.sh'):
        files[path.name] = {'bytes': path.stat().st_size, 'sha256': digest(path)}
    (output / 'manifest.json').write_text(json.dumps({
        'bundle': 'kant-m2-persistent-root',
        'daemon_sha256': digest(PERSIST / 'rootd.js'),
        'files': files,
        'usage': [
            'python3 -m http.server 8000 --bind 0.0.0.0 --directory ' + str(output),
            'On the TV root shell: curl -fsSL http://HOST:8000/install.sh | sh',
        ],
    }, indent=2) + '\n')
    print(f'Persistence bundle: {output}')
    for name, info in files.items():
        print(f'  {name}: {info["bytes"]} bytes sha256={info["sha256"]}')
    print('Serve it with:')
    print(f'  python3 -m http.server 8000 --bind 0.0.0.0 --directory {output}')


if __name__ == '__main__':
    main()
