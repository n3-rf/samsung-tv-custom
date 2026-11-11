# SPDX-License-Identifier: AGPL-3.0-only
"""Offline checks for the persistent root daemon and installer.

The daemon tests only run when a Node.js binary is available; they never touch
a TV, a disk device or the network beyond loopback.
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools'
sys.path.insert(0, str(TOOLS))
import kant_rootctl

TOKEN = 'ab' * 32
NODE = os.environ.get('KANT_TEST_NODE') or shutil.which('node')


def write_fake_firmware(prefix):
    """Create the minimum tree the installer inspects under a test prefix."""
    (prefix / 'opt/etc').mkdir(parents=True)
    unit_dir = prefix / 'usr/lib/systemd/system'
    unit_dir.mkdir(parents=True)
    (unit_dir / 'AT-HUB.service').write_text(
        '[Service]\nExecStart=/opt/etc/parseinfo.sh &\n')
    node = prefix / 'usr/bin/node'
    node.parent.mkdir(parents=True)
    node.write_text('#!/bin/sh\nexit 1\n')
    node.chmod(0o755)
    hook = prefix / 'opt/etc/parseinfo.sh'
    hook.write_text('#!/bin/sh\nvendorfw=1\n')
    hook.chmod(0o755)
    return hook


def build_bundle(directory):
    result = subprocess.run(
        [sys.executable, str(TOOLS / 'build_persist_bundle.py'),
         '--out-dir', str(directory)],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return directory


class BundleChecks(unittest.TestCase):
    def test_bundle_embeds_daemon_and_is_syntax_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            out = build_bundle(Path(directory) / 'bundle')
            installer = (out / 'install.sh').read_text()
            uninstaller = (out / 'uninstall.sh').read_text()
            daemon = (ROOT / 'persist/rootd.js').read_text()
            self.assertNotIn('@@KANT_ROOTD@@', installer)
            self.assertIn(daemon, installer)
            self.assertEqual((out / 'install.sh').stat().st_mode & 0o777, 0o755)
            self.assertEqual((out / 'uninstall.sh').stat().st_mode & 0o777, 0o755)
            self.assertIn('KANT_ROOT_UNINSTALL_OK'.replace('_', '-'), uninstaller)
            for script in (out / 'install.sh', out / 'uninstall.sh'):
                check = subprocess.run(['sh', '-n', str(script)],
                                       capture_output=True, text=True)
                self.assertEqual(check.returncode, 0, check.stderr)
            manifest = json.loads((out / 'manifest.json').read_text())
            self.assertEqual(manifest['daemon_sha256'],
                             hashlib.sha256((ROOT / 'persist/rootd.js').read_bytes()).hexdigest())
            for name, info in manifest['files'].items():
                data = (out / name).read_bytes()
                self.assertEqual(info['bytes'], len(data))
                self.assertEqual(info['sha256'], hashlib.sha256(data).hexdigest())

    def test_build_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            out = build_bundle(Path(directory) / 'bundle')
            again = subprocess.run(
                [sys.executable, str(TOOLS / 'build_persist_bundle.py'),
                 '--out-dir', str(out)],
                capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)


class InstallerChecks(unittest.TestCase):
    def install(self, bundle, prefix, *extra):
        return subprocess.run(
            ['sh', str(bundle / 'install.sh'), '--prefix', str(prefix),
             '--no-start', '--quiet', *extra],
            capture_output=True, text=True)

    def test_install_is_idempotent_and_preserves_vendor_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            prefix = base / 'prefix'
            hook = write_fake_firmware(prefix)
            original = hook.read_text()
            bundle = build_bundle(base / 'bundle')

            first = self.install(bundle, prefix)
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            token = None
            for line in first.stdout.splitlines():
                if line.startswith('KANT-ROOT-TOKEN='):
                    token = line.split('=', 1)[1]
            self.assertIsNotNone(token)
            self.assertRegex(token, r'^[0-9a-f]{64}$')

            root = prefix / 'opt/kant-root'
            self.assertEqual((root / 'token').read_text().strip(), token)
            self.assertEqual((root / 'token').stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / 'rootd.js').read_text(),
                             (ROOT / 'persist/rootd.js').read_text())
            self.assertEqual((root / 'env').stat().st_mode & 0o777, 0o600)
            self.assertTrue((root / 'boot.sh').stat().st_mode & 0o100)
            self.assertIn('kant-rootd.service', (root / 'boot.sh').read_text())
            self.assertEqual((hook.with_name('parseinfo.sh.kant-orig')).read_text(), original)

            installed = hook.read_text()
            lines = installed.splitlines()
            self.assertEqual(lines[0], '#!/bin/sh')
            self.assertEqual([line for line in lines if line == 'vendorfw=1'],
                             ['vendorfw=1'])
            self.assertEqual(installed.count('# >>> kant-root >>>'), 1)
            self.assertEqual(installed.count('# <<< kant-root <<<'), 1)

            second = self.install(bundle, prefix)
            self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
            self.assertIn('KANT-ROOT-TOKEN=' + token, second.stdout)
            self.assertEqual(hook.read_text().count('# >>> kant-root >>>'), 1)

    def test_install_rejects_bad_token_and_missing_hook(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            prefix = base / 'prefix'
            write_fake_firmware(prefix)
            bundle = build_bundle(base / 'bundle')
            bad = self.install(bundle, prefix, '--token', 'xyz')
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn('64 hexadecimal', bad.stderr)

            (prefix / 'opt/etc/parseinfo.sh').write_bytes(b'\x7fELF not a script\n')
            not_script = self.install(bundle, prefix)
            self.assertNotEqual(not_script.returncode, 0)
            self.assertIn('shebang', not_script.stderr)

            (prefix / 'usr/lib/systemd/system/AT-HUB.service').write_text('[Service]\n')
            missing = self.install(bundle, prefix)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn('parseinfo.sh', missing.stderr)

    def test_uninstall_removes_only_the_marked_block(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            prefix = base / 'prefix'
            hook = write_fake_firmware(prefix)
            bundle = build_bundle(base / 'bundle')
            self.assertEqual(self.install(bundle, prefix).returncode, 0)

            result = subprocess.run(
                ['sh', str(bundle / 'uninstall.sh'), '--prefix', str(prefix),
                 '--purge', '--quiet'],
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('# >>> kant-root >>>', hook.read_text())
            self.assertEqual([line for line in hook.read_text().splitlines() if line.strip()],
                             ['#!/bin/sh', 'vendorfw=1'])
            self.assertFalse((prefix / 'opt/kant-root').exists())
            self.assertFalse((prefix / 'run/systemd/system/kant-rootd.service').exists())


class ClientChecks(unittest.TestCase):
    def start_server(self, token=TOKEN, nonce='cd' * 32):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        seen = {}

        def serve():
            conn, _ = listener.accept()
            with conn:
                stream = conn.makefile('rwb', buffering=0)
                stream.write(('KANT-ROOT/1 %s\n' % nonce).encode())
                line = stream.readline().decode().strip()
                seen['auth'] = line
                expected = hmac.new(bytes.fromhex(token), nonce.encode(),
                                    hashlib.sha256).hexdigest()
                if line != 'AUTH ' + expected:
                    stream.write(b'DENY\n')
                    return
                stream.write(b'OK 1.0.0\n')
                while True:
                    line = stream.readline()
                    if not line:
                        return
                    frame = line.decode().strip()
                    seen.setdefault('frames', []).append(frame)
                    if frame == 'PING':
                        stream.write(b'PONG\n')
                    elif frame == 'QUIT':
                        stream.write(b'BYE\n')
                        return
                    elif frame.startswith('EXEC\t'):
                        _, seq, _timeout, payload = frame.split('\t')
                        command = base64.b64decode(payload).decode()
                        out = base64.b64encode(('ran:' + command).encode()).decode()
                        err = base64.b64encode(b'').decode()
                        stream.write(('RESULT\t%s\t0\t0\t%s\t%s\n'
                                      % (seq, out, err)).encode())

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(listener.close)
        return port, seen, thread

    def test_client_authenticates_pings_and_executes(self):
        port, seen, thread = self.start_server()
        client = kant_rootctl.Client('127.0.0.1', port, TOKEN)
        try:
            client.ping()
            result = client.execute('id', 5000)
        finally:
            client.close()
        thread.join(timeout=5)
        self.assertEqual(result['exit'], 0)
        self.assertEqual(result['stdout'], 'ran:id')
        self.assertFalse(result['timedout'])
        self.assertIn('PING', seen['frames'])
        self.assertTrue(seen['auth'].startswith('AUTH '))

    def test_client_rejects_wrong_token(self):
        port, _, thread = self.start_server()
        with self.assertRaises(ConnectionError):
            kant_rootctl.Client('127.0.0.1', port, 'ef' * 32)
        thread.join(timeout=5)


@unittest.skipUnless(NODE, 'Node.js is not installed; set KANT_TEST_NODE to test the daemon')
class DaemonChecks(unittest.TestCase):
    def start_daemon(self):
        directory = Path(tempfile.mkdtemp(prefix='kant-rootd-test-'))
        self.addCleanup(shutil.rmtree, directory, True)
        (directory / 'token').write_text(TOKEN + '\n')
        env = dict(os.environ)
        env.update({
            'KANT_ROOT_ALLOW_NONROOT': '1',
            'KANT_ROOT_DIR': str(directory),
            'KANT_ROOT_TOKEN_FILE': str(directory / 'token'),
            'KANT_ROOT_BIND': '127.0.0.1',
            'KANT_ROOT_PORT': '0',
            'KANT_ROOT_PORT_FILE': str(directory / 'port'),
            'KANT_ROOT_LOG': str(directory / 'rootd.log'),
            'KANT_ROOT_PID': str(directory / 'rootd.pid'),
            'KANT_ROOT_LOCK': str(directory / 'rootd.lock'),
        })
        process = subprocess.Popen([NODE, str(ROOT / 'persist/rootd.js')],
                                   env=env, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)

        def stop():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

        self.addCleanup(stop)
        port_file = directory / 'port'
        for _ in range(200):
            if port_file.exists():
                break
            if process.poll() is not None:
                log = directory / 'rootd.log'
                self.fail(log.read_text() if log.exists() else 'daemon exited')
            time.sleep(0.025)
        else:
            self.fail('daemon did not report its port')
        return process, int(port_file.read_text()), directory

    def test_exec_and_shell(self):
        process, port, directory = self.start_daemon()
        client = kant_rootctl.Client('127.0.0.1', port, TOKEN)
        try:
            client.ping()
            result = client.execute('printf "out"; printf "err" >&2; exit 3', 5000)
            self.assertEqual(result['exit'], 3)
            self.assertEqual(result['stdout'], 'out')
            self.assertEqual(result['stderr'], 'err')
        finally:
            client.close()

        sock = socket.create_connection(('127.0.0.1', port), timeout=5)
        try:
            stream = sock.makefile('rwb', buffering=0)
            nonce = stream.readline().decode().split()[1]
            expected = hmac.new(bytes.fromhex(TOKEN), nonce.encode(),
                                hashlib.sha256).hexdigest()
            stream.write(('AUTH %s\n' % expected).encode())
            self.assertTrue(stream.readline().startswith(b'OK'))
            stream.write(b'SHELL\nprintf "SHELL-OK\\n"; exit 0\n')
            sock.settimeout(10)
            output = b''
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                output += chunk
        finally:
            sock.close()
        self.assertIn(b'SHELL-OK', output)
        self.assertIn(b'[kant-root shell exited]', output)
        process.terminate()
        process.wait(timeout=10)
        log = (directory / 'rootd.log').read_text()
        self.assertNotIn(TOKEN, log)

    def test_wrong_token_is_denied(self):
        _, port, _ = self.start_daemon()
        with self.assertRaises(Exception):
            kant_rootctl.Client('127.0.0.1', port, 'ef' * 32)


if __name__ == '__main__':
    unittest.main()
