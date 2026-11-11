# SPDX-License-Identifier: AGPL-3.0-only
"""Offline image and packaging checks; no network or device access."""
import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from make_proof_volume import create

# Upstream tools/mk_trigger.py at 223f1cd6cca185f93fe7db53ef71eb52963a7086.
UPSTREAM_TRIGGER_SHA256 = (
    'b2dfdd3edf94098c6b5c8c1245ffd186de2a41dfdbd567e523c2ff2b9078b355')


class OfflineChecks(unittest.TestCase):
    def run_tool(self, name, *args, success=True):
        result = subprocess.run([sys.executable, str(ROOT / 'tools' / name), *map(str, args)],
                                capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_fat32_layout_and_determinism(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = [Path(directory) / name for name in ('one.img', 'two.img')]
            create(first)
            create(second)
            def digest(path):
                with path.open('rb') as stream:
                    return hashlib.file_digest(stream, 'sha256').hexdigest()
            self.assertEqual(digest(first), digest(second))
            self.assertEqual(first.stat().st_size, 64 * 1024 * 1024)
            with first.open('rb') as stream:
                boot = stream.read(512)
                self.assertEqual(boot[510:], b'\x55\xaa')
                self.assertEqual(boot[82:90], b'FAT32   ')
                reserved = struct.unpack_from('<H', boot, 14)[0]
                fat_size = struct.unpack_from('<I', boot, 36)[0]
                stream.seek(6 * 512)
                self.assertEqual(stream.read(512), boot)
                stream.seek(reserved * 512)
                fat = stream.read(fat_size * 512)
                self.assertEqual(struct.unpack_from('<III', fat), (0x0FFFFFF8, 0xFFFFFFFF, 0x0FFFFFFF))
                self.assertEqual(stream.read(fat_size * 512), fat)
            with self.assertRaises(FileExistsError):
                create(first)

    def test_trigger_verification_and_wrong_blob_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            payload, cave, image = [out / name for name in ('payload.bin', 'cave.bin', 'p1.img')]
            payload.write_bytes(bytes.fromhex('0110a0e1') * 4)
            self.run_tool('build_cave_blob_kant.py', '--profile', 'kant', '--payload', payload, '--out', cave)
            self.run_tool('build_trigger_kant.py', '--cave-blob', cave, '--out', image)
            result = self.run_tool('verify_trigger_kant.py', image, '--cave-blob', cave)
            self.assertIn('RESULT: PASS', result.stdout)
            altered = bytearray(cave.read_bytes())
            altered[-1] ^= 1
            cave.write_bytes(altered)
            self.run_tool('verify_trigger_kant.py', image, '--cave-blob', cave, success=False)

    def test_network_build_requires_explicit_target(self):
        result = self.run_tool('build.py', '--variant', 'umh-boot', success=False)
        self.assertIn('requires --beacon', result.stderr)
        for endpoint in ('invalid:4444', '192.0.2.10:65535'):
            self.run_tool('build.py', '--variant', 'umh-boot', '--beacon', endpoint, success=False)

    def test_upstream_copy_and_license(self):
        actual = hashlib.sha256((ROOT / 'tools/mk_trigger.py').read_bytes()).hexdigest()
        self.assertEqual(actual, UPSTREAM_TRIGGER_SHA256)
        self.assertTrue((ROOT / 'LICENSE').is_file())
        self.assertIn('GNU AFFERO GENERAL PUBLIC LICENSE', (ROOT / 'LICENSE').read_text())


if __name__ == '__main__':
    unittest.main()
