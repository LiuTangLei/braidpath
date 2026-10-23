"""Release-boundary checks that run on Unix and Windows."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import release


def binary_header(asset):
    """Minimal format fixtures, not executable smoke-test replacements."""
    arch = asset.removesuffix('.exe').rsplit('-', 1)[1]
    data = bytearray(128)
    if '-linux-' in asset or '-freebsd-' in asset:
        data[:6] = b'\x7fELF' + bytes([1 if arch in ('386', 'armv6', 'armv7') else 2, 1])
        struct.pack_into('<H', data, 18, {'amd64': 62, '386': 3, 'arm64': 183, 'armv6': 40, 'armv7': 40}[arch])
    elif '-darwin-' in asset:
        data[:4] = b'\xcf\xfa\xed\xfe'
        struct.pack_into('<I', data, 4, {'amd64': 0x1000007, 'arm64': 0x100000C}[arch])
    else:
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 0x3C, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<H', data, 68, {'amd64': 0x8664, '386': 0x14C, 'arm64': 0xAA64}[arch])
    return data


class ReleaseBoundaryTests(unittest.TestCase):
    def test_optimized_python_rejects_wrong_machine_before_packaging(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            binary = directory / 'input'
            binary.write_bytes(binary_header('braidpath-linux-amd64'))
            output = directory / 'dist'
            result = subprocess.run([
                sys.executable, '-O', str(release.ROOT / 'scripts/release.py'),
                'package', '--target', 'aarch64-unknown-linux-musl',
                '--source', str(binary), '--output', str(output),
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('wrong machine', result.stderr)
            self.assertFalse(output.exists())

    def test_optimized_python_rejects_wrong_release_tag(self):
        result = subprocess.run([
            sys.executable, '-O', str(release.ROOT / 'scripts/release.py'),
            'check-tag', 'v0.0.0-wrong-release',
        ], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Release tag must match', result.stderr)

    def test_complete_manifest_matches_all_platform_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            names = [item['asset'] for item in release.TARGETS]
            for name in names:
                (directory / name).write_bytes(binary_header(name))
            for name in ['install.sh', 'install.ps1', 'LICENSE', 'NOTICE']:
                names.append(name)
                (directory / name).write_bytes(name.encode('ascii'))
            release.checksums(directory)
            lines = (directory / 'SHA256SUMS').read_text().splitlines()
            self.assertEqual(lines, [
                hashlib.sha256((directory / name).read_bytes()).hexdigest() + '  ' + name
                for name in sorted(names)
            ])


if __name__ == '__main__':
    unittest.main()
