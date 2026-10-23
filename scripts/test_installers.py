"""Isolated installer contracts. No root writes, downloads, or host services."""
import hashlib
import json
import os
import re
import sys
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import release

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'install.sh'


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='braidpath-installer-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.prefix = self.root / "prefix with 'quote"
        self.mock = self.root / 'commands'
        self.mock.mkdir()
        self.env = dict(os.environ, PATH=str(self.mock) + os.pathsep + os.environ['PATH'], TEST_OS='Linux', TEST_ARCH='x86_64', TEST_BITS='64', TEST_PAYLOAD=str(self.root))
        self.command('uname', 'case "$1" in -s) echo "$TEST_OS";; -m) echo "$TEST_ARCH";; esac')
        self.command('getconf', 'echo "$TEST_BITS"')
        self.command('sysctl', 'echo 0')
        self.binary = self.root / 'fixture'
        self.binary.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo "braidpath 0.1.0"; else printf "%s\\n" "$@"; fi\n')
        self.binary.chmod(0o755)

    def command(self, name, body):
        path = self.mock / name
        path.write_text('#!/bin/sh\nset -eu\n' + body + '\n')
        path.chmod(0o755)

    def run_install(self, *args, success=True, prefix=True):
        result = subprocess.run(['sh', str(SCRIPT), *(['--prefix', str(self.prefix)] if prefix else []), *map(str, args)], env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        return result

    def download_fixture(self):
        asset = 'braidpath-linux-amd64'
        (self.root / asset).write_bytes(self.binary.read_bytes())
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        (self.root / 'SHA256SUMS').write_text(f'{digest}  {asset}\n')
        (self.root / 'latest').write_text('{"tag_name":"v0.1.0"}')
        self.command('curl', '''url=; output=
while [ "$#" -gt 0 ]; do
 case "$1" in https://*) url=$1; shift;; -o) output=$2; shift 2;; *) shift;; esac
done
[ -n "$url" ] && [ -n "$output" ]
cp "$TEST_PAYLOAD/${url##*/}" "$output"''')

    def test_all_unix_release_targets_and_32_bit_userspace(self):
        cases = [('Linux','x86_64','64','linux-amd64'), ('Linux','x86_64','32','linux-386'), ('Linux','i686','32','linux-386'), ('Linux','aarch64','64','linux-arm64'), ('Linux','aarch64','32','linux-armv7'), ('Linux','armv7l','32','linux-armv7'), ('Linux','armv6l','32','linux-armv6'), ('Darwin','x86_64','64','darwin-amd64'), ('Darwin','arm64','64','darwin-arm64'), ('FreeBSD','amd64','64','freebsd-amd64')]
        assets = {t['asset'] for t in release.TARGETS}
        for system, arch, bits, suffix in cases:
            with self.subTest(system=system,arch=arch,bits=bits):
                self.env.update(TEST_OS=system,TEST_ARCH=arch,TEST_BITS=bits)
                result = self.run_install('--print-target')
                self.assertEqual(result.stdout.strip(), 'braidpath-' + suffix)
                self.assertIn(result.stdout.strip(), assets)

    def test_freebsd_arm64_requires_source_build_without_writes(self):
        for architecture in ['aarch64', 'arm64']:
            with self.subTest(architecture=architecture):
                self.env.update(TEST_OS='FreeBSD', TEST_ARCH=architecture)
                result = self.run_install('--print-target', success=False)
                self.assertIn('No supported release asset', result.stderr)
                self.assertFalse(self.prefix.exists())

    def test_rosetta_uses_native_arm64(self):
        self.env.update(TEST_OS='Darwin', TEST_ARCH='x86_64')
        self.command('sysctl', 'echo 1')
        self.assertEqual(self.run_install('--print-target').stdout.strip(), 'braidpath-darwin-arm64')

    def test_unknown_platform_and_architecture_are_rejected(self):
        for system, arch in [('Linux','mips'), ('Linux','s390x'), ('NetBSD','x86_64')]:
            self.env.update(TEST_OS=system,TEST_ARCH=arch)
            self.run_install('--print-target',success=False)

    def test_install_upgrade_uninstall_preserves_config_and_keys(self):
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.run_install('--local',self.binary,'--sha256',digest)
        config = self.prefix / 'etc/braidpath/args'
        self.assertIn('--relay-ports\n44400-44463\n', config.read_text())
        state = self.prefix / 'var/lib/braidpath/node'
        state.mkdir()
        key = state / 'server-key.json'
        key.write_text('keep this secret')
        config.write_text('get\n--entrance\n127.0.0.1:9001\n')
        self.run_install('--local',self.binary)
        self.assertEqual(config.read_text(),'get\n--entrance\n127.0.0.1:9001\n')
        self.run_install('--remove')
        self.assertFalse((self.prefix/'bin/braidpath').exists())
        self.assertEqual(key.read_text(),'keep this secret')
        self.assertTrue(config.exists())

    def test_runner_does_not_evaluate_configuration(self):
        self.run_install('--local',self.binary)
        config = self.prefix / 'etc/braidpath/args'
        marker = self.root / 'must-not-exist'
        values = ['echo','with spaces',f'$(touch {marker})',f'`touch {marker}`','single \' and " double']
        config.write_bytes(('# comment\r\n\r\n'+'\r\n'.join(values)).encode())
        result = subprocess.check_output([str(self.prefix/'libexec/braidpath-run'),str(config)],text=True)
        self.assertEqual(result.splitlines(),values)
        self.assertFalse(marker.exists())

    def test_checksum_failure_preserves_installed_binary(self):
        self.run_install('--local',self.binary)
        before=(self.prefix/'bin/braidpath').read_bytes()
        self.run_install('--local',self.binary,'--sha256','0'*64,success=False)
        self.assertEqual((self.prefix/'bin/braidpath').read_bytes(),before)
        self.assertFalse((self.prefix/'lib/braidpath/install.lock').exists())

    def test_verified_download_and_update_check(self):
        self.download_fixture()
        self.run_install()
        result=self.run_install('--check')
        self.assertIn('Installed: braidpath 0.1.0',result.stdout)
        self.assertIn('Latest: v0.1.0',result.stdout)

    def test_duplicate_missing_and_corrupt_downloads_fail_closed(self):
        self.download_fixture()
        manifest=self.root/'SHA256SUMS'
        original=manifest.read_text()
        for invalid in [original+original,'','0'*64+'  braidpath-linux-amd64\n']:
            manifest.write_text(invalid)
            self.run_install(success=False)
            self.assertFalse((self.prefix/'bin/braidpath').exists())

    def test_wrong_version_and_unmanaged_binary_are_not_replaced(self):
        self.download_fixture()
        self.run_install('--version','v9.9.9',success=False)
        self.prefix.joinpath('bin').mkdir(parents=True)
        destination=self.prefix/'bin/braidpath'
        destination.write_text('user file')
        self.run_install('--local',self.binary,success=False)
        self.assertEqual(destination.read_text(),'user file')

    def test_dry_run_and_bad_arguments_do_not_write(self):
        self.run_install('--dry-run')
        self.assertFalse(self.prefix.exists())
        for args in [('--version',),('--version','../../escape'),('--version','v1;echo'),('--remove','--local',self.binary),('--check','--remove'),('--service','bad'),('--sha256','0'*64)]:
            self.run_install(*args,success=False)
        self.assertFalse(self.prefix.exists())

    def test_unrecognized_receipt_does_not_adopt_an_existing_program(self):
        metadata = self.prefix/'lib/braidpath'
        metadata.mkdir(parents=True)
        (metadata/'installed').write_text('not an installer receipt\nnone\n')
        self.prefix.joinpath('bin').mkdir()
        destination = self.prefix/'bin/braidpath'
        destination.write_text('user program')
        self.run_install('--local', self.binary, success=False)
        self.assertEqual(destination.read_text(), 'user program')

    def test_concurrent_installer_is_rejected(self):
        lock=self.prefix/'lib/braidpath/install.lock'
        lock.mkdir(parents=True)
        self.run_install('--local',self.binary,success=False)
        self.assertTrue(lock.is_dir())
        self.assertFalse((self.prefix/'bin/braidpath').exists())


class ReleaseTests(unittest.TestCase):
    def test_asset_and_target_names_are_unique(self):
        self.assertEqual(len(release.TARGETS),11)
        for field in ['asset','target']:
            self.assertEqual(len({t[field] for t in release.TARGETS}),len(release.TARGETS))

    def test_release_cli_dispatches_package_and_tag_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / 'binary'
            data = bytearray(64)
            data[:6] = b'\x7fELF\x02\x01'
            struct.pack_into('<H', data, 18, 183)
            binary.write_bytes(data)
            subprocess.run([sys.executable, str(ROOT/'scripts/release.py'), 'package', '--target', 'aarch64-unknown-linux-musl', '--source', str(binary), '--output', str(root/'dist')], check=True)
            self.assertEqual((root/'dist/braidpath-linux-arm64').read_bytes(), data)
            version = re.search(r'^version = "([^"]+)"$', (ROOT/'Cargo.toml').read_text(), re.MULTILINE).group(1)
            subprocess.run([sys.executable, str(ROOT/'scripts/release.py'), 'check-tag', 'v'+version], check=True)

    def test_wrong_binary_machine_and_missing_assets_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'binary'
            data=bytearray(64)
            data[:6]=b'\x7fELF\x02\x01'
            struct.pack_into('<H',data,18,183)
            path.write_bytes(data)
            release.validate_binary(path,'braidpath-linux-arm64')
            with self.assertRaises(ValueError): release.validate_binary(path,'braidpath-linux-amd64')
            with self.assertRaises(FileNotFoundError): release.checksums(directory)


if __name__ == '__main__':
    unittest.main()
