#!/usr/bin/env python3
"""Shared release matrix, binary identity checks, and complete-release checksums."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import re

ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / 'scripts/release-targets.json').read_text())


def require(condition, message):
    # Release validation must also run when Python optimization is enabled.
    if not condition:
        raise ValueError(message)


def validate_binary(path, asset):
    data = Path(path).read_bytes()
    arch = asset.removesuffix('.exe').rsplit('-', 1)[1]
    if '-linux-' in asset or '-freebsd-' in asset:
        require(data[:4] == b'\x7fELF' and data[5] == 1, f'{asset}: expected little-endian ELF')
        require(data[4] == (1 if arch in ('386', 'armv6', 'armv7') else 2), f'{asset}: wrong word size')
        require(struct.unpack_from('<H', data, 18)[0] == {'amd64': 62, '386': 3, 'arm64': 183, 'armv6': 40, 'armv7': 40}[arch], f'{asset}: wrong machine')
    elif '-darwin-' in asset:
        require(data[:4] == b'\xcf\xfa\xed\xfe', f'{asset}: expected Mach-O 64')
        require(struct.unpack_from('<I', data, 4)[0] == {'amd64': 0x1000007, 'arm64': 0x100000C}[arch], f'{asset}: wrong machine')
    elif '-windows-' in asset:
        require(data[:2] == b'MZ', f'{asset}: expected PE executable')
        start = struct.unpack_from('<I', data, 0x3C)[0]
        require(data[start:start+4] == b'PE\0\0', f'{asset}: invalid PE signature')
        require(struct.unpack_from('<H', data, start+4)[0] == {'amd64': 0x8664, '386': 0x14C, 'arm64': 0xAA64}[arch], f'{asset}: wrong machine')
    else:
        raise ValueError(f'Unknown release asset: {asset}')


def package(target, output, source=None):
    item = next(item for item in TARGETS if item['target'] == target)
    executable = 'braidpath.exe' if item['asset'].endswith('.exe') else 'braidpath'
    source = Path(source) if source else ROOT / 'target' / target / 'release' / executable
    validate_binary(source, item['asset'])
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, output / item['asset'])


def checksums(directory):
    directory = Path(directory)
    # An incomplete matrix must never be presented as a complete release.
    for item in TARGETS:
        validate_binary(directory / item['asset'], item['asset'])
    names = sorted([item['asset'] for item in TARGETS] + ['install.sh', 'install.ps1', 'LICENSE', 'NOTICE'])
    lines = []
    for name in names:
        digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        lines.append(f'{digest}  {name}\n')
    (directory / 'SHA256SUMS').write_text(''.join(lines), encoding='ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    matrix = commands.add_parser('matrix')
    matrix.add_argument('kind', choices=['cross', 'native', 'freebsd'])
    stage = commands.add_parser('package')
    stage.add_argument('--target', required=True)
    stage.add_argument('--output', default='dist')
    stage.add_argument('--source')
    sums = commands.add_parser('checksums')
    sums.add_argument('directory')
    tag = commands.add_parser('check-tag')
    tag.add_argument('tag')
    args = parser.parse_args()
    if args.command == 'matrix':
        print(json.dumps({'include': [item for item in TARGETS if item['kind'] == args.kind]}, separators=(',', ':')))
    elif args.command == 'package':
        package(args.target, args.output, args.source)
    elif args.command == 'checksums':
        checksums(args.directory)
    else:
        package_section = (ROOT / 'Cargo.toml').read_text().split('[package]', 1)[1].split('\n[', 1)[0]
        version = re.search(r'^version = "([^"]+)"$', package_section, re.MULTILINE).group(1)
        require(args.tag == 'v' + version, 'Release tag must match Cargo.toml version')


if __name__ == '__main__':
    main()
