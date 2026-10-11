#!/usr/bin/env python3
"""Smoke-test a native bundle installation, including rejection of corruption."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--bundles-dir', type=Path, default=ROOT / 'target/bundles')
    args = parser.parse_args()
    archives = list(args.bundles_dir.glob(f'*-{args.target}.zip')) + list(args.bundles_dir.glob(f'*-{args.target}.tar.gz'))
    if len(archives) != 1:
        parser.error(f'expected one native archive, found {archives}')
    archive = archives[0]
    assert digest(archive) == archive.with_name(archive.name + '.sha256').read_text().split()[0]
    # All files below this fresh workspace-owned temp directory are test artifacts.
    test_root = ROOT / 'target/install-checks'
    test_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='bundle with spaces ', dir=test_root) as temp:
        work = Path(temp).resolve()
        assert work.is_relative_to(test_root.resolve())
        if archive.suffix == '.zip':
            with zipfile.ZipFile(archive) as data:
                data.extractall(work)
        else:
            with tarfile.open(archive) as data:
                data.extractall(work, filter='data')
        bundle = next(work.glob('webrev-*'))
        installed = work / 'installed binaries'
        if os.name == 'nt':
            shell = shutil.which('pwsh') or shutil.which('powershell')
            assert shell, 'PowerShell required'
            command = [shell, '-NoProfile', '-File', str(bundle / 'scripts/install.ps1'), '-InstallDir', str(installed)]
            names = ['webrev.exe', 'webrev-tui.exe']
        else:
            command = ['sh', str(bundle / 'scripts/install.sh'), '--install-dir', str(installed)]
            names = ['webrev', 'webrev-tui']
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout.strip())
        for name in names:
            assert digest(installed / name) == digest(bundle / 'bin' / name)
            subprocess.run([str(installed / name), '--version'], check=True)
        before = {name: digest(installed / name) for name in names}
        # Corrupt the second source: neither existing destination may change.
        with (bundle / 'bin' / names[1]).open('ab') as binary:
            binary.write(b'checksum-test')
        result = subprocess.run(command, capture_output=True, text=True)
        assert result.returncode != 0, 'corrupt bundle accepted'
        assert 'Checksum mismatch' in result.stdout + result.stderr
        assert before == {name: digest(installed / name) for name in names}
    print('Native bundle: install/version/hash checks passed; corruption rejected before replacement.')


if __name__ == '__main__':
    main()
