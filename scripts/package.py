#!/usr/bin/env python3
"""Create a portable bundle with both binaries, installers and SHA-256 hashes."""
import argparse
import hashlib
from pathlib import Path
import shutil
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, help='Rust target triple')
    parser.add_argument('--binary-dir', type=Path, default=ROOT / 'target/release')
    parser.add_argument('--out-dir', type=Path, default=ROOT / 'target/bundles')
    args = parser.parse_args()
    if not all(c.isalnum() or c in '-_' for c in args.target):
        parser.error('target must contain only letters, numbers, hyphens or underscores')
    version = tomllib.loads((ROOT / 'Cargo.toml').read_text(encoding='utf-8'))['workspace']['package']['version']
    name = f'webrev-{version}-{args.target}'
    windows = 'windows' in args.target
    suffix = '.exe' if windows else ''
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='webrev-bundle-') as temp:
        bundle = Path(temp) / name
        (bundle / 'bin').mkdir(parents=True)
        (bundle / 'scripts').mkdir()
        (bundle / 'docs').mkdir()
        for binary in ('webrev', 'webrev-tui'):
            source = args.binary_dir / (binary + suffix)
            if not source.is_file():
                parser.error(f'missing binary: {source}')
            dest = bundle / 'bin' / source.name
            shutil.copyfile(source, dest)
            dest.chmod(0o755)
        documentation = [p.relative_to(ROOT) for p in sorted((ROOT / 'docs').rglob('*'))
                         if p.suffix in ('.md', '.svg')]
        for relative in ['scripts/install.ps1', 'scripts/install.sh', 'README.md', 'LICENSE', *documentation]:
            destination = bundle / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        manifest = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(bundle).as_posix()}\n'
                           for p in sorted(bundle.rglob('*')) if p.is_file())
        (bundle / 'SHA256SUMS').write_text(manifest, encoding='utf-8', newline='\n')
        if windows:
            archive = args.out_dir / (name + '.zip')
            with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
                for p in sorted(bundle.rglob('*')):
                    if p.is_file():
                        output.write(p, p.relative_to(bundle.parent))
        else:
            archive = args.out_dir / (name + '.tar.gz')
            with tarfile.open(archive, 'w:gz') as output:
                output.add(bundle, arcname=name)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_name(archive.name + '.sha256').write_text(f'{checksum}  {archive.name}\n', encoding='ascii', newline='\n')
    print(archive)


if __name__ == '__main__':
    main()
