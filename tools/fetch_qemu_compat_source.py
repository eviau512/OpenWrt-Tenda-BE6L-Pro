# SPDX-License-Identifier: MIT
"""Fetch and verify official QEMU source for an optional ABI-compatibility study.

No emulator is built or executed. This does not establish native Cortex-A53
package compatibility or authorize target installation of downloaded binaries.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import urllib.request

VERSION = '11.1.3'
FINGERPRINT = 'CEACC9E15534EBABB82D3FA03353C9CEF108B584'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--cached-downloads', type=Path,
                        help='Read prior downloads; repeat the complete signature check')
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-qemu-source-'):
        parser.error('Use a fresh /root/be6l-qemu-source-* directory')
    work.mkdir(mode=0o700)
    base = 'https://download.qemu.org/qemu-' + VERSION + '.tar.xz'
    urls = {'source.tar.xz': base, 'source.tar.xz.sig': base + '.sig',
            'release-key.asc': 'https://keys.openpgp.org/vks/v1/by-fingerprint/' + FINGERPRINT}
    for name, url in urls.items():
        limit = 256 * 1024 * 1024 if name == 'source.tar.xz' else 1024 * 1024
        if args.cached_downloads:
            cached = args.cached_downloads / name
            if cached.is_symlink() or not cached.is_file() or cached.stat().st_size > limit:
                raise ValueError('Unexpected cached download')
            shutil.copyfile(cached, work / name)
            total = cached.stat().st_size
        else:
            request = urllib.request.Request(url, headers={'User-Agent': 'BE6L-source-verification/1'})
            with urllib.request.urlopen(request, timeout=120) as incoming, (work / name).open('xb') as output:
                total = 0
                while block := incoming.read(1024 * 1024):
                    total += len(block)
                    if total > limit:
                        raise ValueError('Unexpected download size')
                    output.write(block)
        print('FETCHED', name, total, flush=True)
    home = work / 'gnupg'
    home.mkdir(mode=0o700)
    dearmor = subprocess.run(['gpg', '--no-options', '--homedir', str(home), '--batch',
        '--dearmor', '--output', str(work / 'release-key.gpg'), str(work / 'release-key.asc')],
        capture_output=True)
    (work / 'dearmor.log').write_bytes(dearmor.stdout + dearmor.stderr)
    if dearmor.returncode:
        raise RuntimeError('Isolated public-key decoding failed')
    verified = subprocess.run(['gpgv', '--homedir', str(home), '--keyring', str(work / 'release-key.gpg'),
        '--status-fd', '1', str(work / 'source.tar.xz.sig'), str(work / 'source.tar.xz')], capture_output=True)
    (work / 'signature.log').write_bytes(verified.stdout + verified.stderr)
    signatures = [line.decode().split() for line in verified.stdout.splitlines()
                  if line.startswith(b'[GNUPG:] VALIDSIG ')]
    if verified.returncode or not signatures or not any(
            fields[2] == FINGERPRINT or fields[-1] == FINGERPRINT for fields in signatures):
        raise ValueError('Official QEMU release signature/fingerprint not verified')
    source = work / 'source'
    source.mkdir()
    with tarfile.open(work / 'source.tar.xz', 'r:xz') as archive:
        for member in archive.getmembers():
            if not member.name.startswith('qemu-' + VERSION + '/') and member.name != 'qemu-' + VERSION:
                raise ValueError('Unexpected source archive root')
        # System-firmware subprojects are unnecessary for linux-user and
        # include an upstream absolute X11 symlink. Do not relax data_filter.
        members = [member for member in archive.getmembers()
                   if not member.name.startswith('qemu-' + VERSION + '/roms/')
                   and member.name != 'qemu-' + VERSION + '/roms']
        archive.extractall(source, members=members, filter='data')
    report = dict(version=VERSION, release_page='https://www.qemu.org/download/',
        urls=urls, sha256={name: sha(work / name) for name in urls},
        signing_primary_fingerprint=FINGERPRINT, official_signature_verified=True,
        sources_extracted=True, emulator_built=False, target_executed=False,
        source_tree_scope='linux-user study; upstream roms/ firmware subtree omitted',
        standard_a53_package_compatibility_qualified=False,
        purpose='Optional instruction-emulation fallback; native execution remains preferred')
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('OFFICIAL_QEMU_SOURCE_SIGNATURE_VERIFIED', sha(work / 'source.tar.xz'), flush=True)


if __name__ == '__main__':
    main()
