# SPDX-License-Identifier: MIT
"""Verify the nine ordinary ABI archives produced by the isolated SDK build."""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
from build_normal_a53_missing_modules_v1 import PACKAGES, TARGETS
from inventory_mainroot_a53_v1 import elf


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'build-work', 'apk', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-normal-a53-archives-') or w.exists():
        p.error('Use a fresh /root/be6l-normal-a53-archives-* directory')
    prior = json.loads((a.build_work/'result.json').read_text())
    if (not prior.get('all_requested_recipes_built') or not prior['terminal'] or
            prior.get('error') or sha(a.sdk/'.config') != prior['effective_sdk_config_sha256']):
        raise ValueError('Complete unchanged ordinary SDK build receipt is required')
    for target in TARGETS:
        if sha(a.sdk/target/'Makefile') != prior['source_recipe_sha256'][target]:
            raise ValueError('Ordinary source recipe changed after build: '+target)
    w.mkdir(mode=0o700)
    key = a.sdk/'public-key.pem'
    if b'PRIVATE' in key.read_bytes():
        raise ValueError('Only the ordinary SDK public key may enter verification trust')
    trust = w/'trust'
    trust.mkdir()
    shutil.copy2(key, trust/key.name)
    archives = list((a.sdk/'bin').rglob('*.apk'))
    result = {}

    def run(label, command):
        r = subprocess.run(list(map(str, command)), capture_output=True, timeout=120)
        (w/(label+'.log')).write_bytes(r.stdout+r.stderr)
        if r.returncode:
            raise RuntimeError(label+' failed; inspect retained log')
        return r.stdout

    for name in PACKAGES:
        found = [f for f in archives if f.name.startswith(name+'-') and
                 f.name[len(name)+1:len(name)+2].isdigit()]
        if len(found) != 1:
            raise ValueError('Expected one newly built ordinary archive: '+name)
        archive, = found
        info = json.loads(run(name+'-metadata', [a.apk, 'adbdump', '--format', 'json', archive]))['info']
        if info['name'] != name or info['arch'] not in ('aarch64_cortex-a53', 'all', 'noarch'):
            raise ValueError('Archive has an unexpected ordinary ABI/name: '+name)
        run(name+'-verify', [a.apk, '--network=no', '--keys-dir', trust, 'verify', archive])
        destination = w/'extracted'/name
        destination.mkdir(parents=True)
        run(name+'-extract', [a.apk, '--network=no', '--keys-dir', trust, 'extract',
                            '--no-chown', '--destination', destination, archive])
        elf_files = {}
        for path in destination.rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            with path.open('rb') as stream:
                magic = stream.read(4)
            if magic != b'\x7fELF':
                continue
            data = elf(path)
            if (not data or data['bits'] != 64 or data['machine'] != 183 or data['e_flags'] != '0x0' or
                    data['interpreter'] not in (None, '/lib/ld-musl-aarch64.so.1')):
                raise ValueError('Nonstandard/private ELF in ordinary archive: '+name)
            elf_files[path.relative_to(destination).as_posix()] = data
        result[name] = dict(file=archive.name, sha256=sha(archive), info=info, elf_files=elf_files,
                            ordinary_signature_verified=True, payload_modified=False)
    report = dict(scope='Actual rebuilt ordinary module archive verification; not a root transaction',
        source_build_receipt_sha256=sha(a.build_work/'result.json'),
        sdk_configuration_sha256=sha(a.sdk/'.config'), source_recipe_sha256=prior['source_recipe_sha256'],
        public_key_sha256=sha(key), packages=result, package_count=len(result),
        ordinary_elf_count=sum(len(row['elf_files']) for row in result.values()),
        all_archive_signatures_verified=True, target_package_scripts_executed=False,
        mainroot_composed=False, target_executed=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('ORDINARY_A53_MODULE_ARCHIVES_VERIFIED', len(result), report['ordinary_elf_count'], flush=True)


if __name__ == '__main__':
    main()
