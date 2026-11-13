# SPDX-License-Identifier: MIT
"""Verify cached ordinary A53 packages against the complete selected main root.

Read-only inventory, not a solver or a root transaction. Missing filenames may
still be virtual providers; only the real APK solver can establish a solution.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
from inventory_mainroot_a53_v1 import installed
from package_native_netifd_v3 import root_digest


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('main-root', 'cached-packages', 'apk', 'keys', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-normal-mainroot-plan-') or w.exists():
        p.error('Use a fresh /root/be6l-normal-mainroot-plan-* directory')
    prior = json.loads((a.main_root.parent/'result.json').read_text())
    digest = root_digest(a.main_root)
    if digest != prior['installed_root_records_sha256']:
        raise ValueError('Complete admitted main root changed')
    if not a.keys.is_dir() or not list(a.keys.iterdir()):
        raise ValueError('Existing public verification keys are required')
    for key in a.keys.iterdir():
        if not key.is_file() or b'PRIVATE' in key.read_bytes():
            raise ValueError('Trust directory must contain public keys only')
    w.mkdir(mode=0o700)
    packages, _ = installed(a.main_root)
    retained = {name: item for name, item in packages.items()
                if name == 'kernel' or name.startswith(('kmod-', 'be6l-')) or name in ('procd', 'netifd')}
    wanted = {name: item for name, item in packages.items() if name not in retained}
    candidates = list(a.cached_packages.rglob('*.apk'))
    accepted, missing, alternatives = {}, [], {}
    for name, current in sorted(wanted.items()):
        exact = [f for f in candidates if f.name == name+'-'+current['version']+'.apk']
        if not exact:
            missing.append(name)
            alternatives[name] = sorted({f.name for f in candidates if f.name.startswith(name+'-')
                and re.match(r'[0-9]', f.name[len(name)+1:])})
            continue
        if len({sha(f) for f in exact}) != 1:
            raise ValueError('Same package filename has different archive bytes: '+name)
        archive = sorted(exact)[0]
        result = subprocess.run([str(a.apk), 'adbdump', '--format', 'json', str(archive)],
                                capture_output=True, timeout=60)
        (w/(name+'-metadata.log')).write_bytes(result.stdout+result.stderr)
        if result.returncode:
            raise ValueError('Cannot read signed package metadata: '+name)
        info = json.loads(result.stdout)['info']
        if (info['name'] != name or info['version'] != current['version'] or
                info['arch'] not in ('aarch64_cortex-a53', 'all', 'noarch')):
            raise ValueError('Cached archive is not the exact ordinary A53 package: '+name)
        verify = subprocess.run([str(a.apk), '--network=no', '--keys-dir', str(a.keys),
                                 'verify', str(archive)], capture_output=True, timeout=60)
        (w/(name+'-verify.log')).write_bytes(verify.stdout+verify.stderr)
        if verify.returncode:
            raise ValueError('Existing trusted signature verification failed: '+name)
        accepted[name] = dict(file=str(archive), sha256=sha(archive), info=info,
                              former_arch=current['arch'], payload_modified=False)
        if len(accepted) % 20 == 0:
            print('EXACT_NORMAL_ARCHIVES_VERIFIED', len(accepted), flush=True)
    result = dict(scope='Read-only complete selected-package cache inventory; no solver/transaction',
        main_root_records_sha256=digest, main_installed_packages=len(packages),
        selected_ordinary_package_count=len(wanted), retained_private_and_kernel=retained,
        exact_normal_signed_archives=accepted, missing_exact_archives=missing,
        alternate_version_archives=alternatives,
        original_world=(a.main_root/'etc/apk/world').read_text().splitlines(),
        public_key_sha256={key.name: sha(key) for key in a.keys.iterdir()},
        missing_may_include_virtual_providers=True, real_apk_solver_run=False,
        target_package_scripts_executed=False, roots_modified=False,
        normal_mainroot_composed=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print('NORMAL_SELECTED_CACHE_INVENTORIED', len(accepted), 'missing', len(missing), flush=True)


if __name__ == '__main__':
    main()
