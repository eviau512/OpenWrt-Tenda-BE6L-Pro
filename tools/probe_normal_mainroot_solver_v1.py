# SPDX-License-Identifier: MIT
"""Run real APK3 dependency simulation against signed normal/r105 repositories.

This is an ordinary-package dependency probe, not final mixed-root admission.
The existing private procd/netifd/runtime choices require a later transaction.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from inventory_mainroot_a53_v1 import installed
from package_native_netifd_v3 import root_digest


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'kernel-packages', 'main-root', 'apk', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-normal-solver-') or w.exists():
        p.error('Use a fresh /root/be6l-normal-solver-* directory')
    prior = json.loads((a.main_root.parent/'result.json').read_text())
    digest = root_digest(a.main_root)
    if digest != prior['installed_root_records_sha256']:
        raise ValueError('Admitted source root changed')
    kernel = json.loads((a.kernel_packages/'result.json').read_text())
    if not kernel['normal_signed_component_transaction'] or not kernel['matching_root_composed']:
        raise ValueError('Matching signed kernel package admission missing')
    w.mkdir(mode=0o700)
    repo, trust = w/'repo', w/'trust'
    repo.mkdir(); trust.mkdir()
    for key in [a.sdk/'public-key.pem', *(a.kernel_packages/'trust').glob('*.pem')]:
        if b'PRIVATE' in key.read_bytes():
            raise ValueError('Verification trust must contain public keys only')
        shutil.copy2(key, trust/('key-'+sha(key)+'.pem'))

    def run(label, command, required=True):
        r = subprocess.run(list(map(str, command)), capture_output=True, timeout=180)
        (w/(label+'.log')).write_bytes(r.stdout+r.stderr)
        if required and r.returncode:
            raise RuntimeError(label+' failed; retained log is authoritative')
        return r

    catalog, skipped, kernel_names, extra_arch = {}, [], [], set()
    inputs = [(f, False) for f in sorted((a.sdk/'bin').rglob('*.apk'))]
    inputs += [(f, True) for f in sorted(a.kernel_packages.glob('*.apk'))]
    for index, (archive, matching_kernel) in enumerate(inputs):
        info = json.loads(run('metadata-'+str(index), [a.apk, 'adbdump', '--format', 'json', archive]).stdout)['info']
        is_kernel = info['name'] == 'kernel' or info['name'].startswith('kmod-')
        if is_kernel != matching_kernel:
            skipped.append(dict(file=archive.name, reason='Exclude old SDK kernel/modules'))
            continue
        if not matching_kernel and info['arch'] not in ('aarch64_cortex-a53', 'all', 'noarch'):
            raise ValueError('Non-ordinary user archive in normal SDK: '+archive.name)
        if matching_kernel:
            kernel_names.append(info['name'])
            extra_arch.add(info['arch'])
            if info['name'] == 'kernel' and info['version'] != kernel['kernel_package_version']:
                raise ValueError('Kernel package version differs from matching admission')
        run('verify-'+str(index), [a.apk, '--network=no', '--keys-dir', trust, 'verify', archive])
        name = info['name']+'-'+info['version']+'.apk'
        pin = sha(archive)
        if name in catalog:
            if catalog[name]['sha256'] != pin:
                raise ValueError('Conflicting duplicate signed archive: '+name)
            continue
        # Keep the signed repository stable while the isolated SDK continues
        # building other selections with the same package filenames.
        shutil.copy2(archive, repo/name)
        catalog[name] = dict(sha256=pin, info=info, matching_kernel=matching_kernel)
    if len(kernel_names) != kernel['package_count_rebuilt'] or len(set(kernel_names)) != 57:
        raise ValueError('Incomplete matching r105 package set')
    run('signed-local-index', [a.apk, '--keys-dir', trust, 'mkndx', '--sign-key', a.sdk/'private-key.pem',
        '--output', repo/'packages.adb', '--pkgname-spec', '$name-$version.apk', *sorted(repo.glob('*.apk'))])
    run('verify-local-index', [a.apk, '--keys-dir', trust, 'verify', repo/'packages.adb'])
    repositories = w/'repositories'
    repositories.write_text('file://'+str(repo/'packages.adb')+'\n')
    root = w/'root'; root.mkdir()
    common = [a.apk, '--root', root, '--keys-dir', trust, '--network=no', '--cache=no',
              '--logfile=no', '--repositories-file', repositories]
    run('initialize-empty-root', common+['--arch', 'aarch64_cortex-a53', '--scripts=no', 'add', '--initdb'])
    (root/'etc/apk').mkdir(parents=True, exist_ok=True)
    arches = ['aarch64_cortex-a53']+sorted(extra_arch-{'aarch64_cortex-a53','all','noarch'})
    (root/'etc/apk/arch').write_text('\n'.join(arches)+'\n')
    run('load-local-index', common+['update'])
    packages, _ = installed(a.main_root)
    wanted = sorted(name for name in packages if name not in ('kernel','procd','netifd')
                    and not name.startswith(('kmod-','be6l-')))
    before = root_digest(root)
    simulation = run('ordinary-world-simulate', common+['--scripts=no', 'add', '--simulate',
        'kernel='+kernel['kernel_package_version'], *wanted], required=False)
    if root_digest(root) != before:
        raise ValueError('Simulation changed the isolated package root')
    report = dict(scope='Real APK3 ordinary-world dependency simulation, not final private/mixed composition',
        source_root_records_sha256=digest, source_kernel_receipt_sha256=sha(a.kernel_packages/'result.json'),
        requested_ordinary_names=wanted, original_world=(a.main_root/'etc/apk/world').read_text().splitlines(),
        catalog=catalog, skipped_old_kernel_archives=skipped, matching_kernel_packages=57,
        architectures=arches, signed_local_index_sha256=sha(repo/'packages.adb'),
        actual_solver_exit=simulation.returncode, actual_solver_succeeded=simulation.returncode == 0,
        solver_diagnostics=(simulation.stdout+simulation.stderr).decode(errors='replace'),
        target_scripts_executed=False, original_root_unchanged=root_digest(a.main_root) == digest,
        simulator_root_unchanged=True, final_mixed_root_composed=False,
        private_service_selection_applied=False, full_standard_a53_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('REAL_APK_ORDINARY_DEPENDENCY_PROBED', len(wanted), 'archives', len(catalog),
          'solver_exit', simulation.returncode, flush=True)


if __name__ == '__main__':
    main()
