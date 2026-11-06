# SPDX-License-Identifier: MIT
"""Reconstruct the pinned X-Wrt PPE source before/after941-04 for port review.

Fetches one immutable public Git commit and checks every existing selected
source pin. Applies normal generic/platform overlays and patch order to the
locked reference Linux6.18.60 archive. No BE6L firmware, hardware, MMIO or target action.
This reference intentionally stops at941-04 and is not a full SDK or candidate.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile

BASE = Path(__file__).resolve().parents[1]
REVISION = '5ae8e6912e64682fcad54593467e84c80f170656'
LINUX_VERSION = '6.18.60'
LINUX_SHA = '3c2f44ef6acc021a7ad444d9a2e6ec1ef488ff09368793d0004a6080f69d621e'
STOP = '941-04-net-airoha-preserve-native-ppe-flow-resources.patch'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('linux-archive', 'host-prefix', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--git-cache', type=Path, help='Reuse a read-only Git object cache containing the exact pinned commit')
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-xwrt-ppe-reference-'):
        p.error('Use a fresh /root/be6l-xwrt-ppe-reference-* directory')
    lock = json.loads((BASE/'upstream/xwrt-an7563-20261105.json').read_text())
    if lock['revision'] != REVISION or sha(a.linux_archive) != LINUX_SHA:
        raise ValueError('Pinned X-Wrt/Linux source input differs')
    w.mkdir(mode=0o700)
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0',
               PATH=str(a.host_prefix/'usr/bin')+':/usr/bin:/bin',
               LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))

    def run(label, command, timeout=600):
        with (w/(label+'.log')).open('wb') as output:
            r = subprocess.run(list(map(str, command)), env=env, stdout=output,
                               stderr=subprocess.STDOUT, timeout=timeout)
        if r.returncode:
            raise RuntimeError(label+' failed; retained log is authoritative')
        print('REFERENCE_STAGE', label, flush=True)

    repository = a.git_cache.resolve() if a.git_cache else w/'repository.git'
    git = ['git', '-C', str(repository)]
    if not a.git_cache:
        run('git-init', ['git', 'init', '--bare', repository])
        run('git-fetch', git+['fetch', '--depth=1', lock['repository']+'.git', REVISION])
    if subprocess.check_output(git+['rev-parse', REVISION+'^{commit}']).decode().strip() != REVISION:
        raise ValueError('Wrong fetched Git commit')
    details = subprocess.check_output(git+['show', REVISION+':target/linux/generic/kernel-6.18']).decode()
    if ('LINUX_VERSION-6.18 = .60\n' not in details or
        'LINUX_KERNEL_HASH-'+LINUX_VERSION+' = '+LINUX_SHA+'\n' not in details):
        raise ValueError('The pinned reference kernel recipe differs')
    for name, pin in lock['files'].items():
        data = subprocess.check_output(git+['show', REVISION+':'+name])
        if hashlib.sha256(data).hexdigest() != pin['sha256']:
            raise ValueError('Selected immutable source pin differs: '+name)
    archive = w/'reference-source.tar'
    with archive.open('wb') as output:
        subprocess.run(git+['archive', '--format=tar', REVISION, 'scripts/patch-kernel.sh',
                           'target/linux/generic', 'target/linux/airoha'], stdout=output,
                       env=env, check=True, timeout=120)
    sdk = w/'openwrt'
    sdk.mkdir()
    with tarfile.open(archive) as incoming:
        incoming.extractall(sdk, filter='data')
    kernels = w/'kernel-source'
    kernels.mkdir()
    with tarfile.open(a.linux_archive) as incoming:
        prefix = 'linux-'+LINUX_VERSION
        if any(m.name != prefix and not m.name.startswith(prefix+'/') for m in incoming.getmembers()):
            raise ValueError('Unexpected Linux archive root')
        incoming.extractall(kernels, filter='data')
    kernel = kernels/('linux-'+LINUX_VERSION)
    generic, platform = sdk/'target/linux/generic', sdk/'target/linux/airoha'
    overlays = [x for x in (generic/'files', generic/'files-6.18', platform/'files', platform/'files-6.18') if x.is_dir()]
    for overlay in overlays:
        shutil.copytree(overlay, kernel, symlinks=True, dirs_exist_ok=True)
    script = sdk/'scripts/patch-kernel.sh'
    for index, directory in enumerate((generic/'backport-6.18', generic/'pending-6.18', generic/'hack-6.18')):
        if not directory.is_dir():
            raise ValueError('Expected generic patch directory missing')
        run('generic-patches-'+str(index), ['/bin/sh', script, kernel, directory])
    directory = platform/'patches-6.18'
    driver = kernel/'drivers/net/ethernet/airoha'
    applied = []
    snapshots = {}
    for patch in sorted(directory.glob('*.patch')):
        if patch.name == STOP:
            shutil.copytree(driver, w/'before-94104', symlinks=True)
        run('platform-'+patch.name, ['/bin/sh', script, kernel, directory, patch.name])
        applied.append(patch.name)
        if patch.name == STOP:
            shutil.copytree(driver, w/'after-94104', symlinks=True)
            break
    if not applied or applied[-1] != STOP:
        raise ValueError('Requested941-04 boundary was not prepared')
    for label in ('before-94104', 'after-94104'):
        snapshots[label] = {x.relative_to(w/label).as_posix(): sha(x)
                            for x in sorted((w/label).rglob('*')) if x.is_file()}
    result = dict(reference_revision=REVISION, selected_source_pins_verified=len(lock['files']),
        immutable_git_cache_reused=bool(a.git_cache),
        linux_version=LINUX_VERSION, kernel_details_git_object_checked=True,
        linux_archive_sha256=LINUX_SHA, git_source_archive_sha256=sha(archive),
        reference_through_94104=True, applied_platform_patches=applied,
        driver_snapshot_sha256=snapshots, patch_script_sha256=sha(script),
        reference_firmware_installed=False, be6l_port_applied=False,
        full_sdk_admitted=False, kernel_compiled=False, target_executed=False,
        hardware_drain_qualified=False, routed_admission_enabled=False)
    (w/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print('XWRT_PPE_94104_REFERENCE_PREPARED', flush=True)


if __name__ == '__main__':
    main()
