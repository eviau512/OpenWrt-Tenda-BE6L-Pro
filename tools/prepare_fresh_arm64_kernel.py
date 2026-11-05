# SPDX-License-Identifier: MIT
"""Prepare an isolated kernel from locked Git objects and the Linux archive.

Uses the OpenWrt Kernel/Patch/Default overlay order and patch-kernel.sh.
No damaged generated build cache is copied into this source tree. This is
kernel source preparation, not full SDK, image, module or target admission.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile

REVISION = '30b833ae5b8a6ba94149268c47a8493308a0ee04'
LINUX_SHA = 'f410638061a165c12f42ab871d2f3fcd525515359b5faeee80969cff84524df9'
PATCH_SHA = '3d8ea0036750675d4abe2dd9ca5533b1bc5247f4ee089ae05f6628d2ea69bdfe'
BASE_DRIVER_SHA = '6bf954bf5eef737a338978ec1af3a8e29538f9815398c06162f3d621a597d1d4'
PORT_SHA = 'b11b332cc4331ca7a1b5f1ca5105e6dc27fc632f3cb5b4ac859e94621d6e93f3'
PORT_DRIVER_SHA = 'de1f3299891eef4d987a4e9222eedc535ead18bf0d100c996eea2c0f8d5bb2f1'
BASE = Path(__file__).resolve().parents[1]


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unpack(archive, destination, prefix=None):
    destination.mkdir()
    with tarfile.open(archive) as stream:
        if prefix:
            for member in stream.getmembers():
                if member.name != prefix and not member.name.startswith(prefix + '/'):
                    raise ValueError('Unexpected kernel archive root')
        stream.extractall(destination, filter='data')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openwrt-repository', type=Path, required=True)
    parser.add_argument('--linux-archive', type=Path, required=True)
    parser.add_argument('--host-prefix', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-fresh-kernel-'):
        parser.error('Use a fresh /root/be6l-fresh-kernel-* directory')
    delta = BASE / 'patches/openwrt-arm64-compat.patch'
    port = BASE / 'patches/next/979-xwrt-an7563-sram-only-policy.patch'
    if sha(args.linux_archive) != LINUX_SHA or sha(delta) != PATCH_SHA or sha(port) != PORT_SHA:
        raise ValueError('Locked kernel/archive/project patch mismatch')
    work.mkdir(mode=0o700)
    env = dict(os.environ, PATH=str(args.host_prefix / 'usr/bin') + ':/usr/bin:/bin',
               LD_LIBRARY_PATH=str(args.host_prefix / 'usr/lib/x86_64-linux-gnu'))

    def run(label, command, cwd=None):
        result = subprocess.run(list(map(str, command)), cwd=cwd, env=env, capture_output=True)
        (work / (label + '.log')).write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(label + ' failed; preserve and inspect its log')
        return result.stdout

    git = ['git', '-c', 'safe.directory=' + str(args.openwrt_repository.resolve()),
           '-C', args.openwrt_repository]
    if run('git-object', git + ['cat-file', '-t', REVISION]).strip() != b'commit':
        raise ValueError('Pinned OpenWrt commit object missing')
    archive = work / 'openwrt-source.tar'
    with archive.open('xb') as output:
        result = subprocess.run(list(map(str, git + ['archive', '--format=tar', REVISION])),
                                env=env, stdout=output, stderr=subprocess.PIPE)
    (work / 'git-archive.log').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError('Pinned Git source archive failed')
    sdk = work / 'openwrt'
    unpack(archive, sdk)
    run('check-project-delta', ['git', 'apply', '--check', delta], sdk)
    run('apply-project-delta', ['git', 'apply', delta], sdk)
    unpack(args.linux_archive, work / 'kernel-source', 'linux-6.18.55')
    kernel = work / 'kernel-source/linux-6.18.55'
    platform = sdk / 'target/linux/airoha'
    generic = sdk / 'target/linux/generic'
    overlays = [p for p in (generic / 'files', generic / 'files-6.18',
                           platform / 'files', platform / 'files-6.18') if p.is_dir()]
    for overlay in overlays:
        shutil.copytree(overlay, kernel, symlinks=True, dirs_exist_ok=True)
    patch_dirs = [generic / 'backport-6.18', generic / 'pending-6.18',
                  generic / 'hack-6.18', platform / 'patches-6.18']
    for index, directory in enumerate(patch_dirs):
        if not directory.is_dir():
            raise ValueError('Expected pinned patch directory missing')
        run('kernel-patches-' + str(index), ['/bin/sh', sdk / 'scripts/patch-kernel.sh', kernel, directory])
        print('PATCH_SERIES_APPLIED', directory.relative_to(sdk), flush=True)
    driver = kernel / 'drivers/net/ethernet/airoha/airoha_ppe.c'
    if sha(driver) != BASE_DRIVER_SHA:
        raise ValueError('Freshly prepared driver differs from qualified source pin')
    run('check-sram-port', ['git', 'apply', '--check', '--whitespace=error-all', port], kernel)
    run('apply-sram-port', ['git', 'apply', port], kernel)
    if sha(driver) != PORT_DRIVER_SHA:
        raise ValueError('Fresh ported driver source mismatch')
    report = dict(openwrt_revision=REVISION, openwrt_git_archive_sha256=sha(archive),
        linux_archive_sha256=LINUX_SHA, project_patch_sha256=PATCH_SHA, sram_patch_sha256=PORT_SHA,
        baseline_driver_sha256=BASE_DRIVER_SHA, ported_driver_sha256=sha(driver),
        overlay_directories=[str(p.relative_to(sdk)) for p in overlays],
        patch_directories=[str(p.relative_to(sdk)) for p in patch_dirs],
        patch_script_sha256=sha(sdk / 'scripts/patch-kernel.sh'),
        pristine_case_sensitive_source=True, generated_cache_imported=False,
        original_restore_tree_modified=False, full_sdk_admitted=False,
        full_kernel_built=False, target_executed=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('FRESH_LOCKED_KERNEL_SOURCE_AND_SRAM_PORT_PREPARED', flush=True)


if __name__ == '__main__':
    main()
