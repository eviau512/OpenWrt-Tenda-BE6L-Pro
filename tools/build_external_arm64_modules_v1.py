# SPDX-License-Identifier: MIT
"""Build all seven external modules against the new binfmt kernel, from source.

Uses normal backports/mt76/gpio build interfaces. Does not retain old modules,
install packages, generate an image or access the router.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess


def sha(path):
    with path.open('rb') as incoming:
        return hashlib.file_digest(incoming, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sources', 'kernel-build', 'toolchain', 'host-prefix', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--resume', action='store_true', help='Resume only this exact owned input set after a terminal failure')
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-external-build-') or (w.exists() and not a.resume):
        p.error('Use a fresh /root/be6l-external-build-* directory')
    prepared = json.loads((a.sources/'preparation.json').read_text())
    built = json.loads((a.kernel_build/'result.json').read_text())
    if not built['full_kernel_built'] or not built.get('integer_binfmt_builtin'):
        raise ValueError('New built-in binfmt kernel evidence missing')
    kernel = a.kernel_build/'build'
    if sha(kernel/'.config') != built['effective_config_sha256'] or sha(kernel/'Module.symvers') != built['module_symvers_sha256']:
        raise ValueError('Kernel/configuration changed after build')
    paths = {'backports':'backports-7.2', 'mt76':'mt76-2026.10.08~467ae2e3', 'gpio':'gpio-button-hotplug'}
    for group, records in prepared['source_files'].items():
        for name, digest in records.items():
            if sha(a.sources/paths[group]/name) != digest:
                raise ValueError('Prepared source changed: '+group+'/'+name)
    if any(prepared['different_previous_source_files'].values()):
        raise ValueError('Unreviewed difference from prior module source')
    owner = dict(source_preparation_sha256=sha(a.sources/'preparation.json'),
                 kernel_build_sha256=sha(a.kernel_build/'result.json'),
                 kernel_config_sha256=built['effective_config_sha256'])
    if a.resume:
        if json.loads((w/'.owner.json').read_text()) != owner:
            raise ValueError('Owned external build inputs changed')
        for group, records in prepared['source_files'].items():
            for name, digest in records.items():
                if sha(w/paths[group]/name) != digest:
                    raise ValueError('External build source changed: '+group+'/'+name)
    else:
        w.mkdir(mode=0o700)
        (w/'.owner.json').write_text(json.dumps(owner, indent=2)+'\n')
        for name in paths.values():
            shutil.copytree(a.sources/name, w/name, symlinks=True)
    bp, mt, gpio = (w/paths[name] for name in ('backports', 'mt76', 'gpio'))
    cross = str(a.toolchain/'bin/aarch64-openwrt-linux-musl-')
    hostmake = a.host_prefix/'usr/bin/make'
    env = dict(os.environ, PATH=str(a.toolchain/'bin')+':'+str(a.host_prefix/'usr/bin')+':/usr/bin:/bin',
        LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'), SOURCE_DATE_EPOCH='1792420077',
        KBUILD_BUILD_USER='builder', KBUILD_BUILD_HOST='buildhost', KBUILD_BUILD_VERSION='1',
        KBUILD_BUILD_TIMESTAMP='Mon Oct 19 14:27:57 UTC 2026',
        BISON_PKGDATADIR=str(a.host_prefix/'usr/share/bison'), M4=str(a.host_prefix/'usr/bin/m4'))
    common = ['ARCH=arm64', 'CROSS_COMPILE='+cross, 'HOSTCC='+str(a.kernel_build/'hostcc'),
              'HOSTCXX='+str(a.kernel_build/'hostcxx'),
              'YACC='+str(a.host_prefix/'usr/bin/bison'), 'LEX='+str(a.host_prefix/'usr/bin/flex')]
    stages = []

    def run(label, command):
        print('RUN', label, flush=True)
        with (w/(label+'.log')).open('wb') as output:
            result = subprocess.run(list(map(str, command)), env=env, stdout=output, stderr=subprocess.STDOUT)
        stages.append(dict(stage=label, exit=result.returncode))
        (w/'stages.json').write_text(json.dumps(stages, indent=2)+'\n')
        if result.returncode:
            raise RuntimeError(label+' failed; inspect retained log')

    bp_make = [hostmake, '-C', bp, '-j4', *common, 'KLIB_BUILD='+str(kernel),
        'KLIB='+str(w/'module-install'), 'MODPROBE=true', 'KERNEL_SUBLEVEL=18',
        'KBUILD_LDFLAGS_MODULE_PREREQ=', 'EXTRA_CFLAGS=-I'+str(bp/'include')]
    run('backports-configure', bp_make+['allnoconfig'])
    run('backports-build', bp_make+['modules'])
    include = w/'staging/usr/include'
    include.mkdir(parents=True, exist_ok=True)
    shutil.copytree(bp/'include', include/'mac80211', symlinks=True, dirs_exist_ok=True)
    shutil.copytree(bp/'backport-include', include/'mac80211-backport', symlinks=True, dirs_exist_ok=True)
    (include/'mac80211-backport/linux/module.h').unlink(missing_ok=True)
    for path in (bp/'net/mac80211').glob('*.h'):
        shutil.copyfile(path, include/'mac80211'/path.name)
    ath = include/'mac80211/ath'
    ath.mkdir(exist_ok=True)
    for path in (bp/'drivers/net/wireless/ath').glob('*.h'):
        shutil.copyfile(path, ath/path.name)
    rate = include/'net/mac80211'
    rate.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(bp/'net/mac80211/rate.h', rate/'rate.h')
    flags = ['-nostdinc', '-I'+str(mt), '-I'+str(include/'mac80211-backport/uapi'),
        '-I'+str(include/'mac80211-backport'), '-I'+str(include/'mac80211/uapi'),
        '-I'+str(include/'mac80211'), '-include', 'backport/autoconf.h', '-include', 'backport/backport.h',
        '-DCONFIG_MAC80211_MESH', '-DCONFIG_MT76_NPU', '-DCONFIG_MT7996_NPU']
    kernel_make = [hostmake, '-C', kernel, '-j4', *common]
    run('mt76-build', kernel_make+['M='+str(mt), 'CONFIG_MT76_CONNAC_LIB=m', 'CONFIG_MT7996E=m',
        'CONFIG_MT76_NPU=y', 'CONFIG_MT7996_NPU=y', 'NOSTDINC_FLAGS='+' '.join(flags),
        'KBUILD_EXTRA_SYMBOLS='+str(bp/'Module.symvers'), 'modules'])
    run('gpio-build', kernel_make+['M='+str(gpio), 'modules'])
    modules = {path.name: path for group in (bp, mt, gpio) for path in group.rglob('*.ko')}
    expected = {'compat.ko','cfg80211.ko','mac80211.ko','mt76.ko','mt76-connac-lib.ko','mt7996e.ko','gpio-button-hotplug.ko'}
    if set(modules) != expected:
        raise ValueError('Unexpected external module inventory: '+str(sorted(modules)))
    verified = {}
    for name, path in sorted(modules.items()):
        data = path.read_bytes()
        if data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\xb7\0':
            raise ValueError('External module is not AArch64: '+name)
        modinfo = subprocess.check_output([cross+'readelf', '-p', '.modinfo', str(path)], text=True)
        if 'vermagic=6.18.55 ' not in modinfo:
            raise ValueError('Wrong external kernel vermagic: '+name)
        verified[name] = dict(path=path.relative_to(w).as_posix(), sha256=sha(path), bytes=len(data))
    result = dict(all_external_modules_rebuilt=True, rebuilt_external_module_count=7,
        modules=verified, previous_modules_reused=False,
        kernel_build_receipt_sha256=sha(a.kernel_build/'result.json'),
        kernel_effective_config_sha256=built['effective_config_sha256'],
        kernel_module_symvers_sha256=built['module_symvers_sha256'],
        source_preparation_sha256=sha(a.sources/'preparation.json'),
        backports_resolved_config_sha256=sha(bp/'.config'),
        matching_package_transaction_passed=False, target_executed=False)
    (w/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print('ALL_SEVEN_EXTERNAL_AARCH64_MODULES_REBUILT', json.dumps(verified), flush=True)


if __name__ == '__main__':
    main()
