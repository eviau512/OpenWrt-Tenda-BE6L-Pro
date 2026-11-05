# SPDX-License-Identifier: MIT
"""Prepare all seven external modules from locked archives and normal patches.

No generated object cache or old module is copied. Only a fresh owned source
directory is changed; kernel compilation, packages and target use are separate.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile

ARCHIVES = {
    'backports-7.2.tar.zst': '6ec76a4cb0988b5382b2fc5053610a56ada90b8ef6a5a4f2807cd433badb9454',
    'mt76-2026.10.08~467ae2e3.tar.zst': '2456aeba71bcda19445d539c11f165ab79f5c253345e0c6f6b3b506de01c0fdb',
}
GROUPS = ('build', 'subsys', 'ath', 'ath5k', 'ath9k', 'ath10k', 'ath11k',
          'ath12k', 'rt2x00', 'mt7601u', 'mwl', 'brcm', 'rtl')


def sha(path):
    with path.open('rb') as incoming:
        return hashlib.file_digest(incoming, 'sha256').hexdigest()


def source_records(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in sorted(root.rglob('*'))
            if p.is_file() and not p.is_symlink() and
            (p.suffix in ('.c', '.h', '.S', '.sh', '.awk', '.in') or
             p.name in ('Makefile', 'Kconfig', 'COPYING', 'LICENSE', 'LICENSES'))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prepared', 'downloads', 'previous-module-tree', 'host-prefix', 'work'):
        parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args()
    work = a.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-external-source-') or work.exists():
        parser.error('Use a fresh /root/be6l-external-source-* directory')
    for name, digest in ARCHIVES.items():
        if sha(a.downloads/name) != digest:
            raise ValueError('External source archive mismatch: '+name)
    work.mkdir(mode=0o700)
    for name in ARCHIVES:
        with tarfile.open(a.downloads/name) as archive:
            prefix = name.removesuffix('.tar.zst')
            members = archive.getmembers()
            if any(m.name != prefix and not m.name.startswith(prefix+'/') for m in members):
                raise ValueError('Unexpected external source root')
            archive.extractall(work, filter='data')
    recipes = a.prepared/'openwrt/package/kernel'
    patcher = a.prepared/'openwrt/scripts/patch-kernel.sh'
    env = dict(os.environ, PATH=str(a.host_prefix/'usr/bin')+':/usr/bin:/bin',
               LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    patches = {}

    def apply(label, source, directory):
        if not directory.is_dir():
            return
        selected = sorted(directory.glob('*.patch'))
        if not selected:
            return
        for p in selected:
            patches[p.relative_to(recipes).as_posix()] = sha(p)
        with (work/(label+'.log')).open('wb') as output:
            r = subprocess.run(['/bin/sh', str(patcher), str(source), str(directory)],
                               env=env, stdout=output, stderr=subprocess.STDOUT)
        if r.returncode:
            raise RuntimeError('Normal patch series failed: '+label)

    backports = work/'backports-7.2'
    for group in GROUPS:
        apply('backports-'+group, backports, recipes/'mac80211/patches'/group)
    # Exact Build/Prepare removals from the pinned normal package recipe.
    for name in ('include/linux/ssb', 'include/linux/bcma', 'include/net/bluetooth'):
        target = backports/name
        if not target.resolve().is_relative_to(backports):
            raise ValueError('Unexpected source removal target')
        if target.exists():
            shutil.rmtree(target)
    for name in ('include/linux/cordic.h', 'include/linux/crc8.h', 'include/linux/eeprom_93cx6.h',
                 'include/linux/wl12xx.h', 'include/linux/mhi.h', 'include/net/ieee80211.h',
                 'backport-include/linux/bcm47xx_nvram.h'):
        (backports/name).unlink(missing_ok=True)
    old_backports = a.previous_module_tree/'mac80211-regular/backports-7.2'
    seed = old_backports/'.config'
    seed_text = seed.read_text()
    for line in ('CPTCFG_CFG80211=m', 'CPTCFG_MAC80211=m', 'CPTCFG_MAC80211_MESH=y'):
        if line not in seed_text.splitlines():
            raise ValueError('Wrong backports configuration seed')
    shutil.copyfile(seed, work/'backports-seed.config')
    shutil.copyfile(seed, backports/'.config')
    version = (old_backports/'compat_version').read_text()
    if version != 'compat-wireless-7.2-9-r0+1-30b833ae5\n':
        raise ValueError('Unexpected backports source version')
    (backports/'compat_version').write_text(version)
    mt76 = work/'mt76-2026.10.08~467ae2e3'
    apply('mt76-patches', mt76, recipes/'mt76/patches')
    gpio = work/'gpio-button-hotplug'
    shutil.copytree(recipes/'gpio-button-hotplug/src', gpio, symlinks=False)
    groups = {'backports': (backports, old_backports),
              'mt76': (mt76, a.previous_module_tree/mt76.name),
              'gpio': (gpio, a.previous_module_tree/'gpio-button-hotplug')}
    compared, differences, sources = {}, {}, {}
    for label, (fresh, previous) in groups.items():
        current = source_records(fresh)
        sources[label] = current
        common = {name: digest for name, digest in current.items() if (previous/name).is_file()}
        compared[label] = len(common)
        differences[label] = [name for name, digest in common.items() if sha(previous/name) != digest]
    report = dict(archives=ARCHIVES, package_recipe_sha256={name:sha(recipes/name/'Makefile')
        for name in ('mac80211', 'mt76', 'gpio-button-hotplug')}, patches=patches,
        backports_configuration_seed_sha256=sha(seed), source_files=sources,
        compared_previous_source_files=compared, different_previous_source_files=differences,
        generated_object_cache_copied=False, previous_modules_reused=False,
        prepared_only=True, modules_built=False, target_executed=False)
    (work/'preparation.json').write_text(json.dumps(report, indent=2)+'\n')
    print('EXTERNAL_SOURCES_PREPARED', json.dumps(dict(compared=compared, differences=differences)), flush=True)
    if any(differences.values()):
        raise ValueError('Prepared sources differ from the previous module sources; review before compiling')


if __name__ == '__main__':
    main()
