# SPDX-License-Identifier: MIT
"""Build the nine missing ordinary Lua/ucode packages in an isolated A53 SDK.

Uses the unmodified OpenWrt recipes and SDK signing configuration. It does not
install a root or run target scripts. Full main-root solving remains separate.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time

PACKAGES = ('liblucihttp-lua', 'libubus-lua', 'libuci-lua', 'libyaml',
            'luci-lib-ip', 'luci-lib-jsonc', 'luci-lua-runtime', 'lyaml', 'ucode-mod-lua')
FEEDS = {
    'package/feeds/luci/luci-lib-ip': 'feeds/luci/libs/luci-lib-ip',
    'package/feeds/luci/luci-lib-jsonc': 'feeds/luci/libs/luci-lib-jsonc',
    'package/feeds/luci/luci-lua-runtime': 'feeds/luci/modules/luci-lua-runtime',
    'package/feeds/luci/ucode-mod-lua': 'feeds/luci/contrib/package/ucode-mod-lua',
    'package/feeds/packages/yaml': 'feeds/packages/libs/yaml',
    'package/feeds/packages/lyaml': 'feeds/packages/lang/lua/lyaml',
    'package/feeds/packages/luarocks': 'feeds/packages/lang/lua/luarocks',
}
TARGETS = ('package/feeds/luci/lucihttp', 'package/system/ubus', 'package/system/uci',
           'package/feeds/packages/yaml', 'package/feeds/luci/luci-lib-ip',
           'package/feeds/luci/luci-lib-jsonc', 'package/feeds/luci/luci-lua-runtime',
           'package/feeds/packages/lyaml', 'package/feeds/luci/ucode-mod-lua')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_sysroot(prefix, work):
    """Add the missing matching host math runtime without changing the prefix."""
    relative = Path('usr/lib/x86_64-linux-gnu')
    for name in ('libc.so.6', 'libm.so.6'):
        if sha(prefix/relative/name) != sha(Path('/')/relative/name):
            raise ValueError('System glibc differs from the private host runtime')
    root = work/'host-sysroot'
    root.mkdir()
    for source, destination, skip in ((prefix, root, {'usr'}),
            (prefix/'usr', root/'usr', {'lib'}),
            (prefix/'usr/lib', root/'usr/lib', {'x86_64-linux-gnu'}),
            (prefix/relative, root/relative, set())):
        destination.mkdir(parents=True, exist_ok=True)
        for child in source.iterdir():
            if child.name not in skip:
                if source == prefix/relative and child.is_file() and not child.is_symlink():
                    # ld treats absolute names in scripts outside its physical
                    # sysroot differently. Keep the library/scripts inside it.
                    shutil.copy2(child, destination/child.name)
                else:
                    (destination/child.name).symlink_to(os.readlink(child) if child.is_symlink() else child,
                                                      target_is_directory=child.is_dir())
    missing = root/relative/'libmvec.so.1'
    if missing.exists() or missing.is_symlink():
        raise ValueError('Expected the reviewed missing host libmvec runtime')
    shutil.copy2(Path('/')/relative/'libmvec.so.1', missing)
    return root, dict(source='matching installed libc6 runtime, read-only',
        libc_sha256=sha(prefix/relative/'libc.so.6'), libm_sha256=sha(prefix/relative/'libm.so.6'),
        libmvec_sha256=sha(missing), original_host_prefix_modified=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'host-prefix', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    sdk, w = a.sdk.resolve(), a.work.resolve()
    if (sdk.parent != Path('/root') or not sdk.name.startswith('be6l-normal-a53-sdk-') or
            w.parent != Path('/root') or not w.name.startswith('be6l-normal-a53-modules-') or w.exists()):
        p.error('Use an isolated /root/be6l-normal-a53-sdk-* and fresh modules work directory')
    if not json.loads((sdk/'isolated-copy.json').read_text())['complete']:
        raise ValueError('SDK input copy is incomplete')
    original = (sdk/'.config').read_text()
    required = ('CONFIG_ARCH="aarch64"', 'CONFIG_TARGET_ARCH_PACKAGES="aarch64_cortex-a53"',
                'CONFIG_TARGET_OPTIMIZATION="-Os -pipe -mcpu=cortex-a53"')
    if any(line not in original.splitlines() for line in required) or '-mgeneral-regs-only' in original:
        raise ValueError('SDK must retain the ordinary A53 ABI/compiler profile')
    w.mkdir(mode=0o700)
    sysroot, runtime = host_sysroot(a.host_prefix, w)
    (w/'baseline.config').write_text(original)
    for link, destination in FEEDS.items():
        source, path = sdk/destination, sdk/link
        if not (source/'Makefile').is_file():
            raise ValueError('Pinned local feed recipe missing: '+destination)
        if path.is_symlink() or path.exists():
            if path.resolve() != source.resolve():
                raise ValueError('Existing package feed link differs: '+link)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(os.path.relpath(source, path.parent), target_is_directory=True)
    updated = original
    for name in PACKAGES:
        symbol = 'CONFIG_PACKAGE_'+name
        pattern = r'^(?:'+re.escape(symbol)+r'=.*|# '+re.escape(symbol)+r' is not set)$'
        updated, count = re.subn(pattern, symbol+'=m', updated, flags=re.M)
        if not count:
            updated += '\n'+symbol+'=m\n'
    (sdk/'.config').write_text(updated)
    wrappers = w/'host-bin'
    wrappers.mkdir()
    for name, compiler in [('gcc', 'gcc'), ('cc', 'gcc'), ('g++', 'g++'), ('c++', 'g++')]:
        command = [str(a.host_prefix/'usr/bin'/compiler), '--sysroot='+str(sysroot),
                   '-L'+str(sysroot/'usr/lib/x86_64-linux-gnu'),
                   '-isystem', str(a.host_prefix/'usr/include/x86_64-linux-gnu')]
        target = wrappers/name
        target.write_text('#!/usr/bin/python3\nimport os,sys\ncommand='+repr(command)+
                          '\nos.execv(command[0],command+sys.argv[1:])\n')
        target.chmod(0o755)
        # OpenWrt host recipes also name STAGING_DIR_HOST/bin/gcc directly;
        # PATH alone cannot replace the absent original host-system compiler.
        staged = sdk/'staging_dir/host/bin'/name
        if staged.is_symlink():
            staged.unlink()
        elif staged.exists() and not staged.read_bytes().startswith(b'#!/usr/bin/python3\nimport os,sys\ncommand='):
            raise ValueError('Refusing to replace an unexpected SDK host compiler')
        staged.write_bytes(target.read_bytes())
        staged.chmod(0o755)
    env = dict(os.environ, PATH=':'.join(map(str, [wrappers, sdk/'staging_dir/host/bin', sdk/'staging_dir/hostpkg/bin',
        a.host_prefix/'usr/bin', Path('/usr/bin'), Path('/bin')])),
        LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'),
        BISON_PKGDATADIR=str(a.host_prefix/'usr/share/bison'),
        M4=str(a.host_prefix/'usr/bin/m4'), SOURCE_DATE_EPOCH='1792420077')
    for name in ('GZIP', 'XZ_DEFAULTS', 'XZ_OPT', 'PKG_CONFIG_SYSROOT_DIR', 'PKG_CONFIG_LIBDIR'):
        env.pop(name, None)
    make = [str(a.host_prefix/'usr/bin/make'), '-C', str(sdk), '-j4', 'V=s']
    state = dict(ordinary_a53_profile=True, packages=list(PACKAGES), completed=[],
                 host_runtime_overlay=runtime,
                 active=None, terminal=False, target_executed=False, roots_modified=False,
                 mainroot_compatibility_qualified=False)

    def save():
        (w/'result.json').write_text(json.dumps(state, indent=2)+'\n')

    def run(label, command):
        state['active'] = label
        save()
        print('START', label, flush=True)
        started = time.monotonic()
        with (w/(label+'.log')).open('wb') as output:
            result = subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(label+' failed; inspect retained log')
        state['completed'].append(dict(step=label, elapsed_seconds=time.monotonic()-started))
        save()
        print('PASS', label, flush=True)

    try:
        run('defconfig', make+['defconfig'])
        actual = (sdk/'.config').read_text()
        if any(line not in actual.splitlines() for line in required):
            raise ValueError('Ordinary A53 profile changed during configuration')
        if any('CONFIG_PACKAGE_'+name+'=m' not in actual.splitlines() and
               'CONFIG_PACKAGE_'+name+'=y' not in actual.splitlines() for name in PACKAGES):
            raise ValueError('Requested normal package selection did not survive defconfig')
        state['effective_sdk_config_sha256'] = sha(sdk/'.config')
        state['source_recipe_sha256'] = {target: sha(sdk/target/'Makefile') for target in TARGETS}
        for i, target in enumerate(TARGETS):
            run('compile-'+str(i+1)+'-'+target.split('/')[-1], make+[target+'/compile'])
        state['all_requested_recipes_built'] = True
    except Exception as error:
        state['error'] = type(error).__name__+': '+str(error)
        raise
    finally:
        state.update(active=None, terminal=True)
        save()


if __name__ == '__main__':
    main()
