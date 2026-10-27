# SPDX-License-Identifier: MIT
"""Build all remaining installed Lua C extensions from pinned cached sources."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from a64_soft_context import BASE, SDK, EPOCH
from soft_elf_closure import audit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--modules-root', type=Path, required=True)
parser.add_argument('--resume', action='store_true')
args = parser.parse_args(); root, prior = args.root, args.modules_root
assert all(p.is_absolute() and not any(c.isspace() for c in str(p)) for p in (root, prior))
marker=dict(base=str(prior),abi='AAPCS64-soft')
if args.resume: assert json.loads((root/'.be6l-soft-lua-ui.json').read_text())==marker
else:
    assert not root.exists()
    root.mkdir(); (root / '.be6l-soft-lua-ui.json').write_text(json.dumps(marker)+'\n')
    shutil.copytree(prior / 'sysroot', root / 'sysroot', symlinks=True)
    shutil.copyfile(prior / 'libsoft-builtins.a', root / 'libsoft-builtins.a')
    for name in ('cc', 'softcc', 'soft-toolchain.cmake'):
        (root / name).write_text((prior / name).read_text().replace(str(prior), str(root))); (root / name).chmod(0o755)
sysroot = root / 'sysroot'
main_tree = Path('/root/be6l-openwrt/source/build_dir/target-arm_cortex-a7_musl_eabi')
sources = {}
ignore = shutil.ignore_patterns('*.o', '*.lo', '*.a', '*.so', '*.so.*', '*.la', '.libs', '.deps',
    'CMakeFiles', 'CMakeCache.txt', 'apk-*', 'ipkg-*', '.pkgdir', '.built*', '.configured*', 'lemon')
for name, cached in {
    'luci-ip': SDK/'feeds/luci/libs/luci-lib-ip/src',
    'luci-jsonc': SDK/'feeds/luci/libs/luci-lib-jsonc/src',
    'luci-parser': SDK/'feeds/luci/modules/luci-lua-runtime/src',
    'libyaml': main_tree/'yaml-0.2.5', 'lyaml': main_tree/'lyaml-6.2.7'}.items():
    dest = root / ('source-'+name)
    if not dest.exists(): shutil.copytree(cached, dest, symlinks=False, ignore=ignore)
    sources[name] = dest
env = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH)
env['PATH']='/root/be6l-openwrt/host/bin:'+str(SDK/'staging_dir/host/bin')+':'+env['PATH']
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
env.update(CC=str(root/'softcc'),AR=prefix+'ar',RANLIB=prefix+'ranlib',STRIP=prefix+'strip',CFLAGS='-O2 -fPIC')
logdir = BASE / 'logs' / ('soft-lua-ui-'+root.name); logdir.mkdir(exist_ok=True)
commands = [[str(sources['libyaml']/'configure'), '--host=aarch64-openwrt-linux-musl',
    '--build=x86_64-pc-linux-gnu', '--prefix=/usr', '--libdir=/usr/lib', '--disable-static', '--enable-shared'],
    ['make', '-j4'], ['make', 'install', 'DESTDIR='+str(sysroot)]]
with (logdir/'libyaml-build.txt').open('w') as output:
    for command in commands:
        local = dict(env)
        r = subprocess.run(command, cwd=sources['libyaml'], env=local, stdout=output, stderr=subprocess.STDOUT)
        if r.returncode: print((logdir/'libyaml-build.txt').read_text()[-6000:]); raise SystemExit(r.returncode)
for name, target in (('luci-ip', 'compile'), ('luci-jsonc', 'compile'), ('luci-parser', 'parser.so')):
    command = ['make', '-j4', 'CC='+str(root/'softcc'), 'STAGING_DIR='+str(sysroot),
        'CFLAGS=-O2 -I'+str(sysroot/'usr/include'), 'FPIC=-fPIC',
        'LDFLAGS=-L'+str(sysroot/'usr/lib')+' -llua', target]
    r = subprocess.run(command, cwd=sources[name], env=env, capture_output=True, text=True)
    (logdir/(name+'-build.txt')).write_text(r.stdout+r.stderr)
    if r.returncode: print(r.stdout+r.stderr); raise SystemExit(r.returncode)
lyaml = sources['lyaml']
r = subprocess.run([str(root/'softcc'), '-shared', '-fPIC', '-O2', '-DNDEBUG=1', '-D_FORTIFY_SOURCE=2',
    '-DPACKAGE="lyaml"', '-DVERSION="6.2.7"', '-I'+str(sysroot/'usr/include'),
    '-I'+str(lyaml/'ext/include'), *[str(lyaml/'ext/yaml'/n) for n in ('yaml.c','emitter.c','parser.c','scanner.c')],
    '-L'+str(sysroot/'usr/lib'), '-lyaml', '-llua', '-o', str(lyaml/'yaml.so')], capture_output=True, text=True)
(logdir/'lyaml-build.txt').write_text(r.stdout+r.stderr)
if r.returncode: print(r.stdout+r.stderr); raise SystemExit(r.returncode)
previous = json.loads((prior/'audited/manifest.json').read_text())
initial = {name: prior/'audited'/name for name in previous['files']}
for name, source in {
    'lua-modules/luci/ip.so': sources['luci-ip']/'ip.so',
    'lua-modules/luci/jsonc.so': sources['luci-jsonc']/'jsonc.so',
    'lua-modules/luci/template/parser.so': sources['luci-parser']/'parser.so',
    'lua-modules/yaml.so': lyaml/'yaml.so'}.items():
    initial[name] = source
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
files = audit(initial, sysroot, root/'audited', str(gcc)[:-3])
inventory = dict(previous['source_hashes'])
for name, source in sources.items():
    inventory[name] = {p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(source.rglob('*')) if p.is_file() and
        not (name=='libyaml' and p.name=='Makefile') and
        (p.suffix in ('.c','.h','.y','.lua','.in','.rockspec') or p.name in ('LICENSE','COPYING','Makefile','CMakeLists.txt'))}
manifest = dict(abi='AAPCS64-soft', files=files, source_hashes=inventory,
    dependency_closure_audited=True, strong_symbols_closed=True,
    system_services_replaced=False, full_device_ui_qualified=False,
    native_lua_ui_runtime_qualified=False)
(root/'audited/manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
art = BASE/'artifacts/a64-soft-lua-ui'; art.mkdir(exist_ok=True)
shutil.copyfile(root/'audited/manifest.json', art/'manifest.json')
with tarfile.open(art/'luci.tar','w') as tar:
    for name in files:
        data=(root/'audited'/name).read_bytes(); info=tarfile.TarInfo(name)
        info.size,info.mode,info.mtime=len(data),0o755,int(EPOCH); tar.addfile(info,io.BytesIO(data))
print('NATIVE_COMPLETE_INSTALLED_LUA_C_EXTENSIONS_AUDITED',len(files),flush=True)
