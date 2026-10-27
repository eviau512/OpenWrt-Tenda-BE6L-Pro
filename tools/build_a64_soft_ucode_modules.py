# SPDX-License-Identifier: MIT
"""Complete the installed ucode C-module set from cached public sources only."""
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
parser.add_argument('--web-root', type=Path, required=True)
parser.add_argument('--resume', action='store_true')
args = parser.parse_args(); root, prior = args.root, args.web_root
assert all(p.is_absolute() and not any(c.isspace() for c in str(p)) for p in (root, prior))
marker = dict(base=str(prior), abi='AAPCS64-soft')
if args.resume:
    assert json.loads((root / '.be6l-soft-ucode-modules.json').read_text()) == marker
else:
    assert not root.exists(), 'Use a fresh owned output'
    root.mkdir(); (root / '.be6l-soft-ucode-modules.json').write_text(json.dumps(marker)+'\n')
    shutil.copytree(prior / 'sysroot', root / 'sysroot', symlinks=True)
    shutil.copyfile(prior / 'libsoft-builtins.a', root / 'libsoft-builtins.a')
    for name in ('cc', 'softcc', 'soft-toolchain.cmake'):
        (root / name).write_text((prior / name).read_text().replace(str(prior), str(root))); (root / name).chmod(0o755)
sysroot = root / 'sysroot'
tree = SDK / 'build_dir/target-aarch64_cortex-a53_musl'
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix = str(gcc)[:-3]
md = root / 'source-libmd'
if not md.exists():
    shutil.copytree(tree / 'libmd-1.2.0', md, ignore=shutil.ignore_patterns(
        '*.o', '*.lo', '*.la', '.libs', '.deps', 'ipkg-*', 'apk-*', '.pkgdir',
        'config.log', 'config.status', 'config.h', 'libtool', 'stamp-h1', '.built*', '.configured*'))
env = dict(os.environ, CC=str(root / 'softcc'), AR=prefix+'ar', RANLIB=prefix+'ranlib',
    STRIP=prefix+'strip', CFLAGS='-O2 -fPIC', SOURCE_DATE_EPOCH=EPOCH,
    PKG_CONFIG_PATH='', PKG_CONFIG_LIBDIR=str(sysroot / 'usr/lib/pkgconfig'),
    PKG_CONFIG_SYSROOT_DIR=str(sysroot))
logdir = BASE / 'logs' / ('soft-ucode-modules-' + root.name); logdir.mkdir(exist_ok=True)
with (logdir / 'libmd-build.txt').open('w') as output:
    for command in ([str(md / 'configure'), '--host=aarch64-openwrt-linux-musl',
                     '--build=x86_64-pc-linux-gnu', '--prefix=/usr', '--libdir=/usr/lib',
                     '--disable-static', '--enable-shared'], ['make', '-j4'],
                    ['make', 'install', 'DESTDIR='+str(sysroot)]):
        r = subprocess.run(command, cwd=md, env=env, stdout=output, stderr=subprocess.STDOUT)
        if r.returncode:
            print((logdir / 'libmd-build.txt').read_text()[-5500:]); raise SystemExit(r.returncode)
source = root / 'source-ucode-lib'
if not source.exists():
    shutil.copytree(tree / 'ucode-2026.10.18~d2e8b8d2/lib', source,
                    ignore=shutil.ignore_patterns('*.o', '*.so', '*.a'))
bridge = root / 'source-lua-bridge'; bridge.mkdir(exist_ok=True)
cached_bridge = SDK / 'feeds/luci/contrib/package/ucode-mod-lua/src/lua.c'
shutil.copyfile(cached_bridge, bridge / 'lua.c')
compat_headers = root / 'source-ucode-include'
if not compat_headers.exists():
    shutil.copytree(tree / 'ucode-2026.10.18~d2e8b8d2/include', compat_headers)
export_map = root / 'ucode-module-exports.map'
export_map.write_text('{ global: uc_module_entry; local: *; };\n')
common = [str(root / 'softcc'), '-O2', '-D_GNU_SOURCE', '-fPIC', '-shared',
          '-Wl,--version-script='+str(export_map),
          '-I'+str(compat_headers), '-I'+str(sysroot / 'usr/include'),
          '-I'+str(sysroot / 'usr/include/libnl-tiny'),
          '-L'+str(sysroot / 'usr/lib')]
for name, path, flags in (
    ('digest', source / 'digest.c', ['-DHAVE_DIGEST_EXTENDED', '-lmd']),
    ('nl80211', source / 'nl80211.c', ['-lnl-tiny', '-lubox']),
    ('rtnl', source / 'rtnl.c', ['-lnl-tiny', '-lubox']),
    ('lua', bridge / 'lua.c', ['-llua'])):
    command = common + [str(path), *flags, '-lucode', '-o', str(sysroot / 'usr/lib/ucode' / (name+'.so'))]
    r = subprocess.run(command, capture_output=True, text=True)
    (logdir / (name + '-build.txt')).write_text(r.stdout + r.stderr)
    if r.returncode: print(r.stdout + r.stderr); raise SystemExit(r.returncode)
    dynamic = subprocess.check_output([prefix+'readelf', '--dyn-syms', '--wide',
        str(sysroot / 'usr/lib/ucode' / (name+'.so'))], text=True)
    exported = set()
    for line in dynamic.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].rstrip(':').isdigit() and fields[6] != 'UND' and fields[4] in ('GLOBAL', 'WEAK'):
            exported.add(fields[7])
    assert exported == {'uc_module_entry'}, (name, exported)
    print('NATIVE_UCODE_MODULE_BUILT', name, flush=True)
previous = json.loads((prior / 'audited/manifest.json').read_text())
# Preserve the already-audited53 inputs byte for byte; only the newly compiled
# module paths and their dynamic library closure are added to this fresh root.
initial = {name: prior / 'audited' / name for name in previous['files']}
for name in ('digest', 'nl80211', 'rtnl', 'lua'):
    initial['ucode-modules/'+name+'.so'] = sysroot / 'usr/lib/ucode' / (name+'.so')
bindings_art = BASE / 'artifacts/a64-soft-lua-bindings'
bindings_bytes = (bindings_art / 'manifest.json').read_bytes()
bindings = json.loads(bindings_bytes)
with tarfile.open(bindings_art / 'bindings.tar') as tar:
    for name in ('nixio.so', 'uci.so', 'ubus.so', 'uloop.so'):
        member = tar.getmember(name); assert member.isfile()
        data = tar.extractfile(member).read()
        assert hashlib.sha256(data).hexdigest() == bindings['files'][name]['sha256']
        for dep in bindings['files'][name]['needed']:
            assert bindings['files'][dep]['sha256'] == previous['files'][dep]['sha256'], (name, dep)
        target = sysroot / 'usr/lib/lua' / name
        assert not target.exists()
        target.write_bytes(data)
        initial['lua-modules/'+name] = target
files = audit(initial, sysroot, root / 'audited', prefix)
sources = dict(previous['source_hashes'])
sources['qualified-lua-bindings'] = dict(manifest_sha256=hashlib.sha256(bindings_bytes).hexdigest(),
    selected_files={name: bindings['files'][name]['sha256'] for name in ('nixio.so', 'uci.so', 'ubus.so', 'uloop.so')})
sources['ucode-internal-compat-headers'] = {p.relative_to(compat_headers).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
    for p in sorted(compat_headers.rglob('*')) if p.is_file()}
for name, path in (('libmd', md), ('ucode-extra', source), ('ucode-lua-bridge', bridge)):
    sources[name] = {p.relative_to(path).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(path.rglob('*')) if p.is_file() and
        (p.suffix in ('.c', '.h', '.in', '.ac') or p.name in ('COPYING', 'LICENSE'))}
manifest = dict(abi='AAPCS64-soft', files=files, source_hashes=sources,
    dependency_closure_audited=True, strong_symbols_closed=True,
    new_module_export_policy='uc_module_entry only; hide weak initializer from Lua RTLD_GLOBAL scope',
    system_services_replaced=False, full_device_ui_qualified=False)
(root / 'audited/manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
art = BASE / 'artifacts/a64-soft-ucode-modules'; art.mkdir(exist_ok=True)
shutil.copyfile(root / 'audited/manifest.json', art / 'manifest.json')
with tarfile.open(art / 'luci.tar', 'w') as tar:
    for name in files:
        data = (root / 'audited' / name).read_bytes(); info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(data), 0o755, int(EPOCH); tar.addfile(info, io.BytesIO(data))
print('NATIVE_UCODE_INSTALLED_MODULE_CLOSURE_AUDITED', len(files), flush=True)
