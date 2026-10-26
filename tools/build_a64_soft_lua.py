# SPDX-License-Identifier: MIT
"""Build cached Lua/Nixio in a fresh soft-ABI root; never modify either SDK."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
from a64_soft_context import BASE, SDK, EPOCH

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--base-soft-root', type=Path, required=True)
args = parser.parse_args()
root, prior = args.root, args.base_soft_root
assert root.is_absolute() and prior.is_absolute() and not root.exists()
assert '-ffp-contract=off' in (prior / 'cc').read_text(), 'Rebuild the base C suite with contraction disabled first'
assert not any(c.isspace() for c in str(root))
root.mkdir()
(root / '.be6l-soft-lua.json').write_text(json.dumps({'base': str(prior), 'abi': 'AAPCS64-soft'}) + '\n')
shutil.copytree(prior / 'sysroot', root / 'sysroot', symlinks=True)
shutil.copyfile(prior / 'libsoft-builtins.a', root / 'libsoft-builtins.a')
for name in ('cc', 'softcc'):
    path = root / name
    path.write_text((prior / name).read_text().replace(str(prior), str(root)))
    path.chmod(0o755)
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix = str(gcc)[:-3]
tree = SDK / 'build_dir/target-aarch64_cortex-a53_musl'
sources = {}
for name, version in (('lua', 'lua-5.1.5'), ('nixio', 'luci-lib-nixio')):
    source = tree / version
    assert source.is_dir(), 'Pinned source must already be cached'
    sources[name] = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(source.rglob('*')) if p.is_file() and
                     (p.suffix in ('.c', '.h') or p.name in ('Makefile', 'COPYRIGHT')) and
                     not any(x.startswith(('ipkg-', 'apk-', '.pkgdir', 'dist')) for x in p.relative_to(source).parts)}
    shutil.copytree(source, root / name, symlinks=True, ignore=shutil.ignore_patterns(
        '*.o', '*.a', '*.so*', 'ipkg-*', 'apk-*', '.pkgdir', 'dist', 'lua5.1', 'luac5.1'))
logdir = BASE / 'logs' / ('soft-lua-' + root.name)
logdir.mkdir(parents=True)
env = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH)
cflags = '-O2 -fPIC -fno-stack-protector -fno-vectorize -fno-slp-vectorize -std=gnu99 -DLUA_USE_LINUX'
with (logdir / 'build.txt').open('w') as log:
    commands = [
        ['make', '-C', str(root / 'lua/src'), '-j4', 'all', 'V=5.1', 'PKG_VERSION=5.1.5',
         'CC=' + str(root / 'softcc'), 'CFLAGS=' + cflags,
         'AR=' + prefix + 'ar rcu', 'RANLIB=' + prefix + 'ranlib',
         'MYLIBS=-Wl,-E -ldl', 'MYLDFLAGS=-Wl,-rpath-link,' + str(root / 'lua/src')],
        ['make', '-C', str(root / 'nixio'), '-j4', 'compile', 'CC=' + str(root / 'softcc'),
         'CFLAGS=' + cflags, 'FPIC=-fPIC', 'NIXIO_TLS=', 'NIXIO_SHADOW=no',
         'LUA_CFLAGS=-I' + str(root / 'lua/src'),
         'LDFLAGS=-L' + str(root / 'lua/src') + ' -Wl,-rpath-link,' + str(root / 'lua/src')],
    ]
    for command in commands:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            print((logdir / 'build.txt').read_text()[-5500:])
            raise SystemExit(result.returncode)
# Install development inputs inside this invocation's private sysroot so later
# C bindings cannot accidentally consume the SDK's ordinary hard-float Lua.
for name in ('lua.h','lualib.h','luaconf.h','lauxlib.h','lnum_config.h'):
    shutil.copyfile(root/'lua/src'/name, root/'sysroot/usr/include'/name)
for name in ('liblua.a','liblua.so.5.1.5'):
    target = root/'sysroot/usr/lib'/name
    assert not target.exists(), 'Do not overwrite a different Lua development ABI'
    shutil.copyfile(root/'lua/src'/name, target)
(root/'sysroot/usr/lib/liblua.so').symlink_to('liblua.so.5.1.5')
selected = {'lua': root / 'lua/src/lua5.1', 'luac': root / 'lua/src/luac5.1',
            'liblua.so.5.1.5': root / 'lua/src/liblua.so.5.1.5',
            'nixio.so': root / 'nixio/nixio.so', 'libc.so': root / 'sysroot/lib/libc.so'}
out = root / 'audited'
out.mkdir()
files, definitions, unresolved = {}, set(), set()
for name, source in selected.items():
    data = source.read_bytes()
    assert data[:5] == b'\x7fELF\x02' and data[18:20] == b'\xb7\0'
    dis = subprocess.check_output([prefix + 'objdump', '-d', str(source)], text=True)
    for line in dis.splitlines():
        if '\t' not in line:
            continue
        ins = line.split('\t', 2)[-1]
        if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s', ins):
            continue
        assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b', ins), (name, ins)
    dynamic = subprocess.check_output([prefix + 'readelf', '-d', str(source)], text=True)
    assert not re.search(r'\((?:RPATH|RUNPATH)\)', dynamic)
    needed = re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)
    assert all(dep in selected for dep in needed), (name, needed)
    symbols = subprocess.check_output([prefix + 'readelf', '--dyn-syms', '--wide', str(source)], text=True)
    for line in symbols.splitlines():
        p = line.split()
        if len(p) < 8 or not re.fullmatch(r'\d+:', p[0]):
            continue
        symbol = p[7].split('@')[0]
        if p[6] == 'UND' and p[4] == 'GLOBAL':
            unresolved.add(symbol)
        elif p[6] != 'UND' and p[4] in ('GLOBAL', 'WEAK'):
            definitions.add(symbol)
    target = out / name
    shutil.copyfile(source, target)
    subprocess.run([prefix + 'strip', '--strip-debug', str(target)], check=True)
    files[name] = {'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                   'bytes': target.stat().st_size, 'needed': needed, 'elf_class': 64,
                   'machine': 183, 'fp_simd_register_uses': 0}
assert not unresolved - definitions, sorted(unresolved - definitions)
manifest = {'abi': 'AAPCS64-soft', 'lua': '5.1.5 OpenWrt patched double/int32',
            'nixio_tls': False, 'nixio_shadow': False, 'source_hashes': sources,
            'files': files, 'strong_dynamic_symbols_closed': True,
            'hardware_runtime_qualified': False, 'standard_apk_package': False,
            'replaces_installed_lua': False}
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
artifact = BASE / 'artifacts/a64-soft-lua'
artifact.mkdir(exist_ok=True)
shutil.copyfile(out / 'manifest.json', artifact / 'manifest.json')
shutil.copyfile(out / 'manifest.json', logdir / 'manifest.json')
with tarfile.open(artifact / 'lua.tar', 'w') as archive:
    for name in files:
        data = (out / name).read_bytes()
        info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(data), 0o755, int(EPOCH)
        archive.addfile(info, io.BytesIO(data))
print('AAPCS64_SOFT_LUA_NIXIO_CLOSURE_AUDITED', len(files), flush=True)
