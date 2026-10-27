# SPDX-License-Identifier: MIT
"""Add cached native HTML to the audited LuCI closure in a fresh owned root."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
from a64_soft_context import BASE, SDK, EPOCH
from soft_elf_closure import audit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--luci-root', type=Path, required=True)
args = parser.parse_args()
root, prior = args.root, args.luci_root
assert all(p.is_absolute() and not any(c.isspace() for c in str(p)) for p in (root, prior))
assert not root.exists(), 'Use a fresh output; never modify a qualified build'
root.mkdir()
(root / '.be6l-soft-luci-web.json').write_text(json.dumps(dict(base=str(prior), abi='AAPCS64-soft')) + '\n')
shutil.copytree(prior / 'sysroot', root / 'sysroot', symlinks=True)
shutil.copyfile(prior / 'libsoft-builtins.a', root / 'libsoft-builtins.a')
for name in ('cc', 'softcc', 'soft-toolchain.cmake'):
    (root / name).write_text((prior / name).read_text().replace(str(prior), str(root)))
    (root / name).chmod(0o755)
cached = SDK / 'build_dir/target-aarch64_cortex-a53_musl/ucode-mod-html/html.c'
source = root / 'source-html'; source.mkdir()
shutil.copyfile(cached, source / 'html.c')
sysroot = root / 'sysroot'
subprocess.run([str(root / 'softcc'), '-O2', '-fPIC', '-shared',
    '-I' + str(sysroot / 'usr/include'), '-L' + str(sysroot / 'usr/lib'),
    str(source / 'html.c'), '-lucode', '-o', str(sysroot / 'usr/lib/ucode/html.so')], check=True)
previous = json.loads((prior / 'audited/manifest.json').read_text())
initial = {}
for name in previous['files']:
    if name.startswith('ucode-modules/'):
        path = sysroot / 'usr/lib/ucode' / name.split('/', 1)[1]
    elif name.startswith('lua-modules/'):
        path = sysroot / 'usr/lib/lua' / name.split('/', 1)[1]
    elif name.startswith('plugins/'):
        # The standalone rpcd-luci/rrdns installs use /usr/lib, while rpcd's
        # own plugins use /usr/lib/rpcd. Match the already-audited digest.
        paths = [sysroot / 'usr/lib/rpcd' / name.split('/', 1)[1],
                 sysroot / 'usr/lib' / name.split('/', 1)[1]]
        paths = [p for p in paths if p.is_file()]
        assert len(paths) == 1, name
        path = paths[0]
    elif name.startswith('uhttpd_'):
        path = sysroot / 'usr/lib' / name
    elif '.so' in name:
        paths = [sysroot / p / name for p in ('lib', 'usr/lib') if (sysroot / p / name).is_file()]
        assert len(paths) == 1, name
        path = paths[0]
    else:
        paths = [sysroot / 'usr' / p / name for p in ('bin', 'sbin') if (sysroot / 'usr' / p / name).is_file()]
        assert len(paths) == 1, name
        path = paths[0]
    initial[name] = path
initial['ucode-modules/html.so'] = sysroot / 'usr/lib/ucode/html.so'
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
out = root / 'audited'
files = audit(initial, sysroot, out, str(gcc)[:-3])
sources = dict(previous['source_hashes'])
sources['ucode-html'] = dict(cached_source='ucode-mod-html/html.c',
    files={'html.c': hashlib.sha256((source / 'html.c').read_bytes()).hexdigest()})
manifest = dict(abi='AAPCS64-soft', files=files, source_hashes=sources,
    dependency_closure_audited=True, strong_symbols_closed=True,
    full_native_luci_qualified=False, system_services_replaced=False)
(out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
art = BASE / 'artifacts/a64-soft-luci-web'; art.mkdir(exist_ok=True)
shutil.copyfile(out / 'manifest.json', art / 'manifest.json')
with tarfile.open(art / 'luci.tar', 'w') as tar:
    for name in files:
        data = (out / name).read_bytes(); info = tarfile.TarInfo(name)
        info.size, info.mode, info.mtime = len(data), 0o755, int(EPOCH)
        tar.addfile(info, io.BytesIO(data))
print('NATIVE_LUCI_WEB_CLOSURE_AUDITED', len(files), root, flush=True)
