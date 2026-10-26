# SPDX-License-Identifier: MIT
"""Build/audit real native netifd in a new soft-ABI root, never run the daemon.

All sources and dependencies already cached. No SDK or existing native root is
modified, no network configuration is read and no DUT is contacted.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from a64_soft_context import BASE, SDK, EPOCH

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root',type=Path,required=True)
parser.add_argument('--base-soft-root',type=Path,required=True)
parser.add_argument('--resume',action='store_true')
args=parser.parse_args()
root,prior=args.root,args.base_soft_root
assert root.is_absolute() and prior.is_absolute()
assert '-ffp-contract=off' in (prior/'cc').read_text()
marker=dict(abi='AAPCS64-soft',base=str(prior))
if args.resume:
    assert json.loads((root/'.be6l-soft-netifd.json').read_text())==marker
else:
    assert not root.exists()
    root.mkdir()
    (root/'.be6l-soft-netifd.json').write_text(json.dumps(marker)+'\n')
    shutil.copytree(prior/'sysroot',root/'sysroot',symlinks=True)
    shutil.copyfile(prior/'libsoft-builtins.a',root/'libsoft-builtins.a')
    for name in ('cc','softcc','soft-toolchain.cmake'):
        (root/name).write_text((prior/name).read_text().replace(str(prior),str(root)))
        (root/name).chmod(0o755)
env=dict(os.environ,BE6L_SOFT_ROOT=str(root))
for component in ('libnl-tiny','netifd'):
    subprocess.run([sys.executable,str(BASE/'tools/build_a64_soft_core.py'),component],env=env,check=True)
gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
selected={'netifd':root/'sysroot/usr/sbin/netifd'}
pending=list(selected)
needed={}
while pending:
    name=pending.pop()
    dynamic=subprocess.check_output([prefix+'readelf','-d',str(selected[name])],text=True)
    assert not re.search(r'\((?:RPATH|RUNPATH)\)',dynamic),name
    needed[name]=re.findall(r'\(NEEDED\).*?\[(.*?)\]',dynamic)
    for dep in needed[name]:
        assert re.fullmatch('[A-Za-z0-9_.-]+',dep)
        if dep not in selected:
            candidates=[root/'sysroot'/d/dep for d in ('lib','usr/lib') if (root/'sysroot'/d/dep).is_file()]
            assert len(candidates)==1,(name,dep)
            selected[dep]=candidates[0];pending.append(dep)
out=root/'audited'
out.mkdir()
files,definitions,undefined={},{},{}
for name,p in sorted(selected.items()):
    target=out/name
    shutil.copyfile(p,target)
    subprocess.run([prefix+'strip','--strip-debug',str(target)],check=True)
    data=target.read_bytes()
    assert data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\xb7\0'
    dis=subprocess.check_output([prefix+'objdump','-d',str(target)],text=True)
    for line in dis.splitlines():
        if '\t' not in line:continue
        ins=line.split('\t',2)[-1]
        if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):continue
        assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins),(name,ins)
    symbols=subprocess.check_output([prefix+'readelf','--dyn-syms','--wide',str(target)],text=True)
    definitions[name],undefined[name]=set(),set()
    for line in symbols.splitlines():
        parts=line.split()
        if len(parts)<8 or not re.fullmatch(r'\d+:',parts[0]):continue
        symbol=parts[7].split('@')[0]
        if parts[6]=='UND' and parts[4]=='GLOBAL':undefined[name].add(symbol)
        elif parts[6]!='UND' and parts[4] in ('GLOBAL','WEAK'):definitions[name].add(symbol)
    files[name]=dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),needed=needed[name],
                     machine=183,fp_simd_register_uses=0)
all_definitions=set().union(*definitions.values())
for name,items in undefined.items():assert not items-all_definitions,(name,sorted(items-all_definitions))
sources={}
for component in ('libnl-tiny','netifd'):
    source=root/('source-'+component)
    sources[component]={p.relative_to(source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(source.rglob('*')) if p.is_file() and not p.is_symlink() and
        (p.suffix in ('.c','.h','.sh','.in') or p.name in ('CMakeLists.txt','Makefile','COPYING','LICENSE'))}
assert 'DUMMY_MODE:UNINITIALIZED=OFF' in (root/'core-netifd/CMakeCache.txt').read_text()
manifest=dict(abi='AAPCS64-soft',files=files,source_hashes=sources,real_linux_netlink_backend=True,
              dependency_closure_audited=True,strong_symbols_closed=True,
              native_daemon_executed=False,network_namespace_test_required=True,
              installed_on_dut=False,full_native_image_qualified=False)
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
artifact=BASE/'artifacts/a64-soft-netifd'
artifact.mkdir(exist_ok=True)
shutil.copyfile(out/'manifest.json',artifact/'manifest.json')
with tarfile.open(artifact/'netifd.tar','w') as tar:
    for name in files:
        data=(out/name).read_bytes();info=tarfile.TarInfo(name)
        info.size,info.mode,info.mtime=len(data),0o755,int(EPOCH)
        tar.addfile(info,io.BytesIO(data))
(BASE/'logs'/('soft-netifd-'+root.name+'.json')).write_text(json.dumps(manifest,indent=2)+'\n')
print('NATIVE_REAL_NETIFD_CLOSURE_AUDITED',len(files),flush=True)
