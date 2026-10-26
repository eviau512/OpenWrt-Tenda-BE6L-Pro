# SPDX-License-Identifier: MIT
"""Build cached UCI/ubus/uloop Lua bindings in an owned soft-Lua root."""
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
args=parser.parse_args()
root=args.root
assert root.is_absolute() and (root/'.be6l-soft-lua.json').is_file()
assert json.loads((root/'.be6l-soft-lua.json').read_text())['abi']=='AAPCS64-soft'
assert '-ffp-contract=off' in (root/'cc').read_text()
env=dict(os.environ,BE6L_SOFT_ROOT=str(root))
for name in ('libubox','ubus','uci'):
    subprocess.run([sys.executable,str(BASE/'tools/build_a64_soft_core.py'),name,'--lua'],env=env,check=True)
gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
sysroot=root/'sysroot'
selected={'lua':root/'lua/src/lua5.1','luac':root/'lua/src/luac5.1','nixio.so':root/'nixio/nixio.so',
          'liblua.so.5.1.5':sysroot/'usr/lib/liblua.so.5.1.5',
          'ubusd':sysroot/'usr/sbin/ubusd'}
for name in ('ubus','uci','uloop'):
    selected[name+'.so']=sysroot/'usr/lib/lua'/(name+'.so')
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
            choices=[sysroot/d/dep for d in ('lib','usr/lib') if (sysroot/d/dep).is_file()]
            assert len(choices)==1,(name,dep)
            selected[dep]=choices[0];pending.append(dep)
out=root/'audited-bindings'
out.mkdir(exist_ok=True)
files,definitions,unresolved={},set(),set()
for name,source in selected.items():
    data=source.read_bytes()
    assert data[:5]==b'\x7fELF\x02' and data[18:20]==b'\xb7\0'
    dis=subprocess.check_output([prefix+'objdump','-d',str(source)],text=True)
    for line in dis.splitlines():
        if '\t' not in line:continue
        ins=line.split('\t',2)[-1]
        if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):continue
        assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins),(name,ins)
    symbols=subprocess.check_output([prefix+'readelf','--dyn-syms','--wide',str(source)],text=True)
    for line in symbols.splitlines():
        p=line.split()
        if len(p)<8 or not re.fullmatch(r'\d+:',p[0]):continue
        symbol=p[7].split('@')[0]
        if p[6]=='UND' and p[4]=='GLOBAL':unresolved.add(symbol)
        elif p[6]!='UND' and p[4] in ('GLOBAL','WEAK'):definitions.add(symbol)
    target=out/name
    shutil.copyfile(source,target)
    subprocess.run([prefix+'strip','--strip-debug',str(target)],check=True)
    files[name]={'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
                 'bytes':target.stat().st_size,'needed':needed[name],
                 'elf_class':64,'machine':183,'fp_simd_register_uses':0}
assert not unresolved-definitions,sorted(unresolved-definitions)
manifest={'abi':'AAPCS64-soft','files':files,'strong_dynamic_symbols_closed':True,
          'hardware_runtime_qualified':False,'standard_apk_package':False,
          'replaces_system_libraries':False,'lua_modules':['nixio','uci','ubus','uloop']}
artifact=BASE/'artifacts/a64-soft-lua-bindings'
artifact.mkdir(exist_ok=True)
for path in (out/'manifest.json',artifact/'manifest.json'):
    path.write_text(json.dumps(manifest,indent=2)+'\n')
(BASE/'logs'/('soft-lua-bindings-'+root.name+'.json')).write_text(json.dumps(manifest,indent=2)+'\n')
with tarfile.open(artifact/'bindings.tar','w') as archive:
    for name in files:
        data=(out/name).read_bytes();info=tarfile.TarInfo(name)
        info.size,info.mode,info.mtime=len(data),0o755,int(EPOCH)
        archive.addfile(info,io.BytesIO(data))
print('SOFT_LUA_BINDINGS_CLOSURE_AUDITED',len(files),flush=True)
