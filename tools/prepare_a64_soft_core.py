# SPDX-License-Identifier: MIT
"""Audit and package only new soft-float C programs for isolated RAM testing."""
from pathlib import Path
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
from a64_soft_context import BASE as base, SDK as sdk, ROOT

root=ROOT/'sysroot'
gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
out=base/'artifacts/a64-soft-core';out.mkdir(exist_ok=True)
selected={'libc.so':root/'lib/libc.so'}
selected['busybox']=base/'artifacts/a64-soft-userspace/busybox'
for folder in ('usr/lib','usr/lib/ucode'):
    for path in (root/folder).glob('*.so*'):
        if path.is_file():
            name=('modules/' if folder.endswith('/ucode') else '')+path.name
            selected[name]=path
for folder,names in [('usr/bin',('ubus','uci','ucode','jshn')),
                     ('usr/sbin',('ubusd','procd','init'))]:
    for name in names:selected[name]=root/folder/name
manifest={}
for name,source in selected.items():
    data=source.read_bytes()
    assert data[:5]==b'\x7fELF\x02' and data[18:20]==b'\xb7\x00'
    dis=subprocess.check_output([prefix+'objdump','-d',str(source)],text=True)
    bad=[]
    for line in dis.splitlines():
        if '\t' not in line:continue
        ins=line.split('\t',2)[-1]
        if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):continue
        if re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins):bad.append(ins)
    assert not bad,(name,bad[:8])
    target=out/name;target.parent.mkdir(exist_ok=True)
    shutil.copyfile(source,target)
    subprocess.run([prefix+'strip','--strip-debug',str(target)],check=True)
    data=target.read_bytes()
    dynamic=subprocess.check_output([prefix+'readelf','-d',str(target)],text=True)
    needed=re.findall(r'\(NEEDED\).*?\[(.*?)\]',dynamic)
    manifest[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                    'needed':needed,'machine':183,'fp_simd_register_uses':0}
for name,item in manifest.items():
    assert all(dep in manifest for dep in item['needed']),(name,item['needed'])
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
with tarfile.open(out/'core.tar','w') as archive:
    for name in manifest:
        info=tarfile.TarInfo(name);data=(out/name).read_bytes();info.size=len(data);info.mode=0o700
        archive.addfile(info,io.BytesIO(data))
print('Audited native soft-float ELF files:',len(manifest))
