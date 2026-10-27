# SPDX-License-Identifier: MIT
"""Audit a private AAPCS64-soft dynamic ELF closure, including dlopen modules."""
from pathlib import Path
import hashlib
import re
import shutil
import subprocess

def audit(initial,sysroot,out,prefix):
    selected=dict(initial);pending=list(selected);needed={}
    while pending:
        name=pending.pop();p=selected[name]
        dynamic=subprocess.check_output([prefix+'readelf','-d',str(p)],text=True)
        assert not re.search(r'\((?:RPATH|RUNPATH)\)',dynamic),name
        needed[name]=re.findall(r'\(NEEDED\).*?\[(.*?)\]',dynamic)
        for dep in needed[name]:
            assert re.fullmatch('[A-Za-z0-9_.-]+',dep)
            if dep not in selected:
                paths=[sysroot/d/dep for d in ('lib','usr/lib') if (sysroot/d/dep).is_file()]
                assert len(paths)==1,(name,dep)
                selected[dep]=paths[0];pending.append(dep)
    out.mkdir(exist_ok=True)
    files={};defined=set();undefined={}
    for name,p in sorted(selected.items()):
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        dest=out/name;dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(p,dest);subprocess.run([prefix+'strip','--strip-debug',str(dest)],check=True)
        data=dest.read_bytes();assert data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\xb7\0'
        program=subprocess.check_output([prefix+'readelf','-lW',str(dest)],text=True)
        interp=re.findall(r'Requesting program interpreter: (.*?)\]',program)
        assert not interp or interp==['/lib/ld-musl-aarch64-soft.so.1'],(name,interp)
        dis=subprocess.check_output([prefix+'objdump','-d',str(dest)],text=True)
        for line in dis.splitlines():
            if '\t' not in line:continue
            ins=line.split('\t',2)[-1]
            if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):continue
            assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins),(name,ins)
        symbols=subprocess.check_output([prefix+'readelf','--dyn-syms','--wide',str(dest)],text=True)
        undefined[name]=set()
        for line in symbols.splitlines():
            parts=line.split()
            if len(parts)<8 or not re.fullmatch(r'\d+:',parts[0]):continue
            symbol=parts[7].split('@')[0]
            if parts[6]=='UND' and parts[4]=='GLOBAL':undefined[name].add(symbol)
            elif parts[6]!='UND' and parts[4] in ('GLOBAL','WEAK'):defined.add(symbol)
        files[name]=dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),needed=needed[name],
                         interpreter=interp,fp_simd_register_uses=0)
    for name,items in undefined.items():assert not items-defined,(name,sorted(items-defined))
    return files
