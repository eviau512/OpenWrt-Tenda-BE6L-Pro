# SPDX-License-Identifier: MIT
"""Build statically and dynamically linked AArch64 soft-float acceptance tests."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess
from a64_soft_context import BASE as base, SDK as sdk, ROOT as root

gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
out=base/'artifacts/a64-soft-userspace';out.mkdir(exist_ok=True)
lib=root/'sysroot/lib'
flags=[str(root/'cc'), '--sysroot='+str(root/'sysroot'), '-O2', '-fno-stack-protector',
       '-nostdlib','-I'+str(root/'sysroot/include')]
rt=str(root/'libsoft-builtins.a')
for name,kind in [('runtime-static','static'),('runtime-dynamic','dynamic')]:
    command=[*flags,'-static' if kind=='static' else '-pie',
        str(lib/('crt1.o' if kind=='static' else 'Scrt1.o')),str(lib/'crti.o'),
        str(base/'diagnostics/a64_soft_runtime_test.c'),'-L'+str(lib),
        '-Wl,--start-group','-lc',rt,'-Wl,--end-group',str(lib/'crtn.o'),'-o',str(out/name)]
    if kind=='dynamic': command+=['-Wl,--dynamic-linker=/tmp/be6l-a64-soft-test/libc.so']
    subprocess.run(command,check=True)
(out/'plugin.c').write_text('double soft_plugin_add(double a,double b){return a+b;}\n')
subprocess.run([*flags,'-fPIC','-shared',str(out/'plugin.c'),rt,'-o',str(out/'plugin.so')],check=True)
shutil.copyfile(lib/'libc.so',out/'libc.so')
manifest={}
for name in ('runtime-static','runtime-dynamic','plugin.so','libc.so'):
    path=out/name
    dis=subprocess.check_output([prefix+'objdump','-d',str(path)],text=True)
    instructions='\n'.join(line.split('\t',2)[-1] for line in dis.splitlines() if '\t' in line)
    (out/(name+'.dis')).write_text(dis)
    bad=[line for line in instructions.splitlines()
         if not re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',line)
         and re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',line)]
    assert not bad,(name,bad[:12])
    if name=='libc.so':
        # Generic fma has no source-level recursion. A compiler-contracted
        # fallback calling fma itself exhausted the real DUT's stack.
        fused=subprocess.check_output([prefix+'objdump','-d','--disassemble=fma',str(path)],text=True)
        assert not re.search(r'\bbl\s+[0-9a-f]+\s+<fma(?:@plt)?>',fused), 'Recursive fma contraction'
    subprocess.run([prefix+'strip','--strip-debug',str(path)],check=True)
    data=path.read_bytes()
    manifest[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
