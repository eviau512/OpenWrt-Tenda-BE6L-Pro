# SPDX-License-Identifier: MIT
"""Build an isolated static BusyBox using the tested AArch64 soft-float ABI."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import argparse
import hashlib
import json
from a64_soft_context import BASE as base, SDK as sdk, ROOT as root, EPOCH

original,=sdk.glob('build_dir/target-aarch64*/busybox-*/busybox-1.38.0')
source=root/'busybox'
gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
parser=argparse.ArgumentParser();parser.add_argument('--clean',action='store_true')
args=parser.parse_args()
if not source.exists():
    shutil.copytree(original,source,ignore=shutil.ignore_patterns(
        '*.o','*.a','*.cmd','busybox','busybox_unstripped*','.git','_install'))
    text=(original/'.config').read_text()
    text=text.replace('# CONFIG_STATIC is not set','CONFIG_STATIC=y')
    (source/'.config').write_text(text)
lib=str(root/'sysroot/lib')
wrapper=root/'bbcc'
wrapper.write_text('''#!/bin/sh
link=yes
for arg do
case "$arg" in -c|-S|-E|-r|-Wl,-r|-print*|-dM|--version) link=no;; esac
done
if test "$link" = yes; then
exec CC --sysroot=SYSROOT -isystem SYSROOT/include -idirafter HEADERS -L LIB \
 -nostdlib LIB/crt1.o LIB/crti.o -Wl,--start-group "$@" RT -lc -Wl,--end-group LIB/crtn.o
else
exec CC --sysroot=SYSROOT -isystem SYSROOT/include -idirafter HEADERS "$@"
fi
'''.replace('CC',str(root/'cc')).replace('SYSROOT',str(root/'sysroot'))
    .replace('HEADERS',str(gcc.parent.parent/'include')).replace('LIB',lib)
    .replace('RT',str(root/'libsoft-builtins.a')))
wrapper.chmod(0o755)
env=dict(os.environ);env['PATH']='/root/be6l-openwrt/host/bin:'+str(gcc.parent)+':'+env['PATH']
env['SOURCE_DATE_EPOCH']=EPOCH
env['KBUILD_BUILD_TIMESTAMP']='Mon Oct 19 14:27:57 UTC 2026'
if args.clean:
    assert source.resolve()==root/'busybox'
    subprocess.run(['make','clean','SHELL=/root/be6l-openwrt/host/bin/bash'],
                   cwd=source,env=env,stdout=subprocess.DEVNULL,check=True)
log=base/'logs/a64-soft-busybox-build.txt'
with log.open('w') as output:
    result=subprocess.run(['make','-j4','ARCH=arm64','CROSS_COMPILE='+prefix,
        'CC='+str(wrapper),'HOSTCC=gcc','SHELL=/root/be6l-openwrt/host/bin/bash',
        'SKIP_STRIP=y','busybox'],cwd=source,env=env,stdout=output,stderr=subprocess.STDOUT)
print(log)
if result.returncode:print(log.read_text()[-5000:])
else:
    out=base/'artifacts/a64-soft-userspace'
    shutil.copyfile(source/'busybox',out/'busybox')
    dis=subprocess.check_output([prefix+'objdump','-d',str(out/'busybox')],text=True)
    bad=[]
    for line in dis.splitlines():
        if '\t' not in line:continue
        ins=line.split('\t',2)[-1]
        if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):continue
        if re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins):bad.append(ins)
    assert not bad,bad[:20]
    subprocess.run([prefix+'strip','--strip-debug',str(out/'busybox')],check=True)
    manifest=json.loads((out/'manifest.json').read_text())
    data=(out/'busybox').read_bytes()
    manifest['busybox']={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print('Integer-only static AArch64 BusyBox ready')
raise SystemExit(result.returncode)
