# SPDX-License-Identifier: MIT
"""Isolated AAPCS64 soft-float musl experiment, never alters either SDK."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
from a64_soft_context import BASE as base, SDK as sdk, ROOT as experiment, EPOCH

original,=sdk.glob('build_dir/toolchain-aarch64*/musl-1.2.6')
gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
parser=argparse.ArgumentParser()
parser.add_argument('stage',choices=('prepare','libc','runtime','link'))
args=parser.parse_args()
experiment.mkdir(exist_ok=True)
source=experiment/'musl'; build=experiment/'musl-build'
env=dict(os.environ);env['PATH']='/root/be6l-openwrt/host/bin:'+str(gcc.parent)+':'+env['PATH']
env['SOURCE_DATE_EPOCH']=EPOCH
if args.stage=='prepare':
    assert not source.exists(), 'Refuse to overwrite an existing experiment'
    shutil.copytree(original,source,ignore=shutil.ignore_patterns('obj','lib','config.mak','.git'))
    changes=[]
    # Use existing generic C implementations instead of SIMD/math/fenv assembly.
    for folder in ('src/string/aarch64','src/math/aarch64','src/fenv/aarch64'):
        for path in (source/folder).iterdir():
            if path.is_file():
                changes.append({'path':str(path.relative_to(source)),
                                'operation':'omit_arch_override',
                                'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
                path.unlink()
    # AAPCS64 soft-float has no callee-saved SIMD registers. Keep jmp_buf size
    # unchanged while omitting only those register saves/restores.
    for path in (source/'src/setjmp/aarch64').glob('*.s'):
        before=path.read_text()
        after=re.sub(r'^\s*(?:stp|ldp)\s+d\d+[^\n]*\n','',before,flags=re.M)
        assert len(before.splitlines())-len(after.splitlines())==4
        path.write_text(after)
        changes.append({'path':str(path.relative_to(source)), 'diff': ''.join(
            difflib.unified_diff(before.splitlines(True),after.splitlines(True),
                                fromfile='a/'+str(path.relative_to(source)),
                                tofile='b/'+str(path.relative_to(source))))})
    # Use the same no-FPU fenv contract as musl's other software-float targets.
    path=source/'arch/aarch64/bits/fenv.h'
    before=path.read_text();after=(source/'arch/generic/bits/fenv.h').read_text()
    path.write_text(after)
    changes.append({'path':str(path.relative_to(source)), 'diff': ''.join(
        difflib.unified_diff(before.splitlines(True),after.splitlines(True),
                            fromfile='a/arch/aarch64/bits/fenv.h',tofile='b/arch/aarch64/bits/fenv.h'))})
    path=source/'arch/aarch64/reloc.h';before=path.read_text()
    needle='#define LDSO_ARCH "aarch64"'
    assert before.count(needle)==1
    after=before.replace(needle,'#define LDSO_ARCH "aarch64-soft"')
    path.write_text(after)
    changes.append({'path':str(path.relative_to(source)), 'diff': ''.join(
        difflib.unified_diff(before.splitlines(True),after.splitlines(True),
                            fromfile='a/arch/aarch64/reloc.h',tofile='b/arch/aarch64/reloc.h'))})
    (experiment/'source-changes.json').write_text(json.dumps(changes,indent=2)+'\n')
    wrapper=experiment/'cc'
    wrapper.write_text('#!/bin/sh\nexec /usr/bin/clang --target=aarch64-linux-musl '
        '-march=armv8-a+nofp+nosimd -mabi=aapcs-soft -mno-outline-atomics -ffp-contract=off '
        '--sysroot='+str(gcc.parent.parent)+' --ld-path='+prefix+'ld '
        '-ffile-prefix-map='+str(experiment)+'=/build/a64-soft '
        '-ffile-prefix-map='+str(sdk)+'=/build/openwrt-sdk '
        '-ffile-prefix-map='+str(base)+'=/build/be6l-src '
        '-Wl,--build-id=none "$@"\n')
    wrapper.chmod(0o755)
    build.mkdir()
    subprocess.run([str(source/'configure'),'--target=aarch64-linux-musl',
        '--prefix='+str(experiment/'sysroot'),'--disable-gcc-wrapper','--enable-debug',
        '--syslibdir='+str(experiment/'sysroot/lib'),
        'CC='+str(wrapper),'AR='+prefix+'ar','RANLIB='+prefix+'ranlib',
        'CFLAGS=-O2 -fno-stack-protector -fno-vectorize -fno-slp-vectorize',
        'LIBCC='+str(experiment/'libsoft-builtins.a')],cwd=build,env=env,check=True)
elif args.stage=='libc':
    # Reuse musl's generic volatile-memory barriers, rather than the AArch64
    # inline-assembly version with FP-register constraints.
    shutil.copyfile(source/'arch/generic/fp_arch.h',source/'arch/aarch64/fp_arch.h')
    log=base/'logs/a64-soft-musl-build.txt'
    with log.open('w') as output:
        result=subprocess.run(['make','-j4','lib/libc.a'],cwd=build,env=env,
            stdout=output,stderr=subprocess.STDOUT)
    print(log)
    if result.returncode:
        print(log.read_text()[-7000:])
    raise SystemExit(result.returncode)
elif args.stage=='runtime':
    bundle=base/'upstream/llvm21-soft-builtins'
    manifest=json.loads((bundle/'manifest.json').read_text(encoding='utf-8-sig'))
    objects=experiment/'runtime-objects';objects.mkdir(exist_ok=True)
    outputs=[]
    log=base/'logs/a64-soft-runtime-build.txt'
    with log.open('w') as output:
        for item in manifest['files']:
            path=bundle/item['name']
            assert hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256']
            if path.suffix!='.c':continue
            dest=objects/(path.stem+'.o')
            command=[str(experiment/'cc'),'-O2','-fPIC','-ffreestanding',
                     '-fno-stack-protector','-fno-vectorize','-fno-slp-vectorize',
                     '-D__SOFT_FP__=1','-I'+str(bundle),'-c',str(path),'-o',str(dest)]
            result=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT)
            if result.returncode:
                print(log.read_text()[-5000:]);raise SystemExit(result.returncode)
            outputs.append(str(dest))
    subprocess.run([prefix+'ar','rcs',str(experiment/'libsoft-builtins.a'),*outputs],check=True)
    print('Runtime objects:',len(outputs))
else:
    log=base/'logs/a64-soft-musl-link.txt'
    with log.open('w') as output:
        result=subprocess.run(['make','-j4','all','install'],cwd=build,env=env,
                              stdout=output,stderr=subprocess.STDOUT)
    print(log)
    if result.returncode:
        print('\n'.join(line for line in log.read_text().splitlines()
                        if 'undefined reference' in line or 'error:' in line))
    raise SystemExit(result.returncode)
