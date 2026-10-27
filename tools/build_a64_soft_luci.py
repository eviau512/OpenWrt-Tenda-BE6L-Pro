# SPDX-License-Identifier: MIT
"""Build the remaining cached native LuCI C modules in a fresh owned sysroot."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from a64_soft_context import BASE,SDK,EPOCH
from soft_elf_closure import audit

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root',type=Path,required=True)
parser.add_argument('--services-root',type=Path,required=True)
parser.add_argument('--netifd-root',type=Path,required=True)
parser.add_argument('--resume',action='store_true')
args=parser.parse_args();root,prior,nl=args.root,args.services_root,args.netifd_root
assert all(p.is_absolute() and not any(c.isspace() for c in str(p)) for p in (root,prior,nl))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(prior/'sysroot/lib/libc.so')==sha(nl/'sysroot/lib/libc.so')
marker=dict(base=str(prior),netifd=str(nl),abi='AAPCS64-soft')
if args.resume:assert json.loads((root/'.be6l-soft-luci.json').read_text())==marker
else:
    assert not root.exists();root.mkdir()
    (root/'.be6l-soft-luci.json').write_text(json.dumps(marker)+'\n')
    shutil.copytree(prior/'sysroot',root/'sysroot',symlinks=True)
    shutil.copyfile(prior/'libsoft-builtins.a',root/'libsoft-builtins.a')
    for name in ('cc','softcc','soft-toolchain.cmake'):
        (root/name).write_text((prior/name).read_text().replace(str(prior),str(root)));(root/name).chmod(0o755)
    shutil.copytree(nl/'sysroot/usr/include/libnl-tiny',root/'sysroot/usr/include/libnl-tiny')
    for p in (nl/'sysroot/usr/lib').glob('libnl-tiny.so*'):
        dest=root/'sysroot/usr/lib'/p.name
        assert not dest.exists() and not dest.is_symlink()
        if p.is_symlink():dest.symlink_to(p.readlink())
        else:shutil.copyfile(p,dest)

tree=SDK/'build_dir/target-aarch64_cortex-a53_musl'
if not (root/'sysroot/usr/include/rpcd').exists():
    shutil.copytree(tree/'rpcd-2026.10.04~d99f703e/include/rpcd',root/'sysroot/usr/include/rpcd')
recipes={'iwinfo':'libiwinfo-2026.05.26~66bdd1a0','luci-core':'luci-base/src',
         'lucihttp':'lucihttp-2023.03.15~9b5b683f','rpcd-luci':'rpcd-mod-luci-20240305',
         'rpcd-rrdns':'rpcd-mod-rrdns-20170710','rpcd':'rpcd-2026.10.04~d99f703e'}
env=dict(os.environ,SOURCE_DATE_EPOCH=EPOCH,PKG_CONFIG_PATH='',
         PKG_CONFIG_LIBDIR=str(root/'sysroot/usr/lib/pkgconfig'),PKG_CONFIG_SYSROOT_DIR=str(root/'sysroot'))
env['PATH']='/root/be6l-openwrt/host/bin:'+str(SDK/'staging_dir/host/bin')+':'+env['PATH']
logs=BASE/'logs'/('soft-luci-'+root.name);logs.mkdir(exist_ok=True)
sysroot=root/'sysroot';sources={}
extra=json.loads((BASE/'upstream/llvm21-soft-builtins-extra-lock.json').read_text())
assert extra['commit']=='2078da43e25a4623cab2d0d60decddf709aaea28'
assert len(extra['files'])==1 and extra['files'][0]['name']=='floatunsisf.c'
item=extra['files'][0];helper=BASE/'upstream/llvm21-soft-builtins-extra'/item['name']
assert sha(helper)==item['sha256'] and helper.stat().st_size==item['bytes']
bundle=BASE/'upstream/llvm21-soft-builtins'
original_lock=json.loads((BASE/'upstream/llvm21-soft-builtins-lock.json').read_text())
for entry in original_lock['files']:
    assert sha(bundle/entry['name'])==entry['sha256']
obj=root/'floatunsisf.o'
subprocess.run([str(root/'cc'),'-O2','-fPIC','-ffreestanding','-fno-stack-protector',
    '-fno-vectorize','-fno-slp-vectorize','-D__SOFT_FP__=1','-I'+str(bundle),
    '-c',str(helper),'-o',str(obj)],check=True)
gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
subprocess.run([str(gcc)[:-3]+'ar','rcs',str(root/'libsoft-builtins.a'),str(obj)],check=True)
sources['compiler-rt-extra']=extra
for component,version in recipes.items():
    cached=tree/version;source=root/('source-'+component);build=root/('build-'+component)
    assert cached.is_dir()
    if not source.exists():
        # LuCI's cached src may be a symlink to its feed. Resolve public source
        # contents into the owned copy; never leave writable build links to SDK.
        shutil.copytree(cached,source,symlinks=False,ignore=shutil.ignore_patterns(
            'CMakeFiles','CMakeCache.txt','*.o','*.a','*.so','*.so.*','ipkg-*','apk-*','.pkgdir',
            '.built*','.configured*','lemon','core.so','po2lmo','jsmin'))
    if component=='iwinfo' and not (source/'include/iwinfo').is_dir():
        shutil.copytree(cached/'include/iwinfo',source/'include/iwinfo')
    sources[component]=dict(version=version,files={p.relative_to(source).as_posix():sha(p)
        for p in sorted(source.rglob('*')) if p.is_file() and
        (p.suffix in ('.c','.h','.y','.in') or p.name in ('CMakeLists.txt','Makefile','COPYING','LICENSE'))})
    options=['-DCMAKE_TOOLCHAIN_FILE='+str(root/'soft-toolchain.cmake'),
        '-DCMAKE_INSTALL_PREFIX=/usr','-DCMAKE_INSTALL_LIBDIR=lib','-DCMAKE_BUILD_TYPE=Release',
        '-DCMAKE_SKIP_RPATH=ON','-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
        '-DCMAKE_C_FLAGS=-O2 -Wno-error=sign-compare']
    if component=='iwinfo':
        command=['make','-j4','CC='+str(root/'softcc'),
            'CFLAGS=-O2 -D_GNU_SOURCE -I'+str(sysroot/'usr/include')+' -I'+str(sysroot/'usr/include/libnl-tiny'),
            'FPIC=-fPIC','LDFLAGS=-L'+str(sysroot/'usr/lib'),'BACKENDS=nl80211','SOVERSION=20230701']
        # The standalone Makefile omits the module/CLI dependency on its shared
        # library. Build that prerequisite first rather than racing the linker.
        commands=[command+['libiwinfo.so'],command+['iwinfo.so','iwinfo']]
    elif component=='luci-core':
        commands=[['make','-j4','CC='+str(root/'softcc'),
            'CFLAGS=-O2 -I'+str(sysroot/'usr/include'),'FPIC=-fPIC',
            'LDFLAGS=-L'+str(sysroot/'usr/lib'),'core.so']]
    else:
        if component=='lucihttp':options+=['-DBUILD_TESTS=OFF','-DBUILD_LUA=ON','-DBUILD_UCODE=ON',
            '-DLUA_CFLAGS=-I'+str(sysroot/'usr/include'),'-DLUA_LIBRARIES=lua','-DLUAPATH=lib/lua']
        if component=='rpcd-luci':options+=['-DLIBNL_LIBS=nl-tiny','-DCMAKE_C_FLAGS=-O2 -Wno-error=sign-compare -Wno-error=gnu-folding-constant -I'+str(sysroot/'usr/include/libnl-tiny')]
        if component=='rpcd':options+=['-DIWINFO_SUPPORT=ON','-DFILE_SUPPORT=ON','-DRPCSYS_SUPPORT=ON','-DUCODE_SUPPORT=ON']
        commands=[['cmake','-S',str(source),'-B',str(build),*options],
                  ['cmake','--build',str(build),'-j4'],['cmake','--install',str(build)]]
    with (logs/(component+'.txt')).open('w') as output:
        for command in commands:
            local=dict(env)
            if '--install' in command:local['DESTDIR']=str(sysroot)
            r=subprocess.run(command,cwd=source,env=local,stdout=output,stderr=subprocess.STDOUT)
            if r.returncode:
                print((logs/(component+'.txt')).read_text()[-6500:]);raise SystemExit(r.returncode)
    if component=='iwinfo':
        (sysroot/'usr/include/iwinfo').mkdir(exist_ok=True)
        shutil.copyfile(source/'include/iwinfo.h',sysroot/'usr/include/iwinfo.h')
        for p in (source/'include/iwinfo').glob('*'):
            if p.is_file():shutil.copyfile(p,sysroot/'usr/include/iwinfo'/p.name)
        for p in source.glob('libiwinfo.so*'):
            dest=sysroot/'usr/lib'/p.name
            if p.is_symlink():
                if not dest.is_symlink():dest.symlink_to(p.readlink())
            else:shutil.copyfile(p,dest)
        (sysroot/'usr/lib/lua').mkdir(exist_ok=True)
        shutil.copyfile(source/'iwinfo.so',sysroot/'usr/lib/lua/iwinfo.so')
        shutil.copyfile(source/'iwinfo',sysroot/'usr/bin/iwinfo')
    if component=='luci-core':
        (sysroot/'usr/lib/ucode/luci').mkdir(exist_ok=True)
        shutil.copyfile(source/'core.so',sysroot/'usr/lib/ucode/luci/core.so')
    print('NATIVE_LUCI_COMPONENT_BUILT',component,flush=True)

initial={}
previous=json.loads((prior/'audited/manifest.json').read_text())
for name in previous['files']:
    if name.startswith('plugins/'):p=sysroot/'usr/lib/rpcd'/name.split('/')[1]
    elif name.startswith('uhttpd_'):p=sysroot/'usr/lib'/name
    elif '.so' in name:
        candidates=[sysroot/d/name for d in ('lib','usr/lib') if (sysroot/d/name).is_file()]
        assert len(candidates)==1;p=candidates[0]
    else:
        candidates=[sysroot/'usr'/d/name for d in ('bin','sbin') if (sysroot/'usr'/d/name).is_file()]
        assert len(candidates)==1;p=candidates[0]
    initial[name]=p
for pattern in ('*.so','luci/*.so'):
    for p in (sysroot/'usr/lib/ucode').glob(pattern):initial['ucode-modules/'+p.relative_to(sysroot/'usr/lib/ucode').as_posix()]=p
for p in (sysroot/'usr/lib/lua').glob('*.so'):initial['lua-modules/'+p.name]=p
for p in (sysroot/'usr/lib/rpcd').glob('*.so'):initial['plugins/'+p.name]=p
for name in ('luci','rrdns'):initial['plugins/'+name+'.so']=sysroot/'usr/lib'/str(name+'.so')
initial['iwinfo']=sysroot/'usr/bin/iwinfo'
gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
out=root/'audited';files=audit(initial,sysroot,out,str(gcc)[:-3])
manifest=dict(abi='AAPCS64-soft',files=files,source_hashes=sources,dependency_closure_audited=True,
    strong_symbols_closed=True,rpcd_iwinfo=True,core_luci_ucode=True,
    full_native_luci_qualified=False,system_services_replaced=False)
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
art=BASE/'artifacts/a64-soft-luci';art.mkdir(exist_ok=True)
shutil.copyfile(out/'manifest.json',art/'manifest.json')
with tarfile.open(art/'luci.tar','w') as tar:
    for name in files:
        data=(out/name).read_bytes();info=tarfile.TarInfo(name)
        info.size,info.mode,info.mtime=len(data),0o755,int(EPOCH);tar.addfile(info,io.BytesIO(data))
(logs/'result.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('NATIVE_LUCI_CLOSURE_AUDITED',len(files),flush=True)
