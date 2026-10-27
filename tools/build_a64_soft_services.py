# SPDX-License-Identifier: MIT
"""Build native soft-ABI rpcd/uhttpd/mbedTLS-ustream from pinned cached sources.

Only a fresh owned sysroot is changed. No device, SDK tree or network is touched.
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
import tarfile
from a64_soft_context import BASE,SDK,EPOCH

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root',type=Path,required=True)
parser.add_argument('--base-soft-root',type=Path,required=True)
parser.add_argument('--lua-soft-root',type=Path,required=True)
parser.add_argument('--resume',action='store_true')
args=parser.parse_args()
root,prior,lua=args.root,args.base_soft_root,args.lua_soft_root
assert all(p.is_absolute() and not any(c.isspace() for c in str(p)) for p in (root,prior,lua))
assert '-ffp-contract=off' in (prior/'cc').read_text()
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert digest(prior/'sysroot/lib/libc.so')==digest(lua/'sysroot/lib/libc.so')
marker=dict(abi='AAPCS64-soft',base=str(prior),lua=str(lua))
if args.resume:
    assert json.loads((root/'.be6l-soft-services.json').read_text())==marker
else:
    assert not root.exists()
    root.mkdir();(root/'.be6l-soft-services.json').write_text(json.dumps(marker)+'\n')
    shutil.copytree(prior/'sysroot',root/'sysroot',symlinks=True)
    shutil.copyfile(prior/'libsoft-builtins.a',root/'libsoft-builtins.a')
    for name in ('cc','softcc','soft-toolchain.cmake'):
        (root/name).write_text((prior/name).read_text().replace(str(prior),str(root)))
        (root/name).chmod(0o755)
    for name in ('lua.h','luaconf.h','lualib.h','lauxlib.h','lnum_config.h'):
        shutil.copyfile(lua/'sysroot/usr/include'/name,root/'sysroot/usr/include'/name)
    for p in (lua/'sysroot/usr/lib').glob('liblua.so*'):
        dest=root/'sysroot/usr/lib'/p.name
        assert not dest.exists() and not dest.is_symlink()
        if p.is_symlink():
            target=str(p.readlink());assert not target.startswith('/') and '/' not in target
            dest.symlink_to(target)
        else:shutil.copyfile(p,dest)
for name in ('lua.h','luaconf.h','lualib.h','lauxlib.h','lnum_config.h'):
    source=lua/'sysroot/usr/include'/name;dest=root/'sysroot/usr/include'/name
    if dest.exists():assert digest(source)==digest(dest)
    else:shutil.copyfile(source,dest)

tree=SDK/'build_dir/target-aarch64_cortex-a53_musl'
recipes={
 'ustream':('ustream-ssl-mbedtls/ustream-ssl-2026.03.01~99f1c0db',['-DMBEDTLS=ON']),
 'rpcd':('rpcd-2026.10.04~d99f703e',['-DFILE_SUPPORT=ON','-DRPCSYS_SUPPORT=ON',
          '-DUCODE_SUPPORT=ON','-DIWINFO_SUPPORT=OFF']),
 'uhttpd':('uhttpd-2026.08.24~373145f7',['-DTLS_SUPPORT=ON','-DLUA_SUPPORT=ON',
          '-DUBUS_SUPPORT=ON','-DUCODE_SUPPORT=ON','-DLUA_CFLAGS=-I'+str(root/'sysroot/usr/include'),
          '-DLUA_LIBS=lua'])}
env=dict(os.environ,SOURCE_DATE_EPOCH=EPOCH,PKG_CONFIG_PATH='',
         PKG_CONFIG_LIBDIR=str(root/'sysroot/usr/lib/pkgconfig'),PKG_CONFIG_SYSROOT_DIR=str(root/'sysroot'))
env['PATH']='/root/be6l-openwrt/host/bin:'+str(SDK/'staging_dir/host/bin')+':'+env['PATH']
logs=BASE/'logs'/('soft-services-'+root.name);logs.mkdir(exist_ok=True)
sources={}
for component,(version,extra) in recipes.items():
    cached=tree/version;assert (cached/'CMakeLists.txt').is_file()
    source=root/('source-'+component);build=root/('build-'+component)
    if not source.exists():
        shutil.copytree(cached,source,symlinks=True,ignore=shutil.ignore_patterns(
            'CMakeFiles','CMakeCache.txt','*.o','*.a','*.so','*.so.*',
            'ipkg-*','apk-*','ipkg-install','.pkgdir','.built*','.configured*'))
    sources[component]=dict(version=version,files={p.relative_to(source).as_posix():digest(p)
        for p in sorted(source.rglob('*')) if p.is_file() and not p.is_symlink() and
        (p.suffix in ('.c','.h','.sh','.in') or p.name in ('CMakeLists.txt','Makefile','COPYING','LICENSE'))})
    options=['-DCMAKE_TOOLCHAIN_FILE='+str(root/'soft-toolchain.cmake'),
        '-DCMAKE_BUILD_TYPE=Release','-DCMAKE_INSTALL_PREFIX=/usr','-DCMAKE_INSTALL_LIBDIR=lib',
        '-DCMAKE_SKIP_RPATH=ON','-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
        '-DCMAKE_C_FLAGS=-O2 -Wno-error=sign-compare',
        '-DPKG_CONFIG_EXECUTABLE='+str(SDK/'staging_dir/host/bin/pkg-config.real'),*extra]
    with (logs/(component+'.txt')).open('w') as output:
        for command in (['cmake','-S',str(source),'-B',str(build),*options],
                        ['cmake','--build',str(build),'-j4'],['cmake','--install',str(build)]):
            local=dict(env)
            if '--install' in command:local['DESTDIR']=str(root/'sysroot')
            result=subprocess.run(command,env=local,stdout=output,stderr=subprocess.STDOUT)
            if result.returncode:
                print((logs/(component+'.txt')).read_text()[-6500:]);raise SystemExit(result.returncode)
    print('NATIVE_SERVICE_BUILT',component,flush=True)

gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
selected={'rpcd':root/'sysroot/usr/sbin/rpcd','uhttpd':root/'sysroot/usr/bin/uhttpd',
          'libustream-ssl.so':root/'sysroot/usr/lib/libustream-ssl.so'}
for p in (root/'sysroot/usr/lib/rpcd').glob('*.so'):selected['plugins/'+p.name]=p
for p in (root/'sysroot/usr/lib').glob('uhttpd_*.so'):selected[p.name]=p
for name in ('ubusd','ubus','ucode'):
    candidates=[root/'sysroot/usr'/d/name for d in ('bin','sbin') if (root/'sysroot/usr'/d/name).is_file()]
    assert len(candidates)==1;(selected.update({name:candidates[0]}))
selected['curl']=root/'sysroot/usr/bin/curl'
pending=list(selected);needed={}
while pending:
    name=pending.pop();p=selected[name]
    dynamic=subprocess.check_output([prefix+'readelf','-d',str(p)],text=True)
    assert not re.search(r'\((?:RPATH|RUNPATH)\)',dynamic),name
    needed[name]=re.findall(r'\(NEEDED\).*?\[(.*?)\]',dynamic)
    for dep in needed[name]:
        assert re.fullmatch('[A-Za-z0-9_.-]+',dep)
        if dep not in selected:
            matches=[root/'sysroot'/d/dep for d in ('lib','usr/lib') if (root/'sysroot'/d/dep).is_file()]
            assert len(matches)==1,(name,dep)
            selected[dep]=matches[0];pending.append(dep)
out=root/'audited';out.mkdir(exist_ok=True)
files={};defined=set();undefined={}
for name,p in sorted(selected.items()):
    target=out/name;target.parent.mkdir(exist_ok=True)
    shutil.copyfile(p,target);subprocess.run([prefix+'strip','--strip-debug',str(target)],check=True)
    data=target.read_bytes();assert data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\xb7\0'
    dis=subprocess.check_output([prefix+'objdump','-d',str(target)],text=True)
    for line in dis.splitlines():
        if '\t' not in line:continue
        ins=line.split('\t',2)[-1]
        if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):continue
        assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins),(name,ins)
    symbols=subprocess.check_output([prefix+'readelf','--dyn-syms','--wide',str(target)],text=True)
    undefined[name]=set()
    for line in symbols.splitlines():
        parts=line.split()
        if len(parts)<8 or not re.fullmatch(r'\d+:',parts[0]):continue
        symbol=parts[7].split('@')[0]
        if parts[6]=='UND' and parts[4]=='GLOBAL':undefined[name].add(symbol)
        elif parts[6]!='UND' and parts[4] in ('GLOBAL','WEAK'):defined.add(symbol)
    files[name]=dict(sha256=digest(target),bytes=len(data),needed=needed[name],fp_simd_register_uses=0)
for name,items in undefined.items():assert not items-defined,(name,sorted(items-defined))
manifest=dict(abi='AAPCS64-soft',files=files,source_hashes=sources,
    tls_backend='mbedTLS',rpcd_iwinfo=False,rpcd_file_rpcsys_ucode=True,
    uhttpd_lua_ubus_ucode_tls=True,dependency_closure_audited=True,strong_symbols_closed=True,
    native_services_executed=False,system_services_replaced=False,full_native_luci_qualified=False)
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
artifact=BASE/'artifacts/a64-soft-services';artifact.mkdir(exist_ok=True)
shutil.copyfile(out/'manifest.json',artifact/'manifest.json')
with tarfile.open(artifact/'services.tar','w') as tar:
    for name in files:
        data=(out/name).read_bytes();info=tarfile.TarInfo(name)
        info.size,info.mode,info.mtime=len(data),0o755,int(EPOCH)
        tar.addfile(info,io.BytesIO(data))
(logs/'result.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('NATIVE_SERVICE_CLOSURE_AUDITED',len(files),flush=True)
