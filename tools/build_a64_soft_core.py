# SPDX-License-Identifier: MIT
"""Build cached OpenWrt C components against the isolated soft-float sysroot."""
from pathlib import Path
import argparse
import json
import os
import subprocess
import shutil
import difflib
from a64_soft_context import BASE as base, SDK as sdk, ROOT as root, EPOCH

tree=sdk/'build_dir/target-aarch64_cortex-a53_musl'
gcc,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix=str(gcc)[:-3]
sysroot=root/'sysroot'
parser=argparse.ArgumentParser()
parser.add_argument('component',choices=('jsonc','libubox','ubus','uci','ucode','udebug','procd','libnl-tiny','netifd'))
parser.add_argument('--lua',action='store_true',help='Build Lua bindings against this isolated root only')
args=parser.parse_args()
patterns={'jsonc':'json-c-0.19','libubox':'libubox-2026.07.21~e7608b69',
 'ubus':'ubus-2026.09.25~414c60a2','uci':'uci-2025.12.02~66127cd7',
 'ucode':'ucode-2026.10.18~d2e8b8d2','udebug':'udebug-2026.09.25~6726e98a',
 'procd':'procd-default/procd-2026.10.18~5aef7c33',
 'libnl-tiny':'libnl-tiny-2025.12.02~40493a65', 'netifd':'netifd-2026.09.11~06d06c86'}
wrapper=root/'softcc'
wrapper.write_text('''#!/usr/bin/python3
import os,sys
args=sys.argv[1:]
root=ROOT
flags=[root+'/cc','--sysroot='+root+'/sysroot','-isystem',root+'/sysroot/include',
 '-idirafter',HEADERS,'-Qunused-arguments','-L'+root+'/sysroot/lib',
 '-L'+root+'/sysroot/usr/lib','-Wl,-rpath-link,'+root+'/sysroot/lib:'+root+'/sysroot/usr/lib']
compile_only=any(a in ('-c','-S','-E','-r','--version','-v') or a.startswith('-print') for a in args)
if compile_only:
 command=flags+args
else:
 lib=root+'/sysroot/lib/'
 start=[] if '-shared' in args else [lib+'crt1.o']
 command=flags+['-nostdlib']+start+[lib+'crti.o','-Wl,--start-group']+args+[
  root+'/libsoft-builtins.a','-lc','-Wl,--end-group','-Wl,--exclude-libs,ALL',lib+'crtn.o']
 if '-shared' not in args and '-static' not in args:
  command+=['-Wl,--dynamic-linker=/lib/ld-musl-aarch64-soft.so.1']
os.execv(command[0],command)
'''.replace('ROOT',repr(str(root))).replace('HEADERS',repr(str(gcc.parent.parent/'include'))))
wrapper.chmod(0o755)
toolchain=root/'soft-toolchain.cmake'
toolchain.write_text('\n'.join([
 'set(CMAKE_SYSTEM_NAME Linux)','set(CMAKE_SYSTEM_PROCESSOR aarch64)',
 'set(CMAKE_C_COMPILER "'+str(wrapper)+'")',
 'set(CMAKE_AR "'+prefix+'ar")','set(CMAKE_RANLIB "'+prefix+'ranlib")',
 'set(CMAKE_SYSROOT "'+str(sysroot)+'")',
 'set(CMAKE_FIND_ROOT_PATH "'+str(sysroot)+'")',
 'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)',
 'set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)',
 'set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)',
 'set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)',
 'set(CMAKE_SKIP_RPATH TRUE)',
 'set(CMAKE_C_FLAGS_INIT "-O2 -fno-stack-protector -fno-vectorize -fno-slp-vectorize")',
 'set(CMAKE_INSTALL_LIBDIR lib CACHE STRING "")'])+'\n')
options=['-DBUILD_LUA=OFF','-DBUILD_EXAMPLES=OFF','-DBUILD_TESTING=OFF',
 '-DPKG_CONFIG_EXECUTABLE='+str(sdk/'staging_dir/host/bin/pkg-config.real'),
 '-DCMAKE_POLICY_VERSION_MINIMUM=3.5','-DCMAKE_INSTALL_PREFIX=/usr',
 '-DCMAKE_SKIP_RPATH=ON',
 '-DCMAKE_INSTALL_LIBDIR=lib','-DCMAKE_BUILD_TYPE=Release']
if args.lua:
    assert args.component in ('libubox','ubus','uci')
    assert (sysroot/'usr/include/lua.h').is_file() and (sysroot/'usr/lib/liblua.so').is_file()
    options+=['-DBUILD_LUA=ON','-DLUA_CFLAGS=-I'+str(sysroot/'usr/include'),
              '-DLUAPATH=/usr/lib/lua']
if args.component=='jsonc':options+=['-DBUILD_APPS=OFF','-DENABLE_THREADING=ON']
if args.component in ('ubus','ucode','libnl-tiny','netifd'):options+=['-DCMAKE_C_FLAGS=-O2 -Wno-error=sign-compare']
if args.component=='netifd':
    # Linux UAPI ethtool requests intentionally embed a flexible-array header
    # followed by its storage. Clang accepts this existing GNU layout with a warning.
    options+=['-DCMAKE_C_FLAGS=-O2 -Wno-error=sign-compare -Wno-error=gnu-variable-sized-type-not-at-end']
if args.component=='procd':options+=['-DJAIL_SUPPORT=ON','-DSECCOMP_SUPPORT=OFF','-DEARLY_PATH=/sbin:/bin:/usr/sbin:/usr/bin']
project_source=tree/patterns[args.component]
build=root/('core-'+args.component)
if args.component in ('libnl-tiny','netifd'):
    copy=root/('source-'+args.component)
    if not copy.exists():
        shutil.copytree(project_source,copy,ignore=shutil.ignore_patterns(
            'CMakeFiles','CMakeCache.txt','*.o','*.a','*.so','*.so.*','ipkg-*','apk-*','.pkgdir'))
    project_source=copy
    build.mkdir(exist_ok=True)
    if args.component=='netifd':
        # Upstream's custom command runs this relative to the binary directory.
        shutil.copyfile(project_source/'make_ethtool_modes_h.sh',build/'make_ethtool_modes_h.sh')
        (build/'make_ethtool_modes_h.sh').chmod(0o755)
        options+=['-DDUMMY_MODE=OFF']
if args.component=='procd':
    copy=root/'procd-source'
    if not copy.exists():
        shutil.copytree(project_source,copy,ignore=shutil.ignore_patterns(
            'CMakeFiles','CMakeCache.txt','*.o','*.a','*.so','*.so.*'))
        path=copy/'jail/jail.c';before=path.read_text()
        needle='static void free_and_exit(int ret)'
        assert before.count(needle)==1
        after=before.replace(needle,'static __attribute__((noreturn)) void free_and_exit(int ret)')
        path.write_text(after)
        (root/'procd-noreturn.patch').write_text(''.join(difflib.unified_diff(
            before.splitlines(True),after.splitlines(True),fromfile='a/jail/jail.c',tofile='b/jail/jail.c')))
    project_source=copy;build=root/'core-procd-soft'
    build.mkdir(exist_ok=True)
    for name in ('make_capabilities_h.sh','make_syscall_h.sh'):
        shutil.copyfile(project_source/name,build/name)
        (build/name).chmod(0o755)
env=dict(os.environ)
env['PATH']='/root/be6l-openwrt/host/bin:'+str(sdk/'staging_dir/host/bin')+':'+str(sdk/'staging_dir/hostpkg/bin')+':'+env['PATH']
env['PKG_CONFIG_PATH']=''
env['PKG_CONFIG_LIBDIR']=str(sysroot/'usr/lib/pkgconfig')+':'+str(sysroot/'lib/pkgconfig')
env['PKG_CONFIG_SYSROOT_DIR']=str(sysroot)
env['STAGING_DIR_HOST']=str(sdk/'staging_dir/host')
env['SOURCE_DATE_EPOCH']=EPOCH
log=base/('logs/a64-soft-core-'+args.component+'.txt')
with log.open('w') as output:
    commands=[['cmake','-S',str(project_source),'-B',str(build),
               '-DCMAKE_TOOLCHAIN_FILE='+str(toolchain),*options],
              ['cmake','--build',str(build),'-j4'],
              ['cmake','--install',str(build)]]
    for command in commands:
        local=dict(env)
        if '--install' in command:local['DESTDIR']=str(sysroot)
        result=subprocess.run(command,env=local,stdout=output,stderr=subprocess.STDOUT)
        if result.returncode:
            print(log.read_text()[-5500:]);raise SystemExit(result.returncode)
receipt={'source':patterns[args.component],'abi':'AAPCS64-soft','installed':True,
         'runtime_qualified':False}
(build/'experiment-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(args.component+' built in isolated sysroot; not runtime-qualified')
