# SPDX-License-Identifier: MIT
"""Rebuild only private rpcd/uhttpd plugin paths using locked cached inputs."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import os
import shutil
import subprocess
from a64_soft_context import BASE, SDK, EPOCH

p=argparse.ArgumentParser(description=__doc__); p.add_argument('--work',type=Path,required=True); a=p.parse_args()
work=a.work.resolve()
assert work.parent==Path('/root/be6l-openwrt') and work.name.startswith('native-service-paths-v1-')
assert not work.exists(); work.mkdir()
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
roots={'rpcd':Path('/root/be6l-openwrt/a64-soft-luci-repro-long-v2'),
       'uhttpd':Path('/root/be6l-openwrt/a64-soft-services-repro-long-v2')}
commands=[]; records={}; outputs={}
for component,prior in roots.items():
    source=work/('source-'+component); original=prior/('source-'+component)
    shutil.copytree(original,source,symlinks=False,ignore=shutil.ignore_patterns(
        'CMakeFiles','CMakeCache.txt','*.o','*.a','*.so','*.so.*','.git','apk-*','ipkg-*','.pkgdir'))
    original_hashes={f.relative_to(source).as_posix():sha(f) for f in source.rglob('*') if f.is_file()}
    if component=='rpcd':
        file=source/'include/rpcd/plugin.h'; before=file.read_text()
        old='#define RPC_LIBRARY_DIRECTORY\tINSTALL_PREFIX "/lib/rpcd"'
        assert before.count(old)==1
        after=before.replace(old,'#define RPC_LIBRARY_DIRECTORY\t"/opt/be6l-a64-soft/lib/rpcd"')
        assert '#define RPC_PLUGIN_DIRECTORY\tINSTALL_PREFIX "/libexec/rpcd"' in after
        assert '#define RPC_UCSCRIPT_DIRECTORY INSTALL_PREFIX "/share/rpcd/ucode"' in (source/'ucode.c').read_text()
    else:
        file=source/'main.c'; before=file.read_text(); after=before
        for name in ('lua','ucode','ubus'):
            old='uh_plugin_init("uhttpd_'+name+'.so")'
            assert after.count(old)==1
            after=after.replace(old,'uh_plugin_init("/opt/be6l-a64-soft/lib/uhttpd/uhttpd_'+name+'.so")')
    file.write_text(after)
    patches=[''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),
        fromfile=str(file.relative_to(work)),tofile=str(file.relative_to(work))))]
    def replace_file(path, old, new):
        previous=path.read_text(); assert previous.count(old)==1,(path,old)
        updated=previous.replace(old,new); path.write_text(updated)
        patches.append(''.join(difflib.unified_diff(previous.splitlines(True),updated.splitlines(True),
            fromfile=str(path.relative_to(work)),tofile=str(path.relative_to(work)))))
    search='\tuc_search_path_init(&config.module_search_path);'
    private_search='\n'.join('\tuc_search_path_add(&config.module_search_path, "'+path+'");' for path in (
        '/opt/be6l-a64-soft/lib/ucode/*.so','/usr/share/ucode/*.uc','./*.uc'))
    replace_file(source/'ucode.c',search,private_search)
    if component=='uhttpd':
        replace_file(source/'tls.c','dlopen("libustream-ssl." LIB_EXT,',
            'dlopen("/lib/aarch64-soft/libustream-ssl." LIB_EXT,')
        replace_file(source/'lua.c','\tluaL_openlibs(L);','\n'.join((
            '\tluaL_openlibs(L);','\tlua_getglobal(L, "package");',
            '\tlua_pushliteral(L, "/opt/be6l-a64-soft/lib/lua/?.so;/opt/be6l-a64-soft/lib/lua/?/init.so");',
            '\tlua_setfield(L, -2, "cpath");','\tlua_pop(L, 1);')))
    (work/(component+'-paths.patch')).write_text(''.join(patches))
    toolchain=prior/'soft-toolchain.cmake'
    flags=(prior/'cc').read_text()
    for flag in ('-march=armv8-a+nofp+nosimd','-mabi=aapcs-soft','-ffp-contract=off'):
        assert flag in flags
    build=work/('build-'+component)
    options=['-DCMAKE_TOOLCHAIN_FILE='+str(toolchain),'-DCMAKE_INSTALL_PREFIX=/usr',
        '-DCMAKE_INSTALL_LIBDIR=lib','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_SKIP_RPATH=ON',
        '-DCMAKE_POLICY_VERSION_MINIMUM=3.5','-DCMAKE_C_FLAGS=-O2 -Wno-error=sign-compare']
    if component=='rpcd':options+=['-DIWINFO_SUPPORT=ON','-DFILE_SUPPORT=ON','-DRPCSYS_SUPPORT=ON','-DUCODE_SUPPORT=ON']
    else:options+=['-DTLS_SUPPORT=ON','-DLUA_SUPPORT=ON','-DUBUS_SUPPORT=ON','-DUCODE_SUPPORT=ON',
        '-DLUA_CFLAGS=-I'+str(prior/'sysroot/usr/include'),'-DLUA_LIBS=lua']
    env=dict(os.environ,SOURCE_DATE_EPOCH=EPOCH,PKG_CONFIG_PATH='',
        PKG_CONFIG_LIBDIR=str(prior/'sysroot/usr/lib/pkgconfig'),PKG_CONFIG_SYSROOT_DIR=str(prior/'sysroot'))
    env['PATH']='/root/be6l-openwrt/host/bin:'+str(SDK/'staging_dir/host/bin')+':'+env['PATH']
    for label,command in (('configure',['cmake','-S',source,'-B',build,*options]),
                           ('compile',['cmake','--build',build,'-j4'])):
        command=[str(x) for x in command]; commands.append(command)
        with (work/(component+'-'+label+'.log')).open('wb') as log:
            result=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT)
        assert result.returncode==0,(component,label,result.returncode)
    selected={('opt/be6l-a64-soft/bin/'+component):build/component}
    if component=='rpcd':selected.update({'opt/be6l-a64-soft/lib/rpcd/'+name+'.so':build/(name+'.so') for name in ('file','iwinfo','rpcsys','ucode')})
    else:selected.update({'opt/be6l-a64-soft/lib/uhttpd/uhttpd_'+name+'.so':build/('uhttpd_'+name+'.so') for name in ('lua','ubus','ucode')})
    gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
    for name,binary in selected.items():
        assert binary.is_file(),binary
        target=work/'payload'/name; target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(binary,target)
        subprocess.run([str(gcc)[:-3]+'strip','--strip-debug',target],check=True)
        target.chmod(0o755)
        outputs[name]=dict(sha256=sha(target),bytes=target.stat().st_size,component=component)
    final_hashes={f.relative_to(source).as_posix():sha(f) for f in source.rglob('*') if f.is_file()}
    records[component]=dict(original_source_files=original_hashes,patched_source_files=final_hashes,
        patch_sha256=sha(work/(component+'-paths.patch')),toolchain_sha256=sha(toolchain),
        softcc_sha256=sha(prior/'softcc'),compiler_wrapper_sha256=sha(prior/'cc'))
rpcd=(work/'payload/opt/be6l-a64-soft/bin/rpcd').read_bytes()
assert b'/opt/be6l-a64-soft/lib/rpcd\0' in rpcd and b'/usr/lib/rpcd\0' not in rpcd
ucode=(work/'payload/opt/be6l-a64-soft/lib/rpcd/ucode.so').read_bytes()
assert b'/opt/be6l-a64-soft/lib/rpcd/ucode.so\0' in ucode
assert b'/opt/be6l-a64-soft/lib/ucode/*.so\0' in ucode
httpd=(work/'payload/opt/be6l-a64-soft/bin/uhttpd').read_bytes()
assert b'/lib/aarch64-soft/libustream-ssl.so\0' in httpd
for name in ('lua','ubus','ucode'):
    assert ('/opt/be6l-a64-soft/lib/uhttpd/uhttpd_'+name+'.so\0').encode() in httpd
    assert ('\0uhttpd_'+name+'.so\0').encode() not in httpd
assert b'/opt/be6l-a64-soft/lib/lua/?.so;/opt/be6l-a64-soft/lib/lua/?/init.so\0' in (work/'payload/opt/be6l-a64-soft/lib/uhttpd/uhttpd_lua.so').read_bytes()
assert b'/opt/be6l-a64-soft/lib/ucode/*.so\0' in (work/'payload/opt/be6l-a64-soft/lib/uhttpd/uhttpd_ucode.so').read_bytes()
report=dict(schema=1,kind='native-service-private-plugin-paths-v1',work=str(work),outputs=outputs,
    sources=records,commands=commands,shared_text_rpcd_paths_unchanged=True,
    tls_backend='absolute /lib/aarch64-soft/libustream-ssl.so',
    embedded_vm_c_modules_private_only=True,embedded_vm_shared_text_search_paths_preserved=True,
    builder_sha256=sha(Path(__file__)),
    install_or_sdk_modification_performed=False,target_execution_performed=False,
    normal_package_and_exact_fixture_admission_pending=True)
(work/'build-receipt.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps(dict(work=str(work),receipt_sha256=sha(work/'build-receipt.json'),rebuilt_paths=len(outputs),
    target_execution=False,sdk_modified=False),indent=2))
