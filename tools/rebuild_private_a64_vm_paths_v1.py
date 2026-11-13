# SPDX-License-Identifier: MIT
"""Rebuild private AAPCS64-soft VM defaults and re-sign their five-package graph.

Fresh work only. Ordinary A53 Lua/ucode remain unmodified and canonical. No
device, admitted root, Image, preload implementation or full ABI qualification.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
from inventory_mainroot_a53_v1 import elf, installed, rooted, scan
from package_native_netifd_v3 import copy_path, records, root_digest, sha
from plan_integer_binfmt_v1 import PRIVATE_SOFT_EFLAGS, tag_private, matches

ARCH = 'aarch64_be6l_soft_experimental'
GROUPS = ('be6l-soft-runtime','be6l-soft-tools','be6l-soft-netifd-deps','procd','netifd')
LUA_PATH = '/usr/lib/be6l-a64-soft/lua/'
UCODE_PATH = '/opt/be6l-a64-soft/lib/ucode/*.so:/usr/share/ucode/*.uc:./*.uc'
CHANGED = ('lib/aarch64-soft/liblua.so.5.1.5','lib/aarch64-soft/libucode.so','lib/aarch64-soft/libucode.so.0')


def source_records(directory):
    return {path.relative_to(directory).as_posix():sha(path) for path in sorted(directory.rglob('*'))
            if path.is_file() and not path.is_symlink() and
            (path.suffix in ('.c','.h','.cmake','.in') or path.name in ('Makefile','CMakeLists.txt','COPYRIGHT','COPYING','LICENSE'))
            and not any(part.startswith(('CMakeFiles','apk-','ipkg-','.pkgdir','.git'))
                        for part in path.relative_to(directory).parts)}


def exported(readelf, path, env):
    output = subprocess.check_output([str(readelf),'--dyn-syms','--wide',str(path)],env=env,text=True)
    result = set()
    for row in output.splitlines():
        fields = row.split()
        if len(fields) >= 8 and fields[0].endswith(':') and fields[4] in ('GLOBAL','WEAK') and fields[6] != 'UND':
            result.add(fields[7].split('@')[0])
    return result


def metadata(root):
    result = {}
    for block in (root/'lib/apk/db/installed').read_text().split('\n\n'):
        info = {line[0]:line[2:] for line in block.splitlines() if len(line)>1 and line[1]==':' and line[0] in 'PVADpTLU'}
        if info.get('P') in GROUPS:
            result[info['P']] = info
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base-composition','lua-context','sdk','host-prefix','apk','work'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--release',type=int,default=106)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-a64-vm-isolation-20261113-[a-z0-9-]+',w.name) or w.exists():
        p.error('Use a fresh /root/be6l-a64-vm-isolation-20261113-* directory')
    if not 106 <= a.release <= 999:
        p.error('Use a reviewed private package release in106..999')
    base = a.base_composition/'root'
    base_receipt = json.loads((a.base_composition/'result.json').read_text())
    before_digest = root_digest(base)
    if base_receipt.get('installed_root_records_sha256') != before_digest or not base_receipt.get('normal_signed_component_transaction'):
        raise ValueError('Signed source composition changed')
    packages, owners = installed(base)
    info = metadata(base)
    if set(info) != set(GROUPS) or any(info[name]['A'] != ARCH for name in GROUPS):
        raise ValueError('Missing complete existing five-package private graph')
    all_before = records(base)
    _, base_owners = installed(base)
    base_elf = scan(base,base_owners)
    private_before = {n:v for n,v in base_elf.items() if v['e_flags']==hex(PRIVATE_SOFT_EFLAGS)}
    if len(private_before) != 61:
        raise ValueError('Wrong complete source private ELF inventory')
    lua_source = a.lua_context/'lua'
    ucode_source = a.sdk/'build_dir/target-aarch64_cortex-a53_musl/ucode-2026.10.18~d2e8b8d2'
    sources = {'lua':source_records(lua_source),'ucode':source_records(ucode_source)}
    context_pins = {n:sha(a.lua_context/n) for n in ('cc','softcc','soft-toolchain.cmake','libsoft-builtins.a')}
    w.mkdir(mode=0o700)
    logs = w/'logs'
    logs.mkdir()
    shutil.copytree(a.lua_context/'sysroot',w/'sysroot',symlinks=True)
    shutil.copyfile(a.lua_context/'libsoft-builtins.a',w/'libsoft-builtins.a')
    for name in ('cc','softcc','soft-toolchain.cmake'):
        text = (a.lua_context/name).read_text().replace(str(a.lua_context),str(w))
        if name == 'cc':
            if '-mabi=aapcs-soft' not in text or '-march=armv8-a+nofp+nosimd' not in text or '-ffp-contract=off' not in text:
                raise ValueError('Private compiler contract missing')
            text = text.replace('/usr/bin/clang ',str(a.host_prefix/'usr/bin/clang')+' ')
        (w/name).write_text(text)
        (w/name).chmod(0o755)
    env = dict(os.environ, PATH=str(a.host_prefix/'usr/bin')+':'+str(a.sdk/'staging_dir/host/bin')+':/usr/bin:/bin',
        LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu')+':'+str(a.host_prefix/'lib/x86_64-linux-gnu'),
        SOURCE_DATE_EPOCH='1792420077', PKG_CONFIG_PATH='',
        PKG_CONFIG_LIBDIR=str(w/'sysroot/usr/lib/pkgconfig')+':'+str(w/'sysroot/lib/pkgconfig'),
        PKG_CONFIG_SYSROOT_DIR=str(w/'sysroot'))

    def run(label,command,timeout=300,good=True):
        result = subprocess.run(list(map(str,command)),env=env,capture_output=True,timeout=timeout)
        (logs/(label+'.log')).write_bytes(result.stdout+result.stderr)
        if good and result.returncode:
            raise RuntimeError(label+' failed; inspect private log')
        return result

    ignore = shutil.ignore_patterns('CMakeFiles','CMakeCache.txt','build.ninja','.ninja*','*.o','*.a','*.so','*.so.*',
        'ipkg-*','apk-*','ipkg-install','.pkgdir','.git','.built*','.configured*','.prepared*','lua5.1','luac5.1')
    shutil.copytree(lua_source,w/'lua',symlinks=True,ignore=ignore)
    shutil.copytree(ucode_source,w/'ucode',symlinks=True,ignore=ignore)
    config = w/'lua/src/luaconf.h'
    old = config.read_text()
    needle = '"./?.so;"  LUA_CDIR"?.so;" LUA_CDIR"loadall.so"'
    if old.count(needle) != 1 or old.count('"LUA_CPATH"') != 1:
        raise ValueError('Ambiguous pinned Lua C-path source interface')
    # Only C-module paths change. Shared canonical pure-.lua paths are retained.
    new = old.replace(needle,'"'+LUA_PATH+'?.so;'+LUA_PATH+'loadall.so"').replace('"LUA_CPATH"','"BE6L_A64_SOFT_LUA_CPATH"')
    config.write_text(new)
    patch = ''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/src/luaconf.h',tofile='b/src/luaconf.h'))
    (w/'private-lua-cpath.patch').write_text(patch)
    make = a.host_prefix/'usr/bin/make'
    prefix = next((a.sdk/'staging_dir').glob('toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc'))
    cross = str(prefix)[:-3]
    run('lua-build',[make,'-C',w/'lua/src','-j4','so','PKG_VERSION=5.1.5','CC='+str(w/'softcc'),
        'CFLAGS=-O2 -fPIC -fno-stack-protector -fno-vectorize -fno-slp-vectorize -std=gnu99 -DLUA_USE_LINUX',
        'MYLDFLAGS=-Wl,-rpath-link,'+str(w/'sysroot/usr/lib'), 'AR='+cross+'ar rcu','RANLIB='+cross+'ranlib'])
    cmake = a.host_prefix/'usr/bin/cmake'
    run('ucode-configure',[cmake,'-S',w/'ucode','-B',w/'ucode-build',
        '-DCMAKE_TOOLCHAIN_FILE='+str(w/'soft-toolchain.cmake'),'-DCMAKE_SKIP_RPATH=ON',
        '-DCMAKE_INSTALL_PREFIX=/usr','-DCMAKE_INSTALL_LIBDIR=lib','-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
        '-DCMAKE_C_FLAGS=-O2 -Wno-error=sign-compare','-DSOVERSION=0','-DLIB_SEARCH_PATH='+UCODE_PATH,
        '-DPKG_CONFIG_EXECUTABLE='+str(a.sdk/'staging_dir/host/bin/pkg-config.real')])
    run('ucode-build',[cmake,'--build',w/'ucode-build','--target','libucode','-j4'])
    built = {CHANGED[0]:w/'lua/src/liblua.so.5.1.5',CHANGED[1]:w/'ucode-build/libucode.so.0',CHANGED[2]:w/'ucode-build/libucode.so.0'}
    audited = w/'audited'
    audited.mkdir()
    audit = {}
    for name,source in built.items():
        target = audited/Path(name).name
        shutil.copyfile(source,target)
        run('strip-'+target.name,[cross+'strip','--strip-debug',target])
        data = target.read_bytes()
        current = elf(target)
        original = elf(base/name)
        if current is None or current['bits'] != 64 or current['machine'] != 183 or current['e_flags'] != '0x0':
            raise ValueError('Rebuilt private VM DSO ELF differs')
        if current['needed'] != original['needed'] or current['soname'] != original['soname'] or current['rpath'] or current['runpath']:
            raise ValueError('VM needed/SONAME/search ABI changed: '+name)
        exports = exported(cross+'readelf',target,env)
        if exports != exported(cross+'readelf',base/name,env):
            raise ValueError('VM exported symbol ABI changed: '+name)
        disassembly = run('disassembly-'+target.name,[cross+'objdump','-d',target]).stdout.decode()
        for line in disassembly.splitlines():
            if '\t' not in line:
                continue
            ins = line.split('\t',2)[-1]
            if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):
                continue
            if re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins):
                raise ValueError('VM DSO emits FP/SIMD: '+ins)
        if name == CHANGED[0]:
            if (LUA_PATH+'?.so').encode() not in data or b'./?.so;' in data or b'/usr/lib/lua/?.so' in data or b'BE6L_A64_SOFT_LUA_CPATH' not in data:
                raise ValueError('Private Lua C-path policy not compiled')
        elif UCODE_PATH.split(':')[0].encode() not in data or b'/usr/lib/ucode/*.so' in data or b'./*.so' in data:
            raise ValueError('Private ucode C-path policy not compiled')
        target.write_bytes(tag_private(data))
        audit[name] = dict(before_sha256=sha(base/name),sha256=sha(target),needed=current['needed'],soname=current['soname'],
            exported_symbols=sorted(exports),fp_simd_register_uses=0,private_marker=hex(PRIVATE_SOFT_EFLAGS))
    module_paths = sorted(name for name,v in private_before.items() if name.startswith('opt/be6l-a64-soft/lib/') and name.endswith('.so'))
    if len(module_paths) != 19 or sum('/lua/' in n for n in module_paths) != 4:
        raise ValueError('Incomplete private VM module inventory')
    payload = w/'payload'
    source_owned = {}
    for group in GROUPS:
        directory = payload/group
        directory.mkdir(parents=True)
        source_owned[group] = set(packages[group]['paths'])
        for name in sorted(source_owned[group]):
            if owners.get(name) != [group]:
                raise ValueError('Source payload has ambiguous ownership: '+name)
            copy_path(base/name,directory/name)
    runtime = payload/'be6l-soft-runtime'
    for name in CHANGED:
        if owners.get(name) != ['be6l-soft-runtime']:
            raise ValueError('VM override is not runtime-owned')
        shutil.copyfile(audited/Path(name).name,runtime/name)
        (runtime/name).chmod((base/name).stat().st_mode & 0o7777)
    alias = runtime/'usr/lib/be6l-a64-soft/lua'
    alias.parent.mkdir(parents=True)
    alias.symlink_to('../../../opt/be6l-a64-soft/lib/lua')
    changed_hash = hashlib.sha256(json.dumps(audit,sort_keys=True).encode()).hexdigest()
    versions = {'be6l-soft-runtime':'0.3.'+str(int(changed_hash[:12],16))+'-r1',
                'be6l-soft-tools':'0.3.'+str(int(changed_hash[:12],16))+'-r1',
                'be6l-soft-netifd-deps':'1.1.'+str(int(changed_hash[:12],16))+'-r1',
                'procd':info['procd']['V'].rsplit('-r',1)[0]+'-r'+str(a.release),
                'netifd':info['netifd']['V'].rsplit('-r',1)[0]+'-r'+str(a.release)}
    provenance = dict(revision='private-vm-paths-v1',abi='AAPCS64-soft',private_elf_marker=hex(PRIVATE_SOFT_EFLAGS),
        source_composition_receipt_sha256=sha(a.base_composition/'result.json'),source_root_records_sha256=before_digest,
        source_trees_sha256=sources,source_context_sha256=context_pins,compiler_wrapper_sha256=sha(w/'cc'),
        lua_patch_sha256=sha(w/'private-lua-cpath.patch'),lua_c_module_path=LUA_PATH,
        lua_cpath_environment='BE6L_A64_SOFT_LUA_CPATH',lua_pure_module_paths_preserved=True,
        ucode_search_path=UCODE_PATH,rebuilt_files=audit,
        preserved_private_modules={name:private_before[name]['sha256'] for name in module_paths},
        new_alias={'usr/lib/be6l-a64-soft/lua':os.readlink(alias)},
        old_profile_lock_is_baseline_only=True,normal_a53_payloads_modified=False,
        preload_fixed=False,target_executed=False,full_compatibility_qualified=False)
    proof = runtime/'usr/share/be6l-soft/vm-path-revision.json'
    proof.write_text(json.dumps(provenance,indent=2)+'\n')
    (w/'build-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    expected_payload = {g:records(payload/g) for g in GROUPS}
    (w/'payload-manifest.json').write_text(json.dumps(expected_payload,indent=2)+'\n')
    changes = {g:dict(changed=[n for n,v in expected_payload[g].items() if n in source_owned[g] and v != all_before[n]],
                      added=sorted(set(expected_payload[g])-source_owned[g]),removed=sorted(source_owned[g]-set(expected_payload[g]))) for g in GROUPS}
    if (set(changes['be6l-soft-runtime']['changed']) != set(CHANGED) or
        set(changes['be6l-soft-runtime']['added']) != {'usr/lib/be6l-a64-soft/lua','usr/share/be6l-soft/vm-path-revision.json'} or
        any(changes[g]['changed'] or changes[g]['added'] or changes[g]['removed'] for g in GROUPS if g!='be6l-soft-runtime') or
        any(changes[g]['removed'] for g in GROUPS)):
        raise ValueError('Unreviewed private payload transition')
    trust = w/'trust'
    trust.mkdir()
    for keyfile in (base/'etc/apk/keys').glob('*'):
        if keyfile.is_file():copy_path(keyfile,trust/keyfile.name)
    key = w/'temporary-signing.key'
    approved = w/'approved'
    approved.mkdir()
    archives = {}
    dependencies = {}
    try:
        run('key-generate',['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',key])
        key.chmod(0o600)
        run('key-public',['openssl','pkey','-in',key,'-pubout','-out',trust/'be6l-private-vm.pem'])
        for group in GROUPS:
            depends = info[group].get('D','').split()
            depends = [next((name+'='+versions[name] for name in versions if d.startswith(name+'=')),d) for d in depends]
            if group != 'be6l-soft-runtime' and not any(d.startswith('be6l-soft-runtime=') for d in depends):
                depends.append('be6l-soft-runtime='+versions['be6l-soft-runtime'])
            dependencies[group] = depends
            archive = approved/(group+'-'+versions[group]+'.apk')
            command = [a.apk,'mkpkg','--sign-key',key,'--files',payload/group,'--output',archive]
            fields = dict(name=group,version=versions[group],arch=ARCH,
                description=info[group].get('T','')+'; private VM path revision',license=info[group].get('L',''))
            if depends:fields['depends']=' '.join(depends)
            if info[group].get('p'):fields['provides']=info[group]['p']
            for field,value in fields.items():command += ['--info',field+':'+value]
            run('mkpkg-'+group,command)
            run('verify-'+group,[a.apk,'--network=no','--keys-dir',trust,'verify',archive])
            extracted=w/('verified-'+group)
            extracted.mkdir()
            run('extract-'+group,[a.apk,'--network=no','--keys-dir',trust,'extract','--no-chown','--destination',extracted,archive])
            if records(extracted)!=expected_payload[group]:raise ValueError('Signed package payload differs: '+group)
            archives[group]=archive
        root=w/'root'
        shutil.copytree(base,root,symlinks=True)
        common=[a.apk,'--root',root,'--network=no','--cache=no','--logfile=no','--repositories-file','/dev/null','--keys-dir',trust]
        run('simulate-five-package-upgrade',common+['add','--scripts=no','--simulate',*archives.values()])
        if root_digest(root)!=before_digest:raise ValueError('APK simulation changed the private copy')
        run('normal-five-package-upgrade',common+['add','--scripts=no',*archives.values()])
        query=json.loads(run('query-five-package-bindings',common+['query','--installed','--format','json','--fields','name,version,arch,depends,provides',*GROUPS]).stdout)
        if len(query)!=5:raise ValueError('Incomplete installed private package graph')
        for item in query:
            group=item['name']
            if item['version']!=versions[group] or item['arch']!=ARCH or sorted(item.get('depends',[]))!=sorted(dependencies[group]):
                raise ValueError('Installed exact private runtime binding differs: '+group)
        actual=records(root)
        for group,paths in expected_payload.items():
            if any(actual.get(n)!=v for n,v in paths.items()):raise ValueError('Installed payload bytes differ')
        pkgs,final_owners=installed(root)
        if len(pkgs)!=len(packages):raise ValueError('Service/package selection changed')
        for group in GROUPS:
            if set(pkgs[group]['paths'])!=set(expected_payload[group]):raise ValueError('Installed private ownership differs')
        final_elf=scan(root,final_owners)
        private={n:v for n,v in final_elf.items() if v['e_flags']==hex(PRIVATE_SOFT_EFLAGS)}
        if set(private)!=set(private_before):raise ValueError('Private real-ELF inventory changed')
        for name,item in private.items():
            if name not in CHANGED and item['sha256']!=private_before[name]['sha256']:
                raise ValueError('Unrelated private ELF changed')
        for name in module_paths:
            if sha(root/name)!=private_before[name]['sha256']:raise ValueError('Private VM module changed')
        for module in ('nixio.so','ubus.so','uci.so','uloop.so'):
            target=rooted(root,'usr/lib/be6l-a64-soft/lua/'+module)
            if target is None or sha(target)!=sha(root/'opt/be6l-a64-soft/lib/lua'/module):
                raise ValueError('Private Lua alias does not preserve its complete selected modules')
    finally:
        key.unlink(missing_ok=True)
    if root_digest(base)!=before_digest or source_records(lua_source)!=sources['lua'] or source_records(ucode_source)!=sources['ucode']:
        raise ValueError('Old admitted root/source tree changed')
    report=dict(normal_signed_five_package_transaction=True,source_root_unchanged=True,
        source_composition_receipt_sha256=sha(a.base_composition/'result.json'),source_root_records_sha256=before_digest,
        installed_root_records_sha256=root_digest(root),versions=versions,exact_depends=dependencies,
        packages={g:dict(file=str(path.relative_to(w)),sha256=sha(path),payload_records_sha256=root_digest(payload/g)) for g,path in archives.items()},
        private_signing_key_removed=not key.exists(),normal_a53_payloads_modified=False,
        source_provenance_sha256=sha(w/'build-provenance.json'),payload_manifest_sha256=sha(w/'payload-manifest.json'),
        payload_changes=changes,changed_private_elf_count=3,unchanged_private_elf_count=58,
        private_regular_elf_count=61,preserved_private_module_count=19,
        lua_c_module_path=LUA_PATH,lua_cpath_environment='BE6L_A64_SOFT_LUA_CPATH',
        ucode_search_path=UCODE_PATH,compiled_default_isolation_verified=True,
        module_dlopen_runtime_tested=False,procd_preload_fixed=False,
        mainroot_composition_qualified=False,target_executed=False,full_standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PRIVATE_A64_VM_PATHS_SIGNED_FIVE_PACKAGE_GRAPH',versions['be6l-soft-runtime'],flush=True)


if __name__=='__main__':main()
