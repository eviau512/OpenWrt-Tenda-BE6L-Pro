#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline private procd profile and three ABI-specific bare-name loggers.

Fresh private work only. Original exec calls and setbuf(stdout,NULL) semantics
remain intact. The standard-ABI logger is a new explicitly signed custom
package, not an upstream ordinary archive. No DUT, final root or Image claim.
"""
import argparse
import difflib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from inventory_mainroot_a53_v1 import elf, installed
from package_native_netifd_v3 import copy_path, records, root_digest, sha
from plan_integer_binfmt_v1 import PRIVATE_SOFT_EFLAGS, tag_private
from rebuild_private_a64_vm_paths_v1 import source_records, exported

SONAME = 'libbe6l-setlbf.so'
BOOT_PROFILE = 'BE6L_MAINROOT_NATIVE_BOOTSTRAP'
PRIVATE_JAIL = '/usr/libexec/be6l/ujail'
JAIL_PATHS = (
    '/lib/be6l-arm32','/usr/lib/be6l-arm32','/lib/ld-musl-arm.so.1','/etc/ld-musl-arm.path',
    '/lib/aarch64-soft','/lib/ld-musl-aarch64-soft.so.1','/etc/ld-musl-aarch64-soft.path',
    '/opt/be6l-a64-soft/lib','/usr/lib/be6l-a64-soft','/usr/lib/'+SONAME)
LIBRARIES = {
    'be6l-setlbf-arm32':('arm_cortex-a7','lib/be6l-arm32/'+SONAME),
    'be6l-setlbf-a64-soft':('aarch64_be6l_soft_experimental','lib/aarch64-soft/'+SONAME),
    'be6l-setlbf-a53':('aarch64_cortex-a53','usr/lib/'+SONAME)}


def replace_once(text, old, new):
    if text.count(old) != 1: raise ValueError('Source context does not match exactly: '+old[:90])
    return text.replace(old,new)


def patch_source(source, experiment, patch):
    before = {str(p.relative_to(source)):p.read_text() for p in [source/'service/instance.c',source/'initd/early.c',source/'jail/jail.c']}
    path = source/'service/instance.c'; s = path.read_text()
    s = replace_once(s,'#define UJAIL_BIN_PATH "/sbin/ujail"',
        '#ifdef '+BOOT_PROFILE+'\n#define UJAIL_BIN_PATH "'+PRIVATE_JAIL+'"\n#else\n#define UJAIL_BIN_PATH "/sbin/ujail"\n#endif')
    s = replace_once(s,'setenv("LD_PRELOAD", "/lib/libsetlbf.so", 1);',
        '\n#ifdef '+BOOT_PROFILE+'\n\t\tsetenv("LD_PRELOAD", "'+SONAME+'", 1);\n#else\n\t\tsetenv("LD_PRELOAD", "/lib/libsetlbf.so", 1);\n#endif')
    path.write_text(s)
    path = source/'initd/early.c'; s = path.read_text()
    helper = '''
#ifdef BE6L_MAINROOT_NATIVE_BOOTSTRAP
#include <sys/vfs.h>
#include <linux/magic.h>
#include "be6l-bootstrap-mount.h"

/* Bootstrap promises all three initial mounts. Never hide canonical binfmt
 * readback or RAM state with a stacked mount. Native watchdog owns recovery. */
static void be6l_require_bootstrap_fs(const char *path, unsigned long type)
{
	struct statfs fs;
	int rc = statfs(path, &fs);
	if (be6l_bootstrap_fs_matches(rc, rc ? 0 : (unsigned long)fs.f_type, type))
		return;
	ERROR("BE6L bootstrap filesystem admission failed at %s\\n", path);
	for (;;)
		pause();
}
#endif
'''
    s = replace_once(s,'static void\nearly_dev(void)',helper+'\nstatic void\nearly_dev(void)')
    pair = '\t\tmount("proc", "/proc", "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL);\n\t\tmount("sysfs", "/sys", "sysfs", MS_NODEV | MS_NOEXEC | MS_NOSUID | MS_RELATIME, NULL);'
    s = replace_once(s,pair,'#ifdef '+BOOT_PROFILE+'\n\t\tbe6l_require_bootstrap_fs("/proc", PROC_SUPER_MAGIC);\n\t\tbe6l_require_bootstrap_fs("/sys", SYSFS_MAGIC);\n#else\n'+pair+'\n#endif')
    tmp = '\tmount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOATIME, "mode=01777");'
    s = replace_once(s,tmp,'#ifdef '+BOOT_PROFILE+'\n\tbe6l_require_bootstrap_fs("/tmp", TMPFS_MAGIC);\n#else\n'+tmp+'\n#endif')
    path.write_text(s)
    shutil.copyfile(experiment/'bootstrap-mount.h',source/'initd/be6l-bootstrap-mount.h')
    # Do not mix ABI library basename caches. Pin complete project-owned
    # runtime directories and unique interpreters/pathfiles read-only, then
    # leave ordinary target dependency discovery unchanged.
    path = source/'jail/jail.c'; s = path.read_text()
    mounts = '\n'.join('\t\t"'+name+'",' for name in JAIL_PATHS)
    function = '''
#ifdef BE6L_MAINROOT_NATIVE_BOOTSTRAP
static int be6l_add_logging_runtime(void)
{
	static const char *const paths[] = {
PATHS
	};
	size_t i;
	/* extroot/OCI own their filesystem contract and are deliberately not
	 * admitted by this host-only profile proof. */
	for (i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
		if (mount_is_defined(paths[i]) || access(paths[i], R_OK) ||
		    add_2paths_nodeps(paths[i], paths[i], 1, -1)) {
			ERROR("BE6L logging runtime missing: %s\\n", paths[i]);
			return -1;
		}
	}
	return 0;
}
#endif
'''.replace('PATHS',mounts)
    s = replace_once(s,'int main(int argc, char **argv)',function+'\nint main(int argc, char **argv)')
    needle = '\tif (!opts.extroot) {\n\t\tif (opts.namespace && add_path_and_deps(*opts.jail_argv, 1, -1, 0)) {'
    replacement = '''#ifdef BE6L_MAINROOT_NATIVE_BOOTSTRAP
	if (opts.namespace && getenv("LD_PRELOAD") &&
	    !strcmp(getenv("LD_PRELOAD"), "libbe6l-setlbf.so")) {
		if (opts.extroot || opts.ocibundle || be6l_add_logging_runtime()) {
			ERROR("BE6L logging jail filesystem contract not satisfied\\n");
			ret = EXIT_FAILURE;
			goto errout;
		}
	}
#endif
'''+needle
    s = replace_once(s,needle,replacement)
    path.write_text(s)
    diff = []
    for name,text in before.items():
        diff.extend(difflib.unified_diff(text.splitlines(True),(source/name).read_text().splitlines(True),
                                      fromfile='a/'+name,tofile='b/'+name))
    patch.write_text(''.join(diff))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('work','vm-composition','arm32-runtime','soft-context','sdk','arm32-sdk','host-prefix','apk','host-test'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--reuse-logger-package-set',type=Path,
                   help='Reuse exact already-reviewed signed logger archives after full rebuilt payload comparison')
    a = p.parse_args(); w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-procd-preload-20261113-[a-z0-9-]+',w.name) or w.exists():
        p.error('fresh private /root/be6l-procd-preload-20261113-* required')
    host_proof = json.loads((a.host_test/'result.json').read_text())
    acceptable = lambda t: t.get('pass_') or (t.get('name') == 'cloexec-empty-path-shebang-ENOENT' and
        t.get('status') == 'UNSUPPORTED_ENOSYS' and t.get('measured_errno') == 'EXECVEAT_ERRNO=38')
    expected_host_cases={'bare-slot0','bare-slot1','bare-slot2','buffered-negative-control',
        'dynamic-helper-different-slot','static-helper-to-different-slot','fork-exec-descendant',
        'kernel-shebang-original-execfn','cloexec-empty-path-shebang-ENOENT','mount-policy-six-branches'}
    host_cases=host_proof.get('cases',[])
    if (host_proof.get('case_count') != 10 or len(host_cases)!=10 or
        {t.get('name') for t in host_cases} != expected_host_cases or not all(acceptable(t) for t in host_cases) or
        host_proof.get('passed_case_count') != sum(bool(t.get('pass_')) for t in host_cases) or
        not host_proof.get('fixture_no_ld_library_path')):
        raise ValueError('Actual host musl bounded chain proof absent')
    base = a.vm_composition/'root'; receipt = json.loads((a.vm_composition/'result.json').read_text())
    before = root_digest(base)
    if before != receipt.get('installed_root_records_sha256') or not receipt.get('normal_signed_five_package_transaction'):
        raise ValueError('Frozen VM composition changed')
    arm_receipt = json.loads((a.arm32_runtime/'result.json').read_text())
    # Runtime metadata and exact package version come from its signed receipt.
    arm_version = arm_receipt.get('version') or arm_receipt.get('package',{}).get('version')
    packages, owners = installed(base)
    procd_meta = next({l[0]:l[2:] for l in block.splitlines() if len(l)>1 and l[1]==':'}
        for block in (base/'lib/apk/db/installed').read_text().split('\n\n') if '\nP:procd\n' in '\n'+block+'\n')
    soft_version = next({l[0]:l[2:] for l in block.splitlines() if len(l)>1 and l[1]==':'}['V']
        for block in (base/'lib/apk/db/installed').read_text().split('\n\n') if '\nP:be6l-soft-runtime\n' in '\n'+block+'\n')
    if not arm_version: raise ValueError('ARM32 signed runtime version absent')
    source_old = a.soft_context/'procd-source'; pins = source_records(source_old)
    musl_pins = {}
    for domain,tree in [('arm',a.arm32_sdk),('a53',a.sdk)]:
        files = list(tree.glob('build_dir/toolchain-*/musl-1.2.6/ldso/dynlink.c'))
        if len(files)!=1: raise ValueError('ambiguous exact musl source')
        musl_pins[domain] = sha(files[0])
    musl_pins['soft'] = sha(a.soft_context/'musl/ldso/dynlink.c')
    if len(set(musl_pins.values())) != 1 or host_proof.get('actual_dynlink_sha256') != musl_pins['soft']:
        raise ValueError('Actual three musl and host preload implementations differ')
    w.mkdir(mode=0o700); logs=w/'logs'; logs.mkdir()
    exp=Path(__file__).resolve().parents[1]/'experiments/procd-mixed-abi'
    shutil.copytree(a.soft_context/'sysroot',w/'sysroot',symlinks=True)
    shutil.copyfile(a.soft_context/'libsoft-builtins.a',w/'libsoft-builtins.a')
    for name in ('cc','softcc','soft-toolchain.cmake'):
        text=(a.soft_context/name).read_text().replace(str(a.soft_context),str(w))
        if name=='cc': text=text.replace('/usr/bin/clang ',str(a.host_prefix/'usr/bin/clang')+' ')
        (w/name).write_text(text); (w/name).chmod(0o755)
    env=dict(os.environ,PATH=str(a.host_prefix/'usr/bin')+':'+str(a.sdk/'staging_dir/host/bin')+':/usr/bin:/bin',
        LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu')+':'+str(a.host_prefix/'lib/x86_64-linux-gnu'),
        PKG_CONFIG_PATH='',PKG_CONFIG_LIBDIR=str(w/'sysroot/usr/lib/pkgconfig')+':'+str(w/'sysroot/lib/pkgconfig'),
        PKG_CONFIG_SYSROOT_DIR=str(w/'sysroot'),SOURCE_DATE_EPOCH='1792420077')
    def run(name,command,cwd=None,timeout=300):
        r=subprocess.run(list(map(str,command)),cwd=cwd,env=env,capture_output=True,timeout=timeout)
        (logs/(name+'.log')).write_bytes(r.stdout+r.stderr)
        if r.returncode: raise RuntimeError(name+' failed: '+str(logs/(name+'.log')))
        return r
    cross=str(next(a.sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')))[:-3]
    armcross=str(next(a.arm32_sdk.glob('staging_dir/toolchain-arm_*/bin/arm-openwrt-linux-muslgnueabi-gcc')))[:-3]
    payload=w/'payload'; payload.mkdir(); audit={}
    for name,(arch,path) in LIBRARIES.items():
        dest=payload/name/path; dest.parent.mkdir(parents=True)
        cc = [w/'softcc'] if name.endswith('soft') else [armcross+'gcc','-mfloat-abi=soft','-nostdlib'] if name.endswith('arm32') else [cross+'gcc','-mgeneral-regs-only','-nostdlib']
        run('build-'+name,cc+['-O2','-fPIC','-shared','-Wl,--build-id=none','-Wl,-soname,'+SONAME,exp/'setlbf.c','-lc','-o',dest])
        if name.endswith('soft'): dest.write_bytes(tag_private(dest.read_bytes()))
        info=elf(dest)
        if info['soname'] != SONAME or info['needed'] != ['libc.so'] or info['rpath'] or info['runpath']:
            raise ValueError('Logger ABI/dependency contract differs')
        expected = PRIVATE_SOFT_EFLAGS if name.endswith('soft') else 0 if name.endswith('a53') else None
        if expected is not None and int(info['e_flags'],0) != expected: raise ValueError('Wrong private vs standard marker')
        readelf=(armcross if name.endswith('arm32') else cross)+'readelf'
        exports=exported(readelf,dest,env)
        expected_exports={'_init','_fini'} if name.endswith('soft') else set()
        if exports != expected_exports: raise ValueError('Unexpected exported logger API: '+repr(exports))
        dis=run('disassembly-'+name,[(armcross if name.endswith('arm32') else cross)+'objdump','-d',dest]).stdout.decode()
        for line in dis.splitlines():
            if '\t' not in line: continue
            ins=line.split('\t',2)[-1]
            if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins): continue
            if re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins):
                raise ValueError('Logger FP/SIMD emitted: '+ins)
        audit[name]=dict(path=path,arch=arch,sha256=sha(dest),elf=info,defined_dynamic_exports=sorted(exports),fp_simd_uses=0,
            custom_standard_abi=name.endswith('a53'),upstream_archive=False)
    fixtures=w/'cross-fixtures'; fixtures.mkdir(); cross_fixtures={}
    for name,cc in [('arm32',[armcross+'gcc','-mfloat-abi=soft']),('a64-soft',[w/'softcc']),
                    ('a53',[cross+'gcc','-mgeneral-regs-only']),('arm32-static',[armcross+'gcc','-mfloat-abi=soft','-static'])]:
        path=fixtures/(name+'-fixture')
        run('cross-fixture-'+name,cc+['-O2',exp/'host-fixture.c','-o',path])
        if name=='a64-soft': path.write_bytes(tag_private(path.read_bytes()))
        cross_fixtures[name]=dict(sha256=sha(path),elf=elf(path),executed=False,
                                 role='synthetic integer launch/buffering fixture, not an ordinary package')
    ignore=shutil.ignore_patterns('CMakeFiles','CMakeCache.txt','*.o','*.a','*.so','*.so.*','ipkg-*','apk-*','.pkgdir','.git')
    shutil.copytree(source_old,w/'procd-source',symlinks=True,ignore=ignore)
    patch_source(w/'procd-source',exp,w/'mainroot-profile.patch')
    build=w/'build'; build.mkdir()
    for name in ('make_capabilities_h.sh','make_syscall_h.sh'):
        shutil.copyfile(w/'procd-source'/name,build/name); (build/name).chmod(0o755)
    run('procd-configure',[a.host_prefix/'usr/bin/cmake','-S',w/'procd-source','-B',build,
        '-DCMAKE_TOOLCHAIN_FILE='+str(w/'soft-toolchain.cmake'),'-DCMAKE_MAKE_PROGRAM='+str(a.host_prefix/'usr/bin/make'),
        '-DCMAKE_POLICY_VERSION_MINIMUM=3.5','-DPKG_CONFIG_EXECUTABLE='+str(a.sdk/'staging_dir/host/bin/pkg-config.real'),
        '-DCMAKE_INSTALL_PREFIX=/usr','-DCMAKE_BUILD_TYPE=Release','-DJAIL_SUPPORT=ON','-DSECCOMP_SUPPORT=OFF',
        '-DEARLY_PATH=/sbin:/bin:/usr/sbin:/usr/bin','-DCMAKE_C_FLAGS=-O2 -D'+BOOT_PROFILE])
    run('procd-build',[a.host_prefix/'usr/bin/cmake','--build',build,'-j4'],timeout=600)
    group='procd'; out=payload/group; out.mkdir()
    for name in packages[group]['paths']:
        if owners.get(name) != [group]: raise ValueError('ambiguous procd ownership')
        copy_path(base/name,out/name)
    replacements={'sbin/procd':'procd','sbin/init':'init','sbin/askfirst':'askfirst','sbin/udevtrigger':'udevtrigger','sbin/upgraded':'upgraded/upgraded',PRIVATE_JAIL.lstrip('/'):'ujail'}
    for path,artifact in replacements.items():
        target=out/path; target.parent.mkdir(parents=True,exist_ok=True)
        if target.is_symlink(): target.unlink()
        shutil.copyfile(build/artifact,target); target.chmod(0o755)
        data=target.read_bytes(); info=elf(target)
        if info['machine'] != 183: raise ValueError('Wrong private procd ELF machine')
        dis=run('disassembly-'+target.name,[cross+'objdump','-d',target]).stdout.decode()
        for line in dis.splitlines():
            if '\t' not in line: continue
            ins=line.split('\t',2)[-1]
            if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins): continue
            if re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins):
                raise ValueError('Private procd FP/SIMD emitted: '+ins)
        target.write_bytes(tag_private(data))
        audit[path]=dict(sha256=sha(target),elf=elf(target),fp_simd_uses=0)
    legacy_list=out/'lib/apk/packages/procd.list'
    listed=legacy_list.read_text().splitlines()
    if PRIVATE_JAIL in listed: raise ValueError('Baseline already lists new private helper')
    legacy_list.write_text('\n'.join(sorted(listed+[PRIVATE_JAIL]))+'\n')
    # The bare preload value is profile-specific source state. Original final
    # execvp/execve/execvpe calls are byte-identical source statements.
    inst=(w/'procd-source/service/instance.c').read_text()
    if 'execvp(argv[0], argv);' not in inst or ('setenv("LD_PRELOAD", "'+SONAME+'", 1);') not in inst:
        raise ValueError('Unexpected final exec change')
    version=procd_meta['V'].rsplit('-r',1)[0]+'-r107'
    versions={name:'1.0-r1' for name in LIBRARIES}; versions['procd']=version
    depends={name:[] for name in LIBRARIES}
    depends['be6l-setlbf-arm32']=['be6l-arm32-runtime='+arm_version]
    depends['be6l-setlbf-a64-soft']=['be6l-soft-runtime='+soft_version]
    depends['be6l-setlbf-a53']=['libc']
    depends['procd']=procd_meta.get('D','').split()+[name+'='+versions[name] for name in LIBRARIES]
    trust=w/'trust'; trust.mkdir(); approved=w/'approved'; approved.mkdir()
    for key in (base/'etc/apk/keys').glob('*'):
        if key.is_file(): copy_path(key,trust/key.name)
    frozen=None
    if a.reuse_logger_package_set:
        frozen=json.loads((a.reuse_logger_package_set/'result.json').read_text())
        if not frozen.get('signed_archives_verified_and_extracted'): raise ValueError('Unverified frozen logger set')
        for oldkey in (a.reuse_logger_package_set/'trust').glob('*'):
            if oldkey.is_file():
                if (trust/oldkey.name).exists() and sha(trust/oldkey.name)!=sha(oldkey): raise ValueError('Key filename collision')
                copy_path(oldkey,trust/oldkey.name)
    key=w/'temporary-signing.key'; archives={}; manifest={name:records(payload/name) for name in versions}
    try:
        run('key-generate',['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',key]); key.chmod(0o600)
        run('key-public',['openssl','pkey','-in',key,'-pubout','-out',trust/'be6l-private-procd-profile.pem'])
        for name in versions:
            archive=approved/(name+'-'+versions[name]+'.apk')
            arch=LIBRARIES[name][0] if name in LIBRARIES else procd_meta['A']
            fields=dict(name=name,version=versions[name],arch=arch,license='LGPL-2.1-or-later',
                description='BE6L explicit private mainroot bare-preload logging profile' if name=='procd' else 'BE6L custom per-ABI stdout unbuffering DSO')
            if depends[name]: fields['depends']=' '.join(depends[name])
            if name=='procd' and procd_meta.get('p'): fields['provides']=procd_meta['p']
            cmd=[a.apk,'mkpkg','--sign-key',key,'--files',payload/name,'--output',archive]
            for f,v in fields.items(): cmd+=['--info',f+':'+v]
            if name in LIBRARIES and frozen:
                item=frozen['packages'][name]
                original=a.reuse_logger_package_set/item['file']
                if (item['name'],item['version'],item['arch'],item['depends']) != (name,versions[name],arch,depends[name]):
                    raise ValueError('Frozen logger metadata differs')
                if sha(original)!=item['sha256'] or records(a.reuse_logger_package_set/'payload'/name)!=manifest[name]:
                    raise ValueError('Frozen archive/source payload changed or rebuilt bytes differ')
                shutil.copyfile(original,archive)
            else:
                run('mkpkg-'+name,cmd)
            run('verify-'+name,[a.apk,'--network=no','--keys-dir',trust,'verify',archive])
            extracted=w/('verified-'+name); extracted.mkdir()
            run('extract-'+name,[a.apk,'--network=no','--keys-dir',trust,'extract','--no-chown','--destination',extracted,archive])
            if records(extracted)!=manifest[name]: raise ValueError('Signed extracted payload differs')
            archives[name]=dict(file=str(archive.relative_to(w)),sha256=sha(archive),name=name,version=versions[name],arch=arch,depends=depends[name])
    finally: key.unlink(missing_ok=True)
    if source_records(source_old)!=pins or root_digest(base)!=before: raise ValueError('Frozen source/root changed')
    proof=dict(revision=1,profile=BOOT_PROFILE,source_root_records_sha256=before,
        builder_sha256=sha(Path(__file__)),
        reused_logger_receipt_sha256=sha(a.reuse_logger_package_set/'result.json') if frozen else None,
        vm_composition_receipt_sha256=sha(a.vm_composition/'result.json'),arm32_runtime_receipt_sha256=sha(a.arm32_runtime/'result.json'),
        host_test_receipt_sha256=sha(a.host_test/'result.json'),host_test_cases=host_proof['case_count'],
        actual_three_musl_dynlink_sha256=musl_pins,
        compiler_sha256={'a53':sha(Path(cross+'gcc')),'arm32':sha(Path(armcross+'gcc')),
                         'soft_wrapper':sha(w/'cc'),'soft_link_wrapper':sha(w/'softcc')},
        toolchain_libc_sha256={'a53':sha(Path(cross+'gcc').parent.parent/'lib/libc.so'),
                              'arm32':sha(Path(armcross+'gcc').parent.parent/'lib/libc.so')},
        source_tree_sha256=pins,patch_sha256=sha(w/'mainroot-profile.patch'),
        experiment_sha256={n:sha(exp/n) for n in ('setlbf.c','bootstrap-mount.h','host-fixture.c')},
        library_name=SONAME,library_paths={name:path for name,(_,path) in LIBRARIES.items()},
        compiled_private_jail=PRIVATE_JAIL,jail_readonly_nodeps_paths=list(JAIL_PATHS),
        constructor_stdout_unbuffered=True,constructor_environment_cleared=False,final_exec_calls_preserved=True,
        filesystem_profile_preserves_correct_proc_sys_tmp=True,wrong_bootstrap_filesystem_waits_for_native_recovery=True,
        normal_archives_modified=False,new_normal_abi_archive_is_custom=True,secureexec_qualified=False,
        seccomp_tracing_supported=False,external_root_and_oci_logging_jail_qualified=False,
        audit=audit,cross_fixtures=cross_fixtures,packages=archives,signing_key_removed=not key.exists(),source_root_unchanged=True,
        signed_archives_verified_and_extracted=True,target_executed=False,jail_runtime_qualified=False,
        full_service_chain_target_qualified=False,mainroot_composition_qualified=False,
        full_standard_a53_package_compatibility_qualified=False)
    (w/'payload-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    proof['payload_manifest_sha256']=sha(w/'payload-manifest.json')
    (w/'result.json').write_text(json.dumps(proof,indent=2)+'\n')
    print('PRIVATE_PROCD_BARE_PRELOAD_SIGNED',version,flush=True)


if __name__=='__main__':main()
