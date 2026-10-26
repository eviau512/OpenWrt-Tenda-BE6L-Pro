# SPDX-License-Identifier: MIT
"""Build/admit a signed soft-ABI bundle and transact in a fresh offline root.

No DUT access, target execution, downloads, solver force options or live-library
replacement. Architecture/provenance admission is an explicit repository gate.
"""
from pathlib import Path
import argparse
import json
import shutil
import subprocess
from a64_soft_context import BASE, SDK, EPOCH
from soft_abi_admission import (AdmissionError, admit_profile, admit_extracted_payload,
                                digest, file_records)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--profile-root', type=Path, required=True)
parser.add_argument('--trusted-lock-sha256', required=True)
args = parser.parse_args()
profile = admit_profile(args.profile_root, args.trusted_lock_sha256)
root = args.root
assert root.is_absolute() and not root.exists() and not any(c.isspace() for c in str(root))
root.mkdir()
(root/'.be6l-soft-bundle').write_text('owned offline native package transaction\n')
apk = SDK/'staging_dir/host/bin/apk'
log = BASE/'logs'/('soft-bundle-'+root.name)
log.mkdir()
version = '0.2.'+str(int(args.trusted_lock_sha256[:12],16))+'-r1'
procd_version = '2026.10.26.'+str(int(args.trusted_lock_sha256[:12],16))+'-r1'
runtime_name, tools_name, compat_name = 'be6l-soft-runtime','be6l-soft-tools','be6l-arm32-procd-compat'
names = dict(runtime=runtime_name, tools=tools_name, procd='procd', compat=compat_name)
arch = profile['architecture']
key = root/'fixture-private.key'
public = root/'fixture-public.pem'
packages, expected, cases = {}, {}, []
report = dict(profile_lock_sha256=args.trusted_lock_sha256, architecture=arch,
              hardware_modified=False, target_executed=False, cases=cases,
              binary_redistribution_license_review_complete=False,
              complete_native_sdk=False, ramboot_qualified=False)


def run(label, command, success=True):
    result = subprocess.run([str(x) for x in command], capture_output=True, timeout=90)
    (log/(label+'.txt')).write_bytes(result.stdout+result.stderr)
    assert (result.returncode == 0) == success, (label, result.returncode)
    cases.append(dict(name=label, status=result.returncode, expected_success=success))
    return result


def write_file(folder, name, data, mode=0o644):
    path=folder/name
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def package(group, files, suffix='', override_version=None):
    name=names[group]
    path=root/(name+suffix+'.apk')
    command=[apk,'mkpkg','--sign-key',key,'--files',files,'--output',path,
             '--info','name:'+name,'--info','version:'+(override_version or (procd_version if group=='procd' else version)),
             '--info','arch:'+('arm_cortex-a7' if group=='compat' else arch),
             '--info','description:Experimental BE6L soft-ABI closure with reviewed provenance',
             '--info','license:'+{
                'runtime':'MIT AND ISC AND LGPL-2.1-only AND Apache-2.0 AND (Apache-2.0 WITH LLVM-exception)',
                'tools':'GPL-2.0-only AND LGPL-2.1-only AND MIT AND ISC AND curl',
                'procd':'LGPL-2.1-only', 'compat':'LGPL-2.1-only'}[group]]
    if group in ('tools','procd'):
        command+=['--info','depends:'+runtime_name+'='+version]
    if group=='procd':
        command+=['--info','depends:'+compat_name+'='+version+' jshn ubox ubus ubusd',
                  '--info','provides:procd-any']
    if group=='compat':
        command+=['--info','depends:libc','--info','replaces:procd']
    run('package-'+group+suffix, command)
    return path


try:
    staged={group:root/('files-'+group) for group in names}
    for p in staged.values():p.mkdir()
    programs={'busybox','lua','luac','curl','ubus','ubusd','uci','ucode','jshn'}
    procd_programs={'init','procd','askfirst','udevtrigger','upgraded'}
    lua_modules={'nixio.so','uci.so','ubus.so','uloop.so'}
    for name in profile['files']:
        data=(args.profile_root/'payload'/name).read_bytes()
        if name in procd_programs:
            group,target='procd','sbin/'+name
        elif name in programs:
            group,target='tools','opt/be6l-a64-soft/bin/'+name
        elif name in lua_modules:
            group,target='runtime','opt/be6l-a64-soft/lib/lua/'+name
        elif name.startswith('modules/'):
            group,target='runtime','opt/be6l-a64-soft/lib/ucode/'+name.removeprefix('modules/')
        else:
            assert name.startswith('lib') and '/' not in name,name
            group,target='runtime','lib/aarch64-soft/'+name
        write_file(staged[group],target,data,0o755)
    loader=staged['runtime']/'lib/ld-musl-aarch64-soft.so.1'
    loader.symlink_to('aarch64-soft/libc.so')
    write_file(staged['runtime'],'etc/ld-musl-aarch64-soft.path',b'/lib/aarch64-soft\n')
    write_file(staged['runtime'],'usr/share/be6l-soft/profile-lock.json',(args.profile_root/'profile-lock.json').read_bytes())
    for name in profile['notices']:
        write_file(staged['runtime'],'usr/share/licenses/be6l-soft/'+name,(args.profile_root/'notices'/name).read_bytes())
    for name in profile['original_procd_compatibility_files']:
        data=(args.profile_root/'compatibility'/name).read_bytes()
        group='compat' if name=='lib/libsetlbf.so' else 'procd'
        write_file(staged[group],name,data,0o755 if name.startswith('sbin/') or name.endswith('.so') else 0o644)
    # OpenWrt's auxiliary file list must reflect the new package's actual files.
    own_list=sorted(set(file_records(staged['procd']))|{'lib/apk/packages/procd.list'})
    write_file(staged['procd'],'lib/apk/packages/procd.list',('\n'.join('/'+p for p in own_list)+'\n').encode())
    for group,p in staged.items():expected[group]=file_records(p)
    run('generate-fixture-key',['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',key])
    key.chmod(0o600)
    run('generate-public-key',['openssl','pkey','-in',key,'-pubout','-out',public])
    trust=root/'trust'
    trust.mkdir()
    shutil.copyfile(public,trust/'fixture.pem')
    approved=root/'approved'
    approved.mkdir()
    for group,files in staged.items():
        candidate=package(group,files)
        run('verify-'+group,[apk,'--keys-dir',trust,'--network=no','verify',candidate])
        extracted=root/('extract-'+group)
        extracted.mkdir()
        run('extract-'+group,[apk,'--keys-dir',trust,'--network=no','extract','--no-chown','--destination',extracted,candidate])
        admit_extracted_payload(extracted,expected[group])
        packages[group]=approved/candidate.name
        shutil.copyfile(candidate,packages[group])

    # Same machine, package name/version/architecture and trusted signing key,
    # but an ordinary FP provider substituted after the reviewed build.
    bad=root/'wrong-provider'
    shutil.copytree(staged['runtime'],bad,symlinks=True)
    asm=root/'ordinary-fp.S'
    asm.write_text('.text\n.global be6l_ordinary_pcs\n.type be6l_ordinary_pcs,%function\nbe6l_ordinary_pcs:\n fadd d0,d0,d1\n ret\n')
    gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
    run('build-foreign-provider',[gcc,'-shared','-nostdlib','-Wl,--build-id=none',asm,'-o',bad/'lib/aarch64-soft/libc.so'])
    foreign=(bad/'lib/aarch64-soft/libc.so').read_bytes()
    assert foreign[:6]==b'\x7fELF\x02\x01' and foreign[18:20]==b'\xb7\0'
    wrong=package('runtime',bad,'-wrong-provider')
    empty=root/'metadata-only-root'
    (empty/'etc/apk/keys').mkdir(parents=True)
    shutil.copyfile(public,empty/'etc/apk/keys/fixture.pem')
    minimal=[apk,'--root',empty,'--arch',arch,'--network=no','--scripts=no','--cache=no','--repositories-file','/dev/null']
    run('initialize-metadata-root',minimal+['add','--initdb'])
    run('apk-metadata-alone-accepts-wrong-provider',minimal+['add','--simulate',wrong])
    extracted=root/'extract-wrong-provider'
    extracted.mkdir()
    run('extract-wrong-provider',[apk,'--keys-dir',trust,'--network=no','extract','--no-chown','--destination',extracted,wrong])
    try:
        admit_extracted_payload(extracted,expected['runtime'])
    except AdmissionError as error:
        assert str(error)=='package payload differs from reviewed recipe'
        cases.append(dict(name='reject-signed-same-label-wrong-ABI-provider',passed=True))
    else:raise AssertionError('Substituted ordinary PCS provider admitted')
    assert not (approved/wrong.name).exists()
    modified=root/'modified-profile'
    modified.mkdir()
    altered=dict(profile)
    altered['abi']='AAPCS64-base'
    (modified/'profile-lock.json').write_text(json.dumps(altered))
    try:admit_profile(modified,args.trusted_lock_sha256)
    except AdmissionError as error:
        assert str(error)=='unreviewed profile/provenance lock'
        cases.append(dict(name='reject-modified-profile',passed=True))
    else:raise AssertionError('Modified provenance admitted')

    # Clone the credential-free, APK-managed baseline. Do not overwrite its
    # native PID1 files by hand or edit any installed package records.
    original=Path('/root/be6l-openwrt/compat-apk-root/root')
    installed=root/'rootfs'
    shutil.copytree(original,installed,symlinks=True)
    baseline_init=digest((original/'sbin/init').read_bytes())
    baseline_libc=digest((original/'lib/libc.so').read_bytes())
    (installed/'etc/apk/arch').write_text('arm_cortex-a7\n'+arch+'\n')
    shutil.copyfile(public,installed/'etc/apk/keys/be6l-soft-fixture.pem')
    common=[apk,'--root',installed,'--network=no','--scripts=no','--cache=no','--repositories-file','/dev/null']
    run('simulate-normal-native-procd-upgrade',common+['add','--simulate',*packages.values()])
    run('normal-native-procd-upgrade',common+['add',*packages.values()])
    for group,records in expected.items():
        for name,item in records.items():
            p=installed/name
            if 'symlink' in item:assert p.is_symlink() and str(p.readlink())==item['symlink']
            else:assert digest(p.read_bytes())==item['sha256'],name
    assert digest((installed/'lib/libc.so').read_bytes())==baseline_libc
    assert digest((original/'sbin/init').read_bytes())==baseline_init
    assert (installed/'sbin/init').read_bytes()[4]==2
    assert (installed/'lib/libsetlbf.so').read_bytes()[4]==1
    readonly=[a for a in common if a!='--scripts=no']
    query=run('installed-native-ownership',readonly+['info','--who-owns','/sbin/init','/sbin/procd','/lib/libsetlbf.so'])
    assert ('procd-'+procd_version).encode() in query.stdout and compat_name.encode() in query.stdout
    native=run('installed-native-metadata',readonly+['query','--installed','--format','json','--fields','name,version,arch,depends','procd',runtime_name,tools_name,compat_name])
    metadata=json.loads(native.stdout)
    assert len(metadata)==4
    for entry in metadata:
        assert entry['arch']==('arm_cortex-a7' if entry['name']==compat_name else arch)
    audit=json.loads((BASE/'artifacts/arm64-compat/hybrid-kernel-apk-audit.json').read_text())
    for name,expected_hash in audit['verified_module_files'].items():
        assert digest((installed/name).read_bytes())==expected_hash
    assert len(audit['verified_module_files'])==81
    # A separately signed runtime version cannot satisfy the exact dependency
    # held by this native procd transaction.
    other=package('runtime',staged['runtime'],'-different-version',override_version='99.0-r1')
    rejected=run('reject-unmatched-runtime-version',common+['add','--simulate',other],False)
    assert runtime_name.encode() in rejected.stdout+rejected.stderr
    report.update(passed=True, native_elfs=58, normal_solver_signatures=True,
                  apk_metadata_alone_insufficient_demonstrated=True,
                  same_label_signed_provider_rejected_at_admission=True,
                  pid1_owned_by_native_procd_package=True,
                  arm32_preload_compatibility_package=True, original_arm32_libc_preserved=True,
                  unchanged_matching_kernel_modules=81, rootfs=str(installed),
                  approved_packages={group:dict(file=p.name,sha256=digest(p.read_bytes())) for group,p in packages.items()},
                  versions=dict(runtime=version,procd=procd_version))
finally:
    if key.exists():key.unlink()
    report['throwaway_private_key_removed']=True
    (log/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print('SIGNED_NATIVE_SOFT_APK_BUNDLE_PASS',log,flush=True)
