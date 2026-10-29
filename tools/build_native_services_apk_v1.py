# SPDX-License-Identifier: MIT
"""Signed services APK + normal transaction in a NEW clone; never deploy."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from a64_soft_context import BASE, SDK, EPOCH
from native_services_admission_v1 import ARCH, BASE_LOCK, SHA, admit, admit_installed
from soft_abi_admission import file_records, admit_extracted_payload, AdmissionError

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--work',type=Path,required=True); p.add_argument('--profile',type=Path,required=True)
p.add_argument('--trusted-profile-sha256',required=True); p.add_argument('--base-root',type=Path,required=True)
a=p.parse_args(); work=a.work.resolve(); profile_root=a.profile.resolve(); original=a.base_root.resolve()
assert work.parent==Path('/root/be6l-openwrt') and work.name.startswith('native-services-apk-v1-')
assert not work.exists(); work.mkdir()
profile=admit(profile_root,a.trusted_profile_sha256)
assert profile['source_plugin_paths_corrected']
apk=SDK/'staging_dir/host/bin/apk'; key=work/'throwaway-signing.key'; public=work/'public-key.pem'
sha=lambda p:SHA(Path(p).read_bytes())
cases=[]
def run(label,command,success=True):
    result=subprocess.run([str(x) for x in command],capture_output=True,timeout=120)
    (work/(label+'.log')).write_bytes(result.stdout+result.stderr)
    assert (result.returncode==0)==success,(label,result.returncode)
    cases.append(dict(name=label,expected_success=success,status=result.returncode))
    return result

guard={str(p):sha(p) for p in (SDK/'.config',BASE/'artifacts/arm64-ppe-bridger/build-validation.json',
    BASE/'artifacts/arm64-ppe-bridger-xz-v2/build-validation.json',
    Path('/root/be6l-openwrt/soft-profile-v2/profile-lock.json'))}
old_manifest=json.loads(run('baseline-packages',[apk,'--root',original,'--network=no','--cache=no',
    'query','--installed','--format','json','--fields','name,version,arch,depends','*']).stdout)
assert len(old_manifest)==216
baseline={name:sha(original/name) for name in profile['files'] if name not in profile['new_paths']}
assert all(baseline[name]==profile['files'][name]['sha256'] for name in baseline)
default_paths=('sbin/netifd','sbin/rpcd','usr/sbin/rpcd','usr/sbin/uhttpd','usr/bin/lua')
default_files={name:sha(original/name) for name in default_paths if (original/name).is_file()}
bundle=Path('/root/be6l-openwrt/soft-bundle-v2')
base_receipt=BASE/'logs/soft-bundle-soft-bundle-v2/result.json'
assert sha(base_receipt)==profile['base_bundle_receipt_sha256']
trust=work/'trust'; trust.mkdir()
shutil.copyfile(bundle/'fixture-public.pem',trust/'base-fixture.pem')
for name,item in profile['base_approved_packages'].items():
    package=bundle/item['file']; assert sha(package)==item['sha256']
    run('verify-original-native-'+name,[apk,'--keys-dir',trust,'--network=no','verify',package])
version='1.0.'+str(int(a.trusted_profile_sha256[:12],16))+'-r1'
name='be6l-soft-services-preview'
versions=profile['base_versions']
depends='be6l-soft-runtime='+versions['runtime']+' be6l-soft-tools='+versions['runtime']+' procd='+versions['procd']
files=work/'package-files'; files.mkdir()
for target in profile['new_paths']:
    destination=files/target; destination.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(profile_root/'payload'/target,destination); destination.chmod(0o755)
metadata=files/'usr/share/be6l-soft/services-preview-v1'; metadata.mkdir(parents=True)
for source in ('profile-lock.json','source-rebuild-receipt.json'):
    shutil.copyfile(profile_root/source,metadata/source)
for notice in profile['notices']:
    dest=files/'usr/share/licenses/be6l-soft-services-preview'/notice
    dest.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(profile_root/'notices'/notice,dest)
for f in files.rglob('*'):os.utime(f,(int(EPOCH),int(EPOCH)),follow_symlinks=False)
expected=file_records(files)
def package(output,staged=files,arch=ARCH):
    run('mkpkg-'+output.stem,[apk,'mkpkg','--sign-key',key,'--files',staged,'--output',output,
        '--info','name:'+name,'--info','version:'+version,'--info','arch:'+arch,
        '--info','description:Content-locked BE6L native services preview; no default service promotion',
        '--info','license:LicenseRef-BE6L-Source-Notices','--info','depends:'+depends])
try:
    run('key-generate',['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',key])
    key.chmod(0o600)
    run('key-public',['openssl','pkey','-in',key,'-pubout','-out',public])
    shutil.copyfile(public,trust/'services-preview.pem')
    approved=work/'be6l-soft-services-preview.apk'; package(approved)
    run('verify-signed-package',[apk,'--keys-dir',trust,'--network=no','verify',approved])
    extracted=work/'extracted'; extracted.mkdir()
    run('extract-package',[apk,'--keys-dir',trust,'--network=no','extract','--no-chown','--destination',extracted,approved])
    admit_extracted_payload(extracted,expected)
    installed=work/'root'; shutil.copytree(original,installed,symlinks=True)
    assert ARCH in (installed/'etc/apk/arch').read_text().splitlines()
    shutil.copyfile(public,installed/'etc/apk/keys/services-preview-v1.pem')
    common=[apk,'--root',installed,'--network=no','--cache=no','--scripts=no','--repositories-file','/dev/null']
    foreign=work/'wrong-ordinary-aarch64.apk'; package(foreign,arch='aarch64_cortex-a53')
    run('reject-ordinary-aarch64-label',common+['add','--simulate',foreign],False)
    run('simulate-normal-transaction',common+['add','--simulate',approved])
    run('normal-transaction',common+['add',approved])
    admit_installed(installed,profile)
    for target,item in expected.items():
        assert 'sha256' in item and sha(installed/target)==item['sha256']
        assert (installed/target).stat().st_mode&0o777==item['mode']
    readonly=[x for x in common if x!='--scripts=no']
    ownership={}
    for target in profile['new_paths']:
        result=run('owner-'+target.replace('/','_'),readonly+['info','--who-owns','/'+target]).stdout.decode().strip()
        assert result.endswith(' is owned by '+name+'-'+version),result
        ownership[target]=name+'-'+version
    manifest=json.loads(run('installed-manifest',readonly+['query','--installed','--format','json',
        '--fields','name,version,arch,depends','*']).stdout)
    actual={i['name']:i for i in manifest}; old={i['name']:i for i in old_manifest}
    assert len(manifest)==217 and set(actual)==set(old)|{name}
    assert all(actual[n]==old[n] for n in old)
    assert actual[name]['arch']==ARCH and actual[name]['version']==version
    for target,digest in baseline.items():assert sha(original/target)==sha(installed/target)==digest
    for target,digest in default_files.items():assert sha(installed/target)==digest
    for target in ('etc/ld-musl-aarch64-soft.path','usr/share/be6l-soft/profile-lock.json'):
        assert sha(installed/target)==sha(original/target)
    bad=work/'tampered-signed-files'; shutil.copytree(files,bad,symlinks=True)
    victim=bad/'opt/be6l-a64-soft/bin/rpcd'
    data=victim.read_bytes(); victim.write_bytes(data[:-1]+bytes([data[-1]^1])); victim.chmod(0o755)
    tampered=work/'same-label-content-mismatch.apk'; package(tampered,bad)
    run('verify-tampered-signature',[apk,'--keys-dir',trust,'--network=no','verify',tampered])
    rejected=work/'tampered-extracted'; rejected.mkdir()
    run('extract-tampered',[apk,'--keys-dir',trust,'--network=no','extract','--no-chown','--destination',rejected,tampered])
    try:admit_extracted_payload(rejected,expected)
    except AdmissionError:cases.append(dict(name='reject-trusted-signed-same-label-content-change',passed=True))
    else:raise AssertionError('Changed signed payload admitted')
    # Keep an exact package-managed fixture. It is not a service-start script.
    selected=set(profile['files'])|{'lib/ld-musl-aarch64-soft.so.1','etc/ld-musl-aarch64-soft.path'}
    fixture=work/'native-services-loader-fixture.tar'
    with tarfile.open(fixture,'w') as tar:
        for target in sorted(selected):tar.add(installed/target,arcname=target,recursive=False)
    assert all(sha(Path(p))==digest for p,digest in guard.items())
    report=dict(passed=True,kind='native-services-preview-normal-apk-v1',package_name=name,version=version,
        architecture=ARCH,package_file=str(approved),package_sha256=sha(approved),public_key_sha256=sha(public),
        profile_root=str(profile_root),profile_lock_sha256=a.trusted_profile_sha256,root=str(installed),
        actual_packages=217,base_packages_unchanged=216,existing_native_profile_unchanged=True,
        new_elf_paths=32,total_native_elf_paths=90,unique_payload_hashes=profile['unique_payload_hashes'],
        new_path_ownership=ownership,normal_solver_transaction=True,signatures_verified=True,
        precise_payload_admission=True,needed_and_host_symbol_closure_verified=True,
        fixture_file=str(fixture),fixture_sha256=sha(fixture),fixture_paths=len(selected),
        target_fixture_tested=False,default_services_promoted=False,full_image_build_admitted=False,
        source_plugin_paths_corrected=True,old_default_service_files_unchanged=default_files,
        baseline_guards=guard,cases=cases)
finally:
    if key.exists():key.unlink()
    if 'report' in locals():
        report['throwaway_private_key_removed']=True
        (work/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        (BASE/'logs/native-services-apk-v1-20261029.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('new_path_ownership','cases','baseline_guards')},indent=2))
