# SPDX-License-Identifier: MIT
"""Sign unchanged installed ARM32 SSH plus a metadata-only private access upgrade.

All roots/packages containing SSH keys stay private. No target executable or
script runs. Normal APK replaces transfers the narrow Dropbear payload; an old
recovery-guard dependency remains an explicit combined-root migration gate.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from inventory_mainroot_a53_v1 import elf, installed, rooted
from package_native_netifd_v3 import copy_path, records, root_digest, sha

NAME = 'be6l-arm32-dropbear'
VERSION = '2026.94-r103'
ARCH = 'arm_cortex-a7'
ACCESS = 'be6l-ram-access'
ACCESS_VERSION = '1.0.0-r2'
RUNTIME = 'be6l-arm32-runtime'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('base-root','runtime','apk','work'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();w=a.work.resolve();base=a.base_root.resolve()
    if w!=Path('/root/be6l-native-dropbear-20261113-r1') or w.exists():
        p.error('Fresh /root/be6l-native-dropbear-20261113-r1 required')
    before=records(base);baseline=root_digest(base)
    packages,owners=installed(base);old=packages['dropbear'];access=packages[ACCESS]
    if (old['version']!='2026.94-r3' or old['arch']!=ARCH or old['depends']!=['libc'] or
            access['version']!='1.0.0-r1' or access['depends']!=['dropbear']):
        raise ValueError('Source package metadata differs from reviewed migration')
    rp=a.runtime/'result.json';runtime=json.loads(rp.read_text())
    runtime_package=a.runtime/runtime['package'];runtime_files=a.runtime/'files'
    if (runtime['name']!=RUNTIME or runtime['arch']!=ARCH or runtime['provides'] or
            not runtime['normal_signature_verified'] or sha(runtime_package)!=runtime['package_sha256'] or
            root_digest(runtime_files)!=runtime['payload_records_sha256']):
        raise ValueError('Runtime receipt/payload differs')
    dependency=RUNTIME+'='+runtime['version'];ssh_dependency=NAME+'='+VERSION
    if dependency!=runtime['exact_runtime_dependency']:
        raise ValueError('Runtime dependency receipt differs')
    w.mkdir(mode=0o700);files=w/'files';files.mkdir()
    manifest={};metadata_prefix='lib/apk/packages/dropbear.'
    expected_metadata={'alternatives','conffiles','conffiles_static','list'}
    metadata={n.removeprefix(metadata_prefix) for n in old['paths'] if n.startswith(metadata_prefix)}
    if metadata!=expected_metadata or len(old['paths'])!=12:
        raise ValueError('Unreviewed Dropbear payload set')
    for name in old['paths']:
        if '..' in PurePosixPath(name).parts or owners.get(name)!=['dropbear']:
            raise ValueError('Unsafe/ambiguous source ownership')
        destination=('lib/apk/packages/'+NAME+'.'+name.removeprefix(metadata_prefix)
                     if name.startswith(metadata_prefix) else name)
        copy_path(base/name,files/destination)
        manifest[name]=dict(destination=destination,source=before[name],
            transformation='package-specific metadata path rename' if destination!=name else 'unchanged canonical payload')
    listed=files/('lib/apk/packages/'+NAME+'.list')
    listed.write_text(''.join('/'+x['destination']+'\n' for _,x in sorted(manifest.items())))
    listed.chmod((base/'lib/apk/packages/dropbear.list').stat().st_mode & 0o7777)
    static=files/('lib/apk/packages/'+NAME+'.conffiles_static')
    for line in static.read_text().splitlines():
        name,digest=line.split()
        if name.lstrip('/') not in records(files) or sha(files/name.lstrip('/'))!=digest:
            raise ValueError('Conffiles_static hash does not describe the packaged payload')
    # A conffile declaration is not a claim to own/package those user's keys.
    declarations=(files/('lib/apk/packages/'+NAME+'.conffiles')).read_text().splitlines()
    excluded_user_conffiles=[n for n in declarations if n.lstrip('/') not in records(files)]
    if any(n.startswith('etc/dropbear/') for n in records(files)):
        raise ValueError('Refuse placing source SSH user/host keys into the SSH package')
    for source,item in manifest.items():
        item['packaged']=records(files)[item['destination']]
        if not source.endswith('.list') and item['source']!=item['packaged']:
            raise ValueError('Unexpected SSH payload mutation: '+source)
        if source.endswith('.list'):
            item['transformation']='regenerate exact destination ownership list after metadata rename'
    # Access retains all current credentials, privately, with only P/V/D changed.
    access_files=w/'access-files';access_files.mkdir()
    for name in access['paths']:
        if owners.get(name)!=[ACCESS] or not name.startswith('etc/dropbear/'):
            raise ValueError('Access payload ownership/path changed')
        copy_path(base/name,access_files/name)
    if records(access_files)!={n:before[n] for n in access['paths']}:
        raise ValueError('Access metadata-only upgrade changed credential bytes/modes')
    info=elf(files/'usr/sbin/dropbear')
    if (info is None or info['bits']!=32 or info['machine']!=40 or
            info['sha256']!='0021b4d326c160445bc0fb82680625c1612ccbdd924f58e835ddeb9b10e915f3' or
            info['interpreter']!='/lib/ld-musl-arm.so.1' or info['rpath'] or info['runpath']):
        raise ValueError('Unexpected native ARM32 SSH ELF')
    closure=[]
    for need in info['needed']:
        if '/' in need:raise ValueError('Path-valued DT_NEEDED is unreviewed')
        target=next((rooted(runtime_files,d+'/'+need) for d in ('lib/be6l-arm32','usr/lib/be6l-arm32')
                     if rooted(runtime_files,d+'/'+need) is not None),None)
        dep=elf(target) if target else None
        if dep is None or dep['machine']!=40 or dep['bits']!=32:
            raise ValueError('ARM32 private DT_NEEDED closure missing')
        closure.append(dict(needed=need,resolved=target.relative_to(runtime_files).as_posix(),sha256=dep['sha256']))
    for name in ('usr/bin/dbclient','usr/bin/dropbearkey'):
        if rooted(files,name)!=files/'usr/sbin/dropbear':
            raise ValueError('Canonical SSH alias no longer resolves to original ARM32 ELF')
    (w/'source-destination-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (w/'needed-closure.json').write_text(json.dumps(closure,indent=2)+'\n')
    trust=w/'trust';trust.mkdir()
    for source in [base/'etc/apk/keys',a.runtime/'trust']:
        for keypath in source.glob('*'):
            if keypath.is_file():copy_path(keypath,trust/keypath.name)
    key=w/'temporary-signing.key';public=trust/(NAME+'.pem')
    ssh_package=w/(NAME+'-'+VERSION+'.apk')
    access_package=w/(ACCESS+'-'+ACCESS_VERSION+'.apk')

    def run(label,command,success=True):
        r=subprocess.run(list(map(str,command)),capture_output=True,timeout=180)
        (w/(label+'.log')).write_bytes(r.stdout+r.stderr)
        if success and r.returncode:raise RuntimeError(label+' failed; private log retained')
        return r

    def transaction(root):
        return [a.apk,'--root',root,'--network=no','--cache=no','--logfile=no','--scripts=no',
                '--repositories-file','/dev/null','--keys-dir',trust]

    def identity(root,name,version,arch,depends):
        query=json.loads(run('identity-'+root.name+'-'+name,[x for x in transaction(root) if x!='--scripts=no']+[
            'query','--installed','--format','json','--fields','name,version,arch,depends,provides',name]).stdout)
        if (len(query)!=1 or query[0]['name']!=name or query[0]['version']!=version or
                query[0]['arch']!=arch or query[0].get('depends',[])!=depends or query[0].get('provides',[])):
            raise ValueError('Actual installed identity/dependency/provider differs')
        return query[0]

    def make(package,payload,name,version,arch,depends,replaces=None):
        command=[a.apk,'mkpkg','--sign-key',key,'--files',payload,'--output',package]
        fields=dict(name=name,version=version,arch=arch,license='MIT',
            description='BE6L private ARM32 SSH compatibility metadata; unchanged installed payload',depends=' '.join(depends))
        if replaces:fields['replaces']=replaces
        for k,v in fields.items():command+=['--info',k+':'+v]
        run('mkpkg-'+name,command)

    try:
        run('key-generate',['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',key]);key.chmod(0o600)
        run('key-public',['openssl','pkey','-in',key,'-pubout','-out',public])
        make(ssh_package,files,NAME,VERSION,ARCH,[dependency],'dropbear')
        make(access_package,access_files,ACCESS,ACCESS_VERSION,'noarch',[ssh_dependency])
        for pkg,payload in [(runtime_package,runtime_files),(ssh_package,files),(access_package,access_files)]:
            run('verify-'+pkg.stem,[a.apk,'--network=no','--keys-dir',trust,'verify',pkg])
            extracted=w/('verified-'+pkg.stem);extracted.mkdir()
            run('extract-'+pkg.stem,[a.apk,'--network=no','--keys-dir',trust,'extract','--no-chown','--destination',extracted,pkg])
            if records(extracted)!=records(payload):raise ValueError('Signature extraction differs from payload')
        empty=w/'isolated-root';(empty/'etc/apk').mkdir(parents=True);(empty/'etc/apk/arch').write_text(ARCH+'\n')
        missing=run('negative-missing-exact-runtime',transaction(empty)+['add','--initdb',ssh_package],False)
        if missing.returncode==0:raise ValueError('Missing exact runtime dependency unexpectedly admitted')
        run('normal-isolated-two-package-install',transaction(empty)+['add','--initdb',runtime_package,ssh_package])
        identity(empty,NAME,VERSION,ARCH,[dependency]);identity(empty,RUNTIME,runtime['version'],ARCH,[])
        ep,eo=installed(empty)
        if set(ep)!={NAME,RUNTIME}:raise ValueError('Isolated install contains unexpected packages')
        for payload,name in [(files,NAME),(runtime_files,RUNTIME)]:
            actual=records(empty)
            for path,item in records(payload).items():
                if actual.get(path)!=item or eo.get(path)!=[name]:raise ValueError('Isolated installed payload/ownership differs')
        run('normal-isolated-access-metadata-install',transaction(empty)+['add',access_package])
        identity(empty,ACCESS,ACCESS_VERSION,'noarch',[ssh_dependency])
        ep,eo=installed(empty)
        if any(records(empty).get(n)!=item or eo.get(n)!=[ACCESS] for n,item in records(access_files).items()):
            raise ValueError('Normal isolated access install changed private bytes/modes/ownership')
        root=w/'coexistence-root';shutil.copytree(base,root,symlinks=True)
        transfer=run('normal-private-transfer-three-packages',transaction(root)+['add',runtime_package,ssh_package,access_package],False)
        collision='trying to overwrite lib/ld-musl-arm.so.1 owned by libc-1.2.6-r5.'
        loader_blocked=transfer.returncode!=0
        if loader_blocked and (transfer.returncode!=1 or collision not in transfer.stderr.decode() or
                len([x for x in transfer.stderr.decode().splitlines() if x.startswith('ERROR:')])!=1):
            raise RuntimeError('Unexpected private-root transaction failure; inspect private log')
        identities=[identity(root,NAME,VERSION,ARCH,[dependency]),identity(root,ACCESS,ACCESS_VERSION,'noarch',[ssh_dependency])]
        after=records(root);ip,io=installed(root)
        for source,item in manifest.items():
            path=item['destination']
            if after.get(path)!=item['packaged'] or io.get(path)!=[NAME]:
                raise ValueError('Standard replaces did not transfer exact narrow SSH ownership')
        protected={n:v for n,v in before.items() if n.startswith('etc/dropbear/') or
                   n in ('etc/passwd','etc/shadow','etc/group') or n.startswith('etc/rc.d/')}
        service={n:before[n] for n in old['paths'] if not n.startswith(metadata_prefix)}
        if any(after.get(n)!=v for n,v in (protected|service).items()):
            raise ValueError('Private normal transaction changed SSH/service/user data')
        if any(n.endswith('.apk-new') or n.endswith('.apknew') for n in after if n not in before):
            raise ValueError('Protected config merger needed; do not silently claim a clean migration')
        reverse={n:[d for d in v['depends'] if re.split(r'[<>=~]',d,1)[0]=='dropbear'] for n,v in ip.items()}
        reverse={n:d for n,d in reverse.items() if d}
        simulated=run('normal-old-dropbear-removal-simulation',transaction(root)+['del','--simulate','dropbear'],False)
        # The old guard requires the old identity. No provider shortcut or DB edits.
        removed=False
        if not reverse and not loader_blocked:
            run('normal-remove-old-dropbear',transaction(root)+['del','dropbear']);removed=True
            ip,io=installed(root);after=records(root)
            if 'dropbear' in ip or any(x=='dropbear' or x.startswith('dropbear=') for x in (root/'etc/apk/world').read_text().splitlines()):
                raise ValueError('Old package/world entry survived normal removal')
            if any(after.get(n)!=v for n,v in (protected|service).items()):raise ValueError('Removal changed service/user data')
        (w/'installed-identities.json').write_text(json.dumps(identities,indent=2)+'\n')
        report=dict(name=NAME,version=VERSION,arch=ARCH,depends=[dependency],provides=[],replaces=['dropbear'],
            package=ssh_package.name,package_sha256=sha(ssh_package),
            access_name=ACCESS,access_version=ACCESS_VERSION,access_arch='noarch',access_depends=[ssh_dependency],
            access_package=access_package.name,access_package_sha256=sha(access_package),
            access_payload_unchanged=True,access_credential_file_count=len(access['paths']),
            runtime_result_sha256=sha(rp),runtime_package_sha256=sha(runtime_package),
            source_root_records_sha256=baseline,source_root_unchanged=root_digest(base)==baseline,
            normal_signature_verification_passed=True,extracted_payload_exact=True,
            isolated_two_package_normal_transaction=True,missing_exact_runtime_rejected=missing.returncode!=0,
            isolated_access_metadata_transaction=True,private_three_package_normal_transfer=not loader_blocked,
            private_three_package_transaction_exit=transfer.returncode,
            canonical_arm32_interpreter_owned_by_old_libc_blocks_runtime=loader_blocked,
            private_root_partial_after_rejected_runtime_transaction=loader_blocked,
            actual_installed_ssh_identity=identities[0],
            actual_installed_access_identity=identities[1],canonical_service_payload_unchanged=True,
            ssh_userdata_passwd_and_startup_unchanged=True,protected_private_path_count=len(protected),
            protected_conffile_merger_needed=False,narrow_ssh_replaces_ownership_verified=True,
            old_dropbear_removed_by_normal_transaction=removed,old_name_reverse_dependencies=reverse,
            old_removal_simulation_exit=simulated.returncode,combined_guard_migration_required=bool(reverse),
            source_destination_manifest_sha256=sha(w/'source-destination-manifest.json'),
            needed_closure_sha256=sha(w/'needed-closure.json'),checked_needed_edges=len(closure),
            canonical_interpreter=info['interpreter'],all_native_dso_needed_private_arm32=True,
            private_signing_key_removed=False,mainroot_coexistence_qualified=removed,
            target_executed=False,vm_plugin_isolation_qualified=False,standard_a53_package_compatibility_qualified=False)
    finally:key.unlink(missing_ok=True)
    report['private_signing_key_removed']=not key.exists()
    if not report['source_root_unchanged']:raise ValueError('Source root changed')
    (w/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('SIGNED_NATIVE_ARM32_SSH',NAME,VERSION,'TRANSFERRED',not report['combined_guard_migration_required'],flush=True)


if __name__=='__main__':main()
