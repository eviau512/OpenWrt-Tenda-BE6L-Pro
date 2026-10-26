# SPDX-License-Identifier: MIT
"""Offline signed APK prototype; never operates on a DUT or existing root.

The private architecture string is experimental, not an upstream OpenWrt ABI.
Package metadata is not proof of calling convention; audited provenance remains
mandatory. No target binary or package script is executed by this experiment.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from a64_soft_context import BASE, SDK

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root',type=Path,required=True)
args=parser.parse_args()
root=args.root
assert root.is_absolute() and not root.exists() and not any(c.isspace() for c in str(root))
root.mkdir()
(root/'.be6l-offline-soft-apk').write_text('owned offline APK ABI experiment\n')
architecture='aarch64_be6l_soft_experimental'
artifact=BASE/'artifacts/a64-soft-lua-bindings'
manifest=json.loads((artifact/'manifest.json').read_text())
assert manifest['abi']=='AAPCS64-soft' and manifest['strong_dynamic_symbols_closed']
# Get exact audited files from the tar; never traverse untrusted archive paths.
import tarfile
with tarfile.open(artifact/'bindings.tar') as archive:
    assert sorted(archive.getnames())==sorted(manifest['files'])
    contents={entry.name:archive.extractfile(entry).read() for entry in archive if entry.isfile()}
assert set(contents)==set(manifest['files'])
for name,data in contents.items():
    assert '/' not in name and name not in ('.','..')
    assert hashlib.sha256(data).hexdigest()==manifest['files'][name]['sha256']
manifest_digest=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True).encode()).hexdigest()
version='0.1.'+str(int(manifest_digest[:12],16))+'-r1'
apk=SDK/'staging_dir/host/bin/apk'
logdir=BASE/'logs'/('soft-apk-'+root.name)
logdir.mkdir(parents=True)
key=root/'throwaway-signing.key'
public=root/'throwaway-signing.pub'
packages={}
report={'architecture':architecture,'version':version,'live_dut_modified':False,
        'input_manifest_sha256':manifest_digest,
        'target_execution':False,'standard_openwrt_target':False,'cases':[]}

def run(label,command,success=True):
    result=subprocess.run([str(x) for x in command],capture_output=True,timeout=60)
    (logdir/(label+'.txt')).write_bytes(result.stdout+result.stderr)
    assert (result.returncode==0)==success,(label,result.returncode)
    report['cases'].append({'name':label,'status':result.returncode,'expected_success':success})
    return result

try:
    run('generate-fixture-key',['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',key])
    key.chmod(0o600)
    run('generate-public-key',['openssl','pkey','-in',key,'-pubout','-out',public])
    for group in ('runtime','lua','ubusd','foreign'):
        files=root/('files-'+group)
        files.mkdir()
        private=files/'opt/be6l-a64-soft'
        if group!='foreign':
            for name,data in contents.items():
                wanted=('runtime' if name not in ('lua','luac','ubusd') else 'lua' if name in ('lua','luac') else 'ubusd')
                if group!=wanted:continue
                folder='bin' if name in ('lua','luac','ubusd') else 'lib/lua' if name in ('nixio.so','uci.so','ubus.so','uloop.so') else 'lib'
                target=private/folder/name
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(data);target.chmod(0o755)
            if group=='runtime':
                (files/'lib').mkdir()
                (files/'lib/ld-musl-aarch64-soft.so.1').symlink_to('../opt/be6l-a64-soft/lib/libc.so')
                (files/'etc').mkdir()
                (files/'etc/ld-musl-aarch64-soft.path').write_text('/opt/be6l-a64-soft/lib\n')
        else:
            (files/'foreign-metadata-fixture').write_text('No executable payload; architecture negative only.\n')
        name='be6l-a64-soft-'+group
        package=root/(name+'.apk')
        command=[apk,'mkpkg','--sign-key',key,'--files',files,'--output',package,
            '--info','name:'+name,'--info','version:'+version,
            '--info','arch:'+('aarch64_cortex-a53' if group=='foreign' else architecture),
            '--info','description:Offline soft-ABI namespace experiment',
            '--info','license:LicenseRef-Upstream-Mixed-Experiment']
        if group in ('lua','ubusd'):
            command+=['--info','depends:be6l-a64-soft-runtime='+version]
        run('package-'+group,command)
        packages[group]=package
    install=root/'install-root'
    keys=install/'etc/apk/keys'
    keys.mkdir(parents=True)
    shutil.copyfile(public,keys/'fixture.pem')
    common=[apk,'--root',install,'--arch',architecture,'--network=no','--scripts=no',
            '--cache=no','--repositories-file','/dev/null']
    run('init-database',common+['add','--initdb'])
    for group,package in packages.items():
        run('verify-'+group,[apk,'--keys-dir',keys,'--network=no','verify',package])
    empty_keys=root/'empty-trust'
    empty_keys.mkdir()
    rejected=run('reject-untrusted-signature',[apk,'--keys-dir',empty_keys,'--network=no','verify',packages['runtime']],False)
    assert b'UNTRUSTED' in (rejected.stdout+rejected.stderr).upper()
    rejected=run('reject-missing-runtime',common+['add','--simulate',packages['lua']],False)
    assert b'be6l-a64-soft-runtime (no such package)' in rejected.stdout+rejected.stderr
    rejected=run('reject-foreign-architecture',common+['add','--simulate',packages['foreign']],False)
    assert b'arch: aarch64_cortex-a53' in rejected.stdout+rejected.stderr
    run('install-signed-closure',common+['add',packages['runtime'],packages['lua'],packages['ubusd']])
    for group in ('runtime','lua','ubusd'):
        for source in (root/('files-'+group)).rglob('*'):
            if not source.is_file() or source.is_symlink():continue
            target=install/source.relative_to(root/('files-'+group))
            assert target.read_bytes()==source.read_bytes(),source.name
    assert (install/'lib/ld-musl-aarch64-soft.so.1').is_symlink()
    # The negative fixture has no foreign code, so it proves metadata rejection,
    # not detection of falsely labelled or FP-using AArch64 machine code.
    report.update(passed=True,signature_verification_passed=True,
        exact_runtime_dependency_passed=True,foreign_metadata_rejected=True,
        untrusted_signature_rejected=True,
        installed_payload_hashes_passed=True,
        same_label_wrong_abi_detection_qualified=False,installed_roots_booted=False)
finally:
    if key.exists():key.unlink()
    report['throwaway_private_key_removed']=True
    (logdir/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print('OFFLINE_SIGNED_SOFT_ABI_APK_PROTOTYPE_PASS',logdir,flush=True)
