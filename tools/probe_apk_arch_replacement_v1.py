# SPDX-License-Identifier: MIT
"""Measure APK3 same-P/V cross-architecture transactions on isolated real libs."""
from pathlib import Path
import argparse
import json
import shutil
import subprocess
from plan_normal_mainroot_packages_v1 import sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('arm32-sdk', 'normal-sdk', 'apk', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-apk-arch-semantics-') or w.exists():
        p.error('Use a fresh /root/be6l-apk-arch-semantics-* directory')
    w.mkdir(mode=0o700)
    trust = w/'trust'; trust.mkdir()
    for sdk in (a.arm32_sdk, a.normal_sdk):
        key = sdk/'public-key.pem'
        if b'PRIVATE' in key.read_bytes():
            raise ValueError('Public verification keys only')
        shutil.copy2(key, trust/('key-'+sha(key)+'.pem'))

    def run(label, args, required=True):
        r = subprocess.run(list(map(str, args)), capture_output=True, timeout=120)
        (w/(label+'.log')).write_bytes(r.stdout+r.stderr)
        if required and r.returncode:
            raise RuntimeError(label+' failed; inspect retained log')
        return r

    pairs, metadata = {}, {}
    for architecture, sdk in (('arm_cortex-a7', a.arm32_sdk), ('aarch64_cortex-a53', a.normal_sdk)):
        files = []
        for name, version in (('libc','1.2.6-r5'), ('libgcc1','14.4.0-r5')):
            found = list((sdk/'bin').rglob(name+'-'+version+'.apk'))
            if len(found) != 1:
                raise ValueError('Ambiguous actual archive for '+architecture+'/'+name)
            archive, = found
            info = json.loads(run(architecture+'-'+name+'-info',
                [a.apk, 'adbdump', '--format', 'json', archive]).stdout)['info']
            if (info['name'],info['version'],info['arch']) != (name,version,architecture):
                raise ValueError('Actual archive name/version/architecture differs')
            run(architecture+'-'+name+'-verify', [a.apk, '--network=no', '--keys-dir', trust,'verify',archive])
            snapshot = w/(architecture+'-'+archive.name)
            shutil.copy2(archive,snapshot); files.append(snapshot)
            metadata[architecture+'/'+name] = dict(info=info,sha256=sha(snapshot))
        pairs[architecture] = files
    repo = w/'normal-repo'; repo.mkdir()
    for archive in pairs['aarch64_cortex-a53']:
        shutil.copy2(archive, repo/archive.name.removeprefix('aarch64_cortex-a53-'))
    run('normal-index', [a.apk,'--keys-dir',trust,'mkndx','--sign-key',a.normal_sdk/'private-key.pem',
        '--output',repo/'packages.adb','--pkgname-spec','$name-$version.apk',*repo.glob('*.apk')])
    repositories = w/'repositories'
    repositories.write_text('file://'+str(repo/'packages.adb')+'\n')
    results = {}
    for mode in ('direct-files', 'normal-repo-names', 'normal-repo-upgrade'):
        root = w/mode; root.mkdir()
        common = [a.apk,'--root',root,'--keys-dir',trust,'--network=no','--cache=no',
                  '--logfile=no','--repositories-file','/dev/null']
        run(mode+'-init', common+['--arch','arm_cortex-a7','--scripts=no','add','--initdb'])
        run(mode+'-seed', common+['--arch','arm_cortex-a7','--scripts=no','add',*pairs['arm_cortex-a7']])
        def query(label):
            return json.loads(run(mode+'-'+label,common+['query','--installed','--format','json',
                '--fields','name,version,arch,depends','*']).stdout)
        before = query('before')
        if len(before) != 2 or any(row['arch'] != 'arm_cortex-a7' for row in before):
            raise ValueError('Seed did not actually install the two ARM32 packages')
        (root/'etc/apk').mkdir(parents=True,exist_ok=True)
        (root/'etc/apk/arch').write_text('aarch64_cortex-a53\narm_cortex-a7\n')
        if mode == 'direct-files':
            command = common+['--scripts=no','add',*pairs['aarch64_cortex-a53']]
        else:
            repo_common = [str(x) if str(x) != '/dev/null' else str(repositories) for x in common]
            run(mode+'-load-repo',repo_common+['update'])
            command = repo_common+['--scripts=no','add']
            if mode == 'normal-repo-upgrade':
                command += ['--upgrade']
            command += ['libc=1.2.6-r5','libgcc1=14.4.0-r5']
        r = run(mode+'-replace',command,required=False)
        after = query('after')
        results[mode] = dict(exit_code=r.returncode,before=before,after=after,
            normal_arch_selected=all(row['arch']=='aarch64_cortex-a53' for row in after),
            installed_identity_count=len(after),diagnostics=(r.stdout+r.stderr).decode(errors='replace'))
        if len(after) != 2:
            raise ValueError('Unexpected installed identity count')
    report = dict(scope='Real same-P/V cross-arch two-library transactions, not full root migration',
        archives=metadata,cases=results,package_scripts_executed=False,
        admitted_roots_modified=False,normal_mainroot_composed=False,
        standard_a53_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('APK_ARCH_BEHAVIOR_MEASURED',json.dumps({k:(v['exit_code'],v['normal_arch_selected'])
        for k,v in results.items()}),flush=True)


if __name__ == '__main__':
    main()
