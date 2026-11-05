# SPDX-License-Identifier: MIT
"""Normally repackage admitted private soft-ABI providers with explicit ELF tags.

Only the sealed 2f82 root is an ABI-provenance input. Standard guest ELFs are
never tagged. No binfmt rule, image edit, target script or router operation occurs.
"""
from pathlib import Path, PurePosixPath
import argparse
import json
import os
import shutil
import struct
import subprocess
from package_native_netifd_v3 import copy_path, records, root_digest, sha
from plan_integer_binfmt_v1 import ADMITTED_ROOT, PRIVATE_SOFT_EFLAGS, matches, tag_private

FIELDS = 'name,version,arch,license,description,depends,provides,install-if,provider-priority,origin,tags,replaces'
ARCH = 'aarch64_be6l_soft_experimental'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base-root', 'apk', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-private-marker-apk-') or w.exists():
        p.error('Use a fresh /root/be6l-private-marker-apk-* directory')
    original = a.base_root.resolve()
    if root_digest(original) != ADMITTED_ROOT:
        raise ValueError('Private soft ABI provenance root is not admitted')
    w.mkdir(mode=0o700)
    common = [a.apk, '--root', original, '--network=no', '--cache=no', '--logfile=no', '--repositories-file', '/dev/null']

    def run(label, command):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=240)
        (w/(label+'.log')).write_bytes(result.stdout+result.stderr)
        if result.returncode:
            raise RuntimeError(label+' failed; inspect retained log')
        return result.stdout

    query = ['query', '--installed', '--format', 'json', '--fields', FIELDS, '*']
    packages = json.loads(run('original-packages', common+query))
    by_name = {item['name']:item for item in packages}
    native, owners = {}, {}
    for path in original.rglob('*'):
        if not path.is_file() or path.is_symlink():
            continue
        with path.open('rb') as incoming:
            header = incoming.read(64)
        if not matches(header):
            continue
        relative = path.relative_to(original).as_posix()
        owner = run('owner-'+relative.replace('/', '_'), common+['info', '--who-owns', '/'+relative]).decode().strip()
        found = [item for item in packages if owner.endswith(' is owned by '+item['name']+'-'+item['version'])]
        if len(found) != 1 or found[0]['arch'] != ARCH:
            raise ValueError('Native file lacks admitted private package ownership: '+relative)
        native[relative] = tag_private(path.read_bytes())
        owners[relative] = found[0]['name']
    if len(native) != 61 or len(packages) != 219:
        raise ValueError('Unexpected admitted root inventory')
    selected = set(owners.values())
    while True:
        exact = {name+'='+by_name[name]['version'] for name in selected}
        added = {item['name'] for item in packages if any(dep in exact for field in ('depends', 'install-if')
                 for dep in item.get(field, []))}-selected
        if not added:
            break
        selected |= added
    versions = {}
    for name in selected:
        base, release = by_name[name]['version'].rsplit('-r', 1)
        versions[name] = base+'-r'+str(int(release)+1)
    replacements = {name+'='+by_name[name]['version']:name+'='+version for name, version in versions.items()}
    expected, files = {}, {}
    for name in sorted(selected):
        root = w/'files'/name
        root.mkdir(parents=True)
        listing = run('contents-'+name, common+['info', '--contents', name]).decode().splitlines()
        for line in listing:
            if not line or line.endswith('contains:'):
                continue
            relative = line.lstrip('/')
            if '..' in PurePosixPath(relative).parts:
                raise ValueError('Invalid provider path')
            copy_path(original/relative, root/relative)
            if relative in native:
                (root/relative).write_bytes(native[relative])
        files[name] = root
        for path, value in records(root).items():
            if path in expected:
                raise ValueError('Two providers own the same path')
            expected[path] = value
    key, public, trust = w/'temporary-signing.key', w/'public-key.pem', w/'trust'
    trust.mkdir()
    for path in (original/'etc/apk/keys').iterdir():
        if b'PRIVATE' in path.read_bytes():
            raise ValueError('Not a public verification key')
        copy_path(path, trust/path.name)
    approved = []
    before = records(original)
    try:
        run('key-generate', ['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key])
        key.chmod(0o600)
        run('key-public', ['openssl', 'pkey', '-in', key, '-pubout', '-out', public])
        copy_path(public, trust/'be6l-private-marker.pem')
        for name in sorted(selected):
            old = by_name[name]
            metadata = {field:value for field,value in old.items() if field in FIELDS.split(',')}
            metadata['version'] = versions[name]
            for field in ('depends', 'provides', 'install-if', 'replaces'):
                if field in metadata:
                    metadata[field] = [replacements.get(value, value) for value in metadata[field]]
            target = w/(name+'.apk')
            command = [a.apk, 'mkpkg', '--sign-key', key, '--files', files[name], '--output', target]
            for field, value in metadata.items():
                command += ['--info', field+':'+(' '.join(value) if isinstance(value, list) else str(value))]
            run('mkpkg-'+name, command)
            run('verify-'+name, [a.apk, '--network=no', '--keys-dir', trust, 'verify', target])
            approved.append(target)
        root = w/'root'
        shutil.copytree(original, root, symlinks=True)
        transaction = [a.apk, '--root', root, '--network=no', '--cache=no', '--logfile=no', '--scripts=no',
                       '--keys-dir', trust, '--repositories-file', '/dev/null']
        run('simulate', transaction+['add', '--simulate', *approved])
        if root_digest(root) != ADMITTED_ROOT:
            raise ValueError('Normal transaction simulation changed root')
        run('normal-install', transaction+['add', *approved])
        readonly = [a.apk, '--root', root, '--network=no', '--cache=no', '--logfile=no', '--repositories-file', '/dev/null']
        installed = json.loads(run('installed-packages', readonly+query))
        if len(installed) != 219:
            raise ValueError('Provider transaction changed package count')
        after = records(root)
        for name, value in expected.items():
            if after.get(name) != value:
                raise ValueError('Installed provider payload differs: '+name)
        for relative in native:
            path = root/relative
            if struct.unpack_from('<I', path.read_bytes(), 48)[0] != PRIVATE_SOFT_EFLAGS or matches(path.read_bytes()[:64]):
                raise ValueError('Native owner would recurse through binfmt: '+relative)
            owner = run('installed-owner-'+relative.replace('/', '_'), readonly+['info', '--who-owns', '/'+relative]).decode().strip()
            name = owners[relative]
            if not owner.endswith(' is owned by '+name+'-'+versions[name]):
                raise ValueError('Wrong marked native owner')
        changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
        if any(name not in native and not name.startswith(('lib/apk/', 'etc/apk/')) for name in changed):
            raise ValueError('Unrelated payload changed')
        if root_digest(original) != ADMITTED_ROOT:
            raise ValueError('Original admitted root changed')
    finally:
        key.unlink(missing_ok=True)
    result = dict(normal_signed_component_transaction=True, installed_packages=219,
        private_soft_abi_provenance_root=ADMITTED_ROOT, private_marker=hex(PRIVATE_SOFT_EFLAGS),
        marker_is_standard_arm_feature_flag=False, private_native_files_marked=61,
        native_owners=owners, repackaged_versions=versions, packages={p.name:sha(p) for p in approved},
        standard_guests_modified=False, original_root_unchanged=True,
        installed_root_records_sha256=root_digest(root), private_signing_key_removed=not key.exists(),
        target_scripts_executed=False, binfmt_registered=False, image_built=False, target_executed=False)
    (w/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print('PRIVATE_SOFT_ELF_TAGS_NORMALLY_PACKAGED', len(native), json.dumps(versions), flush=True)


if __name__ == '__main__':
    main()
