# SPDX-License-Identifier: MIT
"""Package the exact inventoried ARM32 DSO closure at ABI-private paths.

Creates one signed APK and a new empty verification root. It changes no admitted
root and provides no generic libc/DSO/normal-A53 package identity. DT_NEEDED
closure does not qualify VM paths, plugin consumers, services or a main root.
"""
from pathlib import Path, PurePosixPath
from collections import defaultdict
import argparse
import hashlib
import json
import os
import posixpath
import re
import subprocess
from inventory_mainroot_a53_v1 import elf, installed, rooted, scan
from package_native_netifd_v3 import copy_path, records, root_digest, sha

NAME = 'be6l-arm32-runtime'
ARCH = 'arm_cortex-a7'
LIBRARIES = ('lib/be6l-arm32', 'usr/lib/be6l-arm32')
INTERPRETER = 'lib/ld-musl-arm.so.1'


def destination(name):
    if name == INTERPRETER:
        return name
    if name == 'usr/bin/ldd':
        return 'usr/lib/be6l-arm32/bin/ldd'
    if name.startswith('usr/lib/'):
        return 'usr/lib/be6l-arm32/'+name[len('usr/lib/'):]
    if name.startswith('lib/'):
        return 'lib/be6l-arm32/'+name[len('lib/'):]
    raise ValueError('Unreviewed runtime source path: '+name)


def dependency_name(value):
    return re.split(r'[<>=~]', value, maxsplit=1)[0].lstrip('!')


def admit_source_arm32_inventory(actual, inventoried):
    """Require a fresh complete source scan, independently of receipt flags."""
    selected = {name:item for name,item in actual.items() if item['machine'] == 40}
    expected = {name:item for name,item in inventoried.items() if item['machine'] == 40}
    if set(selected) != set(expected):
        raise ValueError('Complete source ARM32 ELF set differs from the inventory')
    for name,item in selected.items():
        if item['sha256'] != expected[name]['sha256'] or sorted(item['owners']) != sorted(expected[name]['owners']):
            raise ValueError('Complete source ARM32 ELF hash/owner differs from inventory: '+name)
    return selected


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base-composition', 'inventory', 'apk', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--release', type=int, default=1)
    a = p.parse_args()
    w = a.work.resolve()
    if (w.parent != Path('/root') or not re.fullmatch('be6l-arm32-compat-20261113-[a-z0-9-]+', w.name)
            or w.exists() or not 1 <= a.release <= 999):
        p.error('Use a fresh /root/be6l-arm32-compat-20261113-* and a positive release')
    base = a.base_composition/'root'
    receipt_path = a.base_composition/'result.json'
    base_receipt = json.loads(receipt_path.read_text())
    inventory_path = a.inventory/'result.json'
    inventory = json.loads(inventory_path.read_text())
    baseline = root_digest(base)
    if (not base_receipt.get('normal_signed_component_transaction') or
            base_receipt.get('installed_root_records_sha256') != baseline or
            not inventory.get('full_root_receipts_match')):
        raise ValueError('Sealed source composition/inventory admission differs')
    sources = inventory['arm32_runtime_dso_files']
    aliases = inventory['arm32_runtime_aliases']
    if len(sources) != 75 or len(aliases) != 39:
        raise ValueError('Expected the complete75 DSO/39 alias inventory')
    packages, ownership = installed(base)
    actual_source_elf = scan(base, ownership)
    arm32 = admit_source_arm32_inventory(actual_source_elf, inventory['main_elf'])
    w.mkdir(mode=0o700)
    files = w/'files'
    files.mkdir()
    mapping = {name: destination(name) for name in sources.keys() | aliases.keys()}
    if len(set(mapping.values())) != len(mapping):
        raise ValueError('Runtime relocation has duplicate destinations')
    manifest = {}
    for name, expected in sorted(sources.items()):
        path = base/name
        actual = elf(path)
        if (path.is_symlink() or actual is None or actual['bits'] != 32 or actual['machine'] != 40 or
                actual['sha256'] != expected['sha256'] or actual['needed'] != expected['needed'] or
                actual['rpath'] or actual['runpath'] or sorted(ownership.get(name, [])) != sorted(expected['owners'])):
            raise ValueError('Inventoried source DSO changed: '+name)
        copy_path(path, files/mapping[name])
        if sha(files/mapping[name]) != expected['sha256']:
            raise ValueError('Relocation changed original ELF bytes')
        manifest[name] = dict(type='file', destination=mapping[name], source_sha256=expected['sha256'],
            destination_sha256=sha(files/mapping[name]), owners=expected['owners'],
            source_mode=oct(path.stat().st_mode & 0o7777), needed=actual['needed'], soname=actual['soname'])
    unchanged_alias_text = 0
    for name, expected in sorted(aliases.items()):
        path = base/name
        if not path.is_symlink() or os.readlink(path) != expected['target']:
            raise ValueError('Inventoried source alias changed: '+name)
        resolved = rooted(base, name)
        if resolved is None or resolved.relative_to(base).as_posix() != expected['resolved']:
            raise ValueError('Inventoried source alias resolves differently: '+name)
        target = expected['target']
        immediate = posixpath.normpath(target if target.startswith('/') else posixpath.join(posixpath.dirname(name), target)).lstrip('/')
        if immediate not in mapping:
            raise ValueError('Alias target is outside the closed runtime: '+name)
        new_target = posixpath.relpath(mapping[immediate], posixpath.dirname(mapping[name]))
        output = files/mapping[name]
        output.parent.mkdir(parents=True, exist_ok=True)
        output.symlink_to(new_target)
        unchanged_alias_text += new_target == target
        manifest[name] = dict(type='symlink', destination=mapping[name], source_target=target,
            destination_target=new_target, source_target_sha256=hashlib.sha256(target.encode()).hexdigest(),
            destination_target_sha256=hashlib.sha256(new_target.encode()).hexdigest(),
            resolved_source=expected['resolved'], resolved_destination=mapping[expected['resolved']],
            resolved_elf_sha256=sha(resolved), owners=expected['owners'],
            reason=('Unique ARM32 interpreter must target private libc' if name == INTERPRETER else
                    'Private ldd leaves canonical ldd available to normal A53' if name == 'usr/bin/ldd' else
                    'Relative alias chain preserved'))
    if unchanged_alias_text != 37:
        raise ValueError('Expected only interpreter and private-ldd target text transitions')
    for name, item in manifest.items():
        if item['type'] == 'symlink':
            target = rooted(files, item['destination'])
            if target is None or sha(target) != item['resolved_elf_sha256']:
                raise ValueError('Relocated alias no longer reaches the original ARM32 ELF: '+name)
    path_file = files/'etc/ld-musl-arm.path'
    path_file.parent.mkdir(parents=True)
    path_file.write_text('/lib/be6l-arm32:/usr/lib/be6l-arm32\n')
    path_file.chmod(0o644)
    edges = []
    consumers = defaultdict(list)
    for name, expected in sorted(arm32.items()):
        actual = elf(base/name)
        if actual is None or actual['sha256'] != expected['sha256'] or actual['rpath'] or actual['runpath']:
            raise ValueError('Source ARM32 consumer changed or has an unreviewed search override: '+name)
        if actual['interpreter'] not in (None, '/'+INTERPRETER):
            raise ValueError('Source consumer uses another ARM32 interpreter: '+name)
        for owner in expected['owners']:
            consumers[owner].append(name)
        for needed in actual['needed']:
            if '/' in needed:
                raise ValueError('Absolute/path DT_NEEDED is outside the private default-path model')
            target = next((rooted(files, directory+'/'+needed) for directory in LIBRARIES
                           if rooted(files, directory+'/'+needed) is not None), None)
            info = elf(target) if target else None
            if info is None or info['bits'] != 32 or info['machine'] != 40:
                raise ValueError('Private ARM32 DT_NEEDED closure is incomplete: '+name+' -> '+needed)
            edges.append(dict(consumer=name, needed=needed, resolved=target.relative_to(files).as_posix(), sha256=info['sha256']))
    if len(edges) != len(inventory['arm32_needed_edges']):
        raise ValueError('The full current ARM32 consumer/edge inventory changed')
    basis = dict(manifest=manifest, interpreter='/'+INTERPRETER,
                 loader_path=path_file.read_text(), source_package_versions={name:packages[name]['version']
                 for name in inventory['arm32_runtime_source_packages']})
    digest = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    version = '1.0.'+str(int(digest[:12], 16))+'-r'+str(a.release)
    dependency = NAME+'='+version
    source_owners = set(inventory['arm32_runtime_source_packages'])
    policy = {}
    for owner, paths in sorted(consumers.items()):
        info = packages[owner]
        transferred = [name for name in mapping if owner in ownership.get(name, [])]
        policy[owner] = dict(source_package=info,
            proposed_private_name=owner if owner.startswith('be6l-arm32-') else 'be6l-arm32-'+owner,
            exact_runtime_dependency=dependency, source_elf_paths=paths,
            transferred_runtime_paths=sorted(transferred),
            surviving_elf_paths=sorted(set(paths)-set(sources)),
            original_depends_preserved_for_review=info['depends'],
            possible_abi_dependency_names=sorted({dependency_name(d) for d in info['depends']
                                                  if dependency_name(d) in source_owners | {'libpthread','librt','libdl'}}),
            generic_provides_to_remove=info['provides'],
            mandatory_semantic_dependency_review=True,
            same_path_coinstallation_requires_explicit_root_policy=True,
            consumer_metadata_rebuilt=False)
    blocked = {
        'usr/lib/liblua.so.5.1.5': 'Rebuild private Lua C-module defaults; global /usr/lib/lua and ./?.so are not isolated',
        'usr/lib/libucode.so.20261009': 'Rebuild private LIB_SEARCH_PATH, including all embedded VM consumers',
        'sbin/rpcd': 'Rebuild RPC_LIBRARY_DIRECTORY and its ucode.so RTLD_GLOBAL self-reopen path together',
        'usr/lib/rpcd/ucode.so': 'Compiled self-reopen path still targets canonical /usr/lib/rpcd/ucode.so',
        'usr/sbin/pppd': 'Rebuild with --with-plugin-dir=/usr/lib/be6l-arm32/pppd/2.5.4',
        'sbin/ujail': 'Review jail mounts/private loader and module paths for each retained child ABI',
    }
    contract = dict(runtime_package=NAME, runtime_version=version, runtime_arch=ARCH,
        exact_runtime_dependency=dependency, provides=[], generic_normal_abi_providers_forbidden=True,
        private_loader_path=path_file.read_text().strip(), canonical_interpreter='/'+INTERPRETER,
        immutable_dso_files=75, source_aliases=39, identical_alias_target_texts=37,
        rewritten_alias_target_texts=[INTERPRETER, 'usr/bin/ldd'],
        consumer_packages=policy, source_vm_and_plugin_rebuild_gates=blocked,
        bare_dlopen_resolution={'usr/sbin/uhttpd':'uhttpd_ubus.so is a bare dlopen name; private ARM32 loader path resolves its preserved private copy'},
        unselected_plugins_not_added=['uhttpd-mod-lua', 'uhttpd-mod-ucode'],
        ownership_transfer_required=True, source_roots_modified=False,
        vm_plugin_isolation_qualified=False, consumer_metadata_transaction_qualified=False,
        mainroot_composition_qualified=False, standard_a53_package_compatibility_qualified=False)
    (w/'relocation-manifest.json').write_text(json.dumps(basis, indent=2)+'\n')
    (w/'consumer-metadata-policy.json').write_text(json.dumps(contract, indent=2)+'\n')
    (w/'needed-closure.json').write_text(json.dumps(edges, indent=2)+'\n')
    notices = files/('usr/share/licenses/'+NAME)
    notices.mkdir(parents=True)
    notices.joinpath('SOURCE-MANIFEST.json').write_text(json.dumps(dict(
        source_composition_receipt_sha256=sha(receipt_path), source_root_records_sha256=baseline,
        source_inventory_receipt_sha256=sha(inventory_path), source_files_manifest=basis,
        scope='Unchanged previously selected ARM32 runtime files; source ownership/version provenance retained'), indent=2)+'\n')
    trust = w/'trust'
    trust.mkdir()
    key, public = w/'temporary-signing.key', trust/(NAME+'.pem')
    package = w/(NAME+'-'+version+'.apk')

    def run(label, command):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=180)
        (w/(label+'.log')).write_bytes(result.stdout+result.stderr)
        if result.returncode:
            raise RuntimeError(label+' failed; inspect private evidence')
        return result.stdout

    try:
        run('key-generate', ['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:2048','-out',key])
        key.chmod(0o600)
        run('key-public', ['openssl','pkey','-in',key,'-pubout','-out',public])
        command = [a.apk,'mkpkg','--sign-key',key,'--files',files,'--output',package]
        for field, value in dict(name=NAME, version=version, arch=ARCH,
                license='LicenseRef-BE6L-ARM32-Source-Manifest',
                description='Immutable private ARM32 compatibility DSO closure; no normal ABI providers').items():
            command += ['--info',field+':'+value]
        run('mkpkg',command)
        run('signature-verify',[a.apk,'--network=no','--keys-dir',trust,'verify',package])
        extracted = w/'verified'
        extracted.mkdir()
        run('signature-extract',[a.apk,'--network=no','--keys-dir',trust,'extract','--no-chown','--destination',extracted,package])
        if records(extracted) != records(files):
            raise ValueError('Signed/extracted runtime differs from the complete payload manifest')
        root = w/'verification-root'
        (root/'etc/apk').mkdir(parents=True)
        (root/'etc/apk/arch').write_text(ARCH+'\n')
        transaction=[a.apk,'--root',root,'--network=no','--cache=no',
                     '--repositories-file','/dev/null','--keys-dir',trust]
        run('normal-empty-root-install',transaction+['add','--scripts=no','--initdb',package])
        query = json.loads(run('query-runtime-metadata',transaction+[
            'query','--installed','--format','json','--fields','name,version,arch,depends,provides','*']))
        if (len(query) != 1 or query[0]['name'] != NAME or query[0]['version'] != version or
                query[0]['arch'] != ARCH or query[0].get('depends') or query[0].get('provides')):
            raise ValueError('Private package acquired an unexpected identity/dependency/provider')
        actual_records = records(root)
        if any(actual_records.get(name) != item for name,item in records(files).items()):
            raise ValueError('Normal APK transaction changed runtime payloads')
        installed_info, _ = installed(root)
        installed_paths = set(installed_info[NAME]['paths'])
        if installed_paths != set(records(files)):
            raise ValueError('Normal APK ownership differs from every runtime payload path')
    finally:
        key.unlink(missing_ok=True)
    unchanged = root_digest(base) == baseline
    report = dict(package=package.name, package_sha256=sha(package), name=NAME, version=version,
        arch=ARCH, provides=[], depends=[], normal_signed_runtime_package=True,
        normal_signature_verified=True, extracted_payload_exact=True,
        isolated_empty_root_transaction_passed=True, generic_abi_providers_absent=True,
        private_signing_key_removed=not key.exists(), source_root_unchanged=unchanged,
        source_root_records_sha256=baseline, source_composition_receipt_sha256=sha(receipt_path),
        source_inventory_receipt_sha256=sha(inventory_path),
        relocation_manifest_sha256=sha(w/'relocation-manifest.json'),
        consumer_policy_sha256=sha(w/'consumer-metadata-policy.json'),
        needed_closure_sha256=sha(w/'needed-closure.json'),
        payload_records_sha256=root_digest(files), immutable_source_dso_count=75,
        aliases_preserving_resolved_elf_count=39, alias_target_text_unchanged_count=37,
        actual_source_regular_elf_count=len(actual_source_elf),
        actual_source_arm32_elf_count=len(arm32), complete_source_arm32_scan_matches_inventory=True,
        source_arm32_elf_count=len(arm32), checked_needed_edges=len(edges),
        exact_runtime_dependency=dependency, canonical_interpreter='/'+INTERPRETER,
        loader_search_path=path_file.read_text().strip(),
        vm_plugin_isolation_qualified=False, consumer_metadata_rebuilt=False,
        mainroot_composition_qualified=False, target_executed=False,
        standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    if not unchanged:
        raise ValueError('Admitted source root changed during packaging')
    print('ARM32_PRIVATE_RUNTIME_SIGNED',version,'75_DSO_39_ALIASES',len(edges),'EDGES',flush=True)


if __name__ == '__main__':
    main()
