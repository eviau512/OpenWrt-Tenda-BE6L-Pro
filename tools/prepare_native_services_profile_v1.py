# SPDX-License-Identifier: MIT
"""Pin and statically audit the existing native closure in a NEW preview profile."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import tarfile
from a64_soft_context import BASE, SDK, EPOCH
from soft_abi_admission import admit_profile
from native_services_admission_v1 import ARCH, BASE_LOCK, SHA, safe

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--base-root', type=Path, required=True)
p.add_argument('--plugin-rebuild', type=Path)
p.add_argument('--trusted-rebuild-receipt-sha256')
a = p.parse_args()
work = a.work.resolve(); baseline = a.base_root.resolve()
assert work.parent == Path('/root/be6l-openwrt') and work.name.startswith('native-services-profile-v1-')
assert not work.exists(); work.mkdir()
original = admit_profile(Path('/root/be6l-openwrt/soft-profile-v2'), BASE_LOCK)
merge_path = BASE / 'logs/soft-services-merge-preflight.json'
assert SHA(merge_path.read_bytes()) == '1d3ded067c87cf2352c77aaeb478bf7d5ec25f14cb2350f707eef964b1ec0f81'
merge = json.loads(merge_path.read_text())
assert merge['base_lock_sha256'] == BASE_LOCK and merge['new_elf_paths'] == 32
assert merge['provider_conflicts'] == 0 and merge['exact_dependency_providers_present']
payloads = {}; manifests = {}; origins = {}
for provider, folder, archive, manifest_hash, archive_hash in (
    ('netifd','a64-soft-netifd','netifd.tar','27521df76c5940f6e565e9d7918a40c57abd7bae401cd0d034c41137b9bf7e8c','73b8493011f6b5201b782a328ea96ff0db8759300d6fe55068c0547e8484aeb3'),
    ('lua-ui','a64-soft-lua-ui','luci.tar','3b230eecc7793a331e2e02362761ff187df1f88cbfd971af15b39b4906396eae','c77a85c3eeac135907152347289f6b5566da891ad8172bcbd5f939c9b895d3e7')):
    art = BASE / 'artifacts' / folder
    mf, package = art / 'manifest.json', art / archive
    assert SHA(mf.read_bytes()) == manifest_hash and SHA(package.read_bytes()) == archive_hash
    manifest = json.loads(mf.read_text()); manifests[provider] = manifest
    assert manifest['abi'] == 'AAPCS64-soft' and manifest['strong_symbols_closed']
    by_hash = {}
    with tarfile.open(package) as stream:
        assert {m.name for m in stream} == set(manifest['files'])
    with tarfile.open(package) as stream:
        for member in stream:
            assert member.isfile(); safe(member.name)
            data = stream.extractfile(member).read()
            assert SHA(data) == manifest['files'][member.name]['sha256']
            by_hash[SHA(data)] = data
    for name, item in merge['layout'].items():
        if item['provider'] == provider:
            assert not (baseline / name).exists()
            payloads[name] = by_hash[item['sha256']]
    origins[provider] = dict(manifest_sha256=manifest_hash, archive_sha256=archive_hash,
        prior_runtime_evidence=manifest.get('hardware_test_evidence'), source_hashes=manifest['source_hashes'])
for name, item in merge['layout'].items():
    if item['provider'] == 'frozen-base-profile':
        payloads[name] = (baseline / name).read_bytes()
    assert SHA(payloads[name]) == item['sha256']
assert len(payloads) == 90
rebuilt = None
if a.plugin_rebuild:
    rebuild = a.plugin_rebuild.resolve()
    receipt_file = rebuild/'build-receipt.json'
    assert SHA(receipt_file.read_bytes()) == a.trusted_rebuild_receipt_sha256
    rebuilt = json.loads(receipt_file.read_text())
    assert rebuilt['kind'] == 'native-service-private-plugin-paths-v1'
    assert rebuilt['embedded_vm_c_modules_private_only'] and rebuilt['embedded_vm_shared_text_search_paths_preserved']
    assert rebuilt['shared_text_rpcd_paths_unchanged'] and not rebuilt['install_or_sdk_modification_performed']
    assert rebuilt['builder_sha256'] == SHA((BASE/'tools/build_native_service_paths_v1.py').read_bytes())
    source_services = BASE/'artifacts/a64-soft-services/manifest.json'
    service_manifest = json.loads(source_services.read_text())
    for component, manifest in (('rpcd',manifests['lua-ui']),('uhttpd',service_manifest)):
        expected = manifest['source_hashes'][component]['files']
        actual = rebuilt['sources'][component]['original_source_files']
        assert all(actual.get(name) == digest for name,digest in expected.items()),component
    assert len(rebuilt['outputs']) == 9
    for name, item in rebuilt['outputs'].items():
        assert name in payloads and merge['layout'][name]['provider'] != 'frozen-base-profile'
        data = (rebuild/'payload'/safe(name)).read_bytes()
        assert SHA(data) == item['sha256'] and len(data) == item['bytes']
        payloads[name] = data
    origins['plugin-path-rebuild'] = dict(receipt_sha256=SHA(receipt_file.read_bytes()),
        uhttpd_source_manifest_sha256=SHA(source_services.read_bytes()),outputs=rebuilt['outputs'])
    (work/'source-rebuild-receipt.json').write_bytes(receipt_file.read_bytes())
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix = str(gcc)[:-3]
files = {}; symbols = {}; by_hash = {}
for name, data in sorted(payloads.items()):
    path = work / 'payload' / safe(name); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data); path.chmod(0o755)
    digest = SHA(data)
    if digest not in by_hash:
        dynamic = subprocess.check_output([prefix+'readelf','-dW',path],text=True)
        program = subprocess.check_output([prefix+'readelf','-lW',path],text=True)
        dis = subprocess.check_output([prefix+'objdump','-d',path],text=True)
        assert not re.search(r'\((?:RPATH|RUNPATH)\)',dynamic), name
        for line in dis.splitlines():
            if '\t' not in line: continue
            ins = line.split('\t',2)[-1]
            if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins): continue
            assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins),(name,ins)
        sym = subprocess.check_output([prefix+'readelf','--dyn-syms','--wide',path],text=True)
        exports = set(); undefined = set()
        for line in sym.splitlines():
            found = re.match(r'\s*\d+:\s+\S+\s+\d+\s+\S+\s+(GLOBAL|WEAK)\s+\S+\s+(\S+)\s+(\S+)',line)
            if not found: continue
            binding, section, symbol = found.groups(); symbol = symbol.split('@')[0]
            if section == 'UND':
                if binding == 'GLOBAL': undefined.add(symbol)
            else: exports.add(symbol)
        by_hash[digest] = dict(needed=re.findall(r'\(NEEDED\).*?\[(.*?)\]',dynamic),
            interpreter=re.findall(r'Requesting program interpreter: (.*?)\]',program),
            exports=exports, undefined=undefined)
    audit = by_hash[digest]
    assert audit['needed'] == merge['layout'][name]['needed']
    files[name] = dict(sha256=digest,bytes=len(data),mode=0o755,needed=audit['needed'],
        interpreter=audit['interpreter'],fp_simd_register_uses=0,rpath_runpath=False,
        provider=merge['layout'][name]['provider'])
    symbols[name] = audit
providers = {Path(name).name:name for name in files if name.startswith('lib/aarch64-soft/')}
def closure(name, seen=None):
    seen = set() if seen is None else seen
    if name in seen: return seen
    seen.add(name)
    for dep in files[name]['needed']:
        assert dep in providers,(name,dep)
        closure(providers[dep],seen)
    return seen
for name, item in files.items():
    scope = closure(name)
    for segment, host in (('/lib/lua/','lua'),('/lib/ucode/','ucode'),('/lib/rpcd/','rpcd'),('/lib/uhttpd/','uhttpd')):
        if segment in name: scope |= closure('opt/be6l-a64-soft/bin/'+host)
    exported = set().union(*(symbols[n]['exports'] for n in scope))
    item['unresolved_strong_symbols'] = sorted(symbols[name]['undefined'] - exported)
    item['symbol_scope'] = sorted(scope)
    assert not item['unresolved_strong_symbols'],(name,item['unresolved_strong_symbols'])

# Preserve complete license files plus source-header notices from cached sources.
source_dirs = {
 'netifd':'a64-soft-netifd-repro-long-v2/source-netifd',
 'libnl-tiny':'a64-soft-netifd-repro-long-v2/source-libnl-tiny',
 'iwinfo':'a64-soft-luci-repro-long-v2/source-iwinfo',
 'luci-core':'a64-soft-luci-repro-long-v2/source-luci-core',
 'lucihttp':'a64-soft-luci-repro-long-v2/source-lucihttp',
 'rpcd':'a64-soft-luci-repro-long-v2/source-rpcd',
 'rpcd-luci':'a64-soft-luci-repro-long-v2/source-rpcd-luci',
 'rpcd-rrdns':'a64-soft-luci-repro-long-v2/source-rpcd-rrdns',
 'uhttpd':'a64-soft-services-repro-long-v2/source-uhttpd',
 'ustream':'a64-soft-services-repro-long-v2/source-ustream',
 'ucode-html':'a64-soft-luci-web-reproduction-long-v2/source-html',
 'libmd':'a64-soft-ucode-modules-reproduction-long-v6/source-libmd',
 'ucode-extra':'a64-soft-ucode-modules-reproduction-long-v6/source-ucode-lib',
 'ucode-lua-bridge':'a64-soft-ucode-modules-reproduction-long-v6/source-lua-bridge',
 'luci-ip':'a64-soft-lua-ui-reproduction-long-v2/source-luci-ip',
 'luci-jsonc':'a64-soft-lua-ui-reproduction-long-v2/source-luci-jsonc',
 'luci-parser':'a64-soft-lua-ui-reproduction-long-v2/source-luci-parser',
 'libyaml':'a64-soft-lua-ui-reproduction-long-v2/source-libyaml',
 'lyaml':'a64-soft-lua-ui-reproduction-long-v2/source-lyaml'}
notices = {}; source_notice_inventory = {}
for component, relative in source_dirs.items():
    source = Path('/root/be6l-openwrt') / relative
    if rebuilt and component in ('rpcd','uhttpd'):
        source = a.plugin_rebuild/('source-'+component)
    assert source.is_dir(), component
    headers = []; full = {}
    for path in sorted(source.rglob('*')):
        rel = path.relative_to(source)
        if not path.is_file() or path.is_symlink() or any(n.startswith(('.git','CMakeFiles','.pkgdir','apk-','ipkg-')) for n in rel.parts): continue
        is_license = path.name.upper().startswith(('LICENSE','LICENCE','COPYING','COPYRIGHT'))
        if not is_license and path.suffix not in ('.c','.h'): continue
        data = path.read_bytes()
        if is_license:
            target = work / 'notices' / component / rel
            target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(data)
            full[rel.as_posix()] = SHA(data)
        elif data.lstrip().startswith(b'/*'):
            header = data.lstrip().split(b'*/',1)[0] + b'*/\n'
            if len(header) < 12000 and any(v in header.lower() for v in (b'copyright',b'license',b'permission to use')):
                headers.append(rel.as_posix()+'\n'+header.decode(errors='replace'))
    if headers:
        target = work / 'notices' / component / 'SOURCE-NOTICES.txt'
        target.parent.mkdir(parents=True,exist_ok=True); target.write_text('\n\n'.join(headers))
    assert full or headers,('No source licensing notice',component)
    source_notice_inventory[component] = dict(source=str(source),full_license_files=full,header_notices=len(headers))
for path in sorted((work/'notices').rglob('*')):
    if path.is_file(): notices[path.relative_to(work/'notices').as_posix()] = SHA(path.read_bytes())
bundle_receipt = BASE / 'logs/soft-bundle-soft-bundle-v2/result.json'
bundle = json.loads(bundle_receipt.read_text())
assert bundle['profile_lock_sha256'] == BASE_LOCK and bundle['passed']
profile = dict(schema=2,profile_kind='native-services-preview-v1',abi='AAPCS64-soft',architecture=ARCH,
    base_profile_lock_sha256=BASE_LOCK,base_bundle_receipt_sha256=SHA(bundle_receipt.read_bytes()),
    base_approved_packages=bundle['approved_packages'],base_versions=bundle['versions'],
    source_merge_receipt_sha256=SHA(merge_path.read_bytes()),origin_manifests=origins,
    compiler=original['compiler'],source_date_epoch=EPOCH,files=files,needed_providers=providers,
    new_paths=sorted(name for name,item in files.items() if item['provider']!='frozen-base-profile'),
    elf_paths=90,unique_payload_hashes=len(by_hash),notices=notices,source_notice_inventory=source_notice_inventory,
    static_host_scoped_symbols_closed=True,default_services_promoted=False,
    default_dynamic_plugin_admission=False,
    source_plugin_paths_corrected=bool(rebuilt),
    source_rebuild_receipt_sha256=a.trusted_rebuild_receipt_sha256,
    preparer_sha256=SHA(Path(__file__).read_bytes()),
    default_plugin_blockers=(['New path-fixed hashes require an actual exact-fixture runtime test',
      'Default service configuration and lifecycle promotion remain unqualified'] if rebuilt else
      ['rpcd hardcodes /usr/lib/rpcd while native plugins are in /opt/be6l-a64-soft/lib/rpcd',
       'uhttpd dlopen plugin directory is not in the frozen native loader path']),
    target_execution_performed=False,full_image_build_admitted=False,
    binary_redistribution_license_review_complete=False)
lock = (json.dumps(profile,sort_keys=True,indent=2)+'\n').encode()
(work/'profile-lock.json').write_bytes(lock)
print(json.dumps(dict(profile_root=str(work),profile_lock_sha256=SHA(lock),elf_paths=90,new_paths=32,
    unique_payload_hashes=len(by_hash),source_notice_components=len(source_dirs),native_services_promoted=False),indent=2))
