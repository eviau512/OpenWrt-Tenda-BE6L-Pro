# SPDX-License-Identifier: MIT
"""Bind a candidate's unchanged loader closure to the prior tested fixture.

Run in WSL after candidate composition/image audit. This performs no DUT call,
and deliberately leaves default_loader_chroot_tested false until its real test.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import stat
import subprocess
import tarfile
from a64_soft_context import BASE, SDK
from cpio_selected_files import selected_files

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--work', type=Path, required=True)
p.add_argument('--artifact-name', choices=('arm64-ppe-bridger','arm64-ppe-bridger-xz-v2','arm64-n1-diag-v2','arm64-n1-reasons-v3'), default='arm64-ppe-bridger')
a = p.parse_args()
work = a.work.resolve()
assert work.parent == Path('/root/be6l-openwrt')
prefix = {'arm64-ppe-bridger': 'ppe-bridger-v1-', 'arm64-ppe-bridger-xz-v2': 'ppe-bridger-xz-v2-',
          'arm64-n1-diag-v2': 'n1-image-v2-', 'arm64-n1-reasons-v3': 'n1-image-v3-'}[a.artifact_name]
assert work.name.startswith(prefix)
root = work / 'root'
composition = json.loads((work / 'composition.json').read_text())
assert Path(composition['root']) == root
assert composition['userspace_profile_unchanged']
sha = lambda x: hashlib.sha256(Path(x).read_bytes()).hexdigest()
old = BASE / 'artifacts/arm64-soft-apk'
new = BASE / 'artifacts' / a.artifact_name
prior = json.loads((old / 'build-validation.json').read_text())
candidate = json.loads((new / 'build-validation.json').read_text())
if a.artifact_name in ('arm64-n1-diag-v2','arm64-n1-reasons-v3'):
    assert candidate['n1_diagnostic_only'] and candidate['can_publish'] is False
    assert not candidate['diagnostic_default_enabled'] and not candidate['routed_bind_supported']
    assert candidate['source_abi_numeric_layout']['ct_context_version'] == 2
    assert candidate['source_abi_numeric_layout']['ct_context_bytes'] == 56
    if a.artifact_name == 'arm64-n1-reasons-v3':
        assert candidate['diagnostic_snapshot_version'] == 3
assert prior['default_loader_chroot_tested']
assert prior['normal_native_apk_transaction'] and prior['corrected_fma_libc']
assert candidate['module_layout_audit']['passed']
assert candidate['embedded_cpio_verified']
assert candidate['embedded_cpio_sha256'] == candidate['external_cpio_sha256']
assert candidate['image_sha256'] == sha(new / candidate['image'])
assert candidate['source_abi_build_lock']['clean_full_kernel_and_external_modules_rebuilt']
assert Path(candidate['root']) == root
assert candidate['actual_package_manifest_verified']
assert sha(work/'package-manifest.log') == composition['package_manifest_sha256'] == candidate['actual_package_manifest_sha256']
manifest = json.loads((work/'package-manifest.log').read_text())
packages = {item['name']: item for item in manifest}
assert len(manifest) == len(packages) == candidate['actual_packages'] and len(packages) >= 212
old_packages = {item['name']:item for item in json.loads((old/'packages.json').read_text())}
assert set(old_packages) <= set(packages)
for name, item in old_packages.items():
    if name == 'kernel' or name.startswith('kmod-'):
        continue
    assert all(packages[name][key] == item[key] for key in ('version','arch')), name
assert {'bridger','be6l-network-defaults'} <= set(packages)
assert all(name in ('bridger','be6l-network-defaults') or name.startswith('kmod-')
           for name in set(packages)-set(old_packages))
assert sha(work/'kernel-audit.json') == composition['kernel_audit_sha256']
cpio = work/'rootfs.cpio'
assert sha(cpio) == candidate['external_cpio_sha256']
assert cpio.stat().st_size == candidate['external_cpio_bytes']
bundle_receipt_path = BASE/'logs/soft-bundle-soft-bundle-v2/result.json'
assert sha(bundle_receipt_path) == prior['bundle_receipt_sha256']
bundle_receipt = json.loads(bundle_receipt_path.read_text())
assert all(bundle_receipt[k] for k in ('passed','normal_solver_signatures','pid1_owned_by_native_procd_package'))
assert bundle_receipt['profile_lock_sha256'] == prior['soft_profile_lock_sha256']
assert sha(root/'usr/share/be6l-soft/profile-lock.json') == prior['soft_profile_lock_sha256']
apk = [str(SDK/'staging_dir/host/bin/apk'), '--root', str(root), '--network=no', '--cache=no', '--repositories-file', '/dev/null']
ownership = {}
versions = bundle_receipt['versions']
for name, expected in {'/sbin/init':'procd-'+versions['procd'],
                       '/sbin/procd':'procd-'+versions['procd'],
                       '/lib/aarch64-soft/libc.so':'be6l-soft-runtime-'+versions['runtime']}.items():
    value = subprocess.check_output(apk+['info','--who-owns',name],text=True).strip()
    assert value.endswith(' is owned by '+expected), value
    ownership[name] = expected
for name in ('cls_bpf.ko', 'act_bpf.ko', 'act_vlan.ko'):
    assert 'lib/modules/6.18.55/' + name in candidate['elf64_modules_verified']
fixture = json.loads((old / 'loader-test.json').read_text())
assert fixture['sha256'] == sha(old / 'loader-test.tar')
files = {}
with tarfile.open(old/'loader-test.tar') as archive:
    selected = {m.name for m in archive if m.name != 'opt/be6l-curl-init-probe'}
embedded_files = selected_files(cpio.read_bytes(), selected)
with tarfile.open(old / 'loader-test.tar') as archive:
    for member in archive:
        name = member.name
        assert not Path(name).is_absolute() and '..' not in Path(name).parts
        if name == 'opt/be6l-curl-init-probe':
            assert member.isfile()
            continue  # Test-only, previously qualified probe; not an image file.
        actual = root / name
        embedded = embedded_files[name]
        assert stat.S_IMODE(embedded['mode']) == member.mode == stat.S_IMODE(actual.lstat().st_mode), name
        if member.issym():
            assert actual.is_symlink() and str(actual.readlink()) == member.linkname, name
            assert stat.S_ISLNK(embedded['mode']) and embedded['data'].decode() == member.linkname, name
            files[name] = {'symlink': member.linkname, 'mode': member.mode}
        else:
            assert member.isfile() and actual.is_file() and not actual.is_symlink(), name
            expected = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            assert sha(actual) == expected, name
            assert stat.S_ISREG(embedded['mode']) and hashlib.sha256(embedded['data']).hexdigest() == expected, name
            files[name] = {'sha256': expected, 'mode': member.mode}
for name in ('loader-test.tar', 'loader-test.json'):
    shutil.copyfile(old / name, new / name)
receipt = dict(candidate_image_sha256=candidate['image_sha256'],
    composition_sha256=sha(work / 'composition.json'), fixture_sha256=fixture['sha256'],
    exact_candidate_loader_files=files, probe_from_previous_qualified_fixture=True,
    prior_evidence=prior['default_loader_evidence'], hardware_test_executed=False,
    cpio_sha256=sha(cpio), current_native_package_ownership=ownership,
    source_bundle_receipt_sha256=sha(bundle_receipt_path))
(new / 'loader-closure-admission.json').write_text(json.dumps(receipt, indent=2) + '\n')
candidate.update(default_loader_chroot_tested=False,
    loader_admission_basis='Every candidate loader fixture file matched; actual candidate-tagged chroot test pending.',
    loader_closure_admission_sha256=sha(new / 'loader-closure-admission.json'),
    normal_native_apk_transaction=True, actual_package_manifest_verified=True,
    soft_profile_lock_sha256=prior['soft_profile_lock_sha256'],
    bundle_receipt_sha256=prior['bundle_receipt_sha256'])
(new / 'build-validation.json').write_text(json.dumps(candidate, indent=2) + '\n')
print('CANDIDATE_LOADER_INPUTS_BOUND_REAL_TEST_PENDING', len(files))
