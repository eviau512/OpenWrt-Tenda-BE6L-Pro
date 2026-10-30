# SPDX-License-Identifier: MIT
"""Derive a source-pinned normal N1 image pipeline; never contact hardware."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
from prepare_n1_identity_v2 import once

BASE = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--diagnostic-proof', type=Path, required=True)
parser.add_argument('--install-reviewed-patch', action='store_true')
parser.add_argument('--check-existing', action='store_true')
args = parser.parse_args()
proof = json.loads(args.diagnostic_proof.read_text())
assert proof['cases'] >= 58 and proof['complete_airoha_translation_units_and_link']
assert proof['can_publish'] is False and proof['context_bytes'] == 56
assert proof['userspace_arming_interface'] and not proof['automatic_unb_classification_change']
work = Path(proof['work'])
prepared = json.loads((work / 'preparation.json').read_text())
SDK = Path(prepared['sdk'])
K = SDK / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
patch = work / '977-n1-identity-and-inert-driver-taps.patch'
assert sha(patch) == proof['source_patch_sha256']
assert sha(work / 'tree/drivers/net/ethernet/airoha/airoha-eth.o') == proof['linked_driver_sha256']
original = BASE / 'tools/build_ppe_bridger_image_v1.py'
assert sha(original) == 'df2e5d9f69b6d8db2fe3732dd8a7c32795c587ec554d6f53ac4761fbcc58c7eb'
destination = BASE / 'tools/build_n1_diag_image_v2.py'
assert not destination.exists() or args.check_existing
text = original.read_text()
text = once(text, 'from ppe_module_abi import probe as abi_probe, module_record',
            'from ppe_module_abi_v2 import probe as abi_probe, module_record')
text = once(text, "assert (work / 'raw-apks').is_dir() and (KERNEL / 'vmlinux').is_file()",
            "assert (work / 'matching-apks').is_dir() and (KERNEL / 'vmlinux').is_file()")
text = once(text, "ARTIFACT = BASE / 'artifacts/arm64-ppe-bridger'", "ARTIFACT = BASE / 'artifacts/arm64-n1-diag-v2'")
text = once(text, "work.name.startswith('ppe-bridger-v1-')", "work.name.startswith('n1-image-v2-')")
text = text.replace('driver_version=1', 'driver_version=2').replace('V1_', 'N1_V2_')
text = once(text, 'args = parser.parse_args()', "parser.add_argument('--diagnostic-proof', type=Path, required=True)\nargs = parser.parse_args()")
needle = 'sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()'
text = once(text, needle, needle + '''
n1_proof = json.loads(args.diagnostic_proof.read_text())
assert n1_proof['cases'] >= 58 and n1_proof['complete_airoha_translation_units_and_link']
assert n1_proof['can_publish'] is False and n1_proof['context_bytes'] == 56
assert n1_proof['userspace_arming_interface'] and not n1_proof['automatic_unb_classification_change']
n1_patch = SDK / 'target/linux/airoha/patches-6.18/977-n1-identity-and-inert-driver-taps.patch'
assert sha(n1_patch) == n1_proof['source_patch_sha256']
''')
text = once(text, "    lines = [line for line in lines if not re.match(r'(?:# )?CONFIG_PACKAGE_wpad', line)]", """    lines = [line for line in lines if not re.match(r'(?:# )?CONFIG_PACKAGE_wpad', line)]
    lines = [line for line in lines if not re.match(r'(?:# )?CONFIG_TARGET_INITRAMFS_COMPRESSION_', line)]
    lines.append('CONFIG_TARGET_INITRAMFS_COMPRESSION_GZIP=y')""")
text = once(text, "    return raw, numeric", "    assert numeric['ct_context_version'] == 2 and numeric['ct_context_bytes'] == 56\n    return raw, numeric")
text = once(text, "    state.update(normal_native_apk_transaction=True, preserved_normal_native_ownership=True,", "    state.update(n1_diagnostic_only=True, diagnostic_default_enabled=False, can_publish=False,\n                 routed_bind_supported=False, normal_native_apk_transaction=True, preserved_normal_native_ownership=True,")
text = once(text, "env['PATH'] = str(WORKROOT / 'host/bin') + ':' + env['PATH']", "env['PATH'] = str(WORKROOT / 'host/bin') + ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'")
compile(text, str(destination), 'exec')
if args.check_existing:
    assert not args.install_reviewed_patch
    assert destination.read_text() == text
    print('N1_BUILDER_EXACT_DERIVATION_VERIFIED')
    raise SystemExit(0)
if args.install_reviewed_patch:
    assert all(sha(K / name) == digest for name, digest in prepared['source_files'].items())
    target = SDK / 'target/linux/airoha/patches-6.18' / patch.name
    assert not target.exists()
    target.write_bytes(patch.read_bytes())
destination.write_text(text)
(BASE / 'logs/n1-image-v2-derivation.json').write_text(json.dumps(dict(
    original_builder_sha256=sha(original), derived_builder_sha256=sha(destination),
    diagnostic_proof_sha256=sha(args.diagnostic_proof), patch_sha256=sha(patch),
    arm64_sdk_patch_installed=args.install_reviewed_patch, hardware_operation=False,
    known_images_overwritten=False, xz_retry=False), indent=2) + '\n')
print('N1_NORMAL_IMAGE_BUILDER_DERIVED', destination)
