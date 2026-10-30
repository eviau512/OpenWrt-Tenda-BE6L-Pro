"""Derive the counters-only normal image pipeline after actual compile tests."""
from pathlib import Path
import argparse
import hashlib
import json

b=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--diagnostic-proof',type=Path,required=True)
p.add_argument('--install-reviewed-patch',action='store_true')
p.add_argument('--check-existing',action='store_true')
a=p.parse_args()
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
proof=json.loads(a.diagnostic_proof.read_text(encoding='utf-8'))
assert proof['cases']>=58 and proof['counter_cases']==27
assert proof['complete_airoha_translation_units_and_link']
assert proof['sdk_image_config_modules_sources_unchanged']
assert proof['can_publish'] is False and proof['context_bytes']==56
assert proof['diagnostic_snapshot_version']==3 and proof['producer_context_version']==2
assert proof['diagnostic_counters_do_not_publish'] and proof['same_admission_and_record_checks']
work=Path(proof['work'])
prepared=json.loads((work/'preparation.json').read_text())
sdk=Path(prepared['sdk'])
k=sdk/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
patch=work/'978-n1-bounded-refusal-reasons.patch'
assert sha(patch)==proof['source_patch_sha256']
assert sha(work/'tree/drivers/net/ethernet/airoha/airoha-eth.o')==proof['linked_driver_sha256']
assert sha(work/'tree/drivers/net/ethernet/airoha/reasons.h')==proof['actual_counter_header_sha256']
source=b/'tools/build_n1_diag_image_v2.py'
assert sha(source)=='26e69888397d787cc0a28061aa02ffc61c56a648a82a14b3958ef25b199a5a7f'
text=source.read_text(encoding='utf-8')
def once(old,new):
 global text
 assert text.count(old)==1,old[:100]
 text=text.replace(old,new)
once("ARTIFACT = BASE / 'artifacts/arm64-n1-diag-v2'",
     "ARTIFACT = BASE / 'artifacts/arm64-n1-reasons-v3'")
once("work.name.startswith('n1-image-v2-')","work.name.startswith('n1-image-v3-')")
text=text.replace('driver_version=2','driver_version=3').replace('N1_V2_','N1_V3_')
once("n1_patch = SDK / 'target/linux/airoha/patches-6.18/977-n1-identity-and-inert-driver-taps.patch'",
     """assert n1_proof['diagnostic_snapshot_version'] == 3 and n1_proof['counter_cases'] == 27
assert sha(SDK / 'target/linux/airoha/patches-6.18/977-n1-identity-and-inert-driver-taps.patch') == 'da53aa1c8b49b7139e9a095e04c4df8307c73447398d6d5f9c18d769fff975fb'
n1_patch = SDK / 'target/linux/airoha/patches-6.18/978-n1-bounded-refusal-reasons.patch'""")
once('state.update(n1_diagnostic_only=True, diagnostic_default_enabled=False, can_publish=False,',
     'state.update(diagnostic_snapshot_version=3, n1_diagnostic_only=True, diagnostic_default_enabled=False, can_publish=False,')
destination=b/'tools/build_n1_reason_image_v3.py'
compile(text,str(destination),'exec')
if a.check_existing:
 assert not a.install_reviewed_patch
 assert destination.read_text(encoding='utf-8')==text
 print('N1_V3_NORMAL_BUILDER_EXACT_DERIVATION_VERIFIED')
 raise SystemExit(0)
assert not destination.exists()
if a.install_reviewed_patch:
 assert all(sha(k/name)==digest for name,digest in prepared['source_files'].items())
 target=sdk/'target/linux/airoha/patches-6.18'/patch.name
 assert not target.exists()
 target.write_bytes(patch.read_bytes())
destination.write_text(text,encoding='utf-8')
(b/'logs/n1-reason-image-v3-derivation.json').write_text(json.dumps(dict(
 original_builder_sha256=sha(source),derived_builder_sha256=sha(destination),
 diagnostic_proof_sha256=sha(a.diagnostic_proof),patch_sha256=sha(patch),
 arm64_sdk_patch_installed=a.install_reviewed_patch,hardware_operation=False,
 known_images_overwritten=False,xz_retry=False),indent=2)+'\n')
print('N1_V3_MATCHED_NORMAL_BUILDER_DERIVED',destination)
