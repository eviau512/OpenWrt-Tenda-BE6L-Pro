"""Reject weakened N1 admission receipts without modifying candidate files."""
from pathlib import Path
import copy
import json
from unittest.mock import patch
from n1_candidate_admission import admit

base = Path(__file__).resolve().parents[1]
artifact = base/'artifacts/arm64-n1-diag-v2'
text = (artifact/'build-validation.json').read_text(encoding='utf-8')
loads = json.loads
report = loads(text)
assert admit(artifact) == report
mutations = [
    (('image_sha256',), '0'*64),
    (('can_publish',), True),
    (('routed_bind_supported',), True),
    (('diagnostic_default_enabled',), True),
    (('n1_diagnostic_only',), False),
    (('runtime_failure',), True),
    (('default_loader_chroot_tested',), False),
    (('normal_kernel_module_package_transaction',), False),
    (('embedded_cpio_sha256',), '0'*64),
    (('kernel_headroom_bytes',), -1),
    (('source_abi_build_lock','source_lock_sha256'), '0'*64),
    (('source_abi_build_lock','clean_full_kernel_and_external_modules_rebuilt'), False),
    (('source_abi_numeric_layout','ct_context_bytes'), 16),
    (('image_entry_abi','ct_context_version'), 1),
    (('image_exit_abi','context_flow_cookie_offset'), 24),
    (('loader_closure_admission_sha256',), '0'*64),
    (('default_loader_evidence',), '../outside'),
]
for keys, value in mutations:
    changed = copy.deepcopy(report)
    parent = changed
    for key in keys[:-1]:
        parent = parent[key]
    parent[keys[-1]] = value
    def modified_loads(raw, *args, **kwargs):
        return changed if raw == text else loads(raw, *args, **kwargs)
    with patch('n1_candidate_admission.json.loads', side_effect=modified_loads):
        try:
            admit(artifact)
        except AssertionError:
            pass
        else:
            raise AssertionError('Admission accepted weakened receipt: '+'.'.join(keys))
print('N1_ADMISSION_BASELINE_AND_17_REJECTIONS_PASS_NO_HARDWARE')
