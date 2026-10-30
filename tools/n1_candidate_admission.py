"""Admit only the matched, inert N1 v2 candidate; no hardware operations."""
import hashlib
import json
from pathlib import Path

IMAGE_SHA256 = '9a3955e73fcee9bccee1c8bbf88a56f6eacaf8fa37c71ff6516d1a22578f2855'
SOURCE_SHA256 = 'aec580fec8a85629ba433306a62091dd507c5f527410953cac9b2962cd1fc59a'
PAYLOAD_HASHES = {
    'Image': '526b8f6c309393003e6c54e483f4885d29d4cfb66f50f451c4d91a9efcf7dcef',
    'board.dtb': '372fdd4351a900cc8e9c5d87f500038f7ed6fc626da874510d63c86ef538cc67',
    'entry.bin': '8d9ca98a6b6d6710654c45f01d6f0acbb6af6391b09b22872ce5b720243969ae',
    'linux64-kexec-loader': '14b7fd6561bd4ffd677d8a3934f27b5257c6c3839be33c5b8c28a0fca7ad2bcb',
    'arm32-fallback': 'baba295f687c384de15fe080d0f3cbd6c6761327ad0b6a7542f88c8744de9917',
    'kexec': '77c7f3177a8455f787bf4972217388ed6ec48be971e19b43e4edab7b4beeb028',
    'ld-musl-arm.so.1': '195a3353cbbbb1b586e62aa1b6dd4a746eb774219636a5fb847a622fd548b8c9',
}


def admit_payload(artifact: Path, manifest):
    assert manifest['fit_sha256'] == IMAGE_SHA256
    assert {item['name']: item['sha256'] for item in manifest['files']} == PAYLOAD_HASHES
    assert len(manifest['files']) == len(PAYLOAD_HASHES)
    assert manifest['kernel_header']['effective_size'] == 64684032
    assert manifest['segments'] == [[0x80200000, 64684032], [0x86ee3000, 16384],
                                    [0x90000000, 34660352], [0x87f00000, 4096]]
    for item in manifest['files']:
        data = Path(item['path']).read_bytes()
        assert len(data) == item['size']
        assert hashlib.sha256(data).hexdigest() == PAYLOAD_HASHES[item['name']]
    return manifest


def admit(artifact: Path):
    artifact = artifact.resolve()
    assert artifact.name == 'arm64-n1-diag-v2'
    report = json.loads((artifact/'build-validation.json').read_text(encoding='utf-8'))
    assert report['image_sha256'] == IMAGE_SHA256
    assert hashlib.sha256((artifact/report['image']).read_bytes()).hexdigest() == IMAGE_SHA256
    assert report['n1_diagnostic_only'] is True
    for flag in ('can_publish', 'routed_bind_supported', 'diagnostic_default_enabled'):
        assert report[flag] is False, flag
    assert not report.get('runtime_failure'), 'Known failed runtime requires a new diagnostic plan'
    for flag in ('normal_native_apk_transaction', 'actual_package_manifest_verified',
                 'normal_kernel_module_package_transaction', 'standard_kernel_make',
                 'embedded_cpio_verified', 'default_loader_chroot_tested'):
        assert report[flag] is True, flag
    assert report['embedded_cpio_sha256'] == report['external_cpio_sha256']
    assert report['kernel_effective_bytes'] == 64684032
    assert report['kernel_headroom_bytes'] == 327680
    assert len(report['elf64_modules_verified']) == 84
    assert report['module_layout_audit']['passed'] is True
    lock = report['source_abi_build_lock']
    assert lock['source_lock_sha256'] == SOURCE_SHA256
    assert lock['clean_full_kernel_and_external_modules_rebuilt'] is True
    required = dict(schema=2, ct_context_version=2, ct_context_bytes=56,
                    context_generation_offset=16, context_ct_cookie_offset=24,
                    context_flow_cookie_offset=32, context_tuple_cookie_offset=40)
    for name in ('source_abi_numeric_layout', 'image_entry_abi', 'image_exit_abi'):
        for key, value in required.items():
            assert report[name][key] == value, (name, key)
    closure_path = artifact/'loader-closure-admission.json'
    assert hashlib.sha256(closure_path.read_bytes()).hexdigest() == report['loader_closure_admission_sha256']
    closure = json.loads(closure_path.read_text(encoding='utf-8'))
    assert closure['candidate_image_sha256'] == IMAGE_SHA256
    fixture = json.loads((artifact/'loader-test.json').read_text(encoding='utf-8'))
    assert closure['fixture_sha256'] == fixture['sha256']
    assert hashlib.sha256((artifact/'loader-test.tar').read_bytes()).hexdigest() == fixture['sha256']
    base = artifact.parents[1]
    evidence = (base/report['default_loader_evidence'].replace('\\', '/')).resolve()
    assert evidence.is_relative_to(base/'logs')
    output = (evidence/'result.txt').read_text(encoding='utf-8')
    for token in ('DEFAULT_NATIVE_PROCD_LOADER_PASS', 'CURL_DEFAULT_RC=0 EXPLICIT_RC=0',
                  'NATIVE_LUA_BINDINGS_LOADER_PASS', 'ARM32_PRELOAD_COMPAT_PASS',
                  'SOFT_APK_DEFAULT_LOADERS_PASS'):
        assert token in output, token
    return report
