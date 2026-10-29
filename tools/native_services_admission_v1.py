# SPDX-License-Identifier: MIT
"""Independent content gate for the native services preview; no target I/O."""
from pathlib import Path
import hashlib
import json
import re

ARCH = 'aarch64_be6l_soft_experimental'
BASE_LOCK = '8ecb6b705abb2e003d032938d4332686e3f84233c448dee2658b8ecb035d5177'
SHA = lambda data: hashlib.sha256(data).hexdigest()

def safe(name):
    path = Path(name)
    assert not path.is_absolute() and '..' not in path.parts and str(path) not in ('', '.')
    return path

def admit(root, trusted_lock_sha256):
    assert re.fullmatch('[0-9a-f]{64}', trusted_lock_sha256)
    data = (root / 'profile-lock.json').read_bytes()
    assert SHA(data) == trusted_lock_sha256, 'Unreviewed services profile'
    p = json.loads(data)
    assert p['schema'] == 2 and p['profile_kind'] == 'native-services-preview-v1'
    assert p['architecture'] == ARCH and p['abi'] == 'AAPCS64-soft'
    assert p['base_profile_lock_sha256'] == BASE_LOCK
    assert len(p['files']) == 90 and len(p['new_paths']) == 32
    assert p['default_services_promoted'] is False
    assert p['default_dynamic_plugin_admission'] is False
    assert set(p['new_paths']) <= set(p['files'])
    merge_path = Path(__file__).resolve().parents[1]/'logs/soft-services-merge-preflight.json'
    assert SHA(merge_path.read_bytes()) == p['source_merge_receipt_sha256'] == '1d3ded067c87cf2352c77aaeb478bf7d5ec25f14cb2350f707eef964b1ec0f81'
    merge = json.loads(merge_path.read_text())['layout']
    assert set(p['files']) == set(merge)
    assert set(p['new_paths']) == {name for name,item in merge.items() if item['provider'] != 'frozen-base-profile'}
    rebuilt = {}
    if p.get('source_plugin_paths_corrected'):
        receipt = (root/'source-rebuild-receipt.json').read_bytes()
        assert SHA(receipt) == p['source_rebuild_receipt_sha256']
        rebuilt = json.loads(receipt)['outputs']
        assert len(rebuilt) == 9 and set(rebuilt) <= set(p['new_paths'])
    for name,item in p['files'].items():
        assert item['sha256'] == rebuilt.get(name,merge[name])['sha256']
    actual = {q.relative_to(root / 'payload').as_posix() for q in (root / 'payload').rglob('*') if q.is_file()}
    assert actual == set(p['files'])
    providers = p['needed_providers']
    for name, item in p['files'].items():
        path = root / 'payload' / safe(name)
        assert not path.is_symlink() and path.resolve().is_relative_to((root / 'payload').resolve())
        payload = path.read_bytes()
        assert SHA(payload) == item['sha256'] and len(payload) == item['bytes']
        assert payload[:6] == b'\x7fELF\x02\x01' and payload[18:20] == b'\xb7\0'
        assert item['fp_simd_register_uses'] == 0 and not item['rpath_runpath']
        assert item['mode'] == 0o755
        assert not item['interpreter'] or item['interpreter'] == ['/lib/ld-musl-aarch64-soft.so.1']
        assert all(dep in providers and providers[dep] in p['files'] and
            providers[dep].startswith('lib/aarch64-soft/') and Path(providers[dep]).name == dep for dep in item['needed'])
        assert not item['unresolved_strong_symbols'], (name, item['unresolved_strong_symbols'])
    for name, digest in p['notices'].items():
        path = root / 'notices' / safe(name)
        assert not path.is_symlink() and path.resolve().is_relative_to((root / 'notices').resolve())
        assert SHA(path.read_bytes()) == digest
    return p

def admit_installed(root, profile):
    for name, item in profile['files'].items():
        path = root / safe(name)
        assert path.resolve().is_relative_to(root.resolve())
        assert not path.is_symlink() and path.is_file()
        assert SHA(path.read_bytes()) == item['sha256'], name
        assert path.stat().st_mode & 0o7777 == item['mode'], name
    assert (root / 'lib/ld-musl-aarch64-soft.so.1').is_symlink()
    assert str((root / 'lib/ld-musl-aarch64-soft.so.1').readlink()) == 'aarch64-soft/libc.so'
    assert (root / 'etc/ld-musl-aarch64-soft.path').read_bytes() == b'/lib/aarch64-soft\n'
    assert SHA((root / 'usr/share/be6l-soft/profile-lock.json').read_bytes()) == BASE_LOCK
