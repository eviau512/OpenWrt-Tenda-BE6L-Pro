# SPDX-License-Identifier: MIT
"""Strict one-delta admission chained to the frozen native services v1 profile."""
from pathlib import Path
import argparse
import copy
import json
import shutil

from native_services_admission_v1 import ARCH, BASE_LOCK, SHA, safe, admit as admit_v1, admit_installed

ORIGINAL = Path('/root/be6l-openwrt/native-services-profile-v1-20261029-r2')
ORIGINAL_SHA256 = 'c8b1a5461d60b0e09976286ce1e6efbf36dc2f32f01783425e1edd4a5a2c34f3'
CHILD = Path('/root/be6l-openwrt/native-lua-child-paths-v1-20261029-r1')
CHILD_RECEIPT_SHA256 = 'f91f12dd17456d02539fdd7b583d87602e162bf3252e6d50ca87d19f1749c518'
CHILD_SHA256 = 'f6d565cfb5ce710ddf1aa1aab62ba4c95b0ac2db15bda2f9a1ceded16ac86236'
CHILD_PATH = 'opt/be6l-a64-soft/lib/ucode/lua.so'


def expected_profile():
    previous = admit_v1(ORIGINAL, ORIGINAL_SHA256)
    receipt = (CHILD / 'build-receipt.json').read_bytes()
    assert SHA(receipt) == CHILD_RECEIPT_SHA256
    rebuilt = json.loads(receipt)
    assert rebuilt['output_sha256'] == CHILD_SHA256
    assert rebuilt['output_path'] == CHILD_PATH and rebuilt['abi'] == 'AAPCS64-soft'
    assert rebuilt['fp_simd_register_uses'] == 0 and not rebuilt['rpath_runpath']
    assert rebuilt['original_source_sha256'] == '5f7860ce545221858581e6c1795708e29aa4522d9152578351b2bcd2a9af1cfb'
    assert rebuilt['text_package_path_unchanged']
    item = previous['files'][CHILD_PATH]
    assert item['needed'] == rebuilt['needed'] and item['interpreter'] == []
    assert SHA((CHILD / 'lua.so').read_bytes()) == CHILD_SHA256
    assert len((CHILD / 'lua.so').read_bytes()) == rebuilt['output_bytes']
    changed = copy.deepcopy(previous)
    changed.update(schema=3, profile_kind='native-services-preview-v2',
        previous_native_services_profile_sha256=ORIGINAL_SHA256,
        child_rebuild_receipt_sha256=CHILD_RECEIPT_SHA256,
        admitted_payload_delta=[CHILD_PATH],
        child_vm_cpath_private=True, child_vm_text_path_unchanged=True,
        corrected_package_exact_fixture_tested=False)
    changed['files'][CHILD_PATH].update(sha256=CHILD_SHA256, bytes=rebuilt['output_bytes'])
    changed['unique_payload_hashes'] = len({item['sha256'] for item in changed['files'].values()})
    assert changed['files'][CHILD_PATH]['unresolved_strong_symbols'] == []
    return changed


def admit(root, trusted_lock_sha256):
    root = root.resolve()
    assert SHA((root / 'profile-lock.json').read_bytes()) == trusted_lock_sha256
    actual = json.loads((root / 'profile-lock.json').read_text())
    expected = expected_profile()
    assert actual == expected, 'Only the reviewed one-file child-VM delta is admitted'
    assert SHA((root / 'child-rebuild-receipt.json').read_bytes()) == CHILD_RECEIPT_SHA256
    assert (root / 'source-rebuild-receipt.json').read_bytes() == (ORIGINAL / 'source-rebuild-receipt.json').read_bytes()
    actual_payloads = {p.relative_to(root / 'payload').as_posix() for p in (root / 'payload').rglob('*') if p.is_file()}
    assert actual_payloads == set(expected['files'])
    for name, item in expected['files'].items():
        path = root / 'payload' / safe(name)
        assert path.resolve().is_relative_to((root / 'payload').resolve()) and not path.is_symlink()
        assert SHA(path.read_bytes()) == item['sha256'] and len(path.read_bytes()) == item['bytes']
        assert path.stat().st_mode & 0o7777 == item['mode'] == 0o755
        if name != CHILD_PATH:
            assert path.read_bytes() == (ORIGINAL / 'payload' / name).read_bytes()
    notices = {p.relative_to(root / 'notices').as_posix() for p in (root / 'notices').rglob('*') if p.is_file()}
    assert notices == set(expected['notices'])
    for name, digest in expected['notices'].items():
        path = root / 'notices' / safe(name)
        assert path.resolve().is_relative_to((root / 'notices').resolve()) and not path.is_symlink()
        assert SHA(path.read_bytes()) == digest
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare', type=Path, required=True)
    args = parser.parse_args()
    work = args.prepare.resolve()
    assert work.parent == Path('/root/be6l-openwrt') and work.name.startswith('native-services-profile-v2-')
    assert not work.exists()
    expected = expected_profile()
    shutil.copytree(ORIGINAL, work, symlinks=False)
    shutil.copyfile(CHILD / 'lua.so', work / 'payload' / CHILD_PATH)
    (work / 'payload' / CHILD_PATH).chmod(0o755)
    shutil.copyfile(CHILD / 'build-receipt.json', work / 'child-rebuild-receipt.json')
    (work / 'profile-lock.json').write_text(json.dumps(expected, sort_keys=True, indent=2) + '\n')
    lock = SHA((work / 'profile-lock.json').read_bytes())
    admit(work, lock)
    print(json.dumps(dict(profile_root=str(work), profile_lock_sha256=lock,
        exactly_one_payload_delta=CHILD_PATH, native_paths=90, base_58_unchanged=True,
        original_profile_unchanged=True, default_services_promoted=False), indent=2))


if __name__ == '__main__':
    main()

