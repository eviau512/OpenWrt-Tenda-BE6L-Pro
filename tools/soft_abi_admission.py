# SPDX-License-Identifier: MIT
"""Admission against an explicitly reviewed soft-ABI content/provenance lock.

This is a local repository staging gate, not a claim that APK inspects ELF ABI.
The caller must obtain the trusted lock digest independently of the candidate.
"""
from pathlib import Path
import hashlib
import json
import re


class AdmissionError(ValueError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, reason):
    if not condition:
        raise AdmissionError(reason)


def admit_profile(root, trusted_lock_sha256):
    require(re.fullmatch('[0-9a-f]{64}', trusted_lock_sha256) is not None, 'invalid trust anchor')
    lock = (root/'profile-lock.json').read_bytes()
    require(digest(lock) == trusted_lock_sha256, 'unreviewed profile/provenance lock')
    profile = json.loads(lock)
    require(profile['schema'] == 1 and profile['abi'] == 'AAPCS64-soft', 'wrong calling convention')
    require(profile['architecture'] == 'aarch64_be6l_soft_experimental', 'wrong namespace')
    actual = {p.relative_to(root/'payload').as_posix() for p in (root/'payload').rglob('*') if p.is_file()}
    require(actual == set(profile['files']), 'payload inventory mismatch')
    for name, info in profile['files'].items():
        path = root/'payload'/name
        require(not path.is_symlink() and path.resolve().is_relative_to((root/'payload').resolve()), 'unsafe payload path')
        data = path.read_bytes()
        require(digest(data) == info['sha256'] and len(data) == info['bytes'], 'unreviewed ELF provider: '+name)
        require(data[:6] == b'\x7fELF\x02\x01' and data[18:20] == b'\xb7\0', 'wrong ELF execution ABI: '+name)
        require(all(dep in profile['files'] for dep in info['needed']), 'missing native dependency: '+name)
        require(info['fp_simd_register_uses'] == 0, 'FP/SIMD audit absent: '+name)
        require(not info['interpreter'] or info['interpreter'] == ['/lib/ld-musl-aarch64-soft.so.1'], 'wrong loader: '+name)
    for folder, records in (('notices',profile['notices']),
                            ('compatibility',profile['original_procd_compatibility_files'])):
        for name, expected in records.items():
            p = root/folder/name
            require(not p.is_symlink() and p.resolve().is_relative_to((root/folder).resolve()), 'unsafe input path')
            require(digest(p.read_bytes()) == expected, 'unreviewed '+folder+' input: '+name)
    return profile


def file_records(root):
    records = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            records[name] = {'symlink':str(path.readlink())}
        elif path.is_file():
            records[name] = {'sha256':digest(path.read_bytes()), 'mode':path.stat().st_mode & 0o777}
    return records


def admit_extracted_payload(root, expected):
    require(file_records(root) == expected, 'package payload differs from reviewed recipe')
