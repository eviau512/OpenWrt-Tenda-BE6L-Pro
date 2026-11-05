# SPDX-License-Identifier: MIT
"""Offline feasibility plan for standard A53 dispatch and private soft ABI tags.

Does not modify a root, mark standard packages, load a module, mount a filesystem
or register binfmt. The private marker is not a standard Arm ELF feature flag.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
from package_native_netifd_v3 import root_digest

ADMITTED_ROOT = 'c10de4749faeaf15a6985242e63c10bfa9b74bcdee754d1d8bf77a3a6f82457e'
PRIVATE_SOFT_EFLAGS = 0xbe6a0001


def rule_bytes():
    magic, mask = bytearray(52), bytearray(52)
    magic[:7] = b'\x7fELF\x02\x01\x01'
    mask[:7] = b'\xff'*7
    magic[16] = 2
    mask[16:20] = b'\xfe\xff\xff\xff'  # ET_EXEC or ET_DYN, EM_AARCH64.
    magic[18] = 183
    mask[48:52] = b'\xff'*4  # Standard AArch64 e_flags == 0.
    return bytes(magic), bytes(mask)


def matches(data):
    magic, mask = rule_bytes()
    return len(data) >= len(magic) and all((a & m) == b for a, b, m in zip(data, magic, mask))


def tag_private(data):
    if not matches(data):
        raise ValueError('Expected reviewed private host ELF with original e_flags=0')
    output = bytearray(data)
    struct.pack_into('<I', output, 48, PRIVATE_SOFT_EFLAGS)
    assert output[:48] == data[:48] and output[52:] == data[52:]
    return bytes(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--admitted-root', type=Path, required=True)
    parser.add_argument('--kernel-config', type=Path, required=True)
    parser.add_argument('--standard-guest', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    a = parser.parse_args()
    if root_digest(a.admitted_root) != ADMITTED_ROOT:
        raise ValueError('This plan only admits the sealed 2f82 private-soft root')
    if a.output.exists():
        raise ValueError('Use a fresh report file')
    native = {}
    for path in sorted(a.admitted_root.rglob('*')):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as incoming:
            header = incoming.read(64)
        if len(header) < 64 or header[:6] != b'\x7fELF\x02\x01' or header[18:20] != b'\xb7\0':
            continue
        if struct.unpack_from('<H', header, 16)[0] not in (2, 3):
            continue
        data = path.read_bytes()
        tagged = tag_private(data)
        if matches(tagged):
            raise ValueError('Private owner would recurse through the emulator')
        native[path.relative_to(a.admitted_root).as_posix()] = {
            'original_sha256': hashlib.sha256(data).hexdigest(),
            'planned_private_sha256': hashlib.sha256(tagged).hexdigest()}
    if len(native) != 61:
        raise ValueError('Unexpected private-native inventory')
    guests = {}
    for path in a.standard_guest:
        data = path.read_bytes()
        if not matches(data):
            raise ValueError('Standard guest does not match the planned dispatch: '+str(path))
        guests[path.name] = hashlib.sha256(data).hexdigest()
    sample = bytearray(a.standard_guest[0].read_bytes()[:64])
    for offset, value, size in [(4, 1, 1), (16, 1, 2), (18, 62, 2), (48, PRIVATE_SOFT_EFLAGS, 4)]:
        mutant = sample.copy()
        mutant[offset:offset+size] = value.to_bytes(size, 'little')
        if matches(mutant):
            raise ValueError('Dispatch accepted a wrong class/type/machine/private tag')
    magic, mask = rule_bytes()
    config = a.kernel_config.read_text()
    report = dict(admitted_root_sha256=ADMITTED_ROOT, private_marker=hex(PRIVATE_SOFT_EFLAGS),
        marker_is_standard_arm_elf_flag=False, standard_guests_modified=False,
        private_owners=native, unmarked_private_owners_would_match=len(native),
        planned_tagged_private_owners_would_match=0, standard_guests_matching=guests,
        negative_class_type_machine_marker_controls_passed=True,
        magic_hex=magic.hex(), mask_hex=mask.hex(), proposed_binfmt_flags='POF',
        current_kernel_binfmt_misc_disabled='# CONFIG_BINFMT_MISC is not set' in config,
        activation_admitted=False, files_modified=False, target_executed=False,
        required_gates=['new matching CONFIG_BINFMT_MISC kernel and all modules',
            'normal signed package providers mark every admitted private host ELF',
            'marked, immutable native emulator and matched standard guest runtime',
            'consistent CPU/cache defaults and runtime-root behavior',
            'complete inventory check before any registration',
            'execve/execveat, scripts, argv0, env, permissions, fd/unlink, credentials, signals tests',
            'firmware/CPIO/loader headroom and unattended recovery'],
        standard_a53_package_compatibility_qualified=False)
    a.output.write_text(json.dumps(report, indent=2)+'\n')
    print('OFFLINE_BINFMT_PLAN_PASSED; ACTIVATION_NOT_ADMITTED', len(native), len(guests))


if __name__ == '__main__':
    main()
