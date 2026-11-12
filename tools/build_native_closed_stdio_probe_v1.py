# SPDX-License-Identifier: MIT
"""Build native ARM32 and dynamic/synthetic-static A64 closed-stdio fixtures.

Offline only. The static A64 fixture is freestanding integer code, links no
static libc and makes no standard-static-package ABI claim. Dynamic startup
requires the separately verified normal A53 guest runtime.
"""
from pathlib import Path
import argparse
import json
import re
import struct
import subprocess
from package_native_netifd_v3 import sha
from plan_integer_binfmt_v1 import matches


def program_types(data, arm32=False):
    offset = struct.unpack_from('<I' if arm32 else '<Q', data, 28 if arm32 else 32)[0]
    stride, count = struct.unpack_from('<HH', data, 42 if arm32 else 54)
    if stride < (32 if arm32 else 56) or not count or offset+stride*count > len(data):
        raise ValueError('Malformed ELF program headers')
    return [struct.unpack_from('<I', data, offset+i*stride)[0] for i in range(count)]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cross-compile', required=True)
    p.add_argument('--aarch64-cross-compile', required=True)
    p.add_argument('--work', type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-native-closed-stdio-[a-z0-9-]+', w.name):
        p.error('Use a fresh /root/be6l-native-closed-stdio-* directory')
    w.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[1]/'experiments/qemu-integer-host'
    common = ['-O2', '-Wall', '-Wextra', '-Werror']
    specifications = {
        'native-closed-stdio': (a.cross_compile, common+['-static', '-march=armv7-a', '-marm',
            '-mfloat-abi=soft', '-fno-tree-vectorize'], source/'native-closed-stdio.c'),
        'be6l-closed-stdio-dynamic': (a.aarch64_cross_compile, common+['-mcpu=cortex-a53'], source/'closed-stdio-a64.c'),
        'be6l-closed-stdio-static-synthetic': (a.aarch64_cross_compile, common+['-mcpu=cortex-a53',
            '-DCLOSED_STDIO_FREESTANDING', '-mgeneral-regs-only', '-ffreestanding', '-fno-builtin',
            '-fno-stack-protector', '-fno-tree-loop-distribute-patterns', '-fno-pie', '-no-pie',
            '-nostdlib', '-static', '-Wl,-e,_start'], source/'closed-stdio-a64.c'),
    }
    commands, outputs = {}, {}
    for name, (prefix, flags, path) in specifications.items():
        command = [prefix+'gcc']+flags+[str(path), '-o', str(w/name)]
        built = subprocess.run(command, capture_output=True)
        (w/(name+'.compile.log')).write_bytes(built.stdout+built.stderr)
        if built.returncode:
            raise ValueError('Closed-stdio fixture compile failed: '+name)
        data = (w/name).read_bytes()
        native = name == 'native-closed-stdio'
        if native:
            if data[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<HH', data, 16) != (2, 40):
                raise ValueError('Native parent is not ARM32')
        elif not matches(data[:64]):
            raise ValueError('Guest fixture is not unmarked A64 ELF')
        types = program_types(data, native)
        if name != 'be6l-closed-stdio-dynamic' and (2 in types or 3 in types):
            raise ValueError('Static fixture has dynamic/interpreter program headers')
        if name == 'be6l-closed-stdio-dynamic' and types.count(3) != 1:
            raise ValueError('Dynamic fixture needs one normal A53 loader')
        if native:
            disassembly = subprocess.check_output([prefix+'objdump', '-d', str(w/name)], text=True)
            if re.search(r'^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v[a-z0-9.]+\s', disassembly, re.M):
                raise ValueError('Native parent emits VFP/NEON')
        commands[name] = command
        outputs[name] = dict(sha256=sha(w/name), size=len(data), program_types=types)
    report = dict(native_arm32=True, native_static=True, native_vfp_neon_instruction_count=0,
        commands=commands, files=outputs,
        source_sha256={name: sha(source/name) for name in
                       ['native-closed-stdio.c', 'closed-stdio-a64.c', 'closed-stdio-wire.h']},
        expected_case_count=16, close_masks=[1, 2, 4, 7], exec_modes=['execve', 'execveat-empty-cloexec'],
        report_pipe_min_fd=3, private_fd_alias_scan_limit=256,
        dynamic_fixture_requires_verified_standard_guest_runtime=True,
        static_fixture='synthetic freestanding A64 integer code, no libc/compiler runtime linked',
        static_standard_package_abi_qualified=False, isolated_fixture_only=True,
        existing_loader_bytes_unchanged=True, target_executed=False,
        secureexec_covered=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('NATIVE_CLOSED_STDIO_FIXTURES_BUILT', outputs['native-closed-stdio']['sha256'], flush=True)


if __name__ == '__main__':
    main()
