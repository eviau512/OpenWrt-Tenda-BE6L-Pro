# SPDX-License-Identifier: MIT
"""Compile an ARM32 ptrace control for the retained standard-A64 loader inode.

Offline build only. Target use requires the matching V2 r2 kernel, aware r5
emulator, verified POFX rule and an isolated standard guest with proc mounted.
"""
from pathlib import Path
import argparse
import json
import re
import struct
import subprocess
from package_native_netifd_v3 import sha

SOURCE_PINS = {
    'fs/exec.c': 'bc0a790189b31dd0ead4b4c6ee20b0e4a609d6876f1f32c2408c38cf09e3fc53',
    'kernel/ptrace.c': 'fb526a024bcc0d5b20e2dd42bc8424b6525ec50c3bbfeaf48976ffd0bff71f15',
    'arch/arm64/kernel/ptrace.c': '92b065f91716747ca91abc12fff003111f396ee2ed54f8ec8fa5e08e63c0cf5e',
    'include/linux/ptrace.h': '1150f9a6c9e4dea3247183c16995f8ef4420cdfdb91bf3e4281cfc52e5f9c04c',
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cross-compile', required=True)
    p.add_argument('--work', required=True, type=Path)
    p.add_argument('--kernel-source', type=Path,
        default=Path('/root/be6l-fresh-kernel-20261105-r1/kernel-source/linux-6.18.55'))
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-native-loader-inode-[a-z0-9-]+', w.name):
        p.error('Use a fresh /root/be6l-native-loader-inode-* directory')
    for file, expected in SOURCE_PINS.items():
        if sha(a.kernel_source/file) != expected:
            raise ValueError('Reviewed Linux 6.18.55 ptrace source changed: '+file)
    table = (a.kernel_source/'arch/arm64/tools/syscall_32.tbl').read_text()
    if not re.search(r'^26\s+common\s+ptrace\s+sys_ptrace\s+compat_sys_ptrace$', table, re.M):
        raise ValueError('Reviewed ARM32 compat ptrace syscall mapping changed')
    w.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[1]/'experiments/qemu-integer-host/native-loader-inode.c'
    elf = w/'native-loader-inode'
    command = [a.cross_compile+'gcc', '-static', '-O2', '-march=armv7-a', '-marm', '-mfloat-abi=soft',
               '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(elf)]
    r = subprocess.run(command, capture_output=True)
    (w/'compile.log').write_bytes(r.stdout+r.stderr)
    if r.returncode:
        raise ValueError('Native loader-inode probe compilation failed')
    data = elf.read_bytes()
    if data[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<HH', data, 16) != (2, 40):
        raise ValueError('Wrong native ARM32 static caller ELF')
    offset = struct.unpack_from('<I', data, 28)[0]
    stride, count = struct.unpack_from('<HH', data, 42)
    if stride < 32 or not count or offset+stride*count > len(data) or any(
            struct.unpack_from('<I', data, offset+i*stride)[0] in (2, 3) for i in range(count)):
        raise ValueError('Native caller is not static')
    disassembly = subprocess.check_output([a.cross_compile+'objdump', '-d', str(elf)], text=True)
    if re.search(r'^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v[a-z0-9.]+\s', disassembly, re.M):
        raise ValueError('Native caller has VFP/NEON instructions')
    report = dict(elf_sha256=sha(elf), source_sha256=sha(source), command=command,
        native_arm32=True, static=True, vfp_neon_instruction_count=0, expected_case_count=4,
        cases=['execve-control', 'execve-rename-bad-path', 'execveat-cloexec-control', 'execveat-cloexec-rename-bad-path'],
        kernel_source_sha256=SOURCE_PINS,
        compat_syscall_table_sha256=sha(a.kernel_source/'arch/arm64/tools/syscall_32.tbl'),
        reviewed_event_boundary='exec_binprm after final search_binary_handler success, before return to user mode',
        reviewed_compat_controls='syscall26 compat_sys_ptrace -> compat_arch_ptrace -> compat_ptrace_request -> ptrace_request SETOPTIONS/CONT',
        expected_live_loader_write_errno='ETXTBSY', isolated_fixture_only=True,
        existing_interpreters_unchanged=True, parent_death_kills_child=True,
        ptrace_exec_event_target_verified=False, retained_loader_inode_target_verified=False,
        secureexec_covered=False, target_executed=False, complete_exec_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('NATIVE_LOADER_INODE_PROBE_BUILT', report['elf_sha256'], flush=True)


if __name__ == '__main__':
    main()
