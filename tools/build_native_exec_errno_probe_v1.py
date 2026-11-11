# SPDX-License-Identifier: MIT
"""Build a native static ARM32 caller for the standard-A64 exec error boundary.

Compile/admission only. On-target invocation requires the separately admitted
kernel/emulator POFX pair and an isolated standard guest root with proc mounted.
No target, flash or host-network operation is performed by this builder.
"""
from pathlib import Path
import argparse
import json
import re
import subprocess
from package_native_netifd_v3 import sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cross-compile', required=True)
    p.add_argument('--work', required=True, type=Path)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-native-exec-errno-'):
        p.error('Use a fresh /root/be6l-native-exec-errno-* directory')
    w.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[1]/'experiments/qemu-integer-host/native-a64-exec-errno.c'
    elf = w/'native-a64-exec-errno'
    command = [a.cross_compile+'gcc', '-static', '-O2', '-march=armv7-a', '-marm', '-mfloat-abi=soft',
               '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(elf)]
    r = subprocess.run(command, capture_output=True)
    (w/'compile.log').write_bytes(r.stdout+r.stderr)
    if r.returncode:
        raise ValueError('Native errno probe compilation failed')
    data = elf.read_bytes()
    if data[:6] != b'\x7fELF\x01\x01' or data[18:20] != b'\x28\0':
        raise ValueError('Wrong native caller architecture')
    disassembly = subprocess.check_output([a.cross_compile+'objdump', '-d', str(elf)], text=True)
    if re.search(r'^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v[a-z0-9.]+\s', disassembly, re.M):
        raise ValueError('Native errno caller has VFP/NEON instructions')
    report = dict(elf_sha256=sha(elf), source_sha256=sha(source), command=command,
        native_arm32=True, static=True, vfp_neon_instruction_count=0,
        expected_case_count=16, target_executed=False, isolated_fixture_only=True,
        existing_interpreters_unchanged=True,
        expected_errno_source='Linux6.18.55 fs/exec.c do_open_execat; fs/binfmt_elf.c load_elf_binary/elf_read/load_elf_phdrs',
        expected_cases={'missing-loader':'ENOENT','loader-no-execute':'EACCES','loader-bad-magic':'ELIBBAD',
            'loader-short-header':'EIO','loader-not-directory':'ENOTDIR','original-no-execute':'EACCES',
            'original-bad-phentsize':'ENOEXEC','success-control':0},
        complete_exec_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('NATIVE_A64_EXEC_ERRNO_PROBE_BUILT', report['elf_sha256'], flush=True)


if __name__ == '__main__':
    main()
