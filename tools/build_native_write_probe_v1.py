# SPDX-License-Identifier: MIT
"""Build a non-writing fixed-path ARM32 native interpreter write-access probe."""
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
    if w.parent != Path('/root') or not w.name.startswith('be6l-native-write-probe-'):
        p.error('Use a fresh /root/be6l-native-write-probe-* directory')
    w.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[1]/'experiments/qemu-integer-host/native-interpreter-write-probe.c'
    elf = w/'native-interpreter-write-probe'
    command = [a.cross_compile+'gcc', '-static', '-O2', '-march=armv7-a', '-mfloat-abi=soft',
               '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(elf)]
    r = subprocess.run(command, capture_output=True)
    (w/'compile.log').write_bytes(r.stdout+r.stderr)
    if r.returncode:
        raise ValueError('Native helper compilation failed')
    data = elf.read_bytes()
    if data[:6] != b'\x7fELF\x01\x01' or data[18:20] != b'\x28\0':
        raise ValueError('Wrong native helper architecture')
    disassembly = subprocess.check_output([a.cross_compile+'objdump', '-d', str(elf)], text=True)
    if re.search(r'^\s*[0-9a-f]+:\s+[0-9a-f ]+\s+v[a-z0-9.]+\s', disassembly, re.M):
        raise ValueError('Native helper has VFP/NEON instructions')
    report = dict(elf_sha256=sha(elf), source_sha256=sha(source), command=command,
                  native_arm32=True, static=True, vfp_neon_instruction_count=0,
                  no_truncate_or_write=True, target_executed=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('NATIVE_NON_WRITING_PROBE_BUILT', report['elf_sha256'], flush=True)


if __name__ == '__main__':
    main()
