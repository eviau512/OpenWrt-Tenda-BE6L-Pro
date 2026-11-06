# SPDX-License-Identifier: MIT
"""Compile the standard A53 negative execution/lifetime probes, without running."""
from pathlib import Path
import argparse
import json
import subprocess
from package_native_netifd_v3 import sha
from plan_integer_binfmt_v1 import matches


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cross-compile', required=True)
    p.add_argument('--work', required=True, type=Path)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-exec-corners-'):
        p.error('Use a fresh /root/be6l-exec-corners-* directory')
    w.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[1]/'experiments/qemu-integer-host/standard-exec-corners.c'
    elf = w/'be6l-exec-corners'
    command = [a.cross_compile+'gcc', '-O2', '-mcpu=cortex-a53', '-Wall', '-Wextra', '-Werror',
               str(source), '-o', str(elf)]
    result = subprocess.run(command, capture_output=True)
    (w/'compile.log').write_bytes(result.stdout+result.stderr)
    if result.returncode or not matches(elf.read_bytes()[:64]):
        raise ValueError('Standard A53 probe compilation/admission failed')
    report = dict(source_sha256=sha(source), command=command, elf_sha256=sha(elf),
                  standard_a53_abi=True, expected_negative_cases=12, target_executed=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('STANDARD_A53_EXEC_CORNERS_BUILT', report['elf_sha256'], flush=True)


if __name__ == '__main__':
    main()
