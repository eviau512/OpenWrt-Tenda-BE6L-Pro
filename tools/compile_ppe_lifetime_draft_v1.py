# SPDX-License-Identifier: MIT
"""Replay two recorded kernel compile commands into a private draft directory.

Reads generated headers/configuration; does not invoke make, prepare the kernel,
link modules, modify the kernel build or admit the draft to a candidate.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shlex
import struct
import subprocess


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--kernel-build', type=Path, required=True)
    p.add_argument('--host-prefix', type=Path, required=True)
    a = p.parse_args()
    work = a.work.resolve()
    prep = json.loads((work/'preparation.json').read_text())
    private = Path(prep['source'])
    if work.parent != Path('/root') or not work.name.startswith('be6l-ppe-lifetime-port-20261111-'):
        p.error('Only a prepared private draft is supported')
    out = work/'objects'
    out.mkdir(mode=0o700)
    env = dict(os.environ, LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    results = []
    for name in ('airoha_ppe','airoha_eth'):
        saved = a.kernel_build/f'drivers/net/ethernet/airoha/.{name}.o.cmd'
        line = saved.read_text().splitlines()[0]
        command = shlex.split(line.split(':=',1)[1].replace('\\"','"'))
        oldsrc = Path(command[-1])
        source = private/f'{name}.c'
        command[-1] = str(source)
        command[command.index('-o')+1] = str(out/f'{name}.o')
        command = [('-I'+str(private)) if arg=='-I'+str(oldsrc.parent) else
            '-Wp,-MMD,'+str(out/f'.{name}.o.d') if arg.startswith('-Wp,-MMD,') else arg
            for arg in command]
        (out/f'{name}.command.json').write_text(json.dumps(command,indent=2)+'\n')
        result = subprocess.run(command,cwd=a.kernel_build,env=env,capture_output=True,timeout=120)
        (out/f'{name}.log').write_bytes(result.stdout+result.stderr)
        if result.returncode:
            raise RuntimeError(f'{name} C compilation failed; see private objects/{name}.log')
        raw = (out/f'{name}.o').read_bytes()
        if raw[:5] != b'\x7fELF\x02' or struct.unpack_from('<H',raw,18)[0] != 183:
            raise ValueError('Expected ARM64 ELF64 object')
        results.append(dict(source=str(source),object_sha256=hashlib.sha256(raw).hexdigest(),
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),elf64_aarch64=True))
    report = dict(arm64_objects_compile_passed=True,objects=results,
        complete_kernel_or_modules_linked=False,driver_abi_qualified=False,
        hardware_withdrawal_qualified=False,native_binding_admitted=False,target_executed=False)
    (work/'object-compile.json').write_text(json.dumps(report,indent=2)+'\n')
    print('PPE_DRAFT_ARM64_OBJECTS_COMPILED',json.dumps(report),flush=True)


if __name__=='__main__':
    main()
