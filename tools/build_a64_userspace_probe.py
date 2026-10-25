# SPDX-License-Identifier: MIT
"""Build isolated integer-only EL0 diagnostics using the existing sparse SDK."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import subprocess

base = Path(__file__).resolve().parents[1]
(base/'artifacts').mkdir(exist_ok=True)
(base/'logs').mkdir(exist_ok=True)
sdk = Path('/root/be6l-openwrt/arm64-source')
gcc, = sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix = str(gcc)[:-3]
out = base/'artifacts/a64-userspace-probe'
out.mkdir(exist_ok=True)
flags = ['-O2', '-Wall', '-Wextra', '-Werror', '-ffreestanding', '-fno-builtin',
         '-fno-stack-protector', '-mgeneral-regs-only', '-fno-tree-vectorize',
         '-nostdlib', '-static', '-Wl,--build-id=none', '-Wl,-e,_start']
subprocess.run([str(gcc), *flags, str(base/'diagnostics/a64_userspace_probe.c'),
                '-o', str(out/'probe')], check=True)
dis = subprocess.check_output([prefix+'objdump', '-d', str(out/'probe')], text=True)
(out/'probe.dis').write_text(dis)
instructions='\n'.join(line.split('\t',2)[-1] for line in dis.splitlines() if '\t' in line)
assert not re.search(r'\b[vqds][0-9]+\b', instructions), 'Unexpected FP/SIMD register'
for name, body in {
    'integer-positive': 'mov x0, #42\nmov x8, #94\nsvc #0',
    'simd-negative': 'movi v0.16b, #0\nmov x0, #0\nmov x8, #94\nsvc #0',
}.items():
    source = out/(name+'.S')
    source.write_text('.global _start\n.text\n_start:\n'+body+'\n')
    subprocess.run([str(gcc), *flags, str(source), '-o', str(out/name)], check=True)
    (out/(name+'.dis')).write_text(subprocess.check_output(
        [prefix+'objdump','-d',str(out/name)],text=True))
root = sdk/'staging_dir/target-aarch64_cortex-a53_musl/root-airoha'
for name, relative in [('native-libc.so','lib/libc.so'), ('native-busybox','bin/busybox')]:
    data=(root/relative).read_bytes()
    assert data[:5] == b'\x7fELF\x02' and data[18:20] == b'\xb7\x00'
    shutil.copyfile(root/relative,out/name)
    subprocess.run([prefix+'strip','--strip-debug',str(out/name)],check=True)
manifest={}
for name in ('probe','integer-positive','simd-negative','native-libc.so','native-busybox'):
    data=(out/name).read_bytes()
    manifest[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
