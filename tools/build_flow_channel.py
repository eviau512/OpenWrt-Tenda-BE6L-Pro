"""Build an isolated diagnostic NPU worker channel and matching controller."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

base = Path(__file__).resolve().parents[1]
root = Path('/root/be6l-openwrt')
src = root / 'arm64-source'
firmware = src / 'package/firmware/an7552-npu-firmware/src'
dest = root / 'flow-channel-firmware'; dest.mkdir(exist_ok=True)
for file in firmware.iterdir():
    if file.is_file(): shutil.copyfile(file, dest / file.name)
subprocess.run(['python3', str(base/'tools/generate_flow_abi_vectors.py')], check=True)
for folder in ['flow-abi', 'flow-lease', 'routed-frame']:
    for file in (base / 'experiments' / folder).glob('*.h'):
        shutil.copyfile(file, dest/file.name)
lease = dest/'flow-lease.h'
lease.write_text(lease.read_text().replace('../routed-frame/routed-frame.h', 'routed-frame.h'))
path = dest/'main.c'; text = path.read_text()
assert text.count('#include "tdma.c.inc"') == 1
text = text.replace('#include "tdma.c.inc"', '#include "flow-worker.h"\n#include "tdma.c.inc"', 1)
text = text.replace('\tup_init(core);', '\tfa_worker_boot(core);\n\tup_init(core);', 1)
text = text.replace('\t\tstate[1] = ++heartbeat;', '\t\tstate[1] = ++heartbeat;\n\t\tfa_service(core);', 1)
text = text.replace('\t\tif (read32(AN7552_NPU_BASE + AN7552_PARK_CONTROL)) {',
                    '\t\tif (read32(AN7552_NPU_BASE + AN7552_PARK_CONTROL)) {\n\t\t\tfa_worker_stop(core);', 1)
path.write_text(text)
env = dict(os.environ); env['PATH'] = str(root/'host/bin')+':'+env['PATH']
compiler = src/'staging_dir/hostpkg/riscv32-elf/bin/riscv32-unknown-elf-gcc'
log = base/'logs/flow-channel-build.txt'
with log.open('w') as output:
    subprocess.run(['make','-C',str(dest),'CROSS_COMPILE='+str(compiler)[:-3],
                    'SHELL='+str(root/'host/bin/bash'),'all'], env=env, stdout=output, stderr=subprocess.STDOUT, check=True)
module = root/'flow-channel-module'; module.mkdir(exist_ok=True)
for file in [base/'diagnostics/be6l_flow_channel.c', base/'experiments/flow-abi/flow-abi.h', base/'experiments/flow-abi/flow-actions.h']:
    shutil.copyfile(file,module/file.name)
(module/'Makefile').write_text('obj-m += be6l_flow_channel.o\n')
kernel = src/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
gcc, = src.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
with log.open('a') as output:
    subprocess.run(['make','-C',str(kernel),'M='+str(module),'ARCH=arm64',
                    'CROSS_COMPILE='+str(gcc)[:-3],'SHELL='+str(root/'host/bin/bash'),'modules'],
                   env=env,stdout=output,stderr=subprocess.STDOUT,check=True)
art=base/'artifacts/arm64-compat'
payload=(dest/'build/an7552.bin').read_bytes()
assert len(payload)<=0x10000 and int.from_bytes(payload[8:12],'little')==5
(art/'an7552-flow-channel.bin').write_bytes(payload)
shutil.copyfile(module/'be6l_flow_channel.ko',art/'be6l_flow_channel.ko')
report={'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload),'diagnostic_only':True,
        'synthetic_only':True,'native_firmware_abi':5,'software_channel_version':1,
        'nat_offload_qualified':False,'hardware_drain_proven':False,'actual_npu_channel_tested':False}
(art/'an7552-flow-channel.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
