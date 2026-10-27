"""Build a metadata-only diagnostic against the exact cached running kernel."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import time
BASE=Path(__file__).resolve().parents[1]
SDK=Path('/root/be6l-openwrt/arm64-source')
KERNEL=SDK/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
ROOT=Path('/root/be6l-openwrt')/time.strftime('rx-hash-observer-%Y%m%d-%H%M%S')
ROOT.mkdir()
source=BASE/'diagnostics/be6l_rx_hash_observer.c'
shutil.copyfile(source,ROOT/source.name)
(ROOT/'Makefile').write_text('obj-m += be6l_rx_hash_observer.o\n')
gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
env=dict(os.environ)
env['PATH']='/root/be6l-openwrt/host/bin:'+env['PATH']
env['STAGING_DIR']=str(SDK/'staging_dir')
log=BASE/'logs'/('rx-hash-observer-build-'+ROOT.name+'.txt')
config=hashlib.sha256((KERNEL/'.config').read_bytes()).hexdigest()
with log.open('wb') as out:
 subprocess.run(['make','-C',str(KERNEL),'M='+str(ROOT),'ARCH=arm64',
  'CROSS_COMPILE='+str(gcc)[:-3],'SHELL=/root/be6l-openwrt/host/bin/bash','modules'],
  env=env,stdout=out,stderr=subprocess.STDOUT,check=True)
assert hashlib.sha256((KERNEL/'.config').read_bytes()).hexdigest()==config
data=(ROOT/'be6l_rx_hash_observer.ko').read_bytes()
assert data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\xb7\0'
assert b'vermagic=6.18.55 ' in data
out=BASE/'artifacts/rx-hash-observer'
out.mkdir(exist_ok=True)
(out/'be6l_rx_hash_observer.ko').write_bytes(data)
report=dict(sha256=hashlib.sha256(data).hexdigest(),bytes=len(data),
 source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
 kernel_config_sha256=config,kernel=str(KERNEL),module=str(ROOT/'be6l_rx_hash_observer.ko'),
 hardware_access=False,packet_modifications=False,source_root=str(ROOT))
(out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)
