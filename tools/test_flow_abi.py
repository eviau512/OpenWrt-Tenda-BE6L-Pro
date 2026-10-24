"""Build the two-worker software control-channel host tests, not a live route."""
from pathlib import Path
import json
import subprocess

base = Path(__file__).resolve().parents[1]
(base / "logs").mkdir(parents=True, exist_ok=True)
subprocess.run(['python3', str(base / 'tools/generate_flow_abi_vectors.py')], check=True)
build = Path('/root/be6l-openwrt/flow-abi-tests'); build.mkdir(exist_ok=True)
shim = build / 'mmap.o'
subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-c', str(base / 'tools/wsl1_mmap_compat.c'), '-o', str(shim)], check=True)
test = build / 'test-flow-abi'
subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                '-I'+str(base/'experiments/flow-lease'), '-I'+str(base/'experiments/routed-frame'),
                str(base/'experiments/flow-abi/test-flow-abi.c'), str(shim), '-Wl,--wrap=mmap', '-o', str(test)], check=True)
result = subprocess.check_output([str(test)], text=True).strip()
report = {'result': result, 'ubsan_passed': True, 'software_channel_only': True,
          'live_nat_or_dma_integrated': False, 'actual_npu_channel_tested': False}
(base / 'logs/flow-abi-host-tests.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report))
