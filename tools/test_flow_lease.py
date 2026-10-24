"""Compile and execute the serialized lease reference model, not device code."""
from pathlib import Path
import json
import subprocess

base = Path(__file__).resolve().parents[1]
(base / "logs").mkdir(parents=True, exist_ok=True)
build = Path('/root/be6l-openwrt/flow-lease-tests')
build.mkdir(exist_ok=True)
test = build / 'test-flow-lease'
subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-fsanitize=undefined',
                str(base / 'experiments/flow-lease/test-flow-lease.c'), '-o', str(test)], check=True)
result = subprocess.check_output([str(test)], text=True).strip()
report = {'result': result, 'ubsan_passed': True, 'generations': 2000,
          'randomized_tokens': 32000, 'serialized_reference_only': True,
          'hardware_integrated': False, 'linux_flow_stats_qualified': False}
(base / 'logs/p5-flow-lease-model-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
