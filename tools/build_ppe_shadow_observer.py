"""Build the host-shadow-only observer; no device or hardware access."""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from audit_module_layout import elf_sections

BASE = Path(__file__).resolve().parents[1]
SDK = Path('/root/be6l-openwrt/arm64-source')
K = SDK / 'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
NAME = 'be6l_ppe_shadow_observer'
ROOT = Path('/root/be6l-openwrt') / time.strftime('ppe-shadow-observer-%Y%m%d-%H%M%S')
ROOT.mkdir()
OUT = BASE / 'logs' / ROOT.name
OUT.mkdir()
source = BASE / 'diagnostics' / (NAME + '.c')
text = source.read_text()
assert not re.search(r'\b(?:readl|writel|ioremap|kallsyms_lookup_name|airoha_ppe_foe_get_entry|dma_alloc|dma_map|flow_rule|flow_cls_offload)\b', text)
assert '#define SHADOW_SLOTS 512' in text and '#define SHADOW_WORDS 20' in text
assert '#define MAX_RECORDS 16' in text and 'eth->soc->num_ppe != 1' in text
assert 'out[i] = READ_ONCE(in[i]);' in text
assert 'copy_entry(&first, source);\n\t\tsmp_rmb();\n\t\tcopy_entry(&second, source);' in text
assert 'source=HOST_SHADOW' in text and 'atomic_hardware_snapshot=0' in text
assert 'AIROHA_FOE_STATE_UNBIND' in text and 'PPE_PKT_TYPE_IPV4_HNAPT' in text
assert 'AIROHA_FOE_IB1_BIND_UDP' in text
assert not re.search(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text)
shutil.copyfile(source, ROOT / source.name)
(ROOT / 'Makefile').write_text(
    'obj-m += ' + NAME + '.o\nccflags-y += -I' + str(K / 'drivers/net/ethernet/airoha') + '\n')
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
config = hashlib.sha256((K / '.config').read_bytes()).hexdigest()
assert config == '60ecf68b251cc7193d7332a3d7b2eaff0b84423bf5bbb2ea77b2b4ea67b21078'
protected = [K / 'arch/arm64/boot/Image', *sorted(K.rglob('*.ko'))]
protected_before = {str(p.relative_to(K)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in protected}
env = dict(os.environ)
env.update(PATH='/root/be6l-openwrt/host/bin:' + env['PATH'],
           STAGING_DIR=str(SDK / 'staging_dir'))
with (OUT / 'compile.txt').open('wb') as log:
    subprocess.run(['make', '-C', str(K), 'M=' + str(ROOT), 'ARCH=arm64',
                    'CROSS_COMPILE=' + str(gcc)[:-3],
                    'SHELL=/root/be6l-openwrt/host/bin/bash', 'modules'],
                   env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
module = ROOT / (NAME + '.ko')
cls, machine, sections = elf_sections(module)
assert (cls, machine) == (2, 183)
assert sections['.be6l_module_layout'] == sections['.gnu.linkonce.this_module'] == 704
assert hashlib.sha256((K / '.config').read_bytes()).hexdigest() == config
assert {str(p.relative_to(K)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in protected} == protected_before
assert b'vermagic=6.18.55 ' in module.read_bytes()
ART = BASE / 'artifacts/ppe-shadow-observer'
ART.mkdir(exist_ok=True)
shutil.copyfile(module, ART / module.name)
report = dict(module_sha256=hashlib.sha256(module.read_bytes()).hexdigest(),
              module_bytes=module.stat().st_size,
              source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
              kernel_config_sha256=config, module_struct_bytes=704,
              driver_headers={name: hashlib.sha256((K / 'drivers/net/ethernet/airoha' / name).read_bytes()).hexdigest()
                              for name in ('airoha_eth.h', 'airoha_regs.h')},
              maximum_slots=512, words_per_entry=20, maximum_records=16,
              source='existing_host_shadow_only',
              double_read_best_effort=True, atomic_hardware_snapshot=False,
              own_endpoint_correlation_required_in_private_host_report=True,
              module_filters='UNB IPv4 HNAPT, UDP-bit clear, either TCP port5201/5202',
              driver_debugfs_refresh_performed_by_module=False,
              mmio_access=False, sram_commands=False, dma_ownership_changes=False,
              uses_flow_rule_layout=False, uses_private_driver_functions=False,
              cached_image_and_existing_module_bytes_unchanged=True,
              unchanged_cached_module_count=len(protected) - 1,
              hardware_access=False, loaded_on_hardware=False, deployed=False,
              image_built=False, root=str(ROOT), log=str(OUT / 'compile.txt'))
(OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
(ART / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
(BASE / 'logs/ppe-shadow-observer-latest.json').write_text(json.dumps(dict(directory=str(OUT))) + '\n')
print(json.dumps(report, indent=2), flush=True)
