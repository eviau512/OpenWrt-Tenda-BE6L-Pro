"""Build a typed bounded-learning lab fixture only; never deploy or run it."""
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
NAME = 'be6l_ppe_learn_probe'
ROOT = Path('/root/be6l-openwrt') / time.strftime('ppe-learn-probe-%Y%m%d-%H%M%S')
ROOT.mkdir()
OUT = BASE / 'logs' / ROOT.name
OUT.mkdir()
source = BASE / 'diagnostics' / (NAME + '.c')
text = source.read_text()
assert not re.search(r'\b(?:flow_rule|flow_cls_offload|kallsyms_lookup_name|ioremap|dma_alloc|dma_map|airoha_ppe_foe_get_entry)\b', text)
assert text.count('writel(') == 2
assert 'writel(config_active, eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0))' in text
assert 'writel(config_before, eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0))' in text
assert 'if (seconds < 1 || seconds > 5)' in text
assert 'static bool enable;' in text and 'static bool lab_exclusive;' in text
assert 'if (!lab_exclusive || !parents_empty(eth))' in text
assert text.index('device_lock(device);') < text.index('rtnl_lock();')
assert text.index('learning_window(platform_get_drvdata') < text.index('rtnl_unlock();')
assert 'struct flow_rule' not in text
assert 'static int preflight_failure(' in text and '#define REQUIRE_PREFLIGHT(' in text
assert 'preflight_passed = !err;' in text
assert 'if (err && enable)\n\t\treturn err;' in text
assert 'preflight_errno=%d last_stage=%s' in text
assert 'observed_ppe_count == 1' in text
assert 'bank_count = observed_ppe_count;' in text
assert text.count('i < bank_count') == 3
assert 'banks[1].' not in text and 'FLOW_CFG(1)' not in text
ppe = (K / 'drivers/net/ethernet/airoha/airoha_ppe.c').read_text()
assert re.search(r'if \(airoha_is_7563\(eth\) && addr_type\) \{[^}]+return -EOPNOTSUPP;', ppe)
assert 'PPE_PKT_TYPE_BRIDGE ||\n\t     !airoha_ppe_native_bridge_match' in ppe
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
ART = BASE / 'artifacts/ppe-learn-probe'
ART.mkdir(exist_ok=True)
if (ART / 'manifest.json').exists():
    shutil.copyfile(ART / 'manifest.json', OUT / 'previous-artifact-manifest.json')
shutil.copyfile(module, ART / module.name)
report = dict(module_sha256=hashlib.sha256(module.read_bytes()).hexdigest(),
              module_bytes=module.stat().st_size,
              source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
              kernel_config_sha256=config, module_struct_bytes=704,
              driver_headers={name: hashlib.sha256((K / 'drivers/net/ethernet/airoha' / name).read_bytes()).hexdigest()
                              for name in ('airoha_eth.h', 'airoha_regs.h')},
              uses_flow_rule_layout=False, uses_private_driver_functions=False,
              granular_readonly_stage_diagnostics=True,
              default_failed_preflight_preserved_in_readonly_report=True,
              active_rejection_preconditions_not_weakened=True,
              implemented_ppe_banks_only=True, required_soc_ppe_count=1,
              nonexistent_second_bank_not_accessed=True,
              cached_image_and_existing_module_bytes_unchanged=True,
              unchanged_cached_module_count=len(protected) - 1,
              default_read_only=True, explicit_enable_and_lab_exclusive_required=True,
              all_bank_no_BND_requires_external_existing_debugfs_preflight=True,
              private_flow_mutex_not_held=True, maximum_requested_seconds=5,
              restoration_in_synchronous_kernel_init=True,
              only_writable_register='REG_PPE_PPE_FLOW_CFG(0)', only_added_bits='0x3000',
              classifier_or_register_written_during_build=False, sram_commands=False,
              hardware_access=False, loaded_on_hardware=False, deployed=False,
              image_built=False, root=str(ROOT), log=str(OUT / 'compile.txt'))
(OUT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
(ART / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
(BASE / 'logs/ppe-learn-probe-latest.json').write_text(json.dumps(dict(directory=str(OUT))) + '\n')
print(json.dumps(report, indent=2), flush=True)
