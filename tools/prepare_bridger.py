"""Prepare pinned bridge-offload build inputs; never deploy or build a kernel."""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess

PIN = '30b833ae5b8a6ba94149268c47a8493308a0ee04'
BRIDGER_PIN = 'de7e00a5a673fdda38d3326b624c45facc6245d2'
REQUIRED = ('bridger', 'libbpf', 'libubox', 'libubus', 'libudebug', 'libnl-tiny',
            'kmod-sched-core', 'kmod-sched-flower', 'kmod-sched-bpf',
            'kmod-sched-act-vlan')
SPARSE = ('package/network/services/bridger', 'package/kernel/bpf-headers',
          'package/libs/libbpf', 'package/libs/elfutils')
LLVM_TOOLS = ('clang', 'llc', 'llvm-dis', 'opt', 'llvm-strip')

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('source', type=Path, help='Existing pinned sparse checkout')
parser.add_argument('--apply', action='store_true', help='Update sparse inputs and .config only')
parser.add_argument('--llvm-root', type=Path, help='Host LLVM root containing bin/; avoid a source LLVM build')
parser.add_argument('--report', type=Path)
args = parser.parse_args()
src = args.source.resolve()

def git(*words):
    return subprocess.check_output(['git', '-C', str(src), *words], text=True).strip()

assert git('rev-parse', 'HEAD') == PIN, 'OpenWrt checkout must match the frozen revision'
assert git('config', '--get', 'core.sparseCheckout') == 'true', 'Use the existing sparse checkout'
if args.apply:
    subprocess.run(['git', '-C', str(src), 'sparse-checkout', 'add', *SPARSE], check=True)
recipe = src / SPARSE[0] / 'Makefile'
data = recipe.read_text()
assert 'PKG_SOURCE_VERSION:=' + BRIDGER_PIN in data
assert 'PKG_BUILD_DEPENDS:=bpf-headers' in data
assert '$(BPF_DEPENDS)' in data
for name in REQUIRED[1:]:
    assert '+' + name in data, name

llvm = args.llvm_root
if llvm is None:
    for candidate in (Path('/root/be6l-openwrt/host/llvm21-bpf-tools'),
                      Path('/usr/lib/llvm-21'), Path('/usr/lib/llvm-20'),
                      Path('/usr/lib/llvm-19'), Path('/usr/lib/llvm-18')):
        if all((candidate / 'bin' / name).is_file() for name in LLVM_TOOLS):
            llvm = candidate
            break
if llvm is None:
    missing = {str(candidate): [name for name in LLVM_TOOLS
               if not (candidate / 'bin' / name).is_file()]
               for candidate in (Path('/usr/lib/llvm-21'), Path('/usr/lib/llvm-20'),
                                  Path('/usr/lib/llvm-19'), Path('/usr/lib/llvm-18'))
               if (candidate / 'bin').is_dir()}
    report = dict(openwrt_commit=PIN, bridger_commit=BRIDGER_PIN,
                  host_bpf_tools_missing=missing, config_selection_applied=False,
                  kernel_not_built=True, deployed=False, hardware_qualified=False)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    parser.exit(2, 'Provide --llvm-root with all five host LLVM tools; no LLVM source build was started.\n')
llvm = llvm.resolve()
assert llvm.is_absolute() and not any(c.isspace() for c in str(llvm))
for name in LLVM_TOOLS:
    assert (llvm / 'bin' / name).is_file(), name
version = subprocess.check_output([str(llvm / 'bin/clang'), '--version'], text=True)
match = re.search(r'clang version (\d+)', version)
assert match and int(match.group(1)) >= 12
for name in LLVM_TOOLS[1:]:
    output = subprocess.check_output([str(llvm / 'bin' / name), '--version'], text=True)
    actual = re.search(r'LLVM version (\d+)', output)
    assert actual and actual.group(1) == match.group(1), 'Use one LLVM major version for all host tools'
probe = subprocess.run([str(llvm / 'bin/llc'), '--version'],
                       capture_output=True, text=True, check=True).stdout
assert re.search(r'^\s*bpfel\s+-', probe, re.M), 'Host LLVM lacks the little-endian eBPF backend'

config = src / '.config'
lines = config.read_text().splitlines()
keep = {'CONFIG_PACKAGE_wpad-mbedtls=y', 'CONFIG_TARGET_ROOTFS_INITRAMFS=y'}
assert keep <= set(lines), 'Preserve full wpad and RAM-only image policy'
symbols = {'CONFIG_PACKAGE_' + name: 'y' for name in REQUIRED}
symbols.update(CONFIG_BPF_TOOLCHAIN_HOST='y', CONFIG_BPF_TOOLCHAIN_NONE=None,
               CONFIG_BPF_TOOLCHAIN_BUILD_LLVM=None,
               CONFIG_BPF_TOOLCHAIN_HOST_PATH='"' + str(llvm) + '"')
if args.apply:
    def key(line):
        return line[2:].split(' ', 1)[0] if line.startswith('# CONFIG_') else line.split('=', 1)[0]
    lines = [line for line in lines if key(line) not in symbols]
    lines.extend(name + '=' + value if value is not None else '# ' + name + ' is not set'
                 for name, value in symbols.items())
    config.write_text('\n'.join(lines) + '\n')

report = dict(openwrt_commit=PIN, bridger_commit=BRIDGER_PIN,
              recipe_sha256=hashlib.sha256(recipe.read_bytes()).hexdigest(),
              sparse_directories=list(SPARSE), packages=list(REQUIRED),
              host_llvm_major=int(match.group(1)), host_bpf_backend_verified=True,
              config_selection_applied=args.apply, defconfig_not_run=True,
              kernel_not_built=True, deployed=False, hardware_qualified=False,
              purpose='L2 bridge acceleration; does not enable routed NAT')
if args.report:
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
