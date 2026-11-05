# SPDX-License-Identifier: MIT
"""Read-only startup checks for a matched ARM64 RAM candidate, plus one heartbeat.

Proves kernel build ID, installed modules/packages and native default processes.
This is startup acceptance, not routed offload, long-duration or recovery testing.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess
import time
import urllib.error
import urllib.request
from package_native_netifd_v3 import root_digest, sha
from recovery.ssh_heartbeat import target


def build_ids(notes):
    result, pos = [], 0
    while pos + 12 <= len(notes):
        namesize, descsize, kind = struct.unpack_from('<III', notes, pos)
        pos += 12
        name = notes[pos:pos + namesize]
        pos = (pos + namesize + 3) & ~3
        desc = notes[pos:pos + descsize]
        pos = (pos + descsize + 3) & ~3
        if len(name) != namesize or len(desc) != descsize:
            raise ValueError('Truncated kernel note')
        if kind == 3 and name.rstrip(b'\0') == b'GNU':
            result.append(desc.hex())
    return result


def elf_build_ids(path):
    data = path.read_bytes()
    if data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\xb7\0':
        raise ValueError('Wrong kernel ELF')
    start = struct.unpack_from('<Q', data, 40)[0]
    stride, count = struct.unpack_from('<HH', data, 58)
    result = []
    for i in range(count):
        section = struct.unpack_from('<IIQQQQIIQQ', data, start + i * stride)
        if section[1] == 7:
            result += build_ids(data[section[4]:section[4] + section[5]])
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'composition', 'kernel', 'host-apk', 'identity', 'known-hosts', 'work'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--host', type=target, required=True)
    a = p.parse_args()
    work = a.work.resolve()
    if work.parent != Path('/root') or not re.fullmatch('be6l-candidate-qualification-[a-z0-9-]+', work.name):
        p.error('Use a fresh /root/be6l-candidate-qualification-* directory')
    report = json.loads((a.candidate / 'result.json').read_text())
    root = a.composition / 'root'
    if root_digest(root) != report['root_records_sha256'] or sha(a.kernel / 'vmlinux') != report['vmlinux_sha256']:
        raise ValueError('Sealed source changed')
    expected_ids = elf_build_ids(a.kernel / 'vmlinux')
    if len(expected_ids) != 1:
        raise ValueError('Need a unique expected kernel build ID')
    work.mkdir(mode=0o700)
    ssh = ['ssh', '-i', str(a.identity), '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'UserKnownHostsFile=' + str(a.known_hosts), '-o', 'ConnectTimeout=5',
           '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1', 'root@' + a.host]

    def run(label, command, binary=False):
        result = subprocess.run(ssh + [command], capture_output=True, timeout=90)
        (work / (label + ('.bin' if binary else '.log'))).write_bytes(result.stdout)
        (work / (label + '.stderr')).write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(label + ' failed; inspect private evidence')
        return result.stdout if binary else result.stdout.decode()

    state = run('identity', 'uname -r; uname -m; cat /proc/sys/kernel/random/boot_id; '
        r'head -n1 /proc/mounts; tr "\000" "\n" </proc/device-tree/compatible; '
        'cat /sys/class/mtd/mtd[0-9]/flags; md5sum /dev/mtd0 /dev/mtd1 /dev/mtd2; '
        'grep "^processor" /proc/cpuinfo; readlink /proc/1/exe')
    for pattern in ('^6\\.18\\.55$', '^aarch64$', '^tmpfs / tmpfs ', '^tenda,be6l-pro$', '^/sbin/procd$'):
        if not re.search(pattern, state, re.M):
            raise ValueError('Wrong runtime identity')
    boot = re.search(r'^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$', state, re.M).group()
    if len(re.findall('^0x0$', state, re.M)) != 10 or len(re.findall('^processor', state, re.M)) != 2:
        raise ValueError('CPU count or MTD guards differ')
    for digest, name in (('e831fc5dff58c75da64274f206df5edd', 'mtd0'),
                         ('a910eba27223f8563811168179eb4f04', 'mtd1'),
                         ('124dfc2a6d507d20aa34f8b4eb968e02', 'mtd2')):
        if digest + '  /dev/' + name not in state:
            raise ValueError('Critical partition changed')
    actual_ids = build_ids(run('kernel-notes', 'cat /sys/kernel/notes', True))
    if actual_ids != expected_ids:
        raise ValueError('Running kernel is not the admitted build')
    heartbeat = run('heartbeat', '/usr/sbin/be6l-recovery-guard heartbeat')
    if not heartbeat.startswith('BE6L_HEARTBEAT ' + boot + ' '):
        raise ValueError('No authenticated recovery heartbeat')
    query = ['query', '--installed', '--format', 'json', '--fields', 'name,version,arch', '*']
    expected_packages = json.loads(subprocess.check_output([str(a.host_apk), '--root', str(root),
        '--network=no', '--cache=no', '--logfile=no', '--repositories-file', '/dev/null'] + query))
    installed = json.loads(run('packages', 'apk --network=no --cache=no --logfile=no '
        '--repositories-file /dev/null query --installed --format json --fields name,version,arch "*"'))
    canonical = lambda rows: sorted(rows, key=lambda row: row['name'])
    if canonical(installed) != canonical(expected_packages) or len(installed) != 219:
        raise ValueError('Runtime package set differs')
    modules = {f.relative_to(root).as_posix(): hashlib.md5(f.read_bytes()).hexdigest()
               for f in (root / 'lib/modules').rglob('*.ko')}
    if len(modules) != 84:
        raise ValueError('Unexpected sealed module count')
    native = {}
    for f in root.rglob('*'):
        if f.is_symlink() or not f.is_file() or f.suffix == '.ko':
            continue
        with f.open('rb') as stream:
            header = stream.read(20)
        if header[:6] == b'\x7fELF\x02\x01' and header[18:20] == b'\xb7\0':
            native[f.relative_to(root).as_posix()] = hashlib.md5(f.read_bytes()).hexdigest()
    hashes = run('exact-payloads', 'cd / && md5sum ' + ' '.join(sorted(modules | native)))
    for name, digest in (modules | native).items():
        if digest + '  ' + name not in hashes:
            raise ValueError('Runtime payload bytes differ: ' + name)
    for name in ('/sbin/init', '/sbin/procd', '/sbin/netifd', '/usr/sbin/be6l-recovery-guard'):
        owner = run('owner-' + name.replace('/', '_'), 'apk --network=no --cache=no --logfile=no '
            '--repositories-file /dev/null info --who-owns ' + name)
        if ' is owned by ' not in owner:
            raise ValueError('Missing normal package owner')
    services = json.loads(run('services', 'ubus call service list'))
    for name in ('network', 'be6l-recovery', 'dropbear', 'uhttpd'):
        instances = services.get(name, {}).get('instances', {})
        if not instances or not all(i.get('running') for i in instances.values()):
            raise ValueError('Required service not running: ' + name)
        if any(i.get('respawn_count', 0) for i in instances.values()):
            raise ValueError('Required service respawned: ' + name)
    processes = run('native-default-processes', 'set -- $(pidof netifd); test "$#" = 1 && '
        'readlink /proc/$1/exe && md5sum /proc/1/exe /proc/$1/exe && cat /proc/$1/maps')
    if '/sbin/netifd\n' not in processes:
        raise ValueError('Default netifd executable differs')
    for name in ('sbin/procd', 'sbin/netifd'):
        if hashlib.md5((root / name).read_bytes()).hexdigest() not in processes:
            raise ValueError('Actual process bytes differ')
    vm = {name: '/opt/be6l-a64-soft/lib/ucode/' + name + '.so' in processes
          for name in ('fs', 'ubus', 'uloop', 'uci', 'nl80211')}
    if not all(vm.values()):
        raise ValueError('Native VM module missing from default service')
    snapshots = []
    for i in range(2):
        status = run('npu-' + str(i), 'cat /sys/kernel/debug/1e900000.npu/status')
        if 'running=1 attached=1 failed=0 stopping=0' not in status or 'faulted=0 quiesced=0 faults=0' not in status:
            raise ValueError('NPU is not healthy')
        counters = {int(core): int(count) for core, count in
                    re.findall(r'core([01]) magic=7552d001 heartbeat=(\d+) cause=00000000 pc=00000000', status)}
        if set(counters) != {0, 1}:
            raise ValueError('NPU worker snapshot incomplete')
        snapshots.append(counters)
        if i == 0:
            time.sleep(2)
    if any((snapshots[1][i] - snapshots[0][i]) & 0xffffffff == 0 for i in (0, 1)):
        raise ValueError('NPU worker heartbeat stalled')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open('http://' + a.host + '/cgi-bin/luci/', timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        html = response.read().decode(errors='replace')
        status = response.status
        login_required = response.headers.get('X-LuCI-Login-Required')
    (work / 'luci-response.html').write_text(html)
    # The pinned dispatcher deliberately uses403 for an unauthenticated login
    # form. Require that exact header and form, not an arbitrary forbidden page.
    login_form = (status == 403 and login_required == 'yes' and
                  'luci_username' in html and 'luci_password' in html)
    if not (status == 200 or login_form) or '/luci-static/argon/' not in html or 'lang="zh-cn"' not in html:
        raise ValueError('Chinese LuCI/Argon management not observed')
    packages = {row['name'] for row in installed}
    required = {'luci-theme-argon', 'luci-i18n-base-zh-cn', 'wpad-mbedtls', 'btop', 'curl',
                'lua', 'luci-lib-nixio', 'bridger', 'tailscale', 'sing-box', 'luci-app-passwall'}
    if not required <= packages or {'luci-app-argon-config', 'xray-core'} & packages:
        raise ValueError('Required application selection differs')
    if root_digest(root) != report['root_records_sha256']:
        raise ValueError('Original offline root changed')
    result = dict(fit_sha256=report['image_sha256'], actual_kernel_build_id=actual_ids[0],
        expected_kernel_build_id=expected_ids[0], boot_id=boot, dual_cpu_aarch64=True,
        ram_root=True, ten_mtd_guards=True, critical_partition_digests_unchanged=True,
        exact_installed_packages=len(installed), exact_modules=len(modules),
        exact_native_regular_elf_files=len(native), default_native_pid1=True,
        default_native_netifd=True, default_native_vm_modules_mapped=vm,
        required_services_running_without_respawn=True, recovery_heartbeat_accepted=True,
        npu_workers_advancing=True, npu_faults=0, luci_http_status=status,
        luci_login_form_rendered=login_form, luci_argon_chinese=True,
        required_application_selection_preserved=True, original_offline_root_unchanged=True,
        startup_acceptance_passed=True, new_candidate_recovery_tested=False,
        routed_nat_qualified=False, standard_a53_package_compatibility_qualified=False,
        flash_operations=False)
    (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('NEW_ARM64_CANDIDATE_STARTUP_ACCEPTANCE_PASSED', actual_ids[0], flush=True)


if __name__ == '__main__':
    main()
