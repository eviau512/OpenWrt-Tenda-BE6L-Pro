# SPDX-License-Identifier: MIT
"""Load an admitted ARM64 candidate from the protected ARM32 RAM intermediate.

Uses strict SSH and an explicit outgoing boot ID. Creates only an owned tmpfs
and calls kexec_load; never executes the loaded kernel or writes flash.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import uuid
from recovery.ssh_heartbeat import target


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--payload', type=Path, required=True)
    p.add_argument('--host', type=target, required=True)
    p.add_argument('--identity', type=Path, required=True)
    p.add_argument('--known-hosts', type=Path, required=True)
    p.add_argument('--expected-boot-id', type=lambda s: str(uuid.UUID(s)), required=True)
    p.add_argument('--work', type=Path, required=True)
    a = p.parse_args()
    work = a.work.resolve()
    if work.parent != Path('/root') or not re.fullmatch('be6l-a64-stage-[a-z0-9-]+', work.name):
        p.error('Use a fresh /root/be6l-a64-stage-* directory')
    manifest_path = a.payload / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if manifest['board'] != 'tenda,be6l-pro' or manifest['flash'] != 'read-only' or manifest['executed']:
        raise ValueError('Wrong RAM payload')
    transition = manifest.get('prior_native_runtime_marker_transition')
    if transition:
        marked_paths = manifest.get('prior_loader_marker_only_paths', [])
        if (manifest.get('prior_loader_paths_bound') != 110 or
                manifest['prior_loader_paths_unchanged'] + len(marked_paths) != 110 or
                len(marked_paths) != len(set(marked_paths)) or
                not transition.get('all_61_native_elf_marker_only_delta') or
                not transition.get('other_runtime_payloads_unchanged') or
                transition.get('current_candidate_runtime_tested') is not False or
                manifest['native_netifd_real_isolated_runtime']):
            raise ValueError('Incomplete derived prior runtime/loader marker binding')
    elif manifest['prior_loader_paths_unchanged'] != 110 or not manifest['native_netifd_real_isolated_runtime']:
        raise ValueError('Missing candidate loader/runtime binding')
    names = {f['name'] for f in manifest['files']}
    expected = {'Image', 'board.dtb', 'entry.bin', 'linux64-kexec-loader', 'arm32-fallback', 'kexec', 'ld-musl-arm.so.1'}
    if names != expected or len(manifest['files']) != len(names):
        raise ValueError('Unexpected payload file set')
    for item in manifest['files']:
        data = (a.payload / item['name']).read_bytes()
        if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Payload changed before upload')
    work.mkdir(mode=0o700)
    ssh = ['ssh', '-i', str(a.identity), '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'UserKnownHostsFile=' + str(a.known_hosts), '-o', 'ConnectTimeout=5',
           '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1', 'root@' + a.host]

    def run(label, command, data=None):
        result = subprocess.run(ssh + [command], input=data, capture_output=True, timeout=120)
        (work / (label + '.log')).write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(label + ' failed; inspect retained private log')
        return result.stdout.decode()

    state = run('outgoing-state', 'uname -r; uname -m; cat /proc/sys/kernel/random/boot_id; '
        'cat /sys/kernel/kexec_loaded; cat /proc/iomem; grep MemAvailable /proc/meminfo; '
        'cat /sys/class/mtd/mtd[0-9]/flags; md5sum /dev/mtd0 /dev/mtd1 /dev/mtd2; '
        'grep airoha_wdt_shutdown /proc/kallsyms; cat /sys/kernel/debug/1e900000.npu/status; '
        'head -n1 /proc/mounts; cat /proc/cmdline; /usr/sbin/be6l-recovery-guard status')
    for pattern in (r'^6\.18\.55$', r'^armv7l$', '^' + re.escape(a.expected_boot_id) + '$',
                    r'^0$', r'airoha_wdt_shutdown', r'^tmpfs / tmpfs ', r'module_blacklist=mt7996e',
                    r'^running=0 attached=0 failed=0 stopping=0$',
                    r'^faulted=0 quiesced=0 faults=0 recoveries=0$',
                    r'^ppe=0 tdma=0 discarded_completions=0 interrupt_parks=0$', r'^state=armed$'):
        if not re.search(pattern, state, re.M):
            raise ValueError('Outgoing state does not meet ' + pattern)
    if len(re.findall(r'^0x0$', state, re.M)) != 10:
        raise ValueError('Ten MTD guards not observed')
    for digest, name in (('e831fc5dff58c75da64274f206df5edd', 'mtd0'),
                         ('a910eba27223f8563811168179eb4f04', 'mtd1'),
                         ('124dfc2a6d507d20aa34f8b4eb968e02', 'mtd2')):
        if digest + '  /dev/' + name not in state:
            raise ValueError('Critical partition digest changed')
    ranges = [tuple(int(v, 16) for v in pair) for pair in
              re.findall(r'^([0-9a-f]+)-([0-9a-f]+) : System RAM$', state, re.M)]
    for start, size in manifest['segments']:
        if not any(low <= start and start + size - 1 <= high for low, high in ranges):
            raise ValueError('Payload segment outside observed System RAM')
    for i, (start, size) in enumerate(manifest['segments']):
        for other, length in manifest['segments'][i + 1:]:
            if not (start + size <= other or other + length <= start):
                raise ValueError('Overlapping segments')
    needed = sum(f['size'] for f in manifest['files'])
    available = int(re.search(r'MemAvailable:\s+(\d+)', state).group(1)) * 1024
    if available <= needed * 2 + 64 * 1024 * 1024:
        raise ValueError('Insufficient memory for both upload and kexec pages')
    remote = '/tmp/' + work.name
    run('mount', 'test ! -e ' + remote + ' && mkdir ' + remote +
        ' && mount -t tmpfs -o size=128m,mode=0700 tmpfs ' + remote)
    md5 = {}
    for item in manifest['files']:
        data = (a.payload / item['name']).read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Input changed during transfer')
        run('upload-' + item['name'], 'cat >' + remote + '/' + item['name'], data)
        md5[item['name']] = hashlib.md5(data).hexdigest()
        print('CANDIDATE_FILE_UPLOADED', item['name'], flush=True)
    hashes = run('target-hashes', 'cd ' + remote + ' && md5sum ' + ' '.join(md5))
    for name, digest in md5.items():
        if digest + '  ' + name not in hashes:
            raise ValueError('Target bytes differ')
    loaded = run('load', 'cd ' + remote + ' && chmod 700 linux64-kexec-loader kexec ld-musl-arm.so.1'
        ' && ./linux64-kexec-loader && cat /sys/kernel/kexec_loaded')
    if 'P3_LINUX64_AND_ARM32_BACKUP_LOADED' not in loaded or not re.search('^1$', loaded, re.M):
        raise ValueError('No confirmed kexec load')
    result = dict(loaded=True, executed=False, remote=remote, outgoing_boot_id=a.expected_boot_id,
        protected_arm32_kernel_started=True, watchdog_shutdown_symbol_observed=True,
        ten_mtd_guards=True, critical_digests_unchanged=True, npu_never_attached_and_idle=True,
        md5=md5, fit_sha256=manifest['fit_sha256'],
        payload_manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(), flash_operations=False)
    (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print('NEW_ARM64_CANDIDATE_LOADED_NOT_EXECUTED', manifest['fit_sha256'], flush=True)


if __name__ == '__main__':
    main()
