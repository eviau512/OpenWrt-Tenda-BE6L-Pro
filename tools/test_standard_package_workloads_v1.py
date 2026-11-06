# SPDX-License-Identifier: MIT
"""Run isolated signed A53 package workloads and a post-unregister mm pin test.

Requires a completed exact POFX exec admission; it does not repeat the matrix.
The native helper never truncates or writes the interpreter. No flash, host
network configuration or boot-time registration is involved.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import selectors
import shlex
import subprocess
import uuid
from package_native_netifd_v3 import root_digest, sha
from plan_integer_binfmt_v1 import rule_bytes
from recovery.ssh_heartbeat import target

BASE = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('stage', 'candidate', 'composition', 'emulator-package', 'exec-test',
                 'native-probe', 'identity', 'known-hosts', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--host', type=target, required=True)
    p.add_argument('--expected-boot-id', type=lambda s: str(uuid.UUID(s)), required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-standard-workloads-[a-z0-9-]+', w.name):
        p.error('Use a fresh /root/be6l-standard-workloads-* directory')
    load = lambda directory: json.loads((directory/'result.json').read_text())
    staged, image, emulator, tested, probe = map(load, (a.stage, a.candidate, a.emulator_package, a.exec_test, a.native_probe))
    contract = 'BE6L_X_AT_FLAGS_16_v1'
    root = a.composition/'root'
    native = a.native_probe/'native-interpreter-write-probe'
    if (not image.get('guest_exe_file') or image.get('guest_exe_contract') != contract or
        not emulator.get('kernel_execfd_exe_aware') or emulator.get('guest_exe_contract') != contract or
        tested['boot_id'] != a.expected_boot_id or tested['fit_sha256'] != image['image_sha256'] or
        tested.get('flags') != 'POFX' or not tested['all_exec_cases_passed'] or
        not tested['standard_package_child_chain_passed'] or tested['error'] or
        not tested['rule_unregistered_and_mount_removed'] or not tested['host_payloads_unchanged'] or
        tested['source_stage_receipt_sha256'] != sha(a.stage/'result.json') or
        staged['boot_id'] != a.expected_boot_id or staged['fit_sha256'] != image['image_sha256'] or
        not staged['complete_host_elf_inventory_verified'] or staged['marked_host_elf_count'] != 62 or
        staged['source_emulator_receipt_sha256'] != sha(a.emulator_package/'result.json') or
        root_digest(root) != image['root_records_sha256'] or
        sha(native) != probe['elf_sha256'] or not probe['native_arm32'] or
        not probe['static'] or probe['vfp_neon_instruction_count'] or not probe['no_truncate_or_write']):
        raise ValueError('Missing exact kernel/emulator/exec/host/native-helper admission')
    guest = staged['guest_root']
    if not re.fullmatch('/tmp/be6l-binfmt-stage-[a-z0-9-]+/guest', guest):
        raise ValueError('Unexpected isolated guest path')
    remote_probe = guest.rsplit('/', 1)[0]+'/native-write-probe'
    w.mkdir(mode=0o700)
    ssh = ['ssh', '-T', '-i', str(a.identity), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(a.known_hosts),
           '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1', 'root@'+a.host]

    def bound(command):
        return 'grep -qx '+a.expected_boot_id+' /proc/sys/kernel/random/boot_id && { '+command+'; }'

    def run(label, command, data=None, timeout=120, good=True):
        r = subprocess.run(ssh+[bound(command)], input=data, capture_output=True, timeout=timeout)
        (w/(label+'.stdout')).write_bytes(r.stdout)
        (w/(label+'.stderr')).write_bytes(r.stderr)
        if good and r.returncode:
            raise RuntimeError(label+' failed; inspect private log')
        return r

    scripts = {'standard-package-nixio.lua': '/tmp/be6l-standard-package-nixio.lua',
               'standard-package-workloads.sh': '/tmp/be6l-standard-package-workloads.sh'}
    script_shas = {}
    uploads = {remote_probe: native}
    for name, destination in scripts.items():
        source = BASE/'experiments/qemu-integer-host'/name
        script_shas[name] = sha(source)
        uploads[guest+destination] = source
    for destination, source in uploads.items():
        run('upload-'+source.name, 'cat >'+destination, source.read_bytes())
        run('verify-'+source.name, 'md5sum -c -',
            (hashlib.md5(source.read_bytes()).hexdigest()+'  '+destination+'\n').encode())
    run('helper-mode', 'chmod 555 '+remote_probe)
    digests = {}
    for name in staged['native_host_elf_paths']:
        file = a.emulator_package/'files'/name.lstrip('/') if name == staged['interpreter'] else root/name.lstrip('/')
        digests[name] = hashlib.md5(file.read_bytes()).hexdigest()
    checksums = ''.join(value+'  '+name+'\n' for name, value in sorted(digests.items())).encode()
    run('host-digests-before', 'md5sum -c -', checksums)
    status_command = 'cat /sys/class/mtd/mtd[0-9]/flags; cat /sys/kernel/debug/1e900000.npu/status; /usr/sbin/be6l-recovery-guard heartbeat'
    before = run('before', status_command+'; if grep -q " /proc/sys/fs/binfmt_misc " /proc/mounts; then echo REGISTRY_BUSY; else echo REGISTRY_UNMOUNTED; fi').stdout.decode()
    if (before.splitlines().count('0x0') != 10 or 'running=0 attached=0 failed=0 stopping=1' not in before or
        'ppe=0 tdma=0' not in before or 'REGISTRY_UNMOUNTED' not in before):
        raise ValueError('Target MTD/NPU/registry state changed')
    # Minimal isolated runtime scaffolding; never expose the host /dev tree.
    # Only these four conventional memory character devices are admitted.
    devices = {'null': 3, 'zero': 5, 'random': 8, 'urandom': 9}
    run('guest-device-directory', 'mkdir -p '+guest+'/dev')
    for name, minor in devices.items():
        destination = guest+'/dev/'+name
        run('guest-device-'+name, 'if test ! -e '+destination+'; then /bin/busybox mknod -m 666 '+
            destination+' c 1 '+str(minor)+'; fi; test -c '+destination)
        fields = run('guest-device-metadata-'+name, '/bin/busybox ls -ln '+destination).stdout.decode().split()
        if len(fields) < 7 or fields[0] != 'crw-rw-rw-' or fields[2:6] != ['0', '0', '1,', str(minor)]:
            raise ValueError('Wrong isolated character device metadata: '+name)
    # ubusd requires getpwuid/getgrgid even for UID0. These are locked fixture
    # identities inside the guest, never copied from or installed on the host.
    accounts = {'passwd': b'root:!:0:0:root:/:/bin/false\nnobody:!:65534:65534:nobody:/nonexistent:/bin/false\n',
                'group': b'root:x:0:\nnogroup:x:65534:\n'}
    run('guest-etc-directory', 'mkdir -p '+guest+'/etc')
    for name, data in accounts.items():
        destination = guest+'/etc/'+name
        run('guest-account-'+name, 'if test ! -e '+destination+'; then cat >'+destination+'; fi', data)
        run('guest-account-verify-'+name, 'md5sum -c -',
            (hashlib.md5(data).hexdigest()+'  '+destination+'\n').encode())
    mounted = attempted = cleanup = False
    hold = None
    cases, lifetime = {}, {}
    error = None
    try:
        run('mount', 'mount -t binfmt_misc -o nodev,nosuid,noexec binfmt_misc /proc/sys/fs/binfmt_misc')
        mounted = True
        if sorted(run('registry-empty', 'ls /proc/sys/fs/binfmt_misc').stdout.decode().splitlines()) != ['register', 'status']:
            raise ValueError('Refuse to modify another owner registry')
        magic, mask = rule_bytes()
        escaped = lambda value: ''.join('\\x%02x' % byte for byte in value).encode()
        rule = b':be6l-a53:M::'+escaped(magic)+b':'+escaped(mask)+b':'+staged['interpreter'].encode()+b':POFX\n'
        attempted = True
        run('register', 'cat >/proc/sys/fs/binfmt_misc/register', rule)
        if 'flags: POFX\n' not in run('entry', 'cat /proc/sys/fs/binfmt_misc/be6l-a53').stdout.decode():
            raise ValueError('Wrong registered contract')
        r = run('packages', 'timeout -s KILL 90 chroot '+guest+' /bin/sh /tmp/be6l-standard-package-workloads.sh', good=False)
        cases = {name: dict(passed=state == 'PASS', exit_code=int(code)) for name, state, code in
                 re.findall(r'^PACKAGE_CASE (\S+) (PASS|FAIL) status=(\d+)$', r.stdout.decode(), re.M)}
        lifetime['workload_exit'] = r.returncode
        lua = 'local n=require"nixio"; io.write("BE6L_LIFETIME_READY\\n"); io.flush(); n.nanosleep(12,0)'
        hold = subprocess.Popen(ssh+[bound('timeout -s KILL 25 chroot '+guest+' /usr/bin/lua -e '+shlex.quote(lua))],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with selectors.DefaultSelector() as selector:
            selector.register(hold.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=8) or hold.stdout.readline() != b'BE6L_LIFETIME_READY\n':
                raise RuntimeError('Bounded guest hold did not become ready')
        run('unregister-live', 'echo -1 >/proc/sys/fs/binfmt_misc/be6l-a53')
        lifetime['rule_removed_while_guest_alive'] = hold.poll() is None
        lifetime['interpreter_denied_after_unregister'] = run('interpreter-denied', remote_probe+' denied', good=False).returncode == 0
        out, err = hold.communicate(timeout=30)
        (w/'hold.stdout').write_bytes(out)
        (w/'hold.stderr').write_bytes(err)
        lifetime['guest_hold_exit'] = hold.returncode
        lifetime['interpreter_writable_after_last_guest_exit'] = run('interpreter-allowed', remote_probe+' allowed', good=False).returncode == 0
    except Exception as failure:
        error = type(failure).__name__+': '+str(failure)
    finally:
        if hold is not None and hold.poll() is None:
            try:
                hold.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                hold.kill()
                hold.communicate(timeout=10)
        if attempted:
            run('unregister-final', 'if test -e /proc/sys/fs/binfmt_misc/be6l-a53; then echo -1 >/proc/sys/fs/binfmt_misc/be6l-a53; fi')
        if mounted:
            cleanup = sorted(run('registry-after', 'ls /proc/sys/fs/binfmt_misc').stdout.decode().splitlines()) == ['register', 'status']
            if cleanup:
                run('unmount', 'umount /proc/sys/fs/binfmt_misc')
        run('host-digests-after', 'md5sum -c -', checksums)
        run('after', status_command)
    report = dict(boot_id=a.expected_boot_id, fit_sha256=image['image_sha256'], flags='POFX',
        source_stage_receipt_sha256=sha(a.stage/'result.json'), source_exec_test_sha256=sha(a.exec_test/'result.json'),
        source_native_probe_receipt_sha256=sha(a.native_probe/'result.json'), source_script_sha256=script_shas,
        cases=cases, expected_package_case_count=8,
        all_package_cases_passed=len(cases) == 8 and all(v['passed'] for v in cases.values()),
        interpreter_lifetime=lifetime, rule_unregistered_and_mount_removed=cleanup,
        host_payloads_unchanged=True, error=error, target_executed=True,
        target_package_scripts_executed=False, isolated_standard_runtime_only=True,
        isolated_character_devices={name: dict(major=1, minor=minor, mode='0666') for name, minor in devices.items()},
        isolated_locked_uid_gid_fixture=True,
        standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('STANDARD_PACKAGE_WORKLOADS_RECORDED', json.dumps(report), flush=True)
    if error or not cleanup or not report['all_package_cases_passed'] or not all(
            lifetime.get(k) for k in ('rule_removed_while_guest_alive', 'interpreter_denied_after_unregister',
                                      'interpreter_writable_after_last_guest_exit')) or lifetime.get('guest_hold_exit') != 0:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
