# SPDX-License-Identifier: MIT
"""Temporarily dispatch standard A53 ELF and test the complete child exec path.

Requires the exact qualified RAM kernel, all marked host ELF and signed runtime.
Always unregisters this one rule after the bounded tests. No flash operation,
forced module insertion or persistent/boot-time binfmt configuration occurs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shlex
import subprocess
import uuid
from package_native_netifd_v3 import root_digest, sha
from plan_integer_binfmt_v1 import rule_bytes
from plan_integer_binfmt_v1 import matches
from recovery.ssh_heartbeat import target


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('stage', 'candidate', 'composition', 'emulator-package', 'identity', 'known-hosts', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--host', type=target, required=True)
    p.add_argument('--expected-boot-id', type=lambda s: str(uuid.UUID(s)), required=True)
    p.add_argument('--expected-cases', type=int, default=14)
    p.add_argument('--corner-probe', type=Path, help='Optional admitted standard ELF negative-semantics probe directory')
    p.add_argument('--guest-exe-file', action='store_true',
                   help='Register X only with the matching kernel and aware interpreter receipts')
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-binfmt-test-[a-z0-9-]+', w.name) or w.exists():
        p.error('Use a fresh /root/be6l-binfmt-test-* directory')
    staged = json.loads((a.stage/'result.json').read_text())
    candidate = json.loads((a.candidate/'result.json').read_text())
    emulator = json.loads((a.emulator_package/'result.json').read_text())
    root = a.composition/'root'
    if (staged['boot_id'] != a.expected_boot_id or staged['binfmt_registered'] or
            not staged['complete_host_elf_inventory_verified'] or staged['marked_host_elf_count'] != 62 or
            not staged['single_process_standard_package_controls_passed'] or
            staged['fit_sha256'] != candidate['image_sha256'] or not candidate['integer_binfmt_builtin'] or
            root_digest(root) != candidate['root_records_sha256'] or
            staged['source_emulator_receipt_sha256'] != sha(a.emulator_package/'result.json')):
        raise ValueError('Missing exact target/kernel/native-inventory/standard-runtime admission')
    contract = 'BE6L_X_AT_FLAGS_16_v1'
    if a.guest_exe_file and (
            not candidate.get('guest_exe_file') or candidate.get('guest_exe_contract') != contract or
            not emulator.get('kernel_execfd_exe_aware') or emulator.get('guest_exe_contract') != contract):
        raise ValueError('X requires both the matched kernel contract and aware signed interpreter')
    flags = 'POFX' if a.guest_exe_file else 'POF'
    guest = staged['guest_root']
    if not re.fullmatch('/tmp/be6l-binfmt-stage-[a-z0-9-]+/guest', guest) or staged['interpreter'] != '/usr/libexec/be6l/qemu-aarch64':
        raise ValueError('Unexpected staged paths')
    w.mkdir(mode=0o700)
    ssh = ['ssh', '-T', '-i', str(a.identity), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(a.known_hosts),
           '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1', 'root@'+a.host]

    def run(label, command, data=None, timeout=120, require_success=True):
        command = 'grep -qx '+a.expected_boot_id+' /proc/sys/kernel/random/boot_id && { '+command+'; }'
        r = subprocess.run(ssh+[command], input=data, capture_output=True, timeout=timeout)
        (w/(label+'.stdout')).write_bytes(r.stdout)
        (w/(label+'.stderr')).write_bytes(r.stderr)
        if require_success and r.returncode:
            raise RuntimeError(label+' failed; inspect private log')
        return r

    if a.corner_probe:
        corner = a.corner_probe/'be6l-exec-corners'
        corner_receipt = json.loads((a.corner_probe/'result.json').read_text())
        if (not corner_receipt['standard_a53_abi'] or sha(corner) != corner_receipt['elf_sha256'] or
                not matches(corner.read_bytes()[:64])):
            raise ValueError('Wrong standard negative-semantics probe')
        run('upload-corner-probe', 'cat >'+guest+'/bin/be6l-exec-corners', corner.read_bytes())
        run('verify-corner-probe', 'md5sum -c -',
            (hashlib.md5(corner.read_bytes()).hexdigest()+'  '+guest+'/bin/be6l-exec-corners\n').encode())
        run('corner-probe-mode', 'chmod 755 '+guest+'/bin/be6l-exec-corners')

    # Recheck complete immutable host payloads immediately before activation.
    digests = {}
    for name in staged['native_host_elf_paths']:
        path = a.emulator_package/'files'/name.lstrip('/') if name == staged['interpreter'] else root/name.lstrip('/')
        digests[name] = hashlib.md5(path.read_bytes()).hexdigest()
    digest_input = ''.join(value+'  '+name+'\n' for name, value in sorted(digests.items()))
    run('host-digests-before', 'md5sum -c -', digest_input.encode())
    before = run('before', 'cat /sys/class/mtd/mtd[0-9]/flags; cat /sys/kernel/debug/1e900000.npu/status; '
        '/usr/sbin/be6l-recovery-guard heartbeat; '
        'if grep -q " /proc/sys/fs/binfmt_misc binfmt_misc " /proc/mounts; then '
        'echo BINFMT_ALREADY_MOUNTED; ls /proc/sys/fs/binfmt_misc; else echo BINFMT_UNMOUNTED; fi').stdout.decode()
    if (before.splitlines().count('0x0') != 10 or 'ppe=0 tdma=0' not in before or
            'running=0 attached=0 failed=0 stopping=1' not in before or 'BINFMT_UNMOUNTED' not in before):
        raise ValueError('Target or existing binfmt state differs')
    mounted = False
    registered = False
    registration_attempted = False
    cleanup_ok = False
    cases = {}
    corner_cases = {}
    expected_corners = corner_receipt.get('expected_negative_cases', 3) if a.corner_probe else None
    controls_ok = False
    matrix_exit = None
    error = None
    try:
        run('mount', 'mount -t binfmt_misc -o nodev,nosuid,noexec binfmt_misc /proc/sys/fs/binfmt_misc')
        mounted = True
        entries = run('empty-registry', 'ls /proc/sys/fs/binfmt_misc').stdout.decode().splitlines()
        if sorted(entries) != ['register', 'status']:
            raise ValueError('Refuse to modify an existing dispatch registry')
        magic, mask = rule_bytes()
        def escaped(value):
            return ''.join('\\x%02x' % byte for byte in value).encode()
        rule = b':be6l-a53:M::'+escaped(magic)+b':'+escaped(mask)+b':'+staged['interpreter'].encode()+b':'+flags.encode()+b'\n'
        (w/'registration.txt').write_bytes(rule)
        registration_attempted = True
        run('register', 'cat >/proc/sys/fs/binfmt_misc/register', rule)
        registered = True
        entry = run('registered-entry', 'cat /proc/sys/fs/binfmt_misc/be6l-a53').stdout.decode()
        if ('enabled\n' not in entry or 'flags: '+flags+'\n' not in entry or
                'interpreter '+staged['interpreter']+'\n' not in entry or
                'magic '+magic.hex()+'\n' not in entry or 'mask '+mask.hex()+'\n' not in entry):
            raise ValueError('Kernel registered different dispatch semantics')
        run('native-hosts-after-registration', '/sbin/netifd -h; /opt/be6l-a64-soft/bin/ucode -e '+
            shlex.quote('print("PRIVATE_NATIVE_STILL_RUNS\\n");')+'; /usr/sbin/be6l-recovery-guard heartbeat')
        result = run('matrix', 'timeout -s KILL 90 chroot '+guest+' /bin/be6l-exec-probe', require_success=False)
        matrix_exit = result.returncode
        output = result.stdout.decode()
        cases = {name: dict(passed=state == 'PASS', wait_status=int(status))
                 for name, state, status in re.findall(r'^EXEC_CASE (\S+) (PASS|FAIL) status=(\d+)$', output, re.M)}
        script = ('/usr/bin/ucode -e '+shlex.quote('print(1.25 + 2.5, "\\n");')+
            '; /usr/bin/btop --version; /bin/busybox echo STANDARD_SHELL_CHILD_CHAIN_OK')
        control = run('standard-package-child-chain', 'timeout -s KILL 45 chroot '+guest+' /bin/sh -c '+shlex.quote(script), require_success=False)
        value = control.stdout.decode()
        controls_ok = control.returncode == 0 and all(text in value for text in ('3.75', '1.4.7', 'STANDARD_SHELL_CHILD_CHAIN_OK'))
        if a.corner_probe:
            result = run('negative-corners', 'timeout -s KILL 45 chroot '+guest+' /bin/be6l-exec-corners', require_success=False)
            corner_cases = {name: dict(passed=state == 'PASS', wait_status=int(status))
                for name, state, status in re.findall(r'^EXEC_CORNER (\S+) (PASS|FAIL) status=(\d+)$', result.stdout.decode(), re.M)}
    except Exception as failure:
        error = type(failure).__name__+': '+str(failure)
    finally:
        # Only our own rule/mount; never remove another owner's registry entries.
        if registration_attempted:
            # A lost SSH exit status does not prove the write had no effect.
            run('unregister', 'if test -e /proc/sys/fs/binfmt_misc/be6l-a53; then '
                'echo -1 >/proc/sys/fs/binfmt_misc/be6l-a53; fi')
        if mounted:
            remaining = run('registry-after', 'ls /proc/sys/fs/binfmt_misc').stdout.decode().splitlines()
            cleanup_ok = sorted(remaining) == ['register', 'status']
            if cleanup_ok:
                run('unmount', 'umount /proc/sys/fs/binfmt_misc')
        run('host-digests-after', 'md5sum -c -', digest_input.encode())
        run('after', '/usr/sbin/be6l-recovery-guard heartbeat; cat /sys/class/mtd/mtd[0-9]/flags; '
            'cat /sys/kernel/debug/1e900000.npu/status')
    report = dict(boot_id=a.expected_boot_id, fit_sha256=candidate['image_sha256'],
        source_stage_receipt_sha256=sha(a.stage/'result.json'), flags=flags, cases=cases,
        guest_exe_contract=contract if a.guest_exe_file else None,
        matrix_exit=matrix_exit, expected_exec_case_count=a.expected_cases,
        all_exec_cases_passed=matrix_exit == 0 and len(cases) == a.expected_cases and all(item['passed'] for item in cases.values()),
        standard_package_child_chain_passed=controls_ok, interpreter_credentials_from_guest=False,
        negative_exec_corner_cases=corner_cases,
        expected_negative_case_count=expected_corners,
        source_corner_probe_receipt_sha256=sha(a.corner_probe/'result.json') if a.corner_probe else None,
        all_negative_corners_passed=(len(corner_cases) == expected_corners and all(item['passed'] for item in corner_cases.values())) if a.corner_probe else None,
        rule_unregistered_and_mount_removed=cleanup_ok, host_payloads_unchanged=True,
        error=error, target_executed=True, flash_operations=False,
        standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('BINFMT_EXECUTION_MATRIX_RECORDED', json.dumps(report), flush=True)
    if error or not report['all_exec_cases_passed'] or not controls_ok or not cleanup_ok or (a.corner_probe and not report['all_negative_corners_passed']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
