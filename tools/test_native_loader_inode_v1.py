# SPDX-License-Identifier: MIT
"""Run only four native ptrace/retained-loader-inode cases in owned RAM fixtures.

Requires exact V2 r2, signed aware r5, current-boot startup acceptance and the
complete marked native inventory. Removes only this run's rule and mount.
No flash, persistent registration, secureexec or complete ABI qualification.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess
import uuid
from package_native_netifd_v3 import root_digest, sha
from plan_integer_binfmt_v1 import PRIVATE_SOFT_EFLAGS, matches, rule_bytes
from recovery.ssh_heartbeat import target

CONTRACT = 'BE6L_X_EXECFD_EXE_INTERPFD_V2'
INTERPRETER = '/usr/libexec/be6l/qemu-aarch64'
R5_PACKAGE = '253fc682636d2d40b1e6c016317704b21452c74cc2540d1bffd32223adfa5928'
R5_INTERPRETER = '7e094b445e34d353c47b91cddde062ce2e2d344678813da5e22b9993953d720d'
CASES = {'execve-control', 'execve-rename-bad-path',
         'execveat-cloexec-control', 'execveat-cloexec-rename-bad-path'}


def static_arm32(data):
    if len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01' or struct.unpack_from('<HH', data, 16) != (2, 40):
        return False
    offset = struct.unpack_from('<I', data, 28)[0]
    stride, count = struct.unpack_from('<HH', data, 42)
    return (stride >= 32 and count > 0 and offset+stride*count <= len(data) and
            all(struct.unpack_from('<I', data, offset+i*stride)[0] not in (2, 3) for i in range(count)))


def v2(receipt):
    return (receipt.get('guest_interp_revision') == 2 and receipt.get('dispatch_failures_terminal') is True)


def idle_state(value):
    return (value.splitlines().count('0x0') == 10 and
            'running=0 attached=0 failed=0 stopping=1' in value and 'ppe=0 tdma=0' in value and
            'faulted=0 quiesced=0 faults=0' in value)


def mount_id(value):
    rows = [line.split()[0] for line in value.splitlines()
            if len(line.split()) > 6 and line.split()[4] == '/proc/sys/fs/binfmt_misc' and ' - binfmt_misc ' in line]
    if len(rows) > 1:
        raise ValueError('Ambiguous binfmt mount ownership')
    return rows[0] if rows else None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('stage', 'candidate', 'composition', 'emulator-package', 'corner-probe',
                 'native-probe', 'identity', 'known-hosts', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--host', type=target, required=True)
    p.add_argument('--expected-boot-id', type=lambda s: str(uuid.UUID(s)), required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-native-loader-inode-test-[a-z0-9-]+', w.name) or w.exists():
        p.error('Use a fresh /root/be6l-native-loader-inode-test-* directory')
    load = lambda directory: json.loads((directory/'result.json').read_text())
    staged, image, composition, emulator, corner, native = map(load, (
        a.stage, a.candidate, a.composition, a.emulator_package, a.corner_probe, a.native_probe))
    root = a.composition/'root'
    fit_name = Path(image['image'])
    package_name = Path(emulator['package'])
    if fit_name.is_absolute() or '..' in fit_name.parts or package_name.name != str(package_name):
        raise ValueError('Unsafe sealed artifact name')
    if (not v2(image) or not image.get('guest_interp_fd') or not image.get('guest_exe_file') or
            image.get('guest_exe_contract') != CONTRACT or not image.get('integer_binfmt_builtin') or
            sha(a.candidate/fit_name) != image['image_sha256'] or
            sha(a.composition/'result.json') != image['composition_receipt_sha256'] or
            root_digest(root) != image['root_records_sha256'] or
            composition.get('installed_root_records_sha256') != image['root_records_sha256'] or
            not composition.get('matching_root_composed')):
        raise ValueError('Exact V2 r2 FIT/root admission differs')
    if (not emulator.get('normal_signed_emulator_package') or emulator.get('version') != '11.1.3-r5' or
            emulator.get('guest_exe_contract') != CONTRACT or
            not emulator.get('kernel_execfd_exe_aware') or not emulator.get('kernel_guest_interp_aware') or
            not emulator.get('private_signing_key_removed') or
            emulator.get('package_sha256') != R5_PACKAGE or sha(a.emulator_package/package_name) != R5_PACKAGE or
            emulator.get('relative_interpreter_path') != INTERPRETER.lstrip('/') or
            emulator.get('interpreter_sha256') != R5_INTERPRETER or
            sha(a.emulator_package/'files'/INTERPRETER.lstrip('/')) != R5_INTERPRETER):
        raise ValueError('Exact normally signed aware r5 admission differs')
    if (not v2(staged) or staged.get('boot_id') != a.expected_boot_id or
            staged.get('fit_sha256') != image['image_sha256'] or staged.get('binfmt_registered') is not False or
            staged.get('marked_host_elf_count') != 62 or not staged.get('complete_host_elf_inventory_verified') or
            not staged.get('guest_payload_digests_verified') or not staged.get('normal_signed_emulator_installed') or
            not staged.get('native_interpreter_runs') or not staged.get('single_process_standard_package_controls_passed') or
            staged.get('interpreter') != INTERPRETER or
            staged.get('source_emulator_receipt_sha256') != sha(a.emulator_package/'result.json')):
        raise ValueError('Exact boot/stage/inventory/runtime admission differs')
    qualified_paths = [file for file in a.stage.parent.glob('be6l-candidate-qualification-*/result.json')
                       if sha(file) == staged.get('source_qualification_receipt_sha256')]
    if len(qualified_paths) != 1:
        raise ValueError('Need one exact startup qualification receipt matching the stage seal')
    qualified = json.loads(qualified_paths[0].read_text())
    if (not v2(qualified) or not qualified.get('startup_acceptance_passed') or
            qualified.get('boot_id') != a.expected_boot_id or qualified.get('fit_sha256') != image['image_sha256']):
        raise ValueError('Current boot startup qualification differs')
    guest = staged.get('guest_root', '')
    if not re.fullmatch('/tmp/be6l-binfmt-stage-[a-z0-9-]+/guest', guest):
        raise ValueError('Unexpected isolated guest path')
    corner_file, native_file = a.corner_probe/'be6l-exec-corners', a.native_probe/'native-loader-inode'
    if (not corner.get('standard_a53_abi') or sha(corner_file) != corner.get('elf_sha256') or
            not matches(corner_file.read_bytes()[:64])):
        raise ValueError('Standard A64 fixture admission differs')
    if (not native.get('native_arm32') or not native.get('static') or
            native.get('vfp_neon_instruction_count') != 0 or native.get('expected_case_count') != 4 or
            set(native.get('cases', [])) != CASES or not native.get('isolated_fixture_only') or
            not native.get('existing_interpreters_unchanged') or not native.get('parent_death_kills_child') or
            native.get('secureexec_covered') is not False or sha(native_file) != native.get('elf_sha256') or
            not static_arm32(native_file.read_bytes())):
        raise ValueError('Static ARM32 inode control admission differs')
    expected = set()
    for file in root.rglob('*'):
        if file.is_symlink() or not file.is_file():
            continue
        with file.open('rb') as stream:
            header = stream.read(64)
        if len(header) >= 64 and header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\xb7\0' and struct.unpack_from('<H', header, 16)[0] in (2, 3):
            if matches(header) or struct.unpack_from('<I', header, 48)[0] != PRIVATE_SOFT_EFLAGS:
                raise ValueError('Unmarked native root ELF')
            expected.add('/'+file.relative_to(root).as_posix())
    expected.add(INTERPRETER)
    paths = staged.get('native_host_elf_paths', [])
    if len(expected) != 62 or len(paths) != 62 or set(paths) != expected:
        raise ValueError('Exact 62 native host ELF inventory differs')
    digests = {}
    for name in sorted(expected):
        file = a.emulator_package/'files'/name.lstrip('/') if name == INTERPRETER else root/name.lstrip('/')
        digests[name] = hashlib.md5(file.read_bytes()).hexdigest()
    checksums = ''.join(value+'  '+name+'\n' for name, value in sorted(digests.items())).encode()
    w.mkdir(mode=0o700)
    ssh = ['ssh', '-T', '-i', str(a.identity), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(a.known_hosts),
           '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1', 'root@'+a.host]

    def run(label, command, data=None, timeout=120, good=True):
        command = 'grep -qx '+a.expected_boot_id+' /proc/sys/kernel/random/boot_id && { '+command+'; }'
        result = subprocess.run(ssh+[command], input=data, capture_output=True, timeout=timeout)
        (w/(label+'.stdout')).write_bytes(result.stdout)
        (w/(label+'.stderr')).write_bytes(result.stderr)
        if good and result.returncode:
            raise RuntimeError(label+' failed; inspect private evidence')
        return result

    status_command = ('cat /sys/class/mtd/mtd[0-9]/flags; cat /sys/kernel/debug/1e900000.npu/status; '
                      '/usr/sbin/be6l-recovery-guard heartbeat')
    before = run('before', status_command).stdout.decode()
    if not idle_state(before) or 'BE6L_HEARTBEAT '+a.expected_boot_id+' ' not in before:
        raise ValueError('Target MTD/NPU/boot/heartbeat differs')
    if mount_id(run('mountinfo-before', 'cat /proc/self/mountinfo').stdout.decode()) is not None:
        raise ValueError('Refuse an existing binfmt mount')
    run('host-digests-before', 'md5sum -c -', checksums)
    token = uuid.uuid4().hex
    remote = guest.rsplit('/', 1)[0]+'/inode-'+token
    run('own-upload-directory', 'test ! -e '+remote+' && mkdir -m700 '+remote)
    corner_destination = guest+'/bin/be6l-exec-corners'
    missing = run('corner-absent', 'test ! -e '+corner_destination+' && test ! -L '+corner_destination, good=False)
    if missing.returncode == 0:
        run('upload-corner', 'set -C; cat >'+corner_destination, corner_file.read_bytes())
        run('mode-corner', 'chmod 755 '+corner_destination)
    run('corner-regular', 'test -f '+corner_destination+' && test ! -L '+corner_destination+' && test -x '+corner_destination)
    run('verify-corner', 'md5sum -c -', (hashlib.md5(corner_file.read_bytes()).hexdigest()+'  '+corner_destination+'\n').encode())
    remote_native = remote+'/native-loader-inode'
    run('upload-native', 'set -C; cat >'+remote_native, native_file.read_bytes())
    run('verify-native', 'md5sum -c -', (hashlib.md5(native_file.read_bytes()).hexdigest()+'  '+remote_native+'\n').encode())
    run('mode-native', 'chmod 555 '+remote_native)
    name = 'be6l-inode-'+token
    entry_path = '/proc/sys/fs/binfmt_misc/'+name
    magic, mask = rule_bytes()
    escaped = lambda value: ''.join('\\x%02x' % byte for byte in value).encode()
    rule = b':'+name.encode()+b':M::'+escaped(magic)+b':'+escaped(mask)+b':'+INTERPRETER.encode()+b':POFX\n'
    expected_entry = ('enabled\n', 'interpreter '+INTERPRETER+'\n', 'flags: POFX\n',
                      'magic '+magic.hex()+'\n', 'mask '+mask.hex()+'\n')
    owns_entry = lambda value: all(part in value for part in expected_entry)
    own_mount_id = None
    mount_attempted = registration_attempted = cleanup_ok = False
    host_unchanged = boot_and_guards_after = False
    cases, cleanup_failures = {}, []
    error = None
    exit_code = None
    try:
        mount_attempted = True
        run('mount', 'mount -t binfmt_misc -o nodev,nosuid,noexec binfmt_misc /proc/sys/fs/binfmt_misc')
        own_mount_id = mount_id(run('mountinfo-owned', 'cat /proc/self/mountinfo').stdout.decode())
        if own_mount_id is None:
            raise ValueError('Cannot identify this run binfmt mount')
        if sorted(run('registry-empty', 'ls /proc/sys/fs/binfmt_misc').stdout.decode().splitlines()) != ['register', 'status']:
            raise ValueError('Refuse nonempty dispatch registry')
        (w/'registration.txt').write_bytes(rule)
        registration_attempted = True  # A lost SSH result does not prove no write occurred.
        run('register', 'cat >/proc/sys/fs/binfmt_misc/register', rule)
        if not owns_entry(run('entry', 'cat '+entry_path).stdout.decode()):
            raise ValueError('Kernel registered different POFX semantics')
        result = run('native-inode-four-cases', 'timeout -s KILL 90 '+remote_native+' '+guest,
                     timeout=110, good=False)
        exit_code = result.returncode
        output = result.stdout.decode()
        rows = re.findall(r'^NATIVE_LOADER_INODE (\S+) (PASS|FAIL) (.*)$', output, re.M)
        cases = {case: dict(passed=state == 'PASS', observations=details) for case, state, details in rows}
        if (exit_code != 0 or len(rows) != 4 or set(cases) != CASES or not all(item['passed'] for item in cases.values()) or
                'NATIVE_LOADER_INODE_SUMMARY cases=4 failures=0 cleanup_errors=0 secureexec_covered=0' not in output):
            raise RuntimeError('Native retained-loader-inode cases did not all pass')
    except Exception as failure:
        error = type(failure).__name__+': '+str(failure)
    finally:
        # Cleanup failures remain fatal and are separately recorded. Never
        # delete another name, a changed entry, or a mount with another ID.
        if registration_attempted:
            try:
                exists = run('entry-exists-cleanup', 'test -e '+entry_path, good=False)
                if exists.returncode == 0:
                    if not owns_entry(run('entry-cleanup', 'cat '+entry_path).stdout.decode()):
                        raise ValueError('Own unique rule contents changed; refuse removal')
                    run('unregister', 'echo -1 >'+entry_path)
                elif exists.returncode != 1:
                    raise RuntimeError('Cannot establish whether own rule exists')
            except Exception as failure:
                cleanup_failures.append('unregister: '+type(failure).__name__+': '+str(failure))
        if own_mount_id is not None:
            try:
                current = mount_id(run('mountinfo-cleanup', 'cat /proc/self/mountinfo').stdout.decode())
                if current != own_mount_id:
                    raise ValueError('Owned mount ID changed; refuse unmount')
                remaining = sorted(run('registry-cleanup', 'ls /proc/sys/fs/binfmt_misc').stdout.decode().splitlines())
                if remaining != ['register', 'status']:
                    raise ValueError('Dispatch registry is not empty; refuse unmount')
                run('unmount', 'umount /proc/sys/fs/binfmt_misc')
                if mount_id(run('mountinfo-after', 'cat /proc/self/mountinfo').stdout.decode()) is not None:
                    raise ValueError('binfmt mount remains after cleanup')
                cleanup_ok = not cleanup_failures
            except Exception as failure:
                cleanup_failures.append('unmount: '+type(failure).__name__+': '+str(failure))
        elif mount_attempted:
            cleanup_failures.append('mount ownership was not established; automatic unmount refused')
        try:
            run('host-digests-after', 'md5sum -c -', checksums)
            host_unchanged = True
        except Exception as failure:
            cleanup_failures.append('host hashes: '+type(failure).__name__+': '+str(failure))
        try:
            after = run('after', status_command).stdout.decode()
            boot_and_guards_after = idle_state(after) and 'BE6L_HEARTBEAT '+a.expected_boot_id+' ' in after
            if not boot_and_guards_after:
                raise ValueError('Post-test boot/MTD/NPU/heartbeat differs')
        except Exception as failure:
            cleanup_failures.append('postconditions: '+type(failure).__name__+': '+str(failure))
    passed = (error is None and not cleanup_failures and cleanup_ok and host_unchanged and
              boot_and_guards_after and exit_code == 0 and set(cases) == CASES and
              all(item['passed'] for item in cases.values()))
    report = dict(boot_id=a.expected_boot_id, fit_sha256=image['image_sha256'],
        guest_interp_revision=2, dispatch_failures_terminal=True, guest_exe_contract=CONTRACT,
        source_stage_receipt_sha256=sha(a.stage/'result.json'),
        source_candidate_receipt_sha256=sha(a.candidate/'result.json'),
        source_qualification_receipt_sha256=sha(qualified_paths[0]),
        source_corner_probe_receipt_sha256=sha(a.corner_probe/'result.json'),
        source_native_probe_receipt_sha256=sha(a.native_probe/'result.json'),
        source_emulator_receipt_sha256=sha(a.emulator_package/'result.json'),
        flags='POFX', own_rule_name=name, own_mount_id=own_mount_id,
        cases=cases, expected_case_count=4, native_exit_code=exit_code,
        all_inode_cases_and_postconditions_passed=passed,
        rule_unregistered_and_mount_removed=cleanup_ok, cleanup_failures=cleanup_failures,
        host_payloads_unchanged=host_unchanged, boot_and_guards_preserved=boot_and_guards_after,
        error=error, secureexec_covered=False, target_executed=True,
        flash_operations=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('NATIVE_LOADER_INODE_CASES_RECORDED', json.dumps(report), flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
