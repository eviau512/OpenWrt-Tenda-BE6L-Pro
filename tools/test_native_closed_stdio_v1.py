# SPDX-License-Identifier: MIT
"""Run only sixteen closed-stdio cases in owned isolated RAM fixtures.

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
from build_native_closed_stdio_probe_v1 import program_types

CONTRACT = 'BE6L_X_EXECFD_EXE_INTERPFD_V2'
INTERPRETER = '/usr/libexec/be6l/qemu-aarch64'
R5_PACKAGE = '253fc682636d2d40b1e6c016317704b21452c74cc2540d1bffd32223adfa5928'
R5_INTERPRETER = '7e094b445e34d353c47b91cddde062ce2e2d344678813da5e22b9993953d720d'
NATIVE = 'native-closed-stdio'
DYNAMIC = 'be6l-closed-stdio-dynamic'
STATIC = 'be6l-closed-stdio-static-synthetic'
CASES = {kind+'-'+mode+'-close'+str(mask)
         for kind in ('dynamic', 'synthetic-static')
         for mode in ('execve', 'execveat-cloexec') for mask in (1, 2, 4, 7)}


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
    for name in ('stage', 'candidate', 'composition', 'emulator-package',
                 'native-probe', 'identity', 'known-hosts', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--host', type=target, required=True)
    p.add_argument('--expected-boot-id', type=lambda s: str(uuid.UUID(s)), required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-native-closed-stdio-test-[a-z0-9-]+', w.name) or w.exists():
        p.error('Use a fresh /root/be6l-native-closed-stdio-test-* directory')
    load = lambda directory: json.loads((directory/'result.json').read_text())
    staged, image, composition, emulator, native = map(load, (
        a.stage, a.candidate, a.composition, a.emulator_package, a.native_probe))
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
    if (not native.get('native_arm32') or not native.get('native_static') or
            native.get('native_vfp_neon_instruction_count') != 0 or native.get('expected_case_count') != 16 or
            native.get('close_masks') != [1, 2, 4, 7] or
            native.get('exec_modes') != ['execve', 'execveat-empty-cloexec'] or
            native.get('report_pipe_min_fd') != 3 or native.get('private_fd_alias_scan_limit') != 256 or
            not native.get('dynamic_fixture_requires_verified_standard_guest_runtime') or
            native.get('static_standard_package_abi_qualified') is not False or
            not native.get('isolated_fixture_only') or not native.get('existing_loader_bytes_unchanged') or
            native.get('secureexec_covered') is not False or
            set(native.get('files', {})) != {NATIVE, DYNAMIC, STATIC} or
            '-nostdlib' not in native.get('commands', {}).get(STATIC, [])):
        raise ValueError('Closed-stdio native/dynamic/synthetic-static fixture receipt differs')
    artifacts = {name: a.native_probe/name for name in (NATIVE, DYNAMIC, STATIC)}
    for name, file in artifacts.items():
        data = file.read_bytes()
        record = native['files'][name]
        if sha(file) != record.get('sha256') or len(data) != record.get('size'):
            raise ValueError('Closed-stdio artifact hash/size differs: '+name)
        if name == NATIVE:
            if not static_arm32(data):
                raise ValueError('Parent is not a static ARM32 ELF')
        else:
            if not matches(data[:64]):
                raise ValueError('Guest fixture is not unmarked A64 ELF')
            types = program_types(data)
            if name == DYNAMIC and types.count(3) != 1:
                raise ValueError('Dynamic fixture requires one PT_INTERP')
            if name == STATIC and (2 in types or 3 in types):
                raise ValueError('Synthetic static fixture links an interpreter/runtime')
        if program_types(data, name == NATIVE) != record.get('program_types'):
            raise ValueError('Fixture program headers differ from build receipt')
    source_dir = Path(__file__).resolve().parents[1]/'experiments/qemu-integer-host'
    if set(native.get('source_sha256', {})) != {'native-closed-stdio.c', 'closed-stdio-a64.c', 'closed-stdio-wire.h'}:
        raise ValueError('Incomplete closed-stdio source inventory')
    for name, digest in native['source_sha256'].items():
        if sha(source_dir/name) != digest:
            raise ValueError('Closed-stdio source changed since compilation: '+name)
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
    remote = guest.rsplit('/', 1)[0]+'/closedstdio-'+token
    guest_relative = '/tmp/closedstdio-'+token
    guest_files = guest+guest_relative
    remote_native = remote+'/'+NATIVE
    aliases = {guest+'/bin/'+name: guest_relative+'/'+name for name in (DYNAMIC, STATIC)}
    name = 'be6l-closedstdio-'+token
    entry_path = '/proc/sys/fs/binfmt_misc/'+name
    magic, mask = rule_bytes()
    escaped = lambda value: ''.join('\\x%02x' % byte for byte in value).encode()
    rule = b':'+name.encode()+b':M::'+escaped(magic)+b':'+escaped(mask)+b':'+INTERPRETER.encode()+b':POFX\n'
    expected_entry = ('enabled\n', 'interpreter '+INTERPRETER+'\n', 'flags: POFX\n',
                      'magic '+magic.hex()+'\n', 'mask '+mask.hex()+'\n')
    owns_entry = lambda value: all(part in value for part in expected_entry)
    own_mount_id = None
    mount_attempted = registration_attempted = cleanup_ok = False
    upload_attempted = False
    alias_attempted = []
    fixture_cleanup_ok = host_unchanged = boot_and_guards_after = False
    cases, cleanup_failures = {}, []
    error = None
    exit_code = None
    summary = None
    try:
        upload_attempted = True
        run('own-upload-directories', 'test ! -e '+remote+' && test ! -L '+remote+
            ' && mkdir -m700 '+remote+' && test ! -e '+guest_files+' && test ! -L '+guest_files+
            ' && mkdir -m700 '+guest_files)
        for artifact, file in artifacts.items():
            destination = remote_native if artifact == NATIVE else guest_files+'/'+artifact
            run('upload-'+artifact, 'set -C; cat >'+destination, file.read_bytes())
            run('verify-'+artifact, 'md5sum -c -',
                (hashlib.md5(file.read_bytes()).hexdigest()+'  '+destination+'\n').encode())
            run('mode-'+artifact, 'chmod 555 '+destination)
        # Native C reads these fixed, test-only names. Never replace a node.
        # Payloads themselves stay in the unique guest /tmp fixture directory.
        for alias, destination in aliases.items():
            alias_attempted.append(alias)
            run('alias-'+Path(alias).name, 'test ! -e '+alias+' && test ! -L '+alias+
                ' && ln -s '+destination+' '+alias)
            if run('verify-alias-'+Path(alias).name, 'readlink '+alias).stdout.decode().strip() != destination:
                raise ValueError('Own fixture alias target differs')
        run('host-digests-before-activation', 'md5sum -c -', checksums)
        if not idle_state(run('guards-before-activation', status_command).stdout.decode()):
            raise ValueError('MTD/NPU guards changed before activation')
        mount_attempted = True
        run('mount', 'mount -t binfmt_misc -o nodev,nosuid,noexec binfmt_misc /proc/sys/fs/binfmt_misc')
        own_mount_id = mount_id(run('mountinfo-owned', 'cat /proc/self/mountinfo').stdout.decode())
        if own_mount_id is None:
            raise ValueError('Cannot identify this run binfmt mount')
        if sorted(run('registry-empty', 'ls /proc/sys/fs/binfmt_misc').stdout.decode().splitlines()) != ['register', 'status']:
            raise ValueError('Refuse nonempty dispatch registry')
        (w/'registration.txt').write_bytes(rule)
        registration_attempted = True  # Lost SSH status can follow a successful write.
        run('register', 'cat >/proc/sys/fs/binfmt_misc/register', rule)
        if not owns_entry(run('entry', 'cat '+entry_path).stdout.decode()):
            raise ValueError('Kernel registered different POFX semantics')
        result = run('native-closed-stdio-sixteen-cases', 'timeout -s KILL 90 '+remote_native+' '+guest,
                     timeout=110, good=False)
        exit_code = result.returncode
        output = result.stdout.decode()
        rows = re.findall(r'^NATIVE_CLOSED_STDIO (\S+) (PASS|FAIL) (.*)$', output, re.M)
        for case, state, observations in rows:
            fields = dict(item.split('=', 1) for item in observations.split())
            cases[case] = dict(passed=state == 'PASS', observations=observations,
                expected_closed_mask=int(fields['expected_mask']), report_fd=int(fields['report_fd']),
                stdio_flags=[int(x) for x in fields['guest_flags'].split('/')],
                stdio_errno=[int(x) for x in fields['guest_errno'].split('/')],
                program_loader_fd_aliases=[int(x) for x in fields['aliases'].split('/')],
                private_aux_entries_flags=[int(x) for x in fields['private_aux'].split('/')],
                exec_errno=int(fields['exec_errno']), wait_status=int(fields['wait_status']),
                parent_fd_counts=[int(x) for x in fields['parent_fds'].split('/')],
                after_exit_write_errno=[int(x) for x in fields['after_write_errno'].split('/')],
                interrupted_signal=int(fields['signal']),
                original_stdio_inodes_preserved=state == 'PASS')
        matched = re.search(r'^NATIVE_CLOSED_STDIO_SUMMARY cases=(\d+) failures=(\d+) cleanup_errors=(\d+) static_fixture_synthetic=1 secureexec_covered=0$', output, re.M)
        if matched:
            summary = dict(cases=int(matched[1]), failures=int(matched[2]), cleanup_errors=int(matched[3]))
        if (exit_code != 0 or len(rows) != 16 or set(cases) != CASES or
                not all(item['passed'] for item in cases.values()) or
                summary != dict(cases=16, failures=0, cleanup_errors=0)):
            raise RuntimeError('Closed-stdio cases did not all pass')
    except Exception as failure:
        error = type(failure).__name__+': '+str(failure)
    finally:
        # A unique rule is queried even when the registration SSH result was lost.
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
                if sorted(run('registry-cleanup', 'ls /proc/sys/fs/binfmt_misc').stdout.decode().splitlines()) != ['register', 'status']:
                    raise ValueError('Dispatch registry is not empty; refuse unmount')
                run('unmount', 'umount /proc/sys/fs/binfmt_misc')
                if mount_id(run('mountinfo-after', 'cat /proc/self/mountinfo').stdout.decode()) is not None:
                    raise ValueError('binfmt mount remains after cleanup')
                cleanup_ok = not cleanup_failures
            except Exception as failure:
                cleanup_failures.append('unmount: '+type(failure).__name__+': '+str(failure))
        elif mount_attempted:
            cleanup_failures.append('mount ownership was not established; automatic unmount refused')
        # Fixed entry names can be removed only while they still point to this
        # run's unique directory. No original package payload is overwritten.
        for alias in alias_attempted:
            try:
                value = run('inspect-alias-cleanup-'+Path(alias).name,
                    'if test -L '+alias+'; then readlink '+alias+
                    '; elif test ! -e '+alias+'; then echo ABSENT; else echo FOREIGN; fi').stdout.decode().strip()
                if value == aliases[alias]:
                    run('remove-alias-'+Path(alias).name, 'rm '+alias)
                elif value != 'ABSENT':
                    raise ValueError('Fixture alias ownership changed; refuse removal')
            except Exception as failure:
                cleanup_failures.append('fixture alias: '+type(failure).__name__+': '+str(failure))
        if upload_attempted:
            try:
                # Unique empty-or-owned directories, explicit known filenames,
                # nonrecursive rmdir; no deletion outside this run's RAM paths.
                for directory, names in ((guest_files, (DYNAMIC, STATIC)), (remote, (NATIVE,))):
                    for artifact in names:
                        file = directory+'/'+artifact
                        run('remove-upload-'+artifact, 'if test -f '+file+' && test ! -L '+file+
                            '; then rm '+file+'; elif test ! -e '+file+' && test ! -L '+file+'; then :; else exit 3; fi')
                    run('remove-own-directory-'+('guest' if directory == guest_files else 'native'),
                        'if test -d '+directory+' && test ! -L '+directory+'; then rmdir '+directory+
                        '; elif test ! -e '+directory+' && test ! -L '+directory+'; then :; else exit 3; fi')
                fixture_cleanup_ok = True
            except Exception as failure:
                cleanup_failures.append('fixture files: '+type(failure).__name__+': '+str(failure))
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
    passed = (error is None and not cleanup_failures and cleanup_ok and fixture_cleanup_ok and host_unchanged and
              boot_and_guards_after and exit_code == 0 and set(cases) == CASES and
              all(item['passed'] for item in cases.values()))
    report = dict(boot_id=a.expected_boot_id, fit_sha256=image['image_sha256'],
        guest_interp_revision=2, dispatch_failures_terminal=True, guest_exe_contract=CONTRACT,
        source_stage_receipt_sha256=sha(a.stage/'result.json'),
        source_candidate_receipt_sha256=sha(a.candidate/'result.json'),
        source_qualification_receipt_sha256=sha(qualified_paths[0]),
        source_native_probe_receipt_sha256=sha(a.native_probe/'result.json'),
        source_emulator_receipt_sha256=sha(a.emulator_package/'result.json'),
        flags='POFX', own_rule_name=name, own_mount_id=own_mount_id,
        cases=cases, expected_case_count=16, native_exit_code=exit_code, native_summary=summary,
        all_stdio_cases_and_postconditions_passed=passed,
        rule_unregistered_and_mount_removed=cleanup_ok, cleanup_failures=cleanup_failures,
        own_fixture_aliases_and_files_removed=fixture_cleanup_ok,
        host_payloads_unchanged=host_unchanged, boot_and_guards_preserved=boot_and_guards_after,
        static_fixture_synthetic=True, static_standard_package_abi_qualified=False,
        error=error, secureexec_covered=False, target_executed=True,
        flash_operations=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('NATIVE_CLOSED_STDIO_CASES_RECORDED', json.dumps(report), flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
