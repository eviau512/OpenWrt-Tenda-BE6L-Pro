# SPDX-License-Identifier: MIT
"""Stage a signed interpreter and unmodified standard runtime on a qualified DUT.

RAM only. Verifies every host A64 ELF marker and standard guest file; executes
single-process guest controls with explicit -L. Never registers a binfmt rule.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shlex
import struct
import subprocess
import tarfile
import uuid
from package_native_netifd_v3 import records, root_digest, sha
from plan_integer_binfmt_v1 import PRIVATE_SOFT_EFLAGS, matches
from recovery.ssh_heartbeat import target


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('candidate', 'composition', 'qualification', 'emulator-package', 'guest',
                 'probe', 'identity', 'known-hosts', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--host', type=target, required=True)
    p.add_argument('--expected-boot-id', type=lambda s: str(uuid.UUID(s)), required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-binfmt-stage-[a-z0-9-]+', w.name) or w.exists():
        p.error('Use a fresh /root/be6l-binfmt-stage-* directory')
    image = json.loads((a.candidate/'result.json').read_text())
    qualified = json.loads((a.qualification/'result.json').read_text())
    guest = json.loads((a.guest/'result.json').read_text())
    emulator = json.loads((a.emulator_package/'result.json').read_text())
    probe = json.loads((a.probe/'result.json').read_text())
    root = a.composition/'root'
    guest_root = a.guest/'root'
    package = a.emulator_package/emulator['package']
    probe_file = a.probe/'be6l-exec-probe'
    if (not qualified['startup_acceptance_passed'] or qualified['boot_id'] != a.expected_boot_id or
            qualified['fit_sha256'] != image['image_sha256'] or not image['integer_binfmt_builtin'] or
            root_digest(root) != image['root_records_sha256'] or not guest['standard_payloads_unmodified'] or
            not guest['normal_signed_standard_package_transaction'] or
            root_digest(guest_root) != guest['root_records_sha256'] or
            not emulator['normal_signed_emulator_package'] or sha(package) != emulator['package_sha256'] or
            sha(probe_file) != probe['elf_sha256'] or not probe['standard_a53_abi']):
        raise ValueError('Incomplete candidate/package/runtime/probe binding')
    if not matches(probe_file.read_bytes()[:64]):
        raise ValueError('Probe is not unmodified standard A53 ELF')
    w.mkdir(mode=0o700)
    ssh = ['ssh', '-T', '-i', str(a.identity), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(a.known_hosts),
           '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1', 'root@'+a.host]

    def run(label, command, data=None, timeout=120):
        command = 'grep -qx '+a.expected_boot_id+' /proc/sys/kernel/random/boot_id && { '+command+'; }'
        r = subprocess.run(ssh+[command], input=data, capture_output=True, timeout=timeout)
        (w/(label+'.log')).write_bytes(r.stdout+r.stderr)
        if r.returncode:
            raise RuntimeError(label+' failed; inspect private log')
        return r.stdout.decode()

    state = run('preflight', 'uname -m; head -n1 /proc/mounts; cat /sys/class/mtd/mtd[0-9]/flags; '
        'cat /sys/kernel/debug/1e900000.npu/status; grep binfmt_misc /proc/filesystems; '
        '/usr/sbin/be6l-recovery-guard heartbeat')
    if (not state.startswith('aarch64\ntmpfs / tmpfs ') or state.splitlines().count('0x0') != 10 or
            'running=0 attached=0 failed=0 stopping=1' not in state or 'ppe=0 tdma=0' not in state or
            'faulted=0 quiesced=0 faults=0' not in state):
        raise ValueError('RAM, NPU or MTD preconditions differ')
    remote = '/tmp/'+w.name
    run('private-ram', 'test ! -e '+remote+' && mkdir -m700 '+remote+
        ' && mount -t tmpfs -o size=96m,mode=0700 tmpfs '+remote)
    capsule = w/'capsule.tar'
    with tarfile.open(capsule, 'w') as archive:
        archive.add(guest_root, arcname='guest')
        archive.add(package, arcname='emulator.apk')
        archive.add(a.emulator_package/'trust', arcname='trust')
        archive.add(probe_file, arcname='guest/bin/be6l-exec-probe')
    run('upload', 'tar -xf - -C '+remote, capsule.read_bytes())
    expected = records(guest_root)
    files = {name: hashlib.md5((guest_root/name).read_bytes()).hexdigest()
             for name, item in expected.items() if 'sha256' in item}
    files['bin/be6l-exec-probe'] = hashlib.md5(probe_file.read_bytes()).hexdigest()
    manifest = ''.join(digest+'  guest/'+name+'\n' for name, digest in sorted(files.items()))
    manifest += hashlib.md5(package.read_bytes()).hexdigest()+'  emulator.apk\n'
    run('upload-digests', 'cat >'+remote+'/md5.list', manifest.encode())
    run('verify-payload', 'cd '+remote+' && md5sum -c md5.list')
    # The base root and guest are distinct; normal APK verifies and installs only the private static interpreter.
    run('install-emulator', 'mkdir -p '+remote+'/cache && '
        'apk --network=no --keys-dir '+remote+'/trust verify '+remote+'/emulator.apk && '
        'apk --network=no --cache=yes --cache-dir '+remote+'/cache --cache-packages=yes '
        '--scripts=no --repositories-file /dev/null --keys-dir '+remote+
        '/trust add '+remote+'/emulator.apk')
    interpreter = '/'+emulator['relative_interpreter_path']
    expected_host = set()
    for path in root.rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open('rb') as incoming:
            header = incoming.read(64)
        if len(header) >= 64 and header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\xb7\0' and struct.unpack_from('<H', header, 16)[0] in (2, 3):
            expected_host.add('/'+path.relative_to(root).as_posix())
    if len(expected_host) != 61:
        raise ValueError('Wrong source private host inventory')
    expected_host.add(interpreter)
    scan = '''for f do printf '%s\t' "$f"; /bin/busybox hexdump -v -n 64 -e '1/1 "%02x"' "$f"; printf '\n'; done'''
    output = run('all-host-elf-headers', 'find /bin /sbin /lib /usr /opt -type f -exec /bin/sh -c '+shlex.quote(scan)+' sh {} +', timeout=180)
    actual_host = set()
    for line in output.splitlines():
        name, encoded = line.split('\t', 1)
        header = bytes.fromhex(encoded)
        if len(header) >= 64 and header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\xb7\0' and struct.unpack_from('<H', header, 16)[0] in (2, 3):
            if matches(header) or struct.unpack_from('<I', header, 48)[0] != PRIVATE_SOFT_EFLAGS:
                raise ValueError('Native host would recurse through binfmt: '+name)
            actual_host.add(name)
    if actual_host != expected_host:
        raise ValueError('Unexpected native host ELF file set')
    run('interpreter-native', interpreter+' --version')
    qemu = interpreter+' -L '+remote+'/guest '
    controls = {}
    for name, command in [('busybox', qemu+remote+'/guest/bin/busybox echo STANDARD_BUSYBOX_OK'),
                          ('ucode', qemu+remote+'/guest/usr/bin/ucode -e '+shlex.quote('print(1.25 + 2.5, "\\n");')),
                          ('btop', qemu+remote+'/guest/usr/bin/btop --version')]:
        controls[name] = run('standard-'+name, command)
    if ('STANDARD_BUSYBOX_OK' not in controls['busybox'] or '3.75' not in controls['ucode'] or
            '1.4.7' not in controls['btop']):
        raise ValueError('Single-process standard package controls failed')
    run('guest-proc', 'mkdir -p '+remote+'/guest/proc '+remote+'/guest/tmp && chmod 1777 '+remote+
        '/guest/tmp && mount -t proc -o nosuid,nodev,noexec proc '+remote+'/guest/proc')
    result = dict(boot_id=a.expected_boot_id, fit_sha256=image['image_sha256'], remote=remote,
        guest_root=remote+'/guest', interpreter=interpreter, marked_host_elf_count=len(actual_host),
        complete_host_elf_inventory_verified=True, native_host_elf_paths=sorted(actual_host),
        guest_payload_digests_verified=True, normal_signed_emulator_installed=True,
        native_interpreter_runs=True, single_process_standard_package_controls_passed=True,
        package_controls=controls, source_guest_receipt_sha256=sha(a.guest/'result.json'),
        source_emulator_receipt_sha256=sha(a.emulator_package/'result.json'),
        source_probe_receipt_sha256=sha(a.probe/'result.json'),
        source_qualification_receipt_sha256=sha(a.qualification/'result.json'),
        binfmt_registered=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print('BINFMT_RAM_RUNTIME_STAGED_RULE_NOT_REGISTERED', len(actual_host), flush=True)


if __name__ == '__main__':
    main()
