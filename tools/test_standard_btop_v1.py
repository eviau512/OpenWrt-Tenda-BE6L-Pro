# SPDX-License-Identifier: MIT
"""Bounded real standard-A53 btop TUI workload using the staged private emulator.

Uses strict SSH with a remote PTY. All configuration/logs are in the owned RAM
fixture; no binfmt rule, flash operation or host-network change is performed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess
import time
import uuid
from recovery.ssh_heartbeat import target


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('stage', 'identity', 'known-hosts', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--host', type=target, required=True)
    p.add_argument('--expected-boot-id', type=lambda s: str(uuid.UUID(s)), required=True)
    p.add_argument('--native-pty-harness', type=Path,
                   help='Admitted static ARM32 PTY fixture; avoids SSH PTY permissions')
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not re.fullmatch('be6l-standard-btop-[a-z0-9-]+', w.name) or w.exists():
        p.error('Use a fresh /root/be6l-standard-btop-* directory')
    staged = json.loads((a.stage/'result.json').read_text())
    if (staged['boot_id'] != a.expected_boot_id or not staged['guest_payload_digests_verified'] or
            not staged['single_process_standard_package_controls_passed'] or
            not re.fullmatch('/tmp/be6l-binfmt-stage-[a-z0-9-]+', staged['remote']) or
            staged['interpreter'] != '/usr/libexec/be6l/qemu-aarch64'):
        raise ValueError('Wrong qualified standard package fixture')
    w.mkdir(mode=0o700)
    ssh = ['ssh', '-i', str(a.identity), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile='+str(a.known_hosts),
        '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1']
    prefix = 'grep -qx '+a.expected_boot_id+' /proc/sys/kernel/random/boot_id && '
    remote, guest = staged['remote'], staged['guest_root']
    if guest != remote+'/guest':
        raise ValueError('Unexpected guest root path')
    def run(label, command, data=None, tty=False, timeout=30):
        r = subprocess.run(ssh+['-tt' if tty else '-T', 'root@'+a.host, prefix+command],
            input=data, capture_output=True, timeout=timeout)
        (w/(label+'.stdout')).write_bytes(r.stdout)
        (w/(label+'.stderr')).write_bytes(r.stderr)
        return r
    before = run('before', 'cat /proc/uptime; grep MemAvailable /proc/meminfo; '
        '/usr/sbin/be6l-recovery-guard heartbeat; cat /sys/kernel/debug/1e900000.npu/status')
    if before.returncode or b'ppe=0 tdma=0' not in before.stdout:
        raise ValueError('Target NPU/SSH precondition changed')
    config = b'tty_mode = true\ntruecolor = false\nupdate_ms = 1000\nshown_boxes = "cpu mem proc"\ncheck_temp = false\n'
    setup = run('configuration', 'cat >'+remote+'/btop-live.conf', config)
    if setup.returncode:
        raise ValueError('Could not create owned RAM-only configuration')
    if a.native_pty_harness:
        data = a.native_pty_harness.read_bytes()
        if (len(data) < 52 or data[:7] != b'\x7fELF\x01\x01\x01' or
                struct.unpack_from('<HH',data,16) != (2,40) or
                struct.unpack_from('<I',data,36)[0] & 0x400):
            raise ValueError('Expected native ARM32 soft-float ET_EXEC harness')
        phoff = struct.unpack_from('<I',data,28)[0]
        stride,count = struct.unpack_from('<HH',data,42)
        if stride < 32 or not count or phoff+stride*count > len(data) or any(
                struct.unpack_from('<I',data,phoff+i*stride)[0] in (2,3) for i in range(count)):
            raise ValueError('Native harness must be a complete static ELF without a dynamic interpreter')
        uploaded = run('upload-harness', 'cat >'+remote+'/native-pty-harness', data)
        checked = run('check-harness', 'md5sum -c -',
            (hashlib.md5(data).hexdigest()+'  '+remote+'/native-pty-harness\n').encode())
        mode = run('harness-mode', 'chmod 700 '+remote+'/native-pty-harness')
        if uploaded.returncode or checked.returncode or mode.returncode:
            raise ValueError('Native RAM harness transfer failed')
    started = time.monotonic()
    command = ('stty cols 120 rows 40 && TERM=xterm-256color HOME='+remote+
        ' timeout -s INT 12 '+staged['interpreter']+' -L '+guest+' '+guest+
        '/usr/bin/btop --tty --force-utf -u 1000 -c '+remote+'/btop-live.conf')
    if a.native_pty_harness:
        command = ('TERM=xterm-256color HOME='+remote+' '+remote+'/native-pty-harness 12 '+
            staged['interpreter']+' -L '+guest+' '+guest+
            '/usr/bin/btop --tty --force-utf -u 1000 -c '+remote+'/btop-live.conf')
    result = run('tui', command, tty=not bool(a.native_pty_harness), timeout=30)
    elapsed = time.monotonic()-started
    output = result.stdout.decode(errors='replace')
    plain = re.sub(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))', '', output)
    alternate_screen = '\x1b[?1049h' in output
    labels = {name: name.lower() in plain.lower() for name in ('cpu', 'mem', 'pid')}
    after = run('after', 'cat /proc/uptime; grep MemAvailable /proc/meminfo; '
        '/usr/sbin/be6l-recovery-guard heartbeat; cat /sys/kernel/debug/1e900000.npu/status')
    normal_exit = (result.returncode == 0 and b'interrupted=1 forced=0 wait_status=0' in result.stderr) if a.native_pty_harness else result.returncode == 124
    passed = (normal_exit and 11 <= elapsed < 30 and alternate_screen and
        all(labels.values()) and len(result.stdout) > 4096 and after.returncode == 0)
    report = dict(boot_id=a.expected_boot_id, source_stage_receipt_sha256=hashlib.sha256((a.stage/'result.json').read_bytes()).hexdigest(),
        standard_a53_signed_btop=True, elapsed_seconds=round(elapsed, 2), exit=result.returncode,
        remote_pty=True, ssh_pty_requested=not bool(a.native_pty_harness),
        native_pty_harness_sha256=hashlib.sha256(a.native_pty_harness.read_bytes()).hexdigest() if a.native_pty_harness else None,
        alternate_screen_entered=alternate_screen, displayed_labels=labels,
        output_bytes=len(result.stdout), bounded_tui_workload_passed=passed,
        software_emulation=True, native_fp_support=False, binfmt_registered=False,
        flash_operations=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('STANDARD_BTOP_TUI_RECORDED', json.dumps(report), flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
