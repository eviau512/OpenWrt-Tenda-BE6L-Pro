# SPDX-License-Identifier: MIT
"""Prepare cached-only private netifd fixture and audited namespace launcher."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
from a64_soft_context import BASE,SDK,EPOCH

parser=argparse.ArgumentParser()
parser.add_argument('--build-root',type=Path,required=True)
args=parser.parse_args()
root=args.build_root
artifact=BASE/'artifacts/a64-soft-netifd'
manifest=json.loads((artifact/'manifest.json').read_text())
assert manifest['dependency_closure_audited'] and manifest['real_linux_netlink_backend']
contents={}
with tarfile.open(artifact/'netifd.tar') as tar:
    assert len(tar.getmembers())==len(manifest['files'])
    for p in tar:
        assert p.isfile() and p.name in manifest['files']
        data=tar.extractfile(p).read()
        assert hashlib.sha256(data).hexdigest()==manifest['files'][p.name]['sha256']
        contents['opt/be6l-a64-soft/bin/netifd' if p.name=='netifd' else 'lib/aarch64-soft/'+p.name]=data
core=BASE/'artifacts/a64-soft-core'
core_manifest=json.loads((core/'manifest.json').read_text())
for name in ('ubusd','ubus'):
    data=(core/name).read_bytes()
    assert hashlib.sha256(data).hexdigest()==core_manifest[name]['sha256']
    contents['opt/be6l-a64-soft/bin/'+name]=data
    assert all('lib/aarch64-soft/'+dep in contents for dep in core_manifest[name]['needed'])
baseline=Path('/root/be6l-openwrt/compat-apk-root/root')
contents['bin/busybox']=(baseline/'bin/busybox').read_bytes()
links={'bin/sh':'busybox','lib/ld-musl-aarch64-soft.so.1':'aarch64-soft/libc.so'}
for p in (baseline/'lib').glob('*.so*'):
    if p.is_symlink():
        assert not str(p.readlink()).startswith('/')
        links['lib/'+p.name]=str(p.readlink())
    elif p.is_file():contents['lib/'+p.name]=p.read_bytes()
for name in ('true','false','cat','sleep','ls','readlink','kill','mkdir','ip','grep'):
    links['bin/'+name]='busybox'
contents['etc/ld-musl-aarch64-soft.path']=b'/lib/aarch64-soft\n'
contents['etc/passwd']=b'root:x:0:0:Synthetic fixture:/:/bin/sh\n'
contents['etc/group']=b'root:x:0:\n'
contents['etc/config/network']=b"config interface 'fixture'\n option device 'lo'\n option proto 'static'\n option ipaddr '127.0.0.2/8'\n"
contents['probe.sh']=b'''#!/bin/sh
set -eu
test "$(ls /sys/class/net)" = lo
test "$(cat /proc/1/comm)" = sh
echo PRIVATE_NETNS=$(readlink /proc/self/ns/net)
echo PRIVATE_PIDNS=$(readlink /proc/self/ns/pid)
ubusd -s /var/run/ubus/ubus.sock > /tmp/ubusd.log 2>&1 &
ubusd_pid=$!
netifd_pid=
cleanup() {
 echo PRIVATE_DAEMON_LOGS
 cat /tmp/netifd.log 2>/dev/null || true
 cat /tmp/ubusd.log 2>/dev/null || true
 test -z "$netifd_pid" || kill "$netifd_pid" 2>/dev/null || true
 kill "$ubusd_pid" 2>/dev/null || true
 wait 2>/dev/null || true
}
trap cleanup EXIT
for n in 1 2 3 4 5; do test -S /var/run/ubus/ubus.sock && break; sleep 1; done
test -S /var/run/ubus/ubus.sock
netifd -s /var/run/ubus/ubus.sock -p /lib/netifd -c /etc/config -h /bin/true -r /tmp/resolv.conf -S -l 4 > /tmp/netifd.log 2>&1 &
netifd_pid=$!
for n in 1 2 3 4 5 6 7 8; do
 if ubus -s /var/run/ubus/ubus.sock call network.interface.fixture status > /tmp/status.json 2>/dev/null && grep -q '"up": true' /tmp/status.json; then break; fi
 sleep 1
done
echo INITIAL_STATUS
cat /tmp/status.json
ip -4 -o addr show lo
ubus -s /var/run/ubus/ubus.sock call network.interface.fixture down
for n in 1 2 3 4 5; do
 ubus -s /var/run/ubus/ubus.sock call network.interface.fixture status > /tmp/down.json
 grep -q '"up": false' /tmp/down.json && break
 sleep 1
done
echo DOWN_STATUS
cat /tmp/down.json
ubus -s /var/run/ubus/ubus.sock call network.interface.fixture up
for n in 1 2 3 4 5; do
 ubus -s /var/run/ubus/ubus.sock call network.interface.fixture status > /tmp/up.json
 grep -q '"up": true' /tmp/up.json && break
 sleep 1
done
echo RESTORED_STATUS
cat /tmp/up.json
test "$(ls /sys/class/net)" = lo
kill -0 "$netifd_pid"
echo PRIVATE_NATIVE_NETIFD_LIFECYCLE_DONE
'''
for name in ('dev/null','dev/random','dev/urandom'):contents[name]=b''
dirs=('proc','sys','tmp','etc/config','lib/netifd/proto','lib/netifd/device','var/run/ubus')
with tarfile.open(artifact/'namespace-fixture.tar','w') as tar:
    for name in dirs:
        info=tarfile.TarInfo(name);info.type=tarfile.DIRTYPE;info.mode=0o755;info.mtime=int(EPOCH);tar.addfile(info)
    for name,data in contents.items():
        info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o755 if '/bin/' in '/'+name or name.endswith('.sh') or '.so' in name else 0o644;info.mtime=int(EPOCH)
        tar.addfile(info,io.BytesIO(data))
    for name,target in links.items():
        info=tarfile.TarInfo(name);info.type=tarfile.SYMTYPE;info.linkname=target;info.mtime=int(EPOCH);tar.addfile(info)
runner=artifact/'namespace-runner'
subprocess.run([str(root/'softcc'),'-static','-O2','-Wall','-Wextra','-Werror',
                str(BASE/'diagnostics/a64_private_netifd_runner.c'),'-o',str(runner)],check=True)
gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
dis=subprocess.check_output([str(gcc)[:-3]+'objdump','-d',str(runner)],text=True)
for line in dis.splitlines():
    if '\t' not in line:continue
    ins=line.split('\t',2)[-1]
    if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):continue
    assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins),ins
proof={name:hashlib.sha256((artifact/name).read_bytes()).hexdigest() for name in ('namespace-fixture.tar','namespace-runner')}
(artifact/'namespace-fixture.json').write_text(json.dumps(proof,indent=2)+'\n')
print('PRIVATE_REAL_NETIFD_FIXTURE_AND_STATIC_RUNNER_AUDITED',flush=True)
