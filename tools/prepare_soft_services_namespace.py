# SPDX-License-Identifier: MIT
"""Build a loopback-only native web/RPC fixture using synthetic credentials."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import re
import secrets
import subprocess
import tarfile
from a64_soft_context import BASE,SDK,EPOCH

parser=argparse.ArgumentParser()
parser.add_argument('--build-root',type=Path,required=True)
parser.add_argument('--first-root',type=Path,required=True)
args=parser.parse_args()
root=args.build_root
art=BASE/'artifacts/a64-soft-services'
manifest=json.loads((art/'manifest.json').read_text())
first=json.loads((args.first_root/'audited/manifest.json').read_text())
assert first['files']==manifest['files'] and first['source_hashes']==manifest['source_hashes']
(BASE/'logs/soft-services-reproduction.json').write_text(json.dumps(dict(
    files=len(manifest['files']),all_output_hashes_identical=True,source_hash_maps_identical=True),indent=2)+'\n')
contents={}
with tarfile.open(art/'services.tar') as tar:
    assert len(tar.getmembers())==len(manifest['files'])
    for item in tar:
        assert item.isfile() and item.name in manifest['files']
        data=tar.extractfile(item).read()
        assert hashlib.sha256(data).hexdigest()==manifest['files'][item.name]['sha256']
        if item.name.startswith('plugins/'):
            target='usr/lib/rpcd/'+item.name.split('/')[1]
        elif item.name.startswith('uhttpd_'):
            target='usr/lib/'+item.name
        elif '.so' in item.name:
            target='lib/aarch64-soft/'+item.name
        else:target='opt/be6l-a64-soft/bin/'+item.name
        contents[target]=data
baseline=Path('/root/be6l-openwrt/compat-apk-root/root')
contents['bin/busybox']=(baseline/'bin/busybox').read_bytes()
links={'bin/sh':'busybox','lib/ld-musl-aarch64-soft.so.1':'aarch64-soft/libc.so',
       'lib/libustream-ssl.so':'aarch64-soft/libustream-ssl.so',
       'var/run/ubus.sock':'ubus/ubus.sock'}
for p in (baseline/'lib').glob('*.so*'):
    if p.is_symlink():
        assert not str(p.readlink()).startswith('/')
        links['lib/'+p.name]=str(p.readlink())
    elif p.is_file():contents['lib/'+p.name]=p.read_bytes()
for name in ('true','false','cat','sleep','ls','readlink','kill','mkdir','ip','grep','sha256sum','printf','cmp'):
    links['bin/'+name]='busybox'
contents['etc/ld-musl-aarch64-soft.path']=b'/lib/aarch64-soft\n/usr/lib\n'
contents['etc/passwd']=b'root:x:0:0:Synthetic fixture:/:/bin/sh\n'
contents['etc/group']=b'root:x:0:\n'
password=secrets.token_hex(24)
hashed=subprocess.check_output(['openssl','passwd','-6','-stdin'],input=(password+'\n').encode()).strip().decode()
assert hashed.startswith('$6$')
contents['etc/config/rpcd']=("config login\n option username 'root'\n option password '"+hashed+"'\n list read 'fixture'\n").encode()
contents['etc/config/fixture']=b"config example 'test'\n option answer 'native-soft64'\n"
acl={'unauthenticated':{'read':{'ubus':{'session':['login']}}},
     'fixture':{'read':{'ubus':{'uci':['get']},'uci':['fixture']}}}
contents['usr/share/rpcd/acl.d/fixture.json']=json.dumps(acl).encode()
contents['tmp/login-request.json']=json.dumps(dict(jsonrpc='2.0',id=1,method='call',
    params=['0'*32,'session','login',dict(username='root',password=password)])).encode()
contents['tmp/wrong-login.json']=json.dumps(dict(jsonrpc='2.0',id=1,method='call',
    params=['0'*32,'session','login',dict(username='root',password='incorrect-synthetic-fixture-password')])).encode()
payload=secrets.token_bytes(128*1024)
contents['www/payload.bin']=payload
contents['www/cgi-bin/probe']=b'#!/bin/sh\nprintf \'Content-Type: application/json\\r\\n\\r\\n{"cgi":true}\\n\'\n'
contents['handler.lua']=b'''function handle_request(env)
 assert(math.pow(4,0.5)==2)
 uhttpd.send("Status: 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n")
 uhttpd.send('{"lua_soft64":true,"sqrt":2}')
end
'''
contents['handler.uc']=b'''{%
global.handle_request = function(env) {
 assert(3.25 + 0.75 == 4);
 uhttpd.send("Status: 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n");
 uhttpd.send('{"ucode_soft64":true}');
};
%}
'''
certdir=root/('fixture-certificate-'+secrets.token_hex(8));certdir.mkdir()
cert,key=certdir/'certificate.pem',certdir/'key.pem'
assert not cert.exists() and not key.exists(), 'Use fresh certificate fixture outputs'
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256',
    '-days','2','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost',
    '-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
contents['etc/test-cert.pem']=cert.read_bytes();contents['etc/test-key.pem']=key.read_bytes()
contents['etc/unrelated-ca.pem']=(baseline/'etc/ssl/certs/ca-certificates.crt').read_bytes()
key.unlink()
contents['probe.sh']=b'''#!/bin/sh
set -eu
test "$(ls /sys/class/net)" = lo
test "$(cat /proc/1/comm)" = sh
echo PRIVATE_NETNS=$(readlink /proc/self/ns/net)
echo PRIVATE_PIDNS=$(readlink /proc/self/ns/pid)
ip link set lo up
ubusd -s /var/run/ubus/ubus.sock > /tmp/ubusd.log 2>&1 &
ubusd_pid=$!
rpcd_pid= httpd_pid=
cleanup() {
 echo PRIVATE_DAEMON_LOGS
 for name in ubusd rpcd uhttpd; do cat /tmp/$name.log 2>/dev/null || true; done
 test -z "$httpd_pid" || kill "$httpd_pid" 2>/dev/null || true
 test -z "$rpcd_pid" || kill "$rpcd_pid" 2>/dev/null || true
 kill "$ubusd_pid" 2>/dev/null || true
 wait 2>/dev/null || true
}
trap cleanup EXIT
for n in 1 2 3 4 5; do test -S /var/run/ubus/ubus.sock && break; sleep 1; done
rpcd -s /var/run/ubus/ubus.sock > /tmp/rpcd.log 2>&1 &
rpcd_pid=$!
for n in 1 2 3 4 5; do ubus -s /var/run/ubus/ubus.sock list session | grep -q session && break; sleep 1; done
uhttpd -f -p 127.0.0.1:18880 -s 127.0.0.1:18881 -h /www -C /etc/test-cert.pem -K /etc/test-key.pem -U /var/run/ubus/ubus.sock -u /ubus -l /lua -L /handler.lua -o /ucode -O /handler.uc > /tmp/uhttpd.log 2>&1 &
httpd_pid=$!
sleep 1
curl -q --noproxy '*' --fail --max-time 5 --cacert /etc/test-cert.pem -sS https://127.0.0.1:18881/payload.bin -o /tmp/received.bin
cmp /www/payload.bin /tmp/received.bin
echo TLS_PAYLOAD_SHA256
sha256sum /tmp/received.bin
if curl -q --noproxy '*' --fail --max-time 5 --cacert /etc/unrelated-ca.pem -sS https://127.0.0.1:18881/payload.bin -o /tmp/untrusted.bin 2>/tmp/untrusted-error.txt; then exit 1; else rc=$?; echo TLS_UNTRUSTED_EXIT=$rc; test "$rc" = 60; fi
echo TLS_UNTRUSTED_REJECTED_60
curl -q --noproxy '*' --fail --max-time 5 -sS http://127.0.0.1:18880/lua > /tmp/lua.json
curl -q --noproxy '*' --fail --max-time 5 -sS http://127.0.0.1:18880/ucode > /tmp/ucode.json
curl -q --noproxy '*' --fail --max-time 5 -sS http://127.0.0.1:18880/cgi-bin/probe > /tmp/cgi.json
echo LUA_RESULT; cat /tmp/lua.json; echo
echo UCODE_RESULT; cat /tmp/ucode.json; echo
echo CGI_RESULT; cat /tmp/cgi.json; echo
request() { curl -q --noproxy '*' --fail --max-time 5 -sS -H 'Content-Type: application/json' --data-binary @"$1" http://127.0.0.1:18880/ubus; }
request /tmp/wrong-login.json > /tmp/wrong.json
request /tmp/login-request.json > /tmp/login.json
sid=$(REPLY="$(cat /tmp/login.json)" ucode -e 'let r=json(getenv("REPLY")); assert(r.result[0]==0); print(r.result[1].ubus_rpc_session);')
test "${#sid}" = 32
printf '{"jsonrpc":"2.0","id":1,"method":"call","params":["00000000000000000000000000000000","uci","get",{"config":"fixture"}]}' > /tmp/anonymous-get.json
request /tmp/anonymous-get.json > /tmp/anonymous.json
printf '{"jsonrpc":"2.0","id":1,"method":"call","params":["%s","uci","get",{"config":"fixture"}]}' "$sid" > /tmp/authorized-get.json
request /tmp/authorized-get.json > /tmp/authorized.json
printf '{"jsonrpc":"2.0","id":1,"method":"call","params":["%s","uci","set",{"config":"fixture","section":"test","values":{"answer":"forbidden"}}]}' "$sid" > /tmp/write-request.json
request /tmp/write-request.json > /tmp/write.json
ubus -s /var/run/ubus/ubus.sock call session destroy "{\\"ubus_rpc_session\\":\\"$sid\\"}"
request /tmp/authorized-get.json > /tmp/revoked.json
for name in wrong anonymous authorized write revoked; do
 echo RPC_RESULT_$name
 cat /tmp/$name.json
 echo
done
kill -0 "$rpcd_pid"
kill -0 "$httpd_pid"
test "$(ls /sys/class/net)" = lo
echo PRIVATE_NATIVE_SERVICES_DONE
'''
for name in ('dev/null','dev/random','dev/urandom'):contents[name]=b''
dirs=('proc','sys','tmp','etc/config','usr/lib/rpcd','usr/share/rpcd/acl.d','usr/share/rpcd/ucode',
      'var/run/ubus','www/cgi-bin')
with tarfile.open(art/'namespace-fixture.tar','w') as tar:
    for name in dirs:
        info=tarfile.TarInfo(name);info.type=tarfile.DIRTYPE;info.mode=0o755;info.mtime=int(EPOCH);tar.addfile(info)
    for name,data in contents.items():
        info=tarfile.TarInfo(name);info.size=len(data)
        info.mode=0o755 if '/bin/' in '/'+name or name.endswith('.sh') or '.so' in name or name.startswith('www/cgi-bin/') else (0o644 if name.startswith('www/') else 0o600)
        info.mtime=int(EPOCH);tar.addfile(info,io.BytesIO(data))
    for name,target in links.items():
        info=tarfile.TarInfo(name);info.type=tarfile.SYMTYPE;info.linkname=target;info.mtime=int(EPOCH);tar.addfile(info)
runner=art/'namespace-runner'
subprocess.run([str(root/'softcc'),'-static','-O2','-Wall','-Wextra','-Werror',
    '-DBE6L_FIXTURE_PREFIX="/tmp/be6l-native-services-"',
    str(BASE/'diagnostics/a64_private_netifd_runner.c'),'-o',str(runner)],check=True)
gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
dis=subprocess.check_output([str(gcc)[:-3]+'objdump','-d',str(runner)],text=True)
for line in dis.splitlines():
    if '\t' not in line:continue
    ins=line.split('\t',2)[-1]
    if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s',ins):continue
    assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b',ins),ins
proof={name:hashlib.sha256((art/name).read_bytes()).hexdigest() for name in ('namespace-fixture.tar','namespace-runner')}
proof['payload_sha256']=hashlib.sha256(payload).hexdigest()
(art/'namespace-fixture.json').write_text(json.dumps(proof,indent=2)+'\n')
print('PRIVATE_NATIVE_SERVICES_FIXTURE_AUDITED; REPRODUCTION_IDENTICAL',len(manifest['files']),flush=True)
