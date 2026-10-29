# SPDX-License-Identifier: MIT
"""Prepare an exact, private loopback fixture; never execute it or contact DUT."""
from pathlib import Path
import argparse
import ast
import io
import json
import secrets
import shutil
import subprocess
import tarfile
from a64_soft_context import BASE,EPOCH
from native_services_admission_v1 import SHA,admit,admit_installed

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bundle',type=Path,required=True);a=p.parse_args()
bundle=a.bundle.resolve(); result=json.loads((bundle/'result.json').read_text());root=Path(result['root'])
assert result['passed'] and not result['default_services_promoted']
profile=admit(Path(result['profile_root']),result['profile_lock_sha256']);admit_installed(root,profile)
out=bundle/'isolated-fixture';assert not out.exists();out.mkdir()
contents={name:(root/name).read_bytes() for name in profile['files']}
source_modes={name:(root/name).stat().st_mode & 0o777 for name in contents}
contents['bin/busybox']=(root/'bin/busybox').read_bytes()
source_modes['bin/busybox']=(root/'bin/busybox').stat().st_mode & 0o777
contents['etc/ld-musl-aarch64-soft.path']=(root/'etc/ld-musl-aarch64-soft.path').read_bytes()
links={'bin/sh':'busybox','lib/ld-musl-aarch64-soft.so.1':'aarch64-soft/libc.so','var/run/ubus.sock':'ubus/ubus.sock'}
for path in (root/'lib').glob('*.so*'):
    if path.is_symlink():links['lib/'+path.name]=str(path.readlink())
    elif path.is_file():
        contents['lib/'+path.name]=path.read_bytes()
        source_modes['lib/'+path.name]=path.stat().st_mode & 0o777
for command in ('true','false','cat','sleep','ls','readlink','kill','mkdir','ip','grep','sha256sum','printf','cmp'):
    links['bin/'+command]='busybox'
# Reuse only public literal test code, never old generated passwords/certificates.
tree=ast.parse((BASE/'tools/prepare_soft_services_namespace.py').read_text())
templates={}
for node in tree.body:
    if isinstance(node,ast.Assign) and len(node.targets)==1:
        target=node.targets[0]
        if isinstance(target,ast.Subscript) and isinstance(target.value,ast.Name) and target.value.id=='contents':
            try:name=ast.literal_eval(target.slice);value=ast.literal_eval(node.value)
            except (ValueError,TypeError):continue
            if isinstance(value,bytes):templates[name]=value
for name in ('probe.sh','www/cgi-bin/probe','handler.lua','handler.uc'):
    contents[name]=templates[name]
lua_prefix=b''' assert(package.cpath == "/opt/be6l-a64-soft/lib/lua/?.so;/opt/be6l-a64-soft/lib/lua/?/init.so")
 for _, name in ipairs({"iwinfo", "lucihttp", "luci.ip", "luci.jsonc", "luci.template.parser", "yaml", "nixio", "uci", "ubus", "uloop"}) do assert(require(name)) end
'''
contents['handler.lua']=contents['handler.lua'].replace(b'function handle_request(env)\n',b'function handle_request(env)\n'+lua_prefix)
ucode_prefix=b''' for (let name in ["digest", "html", "lua", "luci.core", "lucihttp", "nl80211", "rtnl"]) assert(require(name));
'''
contents['handler.uc']=contents['handler.uc'].replace(b'global.handle_request = function(env) {\n',b'global.handle_request = function(env) {\n'+ucode_prefix)
password=secrets.token_hex(24)
hashed=subprocess.check_output(['openssl','passwd','-6','-stdin'],input=(password+'\n').encode()).strip().decode()
contents['etc/passwd']=b'root:x:0:0:Synthetic fixture:/:/bin/sh\n'
contents['etc/group']=b'root:x:0:\n'
contents['etc/config/rpcd']=("config login\n option username 'root'\n option password '"+hashed+"'\n list read 'fixture'\n").encode()
contents['etc/config/fixture']=b"config example 'test'\n option answer 'native-soft64'\n"
contents['usr/share/rpcd/acl.d/fixture.json']=json.dumps({'unauthenticated':{'read':{'ubus':{'session':['login']}}},'fixture':{'read':{'ubus':{'uci':['get']},'uci':['fixture']}}}).encode()
for name,value in (('login-request.json',password),('wrong-login.json','incorrect-synthetic-fixture-password')):
    contents['tmp/'+name]=json.dumps(dict(jsonrpc='2.0',id=1,method='call',params=['0'*32,'session','login',dict(username='root',password=value)])).encode()
payload=secrets.token_bytes(128*1024);contents['www/payload.bin']=payload
cert,key=out/'certificate.pem',out/'throwaway-tls.key'
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost','-keyout',key,'-out',cert],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
contents['etc/test-cert.pem']=cert.read_bytes();contents['etc/test-key.pem']=key.read_bytes();key.unlink()
contents['etc/unrelated-ca.pem']=(root/'etc/ssl/certs/ca-certificates.crt').read_bytes()
for name in ('dev/null','dev/random','dev/urandom'):contents[name]=b''
dirs=('proc','sys','tmp','etc/config','usr/lib/rpcd','usr/share/rpcd/acl.d','usr/share/rpcd/ucode','var/run/ubus','www/cgi-bin')
fixture=out/'namespace-fixture.tar'
with tarfile.open(fixture,'w') as stream:
    for name in dirs:
        item=tarfile.TarInfo(name);item.type=tarfile.DIRTYPE;item.mode=0o755;item.mtime=int(EPOCH);stream.addfile(item)
    for name,data in sorted(contents.items()):
        item=tarfile.TarInfo(name);item.size=len(data);item.mtime=int(EPOCH)
        item.mode=source_modes.get(name, 0o755 if name=='probe.sh' or name.startswith('www/cgi-bin/') else 0o644 if name.startswith('www/') else 0o600)
        stream.addfile(item,io.BytesIO(data))
    for name,target in sorted(links.items()):
        assert not target.startswith('/') and '..' not in Path(target).parts
        item=tarfile.TarInfo(name);item.type=tarfile.SYMTYPE;item.linkname=target;item.mode=0o777;item.mtime=int(EPOCH);stream.addfile(item)
old=BASE/'artifacts/a64-soft-services';old_proof=json.loads((old/'namespace-fixture.json').read_text())
assert SHA((old/'namespace-runner').read_bytes())==old_proof['namespace-runner']
shutil.copyfile(old/'namespace-runner',out/'namespace-runner')
proof=dict(schema=1,fixture_only=True,normal_package_receipt_sha256=SHA((bundle/'result.json').read_bytes()),
    profile_lock_sha256=result['profile_lock_sha256'],native_package_sha256=result['package_sha256'],
    **{'namespace-fixture.tar':SHA(fixture.read_bytes()),'namespace-runner':SHA((out/'namespace-runner').read_bytes())},
    payload_sha256=SHA(payload),native_paths=90,all_native_paths_from_actual_package_root=True,
    expected_remote_prefix='/tmp/be6l-native-services-',target_fixture_executed=False,
    defaults_promoted=False,new_native_image_admitted=False,
    test_scope='Private mount/net/PID namespace; loopbackTLS/RPC/auth/ACL/revocation and nativeLua/ucode module imports',
    followup_gates=['Embedded ucode Lua-bridge child-VM module paths still require an explicit default-path test','Full service and netifd lifecycle/default promotion is not implied'])
(out/'namespace-fixture.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
print(json.dumps(dict(output=str(out),fixture_sha256=proof['namespace-fixture.tar'],runner_sha256=proof['namespace-runner'],native_paths=90,target_execution=False),indent=2))
