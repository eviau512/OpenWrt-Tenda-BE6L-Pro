# SPDX-License-Identifier: MIT
"""Prepare a synthetic native LuCI dispatcher/Argon login fixture, not live UI."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import secrets
import subprocess
import tarfile
from a64_soft_context import BASE, EPOCH

parser = argparse.ArgumentParser()
parser.add_argument('--root', type=Path, required=True)
parser.add_argument('--first-root', type=Path, required=True)
parser.add_argument('--extra-modules', action='store_true')
parser.add_argument('--lua-ui', action='store_true')
args = parser.parse_args()
assert not args.lua_ui or args.extra_modules
art = BASE / ('artifacts/a64-soft-lua-ui' if args.lua_ui else 'artifacts/a64-soft-ucode-modules' if args.extra_modules else 'artifacts/a64-soft-luci-web')
prior = BASE / 'artifacts/a64-soft-luci'
manifest = json.loads((art / 'manifest.json').read_text())
first = json.loads((args.first_root / 'audited/manifest.json').read_text())
assert first['files'] == manifest['files'] and first['source_hashes'] == manifest['source_hashes']
(BASE / ('logs/soft-lua-ui-reproduction.json' if args.lua_ui else 'logs/soft-ucode-modules-reproduction.json' if args.extra_modules else 'logs/soft-luci-web-reproduction.json')).write_text(json.dumps(dict(
    files=len(manifest['files']), all_output_hashes_identical=True,
    source_hash_maps_identical=True), indent=2) + '\n')
prior_proof = json.loads((prior / 'namespace-fixture.json').read_text())
assert hashlib.sha256((prior / 'namespace-fixture.tar').read_bytes()).hexdigest() == prior_proof['namespace-fixture.tar']
contents, links, modes, dirs = {}, {}, {}, set()
with tarfile.open(prior / 'namespace-fixture.tar') as tar:
    for item in tar:
        assert not item.name.startswith('/') and '..' not in Path(item.name).parts
        if item.isfile(): contents[item.name] = tar.extractfile(item).read(); modes[item.name] = item.mode
        elif item.issym(): links[item.name] = item.linkname
        elif item.isdir(): dirs.add(item.name)
        else: raise AssertionError(item.name)
with tarfile.open(art / 'luci.tar') as tar:
    assert len(tar.getmembers()) == len(manifest['files'])
    for item in tar:
        assert item.isfile() and item.name in manifest['files']
        data = tar.extractfile(item).read()
        assert hashlib.sha256(data).hexdigest() == manifest['files'][item.name]['sha256']
        if item.name.startswith('ucode-modules/'): target = 'usr/lib/ucode/' + item.name.split('/', 1)[1]
        elif item.name.startswith('lua-modules/'): target = 'usr/lib/lua/' + item.name.split('/', 1)[1]
        elif item.name.startswith('plugins/'): target = 'usr/lib/rpcd/' + item.name.split('/', 1)[1]
        elif item.name.startswith('uhttpd_'): target = 'usr/lib/' + item.name
        elif '.so' in item.name: target = 'lib/aarch64-soft/' + item.name
        else: target = 'opt/be6l-a64-soft/bin/' + item.name
        contents[target] = data; modes[target] = 0o755
baseline = Path('/root/be6l-openwrt/compat-apk-root/root')
# Explicit public UI data paths only. Never copy host configuration, saved
# wireless credentials, root shadow, persistent state or ARM32 native modules.
ui_hashes = {}
for relative in ('usr/share/ucode/luci', 'usr/share/luci/menu.d', 'usr/share/luci/i18n',
                 'www/luci-static/argon', 'www/luci-static/resources'):
    for path in sorted((baseline / relative).rglob('*')):
        if not path.is_file(): continue
        name = path.relative_to(baseline).as_posix()
        data = path.read_bytes()
        assert data[:4] != b'\x7fELF', name
        contents[name] = data; modes[name] = 0o644
        ui_hashes[name] = hashlib.sha256(data).hexdigest()
contents['etc/config/luci'] = b"""config core 'main'
 option lang 'zh_cn'
 option mediaurlbase '/luci-static/argon'
 option resourcebase '/luci-static/resources'
 option ubuspath '/ubus/'
config internal 'sauth'
 option sessionpath '/tmp/luci-sessions'
 option sessiontime '3600'
config internal 'themes'
 option Argon '/luci-static/argon'
"""
contents['etc/config/uhttpd'] = b"config uhttpd 'main'\n list listen_https '127.0.0.1:18881'\n"
contents['etc/config/system'] = b"config system\n option hostname 'native-fixture'\n"
password = secrets.token_hex(24)
hashed = subprocess.check_output(['openssl', 'passwd', '-6', '-stdin'], input=(password+'\n').encode()).strip().decode()
assert hashed.startswith('$6$')
contents['etc/shadow'] = ('root:' + hashed + ':0:0:99999:7:::\n').encode()
contents['etc/config/rpcd'] = ("config login\n option username 'root'\n option password '" + hashed +
                            "'\n list read 'fixture'\n").encode()
login = json.loads(contents['tmp/login-request.json'])
login['params'][3]['password'] = password
contents['tmp/login-request.json'] = json.dumps(login).encode()
contents['tmp/luci-valid-form'] = ('luci_username=root&luci_password=' + password).encode()
contents['tmp/luci-wrong-form'] = b'luci_username=root&luci_password=incorrect-synthetic-fixture-password'
contents['usr/share/luci/menu.d/zz-native-fixture.json'] = json.dumps({
    'admin/native-fixture': {'title': 'Native fixture', 'order': 1,
        'action': {'type': 'template', 'path': 'native-fixture'}}}).encode()
contents['usr/share/ucode/luci/template/native-fixture.ut'] = b'NATIVE_LUCI_AUTHENTICATED\n'
contents['module-probe.uc'] += b"let html=require('html'); assert(html.striptags('<b>native</b>')=='native');\n"
if args.extra_modules:
    contents['global-import-probe.uc'] = b"""let lua=require('lua');
let names=['debug','fs','io','log','math','netaddr','resolv','serial','socket','struct','ubus','uci','udebug','uloop','html','luci.core','lucihttp','digest','rtnl','nl80211'];
for (let name in names) assert(type(require(name))=='object');
assert(type(require('html').striptags)=='function');
assert(type(require('luci.core').hash)=='function');
assert(type(require('rtnl').const.RTM_GETLINK)=='int');
assert(type(require('nl80211').const.NL80211_CMD_GET_WIPHY)=='int');
print('NATIVE_LUA_FIRST_IMPORT_ORDER_PASS\\n');
"""
    contents['module-probe.uc'] += b"""let digest=require('digest');
assert(digest.md5('abc')=='900150983cd24fb0d6963f7d28e17f72');
assert(digest.sha1('abc')=='a9993e364706816aba3e25717850c26c9cd0d89d');
assert(digest.sha256('abc')=='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
let vm=require('lua').create();
vm.eval('assert(math.pow(4,0.5)==2); assert(require("nixio").getpid()>1); assert(require("iwinfo").type("lo")==nil)');
let rtnl=require('rtnl');
let links=rtnl.request(rtnl.const.RTM_GETLINK,rtnl.const.NLM_F_DUMP,{});
assert(type(links)=='array' && length(links)==1 && links[0].ifname=='lo');
let nl=require('nl80211');
let radios=nl.request(nl.const.NL80211_CMD_GET_WIPHY,nl.const.NLM_F_DUMP,{});
let nlerr=nl.error();
printf('PRIVATE_NL80211_DUMP=%J ERROR=%J\\n',radios,nlerr);
// A completed multipart dump with no data has STATE_REPLIED and a null result.
// Require the exact observed success/error pair, not a synthetic empty array.
assert(radios === null && nlerr === null);
print('NATIVE_UCODE_DIGEST_LUA_NETLINK_PASS\\n');
"""
if args.lua_ui:
    lyaml = args.root / 'source-lyaml/lib/lyaml'
    for path in sorted(lyaml.rglob('*.lua')):
        name='usr/share/lua/lyaml/'+path.relative_to(lyaml).as_posix()
        contents[name]=path.read_bytes(); modes[name]=0o644
    contents['lua-ui-probe.lua'] = b'''local ip=require('luci.ip')
local a=ip.IPv4('192.0.2.129/24')
assert(a:is4() and a:contains(ip.IPv4('192.0.2.1')))
assert(not a:contains(ip.IPv4('198.51.100.1')))
assert(ip.IPv6('2001:db8::1/64'):is6())
local j=require('luci.jsonc')
local v=j.parse('{"n":2.5,"ok":true,"a":[1,2]}')
assert(v.n==2.5 and v.ok==true and v.a[2]==2)
assert(j.parse(j.stringify(v)).n==2.5)
assert(j.parse('{broken')==nil)
local parser=require('luci.template.parser')
local f=parser.parse_string('<% return 3.25+0.75 %>')
assert(type(f)=='function' and f()==4)
assert(parser.parse_string('<% local = %>')==nil)
assert(parser.pcdata('<x&>')=='&#60;x&#38;&#62;')
local yaml=require('lyaml')
local data=yaml.load('flag: true\\nvalue: 2.5\\nnames: [a, b]\\n')
assert(data.flag==true and data.value==2.5 and data.names[2]=='b')
assert(yaml.load(yaml.dump({data})).value==2.5)
assert(not pcall(yaml.load,'x: [1,2'))
print('NATIVE_LUCI_LUA_IP_JSON_TEMPLATE_YAML_PASS')
'''
    contents['module-probe.uc'] += b"require('lua').create().include('/lua-ui-probe.lua');\n"
certdir = args.root / ('ui-certificate-' + secrets.token_hex(8)); certdir.mkdir()
cert, key = certdir / 'cert.pem', certdir / 'key.pem'
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
    '-days', '2', '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
    '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
contents['etc/test-cert.pem'], contents['etc/test-key.pem'] = cert.read_bytes(), key.read_bytes()
key.unlink()
old = b"curl -q --noproxy '*' --max-time 5 -sS -D /tmp/luci-headers.txt"
start = contents['probe.sh'].index(old)
end = contents['probe.sh'].index(b'echo PRIVATE_NATIVE_SERVICES_DONE', start)
extra = b'''page=https://127.0.0.1:18881/cgi-bin/luci/admin/native-fixture
ui_request() { curl -q --noproxy '*' --max-time 8 --cacert /etc/test-cert.pem -sS "$@"; }
ui_request -D /tmp/luci-headers.txt -o /tmp/luci-body.txt -w 'NATIVE_LUCI_PAGE_HTTP=%{http_code}\\n' "$page"
echo PRIVATE_LUCI_PAGE_DIAGNOSTIC
cat /tmp/luci-headers.txt
cat /tmp/luci-body.txt
echo
grep -qi '^x-luci-login-required: yes' /tmp/luci-headers.txt
grep -q 'name="luci_username"' /tmp/luci-body.txt
grep -q 'name="luci_password"' /tmp/luci-body.txt
grep -q '/luci-static/argon/' /tmp/luci-body.txt
grep -q 'lang="zh-cn"' /tmp/luci-body.txt
ui_request --data-binary @/tmp/luci-wrong-form -D /tmp/wrong-ui-headers -o /tmp/wrong-ui-body "$page"
grep -qi '^x-luci-login-required: yes' /tmp/wrong-ui-headers
if grep -q 'NATIVE_LUCI_AUTHENTICATED' /tmp/wrong-ui-body; then exit 1; fi
ui_request --data-binary @/tmp/luci-valid-form -c /tmp/ui-cookies -D /tmp/valid-ui-headers -o /tmp/valid-ui-body "$page"
grep -qi '^set-cookie: sysauth_https=' /tmp/valid-ui-headers
ui_request -b /tmp/ui-cookies -D /tmp/authed-ui-headers -o /tmp/authed-ui-body "$page"
grep -q 'NATIVE_LUCI_AUTHENTICATED' /tmp/authed-ui-body
echo NATIVE_LUCI_ARGON_CHINESE_AUTHENTICATION_PASS
'''
contents['probe.sh'] = contents['probe.sh'][:start] + extra + contents['probe.sh'][end:]
if args.extra_modules:
    contents['probe.sh'] = contents['probe.sh'].replace(b'ucode /module-probe.uc',
        b'ucode /global-import-probe.uc\nucode /module-probe.uc')
dirs.update(('usr/share/luci/menu.d', 'usr/share/luci/i18n', 'tmp/luci-sessions'))
with tarfile.open(art / 'namespace-fixture.tar', 'w') as tar:
    for name in sorted(dirs):
        info = tarfile.TarInfo(name); info.type = tarfile.DIRTYPE; info.mode = 0o755; info.mtime = int(EPOCH); tar.addfile(info)
    for name, data in contents.items():
        info = tarfile.TarInfo(name); info.size = len(data)
        info.mode = modes.get(name, 0o644 if name.startswith(('usr/share/', 'www/')) else 0o600)
        info.mtime = int(EPOCH); tar.addfile(info, io.BytesIO(data))
    for name, target in links.items():
        info = tarfile.TarInfo(name); info.type = tarfile.SYMTYPE; info.linkname = target; info.mtime = int(EPOCH); tar.addfile(info)
(art / 'namespace-runner').write_bytes((prior / 'namespace-runner').read_bytes())
proof = {name: hashlib.sha256((art / name).read_bytes()).hexdigest() for name in ('namespace-fixture.tar', 'namespace-runner')}
proof.update(payload_sha256=prior_proof['payload_sha256'], ui_data_sha256=ui_hashes,
    synthetic_credentials_only=True, real_hardware_namespace_excluded=True,
    expected_luci_login_http=403, full_device_ui_qualified=False)
(art / 'namespace-fixture.json').write_text(json.dumps(proof, indent=2) + '\n')
print('NATIVE_LUCI_WEB_FIXTURE_PREPARED', len(manifest['files']), 'ELF', len(ui_hashes), 'PUBLIC_UI_FILES', flush=True)
