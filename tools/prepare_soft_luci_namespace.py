# SPDX-License-Identifier: MIT
"""Extend the existing synthetic service fixture with audited LuCI C modules."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import subprocess
import tarfile
from a64_soft_context import BASE,SDK,EPOCH
from soft_elf_closure import audit
parser=argparse.ArgumentParser()
parser.add_argument('--first-root',type=Path,required=True)
parser.add_argument('--build-root',type=Path,required=True)
args=parser.parse_args();root=args.build_root
art=BASE/'artifacts/a64-soft-luci';prior=BASE/'artifacts/a64-soft-services'
manifest=json.loads((art/'manifest.json').read_text())
first=json.loads((args.first_root/'audited/manifest.json').read_text())
assert first['files']==manifest['files'] and first['source_hashes']==manifest['source_hashes']
(BASE/'logs/soft-luci-reproduction.json').write_text(json.dumps(dict(files=len(manifest['files']),
    all_output_hashes_identical=True,source_hash_maps_identical=True),indent=2)+'\n')
prior_proof=json.loads((prior/'namespace-fixture.json').read_text())
for name in ('namespace-fixture.tar','namespace-runner'):
    assert hashlib.sha256((prior/name).read_bytes()).hexdigest()==prior_proof[name]
contents={};links={};dirs=set();modes={}
with tarfile.open(prior/'namespace-fixture.tar') as tar:
    for item in tar:
        assert not item.name.startswith('/') and '..' not in Path(item.name).parts
        if item.isfile():contents[item.name]=tar.extractfile(item).read();modes[item.name]=item.mode
        elif item.issym():links[item.name]=item.linkname
        elif item.isdir():dirs.add(item.name)
        else:raise AssertionError(item.name)
with tarfile.open(art/'luci.tar') as tar:
    assert len(tar.getmembers())==len(manifest['files'])
    for item in tar:
        assert item.isfile() and item.name in manifest['files']
        data=tar.extractfile(item).read()
        assert hashlib.sha256(data).hexdigest()==manifest['files'][item.name]['sha256']
        if item.name.startswith('ucode-modules/'):target='usr/lib/ucode/'+item.name.split('/',1)[1]
        elif item.name.startswith('lua-modules/'):target='usr/lib/lua/'+item.name.split('/',1)[1]
        elif item.name.startswith('plugins/'):target='usr/lib/rpcd/'+item.name.split('/',1)[1]
        elif item.name.startswith('uhttpd_'):target='usr/lib/'+item.name
        elif '.so' in item.name:target='lib/aarch64-soft/'+item.name
        else:target='opt/be6l-a64-soft/bin/'+item.name
        contents[target]=data;modes[target]=0o755
baseline=Path('/root/be6l-openwrt/compat-apk-root/root')
contents['www/cgi-bin/luci']=(baseline/'www/cgi-bin/luci').read_bytes();modes['www/cgi-bin/luci']=0o755
for p in (baseline/'usr/share/ucode/luci').rglob('*'):
    if p.is_file() and p.suffix in ('.uc','.ut'):
        name=p.relative_to(baseline).as_posix();contents[name]=p.read_bytes();modes[name]=0o644
links['usr/bin/ucode']='../../opt/be6l-a64-soft/bin/ucode'
links['usr/bin/env']='../../bin/busybox'
modules=sorted(name.removeprefix('ucode-modules/').removesuffix('.so').replace('/','.')
               for name in manifest['files'] if name.startswith('ucode-modules/'))
contents['module-probe.uc']=("for (let name in "+json.dumps(modules)+") {\n"
    " let m=require(name); assert(type(m)=='object');\n}\n"
    "let h=require('lucihttp'); assert(h.urldecode('%41%42%43',h.DECODE_STRICT)=='ABC');\n"
    "assert(type(require('luci.core').hash)=='function');\n"
    "print('NATIVE_LUCI_C_MODULES_LOADED\\n');\n").encode()
contents['handler.lua']=contents['handler.lua'].replace(b' assert(math.pow',
    b' local iw=require("iwinfo"); assert(type(iw.type)=="function"); assert(iw.type("lo")==nil)\n assert(math.pow')
probe=root/'unsigned-float-probe'
subprocess.run([str(root/'softcc'),'-static','-O2','-Wall','-Wextra','-Werror',
    str(BASE/'diagnostics/a64_unsigned_float_test.c'),'-o',str(probe)],check=True)
gcc,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
probe_manifest=audit({'unsigned-float-probe':probe},root/'sysroot',root/'probe-audited',str(gcc)[:-3])
contents['opt/be6l-a64-soft/bin/unsigned-float-probe']=(root/'probe-audited/unsigned-float-probe').read_bytes()
modes['opt/be6l-a64-soft/bin/unsigned-float-probe']=0o755
extra=b'''unsigned-float-probe
ucode /module-probe.uc
echo PRIVATE_IWINFO_DEVICES
ubus -s /var/run/ubus/ubus.sock call iwinfo devices
ubus -s /var/run/ubus/ubus.sock list luci-rpc | grep -q luci-rpc
ubus -s /var/run/ubus/ubus.sock list network.rrdns | grep -q network.rrdns
curl -q --noproxy '*' --max-time 5 -sS -D /tmp/luci-headers.txt -o /tmp/luci-body.txt -w 'NATIVE_LUCI_PAGE_HTTP=%{http_code}\\n' http://127.0.0.1:18880/cgi-bin/luci/
echo PRIVATE_LUCI_PAGE_DIAGNOSTIC
cat /tmp/luci-headers.txt
cat /tmp/luci-body.txt
echo
'''
assert contents['probe.sh'].count(b'echo PRIVATE_NATIVE_SERVICES_DONE')==1
contents['probe.sh']=contents['probe.sh'].replace(b'echo PRIVATE_NATIVE_SERVICES_DONE',extra+b'echo PRIVATE_NATIVE_SERVICES_DONE')
with tarfile.open(art/'namespace-fixture.tar','w') as tar:
    for name in sorted(dirs):
        info=tarfile.TarInfo(name);info.type=tarfile.DIRTYPE;info.mode=0o755;info.mtime=int(EPOCH);tar.addfile(info)
    for name,data in contents.items():
        info=tarfile.TarInfo(name);info.size=len(data);info.mode=modes.get(name,0o600);info.mtime=int(EPOCH)
        tar.addfile(info,io.BytesIO(data))
    for name,target in links.items():
        info=tarfile.TarInfo(name);info.type=tarfile.SYMTYPE;info.linkname=target;info.mtime=int(EPOCH);tar.addfile(info)
(art/'namespace-runner').write_bytes((prior/'namespace-runner').read_bytes())
proof={name:hashlib.sha256((art/name).read_bytes()).hexdigest() for name in ('namespace-fixture.tar','namespace-runner')}
proof.update(payload_sha256=prior_proof['payload_sha256'],unsigned_float_probe=probe_manifest,
    expected_luci_page_blocker='html module not yet in the native closure')
(art/'namespace-fixture.json').write_text(json.dumps(proof,indent=2)+'\n')
print('NATIVE_LUCI_C_MODULE_FIXTURE_PREPARED; REPRODUCTION_IDENTICAL',len(manifest['files']))
