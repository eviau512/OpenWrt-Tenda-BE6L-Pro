# SPDX-License-Identifier: MIT
"""Review a native service closure merge without modifying packages or an image."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import tarfile
from a64_soft_context import BASE
from soft_abi_admission import admit_profile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--base-profile',type=Path,required=True)
parser.add_argument('--trusted-base-lock-sha256',required=True)
args=parser.parse_args()
profile=admit_profile(args.base_profile,args.trusted_base_lock_sha256)
layout={}; duplicates=[]
programs={'busybox','lua','luac','curl','ubus','ubusd','uci','ucode','jshn','netifd','rpcd','uhttpd','iwinfo'}
procd={'init','procd','askfirst','udevtrigger','upgraded'}
lua={'nixio.so','uci.so','ubus.so','uloop.so'}

def target(name,base=False):
    if base and name in procd:return 'sbin/'+name
    if name in programs:return 'opt/be6l-a64-soft/bin/'+name
    if base and name in lua:return 'opt/be6l-a64-soft/lib/lua/'+name
    if name.startswith('modules/'):return 'opt/be6l-a64-soft/lib/ucode/'+name.split('/',1)[1]
    if name.startswith('ucode-modules/'):return 'opt/be6l-a64-soft/lib/ucode/'+name.split('/',1)[1]
    if name.startswith('lua-modules/'):return 'opt/be6l-a64-soft/lib/lua/'+name.split('/',1)[1]
    if name.startswith('plugins/'):return 'opt/be6l-a64-soft/lib/rpcd/'+name.split('/',1)[1]
    if name.startswith('uhttpd_'):return 'opt/be6l-a64-soft/lib/uhttpd/'+name
    assert name.startswith('lib') and '/' not in name,name
    return 'lib/aarch64-soft/'+name

def add(group,name,data,metadata,base=False):
    digest=hashlib.sha256(data).hexdigest()
    assert digest==metadata['sha256']
    assert data[:6]==b'\x7fELF\x02\x01' and data[18:20]==b'\xb7\0'
    path=target(name,base)
    if path in layout:
        assert layout[path]['sha256']==digest,('Conflicting native provider',path,group,name)
        duplicates.append(dict(path=path,additional_provider=group))
    else:layout[path]=dict(sha256=digest,bytes=len(data),needed=metadata['needed'],provider=group)

for name,metadata in profile['files'].items():
    add('frozen-base-profile',name,(args.base_profile/'payload'/name).read_bytes(),metadata,base=True)
base_paths=set(layout)
for group,archive in (('netifd','netifd.tar'),('lua-ui','luci.tar')):
    art=BASE/('artifacts/a64-soft-'+group)
    manifest=json.loads((art/'manifest.json').read_text())
    with tarfile.open(art/archive) as tar:
        assert {m.name for m in tar}==set(manifest['files'])
    with tarfile.open(art/archive) as tar:
        for member in tar:
            assert member.isfile() and '..' not in Path(member.name).parts
            add(group,member.name,tar.extractfile(member).read(),manifest['files'][member.name])
providers={Path(p).name:p for p in layout if p.startswith('lib/aarch64-soft/')}
for path,metadata in layout.items():
    assert all(dep in providers for dep in metadata['needed']),(path,metadata['needed'])
new={p:metadata for p,metadata in layout.items() if p not in base_paths}
report=dict(base_lock_sha256=args.trusted_base_lock_sha256,
    total_elf_paths=len(layout),base_elf_paths=len(base_paths),new_elf_paths=len(new),
    new_raw_elf_bytes=sum(v['bytes'] for v in new.values()),
    identical_duplicate_providers=len(duplicates),provider_conflicts=0,
    exact_dependency_providers_present=True,layout=layout,duplicates=duplicates,
    review_only=True,approved_new_admission_lock=False,packages_or_image_modified=False,
    default_service_replacement_qualified=False,
    image_growth_unknown_until_real_package_transaction_and_cpio_measurement=True)
(BASE/'logs/soft-services-merge-preflight.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ('layout','duplicates')},indent=2))
