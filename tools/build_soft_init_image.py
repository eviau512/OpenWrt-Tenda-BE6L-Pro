# SPDX-License-Identifier: MIT
"""RAM diagnostic: native soft64 init/procd with preserved ARM32 applications.

Uses a private root copy and standard OpenWrt target/linux/install. The original
external CPIO is restored in finally. Package upgrades are not qualified.
"""
from pathlib import Path
import hashlib
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
from a64_soft_context import BASE as base, SDK as sdk, ROOT as soft, EPOCH
from prepare_ramboot import tree, image, text
from verify_embedded_compat_cpio import verify

sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
baseline=json.loads((base/'artifacts/arm64-compat/build-validation.json').read_text())
assert baseline['image_sha256']=='fb5e8a5df2a2e037d393728f730a662918440ea79baffea72ab3b776cae34181'
assert baseline['ramboot_validated']
external=Path('/root/be6l-openwrt/compat-rootfs/rootfs.cpio')
assert sha(external)==baseline['external_cpio_sha256']
root_report=json.loads((base/'artifacts/arm64-compat/hybrid-apk-root.json').read_text())
original=Path(root_report['root'])
assert original==Path('/root/be6l-openwrt/compat-apk-root/root')
work=soft/'native-image';assert not work.exists()
work.mkdir();root=work/'root'
shutil.copytree(original,root,symlinks=True)
artifact=base/'artifacts/a64-soft-core'
manifest=json.loads((artifact/'manifest.json').read_text())
assert 'init' in manifest and manifest['init']['machine']==183
def target(relative):
    p=root/relative
    p.parent.mkdir(parents=True,exist_ok=True)
    assert p.parent.resolve().is_relative_to(root.resolve()), relative
    if p.is_symlink():p.unlink()
    return p
replaced={}
for name in ('init','procd'):
    source=artifact/name;assert sha(source)==manifest[name]['sha256']
    data=source.read_bytes();assert data[:5]==b'\x7fELF\x02' and data[18:20]==b'\xb7\x00'
    assert b'/lib/ld-musl-aarch64-soft.so.1\0' in data
    p=target('sbin/'+name);shutil.copyfile(source,p);p.chmod(0o755)
    replaced['sbin/'+name]=sha(p)
for name,item in manifest.items():
    if name=='libc.so' or (name.startswith('lib') and '.so' in name):
        source=artifact/name;assert sha(source)==item['sha256']
        p=target('lib/aarch64-soft/'+name);shutil.copyfile(source,p);p.chmod(0o755)
        replaced['lib/aarch64-soft/'+name]=sha(p)
loader=target('lib/ld-musl-aarch64-soft.so.1')
assert not loader.exists();loader.symlink_to('aarch64-soft/libc.so')
target('etc/ld-musl-aarch64-soft.path').write_text('/lib/aarch64-soft\n')
assert sha(root/'lib/firmware/airoha/an7552.bin')=='934d85a5949ec622cdf853b8442aeb3c5cdd92a81866a843963f4fbf26a3a867'
for name,digest in baseline['elf64_modules_verified'].items():assert sha(root/name)==digest
assert (root/'etc/apk/world').read_bytes()==(original/'etc/apk/world').read_bytes()
meta={'runtime_abi':'aarch64_kernel_soft64_init_arm32_apps',
      'native_init_procd':True,'fully_native_userspace':False,
      'package_upgrades_qualified':False,
      'package_metadata':'Diagnostic overrides of init/procd; base APK records do not describe those replacement ELFs.',
      'unmodified_modules':baseline['elf64_modules_verified'], 'overrides':replaced}
target('etc/be6l-soft-init.json').write_text(json.dumps(meta,indent=2)+'\n')
target('etc/be6l-compat-build.json').write_text(json.dumps(meta,indent=2)+'\n')
epoch=int(EPOCH)
paths=['.']+sorted(str(p.relative_to(root)) for p in root.rglob('*'))
for name in paths:os.utime(root/name,(epoch,epoch),follow_symlinks=False)
cpio=work/'rootfs.cpio'
with cpio.open('wb') as output:
    subprocess.run([str(sdk/'staging_dir/host/bin/cpio'),'--null','--reproducible',
        '-o','-H','newc','-R','0:0'],cwd=root,input=('\0'.join(paths)+'\0').encode(),
        stdout=output,check=True)
kernel=sdk/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
nodes=work/'device-nodes.list'
nodes.write_text('nod /dev/console 0600 0 0 c 5 1\nnod /dev/null 0666 0 0 c 1 3\n')
with cpio.open('ab') as output:
    subprocess.run([str(kernel/'usr/gen_init_cpio'),'-t',EPOCH,str(nodes)],stdout=output,check=True)
assert sha(kernel/'.config')==baseline['kernel_config_sha256']
saved=work/'baseline.cpio';shutil.copyfile(external,saved)
env=dict(os.environ);env.update(PATH='/root/be6l-openwrt/host/bin:'+env['PATH'],
    CONFIG_SHELL='/root/be6l-openwrt/host/bin/bash',FORCE_UNSAFE_CONFIGURE='1',SOURCE_DATE_EPOCH=EPOCH)
logs=base/'logs/soft-init-image';logs.mkdir(exist_ok=True)
try:
    shutil.copyfile(cpio,external)
    with (logs/'build.txt').open('w') as output:
        subprocess.run(['make','-j4','SHELL='+env['CONFIG_SHELL'],'V=s','target/linux/install'],
            cwd=sdk,env=env,stdout=output,stderr=subprocess.STDOUT,check=True)
    fit,=list((sdk/'bin/targets/airoha/an7563a64').glob('*tenda_be6l-pro-initramfs-kernel.bin'))
    content=fit.read_bytes();dt=tree(content)
    conf=dt['/configurations/'+text(dt['/configurations']['default'])]
    packed,props=image(dt,text(conf['kernel']));dtb,_=image(dt,text(conf['fdt']))
    assert text(props['arch'])=='arm64' and text(props['compression'])=='lzma'
    assert int.from_bytes(props['load'],'big')==0x80200000
    decoder=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    data=decoder.decompress(packed,max_length=0x3e00000)
    assert decoder.eof and not decoder.unused_data and data[0x38:0x3c]==b'ARMd'
    _,size,_=struct.unpack_from('<QQQ',data,8)
    assert size>=len(data) and 0x80200000+size<=0x84000000
    board=tree(dtb)
    assert b'tenda,be6l-pro\0' in board['/']['compatible']
    assert sum('read-only' in p for p in board.values())==10
    assert any('airoha,bmt-read-only' in p for p in board.values())
    embedded=verify(kernel,data,cpio)
    compiler,=sdk.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
    layout=logs/'module-layout.json'
    subprocess.run([sys.executable,str(base/'tools/audit_module_layout.py'),'--kernel',str(kernel),
        '--root',str(root),'--arch','arm64','--cross-compile',str(compiler)[:-3],
        '--output',str(layout)],check=True)
    for name,digest in baseline['elf64_modules_verified'].items():assert sha(root/name)==digest
    assert sha(kernel/'.config')==baseline['kernel_config_sha256']
    out=base/'artifacts/arm64-soft-init';out.mkdir(exist_ok=True)
    shutil.copyfile(fit,out/fit.name)
    report={**meta,**embedded,'image':fit.name,'image_sha256':sha(fit),
        'external_cpio_sha256':sha(cpio),'external_cpio_bytes':cpio.stat().st_size,
        'kernel_config_sha256':sha(kernel/'.config'),'kernel_effective_bytes':size,
        'elf64_modules_verified':baseline['elf64_modules_verified'],
        'native_init_elf64_verified':True,'native_init_nofp_audited':True,
        'module_layout_audit':json.loads(layout.read_text()),'dtb_readonly_partitions':10,
        'native_aarch64_userspace_usable':False,'ramboot_validated':False,
        'base_image_sha256':baseline['image_sha256'],'standard_kernel_make':True}
    (out/'build-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    print('SOFT64_INIT_IMAGE_VALIDATED',report['image_sha256'],flush=True)
finally:
    # Restore bytes but leave a fresh mtime: the next standard baseline build
    # must rebuild its embedded CPIO rather than reuse this diagnostic object.
    assert sha(external)==sha(cpio), 'External CPIO changed independently; preserve it for review'
    shutil.copyfile(saved,external)
    assert sha(external)==baseline['external_cpio_sha256']
    print('BASELINE_EXTERNAL_CPIO_RESTORED',flush=True)
