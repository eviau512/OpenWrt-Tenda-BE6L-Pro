# SPDX-License-Identifier: MIT
"""Compose a protected RAM image from a normally transacted native APK root.

Standard target/linux/install; restore the baseline external CPIO in finally.
Never copy replacement init/procd/libc over an installed package's records.
"""
from pathlib import Path
import argparse
import json
import lzma
import os
import shutil
import struct
import subprocess
import sys
from a64_soft_context import BASE, SDK, EPOCH
from prepare_ramboot import tree, image, text
from verify_embedded_compat_cpio import verify
from soft_abi_admission import digest, file_records

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--bundle-root',type=Path,required=True)
parser.add_argument('--work',type=Path,required=True)
args=parser.parse_args()
bundle=args.bundle_root
receipt_path=BASE/'logs'/('soft-bundle-'+bundle.name)/'result.json'
receipt=json.loads(receipt_path.read_text())
assert receipt['passed'] and receipt['normal_solver_signatures'] and receipt['pid1_owned_by_native_procd_package']
original=Path(receipt['rootfs'])
assert original==bundle/'rootfs'
assert args.work.is_absolute() and not args.work.exists()
args.work.mkdir()
root=args.work/'root'
shutil.copytree(original,root,symlinks=True)
for group in ('runtime','tools','procd','compat'):
    for name,item in file_records(bundle/('files-'+group)).items():
        p=root/name
        if 'symlink' in item:assert p.is_symlink() and str(p.readlink())==item['symlink']
        else:assert digest(p.read_bytes())==item['sha256'],name
baseline=json.loads((BASE/'artifacts/arm64-compat/build-validation.json').read_text())
assert baseline['image_sha256']=='fb5e8a5df2a2e037d393728f730a662918440ea79baffea72ab3b776cae34181'
external=Path('/root/be6l-openwrt/compat-rootfs/rootfs.cpio')
assert digest(external.read_bytes())==baseline['external_cpio_sha256']
assert (root/'sbin/init').read_bytes()[4]==2
assert (root/'lib/libc.so').read_bytes()[4]==1
assert digest((root/'lib/aarch64-soft/libc.so').read_bytes())=='143100b85695d93b77a8b79b518f17cb48134ab38c828a07b0a9d171811dcddb'
for name,sha in baseline['elf64_modules_verified'].items():assert digest((root/name).read_bytes())==sha
assert digest((root/'lib/firmware/airoha/an7552.bin').read_bytes())=='934d85a5949ec622cdf853b8442aeb3c5cdd92a81866a843963f4fbf26a3a867'
assert not list((root/'usr/bin').glob('portal_autologin*'))
assert b'arm_cortex-a7\naarch64_be6l_soft_experimental\n'==(root/'etc/apk/arch').read_bytes()
metadata=dict(runtime_abi='aarch64_kernel_soft64_native_c_arm32_remaining_apps',
              native_init_procd=True, fully_native_userspace=False,
              corrected_fma_libc=True, native_c_elfs=58,
              package_metadata='Native init/procd owned by a signed normally installed soft-ABI procd package.',
              normal_native_apk_transaction=True, package_upgrades_qualified=False,
              soft_profile_lock_sha256=receipt['profile_lock_sha256'],
              kernel_changes_require_matching_ramboot=True, ramboot_validated=False)
for name in ('be6l-soft-init.json','be6l-compat-build.json'):
    (root/'etc'/name).write_text(json.dumps(metadata,indent=2)+'\n')
paths=['.']+sorted(str(p.relative_to(root)) for p in root.rglob('*'))
for name in paths:os.utime(root/name,(int(EPOCH),int(EPOCH)),follow_symlinks=False)
cpio=args.work/'rootfs.cpio'
with cpio.open('wb') as output:
    subprocess.run([str(SDK/'staging_dir/host/bin/cpio'),'--null','--reproducible','-o','-H','newc','-R','0:0'],
                   cwd=root,input=('\0'.join(paths)+'\0').encode(),stdout=output,check=True)
kernel=SDK/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
nodes=args.work/'device-nodes.list'
nodes.write_text('nod /dev/console 0600 0 0 c 5 1\nnod /dev/null 0666 0 0 c 1 3\n')
with cpio.open('ab') as output:
    subprocess.run([str(kernel/'usr/gen_init_cpio'),'-t',EPOCH,str(nodes)],stdout=output,check=True)
assert digest((kernel/'.config').read_bytes())==baseline['kernel_config_sha256']
saved=args.work/'baseline.cpio'
shutil.copyfile(external,saved)
env=dict(os.environ)
env.update(PATH='/root/be6l-openwrt/host/bin:'+env['PATH'],CONFIG_SHELL='/root/be6l-openwrt/host/bin/bash',
           FORCE_UNSAFE_CONFIGURE='1',SOURCE_DATE_EPOCH=EPOCH)
logs=BASE/'logs'/('soft-apk-image-'+args.work.name)
logs.mkdir()
try:
    shutil.copyfile(cpio,external)
    with (logs/'build.txt').open('w') as output:
        subprocess.run(['make','-j4','SHELL='+env['CONFIG_SHELL'],'V=s','target/linux/install'],
                       cwd=SDK,env=env,stdout=output,stderr=subprocess.STDOUT,check=True)
    fit,=list((SDK/'bin/targets/airoha/an7563a64').glob('*tenda_be6l-pro-initramfs-kernel.bin'))
    dt=tree(fit.read_bytes())
    conf=dt['/configurations/'+text(dt['/configurations']['default'])]
    packed,props=image(dt,text(conf['kernel']))
    dtb,_=image(dt,text(conf['fdt']))
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
    compiler,=SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
    layout=logs/'module-layout.json'
    subprocess.run([sys.executable,str(BASE/'tools/audit_module_layout.py'),'--kernel',str(kernel),'--root',str(root),
                    '--arch','arm64','--cross-compile',str(compiler)[:-3],'--output',str(layout)],check=True)
    for name,sha in baseline['elf64_modules_verified'].items():assert digest((root/name).read_bytes())==sha
    assert digest((kernel/'.config').read_bytes())==baseline['kernel_config_sha256']
    out=BASE/'artifacts/arm64-soft-apk'
    out.mkdir(exist_ok=True)
    shutil.copyfile(fit,out/fit.name)
    report={**metadata,**embedded,'image':fit.name,'image_sha256':digest(fit.read_bytes()),
            'external_cpio_sha256':digest(cpio.read_bytes()),'external_cpio_bytes':cpio.stat().st_size,
            'kernel_config_sha256':baseline['kernel_config_sha256'],'kernel_effective_bytes':size,
            'elf64_modules_verified':baseline['elf64_modules_verified'],
            'module_layout_audit':json.loads(layout.read_text()),'dtb_readonly_partitions':10,
            'native_aarch64_userspace_usable':False,'standard_kernel_make':True,
            'bundle_receipt_sha256':digest(receipt_path.read_bytes()),'root':str(root),
            'base_image_sha256':baseline['image_sha256']}
    (out/'build-validation.json').write_text(json.dumps(report,indent=2)+'\n')
    (logs/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print('SOFT_APK_RAM_IMAGE_VALIDATED',report['image_sha256'],flush=True)
finally:
    assert digest(external.read_bytes())==digest(cpio.read_bytes()),'External CPIO changed independently'
    shutil.copyfile(saved,external)
    assert digest(external.read_bytes())==baseline['external_cpio_sha256']
    print('BASELINE_EXTERNAL_CPIO_RESTORED',flush=True)
