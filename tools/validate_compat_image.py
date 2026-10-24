"""WSL: export only a protected external-CPIO ARM64/ARM32 RAM experiment."""
from pathlib import Path
import hashlib,json,lzma,shutil,struct,sys,subprocess
base=Path(__file__).resolve().parents[1]
src=Path('/root/be6l-openwrt/arm64-source')
logs=base/'logs/arm64-compat-build'
sys.path.insert(0,str(base/'tools'))
from prepare_ramboot import tree,image,text
from verify_embedded_compat_cpio import verify as verify_cpio
report=json.loads((logs/'rootfs-validation.json').read_text())
assert report['runtime_abi']=='aarch64_kernel_arm_eabi_soft_userspace'
assert report['elf32_userspace_verified'] and report['elf64_modules_verified']
kernel=src/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55'
config=(kernel/'.config').read_text().splitlines()
for s in ['CONFIG_COMPAT=y','CONFIG_COMPAT_BINFMT_ELF=y','CONFIG_COMPAT_32BIT_TIME=y',
          'CONFIG_INITRAMFS_SOURCE="/root/be6l-openwrt/compat-rootfs/rootfs.cpio"',
          'CONFIG_INITRAMFS_COMPRESSION_GZIP=y','CONFIG_NET_AIROHA_AN7552_NPU=y',
          'CONFIG_PINCTRL_AIROHA_AN7563=y','CONFIG_MTD_NAND_MTK_BMT=y']:
    assert s in config,s
cpio=Path('/root/be6l-openwrt/compat-rootfs/rootfs.cpio')
assert hashlib.sha256(cpio.read_bytes()).hexdigest()==report['external_cpio_sha256']
images=list((src/'bin/targets/airoha/an7563a64').glob('*tenda_be6l-pro-initramfs-kernel.bin'))
assert len(images)==1
fit=images[0].read_bytes();nodes=tree(fit)
ref=nodes['/configurations/'+text(nodes['/configurations']['default'])]
packed,props=image(nodes,text(ref['kernel']));dtb,_=image(nodes,text(ref['fdt']))
assert text(props['arch'])=='arm64' and int.from_bytes(props['load'],'big')==0x80200000
assert text(props['compression'])=='lzma'
d=lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
data=d.decompress(packed,max_length=0x3e00000)
assert d.eof and not d.unused_data and data[0x38:0x3c]==b'ARMd'
offset,size,flags=struct.unpack_from('<QQQ',data,8)
assert size>=len(data) and size and 0x80200000+size<=0x84000000
dt=tree(dtb)
assert b'tenda,be6l-pro\0' in dt['/']['compatible']
assert sum('read-only' in p for p in dt.values())==10
assert any('airoha,bmt-read-only' in p for p in dt.values())
report.update(verify_cpio(kernel, data, cpio))
layout_root=Path(report.get('hybrid_apk_offline_validation',{}).get('root','/root/be6l-openwrt/compat-rootfs/root'))
compiler,=src.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
layout_report=logs/'module-layout-audit.json'
subprocess.run([sys.executable,str(base/'tools/audit_module_layout.py'),
    '--kernel',str(kernel),'--root',str(layout_root),'--arch','arm64',
    '--cross-compile',str(compiler)[:-3],'--output',str(layout_report)],check=True)
report['module_layout_audit']=json.loads(layout_report.read_text())
dest=base/'artifacts/arm64-compat';dest.mkdir(exist_ok=True)
shutil.copyfile(images[0],dest/images[0].name)
if report.get('hybrid_apk_offline_validation'):
    root=Path(report['hybrid_apk_offline_validation']['root'])
    manifest=subprocess.check_output([str(src/'staging_dir/host/bin/apk'), '--root', str(root),
        '--arch', 'arm_cortex-a7', '--network=no', '--repositories-file', '/dev/null',
        'list', '--quiet', '--manifest'],text=True)
    manifest='\n'.join(line.replace(' ', ' - ', 1) for line in sorted(manifest.splitlines()))+'\n'
    manifest_path=dest/(images[0].stem+'.manifest')
    manifest_path.write_text(manifest)
    report['image_manifest_sha256']=hashlib.sha256(manifest.encode()).hexdigest()
    report['image_manifest_packages']=len(manifest.splitlines())
report['native_aarch64_userspace_usable']=False
shutil.copyfile(kernel/'.config',logs/'kernel.config')
report.update({'image':images[0].name,'image_sha256':hashlib.sha256(fit).hexdigest(),
               'kernel_image_bytes':len(data),'kernel_effective_bytes':size,
               'kernel_config_sha256':hashlib.sha256((kernel/'.config').read_bytes()).hexdigest(),
               'dtb_readonly_partitions':10,'standard_kernel_make':True,
               'userspace_build_exit':0,'ramboot_validated':False})
previous=dest/'build-validation.json'
if previous.exists():
    old=json.loads(previous.read_text())
    if old.get('image_sha256')==report['image_sha256']:
        for k in ['runtime_failure','ramboot_validated','runtime_evidence',
                  'current_image_dual_band_test_seconds_per_direction','current_image_300_second_qualified',
                  'current_image_active_lifecycle_qualified','current_image_active_lifecycle_evidence',
                  'wan_forwarding_baseline_evidence','mesh_initialization_evidence',
                  'first_long_test_failure','performance_conditions',
                  'nat_ipv6_offload_qualified','linux_per_flow_statistics_qualified']:
            if k in old:report[k]=old[k]
previous.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k not in ['elf64_modules_verified','module_payloads']},indent=2),flush=True)
