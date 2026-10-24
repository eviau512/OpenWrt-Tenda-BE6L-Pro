"""WSL: bounded external CPIO experiment, ARM32 userspace + matching ARM64 modules.

This composes two standard OpenWrt builds for RAM qualification. It is not a
new official multi-ABI target or a qualified repository for kmod upgrades.
"""
from pathlib import Path
import hashlib,json,os,re,shutil,stat,struct,subprocess

base=Path(__file__).resolve().parents[1]
work=Path('/root/be6l-openwrt/compat-rootfs')
src32=Path('/root/be6l-openwrt/source')
src64=Path('/root/be6l-openwrt/arm64-source')
logs=base/'logs/arm64-compat-build'
assert (base/'logs/proxy-build-1213/build.exit').read_text().strip()=='0'
assert (logs/'kernel.exit').read_text().strip()=='0'
config64=(src64/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55/.config').read_text().splitlines()
for line in ['CONFIG_ARM64=y','CONFIG_64BIT=y','CONFIG_COMPAT=y','CONFIG_COMPAT_BINFMT_ELF=y','CONFIG_COMPAT_32BIT_TIME=y',
             'CONFIG_KUSER_HELPERS=y','CONFIG_PINCTRL_AIROHA_AN7563=y','CONFIG_MTD_NAND_MTK_BMT=y']:
    assert line in config64,line
original=src32/'build_dir/target-arm_cortex-a7_musl_eabi/root-airoha'
assert (original/'bin/busybox').is_file()
selected={m.group(1) for line in (src32/'.config').read_text().splitlines()
          if (m:=re.match(r'^CONFIG_PACKAGE_(kmod-[\w.-]+)=y$',line))}
work.mkdir(exist_ok=True)
owner=work/'.owner'
assert not owner.exists() or owner.read_text()=='be6l-compat-1213\n'
owner.write_text('be6l-compat-1213\n')
root=work/'root'
if root.exists():
    assert root.resolve()==Path('/root/be6l-openwrt/compat-rootfs/root') and owner.read_text()=='be6l-compat-1213\n'
    shutil.rmtree(root)
shutil.copytree(original,root,symlinks=True)
oldmodules={p.name for p in (root/'lib/modules').rglob('*.ko')}
shutil.rmtree(root/'lib/modules')
for name in ['modules.d','modules-boot.d']:
    p=root/'etc'/name
    if p.exists():shutil.rmtree(p)
linux64=src64/'build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64'
payloads={}
for parent in [*linux64.glob('*/ipkg-aarch64_cortex-a53'),*linux64.glob('*/*/ipkg-aarch64_cortex-a53')]:
    for p in parent.iterdir():
        if p.is_dir() and (p.name in selected or p.name=='kernel'):
            assert p.name not in payloads,p.name
            payloads[p.name]=p
assert {'kernel','kmod-mt7996e','kmod-tun','kmod-nft-tproxy'}<=payloads.keys(),sorted(payloads)
for name,p in sorted(payloads.items()):
    for child in p.iterdir():
        if child.name.startswith('.') or child.name=='CONTROL':continue
        dest=root/child.name
        if child.is_dir():shutil.copytree(child,dest,symlinks=True,dirs_exist_ok=True)
        else:shutil.copy2(child,dest,follow_symlinks=False)
modulepaths=list((root/'lib/modules').rglob('*.ko'))
newmodules={p.name for p in modulepaths}
# Built-ins can legitimately replace modules, but require explicit evidence.
builtin=linux64/'linux-6.18.55/modules.builtin'
builtins={Path(x).name for x in builtin.read_text().splitlines()}
assert oldmodules<=newmodules|builtins,sorted(oldmodules-newmodules-builtins)
for name in ['bin/busybox','usr/bin/curl','usr/bin/lua','usr/bin/btop',
             'usr/lib/lua/nixio.so','usr/bin/sing-box','usr/sbin/tailscaled']:
    p=root/name
    data=p.read_bytes()[:64]
    assert data[:6]==b'\x7fELF\x01\x01' and struct.unpack_from('<H',data,18)[0]==40,name
for name in ['www/luci-static/argon','usr/lib/lua/luci/i18n/base.zh-cn.lmo',
             'usr/lib/lua/luci/i18n/passwall.zh-cn.lmo',
             'etc/init.d/passwall','etc/uci-defaults/98-be6l-proxy-packages']:
    assert (root/name).exists(),name
# Run our own default after the package's own uci-defaults scripts.
(root/'etc/uci-defaults/98-be6l-proxy-packages').rename(root/'etc/uci-defaults/zz-be6l-proxy-packages')
for name in ['xray','xray-plugin','hysteria','naive','ss-local','ss-redir','ssr-local','ssr-redir']:
    assert not(root/'usr/bin'/name).exists(),name
assert not list((root/'usr/bin').glob('portal_autologin*'))
for p in (root/'etc/crontabs').glob('*'):
    if p.is_file():assert 'portal_autologin' not in p.read_text()
assert (root/'lib/ld-musl-arm.so.1').exists()
elf32=[];elf64modules={}
for p in root.rglob('*'):
    if p.is_symlink() or not p.is_file():continue
    with p.open('rb') as f:hdr=f.read(20)
    if not hdr.startswith(b'\x7fELF'):continue
    rel=str(p.relative_to(root));machine=struct.unpack_from('<H',hdr,18)[0]
    if rel.startswith('lib/firmware/'):continue
    if rel.startswith('lib/modules/') and rel.endswith('.ko'):
        assert hdr[4]==2 and machine==183,rel
        elf64modules[rel]=hashlib.sha256(p.read_bytes()).hexdigest()
    else:
        assert hdr[4]==1 and machine==40,(rel,machine)
        elf32.append(rel)
assert len(elf64modules)>30 and len(elf32)>30
shutil.copyfile(src32/'target/linux/generic/other-files/init',root/'init')
(root/'init').chmod(0o755)
(root/'dev').mkdir(exist_ok=True)
report={'runtime_abi':'aarch64_kernel_arm_eabi_soft_userspace',
        'openwrt_commit':'30b833ae5b8a6ba94149268c47a8493308a0ee04',
        'user_package_arch':'arm_cortex-a7','kernel_module_arch':'ELF64 AArch64',
        'elf32_userspace_verified':len(elf32),'elf64_modules_verified':elf64modules,
        'module_payloads':sorted(payloads),'kernel_vermagic':(linux64/'linux-6.18.55/.vermagic').read_text().strip(),
        'config32_sha256':hashlib.sha256((src32/'.config').read_bytes()).hexdigest(),
        'config64_sha256':hashlib.sha256((src64/'.config').read_bytes()).hexdigest(),
        'package_metadata_qualification':'External CPIO experiment; ARM32 APK database is not qualified for kernel/kmod upgrades.',
        'tailscale_login':False,'passwall_enabled_by_default':False,'proxy_core':'sing-box only',
        'flash_images':False,'ramboot_validated':False}
(root/'etc/be6l-compat-build.json').write_text(json.dumps({k:v for k,v in report.items() if k!='elf64_modules_verified'},indent=2)+'\n')
epoch=int(subprocess.check_output(['git','show','-s','--format=%ct','HEAD'],cwd=src32,text=True))
paths=['.']+sorted(str(p.relative_to(root)) for p in root.rglob('*'))
for name in paths:os.utime(root/name,(epoch,epoch),follow_symlinks=False)
cpio=work/'rootfs.cpio'
with cpio.open('wb') as f:
    subprocess.run([str(src32/'staging_dir/host/bin/cpio'),'--null','--reproducible','-o','-H','newc','-R','0:0'],
                   cwd=root,input=('\0'.join(paths)+'\0').encode(),stdout=f,check=True)
# Linux initramfs accepts concatenated newc archives. Use its own generator
# for device nodes instead of depending on mknod support in the WSL host.
device_list=work/'device-nodes.list'
device_list.write_text('nod /dev/console 0600 0 0 c 5 1\nnod /dev/null 0666 0 0 c 1 3\n')
with cpio.open('ab') as f:
    subprocess.run([str(linux64/'linux-6.18.55/usr/gen_init_cpio'),'-t',str(epoch),str(device_list)],stdout=f,check=True)
report['external_cpio_sha256']=hashlib.sha256(cpio.read_bytes()).hexdigest()
report['external_cpio_bytes']=cpio.stat().st_size
(logs/'rootfs-validation.json').write_text(json.dumps(report,indent=2)+'\n')
print('COMPAT_ROOTFS_VERIFIED',json.dumps({k:v for k,v in report.items() if k not in ['elf64_modules_verified','module_payloads']}),flush=True)
