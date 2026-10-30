# SPDX-License-Identifier: MIT
"""Normal OpenWrt ARM32 handoff build, isolated outputs and preserved baseline."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time

BASE=Path(__file__).resolve().parents[1]
SDK=Path('/root/be6l-openwrt/source')
PIN='30b833ae5b8a6ba94149268c47a8493308a0ee04'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage',choices=('prepare','build','resume-install'))
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args();work=args.work.resolve()
    assert work.parent==Path('/root/be6l-openwrt') and work.name.startswith('arm32-handoff-v1-')
    assert subprocess.check_output(['git','-C',str(SDK),'rev-parse','HEAD'],text=True).strip()==PIN
    source=Path('/root/be6l-openwrt/wdt-handoff-v1-20261030-r1')
    patch=source/'976-watchdog-checked-kexec-handoff.patch'
    assert sha(patch)=='bcd2a978fc264f6a2e658ccc9aa0420934aaa139dd29850fcab5c8213aff2d92'
    dest=SDK/'target/linux/airoha/patches-6.18'/patch.name
    if args.stage=='prepare':
        assert not work.exists() and not dest.exists()
        for name in ('ui-build-validation.json','ramboot/manifest.json'):
            assert (BASE/'artifacts'/name).is_file()
        guard={str(p):sha(p) for p in (BASE/'artifacts').rglob('*initramfs-kernel.bin')}
        guard[str(BASE/'artifacts/ramboot/manifest.json')]=sha(BASE/'artifacts/ramboot/manifest.json')
        config=(SDK/'.config').read_text()
        for line in ('CONFIG_TARGET_ROOTFS_INITRAMFS=y','# CONFIG_TARGET_ROOTFS_SQUASHFS is not set',
                     'CONFIG_TARGET_INITRAMFS_COMPRESSION_GZIP=y','CONFIG_PACKAGE_wpad-mbedtls=y'):
            assert line in config.splitlines(),line
        work.mkdir();shutil.copyfile(SDK/'.config',work/'sdk-config-before')
        shutil.copyfile(patch,dest)
        records={p.name:sha(p) for p in dest.parent.glob('*.patch')}
        receipt=dict(schema=1,work=str(work),sdk=str(SDK),openwrt_commit=PIN,
            sdk_config_sha256=sha(SDK/'.config'),patches=records,immutable_artifacts=guard,
            fixed_source_patch_sha256=sha(patch),only_initramfs=True,
            device_operation=False,build_started=False,build_completed=False)
        (work/'owner.json').write_text(json.dumps(receipt,indent=2)+'\n')
        print('ARM32_NORMAL_BUILD_PREPARED',work);return
    receipt=json.loads((work/'owner.json').read_text());assert receipt['work']==str(work)
    assert sha(SDK/'.config')==receipt['sdk_config_sha256']
    assert {p.name:sha(p) for p in dest.parent.glob('*.patch')}==receipt['patches']
    assert all(sha(Path(p))==digest for p,digest in receipt['immutable_artifacts'].items())
    if args.stage=='build':
        assert not (work/'build-started.json').exists()
        (work/'build-started.json').write_text(json.dumps(dict(pid=os.getpid(),started_epoch=time.time()))+'\n')
        previous=[]
    else:
        prior=json.loads((work/'build-result.json').read_text())
        previous=prior['stages']
        assert prior['owned_build_finished'] and not prior['build_completed']
        assert previous[-1]==dict(stage='package-install',status=2)
        assert all(x['status']==0 for x in previous[:-1])
        assert sha(SDK/'build_dir/target-arm_cortex-a7_musl_eabi/linux-airoha_an7563/linux-6.18.55/drivers/watchdog/airoha_wdt.c')=='e98c5a4f09bfffc596d2e3914e69da9c0511137ba15f11b65f56c3c1cb3fefce'
        shutil.copyfile(work/'build-result.json',work/'failed-install-before-path-fix.json')
        receipt.update(previous_failure_preserved=True,resume_reason='GNU find -execdir rejected inherited Windows PATH')
    env=dict(os.environ,FORCE_UNSAFE_CONFIGURE='1',SOURCE_DATE_EPOCH='1792420077',
        CONFIG_SHELL='/root/be6l-openwrt/host/bin/bash',
        PATH='/root/be6l-openwrt/host/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off')
    stages=[('kernel-clean',['target/linux/clean']),
            ('external-clean',['package/kernel/mt76/clean','package/kernel/mac80211/clean','package/kernel/bpf-headers/clean']),
            ('kernel-compile',['-j4','target/linux/compile']),
            ('package-compile',['-j4','package/compile']),
            ('package-install',['package/install']),
            ('target-install',['-j4','target/linux/install'])]
    if args.stage=='resume-install':stages=stages[-2:]
    results=previous[:-1] if previous else []
    try:
        for label,targets in stages:
            print('NORMAL_BUILD_STAGE',label,flush=True)
            with (work/(label+'.log')).open('wb') as log:
                result=subprocess.run(['make','SHELL='+env['CONFIG_SHELL'],'V=s',*targets],
                    cwd=SDK,env=env,stdout=log,stderr=subprocess.STDOUT)
            results.append(dict(stage=label,status=result.returncode))
            (work/'stages.json').write_text(json.dumps(results,indent=2)+'\n')
            assert result.returncode==0,(label,result.returncode)
        image=SDK/'bin/targets/airoha/an7563/openwrt-airoha-an7563-tenda_be6l-pro-initramfs-kernel.bin'
        assert image.is_file()
        out=BASE/'artifacts/arm32-wdt-handoff-v1';assert not out.exists();out.mkdir()
        shutil.copyfile(image,out/image.name)
        for name in ('profiles.json','sha256sums','config.buildinfo','openwrt-airoha-an7563-tenda_be6l-pro.manifest'):
            p=image.parent/name
            if p.is_file():shutil.copyfile(p,out/name)
        receipt.update(build_completed=True,image_sha256=sha(image),image_bytes=image.stat().st_size,
            artifact_dir=str(out),sdk_config_after_sha256=sha(SDK/'.config'),
            target_executed=False,full_image_admission_pending=True)
    finally:
        assert all(sha(Path(p))==digest for p,digest in receipt['immutable_artifacts'].items())
        receipt.update(stages=results,owned_build_finished=True)
        (work/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print('ARM32_NORMAL_BUILD_COMPLETE_REQUIRES_IMAGE_ADMISSION',work,flush=True)


if __name__=='__main__':main()
