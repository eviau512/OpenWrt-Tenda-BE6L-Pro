# SPDX-License-Identifier: MIT
"""Compile and fault-test the actual patched watchdog functions, no DUT calls."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
BASE=HERE.parents[1]
sys.path.insert(0,str(BASE/'tools'))
from prepare_watchdog_handoff_v1 import SOURCES, PIN
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()


def function(source,name):
    match=re.search(r'^static [^\n]+\b'+name+r'\([^;]*?\)\n\{',source,re.M)
    assert match,name
    pos=match.end(); depth=1
    while depth:
        depth += (source[pos]=='{')-(source[pos]=='}'); pos+=1
    return source[match.start():pos]+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    args=parser.parse_args();work=args.work.resolve()
    assert work.parent==Path('/root/be6l-openwrt') and work.name.startswith('wdt-handoff-v1-')
    receipt=json.loads((work/'preparation.json').read_text())
    source=work/'airoha_wdt.c';assert sha(source)==receipt['patched_source_sha256']
    out=BASE/'logs'/time.strftime('wdt-handoff-v1-%Y%m%d-%H%M%S');out.mkdir()
    protected={}
    for arch,kernel in SOURCES.items():
        for p in [kernel/'drivers/watchdog/airoha_wdt.c',kernel/'.config',kernel/'Module.symvers',
                  kernel/'drivers/watchdog/airoha_wdt.o', *sorted(kernel.rglob('*.ko'))]:
            if p.is_file():protected[str(p)]=sha(p)
    assert all(sha(k/'drivers/watchdog/airoha_wdt.c')==PIN for k in SOURCES.values())
    text=source.read_text()
    defines=text[text.index('#define TIMER_CTRL'):text.index('/* Airoha watchdog structure')]
    descriptor=re.search(r'struct airoha_wdt_desc \{.*?\n\};',text,re.S)[0]
    names=['start','stop','ping','set_timeout','get_timeleft','shutdown','suspend','resume']
    functions='\n'.join(function(text,'airoha_wdt_'+name) for name in names)
    host=work/'actual-functions.c'
    host.write_text((HERE/'shim.c').read_text().replace('/* ACTUAL_FUNCTIONS */',defines+descriptor+'\n'+functions))
    subprocess.run(['cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fsanitize=undefined',
                    '-fno-sanitize-recover=all',str(host),'-o',str(work/'actual-functions')],check=True)
    result=json.loads(subprocess.check_output([str(work/'actual-functions')],text=True))
    env=dict(os.environ,PATH='/root/be6l-openwrt/host/bin:'+os.environ['PATH'],KCONFIG_NOSILENTUPDATE='1')
    objects={}
    for arch,kernel in SOURCES.items():
        sdk=Path('/root/be6l-openwrt')/('source' if arch=='arm' else 'arm64-source')
        candidates=list(sdk.glob('staging_dir/toolchain-*/bin/'+('arm' if arch=='arm' else 'aarch64')+'-openwrt-linux-musl*-gcc'))
        assert len(candidates)==1,candidates
        gcc=candidates[0];folder=work/('object-'+arch);assert not folder.exists();folder.mkdir()
        shutil.copyfile(source,folder/'airoha_wdt.c')
        (folder/'Makefile').write_text('obj-m += airoha_wdt.o\n')
        with (out/('compile-'+arch+'.txt')).open('wb') as log:
            subprocess.run(['make','-C',str(kernel),'M='+str(folder),'ARCH='+arch,
                            'CROSS_COMPILE='+str(gcc)[:-3],'SHELL=/root/be6l-openwrt/host/bin/bash',
                            'airoha_wdt.o'],env=dict(env,STAGING_DIR=str(sdk/'staging_dir')),
                           stdout=log,stderr=subprocess.STDOUT,check=True)
        data=(folder/'airoha_wdt.o').read_bytes()
        assert data[:4]==b'\x7fELF' and data[4]==(1 if arch=='arm' else 2)
        assert int.from_bytes(data[18:20],'little')==(40 if arch=='arm' else 183)
        objects[arch]=dict(sha256=sha(folder/'airoha_wdt.o'),bytes=len(data))
    assert all(sha(Path(p))==digest for p,digest in protected.items())
    result.update(schema=1,source_sha256=sha(source),objects=objects,protected_files=len(protected),
                  sdk_sources_configs_modules_unchanged=True,target_executed=False,image_built=False,
                  shutdown_cannot_abort_kexec=True,full_image_validation_pending=True,
                  source_function_sha256={name:hashlib.sha256(function(text,'airoha_wdt_'+name).encode()).hexdigest() for name in names})
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    (BASE/'logs/wdt-handoff-v1-latest.json').write_text(json.dumps(dict(directory=str(out)))+'\n')
    print(json.dumps(dict(directory=str(out),**result),indent=2))


if __name__=='__main__':main()
