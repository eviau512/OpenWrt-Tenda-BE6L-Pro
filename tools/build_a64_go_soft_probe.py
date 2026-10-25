# SPDX-License-Identifier: MIT
"""Test the cached Go compiler's documented internal soft-float debug switch."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import argparse
from a64_soft_context import BASE as base, ROOT as root

parser=argparse.ArgumentParser();parser.add_argument('--assembly',action='store_true')
parser.add_argument('--overlay-compiler',action='store_true')
args=parser.parse_args()
goroot=Path(os.environ.get('BE6L_GO_ROOT','/root/be6l-openwrt/source/staging_dir/hostpkg/lib/go-1.27'))
root.mkdir(exist_ok=True)
out=base/'artifacts/a64-go-soft';out.mkdir(exist_ok=True)
env=dict(os.environ)
env.update(GOROOT=str(goroot),GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',
    GOOS='linux',GOARCH='arm64',GOARM64='v8.0',CGO_ENABLED='0',GOWORK='off',
    GOCACHE=str(root/'go-cache'))
log=base/('logs/a64-go-soft-'+('overlay' if args.overlay_compiler else 'baseline')+
          ('-assembly' if args.assembly else '')+'.txt')
with log.open('w') as output:
    flags=['-gcflags=all=-d=softfloat']
    if args.overlay_compiler:flags+=['-toolexec='+str(root/'go-soft-toolexec')]
    if args.assembly:flags+=['-gcflags=runtime=-d=softfloat -S']
    result=subprocess.run([str(goroot/'bin/go'),'build','-p','4','-trimpath',
        '-tags=purego',*flags,'-o',str(out/'go-probe'),
        str(base/'diagnostics/a64_go_soft_probe.go')],env=env,
        stdout=output,stderr=subprocess.STDOUT)
if result.returncode:
    text=log.read_text();errors='\n'.join(x for x in text.splitlines() if 'illegal combination' in x)
    print((errors if errors else text[-4000:])[-4000:])
else:
    data=(out/'go-probe').read_bytes()
    report={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
            'force_softfloat_debug_switch':True,'purego':True,
            'runtime_tested':False,'native_go_qualified':False}
    report['minmax_compiler_overlay']=args.overlay_compiler
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
raise SystemExit(result.returncode)
