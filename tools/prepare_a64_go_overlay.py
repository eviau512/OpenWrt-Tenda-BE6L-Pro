# SPDX-License-Identifier: MIT
"""Build an independent Go compiler overlay for a verified soft-float omission."""
from pathlib import Path
import difflib
import hashlib
import json
import os
import subprocess
from a64_soft_context import BASE as base, ROOT as root

goroot=Path(os.environ.get('BE6L_GO_ROOT','/root/be6l-openwrt/source/staging_dir/hostpkg/lib/go-1.27'))
root.mkdir(exist_ok=True)
source=goroot/'src/cmd/compile/internal/ssagen/ssa.go'
text=source.read_text()
assert hashlib.sha256(source.read_bytes()).hexdigest()=='c4049961202dbfdf8b281b857a55e62ddbab04e109c1722aecbbf0a794983f81', 'Unreviewed Go compiler source'
start=text.index('func (s *state) minMax(')
before=text[:start];body=text[start:]
needle='\t\t\tif hasIntrinsic {'
assert body.count(needle)==1
changed=before+body.replace(needle,'\t\t\tif hasIntrinsic && !Arch.SoftFloat {',1)
replacement=root/'go-ssagen-ssa.go';replacement.write_text(changed)
overlay=root/'go-soft-overlay.json'
overlay.write_text(json.dumps({'Replace':{str(source):str(replacement)}},indent=2)+'\n')
(root/'go-minmax-softfloat.patch').write_text(''.join(difflib.unified_diff(
    text.splitlines(True),changed.splitlines(True),
    fromfile='a/src/cmd/compile/internal/ssagen/ssa.go',
    tofile='b/src/cmd/compile/internal/ssagen/ssa.go')))
env=dict(os.environ)
env.update(GOROOT=str(goroot),GOTOOLCHAIN='local',GOPROXY='off',GOSUMDB='off',
    GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',GOWORK='off',GOCACHE=str(root/'go-host-cache'))
log=base/'logs/a64-go-overlay-compiler-build.txt'
with log.open('w') as output:
    result=subprocess.run([str(goroot/'bin/go'),'build','-p','4','-trimpath',
        '-overlay='+str(overlay),'-o',str(root/'soft-compile'),'cmd/compile'],
        env=env,stdout=output,stderr=subprocess.STDOUT)
if result.returncode:print(log.read_text()[-5000:]);raise SystemExit(result.returncode)
helper=root/'go-soft-toolexec'
helper.write_text('#!/usr/bin/python3\nimport os,sys\ntool=sys.argv[1]\n'
    'if os.path.basename(tool)=="compile":tool='+repr(str(root/'soft-compile'))+'\n'
    'os.execv(tool,[sys.argv[1]]+sys.argv[2:])\n')
helper.chmod(0o755)
print('Independent compiler ready; original source SHA256='+hashlib.sha256(source.read_bytes()).hexdigest())
