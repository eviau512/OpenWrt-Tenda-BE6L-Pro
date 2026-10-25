# SPDX-License-Identifier: MIT
"""Fresh isolated C soft-float build; this does not produce a firmware image."""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

base=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--root',required=True)
parser.add_argument('--resume',action='store_true')
args=parser.parse_args()
root=Path(args.root)
assert root.is_absolute() and not any(c.isspace() for c in str(root))
marker=root/'.be6l-soft-suite'
if args.resume:
    assert marker.is_file() and marker.read_text()=='AAPCS64-soft C experiment\n'
else:
    assert not root.exists(), 'Choose a new output directory; no directory is deleted'
    root.mkdir();marker.write_text('AAPCS64-soft C experiment\n')
env=dict(os.environ);env['BE6L_SOFT_ROOT']=str(root)
run=base/'logs'/('soft-suite-'+root.name)
(base/'logs').mkdir(exist_ok=True)
run.mkdir(exist_ok=True)
steps=[('build_a64_soft_musl.py',['prepare']),('build_a64_soft_musl.py',['libc']),
       ('build_a64_soft_musl.py',['runtime']),('build_a64_soft_musl.py',['link']),
       ('build_a64_soft_tests.py',[]),('build_a64_soft_busybox.py',[])]+[
       ('build_a64_soft_core.py',[name]) for name in ('jsonc','libubox','ubus','uci','ucode','udebug','procd')]+[
       ('prepare_a64_soft_core.py',[])]
for script,flags in steps:
    if args.resume and flags==['prepare'] and (root/'musl/configure').exists():continue
    print('STAGE',script,*flags,flush=True)
    result=subprocess.run([sys.executable,str(base/'tools'/script),*flags],env=env)
    # Preserve each stage's own logs before any later clean reproduction.
    for pattern in ('a64-soft-*.txt',):
        for log in (base/'logs').glob(pattern):shutil.copyfile(log,run/log.name)
    if result.returncode:raise SystemExit(result.returncode)
for name in ('a64-soft-userspace','a64-soft-core'):
    shutil.copyfile(base/'artifacts'/name/'manifest.json',run/(name+'-manifest.json'))
(run/'build-result.json').write_text(json.dumps({'root':str(root),'clean_start':not args.resume,
    'c_suite_built':True,'firmware_image_built':False,'runtime_tested':False},indent=2)+'\n')
print('SOFT_C_SUITE_BUILD_PASS',run,flush=True)
