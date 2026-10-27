# SPDX-License-Identifier: MIT
"""Export package records from the actual mixed root, not SDK native staging."""
from pathlib import Path
import argparse
import json
import subprocess
from a64_soft_context import BASE, SDK
from soft_abi_admission import digest

parser=argparse.ArgumentParser()
parser.add_argument('--artifact-name',choices=('arm64-soft-apk','arm64-rxhash'),default='arm64-soft-apk')
args=parser.parse_args()
out=BASE/'artifacts'/args.artifact_name
path=out/'build-validation.json'
report=json.loads(path.read_text())
root=Path(report['root'])
common=[str(SDK/'staging_dir/host/bin/apk'),'--root',str(root),'--network=no','--cache=no']
manifest=subprocess.check_output(common+['list','--quiet','--manifest'])
(out/'packages.manifest').write_bytes(manifest)
metadata=json.loads(subprocess.check_output(common+['query','--installed','--format','json',
    '--fields','name,version,arch,depends','*'],text=True))
selected={entry['name']:entry for entry in metadata}
assert len(selected)==212
assert selected['procd']['arch']=='aarch64_be6l_soft_experimental'
assert selected['libc']['arch']=='arm_cortex-a7'
assert selected['wpad-mbedtls']['arch']=='arm_cortex-a7'
for name in ('curl','lua','luci-lib-nixio','btop','tailscale','sing-box','luci-app-passwall'):
    assert name in selected,name
assert 'xray-core' not in selected
assert report['native_c_elfs']==58 and (root/'sbin/init').read_bytes()[4]==2
(out/'packages.json').write_text(json.dumps(metadata,indent=2)+'\n')
report.update(actual_package_manifest_verified=True, actual_packages=len(selected),
              actual_package_manifest_sha256=digest(manifest))
path.write_text(json.dumps(report,indent=2)+'\n')
print('ACTUAL_MIXED_PACKAGE_MANIFEST_VERIFIED',len(selected))
