# SPDX-License-Identifier: MIT
"""Inventory a first native netifd step; no package/image/default is changed."""
from pathlib import Path
import argparse
import hashlib
import json
from native_services_admission_v2 import admit
from a64_soft_context import BASE

p=argparse.ArgumentParser()
p.add_argument('--profile',type=Path,required=True)
p.add_argument('--trusted-profile-sha256',required=True)
a=p.parse_args()
profile=admit(a.profile,a.trusted_profile_sha256)
root='opt/be6l-a64-soft/bin/netifd'
assert root in profile['files']
providers=profile['needed_providers']
todo=[root];selected={}
while todo:
 name=todo.pop()
 if name in selected:continue
 metadata=profile['files'][name]
 data=(a.profile/'payload'/name).read_bytes()
 assert hashlib.sha256(data).hexdigest()==metadata['sha256']
 assert metadata['fp_simd_register_uses']==0
 selected[name]=metadata
 for dependency in metadata['needed']:
  assert dependency in providers,(name,dependency)
  todo.append(providers[dependency])
added={name:metadata for name,metadata in selected.items() if name in profile['new_paths']}
dynamic={name:metadata['bytes'] for name,metadata in profile['files'].items()
         if name.startswith('opt/be6l-a64-soft/lib/ucode/')}
report=dict(profile_sha256=a.trusted_profile_sha256,
    profile_paths=len(profile['files']),entry=root,
    dt_needed_closure=selected,new_dt_needed_paths=added,
    new_dt_needed_raw_bytes=sum(v['bytes'] for v in added.values()),
    candidate_ucode_dynamic_modules=dynamic,
    only_dt_needed_accounted=True,complete_execution_closure_qualified=False,
    compressed_budget_measured=False,normal_replacement_package_built=False,
    default_execution_paths_modified=False,sdk_or_image_modified=False,
    remaining_gates=[
      'Verify embedded ucode dynamic-load defaults and every required module/child.',
      'Normally replace the component-owned default path with explicit ABI dependencies.',
      'Measure the actual signed package transaction/CPIO and rebuilt Image boundary.',
      'Qualify real DHCP/DNS/firewall/wireless/service restarts on a new RAM image.'])
path=BASE/'logs/native-netifd-first-stage-inventory-20261030.json'
path.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(dt_needed_paths=len(selected),new_dt_needed_paths=list(added),
                     new_raw_bytes=report['new_dt_needed_raw_bytes'],
                     dynamic_modules_not_yet_selected=len(dynamic),
                     review_only=True),indent=2))
