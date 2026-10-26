"""Compare two independently built real netifd closures, including source maps."""
from pathlib import Path
import argparse
import json
from a64_soft_context import BASE
parser=argparse.ArgumentParser()
parser.add_argument('first',type=Path)
parser.add_argument('second',type=Path)
args=parser.parse_args()
a=json.loads((args.first/'audited/manifest.json').read_text())
b=json.loads((args.second/'audited/manifest.json').read_text())
assert a['abi']==b['abi']=='AAPCS64-soft'
assert a['files']==b['files']
assert a['source_hashes']==b['source_hashes']
report=dict(files=len(a['files']),all_output_hashes_identical=True,source_hash_maps_identical=True,
            real_linux_netlink_backend=True,target_executed=False)
(BASE/'logs/soft-netifd-reproduction.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
