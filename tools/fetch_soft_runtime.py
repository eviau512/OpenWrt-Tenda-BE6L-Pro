# SPDX-License-Identifier: MIT
"""Fetch only hash-locked compiler-rt files; never fetch an LLVM source tree."""
from pathlib import Path
import hashlib
import json
import re
import urllib.request

base=Path(__file__).resolve().parents[1]
lock=json.loads((base/'upstream/llvm21-soft-builtins-lock.json').read_text())
commit=lock['commit']
assert re.fullmatch('[0-9a-f]{40}',commit)
out=base/'upstream/llvm21-soft-builtins';out.mkdir(exist_ok=True)
for item in lock['files']:
    name=item['name']
    assert re.fullmatch(r'[A-Za-z0-9_.-]+',name) and '..' not in name
    path=out/name
    if path.exists():data=path.read_bytes()
    else:
        url='https://raw.githubusercontent.com/llvm/llvm-project/'+commit+'/compiler-rt/'+('' if name=='LICENSE.TXT' else 'lib/builtins/')+name
        with urllib.request.urlopen(url,timeout=30) as response:data=response.read()
    assert len(data)==item['bytes'] and hashlib.sha256(data).hexdigest()==item['sha256'],name
    if 'git_blob' in item:
        assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==item['git_blob'],name
    path.write_bytes(data)
manifest={'commit':commit,'files':[item for item in lock['files'] if item['name']!='LICENSE.TXT']}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print('Verified compiler-rt files:',len(lock['files']))
