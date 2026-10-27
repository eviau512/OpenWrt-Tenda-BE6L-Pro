# SPDX-License-Identifier: MIT
"""Fetch one required compiler-rt helper at the already pinned LLVM commit."""
from pathlib import Path
import base64
import hashlib
import json
import urllib.request
base=Path(__file__).resolve().parents[1]
commit='2078da43e25a4623cab2d0d60decddf709aaea28'
assert json.loads((base/'upstream/llvm21-soft-builtins-lock.json').read_text())['commit']==commit
name='floatunsisf.c'
url='https://api.github.com/repos/llvm/llvm-project/contents/compiler-rt/lib/builtins/'+name+'?ref='+commit
req=urllib.request.Request(url,headers={'Accept':'application/vnd.github+json','User-Agent':'BE6L-source-audit'})
with urllib.request.urlopen(req,timeout=30) as r:meta=json.load(r)
assert meta['type']=='file' and meta['name']==name and meta['encoding']=='base64'
data=base64.b64decode(meta['content'])
blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
assert blob==meta['sha'] and len(data)==meta['size'] and len(data)<10000
assert len(data)==1774 and blob=='ec062b5943e98cb0c2b6588d5b7c728ae7a4d5e3'
assert hashlib.sha256(data).hexdigest()=='a002e5243cabecefc49858dc505b1a3f89fdd75362adb00e4bbe3eb707fff9a4'
assert b'Apache-2.0 WITH LLVM-exception' in data
dest=base/'upstream/llvm21-soft-builtins-extra';dest.mkdir(exist_ok=True)
path=dest/name
if path.exists():assert path.read_bytes()==data
else:path.write_bytes(data)
lock=dict(commit=commit,files=[dict(name=name,bytes=len(data),git_blob=blob,
    sha256=hashlib.sha256(data).hexdigest())],license_from='llvm21-soft-builtins/LICENSE.TXT')
(base/'upstream/llvm21-soft-builtins-extra-lock.json').write_text(json.dumps(lock,indent=2)+'\n')
print('ONE_PINNED_RUNTIME_SOURCE_FETCHED',name,len(data),hashlib.sha256(data).hexdigest())
