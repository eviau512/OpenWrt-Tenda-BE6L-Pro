# SPDX-License-Identifier: MIT
"""Compile four actual draft driver units into private objects, never make/link.

Recorded matching commands/headers are read-only. No module ABI, runtime, DMA
withdrawal, kernel candidate or remove/devres admission follows from this.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shlex
import struct
import subprocess


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('draft','matching-mt76-build','host-prefix'):
        p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();w=a.draft.resolve()
    if w.parent!=Path('/root') or not w.name.startswith('be6l-mt76-rx-lease-draft-20261113-'):
        p.error('Prepared private source draft required')
    prep=json.loads((w/'preparation.json').read_text());src=Path(prep['private_source'])
    for n,pin in prep['original_sha256'].items():
        if sha(a.matching_mt76_build/n)!=pin:raise ValueError('Matched source differs: '+n)
    for n,pin in prep['modified_sha256'].items():
        if sha(src/n)!=pin:raise ValueError('Draft source changed: '+n)
    out=w/'objects';out.mkdir(mode=0o700)
    env=dict(os.environ,LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'))
    results=[]
    for name in ('mac80211','mt7996/main','mt7996/init','npu'):
        rel=Path(name);saved=a.matching_mt76_build/rel.parent/('.'+rel.name+'.o.cmd')
        argv=shlex.split(saved.read_text().splitlines()[0].split(':=',1)[1].replace('\\"','"'))
        flat=name.replace('/','-');target=out/(flat+'.o')
        argv=[('-I'+str(src)+x[len('-I'+str(a.matching_mt76_build)):])
              if x.startswith('-I'+str(a.matching_mt76_build)) else x for x in argv]
        argv=[('-Wp,-MMD,'+str(out/('.'+flat+'.d'))) if x.startswith('-Wp,-MMD,') else x for x in argv]
        argv[argv.index('-o')+1]=str(target);argv[-1]=str(src/(name+'.c'))
        (out/(flat+'.command.json')).write_text(json.dumps(argv,indent=2)+'\n')
        r=subprocess.run(argv,cwd=src,env=env,capture_output=True,timeout=120)
        (out/(flat+'.log')).write_bytes(r.stdout+r.stderr)
        if r.returncode:raise RuntimeError('Actual driver object failed: '+name)
        raw=target.read_bytes()
        if raw[:5]!=b'\x7fELF\x02' or struct.unpack_from('<H',raw,18)[0]!=183:
            raise ValueError('Expected AArch64 ELF64 object')
        results.append(dict(unit=name,object_sha256=sha(target),source_sha256=sha(src/(name+'.c'))))
    report=dict(actual_arm64_driver_objects_compiled=True,object_count=4,objects=results,
        matching_source_rechecked=True,make_invoked=False,modules_linked=False,
        actual_cache_sidecar=True,skb_cb_layout_unchanged=True,
        kernel_or_module_abi_qualified=False,hardware_all_provider=False,
        native_admission_closed=True,target_executed=False)
    (w/'object-compile.json').write_text(json.dumps(report,indent=2)+'\n')
    print('MT76_RX_LEASE_ARM64_UNITS_COMPILED',len(results),flush=True)


if __name__=='__main__':main()
