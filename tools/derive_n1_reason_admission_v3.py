# SPDX-License-Identifier: MIT
"""Derive an exact v3 candidate gate; RAM payload remains closed initially."""
from pathlib import Path
import argparse
import hashlib
import json

b=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--payload-ready',action='store_true')
a=p.parse_args()
source=b/'tools/n1_candidate_admission.py'
assert hashlib.sha256(source.read_bytes()).hexdigest()=='e9dd5c6e849ecee5e51af8f48b6ab948ace09c3ca50c75a154267b9ae9bac142'
original=source.read_text(encoding='utf-8')
text=original
start=text.index('PAYLOAD_HASHES = {');end=text.index('def admit(artifact: Path):')
text=text[:start]+'''def admit_payload(artifact, manifest):
    raise RuntimeError('V3 RAM payload not yet pinned; execution is refused')


'''+text[end:]
text=text.replace('arm64-n1-diag-v2','arm64-n1-reasons-v3')
text=text.replace('inert N1 v2 candidate','inert N1 v3 candidate')
text=text.replace('9a3955e73fcee9bccee1c8bbf88a56f6eacaf8fa37c71ff6516d1a22578f2855',
                  'fd30e3894dfda619b1cd27e1575adb7388a58376a8fdb5c8b4ed88cbbea60835')
text=text.replace('aec580fec8a85629ba433306a62091dd507c5f527410953cac9b2962cd1fc59a',
                  '303589c428317ef31ff2e3fcdef8ffa5407bdff632238eb71414311cf4d6ec86')
needle="    assert report['n1_diagnostic_only'] is True"
assert text.count(needle)==1
text=text.replace(needle,needle+"\n    assert report['diagnostic_snapshot_version'] == 3")
destination=b/'tools/n1_reason_candidate_admission.py'
unprepared=text
if a.payload_ready:
    section=original[original.index('PAYLOAD_HASHES = {'):original.index('def admit(artifact: Path):')]
    section=section.replace('526b8f6c309393003e6c54e483f4885d29d4cfb66f50f451c4d91a9efcf7dcef',
                            'b27e0b5a28711e1fddb3afb87025f6bbdfa92b643919efcf28ea4db57867d0c4')
    start=text.index('def admit_payload(');end=text.index('def admit(artifact: Path):')
    text=text[:start]+section+text[end:]
    scope={}
    exec(compile(text,str(destination),'exec'),scope)
    artifact=b/'artifacts/arm64-n1-reasons-v3'
    scope['admit'](artifact)
    scope['admit_payload'](artifact,json.loads((artifact/'ramboot/manifest.json').read_text(encoding='utf-8')))
    assert not destination.exists() or destination.read_text(encoding='utf-8') in (unprepared,text)
else:
    assert not destination.exists()
compile(text,str(destination),'exec')
destination.write_text(text,encoding='utf-8',newline='\n')
print('V3_EXACT_CANDIDATE_AND_PAYLOAD_GATE_DERIVED' if a.payload_ready else 'V3_EXACT_CANDIDATE_GATE_DERIVED_RAM_EXECUTION_CLOSED')
