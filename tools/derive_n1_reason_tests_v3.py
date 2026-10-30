"""Derive an isolated full-driver test with actual bounded-counter tests."""
from pathlib import Path
import hashlib

b=Path(__file__).resolve().parents[1]
source=b/'experiments/wired-kernel-diag-v2/run.py'
assert hashlib.sha256(source.read_bytes()).hexdigest()=='28e41960c12a282436a0f87c7dfbb44750611ae371982a9084e4c64fe6b9f926'
text=source.read_text(encoding='utf-8')
def once(old,new):
 global text
 assert text.count(old)==1,old[:100]
 text=text.replace(old,new)
once("work.name.startswith('n1-identity-v2-')","work.name.startswith('n1-reasons-v3-')")
once("time.strftime('n1-identity-v2-%Y%m%d-%H%M%S')","time.strftime('n1-reasons-v3-%Y%m%d-%H%M%S')")
once("actual = (HERE / 'test-record.c').read_text()","actual = (HERE.parent / 'wired-kernel-diag-v2/test-record.c').read_text()")
once("shutil.copyfile(HERE / 'record.h', work / 'record.h')",
     "shutil.copyfile(HERE.parent / 'wired-kernel-diag-v2/record.h', work / 'record.h')")
once("sha(work / '977-n1-identity-and-inert-driver-taps.patch')","sha(work / '978-n1-bounded-refusal-reasons.patch')")
once("(BASE / 'logs/n1-identity-v2-latest.json')","(BASE / 'logs/n1-reasons-v3-latest.json')")
once("print('N1_V2_OFFLINE_COMPILE_PASS', out)","print('N1_V3_COUNTERS_AND_FULL_DRIVER_COMPILE_PASS', out)")
needle="(out / 'result.json').write_text(json.dumps(result, indent=2) + '\\n')"
extra="""
reason_source = (HERE / 'test-reasons.c').read_text()
(work / 'actual-reasons.c').write_text(reason_source)
shutil.copyfile(driver / 'reasons.h', work / 'reasons.h')
with (out / 'counter-compile.txt').open('wb') as output:
    subprocess.run(['cc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-fsanitize=undefined,address', '-fno-sanitize-recover=all',
        str(work / 'actual-reasons.c'), '-o', str(work / 'actual-reasons')],
        stdout=output, stderr=subprocess.STDOUT, check=True)
reason_test = subprocess.check_output([str(work / 'actual-reasons')], text=True)
(out / 'actual-reasons.txt').write_text(reason_test)
reason_result = json.loads(reason_test)
assert reason_result['actual_header'] and reason_result['counter_cases'] == 27
result.update(diagnostic_snapshot_version=3, producer_context_version=2,
              counter_cases=reason_result['counter_cases'],
              actual_counter_header_sha256=sha(work / 'reasons.h'),
              counter_source_sha256=sha(work / 'actual-reasons.c'),
              same_admission_and_record_checks=True,
              diagnostic_counters_do_not_publish=True)
"""
once(needle,extra+'\n'+needle)
destination=b/'experiments/wired-kernel-diag-v3/run.py'
compile(text,str(destination),'exec')
destination.write_text(text,encoding='utf-8',newline='\n')
print('N1_V3_FULL_DRIVER_TEST_DERIVED_NO_HARDWARE')
