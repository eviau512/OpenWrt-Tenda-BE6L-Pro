#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build actual cached musl1.2.6 for native-host bare-preload chain tests.

Three host prefixes model three separate musl search domains. They are not
three target ABIs, target execution, a jail, secureexec or mainroot admission.
No deployed LD_LIBRARY_PATH, interpreter rewriting or environment clearing.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import re
import shutil
import subprocess
import tarfile
import time


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--host-prefix', type=Path, required=True)
    p.add_argument('--musl-archive', type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-procd-preload-host-20261113-') or w.exists():
        p.error('fresh private /root/be6l-procd-preload-host-20261113-* required')
    w.mkdir(mode=0o700)
    hp = a.host_prefix.resolve()
    src = Path(__file__).resolve().parents[1]/'experiments/procd-mixed-abi'
    env = dict(os.environ, PATH=str(hp/'usr/bin')+':/usr/bin:/bin',
               LD_LIBRARY_PATH=str(hp/'usr/lib/x86_64-linux-gnu')+':'+str(hp/'lib/x86_64-linux-gnu'))
    logs = w/'logs'; logs.mkdir()

    def run(name, cmd, cwd=None, timeout=240, allowed=(0,)):
        r = subprocess.run(list(map(str,cmd)),cwd=cwd,env=env,capture_output=True,timeout=timeout)
        (logs/(name+'.log')).write_bytes(r.stdout+r.stderr)
        if r.returncode not in allowed: raise RuntimeError(name+' failed: '+str(logs/(name+'.log')))
        return r

    # Pinned downloaded source, copied/extracted only inside new private work.
    with tarfile.open(a.musl_archive) as archive:
        archive.extractall(w, filter='data')
    ms = w/'musl-1.2.6'
    cc = w/'hostcc'
    cc.write_text('#!/bin/sh\nexec '+str(hp/'usr/bin/gcc')+' --sysroot='+str(hp)+
                  ' -isystem '+str(hp/'usr/include/x86_64-linux-gnu')+' -L'+str(hp/'usr/lib/x86_64-linux-gnu')+' "$@"\n')
    cc.chmod(0o755)
    # Private host environment is needed by compiler tools, never passed to the
    # fixture itself; fixture loading uses actual musl prefix .path handling.
    buildenv = dict(env,CC=str(cc))
    oldenv = env; env = buildenv
    run('musl-configure',[ms/'configure','--prefix='+str(w/'host-musl'),'--syslibdir='+str(w/'host-musl/lib'),
                          '--disable-gcc-wrapper'],cwd=ms)
    run('musl-build',[hp/'usr/bin/make','-j4'],cwd=ms,timeout=600)
    run('musl-install',[hp/'usr/bin/make','install'],cwd=ms)
    env = oldenv
    built = w/'host-musl'
    if not (built/'lib/libc.so').is_file(): raise ValueError('actual shared musl missing')
    muslcc = w/'muslcc'
    muslcc.write_text('#!/bin/sh\nexec '+str(hp/'usr/bin/gcc')+' --sysroot='+str(hp)+' -nostdinc -isystem '+str(built/'include')+
        ' -nostdlib '+str(built/'lib/crt1.o')+' '+str(built/'lib/crti.o')+' "$@" -L'+str(built/'lib')+
        ' -lc '+str(built/'lib/crtn.o')+'\n')
    muslcc.chmod(0o755)
    programs = []
    for i in range(3):
        prefix = w/('slot'+str(i)); (prefix/'lib').mkdir(parents=True); (prefix/'etc').mkdir()
        shutil.copyfile(built/'lib/libc.so',prefix/'lib/ld-musl-x86_64.so.1')
        (prefix/'lib/ld-musl-x86_64.so.1').chmod(0o755)
        (prefix/'lib/libc.so').symlink_to('ld-musl-x86_64.so.1')
        (prefix/'etc/ld-musl-x86_64.path').write_text(str(prefix/'lib')+'\n')
        # Library has the production constructor, no test-only env mutation.
        run('logger'+str(i),[hp/'usr/bin/gcc','--sysroot='+str(hp),'-nostdinc','-isystem',built/'include','-nostdlib','-shared','-fPIC','-O2',
             src/'setlbf.c','-Wl,-soname,libbe6l-setlbf.so','-L'+str(built/'lib'),'-lc',
             '-o',prefix/'lib/libbe6l-setlbf.so'])
        program = prefix/'probe'
        run('fixture'+str(i),[muslcc,'-O2',src/'host-fixture.c','-I'+str(src),
             '-Wl,--dynamic-linker='+str(prefix/'lib/ld-musl-x86_64.so.1'),'-o',program])
        programs.append(program)
    static = w/'static-helper'
    run('static-helper',[muslcc,'-static','-O2',src/'host-fixture.c','-I'+str(src),'-o',static])
    run('mount-policy',[static,'mount-policy'])
    cases = []

    def check(name, command, preload=True, expected_exec=None, expected_logger=None):
        report_r, report_w = os.pipe(); ack_r, ack_w = os.pipe()
        # Preserve exactly FD3/4 by a child-only dup; original pipes may happen
        # to use 3/4, so clone them high before spawning.
        import fcntl
        report_hi = fcntl.fcntl(report_w,fcntl.F_DUPFD,20)
        ack_hi = fcntl.fcntl(ack_r,fcntl.F_DUPFD,20)
        fixture_env = {'PATH':'/usr/bin:/bin'}
        if preload: fixture_env['LD_PRELOAD'] = 'libbe6l-setlbf.so'
        def setup():
            os.dup2(report_hi,3); os.dup2(ack_hi,4)
        child = subprocess.Popen(list(map(str,command)),env=fixture_env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                   close_fds=False,preexec_fn=setup)
        for fd in (report_w,ack_r,report_hi,ack_hi): os.close(fd)
        try:
            if not select.select([report_r],[],[],5)[0]: raise RuntimeError(name+' no ready')
            report = os.read(report_r,8192).decode()
            if 'READY ' not in report or ('preload=libbe6l-setlbf.so' in report) != preload:
                raise ValueError(name+' wrong inherited env/report: '+report)
            if expected_exec is not None and 'execfn='+str(expected_exec)+' ' not in report:
                raise ValueError(name+' AT_EXECFN changed: '+report)
            reported_pid = int(re.search(r'READY pid=(\d+) ',report).group(1))
            maps = Path('/proc/'+str(reported_pid)+'/maps').read_text()
            mapped = sorted({row.split()[-1] for row in maps.splitlines() if 'libbe6l-setlbf.so' in row})
            wanted = expected_logger or (expected_exec.parent/'lib/libbe6l-setlbf.so' if expected_exec in programs else None)
            if preload and (wanted is None or mapped != [str(wanted)]):
                raise ValueError(name+' wrong actual library mapping: '+repr(mapped))
            if not preload and mapped: raise ValueError('negative control unexpectedly preloaded')
            live = bool(select.select([child.stdout],[],[],0.25)[0])
            token = os.read(child.stdout.fileno(),128) if live else b''
            if live != preload or (preload and token != b'LIVE_UNBUFFERED_TOKEN'):
                raise ValueError(name+' live buffering wrong')
            os.write(ack_w,b'x')
            tail,err = child.communicate(timeout=5)
            if child.returncode or err: raise ValueError(name+' child failure '+repr(err))
            if token+tail != b'LIVE_UNBUFFERED_TOKEN': raise ValueError(name+' wrong stdout')
            cases.append(dict(name=name,pass_=True,live_unbuffered=live,mapped_loggers=mapped,report=report.strip()))
        finally:
            if child.poll() is None: child.kill(); child.wait(timeout=5)
            os.close(report_r); os.close(ack_w)

    for i,program in enumerate(programs): check('bare-slot'+str(i),[program],expected_exec=program)
    check('buffered-negative-control',[programs[0]],False,expected_exec=programs[0])
    check('dynamic-helper-different-slot',[programs[0],'exec',programs[1]],expected_exec=programs[1])
    check('static-helper-to-different-slot',[static,'exec',programs[2]],expected_exec=programs[2])
    check('fork-exec-descendant',[programs[1],'descendant',programs[2]],expected_exec=programs[2])
    # Real kernel shebang supplies its original pathname to AT_EXECFN; the
    # interpreter's argv0 is unchanged by this preload approach.
    script = w/'direct-script'
    script.write_text('#!'+str(programs[0])+'\n')
    script.chmod(0o755)
    check('kernel-shebang-original-execfn',[script],expected_exec=script,expected_logger=programs[0].parent/'lib/libbe6l-setlbf.so')
    # Concrete guard against the rejected executable-FD wrapper approach.
    negative = run('cloexec-empty-path-shebang-ENOENT',[static,'cloexec-script',script],allowed=(0,77))
    cases.append(dict(name='cloexec-empty-path-shebang-ENOENT',pass_=negative.returncode == 0,
        status='PASS' if negative.returncode == 0 else 'UNSUPPORTED_ENOSYS',
        measured_errno=negative.stderr.decode().strip(),target_qualified=False))
    cases.append(dict(name='mount-policy-six-branches',pass_=True))
    result = dict(revision=1,host_only=True,target_executed=False,secureexec_qualified=False,
        full_standard_a53_compatibility_qualified=False,actual_musl_archive_sha256=sha(a.musl_archive),
        actual_dynlink_sha256=sha(ms/'ldso/dynlink.c'),actual_host_libc_sha256=sha(built/'lib/libc.so'),
        source_sha256={n:sha(src/n) for n in ('setlbf.c','host-fixture.c','bootstrap-mount.h')},
        fixture_no_ld_library_path=True,case_count=len(cases),passed_case_count=sum(t['pass_'] for t in cases),cases=cases,
        notes='Three native x86_64 musl prefix domains, not three executed target ABIs; no jail or DUT proof.')
    (w/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print('HOST_BARE_PRELOAD_CASES',len(cases),flush=True)


if __name__ == '__main__': main()
