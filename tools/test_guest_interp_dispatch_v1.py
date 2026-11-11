# SPDX-License-Identifier: MIT
"""Compile actual V2 dispatch/helper C with host stubs and injected failures.

This is a source regression, not a kernel boot, concurrency or ABI test. The
complete search_binary_handler/load_misc_binary bodies come from --kernel;
only their external kernel services are stubbed. Artifacts remain in --out.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess


def function(text, name):
    match = re.search(r"^static\s+[^\n]*\b" + re.escape(name) + r"\([^;]*?\)\s*\{", text, re.M)
    if not match:
        raise ValueError("function not found: " + name)
    begin = match.start()
    pos = text.index("{", match.start())
    depth = 1
    pos += 1
    # These four functions have no braces inside string/character literals.
    while depth:
        depth += (text[pos] == "{") - (text[pos] == "}")
        pos += 1
    return text[begin:pos]


PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <sys/types.h>
#define IS_BUILTIN(x) 1
#define CONFIG_BINFMT_MISC 1
#define MISC_FMT_BE6L_EXECFD_EXE 1
#define MISC_FMT_PRESERVE_ARGV0 2
#define MISC_FMT_OPEN_FILE 4
#define MISC_FMT_OPEN_BINARY 8
#define MISC_FMT_CREDENTIALS 16
#define BINPRM_FLAGS_PATH_INACCESSIBLE 1
#define BINPRM_FLAGS_PRESERVE_ARGV0 2
#define GFP_KERNEL 0
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x) >= (uintptr_t)-4095)
struct file {int identity;};
struct mm_struct {struct file *be6l_binfmt_interpreter;};
struct linux_binprm {struct file *file,*interpreter,*executable;
 struct mm_struct *mm; const char *interp; int argc,interp_flags;
 unsigned int point_of_no_return:1,have_execfd:1,execfd_creds:1;
 unsigned int be6l_execfd_exe:1,be6l_binfmt_terminal:1;};
struct binfmt_misc {int enabled;};
typedef struct {int flags;const char *interpreter;struct file *interp_file;} Node;
struct linux_binfmt {int (*load_binary)(struct linux_binprm *);int module;};
static struct file guest={1},emulator={2};
static struct binfmt_misc misc={1};
static Node node={MISC_FMT_BE6L_EXECFD_EXE|MISC_FMT_OPEN_BINARY|MISC_FMT_PRESERVE_ARGV0,"/emulator",&emulator};
static int match_guest=1,helper_error,copy_error,open_error,denial_error;
static int native_calls,helper_calls,node_puts,prepare_error,security_error;
static struct binfmt_misc *load_binfmt_misc(void){return &misc;}
static Node *get_binfmt_handler(struct binfmt_misc *m,struct linux_binprm *b){return match_guest&&b->file==&guest ? &node:NULL;}
static void put_binfmt_handler(Node *p){node_puts++;}
static int remove_arg_zero(struct linux_binprm *b){b->argc--;return 0;}
static int copy_string_kernel(const char *s,struct linux_binprm *b){return copy_error;}
static int bprm_change_interp(const char *s,struct linux_binprm *b){b->interp=s;return 0;}
static struct file *open_exec(const char *s){return open_error?ERR_PTR(open_error):&emulator;}
static struct file *file_clone_open(struct file *f){return f;}
static int exe_file_deny_write_access(struct file *f){return denial_error;}
static void exe_file_allow_write_access(struct file *f){}
static void fput(struct file *f){}
static struct file *get_file(struct file *f){return f;}
static int be6l_prepare_guest_interp(struct linux_binprm *b){helper_calls++;return helper_error;}
static int set_mm_exe_file(struct mm_struct *m,struct file *f){return 0;}
static int prepare_binprm(struct linux_binprm *b){return prepare_error;}
static int security_bprm_check(struct linux_binprm *b){return security_error;}
static int try_module_get(int m){return 1;}
static void put_binfmt(struct linux_binfmt *f){}
static int binfmt_lock;
#define read_lock(x) ((void)0)
#define read_unlock(x) ((void)0)
static struct linux_binfmt formats[2];
#define list_for_each_entry(pos,head,member) for(pos=*(head);pos<*(head)+2;pos++)
static int native_binary(struct linux_binprm *b){native_calls++;return 0;}
'''

MAIN = r'''
static int failures;
static void emit(const char *name,bool ok,int got,int expected){
 printf("%s\t%s\t%d\t%d\t%d\t%d\n",name,ok?"PASS":"FAIL",got,expected,native_calls,helper_calls);failures+=!ok;
}
static struct linux_binprm reset(struct mm_struct *mm){
 match_guest=1;helper_error=copy_error=open_error=denial_error=0;
 native_calls=helper_calls=node_puts=prepare_error=security_error=0;misc.enabled=1;
 node.flags=MISC_FMT_BE6L_EXECFD_EXE|MISC_FMT_OPEN_BINARY|MISC_FMT_PRESERVE_ARGV0;
 memset(mm,0,sizeof(*mm));
 return (struct linux_binprm){.file=&guest,.mm=mm,.interp="/guest",.argc=1};
}
int main(void){
 struct mm_struct mm;struct linux_binprm b;int r;
 formats[0]=(struct linux_binfmt){.load_binary=load_misc_binary};
 formats[1]=(struct linux_binfmt){.load_binary=native_binary};
 b=reset(&mm);match_guest=0;r=search_binary_handler(&b);
 emit("unmatched-native-control",r==0&&native_calls==1,r,0);
 b=reset(&mm);misc.enabled=0;r=search_binary_handler(&b);
 emit("disabled-misc-native-control",r==0&&native_calls==1,r,0);
 const int errors[]={-ENOEXEC,-ENOMEM,-EIO,-ENOENT,-ELIBBAD,-EACCES};
 const char *names[]={"X-helper-ENOEXEC-terminal","X-helper-ENOMEM-terminal","X-helper-EIO-terminal","X-loader-ENOENT-terminal","X-loader-ELIBBAD-terminal","X-loader-EACCES-terminal"};
 for(unsigned i=0;i<sizeof(errors)/sizeof(*errors);i++){
  b=reset(&mm);helper_error=errors[i];r=search_binary_handler(&b);
  emit(names[i],r==errors[i]&&native_calls==0&&helper_calls==1&&node_puts==1,r,errors[i]);
 }
 b=reset(&mm);copy_error=-ENOEXEC;r=search_binary_handler(&b);
 emit("X-early-argument-ENOEXEC-terminal",r==-ENOEXEC&&native_calls==0&&helper_calls==0,r,-ENOEXEC);
 b=reset(&mm);open_error=-ENOEXEC;r=search_binary_handler(&b);
 emit("X-emulator-open-ENOEXEC-terminal",r==-ENOEXEC&&native_calls==0&&helper_calls==0,r,-ENOEXEC);
 b=reset(&mm);b.have_execfd=1;r=search_binary_handler(&b);
 emit("X-nested-O-ENOEXEC-terminal",r==-ENOEXEC&&native_calls==0&&helper_calls==0,r,-ENOEXEC);
 b=reset(&mm);node.flags=MISC_FMT_PRESERVE_ARGV0;copy_error=-ENOEXEC;r=search_binary_handler(&b);
 emit("non-X-ENOEXEC-still-falls-through",r==0&&native_calls==1,r,0);
 b=reset(&mm);r=search_binary_handler(&b);
 emit("X-success-rewrites-interpreter",r==0&&native_calls==0&&b.interpreter==&emulator&&b.have_execfd&&b.be6l_execfd_exe,r,0);
 b.executable=b.file;b.file=b.interpreter;b.interpreter=NULL;r=search_binary_handler(&b);
 emit("X-next-round-native-emulator-accepted",r==0&&native_calls==1,r,0);
 b=reset(&mm);b.be6l_binfmt_terminal=1;match_guest=0;r=search_binary_handler(&b);
 emit("stale-terminal-reset-at-new-search",r==0&&native_calls==1&&!b.be6l_binfmt_terminal,r,0);
 b=reset(&mm);prepare_error=-EIO;r=search_binary_handler(&b);
 emit("prepare-error-preserved",r==-EIO&&native_calls==0&&helper_calls==0,r,-EIO);
 b=reset(&mm);security_error=-EACCES;r=search_binary_handler(&b);
 emit("security-error-preserved",r==-EACCES&&native_calls==0&&helper_calls==0,r,-EACCES);
 return failures?1:0;
}
'''

PHDR_PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <sys/types.h>
#define GFP_KERNEL 0
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x) >= (uintptr_t)-4095)
struct file {int unused;};
static int allocation_failure,read_error,short_read,live_allocations;
static void *kmalloc(size_t s,int flags){void *p=allocation_failure?NULL:malloc(s);live_allocations+=!!p;return p;}
static void kfree(void *p){if(p){live_allocations--;free(p);}}
static ssize_t kernel_read(struct file *f,void *b,size_t n,loff_t *pos){
 if(read_error)return read_error;memset(b,0,n);return short_read?(ssize_t)n-1:(ssize_t)n;
}
'''

PHDR_MAIN = r'''
int main(void){
 struct file f;Elf64_Ehdr h={.e_phentsize=sizeof(Elf64_Phdr),.e_phnum=2};
 const int expected[]={0,-ENOMEM,-EIO,-EINTR,-ENOEXEC,-ENOEXEC,-ENOEXEC};
 const char *names[]={"phdr-read-success","phdr-ENOMEM-preserved","phdr-short-read-EIO-preserved","phdr-interrupted-read-preserved","phdr-bad-entsize-ENOEXEC","phdr-empty-ENOEXEC","phdr-over-limit-ENOEXEC"};
 int failures=0;
 for(int i=0;i<7;i++){
  allocation_failure=i==1;short_read=i==2;read_error=i==3?-EINTR:0;
  h.e_phentsize=i==4?1:sizeof(Elf64_Phdr);h.e_phnum=i==5?0:i==6?65535:2;
  Elf64_Phdr *p=be6l_elf_phdrs(&f,&h);
  int err=IS_ERR(p)?PTR_ERR(p):!p?-ENOEXEC:0;
  if(p&&!IS_ERR(p))kfree(p);
  bool ok=err==expected[i]&&live_allocations==0;
  printf("%s\t%s\t%d\t%d\n",names[i],ok?"PASS":"FAIL",err,expected[i]);failures+=!ok;
 }
 return failures?1:0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--host-prefix", type=Path, help="Optional unpacked host compiler/sysroot; does not install packages")
    args = parser.parse_args()
    args.out = args.out.resolve()
    if args.out.parent != Path("/root") or not args.out.name.startswith("be6l-exec-dispatch-tests-20261111-"):
        parser.error("Use a fresh /root/be6l-exec-dispatch-tests-20261111-* directory")
    args.out.mkdir(mode=0o700)
    env = dict(os.environ)
    compiler = ["cc"]
    if args.host_prefix:
        compiler = [str(args.host_prefix / "usr/bin/gcc"), "--sysroot=" + str(args.host_prefix), "-static",
                    "-isystem", str(args.host_prefix / "usr/include/x86_64-linux-gnu"),
                    "-L" + str(args.host_prefix / "usr/lib/x86_64-linux-gnu")]
        env.update(PATH=str(args.host_prefix / "usr/bin") + ":/usr/bin:/bin",
                   LD_LIBRARY_PATH=str(args.host_prefix / "usr/lib/x86_64-linux-gnu"))
    sources = {name: (args.kernel / name).read_text() for name in ("fs/exec.c", "fs/binfmt_misc.c")}
    bodies = {name: function(sources[src], name) for src, name in (
        ("fs/exec.c", "search_binary_handler"),
        ("fs/binfmt_misc.c", "load_misc_binary"),
        ("fs/binfmt_misc.c", "be6l_elf_read"),
        ("fs/binfmt_misc.c", "be6l_elf_phdrs"),
    )}
    cases = {}
    suites = {
        "dispatch": PRELUDE + bodies["load_misc_binary"] + "\n" + bodies["search_binary_handler"] + MAIN,
        "phdr": PHDR_PRELUDE + bodies["be6l_elf_read"] + "\n" + bodies["be6l_elf_phdrs"] + PHDR_MAIN,
    }
    for name, code in suites.items():
        source = args.out / (name + ".c")
        binary = args.out / name
        source.write_text(code)
        compiled = subprocess.run(compiler + ["-std=gnu11", "-Wall", "-Wextra", "-Wno-unused-parameter", "-Wno-unused-variable", "-O2", str(source), "-o", str(binary)], env=env, capture_output=True, text=True)
        (args.out / (name + "-compile.txt")).write_text(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        result = subprocess.run([str(binary)], env=env, capture_output=True, text=True, timeout=10)
        (args.out / (name + ".txt")).write_text(result.stdout + result.stderr)
        for line in result.stdout.splitlines():
            label, status, got, expected, *counts = line.split("\t")
            cases[label] = {"pass": status == "PASS", "actual_errno": int(got), "expected_errno": int(expected)}
            if counts:
                cases[label].update(native_handler_calls=int(counts[0]), guest_helper_calls=int(counts[1]))
        if result.returncode not in (0, 1):
            raise RuntimeError(f"{name} harness exited {result.returncode}: {result.stderr}")
    report = {
        "scope": "Actual extracted C function bodies with substituted kernel services; no device, locking, credentials or complete exec-chain qualification.",
        "kernel": str(args.kernel),
        "sources_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in sources.items()},
        "functions_sha256": {k: hashlib.sha256(v.encode()).hexdigest() for k, v in bodies.items()},
        "tests": cases,
        "passed": sum(case["pass"] for case in cases.values()),
        "total": len(cases),
    }
    (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(report["passed"] != report["total"])


if __name__ == "__main__":
    main()
