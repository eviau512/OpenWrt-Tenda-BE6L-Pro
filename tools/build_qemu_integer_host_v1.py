# SPDX-License-Identifier: MIT
"""Offline, isolated build of the experimental ARM64 integer-host emulator.

Uses an already admitted private AAPCS64-soft compiler profile. Only a fresh
owned work directory is changed. No package transaction or DUT access occurs.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import zipfile
from prepare_qemu_integer_host_v1 import prepare
from soft_elf_closure import audit

TARS = {
    'meson-1.11.2.tar.gz': '698feae069cef3ecd4d7aaf281d7df359bdfcf555a9a1564383d3b913fa8a736',
    'pcre2-10.49.tar.bz2': '53c156e1ba416a20da8e65395daa132da0d80e76910424caca3fcdae7831d384',
    'zlib-1.3.2.tar.xz': 'd7a0654783a4da529d1bb793b7ad9c3318020af77667bcae35f95d0e42a792f3',
    'glib-2.86.0.tar.xz': 'b5739972d737cfb0d6fd1e7f163dfe650e2e03740bb3b8d408e4d1faea580d6d',
}


def sha(path):
    with path.open('rb') as incoming:
        return hashlib.file_digest(incoming, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('work', 'cached-sdk', 'glib-archive', 'runtime-source', 'python-wheels',
                 'verified-qemu', 'native-profile', 'toolchain', 'host-prefix', 'host-cc'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--binfmt-defaults', action='store_true',
                        help='Use gated cortex-a53/4MiB TCG defaults for option-free binfmt dispatch')
    parser.add_argument('--binfmt-fd-paths', action='store_true',
                        help='Enable the narrow integer-host FD/proc/CLOEXEC dispatch fixes')
    parser.add_argument('--binfmt-proc-stat', action='store_true',
                        help='Redirect following guest proc-exe stat/statx to its named ELF; deleted inode retention remains open')
    parser.add_argument('--binfmt-guest-exe', action='store_true',
                        help='Use the private kernel X/AT_FLAGS bit16 contract when the host supplies it')
    parser.add_argument('--binfmt-guest-interp', action='store_true', help='Consume the private V2 kernel PT_INTERP descriptor')
    a = parser.parse_args()
    if a.binfmt_fd_paths and not a.binfmt_defaults:
        parser.error('--binfmt-fd-paths requires --binfmt-defaults')
    if a.binfmt_proc_stat and not a.binfmt_fd_paths:
        parser.error('--binfmt-proc-stat requires --binfmt-fd-paths')
    if a.binfmt_guest_exe and not a.binfmt_proc_stat:
        parser.error('--binfmt-guest-exe requires --binfmt-proc-stat')
    if a.binfmt_guest_interp and not a.binfmt_guest_exe:
        parser.error('--binfmt-guest-interp requires --binfmt-guest-exe')
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-qemu-integer-') or w.exists():
        parser.error('Use a fresh /root/be6l-qemu-integer-* work directory')
    base = Path(__file__).resolve().parents[1]
    lock = json.loads((base/'upstream/qemu-integer-host-build-lock.json').read_text())
    original = json.loads((base/'upstream/llvm21-soft-builtins-lock.json').read_text())
    if original['commit'] != lock['runtime_extra']['commit']:
        raise ValueError('Compiler runtime revisions differ')
    archives = {name: a.cached_sdk/'dl'/name for name in TARS}
    archives['glib-2.86.0.tar.xz'] = a.glib_archive
    for name, path in archives.items():
        if sha(path) != TARS[name]:
            raise ValueError('Source archive hash mismatch: '+name)
    for item in original['files']+lock['runtime_extra']['files']:
        if sha(a.runtime_source/item['name']) != item['sha256']:
            raise ValueError('Compiler runtime source hash mismatch: '+item['name'])
    wheels = {}
    for item in lock['python_wheels']:
        path = a.python_wheels/item['filename']
        if sha(path) != item['sha256']:
            raise ValueError('Python wheel hash mismatch: '+item['name'])
        wheels[item['filename']] = path
    w.mkdir(mode=0o700)
    deps, bin_dir, pydeps = w/'deps', w/'bin', w/'pydeps'
    for directory in (deps, bin_dir, pydeps):
        directory.mkdir()
    for path in archives.values():
        with tarfile.open(path) as archive:
            archive.extractall(w, filter='data')
    for path in wheels.values():
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                name = Path(member.filename)
                target = pydeps/name
                if name.is_absolute() or '..' in name.parts or not target.parent.resolve().is_relative_to(pydeps):
                    raise ValueError('Unsafe wheel member')
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(member))
    for name, cached in [('ninja', 'ninja'), ('pkg-config', 'pkg-config.real')]:
        shutil.copyfile(a.cached_sdk/'staging_dir/host/bin'/cached, bin_dir/name)
        (bin_dir/name).chmod(0o755)
    (bin_dir/'meson').write_text('#!/usr/bin/python3\nimport runpy,sys\nsys.path.insert(0,'+
        repr(str(w/'meson-1.11.2'))+')\nrunpy.run_module("mesonbuild.mesonmain",run_name="__main__")\n')
    (bin_dir/'meson').chmod(0o755)
    shutil.copyfile(a.native_profile/'libsoft-builtins.a', w/'libsoft-builtins.a')
    compiler = (a.native_profile/'softcc').read_text()
    if compiler.count("root+'/libsoft-builtins.a'") != 1 or '-mabi=aapcs-soft' not in compiler:
        raise ValueError('Unexpected native-profile compiler wrapper')
    (w/'softcc').write_text(compiler.replace("root+'/libsoft-builtins.a'", repr(str(w/'libsoft-builtins.a'))))
    (w/'softcc').chmod(0o755)
    prefix = str(a.toolchain/'bin/aarch64-openwrt-linux-musl-')
    env = dict(os.environ, PATH=str(bin_dir)+':'+str(a.host_prefix/'usr/bin')+':/usr/bin:/bin',
        LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'), PYTHONPATH=str(pydeps),
        PKG_CONFIG=str(bin_dir/'pkg-config'), PKG_CONFIG_PATH='', PKG_CONFIG_SYSROOT_DIR='',
        PKG_CONFIG_LIBDIR=str(deps/'lib/pkgconfig'), SOURCE_DATE_EPOCH='1792420077',
        BISON_PKGDATADIR=str(a.host_prefix/'usr/share/bison'), M4=str(a.host_prefix/'usr/bin/m4'))
    stages = []

    def run(label, command, cwd=None):
        print('RUN', label, flush=True)
        with (w/(label+'.log')).open('wb') as output:
            result = subprocess.run(list(map(str, command)), cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
        stages.append(dict(stage=label, exit=result.returncode))
        (w/'stages.json').write_text(json.dumps(stages, indent=2)+'\n')
        if result.returncode:
            raise RuntimeError(label+' failed; see its log')

    run('runtime-helper', [w/'softcc', '-O2', '-fPIC', '-ffreestanding', '-fno-stack-protector',
        '-D__SOFT_FP__=1', '-I'+str(a.runtime_source), '-c', a.runtime_source/'fixunstfdi.c', '-o', w/'fixunstfdi.o'])
    run('runtime-archive', [prefix+'ar', 'rcs', w/'libsoft-builtins.a', w/'fixunstfdi.o'])
    common = ['-G', 'Ninja', '-DCMAKE_SYSTEM_NAME=Linux', '-DCMAKE_SYSTEM_PROCESSOR=aarch64',
        '-DCMAKE_C_COMPILER='+str(w/'softcc'), '-DCMAKE_AR='+prefix+'ar', '-DCMAKE_RANLIB='+prefix+'ranlib',
        '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX='+str(deps), '-DCMAKE_INSTALL_LIBDIR=lib',
        '-DCMAKE_C_FLAGS=-fPIC']
    for name, version, flags in [('pcre2', '10.49', ['-DBUILD_SHARED_LIBS=OFF', '-DPCRE2_BUILD_PCRE2_8=ON',
        '-DPCRE2_BUILD_PCRE2_16=OFF', '-DPCRE2_BUILD_PCRE2_32=OFF', '-DPCRE2_BUILD_PCRE2GREP=OFF',
        '-DPCRE2_BUILD_TESTS=OFF', '-DPCRE2_SUPPORT_JIT=OFF']),
        ('zlib', '1.3.2', ['-DZLIB_BUILD_SHARED=OFF', '-DZLIB_BUILD_TESTING=OFF'])]:
        build = w/(name+'-build')
        run(name+'-configure', [a.host_prefix/'usr/bin/cmake', '-S', w/(name+'-'+version), '-B', build]+common+flags)
        run(name+'-build', [bin_dir/'ninja', '-C', build, '-j4'])
        run(name+'-install', [bin_dir/'ninja', '-C', build, 'install'])
    cross = w/'cross.ini'
    cross.write_text('\n'.join(['[binaries]', 'c = '+repr(str(w/'softcc')), 'ar = '+repr(prefix+'ar'),
        'strip = '+repr(prefix+'strip'), 'pkg-config = '+repr(str(bin_dir/'pkg-config')),
        '[host_machine]', "system = 'linux'", "cpu_family = 'aarch64'", "cpu = 'aarch64'", "endian = 'little'",
        '[properties]', 'needs_exe_wrapper = true', '[built-in options]', "c_args = ['-O2', '-fPIC']"])+ '\n')
    glib = w/'glib-2.86.0/meson.build'
    old = glib.read_text()
    new = old.replace("libffi_dep = dependency('libffi', version : '>= 3.0.0')", 'libffi_dep = disabler()')
    new = new.replace("libz_dep = dependency('zlib')", 'libz_dep = disabler()')
    for directory in ('gobject', 'gio', 'girepository', 'fuzzing', 'docs/reference'):
        needle = "subdir('"+directory+"')"
        if new.count(needle) != 1:
            raise ValueError('Unexpected GLib release context')
        new = new.replace(needle, '# Minimal GLib/GModule only: '+needle)
    (w/'glib-minimal.patch').write_text(''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile='a/meson.build', tofile='b/meson.build')))
    glib.write_text(new)
    run('glib-configure', [bin_dir/'meson', 'setup', w/'glib-build', glib.parent, '--cross-file', cross,
        '--prefix', deps, '--libdir=lib', '--default-library=static', '--buildtype=release', '--wrap-mode=nofallback',
        '-Dselinux=disabled', '-Dlibmount=disabled', '-Dtests=false', '-Dintrospection=disabled', '-Dsysprof=disabled',
        '-Dnls=disabled', '-Dman-pages=disabled', '-Ddocumentation=false', '-Dlibelf=disabled', '-Dsystemtap=disabled', '-Ddtrace=disabled'])
    run('glib-build', [bin_dir/'ninja', '-C', w/'glib-build', '-j4'])
    run('glib-install', [bin_dir/'meson', 'install', '-C', w/'glib-build', '--no-rebuild'])
    source_info = prepare(a.verified_qemu, w/'qemu-source', a.binfmt_defaults,
                          a.binfmt_fd_paths, a.binfmt_proc_stat, a.binfmt_guest_exe, a.binfmt_guest_interp)
    source = w/'qemu-source/qemu-11.1.3'
    build = w/'qemu-build'
    build.mkdir()
    run('qemu-configure', [source/'configure', '--target-list=aarch64-linux-user', '--cc='+str(w/'softcc'),
        '--cxx=', '--cross-prefix='+prefix, '--host-cc='+str(a.host_cc), '--cpu=aarch64', '--python=/usr/bin/python3',
        '--without-default-features', '--disable-system', '--disable-tools', '--disable-guest-agent', '--disable-docs',
        '--disable-plugins', '--disable-rust', '--disable-download', '--enable-linux-user', '--enable-tcg',
        '--extra-cflags=-DBE6L_INTEGER_HOST=1 -ffp-contract=off', '--static', '--disable-pie'], cwd=build)
    run('qemu-build', [bin_dir/'ninja', '-C', build, '-j4', 'qemu-aarch64'])
    files = audit({'qemu-aarch64': build/'qemu-aarch64'}, a.native_profile/'sysroot', w/'admitted', prefix)
    report = dict(emulator_built=True, static_elf_admission=files, source_preparation=source_info,
        source_archive_sha256=TARS, build_lock_sha256=sha(base/'upstream/qemu-integer-host-build-lock.json'),
        runtime_archive_sha256=sha(w/'libsoft-builtins.a'), glib_patch_sha256=sha(w/'glib-minimal.patch'),
        target_executed=False, same_isa_execve_containment_implemented=False,
        standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('INTEGER_HOST_EMULATOR_BUILT_AND_STATICALLY_ADMITTED', json.dumps(files), flush=True)


if __name__ == '__main__':
    main()
