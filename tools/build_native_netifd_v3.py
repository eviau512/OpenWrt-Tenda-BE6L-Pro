# SPDX-License-Identifier: MIT
"""Build real Linux netifd with an opt-in soft64 embedded-VM namespace.

An isolated CMake build plus ELF/dependency checks; no package transaction,
default service replacement, network access or DUT execution is performed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess

TOOLCHAIN = "arm64-source/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.4.0_musl"
PROFILE_PIN = "fbe5405f873d14791e3da04f09bb3bc8fdb018f237f71d9ce1aa320b5f0f757f"
MODULES = ("fs", "ubus", "uloop", "uci", "nl80211")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--host-prefix", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--libnl-source", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--preparation", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path("/root") or not work.name.startswith("be6l-native-netifd-"):
        parser.error("Use a fresh /root/be6l-native-netifd-*")
    if sha(args.profile / "profile-lock.json") != PROFILE_PIN:
        raise ValueError("Wrong admitted 90-path profile")
    profile = json.loads((args.profile / "profile-lock.json").read_text())
    prepared = json.loads((args.preparation / "preparation.json").read_text())
    for name, expected in prepared["source_file_sha256"].items():
        if sha(args.source / name) != expected:
            raise ValueError("Source preparation baseline mismatch: " + name)
    for name, expected in prepared["modified_file_sha256"].items():
        if sha(args.preparation / name) != expected:
            raise ValueError("Prepared source bytes mismatch: " + name)
    work.mkdir()
    sysroot = work / "sysroot"
    shutil.copytree(args.bootstrap / "a64-soft-lua-fixed-v3/sysroot", sysroot, symlinks=True)
    shutil.copyfile(args.bootstrap / "a64-soft-lua-fixed-v3/libsoft-builtins.a", work / "libsoft-builtins.a")
    libnl_name = "lib/aarch64-soft/libnl-tiny.so.1"
    libnl = args.profile / "payload" / libnl_name
    if sha(libnl) != profile["files"][libnl_name]["sha256"]:
        raise ValueError("Untrusted libnl-tiny payload")
    shutil.copyfile(libnl, sysroot / "usr/lib/libnl-tiny.so.1")
    link = sysroot / "usr/lib/libnl-tiny.so"
    if not os.path.lexists(link):
        link.symlink_to("libnl-tiny.so.1")
    headers = sysroot / "usr/include/libnl-tiny"
    if not headers.exists():
        shutil.copytree(args.libnl_source / "include", headers)
    source = work / "source"
    shutil.copytree(args.source, source, ignore=shutil.ignore_patterns(
        "CMakeFiles", "CMakeCache.txt", "*.o", "*.so", "*.so.*", "*.a", ".pkgdir", "ipkg-*", "apk-*"))
    for name in prepared["modified_file_sha256"]:
        shutil.copyfile(args.preparation / name, source / name)
    compiler = work / "softcc"
    toolchain = args.bootstrap / TOOLCHAIN
    clang = args.host_prefix / "usr/bin/clang"
    linker = toolchain / "bin/aarch64-openwrt-linux-musl-ld"
    flags = [str(clang), "--target=aarch64-linux-musl", "-march=armv8-a+nofp+nosimd", "-mabi=aapcs-soft",
             "-mno-outline-atomics", "-ffp-contract=off", "-fno-vectorize", "-fno-slp-vectorize",
             "--sysroot=" + str(sysroot), "--ld-path=" + str(linker),
             "-isystem", str(sysroot / "include"), "-isystem", str(sysroot / "usr/include"),
             "-idirafter", str(toolchain / "include"), "-Qunused-arguments",
             "-L" + str(sysroot / "lib"), "-L" + str(sysroot / "usr/lib"),
             "-Wl,-rpath-link," + str(sysroot / "lib") + ":" + str(sysroot / "usr/lib"),
             "-Wl,--build-id=none", "-ffile-prefix-map=" + str(work) + "=/build/be6l-netifd"]
    compiler.write_text('''#!/usr/bin/python3
import os,sys
flags=FLAGS
arguments=sys.argv[1:]
root=ROOT
compile_only=any(value in ('-c','-S','-E','-r','--version','-v') or value.startswith('-print') for value in arguments)
if compile_only:
    command=flags+arguments
else:
    lib=root+'/sysroot/lib/'
    start=[] if '-shared' in arguments else [lib+'crt1.o']
    command=flags+['-nostdlib']+start+[lib+'crti.o','-Wl,--start-group']+arguments+[
        root+'/libsoft-builtins.a','-lc','-Wl,--end-group','-Wl,--exclude-libs,ALL',lib+'crtn.o']
    if '-shared' not in arguments and '-static' not in arguments:
        command+=['-Wl,--dynamic-linker=/lib/ld-musl-aarch64-soft.so.1']
os.execv(command[0],command)
'''.replace("FLAGS", repr(flags)).replace("ROOT", repr(str(work))))
    compiler.chmod(0o755)
    cmake = work / "toolchain.cmake"
    cmake.write_text("\n".join([
        "set(CMAKE_SYSTEM_NAME Linux)", "set(CMAKE_SYSTEM_PROCESSOR aarch64)",
        'set(CMAKE_C_COMPILER "' + str(compiler) + '")',
        'set(CMAKE_AR "' + str(toolchain / "bin/aarch64-openwrt-linux-musl-ar") + '")',
        'set(CMAKE_RANLIB "' + str(toolchain / "bin/aarch64-openwrt-linux-musl-ranlib") + '")',
        'set(CMAKE_SYSROOT "' + str(sysroot) + '")',
        'set(CMAKE_FIND_ROOT_PATH "' + str(sysroot) + '")',
        "set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)", "set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)",
        "set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)", "set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)",
        "set(CMAKE_SKIP_RPATH TRUE)"]) + "\n")
    build = work / "build"
    build.mkdir()
    shutil.copyfile(source / "make_ethtool_modes_h.sh", build / "make_ethtool_modes_h.sh")
    (build / "make_ethtool_modes_h.sh").chmod(0o755)
    env = dict(os.environ, PATH=str(args.host_prefix / "usr/bin") + ":/usr/bin:/bin",
               LD_LIBRARY_PATH=str(args.host_prefix / "usr/lib/x86_64-linux-gnu"),
               SOURCE_DATE_EPOCH="1792420077", PKG_CONFIG_PATH="",
               PKG_CONFIG_LIBDIR=str(sysroot / "usr/lib/pkgconfig"), PKG_CONFIG_SYSROOT_DIR=str(sysroot))

    def run(label, command):
        with (work / (label + ".log")).open("wb") as output:
            result = subprocess.run(list(map(str, command)), env=env, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(label + " failed; inspect its log")

    cmake_bin = args.host_prefix / "usr/bin/cmake"
    run("configure", [cmake_bin, "-S", source, "-B", build, "-DCMAKE_TOOLCHAIN_FILE=" + str(cmake),
        "-DCMAKE_POLICY_VERSION_MINIMUM=3.5", "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_INSTALL_PREFIX=/usr",
        "-DCMAKE_SKIP_RPATH=ON", "-DDUMMY_MODE=OFF", "-DBE6L_AAPCS_SOFT_NETIFD=ON",
        "-DLIBNL_LIBS=" + str(sysroot / "usr/lib/libnl-tiny.so.1"),
        "-DCMAKE_C_FLAGS=-O2 -I" + str(headers) + " -Wno-error=sign-compare -Wno-error=gnu-variable-sized-type-not-at-end"])
    run("compile", [cmake_bin, "--build", build, "-j4"])
    payload = work / "payload"
    (payload / "sbin").mkdir(parents=True)
    binary = payload / "sbin/netifd"
    shutil.copyfile(build / "netifd", binary)
    strip = toolchain / "bin/aarch64-openwrt-linux-musl-strip"
    run("strip", [strip, "--strip-debug", binary])
    readelf = toolchain / "bin/aarch64-openwrt-linux-musl-readelf"
    objdump = toolchain / "bin/aarch64-openwrt-linux-musl-objdump"
    objects = {"netifd": binary}
    for module in MODULES:
        name = "opt/be6l-a64-soft/lib/ucode/" + module + ".so"
        file = args.profile / "payload" / name
        if sha(file) != profile["files"][name]["sha256"]:
            raise ValueError("Untrusted native module: " + module)
        destination = payload / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, destination)
        objects["module:" + module] = destination
    destination = payload / libnl_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(libnl, destination)
    pending = list(objects)
    needed, definitions, undefined, metadata = {}, {}, {}, {}
    while pending:
        name = pending.pop()
        path = objects[name]
        data = path.read_bytes()
        if data[:6] != b"\x7fELF\x02\x01" or data[18:20] != b"\xb7\0":
            raise ValueError("Wrong native ELF ABI: " + name)
        dynamic = subprocess.check_output([str(readelf), "-d", str(path)], text=True, env=env)
        if re.search(r"\((RPATH|RUNPATH)\)", dynamic):
            raise ValueError("Unexpected runtime search path")
        needed[name] = re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic)
        for dependency in needed[name]:
            if dependency not in objects:
                candidates = [sysroot / folder / dependency for folder in ("lib", "usr/lib")
                              if (sysroot / folder / dependency).is_file()]
                if len(candidates) != 1:
                    raise ValueError("Missing/ambiguous provider: " + dependency)
                objects[dependency] = candidates[0]
                pending.append(dependency)
        instructions = subprocess.check_output([str(objdump), "-d", str(path)], text=True, env=env)
        for line in instructions.splitlines():
            if "\t" not in line:
                continue
            instruction = line.split("\t", 2)[-1]
            if re.match(r"^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s", instruction):
                continue
            if re.search(r"(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b", instruction):
                raise ValueError("FP/SIMD instruction: " + name + ": " + instruction)
        symbols = subprocess.check_output([str(readelf), "--dyn-syms", "--wide", str(path)], text=True, env=env)
        definitions[name], undefined[name] = set(), set()
        for line in symbols.splitlines():
            fields = line.split()
            if len(fields) < 8 or not re.fullmatch(r"\d+:", fields[0]):
                continue
            symbol = fields[7].split("@")[0]
            if fields[6] == "UND" and fields[4] == "GLOBAL":
                undefined[name].add(symbol)
            elif fields[6] != "UND" and fields[4] in ("GLOBAL", "WEAK"):
                definitions[name].add(symbol)
        metadata[name] = dict(sha256=sha(path), bytes=len(data), needed=needed[name], fp_simd_register_uses=0)

    def scope(name):
        selected, todo = set(), [name]
        while todo:
            current = todo.pop()
            if current not in selected:
                selected.add(current)
                todo.extend(needed[current])
        return selected

    host_scope = scope("netifd")
    for name in objects:
        selected = scope(name) | (host_scope if name.startswith("module:") else set())
        missing = undefined[name] - set().union(*(definitions[item] for item in selected))
        if missing:
            raise ValueError("Unresolved strong symbols: " + name + ": " + str(sorted(missing)))
    header = subprocess.check_output([str(readelf), "-l", str(binary)], text=True, env=env)
    if "/lib/ld-musl-aarch64-soft.so.1" not in header:
        raise ValueError("Wrong netifd ELF interpreter")
    for path in payload.rglob("*"):
        if path.is_file():
            path.chmod(0o755)
    report = dict(abi="AAPCS64-soft", profile_sha256=PROFILE_PIN, source_preparation=prepared,
                  compiler_sha256=sha(clang.resolve()), files=metadata,
                  native_vm_modules=list(MODULES), real_linux_backend=True,
                  normal_package_built=False, default_service_replaced=False,
                  target_executed=False, complete_execution_closure_qualified=False,
                  remaining="Dynamic script/child execution, signed component packages and actual target qualification")
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("NATIVE_NETIFD_V3_BUILT_AND_STATIC_ABI_AUDITED", len(objects))


if __name__ == "__main__":
    main()
