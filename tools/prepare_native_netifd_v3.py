# SPDX-License-Identifier: MIT
"""Prepare an opt-in soft64 netifd VM path fix in a fresh source fragment.

This never installs a package, alters an SDK, contacts a router or claims a
complete service closure. Native binary plugins get a separate namespace;
stock text modules retain their existing locations.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json

PIN = "c42a0ba6d866f38d55ccadb746c14f2dc8ad51bc029f4e303bd0a34c76b03cc6"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(source, output):
    original = {name: (source / name).read_bytes() for name in ("ucode.c", "CMakeLists.txt")}
    if sha(original["ucode.c"]) != PIN:
        raise ValueError("Wrong netifd ucode.c source; review a new source pin first")
    before = original["ucode.c"].decode()
    needle = '''\tuc_search_path_init(&config.module_search_path);
\tuc_search_path_add(&config.module_search_path, DEFAULT_MAIN_PATH "/*.so");
\tuc_search_path_add(&config.module_search_path, DEFAULT_MAIN_PATH "/*.uc");'''
    replacement = '''#ifdef BE6L_AAPCS_SOFT_NETIFD
#if !defined(__aarch64__) || defined(__ARM_FP) || defined(__ARM_NEON)
#error "BE6L native netifd requires the admitted AArch64 no-FP/SIMD build"
#endif
\t/* The COMPAT system retains ARM32 plugins at the normal .so paths.
\t * Text modules are ABI-neutral; binary plugins are package-owned soft64.
\t */
\tuc_search_path_add(&config.module_search_path,
\t\t\t   "/opt/be6l-a64-soft/lib/ucode/*.so");
\tuc_search_path_add(&config.module_search_path,
\t\t\t   "/usr/share/ucode/*.uc");
\tuc_search_path_add(&config.module_search_path,
\t\t\t   "/opt/be6l-a64-soft/lib/netifd/*.so");
\tuc_search_path_add(&config.module_search_path, DEFAULT_MAIN_PATH "/*.uc");
#else
\tuc_search_path_init(&config.module_search_path);
\tuc_search_path_add(&config.module_search_path, DEFAULT_MAIN_PATH "/*.so");
\tuc_search_path_add(&config.module_search_path, DEFAULT_MAIN_PATH "/*.uc");
#endif'''
    if before.count(needle) != 1:
        raise ValueError("Unexpected netifd VM initialization context")
    changed = {"ucode.c": before.replace(needle, replacement)}
    cmake = original["CMakeLists.txt"].decode()
    marker = "TARGET_LINK_LIBRARIES(netifd ${LIBS})"
    if cmake.count(marker) != 1:
        raise ValueError("Unexpected netifd CMake context")
    changed["CMakeLists.txt"] = cmake.replace(marker, marker + '''

OPTION(BE6L_AAPCS_SOFT_NETIFD "Use admitted BE6L native ucode plugins" OFF)
IF(BE6L_AAPCS_SOFT_NETIFD)
  TARGET_COMPILE_DEFINITIONS(netifd PRIVATE BE6L_AAPCS_SOFT_NETIFD=1)
ENDIF()
''')
    output.mkdir()
    patch = ""
    for name, text in changed.items():
        (output / name).write_text(text, newline="\n")
        patch += "".join(difflib.unified_diff(original[name].decode().splitlines(True),
            text.splitlines(True), fromfile="a/" + name, tofile="b/" + name))
    (output / "001-netifd-soft64-ucode-paths.patch").write_text(patch, newline="\n")
    report = dict(source_version="2026.09.11~06d06c86", source_file_sha256={
        name: sha(data) for name, data in original.items()},
        modified_file_sha256={name: sha(text.encode()) for name, text in changed.items()},
        patch_sha256=sha(patch.encode()), default_option_enabled=False,
        native_binary_modules_private=True, text_module_paths_preserved=True,
        compiler_option="-DBE6L_AAPCS_SOFT_NETIFD=ON",
        required_static_vm_modules=["fs", "ubus", "uloop", "uci", "nl80211"],
        package_built=False, sdk_modified=False, target_executed=False,
        complete_execution_closure_qualified=False)
    (output / "preparation.json").write_text(json.dumps(report, indent=2) + "\n", newline="\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), indent=2))
