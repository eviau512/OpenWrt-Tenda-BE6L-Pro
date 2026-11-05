# SPDX-License-Identifier: MIT
"""Compile/link all configured Airoha Ethernet units in an isolated fixture.

Uses the real cached ARM64 kernel headers/configuration and saved compiler
arguments. Does not rebuild a kernel, package, rootfs or bootable image.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess

KERNEL = "arm64-source/build_dir/target-aarch64_cortex-a53_musl/linux-airoha_an7563a64/linux-6.18.55"
TOOLCHAIN = "arm64-source/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.4.0_musl"
DRIVER = "drivers/net/ethernet/airoha"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bootstrap", type=Path, required=True)
    parser.add_argument("--port", type=Path, required=True)
    parser.add_argument("--host-prefix", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path("/root") or not work.name.startswith("be6l-driver-check-"):
        parser.error("Use /root/be6l-driver-check-*")
    work.mkdir()
    original = args.bootstrap / KERNEL
    kernel = work / "kernel"
    config = (original / ".config").read_text()
    if "\nCONFIG_ARM64=y\n" not in config or "\nCONFIG_DEBUG_FS=y\n" not in config:
        raise ValueError("Wrong configured kernel fixture")
    proof = json.loads((args.port / "preparation.json").read_text())
    if sha(args.port / "airoha_ppe.c") != proof["source_sha256"]:
        raise ValueError("Port preparation source mismatch")
    if sha(original / DRIVER / "airoha_ppe.c") != proof["baseline_source_sha256"]:
        raise ValueError("Wrong driver fixture baseline")
    shutil.copytree(original, kernel, symlinks=True, copy_function=os.link)
    changed = kernel / DRIVER / "airoha_ppe.c"
    changed.unlink()  # Break only this new fixture's hardlink before writing.
    shutil.copyfile(args.port / "airoha_ppe.c", changed)
    compiler = args.bootstrap / TOOLCHAIN / "bin/aarch64-openwrt-linux-musl-gcc"
    linker = args.bootstrap / TOOLCHAIN / "bin/aarch64-openwrt-linux-musl-ld"
    env = dict(os.environ, PATH=str(compiler.parent) + ":" + str(args.host_prefix / "usr/bin") + ":/usr/bin:/bin",
               STAGING_DIR=str(args.bootstrap / "arm64-source/staging_dir"),
               LD_LIBRARY_PATH=str(args.host_prefix / "usr/lib/x86_64-linux-gnu"))
    objects, commands = [], {}
    dependencies = work / "dependencies"
    dependencies.mkdir()
    for name in ("airoha_eth", "airoha_ppe", "diag", "airoha_ppe_debugfs"):
        saved = (original / DRIVER / ("." + name + ".o.cmd")).read_text().splitlines()[0]
        arguments = shlex.split(saved.split(":=", 1)[1])
        if arguments[0] == "ccache":
            arguments.pop(0)
        if arguments[0] != "aarch64-openwrt-linux-musl-gcc":
            raise ValueError("Unexpected saved compiler")
        arguments[0] = str(compiler)
        destination = work / (name + ".o")
        index = arguments.index("-o")
        arguments[index + 1] = str(destination)
        arguments = ["-Wp,-MMD," + str(dependencies / (name + ".d"))
                     if item.startswith("-Wp,-MMD,") else item for item in arguments]
        with (work / (name + ".log")).open("wb") as output:
            result = subprocess.run(arguments, cwd=kernel, env=env, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError("Real ARM64 unit failed: " + name)
        objects.append(destination)
        commands[name] = arguments
        print("ARM64_UNIT_BUILT", name, flush=True)
    with (work / "link.log").open("wb") as output:
        result = subprocess.run([str(linker), "-r", "-o", str(work / "airoha-eth.o"), *map(str, objects)],
                                env=env, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("Configured Airoha composite link failed")
    report = dict(source_sha256=proof["source_sha256"], compiler_sha256=sha(compiler),
                  kernel_config_sha256=sha(original / ".config"),
                  module_symvers_sha256=sha(original / "Module.symvers"),
                  actual_arm64_translation_units=[path.name for path in objects],
                  object_sha256={path.name: sha(path) for path in objects},
                  composite_sha256=sha(work / "airoha-eth.o"),
                  compiler_commands=commands, configured_driver_composite_linked=True,
                  ccache_used=False, full_kernel_built=False, packages_built=False,
                  sdk_modified=False, target_executed=False, hardware_qualified=False)
    (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("REAL_ARM64_AIROHA_DRIVER_LINKED_NO_IMAGE")


if __name__ == "__main__":
    main()
