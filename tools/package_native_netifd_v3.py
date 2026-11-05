# SPDX-License-Identifier: MIT
"""Signed native netifd + private modules + RAM recovery in a NEW APK root.

All target scripts are disabled during package transactions. rc.common is
used only for offline enable. No service, root image or device is executed.
"""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import os
import shutil
import subprocess

ARCH = "aarch64_be6l_soft_experimental"
BASE = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def records(root):
    result = {}
    for path in root.rglob("*"):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[name] = {"symlink": os.readlink(path)}
        elif path.is_file():
            result[name] = {"sha256": sha(path), "mode": path.stat().st_mode & 0o7777}
    return result


def copy_path(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        destination.symlink_to(os.readlink(source))
    elif source.is_dir():
        destination.mkdir(exist_ok=True)
    else:
        shutil.copy2(source, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-root", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--native-build", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--host-bash", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path("/root") or not work.name.startswith("be6l-netifd-apk-"):
        parser.error("Use a fresh /root/be6l-netifd-apk-*")
    work.mkdir()
    original = args.base_root.resolve()
    before = records(original)
    profile_path = args.profile / "profile-lock.json"
    if sha(profile_path) != "fbe5405f873d14791e3da04f09bb3bc8fdb018f237f71d9ce1aa320b5f0f757f":
        raise ValueError("Wrong source profile")
    profile = json.loads(profile_path.read_text())
    build = json.loads((args.native_build / "result.json").read_text())
    if build["abi"] != "AAPCS64-soft" or not build["real_linux_backend"]:
        raise ValueError("Wrong native build")
    if ARCH not in (original / "etc/apk/arch").read_text().splitlines():
        raise ValueError("Missing explicitly admitted native package architecture")
    for name, item in profile["files"].items():
        if name not in profile["new_paths"] and sha(original / name) != item["sha256"]:
            raise ValueError("Wrong base native payload: " + name)
    common = [str(args.apk), "--root", str(original), "--network=no", "--cache=no",
              "--repositories-file", "/dev/null"]

    def run(label, command, success=True, env=None):
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=180, env=env)
        (work / (label + ".log")).write_bytes(result.stdout + result.stderr)
        if (result.returncode == 0) != success:
            raise RuntimeError(label + " returned " + str(result.returncode))
        return result

    query = ["query", "--installed", "--format", "json", "--fields", "name,version,arch,depends,description,license"]
    original_packages = json.loads(run("original-packages", common + query + ["*"]).stdout)
    old, = [item for item in original_packages if item["name"] == "netifd"]
    ownership = run("original-netifd-files", common + ["info", "--contents", "netifd"]).stdout.decode()
    owned = []
    for line in ownership.splitlines():
        if not line or line.endswith("contains:"):
            continue
        name = line.lstrip("/")
        if ".." in PurePosixPath(name).parts or not (original / name).exists() and not (original / name).is_symlink():
            raise ValueError("Unexpected package file list entry")
        owned.append(name)
    if "sbin/netifd" not in owned:
        raise ValueError("netifd file ownership missing")
    netifd_files = work / "netifd-files"
    netifd_files.mkdir()
    for name in owned:
        copy_path(original / name, netifd_files / name)
    binary = args.native_build / "payload/sbin/netifd"
    if sha(binary) != build["files"]["netifd"]["sha256"]:
        raise ValueError("Native netifd build output changed")
    shutil.copyfile(binary, netifd_files / "sbin/netifd")
    (netifd_files / "sbin/netifd").chmod(0o755)
    runtime_files = work / "runtime-files"
    runtime_files.mkdir()
    retained_native_payloads = {}
    for path in (args.native_build / "payload").rglob("*"):
        if path.is_file() and path.relative_to(args.native_build / "payload").as_posix() != "sbin/netifd":
            name = path.relative_to(args.native_build / "payload").as_posix()
            if name in before:
                if before[name].get("sha256") != sha(path):
                    raise ValueError("Refuse replacing a different base-native payload: " + name)
                retained_native_payloads[name] = before[name]
            else:
                copy_path(path, runtime_files / name)
    expected_new_runtime = {"lib/aarch64-soft/libnl-tiny.so.1",
                            "opt/be6l-a64-soft/lib/ucode/nl80211.so"}
    if set(records(runtime_files)) != expected_new_runtime or len(retained_native_payloads) != 4:
        raise ValueError("Expected two new runtime paths and four retained base-owned VM modules")
    for notice in ("libnl-tiny/SOURCE-NOTICES.txt", "ucode-extra/SOURCE-NOTICES.txt"):
        if notice not in profile["notices"]:
            raise ValueError("Required source notice missing")
        destination = runtime_files / "usr/share/licenses/be6l-soft-netifd-deps" / notice
        copy_path(args.profile / "notices" / notice, destination)
        destination.chmod(0o644)
    guard_files = work / "guard-files"
    guard_files.mkdir()
    guard_source = BASE / "packages/be6l-recovery-guard/files"
    for name, destination, mode in (
        ("be6l-recovery.config", "etc/config/be6l-recovery", 0o600),
        ("be6l-recovery.init", "etc/init.d/be6l-recovery", 0o755),
        ("be6l-recovery-guard", "usr/sbin/be6l-recovery-guard", 0o755),
        ("state.sh", "usr/lib/be6l-recovery-guard/state.sh", 0o644)):
        target = guard_files / destination
        copy_path(guard_source / name, target)
        target.chmod(mode)
    key, public = work / "throwaway-signing.key", work / "public-key.pem"
    trust = work / "trust"
    trust.mkdir()
    for path in (original / "etc/apk/keys").glob("*"):
        if path.is_file():
            copy_path(path, trust / path.name)
    version = old["version"].rsplit("-r", 1)[0] + "-r100"
    runtime_version = "1.0." + str(int(build["files"]["netifd"]["sha256"][:12], 16)) + "-r1"
    native_package = work / "netifd-native.apk"
    runtime_package = work / "netifd-native-runtime.apk"
    guard_package = work / "be6l-recovery-guard.apk"
    wrong = work / "netifd-wrong-ordinary-arch.apk"

    def package(destination, files, name, package_version, arch, depends, license):
        run("mkpkg-" + destination.stem, [args.apk, "mkpkg", "--sign-key", key, "--files", files,
            "--output", destination, "--info", "name:" + name, "--info", "version:" + package_version,
            "--info", "arch:" + arch, "--info", "description:BE6L experimental native netifd/RAM recovery",
            "--info", "license:" + license, "--info", "depends:" + " ".join(depends)])

    try:
        run("key-generate", ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key])
        key.chmod(0o600)
        run("key-public", ["openssl", "pkey", "-in", key, "-pubout", "-out", public])
        if not public.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----"):
            raise ValueError("Invalid fixture public key")
        copy_path(public, trust / "be6l-netifd-v3.pem")
        depends = list(old["depends"]) + ["be6l-soft-netifd-deps=" + runtime_version]
        package(runtime_package, runtime_files, "be6l-soft-netifd-deps", runtime_version, ARCH,
                ["be6l-soft-runtime=" + profile["base_versions"]["runtime"]], "LicenseRef-BE6L-Source-Notices")
        package(native_package, netifd_files, "netifd", version, ARCH, depends, old["license"])
        package(wrong, netifd_files, "netifd", version, "aarch64_cortex-a53", depends, old["license"])
        package(guard_package, guard_files, "be6l-recovery-guard", "1.0.0-r1", "noarch",
                ["busybox", "procd", "uci", "dropbear"], "MIT")
        for package_file in (runtime_package, native_package, guard_package, wrong):
            run("verify-" + package_file.stem, [args.apk, "--keys-dir", trust, "--network=no", "verify", package_file])
        root = work / "root"
        shutil.copytree(original, root, symlinks=True)
        transaction = [args.apk, "--root", root, "--keys-dir", trust, "--network=no", "--cache=no",
                       "--scripts=no", "--repositories-file", "/dev/null"]
        approved = [runtime_package, native_package, guard_package]
        run("simulate-valid", transaction + ["add", "--simulate", *approved])
        run("reject-ordinary-aarch64", transaction + ["add", "--simulate", runtime_package, wrong, guard_package], False)
        if records(root) != before:
            raise ValueError("Simulation changed root payloads")
        run("normal-transaction", transaction + ["add", *approved])
        log = root / "tmp/log/apk.log"
        if log.is_file():
            if not log.resolve().is_relative_to(root):
                raise ValueError("APK log escapes owned root")
            shutil.copyfile(log, work / "apk-internal.log")
            log.unlink()
            if "tmp/log/apk.log" in before:
                copy_path(original / "tmp/log/apk.log", log)
        lock_directory = root / "var/lock"
        if not lock_directory.resolve().is_relative_to(root):
            raise ValueError("Offline lock path escapes owned root")
        lock_directory.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, IPKG_INSTROOT=str(root))
        enabled = run("enable-recovery", [args.host_bash, root / "etc/rc.common", root / "etc/init.d/be6l-recovery", "enable"], env=env)
        if enabled.stderr:
            raise ValueError("Offline service enable emitted an error")
        lock_file = lock_directory / "procd_be6l-recovery.lock"
        if lock_file.exists():
            lock_file.unlink()
        startup = root / "etc/rc.d/S95be6l-recovery"
        if not startup.is_symlink() or startup.resolve() != (root / "etc/init.d/be6l-recovery").resolve():
            raise ValueError("Recovery startup link missing")
        expected = records(netifd_files) | records(runtime_files) | records(guard_files)
        readonly = [args.apk, "--root", root, "--network=no", "--cache=no", "--repositories-file", "/dev/null"]
        owners = {}
        netifd_names, runtime_names = set(records(netifd_files)), set(records(runtime_files))
        for name, item in expected.items():
            path = root / name
            actual = {"symlink": os.readlink(path)} if path.is_symlink() else {"sha256": sha(path), "mode": path.stat().st_mode & 0o7777}
            if actual != item:
                raise ValueError("Installed payload mismatch: " + name)
            owner = run("owner-" + name.replace("/", "_"), readonly + ["info", "--who-owns", "/" + name]).stdout.decode().strip()
            expected_owner = ("netifd-" + version if name in netifd_names else
                              "be6l-soft-netifd-deps-" + runtime_version if name in runtime_names else
                              "be6l-recovery-guard-1.0.0-r1")
            if not owner.endswith(" is owned by " + expected_owner):
                raise ValueError("Wrong installed component owner: " + name)
            owners[name] = owner
        after = records(root)
        for name, item in retained_native_payloads.items():
            if after.get(name) != item:
                raise ValueError("Existing native module bytes/mode changed: " + name)
        changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
        expected_changes = set(expected) | {"etc/rc.d/S95be6l-recovery", "etc/rc.d/K01be6l-recovery"}
        unexpected = [name for name in changed - expected_changes if not name.startswith(("lib/apk/", "etc/apk/"))]
        if unexpected:
            raise ValueError("Unrelated root files changed: " + str(unexpected))
        installed = json.loads(run("installed-packages", readonly + query + ["*"]).stdout)
        new_netifd, = [item for item in installed if item["name"] == "netifd"]
        if new_netifd["arch"] != ARCH or new_netifd["version"] != version:
            raise ValueError("Component replacement metadata not admitted")
        if records(original) != before:
            raise ValueError("Original baseline changed")
        report = dict(normal_signed_component_transaction=True, wrong_ordinary_arch_refused=True,
            baseline_packages=len(original_packages), installed_packages=len(installed),
            netifd=new_netifd, recovery_enabled_in_offline_root=True,
            package_payload_ownership=owners, changed_root_paths=sorted(changed),
            existing_native_modules_retained=retained_native_payloads,
            packages={path.name: sha(path) for path in approved}, native_build_receipt_sha256=sha(args.native_build / "result.json"),
            original_root_unchanged=True, private_key_removed_on_exit=True,
            services_executed=False, image_built=False, target_executed=False,
            full_native_userspace_qualified=False)
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print("NATIVE_NETIFD_AND_RECOVERY_NORMAL_SIGNED_APK_ROOT", len(installed))
    finally:
        if key.exists():
            key.unlink()


if __name__ == "__main__":
    main()
