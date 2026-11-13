# SPDX-License-Identifier: MIT
"""Bounded host tests of actual bootstrap C. Never mount, register, reboot or run DUT.

Synthetic ELF fixtures test inventory policy, not execution compatibility.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
from build_mainroot_bootstrap_v1 import SOURCE, PRIVATE, BOOTSTRAP, BUSYBOX, EMULATOR, NATIVE_INIT, manifest_entry, write_header
from plan_integer_binfmt_v1 import rule_bytes


def fake_elf(role=1, dynamic=False):
    data = bytearray(120)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", data, 16, 2, 183, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<I", data, 48, PRIVATE if role == 1 else 0)
    struct.pack_into("<HHH", data, 52, 64, 56, 1)
    struct.pack_into("<I", data, 64, 3 if dynamic else 1)
    if role == 3:
        data[4] = 1
        struct.pack_into("<H", data, 18, 40)
    return bytes(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host-tools", type=Path, required=True)
    p.add_argument("--native-build", type=Path, required=True)
    p.add_argument("--base-root", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path("/root") or not w.name.startswith("be6l-mainroot-bootstrap-tests-") or w.exists():
        p.error("Use a new /root/be6l-mainroot-bootstrap-tests-*")
    w.mkdir()
    root = w / "fixture"
    root.mkdir()
    files = {"init": (fake_elf(), 0o555), BOOTSTRAP: (fake_elf(), 0o555), BUSYBOX: (fake_elf(), 0o555),
             EMULATOR: (fake_elf(), 0o555), "usr/bin/standard": (fake_elf(2), 0o755),
             "usr/bin/arm32": (fake_elf(3), 0o755), NATIVE_INIT: (b"# native script fixture\n", 0o555)}
    for name, (data, mode) in files.items():
        dest = root / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(mode)
    (root / "usr/bin/link").symlink_to("standard")
    entries = [manifest_entry(name, root / name, role=4 if name in ("init", BOOTSTRAP) else None,
                              native=name in ("init", BOOTSTRAP, BUSYBOX, EMULATOR)) for name in files]
    entries.append(manifest_entry("usr/bin/link", root / "usr/bin/link"))
    write_header(w / "bootstrap_manifest.h", entries, "/not-used-in-host-test", "synthetic-policy-fixture")
    h = a.host_tools.resolve()
    cc = [str(h / "usr/bin/clang"), "--target=x86_64-linux-gnu", "--sysroot=" + str(h),
          "--gcc-toolchain=" + str(h / "usr"), "--ld-path=" + str(h / "usr/bin/ld.lld"),
          "-isystem", str(h / "usr/include/x86_64-linux-gnu"), "-B" + str(h / "usr/lib/x86_64-linux-gnu"),
          "-L" + str(h / "usr/lib/x86_64-linux-gnu"), "-static", "-std=c11", "-Os", "-Wall", "-Wextra",
          "-Wno-unused-function", "-Wno-misleading-indentation", "-DBE6L_BOOTSTRAP_HOST_TEST", "-I", str(w)]
    binary = w / "host-bootstrap"
    compiled = subprocess.run(cc + [str(SOURCE / "bootstrap.c"), "-o", str(binary)], capture_output=True, timeout=60)
    (w / "compile.log").write_bytes(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(compiled.stderr.decode(errors="replace"))
    results = []

    def check(name, args, success=True, expected=None, env=None):
        q = subprocess.run([binary] + list(map(str, args)), capture_output=True, timeout=5, env=env)
        ok = (q.returncode == 0) == success and (expected is None or q.stdout.decode().strip() == expected)
        results.append(dict(name=name, passed=ok, exit=q.returncode))
        if not ok:
            raise AssertionError((name, q.returncode, q.stdout, q.stderr))

    check("complete-synthetic-inventory", ["--verify-root", root])

    def mutate(name, rel, change, restore, success=False):
        change(root / rel)
        try:
            check(name, ["--verify-root", root], success)
        finally:
            restore(root / rel)

    original = (root / BUSYBOX).read_bytes()
    mutate("changed-native-hash", BUSYBOX, lambda f: f.write_bytes(original + b"x"), lambda f: f.write_bytes(original))
    mutate("writable-native-mode", BUSYBOX, lambda f: f.chmod(0o577), lambda f: f.chmod(0o555))
    mutate("missing-private-marker", BUSYBOX, lambda f: f.write_bytes(fake_elf(2)), lambda f: f.write_bytes(original))
    mutate("dynamic-private-helper", BUSYBOX, lambda f: f.write_bytes(fake_elf(dynamic=True)), lambda f: f.write_bytes(original))
    mutate("self-copy-differs", "init", lambda f: f.write_bytes(original + b"x"), lambda f: f.write_bytes(original))
    mutate("self-marker-required", "init", lambda f: f.write_bytes(fake_elf(2)), lambda f: f.write_bytes(original))
    for role, label in ((1, "private"), (2, "standard"), (3, "arm32")):
        extra = root / "usr/bin/unlisted"
        extra.write_bytes(fake_elf(role))
        check("unlisted-" + label + "-elf", ["--verify-root", root], False)
        extra.unlink()
    mutate("changed-critical-link", "usr/bin/link", lambda f: (f.unlink(), f.symlink_to("arm32")), lambda f: (f.unlink(), f.symlink_to("standard")))
    mutate("writable-ancestor", "usr/bin", lambda f: f.chmod(0o777), lambda f: f.chmod(0o755))
    directory = root / "usr/bin"
    directory.rename(root / "usr/bin-real")
    directory.symlink_to("bin-real")
    check("symlink-ancestor", ["--verify-root", root], False)
    directory.unlink()
    (root / "usr/bin-real").rename(directory)
    native = root / BUSYBOX
    native.unlink()
    native.symlink_to("/etc/passwd")
    check("symlink-native-file", ["--verify-root", root], False)
    native.unlink()
    native.write_bytes(original)
    native.chmod(0o555)
    check("restored-synthetic-inventory", ["--verify-root", root])
    for length in (0, 1, 3, 55, 56, 63, 64, 65, 16383, 16384, 16385, 1000000):
        data = b"abc" if length == 3 else bytes((i * 37 + 11) % 256 for i in range(length))
        sample = w / "sha-input"
        sample.write_bytes(data)
        check("sha256-%d-byte" % length, ["--hash", sample], expected=hashlib.sha256(data).hexdigest())
    for grace, timeout, last, expected in ((600, 300, -1, 600), (600, 300, 100, 600), (600, 300, 500, 800), (600, 300, 800, 1100)):
        check("deadline-%d-%d" % (grace, last), ["--deadline", grace, timeout, last], expected=str(expected))
    check("deadline-leading-zero", ["--deadline", "0600", 300, -1], False)
    boot = "c695fbae-aceb-4111-a514-5921af036506"
    hbdir = w / "heartbeat"
    hbdir.mkdir(mode=0o700)
    heartbeat = hbdir / "heartbeat"
    for label, data, good in (("bound", boot + " 123\n", True), ("foreign-boot", "00000000-0000-0000-0000-000000000000 123\n", False),
                              ("future", boot + " 201\n", False), ("leading-zero", boot + " 0123\n", False),
                              ("extra-token", boot + " 123 extra\n", False), ("negative", boot + " -1\n", False)):
        heartbeat.write_text(data)
        heartbeat.chmod(0o600)
        check("heartbeat-" + label, ["--heartbeat-parse", hbdir, boot, 200], good)
    heartbeat.chmod(0o644)
    check("heartbeat-not-private", ["--heartbeat-parse", hbdir, boot, 200], False)
    heartbeat.unlink()
    heartbeat.symlink_to(w / "sha-input")
    check("heartbeat-symlink", ["--heartbeat-parse", hbdir, boot, 200], False)
    magic, mask = rule_bytes()
    interp = "/proc/self/fd/7"
    canonical = "enabled\ninterpreter %s\nflags: POFX\noffset 0\nmagic %s\nmask %s\n" % (interp, magic.hex(), mask.hex())
    entry = w / "rule-entry"
    for label, text, good in (("exact", canonical, True), ("C-flag", canonical.replace("POFX", "POFCX"), False),
                              ("missing-X", canonical.replace("POFX", "POF"), False), ("other-inode-fd", canonical.replace("fd/7", "fd/8"), False),
                              ("wrong-magic", canonical.replace("magic 7f", "magic 7e"), False), ("wrong-mask", canonical.replace("mask ff", "mask fe"), False),
                              ("disabled", canonical.replace("enabled\n", "disabled\n"), False), ("tail", canonical + "unexpected\n", False)):
        entry.write_text(text)
        check("rule-" + label, ["--rule-readback", entry, interp], good)
    for action, good, now in (("H", True, "100"), ("bad", False, "100"), ("EOF", False, "100"), ("timeout", False, "600")):
        env = dict(os.environ, BE6L_TEST_BOOTTIME=now)
        check("phase-handoff-" + action, ["--phase-handshake", action], good, env=env)
    # The real sealed input is copied only into this private test directory.
    actual = w / "actual-root"
    shutil.copytree(a.base_root, actual, symlinks=True)
    for file in (a.native_build / "payload").rglob("*"):
        dest = actual / file.relative_to(a.native_build / "payload")
        if file.is_dir() and not file.is_symlink():
            dest.mkdir(parents=True, exist_ok=True)
        elif file.is_symlink():
            if dest.exists() or dest.is_symlink():
                dest.unlink()
            dest.symlink_to(os.readlink(file))
        else:
            shutil.copy2(file, dest)
    emulator = a.native_build / "verified-r5" / EMULATOR
    (actual / EMULATOR).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(emulator, actual / EMULATOR)
    # Compile actual manifest into a second HOST binary; no target code runs.
    actual_binary = w / "host-actual-manifest"
    command = cc.copy()
    command[command.index(str(w))] = str(a.native_build)
    q = subprocess.run(command + [str(SOURCE / "bootstrap.c"), "-o", str(actual_binary)], capture_output=True, timeout=60)
    (w / "compile-actual.log").write_bytes(q.stdout + q.stderr)
    if q.returncode:
        raise RuntimeError(q.stderr.decode(errors="replace"))
    binary = actual_binary
    check("actual-sealed-root-plus-payload-full-C-inventory", ["--verify-root", actual])
    (actual / EMULATOR).write_bytes(b"corrupt")
    check("actual-r5-corruption", ["--verify-root", actual], False)
    report = dict(passed=len(results), total=len(results), tests=results,
                  source_sha256=hashlib.sha256((SOURCE / "bootstrap.c").read_bytes()).hexdigest(),
                  native_result_sha256=hashlib.sha256((a.native_build / "result.json").read_bytes()).hexdigest(),
                  host_fixture_only=True, target_code_executed=False, actual_binfmt_kernel_F_procfd_qualified=False,
                  mounts_performed=False, device_accessed=False, production_root_changed=False)
    (w / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("NATIVE_BOOTSTRAP_HOST_TESTS_PASS", len(results))


if __name__ == "__main__":
    main()
