# SPDX-License-Identifier: MIT
"""Test the NEW bootstrap provenance branch using preserved signed archives.

Reads the existing isolated28-package root. No hybrid root, package install,
target execution, old workload rerun, Image, mount or DUT operation.
"""
from pathlib import Path
import argparse
import copy
import json
import subprocess
from build_mainroot_bootstrap_v1 import verified_normal_provenance, verify_normal_file, owners, elf
from package_native_netifd_v3 import root_digest, sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("fixture", "original-archives", "emulator-package", "apk", "work"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path("/root") or not w.name.startswith("be6l-mainroot-provenance-tests-") or w.exists():
        p.error("Use a new /root/be6l-mainroot-provenance-tests-*")
    receipt_path = a.fixture / "result.json"
    receipt = json.loads(receipt_path.read_text())
    if not receipt["normal_signed_standard_package_transaction"] or len(receipt["packages"]) != 28:
        raise ValueError("Expected preserved signed28-package fixture")
    by_name = {}
    for file in a.original_archives.rglob("*.apk"):
        by_name.setdefault(file.name, []).append(file)
    packages = []
    for item in receipt["packages"]:
        matches = [f for f in by_name.get(item["file"], ()) if sha(f) == item["sha256"]]
        if not matches:
            raise ValueError("Original exact archive missing: " + item["file"])
        packages.append(matches[0])
    before = root_digest(a.fixture / "root")
    w.mkdir()

    operation = 0

    def run(label, args):
        nonlocal operation
        operation += 1
        q = subprocess.run(list(map(str, args)), capture_output=True, timeout=120)
        (w / ("%03d-" % operation + label + ".log")).write_bytes(q.stdout + q.stderr)
        if q.returncode:
            raise RuntimeError(label + " failed")
        return q.stdout

    normal, archives = verified_normal_provenance(packages, a.fixture / "trust", a.apk, w, run)
    owned = owners(a.fixture / "root")
    selected = []
    for file in (a.fixture / "root").rglob("*"):
        if file.is_symlink() or not file.is_file() or elf(file.read_bytes()) != 2:
            continue
        name = file.relative_to(a.fixture / "root").as_posix()
        verify_normal_file(name, file, owned, normal)
        selected.append(name)
    if len(normal) != 30 or len(selected) != 30:
        raise ValueError("Unexpected preserved normal ELF inventory")
    checks = [dict(name="28-original-signatures-and-PVA", passed=True), dict(name="30-normal-ELF-byte-and-installed-owner", passed=True)]

    def reject(label, function):
        try:
            function()
        except (ValueError, RuntimeError):
            checks.append(dict(name=label, passed=True))
        else:
            raise AssertionError(label + " unexpectedly accepted")

    name = sorted(selected)[0]
    source = a.fixture / "root" / name
    for field, value in (("P", "be6l-mislabeled-private"), ("V", "0-r999"), ("A", "arm_cortex-a7")):
        bad = copy.deepcopy(owned)
        bad[name][field] = value
        reject("wrong-owner-" + field, lambda: verify_normal_file(name, source, bad, normal))
    bad = copy.deepcopy(owned)
    del bad[name]
    reject("missing-installed-owner", lambda: verify_normal_file(name, source, bad, normal))
    mutated = w / "mutated-normal-elf"
    mutated.write_bytes(source.read_bytes() + b"changed")
    reject("modified-normal-payload", lambda: verify_normal_file(name, mutated, owned, normal))
    reject("unlisted-normal-path", lambda: verify_normal_file("usr/bin/unlisted", source, owned, normal))
    reject("empty-archive-list", lambda: verified_normal_provenance([], a.fixture / "trust", a.apk, w, run))
    reject("oversized-archive-list", lambda: verified_normal_provenance([str(packages[0])] * 513, a.fixture / "trust", a.apk, w, run))
    corrupt = w / "corrupt-signed.apk"
    data = bytearray(packages[0].read_bytes())
    data[len(data) // 2] ^= 1
    corrupt.write_bytes(data)
    bad_work = w / "bad-archive"
    bad_work.mkdir()
    reject("tampered-signed-archive", lambda: verified_normal_provenance([corrupt], a.fixture / "trust", a.apk, bad_work, run))
    private_work = w / "private-archive"
    private_work.mkdir()
    reject("signed-private-ABI-is-not-ordinary-A53", lambda: verified_normal_provenance(
        [a.emulator_package / "be6l-integer-emulator-11.1.3-r5.apk"], a.emulator_package / "trust", a.apk, private_work, run))
    if root_digest(a.fixture / "root") != before or any(sha(f) != item["sha256"] for f, item in zip(packages, receipt["packages"])):
        raise ValueError("Original isolated root or preserved archive changed")
    report = dict(normal_provenance_branch_checks_passed=len(checks), checks=checks,
                  signed_original_archives_verified=len(archives), standard_elf_byte_owner_checks=len(selected),
                  original_fixture_receipt_sha256=sha(receipt_path), original_root_records_sha256=before,
                  original_root_and_archives_unchanged=True, normal_archives=archives,
                  source_sha256=sha(Path(__file__)), builder_source_sha256=sha(Path(__file__).with_name("build_mainroot_bootstrap_v1.py")),
                  isolated_fixture_only=True, hybrid_root_created=False, package_installation=False,
                  old_execution_workloads_repeated=False, target_executed=False, mainroot_qualified=False,
                  standard_a53_package_compatibility_qualified=False)
    (w / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("BOOTSTRAP_NORMAL_PROVENANCE_BRANCH_PASS", len(checks), len(archives), len(selected))


if __name__ == "__main__":
    main()
