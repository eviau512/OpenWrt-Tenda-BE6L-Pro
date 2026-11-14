# SPDX-License-Identifier: MIT
"""Normal signed bootstrap/guard/passwd-shell transactions in a NEW private copy.

No scripts, force options, untrusted installs, manual DB edits, Image or DUT.
The resulting root is an OFFLINE fixture, never an admitted normal main root.
"""
from pathlib import Path
import argparse
import json
import os
import shutil
import subprocess
from build_mainroot_bootstrap_v1 import SOURCE, BOOTSTRAP, BUSYBOX, EMULATOR, R5_APK_SHA, owners, elf
from package_native_netifd_v3 import records, root_digest, sha, copy_path


def root_shell_only(data):
    lines = data.decode().splitlines(keepends=True)
    found = 0
    for i, line in enumerate(lines):
        fields = line.rstrip("\n").split(":")
        if fields[0] == "root":
            if len(fields) != 7:
                raise ValueError("Malformed root account")
            found += 1
            fields[-1] = "/usr/libexec/be6l/native-recovery-shell"
            lines[i] = ":".join(fields) + ("\n" if line.endswith("\n") else "")
    if found != 1:
        raise ValueError("Exactly one root account required")
    result = "".join(lines).encode()
    a = data.decode().splitlines()
    b = result.decode().splitlines()
    if len(a) != len(b) or any(x != y and (x.split(":")[:-1] != y.split(":")[:-1] or not x.startswith("root:")) for x, y in zip(a, b)):
        raise ValueError("Unexpected passwd change")
    return result


def accept_frozen_conffile(root, old, new, attributes):
    target, staged = root / "etc/passwd", root / "etc/passwd.apk-new"
    st = target.lstat()
    if target.is_symlink() or not target.is_file() or target.read_bytes() != old or (st.st_uid, st.st_gid, st.st_mode & 0o7777) != attributes:
        raise ValueError("Current passwd changed after freeze; conffile left untouched")
    st = staged.lstat()
    if staged.is_symlink() or not staged.is_file() or staged.read_bytes() != new or (st.st_uid, st.st_gid, st.st_mode & 0o7777) != attributes:
        raise ValueError("Unexpected signed passwd conffile bytes/attributes")
    # Same-directory atomic acceptance of APK's ordinary protected conffile.
    if target.read_bytes() != old:
        raise ValueError("Passwd changed immediately before atomic conffile acceptance")
    os.replace(staged, target)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for field in ("base-root", "bootstrap-build", "host-tests", "emulator-package", "apk", "work"):
        p.add_argument("--" + field, type=Path, required=True)
    a = p.parse_args()
    w, original = a.work.resolve(), a.base_root.resolve()
    if w.parent != Path("/root") or not w.name.startswith("be6l-mainroot-bootstrap-apk-") or w.exists():
        p.error("Use a new /root/be6l-mainroot-bootstrap-apk-*")
    build = json.loads((a.bootstrap_build / "result.json").read_text())
    frozen = records(original)
    frozen_digest = root_digest(original)
    if frozen_digest != build["input_root_records_sha256"] or build["source_sha256"] != sha(SOURCE / "bootstrap.c") or not build["static_native"] or build["fp_simd_register_uses"]:
        raise ValueError("Exact current source/build/input-root binding required")
    if sha(a.bootstrap_build / "payload" / BOOTSTRAP) != build["bootstrap_sha256"]:
        raise ValueError("Bootstrap payload changed")
    host_receipt = json.loads((a.host_tests / "result.json").read_text())
    if host_receipt["passed"] != host_receipt["total"] or host_receipt["native_result_sha256"] != sha(a.bootstrap_build / "result.json") or host_receipt["source_sha256"] != sha(SOURCE / "bootstrap.c"):
        raise ValueError("Matching successful host verifier receipt required")
    source_owners = owners(original)
    original_init_owner = source_owners.get("init")
    if original_init_owner is not None and original_init_owner["P"] != "base-files":
        raise ValueError("Unexpected init owner")
    if source_owners["etc/passwd"]["P"] != "base-files":
        raise ValueError("This transaction explicitly replaces only base-files passwd ownership")
    if source_owners["usr/sbin/be6l-recovery-guard"]["P"] != "be6l-recovery-guard":
        raise ValueError("Expected existing private guard package")
    dropbear = "usr/sbin/dropbear"
    if elf((original / dropbear).read_bytes()) != 3:
        raise ValueError("Native ARM32 canonical Dropbear required")
    native_dropbear = source_owners[dropbear]
    bb_owner = source_owners[BUSYBOX]
    if native_dropbear["P"] not in ("dropbear", "be6l-arm32-dropbear"):
        raise ValueError("Unexpected native SSH owner")
    passwd = (original / "etc/passwd").read_bytes()
    passwd_stat = (original / "etc/passwd").lstat()
    passwd_attributes = (passwd_stat.st_uid, passwd_stat.st_gid, passwd_stat.st_mode & 0o7777)
    changed_passwd = root_shell_only(passwd)
    w.mkdir(mode=0o700)
    trust = w / "trust"
    trust.mkdir()
    for directory in (original / "etc/apk/keys", a.emulator_package / "trust"):
        for f in directory.iterdir():
            if f.is_file():
                copy_path(f, trust / f.name)
    key = w / "temporary-signing.key"

    def run(label, argv, success=True):
        q = subprocess.run(list(map(str, argv)), capture_output=True, timeout=180)
        (w / (label + ".log")).write_bytes(q.stdout + q.stderr)
        if (q.returncode == 0) != success:
            raise RuntimeError(label + " returned " + str(q.returncode) + ": " + q.stderr.decode(errors="replace")[-1200:])
        return q.stdout

    packages = {}
    try:
        run("key-generate", ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key])
        key.chmod(0o600)
        public = w / "public-key.pem"
        run("key-public", ["openssl", "pkey", "-in", key, "-pubout", "-out", public])
        copy_path(public, trust / "be6l-mainroot-bootstrap.pem")
        bootstrap = w / "bootstrap-files"
        guard = w / "guard-files"
        bootstrap.mkdir()
        guard.mkdir()
        for f in (a.bootstrap_build / "payload").rglob("*"):
            if not f.is_file() and not f.is_symlink():
                continue
            rel = f.relative_to(a.bootstrap_build / "payload").as_posix()
            copy_path(f, (guard if rel == "usr/sbin/be6l-recovery-guard" else bootstrap) / rel)
        copy_path(public, bootstrap / "etc/apk/keys/be6l-mainroot-bootstrap.pem")
        for rel in ("etc/config/be6l-recovery", "etc/init.d/be6l-recovery", "usr/lib/be6l-recovery-guard/state.sh"):
            copy_path(original / rel, guard / rel)
        config = w / "config-files"
        (config / "etc").mkdir(parents=True)
        (config / "etc/passwd").write_bytes(changed_passwd)
        (config / "etc/passwd").chmod((original / "etc/passwd").stat().st_mode & 0o7777)

        def package(name, version, files, arch, depends=(), replaces=None, label=None):
            label = label or name
            out = w / (label + ".apk")
            command = [a.apk, "mkpkg", "--sign-key", key, "--files", files, "--output", out]
            fields = dict(name=name, version=version, arch=arch, license="MIT", description="BE6L private native bootstrap recovery offline fixture")
            if depends:
                fields["depends"] = " ".join(depends)
            if replaces:
                fields["replaces"] = replaces
            for k, v in fields.items():
                command += ["--info", k + ":" + v]
            run("mkpkg-" + label, command)
            run("verify-" + label, [a.apk, "--network=no", "--keys-dir", trust, "verify", out])
            packages[label] = dict(name=name, version=version, arch=arch, sha256=sha(out))
            return out

        bootstrap_version = "1.0.0-r1"
        boot_apk = package("be6l-mainroot-bootstrap", bootstrap_version, bootstrap, "aarch64_be6l_soft_experimental",
                           [bb_owner["P"] + "=" + bb_owner["V"], "be6l-integer-emulator=11.1.3-r5"], "base-files")
        guard_apk = package("be6l-recovery-guard", "1.0.0-r3", guard, "noarch",
                            ["be6l-mainroot-bootstrap=" + bootstrap_version, "procd", "uci", "busybox", native_dropbear["P"] + "=" + native_dropbear["V"]])
        cfg_apk = package("be6l-native-recovery-config", "1.0.0-r1", config, "noarch",
                          ["be6l-mainroot-bootstrap=" + bootstrap_version, native_dropbear["P"] + "=" + native_dropbear["V"]], "base-files")
        cfg_upgrade = package("be6l-native-recovery-config", "1.0.0-r2", config, "noarch",
                              ["be6l-mainroot-bootstrap=" + bootstrap_version, native_dropbear["P"] + "=" + native_dropbear["V"]], "base-files", "config-protection-negative")
        r5 = a.emulator_package / "be6l-integer-emulator-11.1.3-r5.apk"
        if sha(r5) != R5_APK_SHA:
            raise ValueError("Exact signed r5 APK differs")
        root = w / "root"
        shutil.copytree(original, root, symlinks=True)

        def transaction(target):
            return [a.apk, "--root", target, "--keys-dir", trust, "--network=no", "--cache=no", "--scripts=no", "--logfile=no", "--repositories-file", "/dev/null"]

        tx = transaction(root)
        if records(original) != frozen or (root / "etc/passwd").read_bytes() != passwd:
            raise ValueError("Input/frozen passwd changed before config transaction")
        run("simulate-bootstrap", tx + ["add", "--simulate", r5, boot_apk, guard_apk, cfg_apk])
        if (root / "etc/passwd").read_bytes() != passwd:
            raise ValueError("Simulation modified passwd")
        run("install-bootstrap", tx + ["add", r5, boot_apk, guard_apk, cfg_apk])
        # APK's protected-path policy is directory-wide, not file-specific.
        # Accept its ordinary .apk-new only after an exact frozen-file check;
        # no protection override and no database write is performed here.
        apk_new = root / "etc/passwd.apk-new"
        accepted_apk_new = False
        if (root / "etc/passwd").read_bytes() != changed_passwd:
            if (root / "etc/passwd").read_bytes() != passwd or not apk_new.is_file() or apk_new.is_symlink() or apk_new.read_bytes() != changed_passwd:
                raise ValueError("Unexpected passwd conflict; refuse conffile merge")
            if records(original) != frozen or (root / "etc/passwd").read_bytes() != passwd:
                raise ValueError("Source or target passwd changed after freeze")
            reject_root = w / "reject-modified-conffile"
            (reject_root / "etc").mkdir(parents=True)
            copy_path(root / "etc/passwd", reject_root / "etc/passwd")
            copy_path(apk_new, reject_root / "etc/passwd.apk-new")
            local_modified = passwd + b"# concurrent local fixture edit\n"
            (reject_root / "etc/passwd").write_bytes(local_modified)
            try:
                accept_frozen_conffile(reject_root, passwd, changed_passwd, passwd_attributes)
            except ValueError:
                pass
            else:
                raise ValueError("Modified-original conflict was incorrectly accepted")
            if (reject_root / "etc/passwd").read_bytes() != local_modified or (reject_root / "etc/passwd.apk-new").read_bytes() != changed_passwd:
                raise ValueError("Rejected conffile conflict changed either file")
            accept_frozen_conffile(root, passwd, changed_passwd, passwd_attributes)
            accepted_apk_new = True
        if (root / "etc/passwd").read_bytes() != changed_passwd:
            raise ValueError("Normal protected-config transaction did not apply exact root-shell-only payload")
        expected_owners = {"init": "be6l-mainroot-bootstrap", BOOTSTRAP: "be6l-mainroot-bootstrap",
                           "usr/libexec/be6l/native-recovery-shell": "be6l-mainroot-bootstrap",
                           "usr/sbin/be6l-recovery-guard": "be6l-recovery-guard", "etc/passwd": "be6l-native-recovery-config"}
        actual_owners = owners(root)
        for rel, expected in expected_owners.items():
            if actual_owners.get(rel, {}).get("P") != expected:
                raise ValueError("Wrong normal APK ownership: " + rel)
            readonly = [a.apk, "--root", root, "--keys-dir", trust, "--network=no", "--cache=no", "--logfile=no", "--repositories-file", "/dev/null"]
            run("owner-" + rel.replace("/", "_"), readonly + ["info", "--who-owns", "/" + rel])
        audit = run("accepted-passwd-audit", readonly + ["audit", "--backup", "etc/passwd"])
        if audit.strip():
            raise ValueError("Accepted passwd does not match installed conffile hash")
        verifier = a.host_tests / "host-actual-manifest"
        verified = run("compiled-manifest-full-fixture", [verifier, "--verify-root", root]).decode().strip()
        if verified != "VERIFY PASS " + build["manifest_id"]:
            raise ValueError("Installed APK root differs from compiled C trust manifest")
        after = records(root)
        allowed = set(records(bootstrap)) | set(records(guard)) | {"etc/passwd", EMULATOR}
        changed = {n for n in frozen.keys() | after.keys() if frozen.get(n) != after.get(n)}
        unrelated = [n for n in changed - allowed if not n.startswith(("lib/apk/", "etc/apk/"))]
        if unrelated:
            raise ValueError("Unrelated payload changed: " + str(unrelated))
        protected = [n for n in frozen if n.startswith(("etc/dropbear/", "etc/ssh/", "root/", "etc/apk/protected_paths.d/")) or n in ("etc/shadow", "etc/group")]
        if any(after.get(n) != frozen[n] for n in protected):
            raise ValueError("Userdata/password hashes/SSH identity/protection policies changed")
        if any(n.endswith(".apk-new") for n in after):
            raise ValueError("Unresolved .apk-new in composed fixture")
        # Decisive proof that default protection returned: a new signed version
        # must preserve a deliberately modified config and create .apk-new.
        negative = w / "protected-negative-root"
        shutil.copytree(root, negative, symlinks=True)
        changed_lines = changed_passwd.decode().splitlines(keepends=True)
        for i, line in enumerate(changed_lines):
            if line.startswith("root:"):
                fields = line.rstrip("\n").split(":")
                fields[4] += "_host_fixture"
                changed_lines[i] = ":".join(fields) + "\n"
        locally_modified = "".join(changed_lines).encode()
        (negative / "etc/passwd").write_bytes(locally_modified)
        run("restored-protection-negative", transaction(negative) + ["add", cfg_upgrade])
        if (negative / "etc/passwd").read_bytes() != locally_modified or (negative / "etc/passwd.apk-new").read_bytes() != changed_passwd:
            raise ValueError("Actual default conffile protection was not restored")
        if records(original) != frozen or root_digest(original) != frozen_digest:
            raise ValueError("Original input root changed")
        report = dict(normal_signed_bootstrap_transactions=True, normal_signed_guard_upgrade=True,
                      normal_signed_passwd_only_shell_transaction=True, explicit_replaces_base_files=True,
                      temporary_protection_rule_used=False, default_protection_always_enabled=True,
                      exact_frozen_apk_new_conffile_accepted=accepted_apk_new, actual_default_protection_negative_passed=True,
                      modified_original_conffile_rejected_intact=accepted_apk_new, accepted_passwd_apk_audit_clean=True,
                      original_passwd_uid_gid_mode_preserved=True,
                      root_password_fields_unchanged=True, shadow_group_userdata_hostkeys_unchanged=True,
                      original_init_owner=original_init_owner,
                      protected_existing_paths_checked=len(protected), original_root_unchanged=True,
                      input_root_records_sha256=frozen_digest, output_root_records_sha256=root_digest(root),
                      bootstrap_build_receipt_sha256=sha(a.bootstrap_build / "result.json"), packages=packages,
                      ownership={n: actual_owners[n] for n in expected_owners}, changed_root_paths=sorted(changed),
                      native_dropbear_owner=native_dropbear, source_sha256=sha(Path(__file__)),
                      scripts_executed=False, force_options_used=False, untrusted_options_used=False,
                      manual_apk_db_edits=False, final_normal_root_regenerated=False,
                      compiled_manifest_full_fixture_passed=True, host_verifier_sha256=sha(verifier),
                      host_verifier_receipt_sha256=sha(a.host_tests / "result.json"), target_executed=False, candidate_admitted=False)
    finally:
        key.unlink(missing_ok=True)
    report["private_signing_key_removed"] = not key.exists()
    (w / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("OFFLINE_SIGNED_BOOTSTRAP_CONFIG_TRANSACTIONS_PASS; NOT_ADMITTED")


if __name__ == "__main__":
    main()
