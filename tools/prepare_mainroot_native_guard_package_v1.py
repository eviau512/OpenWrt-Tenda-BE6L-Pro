# SPDX-License-Identifier: MIT
"""Sign guard r4 with exact private native SSH dependency; no root transaction.

This metadata component can unblock an offline solver. It does not qualify the
old baseline bootstrap manifest for a newly composed normal main root.
"""
from pathlib import Path
import argparse
import json
import shutil
import subprocess
from package_native_netifd_v3 import root_digest, sha, copy_path

SSH = "be6l-arm32-dropbear=2026.94-r103"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ("base-root", "bootstrap-build", "apk", "work"):
        p.add_argument("--" + n, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path("/root") or not w.name.startswith("be6l-mainroot-guard-ssh-") or w.exists():
        p.error("Use a new /root/be6l-mainroot-guard-ssh-*")
    build = json.loads((a.bootstrap_build / "result.json").read_text())
    before = root_digest(a.base_root)
    if before != build["input_root_records_sha256"]:
        raise ValueError("Guard source root must match the offline build receipt")
    w.mkdir(mode=0o700)
    files, trust = w / "files", w / "trust"
    files.mkdir()
    trust.mkdir()
    for rel in ("etc/config/be6l-recovery", "etc/init.d/be6l-recovery", "usr/lib/be6l-recovery-guard/state.sh"):
        copy_path(a.base_root / rel, files / rel)
    link = files / "usr/sbin/be6l-recovery-guard"
    link.parent.mkdir(parents=True)
    link.symlink_to("../libexec/be6l/mainroot-bootstrap")
    depends = ["be6l-mainroot-bootstrap=1.0.0-r1", SSH, "procd", "uci", "busybox"]
    key = w / "temporary-signing.key"

    def run(label, argv):
        q = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120)
        (w / (label + ".log")).write_bytes(q.stdout + q.stderr)
        if q.returncode:
            raise RuntimeError(label + " failed")
        return q.stdout

    try:
        run("key", ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key])
        key.chmod(0o600)
        public = trust / "be6l-mainroot-native-guard.pem"
        run("public", ["openssl", "pkey", "-in", key, "-pubout", "-out", public])
        package = w / "be6l-recovery-guard-1.0.0-r4.apk"
        command = [a.apk, "mkpkg", "--sign-key", key, "--files", files, "--output", package]
        for k, v in dict(name="be6l-recovery-guard", version="1.0.0-r4", arch="noarch", license="MIT",
                         description="BE6L native recovery guard; exact private ARM32 SSH dependency", depends=" ".join(depends)).items():
            command += ["--info", k + ":" + v]
        run("mkpkg", command)
        run("verify", [a.apk, "--network=no", "--keys-dir", trust, "verify", package])
        metadata = run("metadata", [a.apk, "adbdump", package]).decode()
        if SSH not in metadata or "    - dropbear" in metadata:
            raise ValueError("Signed metadata lacks exact private native SSH dependency")
        if root_digest(a.base_root) != before:
            raise ValueError("Source root changed")
    finally:
        key.unlink(missing_ok=True)
    report = dict(normal_signed_guard_component=True, name="be6l-recovery-guard", version="1.0.0-r4", arch="noarch",
                  package_sha256=sha(package), dependencies=depends, generic_dropbear_dependency=False,
                  original_root_unchanged=True, source_root_records_sha256=before,
                  source_sha256=sha(Path(__file__)), private_signing_key_removed=not key.exists(),
                  root_transaction_performed=False, compiled_manifest_regenerated=False,
                  target_executed=False, candidate_admitted=False)
    (w / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("SIGNED_NATIVE_SSH_GUARD_COMPONENT_PASS; ROOT_NOT_COMPOSED")


if __name__ == "__main__":
    main()
