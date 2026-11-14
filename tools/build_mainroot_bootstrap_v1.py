# SPDX-License-Identifier: MIT
"""Compile a manifest-bound native bootstrap PAYLOAD; never compose/admit an Image.

The input root is read-only. The signed bootstrap/config transaction, final root
regeneration, kernel F/proc-fd test and whole Image admission remain separate.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
from package_native_netifd_v3 import root_digest
from plan_integer_binfmt_v1 import rule_bytes
from prepare_ramboot import tree

BASE = Path(__file__).resolve().parents[1]
SOURCE = BASE / "experiments/mainroot-bootstrap"
PRIVATE = 0xbe6a0001
BOOTSTRAP = "usr/libexec/be6l/mainroot-bootstrap"
NATIVE_INIT = "usr/libexec/be6l/initramfs-init-native"
BUSYBOX = "opt/be6l-a64-soft/bin/busybox"
EMULATOR = "usr/libexec/be6l/qemu-aarch64"
BUSYBOX_SHA = "1c5562bcb7ec47ae5efad6776a9a2b04a33367b20995b49dff357e283ace9f4b"
INIT_SHA = "1d1991b6b702247a2c59bc89b4ec700820339b06a84aefe1a424f7e451017e6b"
R5_APK_SHA = "253fc682636d2d40b1e6c016317704b21452c74cc2540d1bffd32223adfa5928"
R5_SHA = "7e094b445e34d353c47b91cddde062ce2e2d344678813da5e22b9993953d720d"
INIT_SCRIPT = """#!/opt/be6l-a64-soft/bin/busybox sh
# Original OpenWrt initramfs root-copy ordering; every external helper is native.
export INITRAMFS=1
BB=/opt/be6l-a64-soft/bin/busybox
fail() { exec /usr/libexec/be6l/mainroot-bootstrap --early-failure; }
DIRS=$(echo *)
NEW_ROOT=/new_root
"$BB" mkdir -p "$NEW_ROOT" || fail
"$BB" mount -t tmpfs tmpfs "$NEW_ROOT" || fail
"$BB" cp -pr $DIRS "$NEW_ROOT" || fail
exec "$BB" switch_root "$NEW_ROOT" /usr/libexec/be6l/mainroot-bootstrap --post-switch-root
"""


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf(data):
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[5] != 1:
        return None
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind not in (2, 3):
        return None
    if data[4] == 1 and machine == 40:
        return 3
    if data[4] != 2 or machine != 183:
        raise ValueError("Unexpected executable ELF machine/class")
    flags = struct.unpack_from("<I", data, 48)[0]
    if flags not in (0, PRIVATE):
        raise ValueError("Unreviewed A64 e_flags")
    return 1 if flags == PRIVATE else 2


def static_elf(data):
    offset = struct.unpack_from("<Q", data, 32)[0]
    stride, count = struct.unpack_from("<HH", data, 54)
    if stride != 56 or not 1 <= count <= 128 or offset + count * 56 > len(data):
        raise ValueError("Invalid static A64 program headers")
    if any(struct.unpack_from("<I", data, offset + i * stride)[0] in (2, 3) for i in range(count)):
        raise ValueError("Expected static native integer helper")


def owners(root):
    result = {}
    for block in (root / "lib/apk/db/installed").read_text().split("\n\n"):
        fields = dict(line.split(":", 1) for line in block.splitlines() if line[:2] in ("P:", "V:", "A:"))
        directory = ""
        for line in block.splitlines():
            if line.startswith("F:"):
                directory = line[2:]
            elif line.startswith("R:"):
                name = (directory + "/" + line[2:]).lstrip("/")
                if name in result:
                    raise ValueError("Duplicate APK owner: " + name)
                result[name] = fields
    return result


def manifest_entry(path, source, role=None, native=False):
    st = source.lstat()
    if st.st_uid != 0:
        raise ValueError("Root-owned payload required: " + path)
    if source.is_symlink():
        return dict(path=path, digest="", link=os.readlink(source), size=0, mode=0, role=5, static_native=0)
    data = source.read_bytes()
    if st.st_mode & 0o022:
        raise ValueError("Writable trusted payload: " + path)
    detected = elf(data)
    role = role if role is not None else (detected or 0)
    if native:
        if detected != 1:
            raise ValueError("Native helper has no private marker")
        static_elf(data)
    return dict(path=path, digest=hashlib.sha256(data).hexdigest(), link="", size=len(data),
                mode=stat.S_IMODE(st.st_mode), role=role, static_native=int(native))


def write_header(path, entries, bmt, identifier):
    if len(entries) > 4096:
        raise ValueError("Compiled manifest exceeds explicit admission limit")
    magic, mask = rule_bytes()
    constants = dict(BOOTSTRAP_PATH=BOOTSTRAP, NATIVE_INIT_PATH=NATIVE_INIT,
                     NATIVE_BUSYBOX_PATH=BUSYBOX, EMULATOR_PATH=EMULATOR,
                     BMT_PROPERTY_PATH=bmt, MANIFEST_ID=identifier)
    lines = ["/* Generated trusted manifest; not runtime configuration. */"]
    lines += ["#define %s %s" % (k, json.dumps(v)) for k, v in constants.items()]
    lines += ["#define MANIFEST_COUNT %dU" % len(entries), "static const struct manifest_entry manifest[] = {"]
    for e in entries:
        lines.append("{%s,%s,%s,%dULL,%dU,%dU,%dU}," %
                     (json.dumps(e["path"]), json.dumps(e["digest"]), json.dumps(e["link"]),
                      e["size"], e["mode"], e["role"], e["static_native"]))
    lines += ["};"]
    for name, data in (("rule_magic", magic), ("rule_mask", mask)):
        lines += ["static const unsigned char %s[52] = {%s};" % (name, ",".join(str(v) for v in data))]
    path.write_text("\n".join(lines) + "\n")


def audit_integer(path, prefix):
    data = path.read_bytes()
    static_elf(data)
    dis = subprocess.check_output([prefix + "objdump", "-d", path], text=True)
    count = 0
    for line in dis.splitlines():
        if "\t" not in line:
            continue
        ins = line.split("\t", 2)[-1]
        if re.match(r"^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s", ins):
            continue
        if re.search(r"(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b", ins):
            raise ValueError("FP/SIMD instruction in native bootstrap: " + ins)
        count += 1
    if not count:
        raise ValueError("Empty native disassembly")
    return count


def verified_normal_provenance(packages, keys, apk, work, run):
    """Actual signature/extract/metadata branch, shared with a bounded fixture.

    Returns normal ELF provenance, never installs or executes a target package.
    """
    if not isinstance(packages, list) or not packages or len(packages) > 512:
        raise ValueError("Explicit bounded normal package list required")
    normal, normal_packages = {}, []
    for i, value in enumerate(packages):
        package = Path(value).resolve()
        run("normal-%d-verify" % i, [apk, "--network=no", "--keys-dir", keys, "verify", package])
        metadata = run("normal-%d-metadata" % i, [apk, "adbdump", package]).decode()
        fields = {}
        for key in ("name", "version", "arch"):
            matches = re.findall(r"^  " + key + r": (\S+)$", metadata, re.M)
            if len(matches) != 1:
                raise ValueError("Ambiguous signed package metadata")
            fields[key] = matches[0]
        if fields["arch"] not in ("aarch64_cortex-a53", "all", "noarch") or fields["name"].startswith("be6l-"):
            raise ValueError("Normal archive arch/name is not ordinary A53/noarch")
        dest = work / ("verified-normal-%d" % i)
        dest.mkdir()
        run("normal-%d-extract" % i, [apk, "--network=no", "--keys-dir", keys, "extract", "--no-chown", "--destination", dest, package])
        for file in dest.rglob("*"):
            if file.is_symlink() or not file.is_file():
                continue
            data = file.read_bytes()
            if elf(data) == 2:
                name = file.relative_to(dest).as_posix()
                item = dict(sha256=hashlib.sha256(data).hexdigest(), P=fields["name"], V=fields["version"], A=fields["arch"])
                if name in normal and normal[name] != item:
                    raise ValueError("Normal archive ELF collision: " + name)
                normal[name] = item
        normal_packages.append(dict(sha256=sha(package), **fields))
    return normal, normal_packages


def verify_normal_file(name, file, owned, normal):
    verified = normal.get(name)
    if not verified or verified["sha256"] != sha(file) or owned.get(name) != {k: verified[k] for k in ("P", "V", "A")}:
        raise ValueError("Normal A53 bytes/owner lack exact signed archive provenance: " + name)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--expected-root-sha256", required=True)
    p.add_argument("--emulator-package", type=Path, required=True)
    p.add_argument("--apk", type=Path, required=True)
    p.add_argument("--dtb", type=Path, required=True)
    p.add_argument("--softcc", type=Path, required=True)
    p.add_argument("--cross-prefix", required=True)
    p.add_argument("--normal-package-list", type=Path, help="JSON list of exact APK paths; all normal ELF bytes independently extracted/verified")
    p.add_argument("--normal-keys-dir", type=Path)
    p.add_argument("--work", type=Path, required=True)
    a = p.parse_args()
    root, work = a.root.resolve(), a.work.resolve()
    if work.parent != Path("/root") or not work.name.startswith("be6l-mainroot-bootstrap-"):
        p.error("Use a new /root/be6l-mainroot-bootstrap-*")
    if work.exists() or not re.fullmatch("[0-9a-f]{64}", a.expected_root_sha256):
        raise ValueError("Fresh work and explicit root seal required")
    before = root_digest(root)
    if before != a.expected_root_sha256:
        raise ValueError("Input root seal differs")
    if sha(root / BUSYBOX) != BUSYBOX_SHA or sha(root / "init") != INIT_SHA:
        raise ValueError("Unreviewed native BusyBox or original root-copy init")
    for item in root.iterdir():
        if not re.fullmatch("[A-Za-z0-9_.+-]+", item.name) or item.name in ("new_root", "be6l-recovery-state"):
            raise ValueError("Unsafe original root-copy top-level name")
    dt = tree(a.dtb.read_bytes())
    properties = [n for n, props in dt.items() if "airoha,bmt-read-only" in props]
    if len(properties) != 1 or b"tenda,be6l-pro\0" not in dt["/"]["compatible"]:
        raise ValueError("Unreviewed readonly BMT/board DT")
    bmt = "/sys/firmware/devicetree/base" + properties[0] + "/airoha,bmt-read-only"
    emulator = a.emulator_package.resolve()
    if sha(emulator / "be6l-integer-emulator-11.1.3-r5.apk") != R5_APK_SHA:
        raise ValueError("Exact signed r5 APK required")
    work.mkdir()

    def run(label, argv):
        q = subprocess.run(list(map(str, argv)), capture_output=True, timeout=180)
        (work / (label + ".log")).write_bytes(q.stdout + q.stderr)
        if q.returncode:
            raise RuntimeError(label + " failed: " + q.stderr.decode(errors="replace")[-1000:])
        return q.stdout

    r5 = work / "verified-r5"
    r5.mkdir()
    run("r5-verify", [a.apk, "--network=no", "--keys-dir", emulator / "trust", "verify", emulator / "be6l-integer-emulator-11.1.3-r5.apk"])
    run("r5-extract", [a.apk, "--network=no", "--keys-dir", emulator / "trust", "extract", "--no-chown", "--destination", r5, emulator / "be6l-integer-emulator-11.1.3-r5.apk"])
    if sha(r5 / EMULATOR) != R5_SHA or stat.S_IMODE((r5 / EMULATOR).stat().st_mode) != 0o555:
        raise ValueError("Signed r5 payload differs")
    normal, normal_packages = {}, []
    if a.normal_package_list:
        if not a.normal_keys_dir:
            raise ValueError("Normal package public trust directory required")
        packages = json.loads(a.normal_package_list.read_text())
        normal, normal_packages = verified_normal_provenance(packages, a.normal_keys_dir, a.apk, work, run)
    owned = owners(root)
    entries = []
    replaced = {"init", NATIVE_INIT, BOOTSTRAP, EMULATOR, "usr/sbin/be6l-recovery-guard", "usr/libexec/be6l/native-recovery-shell"}
    for file in sorted(root.rglob("*")):
        name = file.relative_to(root).as_posix()
        if name in replaced:
            continue
        if file.is_symlink():
            entries.append(manifest_entry(name, file))
        elif file.is_file():
            role = elf(file.read_bytes())
            # The bootstrap APK changes its own DB checksum: hashing the full
            # installed DB into this binary would create a self-reference.
            # Final composition admission authenticates that DB; runtime pins
            # the actual ELF bytes, loader config and symlink closure instead.
            critical = name == "etc/config/be6l-recovery" or name.startswith("etc/ld-musl-") and name.endswith(".path")
            if role or critical:
                if role == 2:
                    verify_normal_file(name, file, owned, normal)
                entries.append(manifest_entry(name, file, native=name == BUSYBOX))
    payload = work / "payload"
    (payload / NATIVE_INIT).parent.mkdir(parents=True)
    (payload / NATIVE_INIT).write_text(INIT_SCRIPT)
    (payload / NATIVE_INIT).chmod(0o555)
    entries += [manifest_entry(NATIVE_INIT, payload / NATIVE_INIT), manifest_entry(EMULATOR, r5 / EMULATOR, native=True)]
    for name in ("init", BOOTSTRAP):
        entries.append(dict(path=name, digest="", link="", size=0, mode=0o555, role=4, static_native=1))
    for name, target in (("usr/sbin/be6l-recovery-guard", "../libexec/be6l/mainroot-bootstrap"), ("usr/libexec/be6l/native-recovery-shell", "mainroot-bootstrap")):
        entries.append(dict(path=name, digest="", link=target, size=0, mode=0, role=5, static_native=0))
        dest = payload / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.symlink_to(target)
    entries.sort(key=lambda e: e["path"])
    if len({e["path"] for e in entries}) != len(entries):
        raise ValueError("Duplicate manifest path")
    provenance = dict(input_root_records_sha256=before, signed_r5_apk_sha256=R5_APK_SHA,
                      normal_packages=normal_packages, entries=entries, bmt_property=bmt)
    identifier = hashlib.sha256(json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    (work / "manifest.json").write_text(json.dumps(dict(manifest_id=identifier, **provenance), indent=2) + "\n")
    write_header(work / "bootstrap_manifest.h", entries, bmt, identifier)
    output = work / "mainroot-bootstrap.unmarked"
    run("compile", [a.softcc, "-static", "-Os", "-std=c11", "-Wall", "-Wextra", "-Wno-unused-function", "-Wno-misleading-indentation", "-I", work, SOURCE / "bootstrap.c", "-o", output])
    instructions = audit_integer(output, a.cross_prefix)
    data = bytearray(output.read_bytes())
    if elf(data) != 2:
        raise ValueError("Unmarked bootstrap has wrong ABI")
    struct.pack_into("<I", data, 48, PRIVATE)
    for name in ("init", BOOTSTRAP):
        dest = payload / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        dest.chmod(0o555)
    after = root_digest(root)
    if before != after:
        raise ValueError("Input root changed during build")
    account_shell = next((line.split(":")[-1] for line in (root / "etc/passwd").read_text().splitlines() if line.startswith("root:")), None)
    result = dict(manifest_id=identifier, input_root_records_sha256=before, original_root_unchanged=True,
                  bootstrap_sha256=sha(payload / BOOTSTRAP), bootstrap_bytes=len(data), private_marker=hex(PRIVATE),
                  static_native=True, aapcs64_soft=True, fp_simd_register_uses=0, audited_instructions=instructions,
                  native_busybox_sha256=BUSYBOX_SHA, signed_r5_apk_sha256=R5_APK_SHA, interpreter_sha256=R5_SHA,
                  complete_input_elf_inventory=True, manifest_entries=len(entries),
                  elf_roles={str(role): sum(e["role"] == role for e in entries) for role in (1, 2, 3, 4)},
                  normal_archives_verified=len(normal_packages), source_sha256=sha(SOURCE / "bootstrap.c"),
                  sha256_source_sha256=sha(SOURCE / "sha256.h"), compiled_header_sha256=sha(work / "bootstrap_manifest.h"),
                  compiler_wrapper_sha256=sha(a.softcc), dtb_sha256=sha(a.dtb),
                  root_account_native_shell=account_shell == "/usr/libexec/be6l/native-recovery-shell",
                  bootstrap_package_signed=False, final_root_composed=False, kernel_F_procfd_qualified=False,
                  target_executed=False, candidate_admitted=False, standard_a53_package_compatibility_qualified=False)
    (work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("OFFLINE_NATIVE_BOOTSTRAP_PAYLOAD_BUILT; NOT_ADMITTED", identifier, len(data))


if __name__ == "__main__":
    main()
