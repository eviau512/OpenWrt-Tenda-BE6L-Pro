# SPDX-License-Identifier: MIT
"""Read-only main-root vs unmodified signed standard-A53 package inventory.

Does not execute target ELFs or run APK transactions. Reports actual ELF tags,
root-relative symlinks, APK names/owners and payload collisions. Resolution is
an explicit offline model, not evidence that dlopen or package scripts work.
"""
from pathlib import Path, PurePosixPath
import argparse
from collections import Counter
import hashlib
import json
import os
import re
import stat
import struct
from package_native_netifd_v3 import root_digest


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def installed(root):
    packages, owners = {}, {}
    for block in (root / "lib/apk/db/installed").read_text().split("\n\n"):
        values, names, directory = {}, [], ""
        for line in block.splitlines():
            if len(line) < 2 or line[1] != ":":
                continue
            key, value = line[0], line[2:]
            if key == "F":
                directory = value
            elif key == "R":
                names.append(str(PurePosixPath(directory) / value))
            elif key in ("P", "V", "A", "D", "p", "T", "C"):
                values[key] = value
        if "P" in values:
            packages[values["P"]] = dict(name=values["P"], version=values.get("V"), arch=values.get("A"),
                depends=values.get("D", "").split(), provides=values.get("p", "").split(), paths=names)
            for name in names:
                owners.setdefault(name, []).append(values["P"])
    return packages, owners


def elf(path):
    data = path.read_bytes()
    if data[:6] not in (b"\x7fELF\x01\x01", b"\x7fELF\x02\x01"):
        return None
    bits = 64 if data[4] == 2 else 32
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind not in (2, 3):
        return None
    if bits == 64:
        phoff, flags, entsize, count = struct.unpack_from("<Q", data, 32)[0], struct.unpack_from("<I", data, 48)[0], *struct.unpack_from("<HH", data, 54)
    else:
        phoff, flags, entsize, count = struct.unpack_from("<I", data, 28)[0], struct.unpack_from("<I", data, 36)[0], *struct.unpack_from("<HH", data, 42)
    segments, interp, dynamic = [], None, None
    for index in range(count):
        offset = phoff + entsize * index
        if bits == 64:
            typ, pflags, off, va, pa, size, memsize, align = struct.unpack_from("<IIQQQQQQ", data, offset)
        else:
            typ, off, va, pa, size, memsize, pflags, align = struct.unpack_from("<IIIIIIII", data, offset)
        if typ == 1:
            segments.append((va, off, size))
        if typ == 3:
            interp = data[off:off+size].rstrip(b"\0").decode()
        if typ == 2:
            dynamic = (off, size)
    tags = []
    if dynamic:
        form, step = ("<qQ", 16) if bits == 64 else ("<iI", 8)
        for offset in range(dynamic[0], dynamic[0]+dynamic[1], step):
            tag, value = struct.unpack_from(form, data, offset)
            if tag == 0:
                break
            tags.append((tag, value))
    strings = next((value for tag, value in tags if tag == 5), None)
    strbase = next((off+strings-va for va, off, size in segments if strings is not None and va <= strings < va+size), None)

    def get_string(value):
        begin = strbase + value
        return data[begin:data.index(0, begin)].decode()

    return dict(bits=bits, machine=machine, type=kind, e_flags=hex(flags), interpreter=interp,
                needed=[get_string(value) for tag, value in tags if tag == 1],
                soname=next((get_string(value) for tag, value in tags if tag == 14), None),
                rpath=next((get_string(value) for tag, value in tags if tag == 15), None),
                runpath=next((get_string(value) for tag, value in tags if tag == 29), None),
                bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def record(path):
    mode = path.lstat().st_mode
    if stat.S_ISLNK(mode):
        return dict(type="symlink", target=os.readlink(path))
    if stat.S_ISREG(mode):
        return dict(type="file", sha256=sha(path), mode=oct(stat.S_IMODE(mode)))
    return dict(type="other", mode=oct(mode))


def rooted(root, name):
    pending, result, links = name.lstrip("/").split("/"), [], 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if result:
                result.pop()
            continue
        path = root.joinpath(*result, part)
        if path.is_symlink():
            links += 1
            if links > 40:
                raise ValueError("symlink loop: " + name)
            target = os.readlink(path)
            if target.startswith("/"):
                result = []
            pending = target.split("/") + pending
        else:
            result.append(part)
    path = root.joinpath(*result)
    return path if path.exists() else None


def scan(root, owners):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                continue
        info = elf(path)
        if info:
            name = path.relative_to(root).as_posix()
            result[name] = dict(info, owners=owners.get(name, []))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--main-root", required=True, type=Path)
    p.add_argument("--standard-work", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    out = a.out.resolve()
    if out.parent != Path("/root") or not out.name.startswith("be6l-mainroot-a53-inventory-"):
        p.error("Use a fresh /root/be6l-mainroot-a53-inventory-* directory")
    out.mkdir(mode=0o700)
    guest = a.standard_work / "root"
    packages, owners = installed(a.main_root)
    standard, stdowners = installed(guest)
    actual = scan(a.main_root, owners)
    expected = scan(guest, stdowners)
    receipt = json.loads((a.standard_work / "result.json").read_text())
    main_receipt = json.loads((a.main_root.parent / "result.json").read_text())
    main_digest, standard_digest = root_digest(a.main_root), root_digest(guest)
    if main_digest != main_receipt["installed_root_records_sha256"] or standard_digest != receipt["root_records_sha256"]:
        raise ValueError("Actual root differs from its admitted complete payload receipt")
    if {name: info["sha256"] for name, info in expected.items()} != receipt["standard_elf_sha256"]:
        raise ValueError("Standard ELF bytes differ from signed fixture receipt")
    name_collisions = {name: {"main": packages[name], "standard": standard[name]} for name in sorted(packages.keys() & standard.keys())}
    conflicts, identical, only_standard = {}, {}, []
    standard_paths = sorted({name for info in standard.values() for name in info["paths"]})
    for name in standard_paths:
        path, main_path = guest / name, a.main_root / name
        if not path.exists() and not path.is_symlink():
            raise ValueError("APK-owned standard path is absent: " + name)
        if main_path.exists() or main_path.is_symlink():
            stdrec, mainrec = record(path), record(main_path)
            row = dict(main=mainrec, standard=stdrec, main_owners=owners.get(name, []), standard_owners=stdowners.get(name, []))
            (identical if stdrec == mainrec else conflicts)[name] = row
        else:
            only_standard.append(name)
    loader_files = {}
    for rootname, root in [("main", a.main_root), ("standard", guest)]:
        loader_files[rootname] = {}
        for directory in (root / "etc", root / "lib"):
            for path in sorted(directory.glob("*musl*")):
                if path.is_file() and not path.is_symlink() and path.suffix == ".path":
                    loader_files[rootname][path.relative_to(root).as_posix()] = path.read_text()
        for path in sorted((root / "lib").glob("ld-*")):
            loader_files[rootname][path.relative_to(root).as_posix()] = record(path)
    # Existing-root resolution for every standard DT_NEEDED, with no LD_LIBRARY_PATH.
    resolution = {}
    for name, info in expected.items():
        requests = ([info["interpreter"]] if info["interpreter"] else []) + info["needed"]
        rows = []
        for dependency in requests:
            candidates = [dependency] if "/" in dependency else [directory + "/" + dependency for directory in ("/lib", "/usr/local/lib", "/usr/lib")]
            found = next(((candidate, rooted(a.main_root, candidate)) for candidate in candidates if rooted(a.main_root, candidate)), None)
            if found:
                candidate, target = found
                loaded = elf(target)
                rows.append(dict(request=dependency, path=candidate, resolved=target.relative_to(a.main_root).as_posix(), elf=loaded,
                    standard_compatible_header=bool(loaded and loaded["bits"] == 64 and loaded["machine"] == 183 and loaded["e_flags"] == "0x0")))
            else:
                rows.append(dict(request=dependency, missing=True))
        resolution[name] = rows
    arm32 = {name: info for name, info in actual.items() if info["bits"] == 32}
    arm32_dsos = {name: info for name, info in arm32.items()
                  if name.startswith(("lib/", "usr/lib/")) and (name.endswith(".so") or ".so." in name)}
    arm32_aliases = {}
    for path in sorted(a.main_root.rglob("*")):
        if not path.is_symlink():
            continue
        name = path.relative_to(a.main_root).as_posix()
        target = rooted(a.main_root, name)
        if target and target.relative_to(a.main_root).as_posix() in arm32_dsos:
            arm32_aliases[name] = dict(target=os.readlink(path), owners=owners.get(name, []),
                resolved=target.relative_to(a.main_root).as_posix())
    arm32_edges, missing_arm32 = [], []
    for name, info in arm32.items():
        for dep in info["needed"]:
            candidates = [dep] if "/" in dep else [directory + "/" + dep for directory in ("/lib", "/usr/local/lib", "/usr/lib")]
            found = next((rooted(a.main_root, path) for path in candidates if rooted(a.main_root, path)), None)
            target = found.relative_to(a.main_root).as_posix() if found else None
            row = dict(source=name, needed=dep, resolved=target)
            (arm32_edges if target in arm32 else missing_arm32).append(row)
    vm_modules = {name: info for name, info in arm32.items() if name.startswith(("usr/lib/lua/", "usr/lib/ucode/"))}
    vm_extra = sorted({pkg for name, info in vm_modules.items() if name not in expected for pkg in info["owners"]})
    embedded_vms = {name: info for name, info in actual.items() if any("liblua" in dep or "libucode" in dep for dep in info["needed"])}
    literals = {}
    needles = (b"/usr/lib/lua", b"/usr/lib/ucode", b"/usr/lib/rpcd", b"/usr/lib/pppd", b"/usr/lib/uhttpd",
               b"/opt/be6l-a64-soft/lib", b"/lib/libsetlbf.so", b"LD_PRELOAD")
    for name in actual:
        strings = sorted({s.decode() for s in re.findall(rb"[ -~]{5,}", (a.main_root / name).read_bytes()) if any(x in s for x in needles)})
        if strings:
            literals[name] = strings
    report = dict(scope="Read-only inventory; no APK transaction, script execution, root mutation, or runtime compatibility claim",
        main_root=str(a.main_root), standard_root=str(guest), standard_work_receipt_sha256=sha(a.standard_work / "result.json"),
        main_root_records_sha256=main_digest, standard_root_records_sha256=standard_digest,
        full_root_receipts_match=True,
        main_db_sha256=sha(a.main_root / "lib/apk/db/installed"), standard_db_sha256=sha(guest / "lib/apk/db/installed"),
        main_arch=(a.main_root / "etc/apk/arch").read_text().splitlines(),
        standard_arch=(guest / "etc/apk/arch").read_text().splitlines(),
        main_packages=packages, standard_packages=standard,
        main_elf=actual, standard_elf=expected, package_name_collisions=name_collisions,
        payload_conflicts=conflicts, payload_identical=identical, payload_only_standard=only_standard,
        loader_files=loader_files, standard_resolution_in_current_mainroot=resolution,
        arm32_runtime_dso_files=arm32_dsos, arm32_runtime_aliases=arm32_aliases,
        arm32_needed_edges=arm32_edges, arm32_missing_or_wrong_abi_needed_edges=missing_arm32,
        arm32_runtime_source_packages=sorted({pkg for info in arm32_dsos.values() for pkg in info["owners"]}),
        arm32_all_elf_source_packages=sorted({pkg for info in arm32.values() for pkg in info["owners"]}),
        vm_modules=vm_modules, additional_normal_module_package_lower_bound=vm_extra,
        vm_embedders=embedded_vms, embedded_module_and_preload_path_literals=literals,
        init_script=(a.main_root / "init").read_text(),
        counts=dict(main_packages=len(packages), standard_packages=len(standard), main_exec_dso_elf=len(actual),
                    main_private_a64_elf=sum(x["bits"] == 64 and x["e_flags"] == "0xbe6a0001" for x in actual.values()),
                    standard_elf=len(expected), package_name_collisions=len(name_collisions),
                    payload_conflicts=len(conflicts), payload_identical=len(identical), payload_only_standard=len(only_standard)),
        roots_modified=False, full_standard_a53_package_compatibility_qualified=False)
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report["counts"], indent=2))
    print("MAIN_ARCH", report["main_arch"])
    print("MAIN_ELF_ABIS", dict(Counter((x["bits"], x["machine"], x["e_flags"]) for x in actual.values())))
    print("PACKAGE_NAMES", sorted(name_collisions))
    print("PRIVATE_OWNERS", sorted({owner for x in actual.values() if x["e_flags"] == "0xbe6a0001" for owner in x["owners"]}))
    print("ARM32_RUNTIME", len(arm32_dsos), len(arm32_aliases), "needed_edges", len(arm32_edges), "unresolved", len(missing_arm32))
    print("EXTRA_NORMAL_MODULE_PACKAGE_LOWER_BOUND", vm_extra)


if __name__ == "__main__":
    main()
