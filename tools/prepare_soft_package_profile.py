# SPDX-License-Identifier: MIT
"""Create a reviewable, versioned native soft-ABI package admission lock.

Cached inputs only. A later admission step must be given this lock's reviewed
SHA256 explicitly; ELF machine/architecture labels never grant ABI admission.
No existing sysroot, SDK, package database or DUT is modified.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
from a64_soft_context import BASE, SDK, EPOCH

ARCH = 'aarch64_be6l_soft_experimental'
CORRECTED_LIBC = '143100b85695d93b77a8b79b518f17cb48134ab38c828a07b0a9d171811dcddb'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def prepare(root):
    assert root.is_absolute() and not root.exists() and not any(c.isspace() for c in str(root))
    root.mkdir()
    (root / '.be6l-soft-profile').write_text('owned offline profile preparation\n')
    content, original_manifests = {}, {}
    for group, archive in (('core', 'core.tar'), ('lua-bindings', 'bindings.tar'), ('network', 'network.tar')):
        artifact = BASE / ('artifacts/a64-soft-' + group)
        manifest_bytes = (artifact / 'manifest.json').read_bytes()
        manifest = json.loads(manifest_bytes)
        files = manifest.get('files', manifest)
        original_manifests[group] = digest(manifest_bytes)
        with tarfile.open(artifact / archive) as tar:
            members = tar.getmembers()
            assert len(members) == len(files) and {p.name for p in members} == set(files)
            for member in members:
                assert member.isfile() and not member.name.startswith('/') and '..' not in Path(member.name).parts
                data = tar.extractfile(member).read()
                assert digest(data) == files[member.name]['sha256']
                if member.name in content:
                    assert content[member.name] == data, ('Conflicting closure provider', member.name)
                content[member.name] = data
    assert digest(content['libc.so']) == CORRECTED_LIBC
    core = Path('/root/be6l-openwrt/a64-soft-no-contract-repro-long-v2')
    lua = Path('/root/be6l-openwrt/a64-soft-lua-bindings-repro-long-v6')
    network = Path('/root/be6l-openwrt/a64-soft-network-fixed-repro-long-v4')
    # Include every ELF owned by the original procd package, rather than leaving
    # ARM32 helper files under a package claimed to contain only the native ABI.
    for name in ('askfirst', 'udevtrigger', 'upgraded'):
        content[name] = (core / 'sysroot/usr/sbin' / name).read_bytes()
    content['libsetlbf.so'] = (core / 'sysroot/usr/lib/libsetlbf.so').read_bytes()
    gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
    prefix = str(gcc)[:-3]
    payload = root / 'payload'
    payload.mkdir()
    files = {}
    for name, data in sorted(content.items()):
        p = payload / name
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(data)
        subprocess.run([prefix + 'strip', '--strip-debug', str(p)], check=True)
        data = p.read_bytes()
        assert data[:6] == b'\x7fELF\x02\x01' and data[18:20] == b'\xb7\0'
        dynamic = subprocess.check_output([prefix + 'readelf', '-d', str(p)], text=True)
        assert not re.search(r'\((?:RPATH|RUNPATH)\)', dynamic), name
        needed = re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)
        dis = subprocess.check_output([prefix + 'objdump', '-d', str(p)], text=True)
        for line in dis.splitlines():
            if '\t' not in line:
                continue
            ins = line.split('\t', 2)[-1]
            if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s', ins):
                continue
            assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b', ins), (name, ins)
        program = subprocess.check_output([prefix + 'readelf', '-lW', str(p)], text=True)
        interpreter = re.findall(r'Requesting program interpreter: (.*?)\]', program)
        assert not interpreter or interpreter == ['/lib/ld-musl-aarch64-soft.so.1'], (name, interpreter)
        files[name] = dict(sha256=digest(data), bytes=len(data), needed=needed,
                           interpreter=interpreter, machine=183, elf_class=64,
                           fp_simd_register_uses=0)
    for name, item in files.items():
        assert all(dep in files for dep in item['needed']), (name, item['needed'])

    tree = SDK / 'build_dir/target-aarch64_cortex-a53_musl'
    sources = {'musl': core/'musl', 'busybox': core/'busybox', 'lua': lua/'lua', 'nixio': lua/'nixio',
               'mbedtls': network/'source-mbedtls', 'curl': network/'source-curl',
               'compiler-rt': BASE/'upstream/llvm21-soft-builtins'}
    for name, path in {
        'jsonc':'json-c-0.19', 'libubox':'libubox-2026.07.21~e7608b69',
        'ubus':'ubus-2026.09.25~414c60a2', 'uci':'uci-2025.12.02~66127cd7',
        'ucode':'ucode-2026.10.18~d2e8b8d2', 'udebug':'udebug-2026.09.25~6726e98a',
    }.items(): sources[name] = tree/path
    sources['procd'] = core/'procd-source'  # Includes the tested noreturn correction.
    inventories, notices = {}, {}
    notice_dir = root/'notices'
    notice_dir.mkdir()
    for component, source in sources.items():
        entries, license_entries, header_notices = {}, {}, []
        assert source.is_dir(), component
        for p in sorted(source.rglob('*')):
            rel = p.relative_to(source)
            if not p.is_file() or p.is_symlink() or any(
                part.startswith(('ipkg-', 'apk-', '.pkgdir', 'CMakeFiles', '.git', 'dist'))
                or part in ('obj', 'lib', 'build', '_install') for part in rel.parts[:-1]):
                continue
            license_file = p.name.upper().startswith(('LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT'))
            selected = license_file or p.suffix in ('.c','.h','.s','.S','.mk','.cmake') or p.name in (
                'Makefile','CMakeLists.txt','configure','.config','config.mak')
            if not selected:
                continue
            data = p.read_bytes()
            entries[rel.as_posix()] = digest(data)
            if license_file:
                license_entries[rel.as_posix()] = digest(data)
                target = notice_dir/component/rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            elif p.suffix in ('.c','.h') and data.lstrip().startswith(b'/*'):
                header = data.lstrip().split(b'*/',1)[0] + b'*/\n'
                if len(header) < 12000 and any(word in header.lower() for word in (
                    b'copyright', b'license', b'permission to use')):
                    header_notices.append(rel.as_posix()+'\n'+header.decode('utf-8',errors='replace'))
        assert entries, component
        if header_notices:
            (notice_dir/component).mkdir(exist_ok=True)
            (notice_dir/component/'SOURCE-NOTICES.txt').write_text('\n\n'.join(header_notices))
        assert license_entries or header_notices, ('Missing licensing input', component)
        inventories[component] = dict(files=len(entries), tree_sha256=digest(canonical(entries)),
                                      license_files=license_entries,
                                      source_notice_headers=len(header_notices))
        # Full per-file inventory stays local for independent reconstruction.
        (root/(component+'-source-inventory.json')).write_bytes(canonical(entries))
    for p in sorted(notice_dir.rglob('*')):
        if p.is_file(): notices[p.relative_to(notice_dir).as_posix()] = digest(p.read_bytes())
    builders = {name:digest((BASE/'tools'/name).read_bytes()) for name in (
        'build_a64_soft_musl.py','build_a64_soft_busybox.py','build_a64_soft_core.py',
        'build_a64_soft_network.py','build_a64_soft_lua.py','build_a64_soft_lua_bindings.py',
        'prepare_a64_soft_core.py')}
    version = subprocess.check_output(['/usr/bin/clang','--version'],text=True).splitlines()[0]
    assert 'clang version 21.1.8' in version
    flags = ('--target=aarch64-linux-musl','-march=armv8-a+nofp+nosimd','-mabi=aapcs-soft',
             '-mno-outline-atomics','-ffp-contract=off')
    for source_root in (core,lua,network):
        assert all(flag in (source_root/'cc').read_text() for flag in flags)
    original = Path('/root/be6l-openwrt/compat-apk-root/root')
    compatibility = {}
    for name in ('lib/libsetlbf.so', 'etc/hotplug-preinit.json', 'etc/hotplug.json',
                 'lib/functions/procd.sh', 'sbin/reload_config', 'sbin/service',
                 'lib/apk/packages/procd.rusers'):
        data = (original/name).read_bytes()
        if name.endswith('.so'):
            assert data[:6] == b'\x7fELF\x01\x01' and data[18:20] == b'\x28\0'
        else:
            assert not data.startswith(b'\x7fELF')
        target = root/'compatibility'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        compatibility[name] = digest(data)
    profile = dict(schema=1, abi='AAPCS64-soft', architecture=ARCH, source_date_epoch=EPOCH,
                   compiler=dict(version=version, binary_sha256=digest(Path('/usr/bin/clang').resolve().read_bytes()),
                                 required_flags=list(flags)),
                   source_inventories=inventories, builder_sha256=builders,
                   input_manifest_sha256=original_manifests, notices=notices, files=files,
                   original_procd_compatibility_files=compatibility,
                   license_inventory_collected=True, binary_redistribution_license_review_complete=False,
                   ordinary_aarch64_packages_compatible=False, complete_native_sdk=False,
                   runtime_new_helpers_qualified=False)
    lock = root/'profile-lock.json'
    lock.write_bytes(canonical(profile))
    report = dict(profile_lock_sha256=digest(lock.read_bytes()), files=len(files), components=len(inventories),
                  corrected_libc_verified=True, local_root=str(root), hardware_modified=False)
    (BASE/'logs'/('soft-profile-'+root.name+'.json')).write_bytes(canonical(report))
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    prepare(parser.parse_args().root)
