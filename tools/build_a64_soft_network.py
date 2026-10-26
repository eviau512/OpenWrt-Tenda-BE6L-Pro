# SPDX-License-Identifier: MIT
"""Build an isolated no-FP TLS/curl closure from the existing pinned SDK cache.

This is an experimental dependency closure, not an image, APK, or replacement
for the installed curl. No target execution or source download is performed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import io
import tarfile

from a64_soft_context import BASE, SDK, EPOCH

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--root', required=True, type=Path)
parser.add_argument('--base-soft-root', required=True, type=Path)
parser.add_argument('--resume', action='store_true')
args = parser.parse_args()
root, prior = args.root, args.base_soft_root
assert root.is_absolute() and prior.is_absolute() and root != prior
assert '-ffp-contract=off' in (prior / 'cc').read_text(), 'Rebuild the base C suite with contraction disabled first'
assert not any(c.isspace() for c in str(root))
marker = root / '.be6l-soft-network.json'
ownership = {'purpose': 'isolated AAPCS64-soft TLS/curl', 'base': str(prior)}
if args.resume:
    assert json.loads(marker.read_text()) == ownership
else:
    assert not root.exists(), 'Choose a fresh output directory; no directory is deleted'
    root.mkdir()
    marker.write_text(json.dumps(ownership, indent=2) + '\n')
    shutil.copytree(prior / 'sysroot', root / 'sysroot', symlinks=True)
    shutil.copyfile(prior / 'libsoft-builtins.a', root / 'libsoft-builtins.a')
    for name in ('cc', 'softcc', 'soft-toolchain.cmake'):
        text = (prior / name).read_text().replace(str(prior), str(root))
        (root / name).write_text(text)
        (root / name).chmod(0o755)

tree = SDK / 'build_dir/target-aarch64_cortex-a53_musl'
patterns = {'mbedtls': 'mbedtls-3.6.7', 'curl': 'curl-8.23.0'}
sysroot = root / 'sysroot'
gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
prefix = str(gcc)[:-3]
bundle = BASE / 'upstream/llvm21-soft-builtins'
lock = json.loads((BASE / 'upstream/llvm21-soft-builtins-lock.json').read_text())
assert lock['commit'] == '2078da43e25a4623cab2d0d60decddf709aaea28'
for item in lock['files']:
    data = (bundle / item['name']).read_bytes()
    assert len(data) == item['bytes'] and hashlib.sha256(data).hexdigest() == item['sha256']
objects = root / 'network-runtime-objects'
objects.mkdir(exist_ok=True)
extra = []
for name in ('udivti3.c', 'udivmodti4.c'):
    assert any(item['name'] == name for item in lock['files'])
    obj = objects / (name[:-2] + '.o')
    subprocess.run([str(root / 'cc'), '-O2', '-fPIC', '-ffreestanding',
                    '-Qunused-arguments',
                    '-fno-stack-protector', '-fno-vectorize', '-fno-slp-vectorize',
                    '-D__SOFT_FP__=1', '-I' + str(bundle), '-c', str(bundle / name),
                    '-o', str(obj)], check=True, stdout=subprocess.DEVNULL)
    extra.append(str(obj))
subprocess.run([prefix + 'ar', 'rcs', str(root / 'libsoft-builtins.a'), *extra], check=True)
runtime_hash = hashlib.sha256((root / 'libsoft-builtins.a').read_bytes()).hexdigest()
stamp = root / 'network-runtime.json'
relink = not stamp.exists() or json.loads(stamp.read_text())['sha256'] != runtime_hash
stamp.write_text(json.dumps({'sha256': runtime_hash, 'added_integer_helpers': ['__udivti3', '__udivmodti4']}) + '\n')
env = dict(os.environ)
env.update(SOURCE_DATE_EPOCH=EPOCH,
           PKG_CONFIG_PATH='',
           PKG_CONFIG_LIBDIR=str(sysroot / 'usr/lib/pkgconfig') + ':' + str(sysroot / 'lib/pkgconfig'),
           PKG_CONFIG_SYSROOT_DIR=str(sysroot))
env['PATH'] = '/root/be6l-openwrt/host/bin:' + str(SDK / 'staging_dir/host/bin') + ':' + env['PATH']
logdir = BASE / 'logs' / ('soft-network-' + root.name)
logdir.mkdir(parents=True, exist_ok=True)
receipts = {}

for component, version in patterns.items():
    cached = tree / version
    assert cached.is_dir(), 'Required pinned source is not cached: ' + version
    source = root / ('source-' + component)
    if not source.exists():
        shutil.copytree(cached, source, symlinks=True, ignore=shutil.ignore_patterns(
            'CMakeFiles', 'CMakeCache.txt', 'build.ninja', '.ninja*', '*.o', '*.a',
            '*.so', '*.so.*', 'cmake_install.cmake', 'install_manifest.txt',
            'ipkg-*', 'apk-*', 'ipkg-install', '.pkgdir', '.built*', '.configured*'))
    options = ['-DCMAKE_TOOLCHAIN_FILE=' + str(root / 'soft-toolchain.cmake'),
               '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_INSTALL_PREFIX=/usr',
               '-DCMAKE_INSTALL_LIBDIR=lib', '-DCMAKE_SKIP_RPATH=ON',
               '-DCMAKE_POLICY_VERSION_MINIMUM=3.5',
               '-DCMAKE_POSITION_INDEPENDENT_CODE=ON']
    removed_generated = []
    if component == 'mbedtls':
        config = source / 'include/mbedtls/mbedtls_config.h'
        before = config.read_text()
        disabled = ('MBEDTLS_HAVE_ASM', 'MBEDTLS_AESCE_C', 'MBEDTLS_AESNI_C',
                    'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_IF_PRESENT',
                    'MBEDTLS_SHA256_USE_ARMV8_A_CRYPTO_ONLY',
                    'MBEDTLS_SHA512_USE_A64_CRYPTO_IF_PRESENT',
                    'MBEDTLS_SHA512_USE_A64_CRYPTO_ONLY')
        text = before
        for name in disabled:
            text = re.sub(r'^#define ' + name + r'(?=\s|$)', '// soft ABI: #undef ' + name,
                          text, flags=re.M)
        config.write_text(text)
        assert not re.search(r'^#define MBEDTLS_(?:HAVE_ASM|AESCE_C|AESNI_C)\b', text, re.M)
        options += ['-DUSE_SHARED_MBEDTLS_LIBRARY=ON', '-DUSE_STATIC_MBEDTLS_LIBRARY=OFF',
                    '-DENABLE_TESTING=OFF', '-DENABLE_PROGRAMS=OFF']
    else:
        # The OpenWrt cache was built with Autoconf. Its generated source-local
        # header shadows CMake's header even with an independent build directory.
        generated = source / 'lib/curl_config.h'
        if generated.exists():
            assert generated.resolve().is_relative_to(root.resolve())
            assert 'Generated from curl_config.h.in by configure' in generated.read_text()[:200]
            generated.unlink()
        removed_generated.append('lib/curl_config.h (cached Autoconf output)')
        options += ['-DBUILD_SHARED_LIBS=ON', '-DBUILD_STATIC_LIBS=OFF',
                    '-DBUILD_CURL_EXE=ON', '-DBUILD_TESTING=OFF',
                    '-DBUILD_LIBCURL_DOCS=OFF', '-DBUILD_MISC_DOCS=OFF',
                    '-DENABLE_CURL_MANUAL=OFF', '-DENABLE_IPV6=ON',
                    '-DENABLE_THREADED_RESOLVER=ON',
                    '-DCURL_ENABLE_SSL=ON', '-DCURL_USE_MBEDTLS=ON',
                    '-DCURL_USE_OPENSSL=OFF', '-DCURL_USE_LIBPSL=OFF',
                    '-DCURL_USE_LIBSSH2=OFF', '-DCURL_USE_LIBSSH=OFF',
                    '-DUSE_LIBIDN2=OFF', '-DCURL_USE_GSSAPI=OFF',
                    '-DCURL_ZLIB=OFF', '-DCURL_BROTLI=OFF', '-DCURL_ZSTD=OFF',
                    '-DUSE_NGHTTP2=OFF', '-DUSE_NGHTTP3=OFF',
                    '-DCURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt',
                    '-DCURL_CA_PATH=none', '-DCURL_WERROR=OFF']
        options += ['-DCURL_DISABLE_' + name + '=ON' for name in (
            'DICT', 'FILE', 'FTP', 'GOPHER', 'IMAP', 'LDAP', 'LDAPS', 'MQTT',
            'POP3', 'IPFS', 'RTSP', 'SMTP', 'WEBSOCKETS', 'TELNET', 'TFTP')]
    build = root / ('build-' + component)
    print('SOFT_NETWORK_BUILD', component, flush=True)
    with (logdir / (component + '.txt')).open('w') as log:
        build_command = ['cmake', '--build', str(build), '-j4']
        if relink and component == 'mbedtls':
            build_command.append('--clean-first')
        for command in (['cmake', '-S', str(source), '-B', str(build), *options],
                        build_command,
                        ['cmake', '--install', str(build)]):
            local = dict(env)
            if '--install' in command:
                local['DESTDIR'] = str(sysroot)
            result = subprocess.run(command, env=local, stdout=log, stderr=subprocess.STDOUT)
            if result.returncode:
                print((logdir / (component + '.txt')).read_text()[-6000:])
                raise SystemExit(result.returncode)
    receipts[component] = {'cached_source': version,
                           'source_cmakelists_sha256': hashlib.sha256((cached / 'CMakeLists.txt').read_bytes()).hexdigest(),
                           'removed_generated_inputs': removed_generated,
                           'options': options}

selected = {'curl': sysroot / 'usr/bin/curl', 'libc.so': sysroot / 'lib/libc.so'}
for pattern in ('libcurl.so*', 'libmbedtls.so*', 'libmbedcrypto.so*', 'libmbedx509.so*'):
    for path in sorted((sysroot / 'usr/lib').glob(pattern)):
        if path.is_file():
            selected[path.name] = path
manifest = {}
definitions, unresolved = set(), set()
out = root / 'audited'
out.mkdir(exist_ok=True)
for name, source in selected.items():
    data = source.read_bytes()
    assert data[:5] == b'\x7fELF\x02' and data[18:20] == b'\xb7\0', name
    dis = subprocess.check_output([prefix + 'objdump', '-d', str(source)], text=True)
    for line in dis.splitlines():
        if '\t' not in line:
            continue
        instruction = line.split('\t', 2)[-1]
        if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s', instruction):
            continue
        assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b', instruction), (name, instruction)
    dynamic = subprocess.check_output([prefix + 'readelf', '-d', str(source)], text=True)
    assert not re.search(r'\((?:RPATH|RUNPATH)\)', dynamic), name
    needed = re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)
    assert all(dep in selected for dep in needed), (name, needed)
    symbols = subprocess.check_output([prefix + 'readelf', '--dyn-syms', '--wide', str(source)], text=True)
    for line in symbols.splitlines():
        parts = line.split()
        if len(parts) < 8 or not re.fullmatch(r'\d+:', parts[0]):
            continue
        symbol = parts[7].split('@')[0]
        if parts[6] == 'UND' and parts[4] == 'GLOBAL':
            unresolved.add(symbol)
        elif parts[6] != 'UND' and parts[4] in ('GLOBAL', 'WEAK'):
            definitions.add(symbol)
    target = out / name
    shutil.copyfile(source, target)
    subprocess.run([prefix + 'strip', '--strip-debug', str(target)], check=True)
    target.chmod(0o755)
    manifest[name] = {'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
                      'bytes': target.stat().st_size, 'needed': needed,
                      'elf_class': 64, 'machine': 183, 'fp_simd_register_uses': 0}
assert not unresolved - definitions, ('Unresolved strong dynamic symbols', sorted(unresolved - definitions))

report = {'abi': 'AAPCS64-soft', 'root': str(root), 'components': receipts,
          'files': manifest, 'dependency_closure_audited': True,
          'strong_dynamic_symbols_closed': True,
          'unique_elf_images': len({item['sha256'] for item in manifest.values()}),
          'hardware_runtime_qualified': False, 'firmware_built': False,
          'standard_apk_package': False, 'replaces_installed_curl': False,
          'tls_backend': 'mbedtls', 'ca_bundle': '/etc/ssl/certs/ca-certificates.crt',
          'scope': 'HTTP/HTTPS, IPv6, threaded DNS; no optional compression/HTTP2 dependencies'}
(out / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
(logdir / 'build-result.json').write_text(json.dumps(report, indent=2) + '\n')
artifact = BASE / 'artifacts/a64-soft-network'
artifact.mkdir(exist_ok=True)
(artifact / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
with tarfile.open(artifact / 'network.tar', 'w') as archive:
    for name in manifest:
        data = (out / name).read_bytes()
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o755
        info.mtime = int(EPOCH)
        archive.addfile(info, io.BytesIO(data))
print('AAPCS64_SOFT_NETWORK_CLOSURE_AUDITED', len(manifest), flush=True)
