# SPDX-License-Identifier: MIT
"""Build one isolated Lua-child path correction; do not install or admit it."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import os
import re
import subprocess

from a64_soft_context import SDK, EPOCH

SOURCE_SHA256 = '5f7860ce545221858581e6c1795708e29aa4522d9152578351b2bcd2a9af1cfb'
CPATH = '/opt/be6l-a64-soft/lib/lua/?.so;/opt/be6l-a64-soft/lib/lua/?/init.so'
PRIOR = Path('/root/be6l-openwrt/a64-soft-ucode-modules-reproduction-long-v6')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    assert work.parent == Path('/root/be6l-openwrt')
    assert work.name.startswith('native-lua-child-paths-v1-') and not work.exists()
    source = PRIOR / 'source-lua-bridge/lua.c'
    assert sha(source) == SOURCE_SHA256
    flags = (PRIOR / 'cc').read_text()
    for flag in ('-march=armv8-a+nofp+nosimd', '-mabi=aapcs-soft', '-ffp-contract=off'):
        assert flag in flags
    original = source.read_text()
    old = '\tluaL_openlibs(L);\n\n\tluaL_newmetatable(L, "ucode.value");'
    new = '\n'.join((
        '\tluaL_openlibs(L);',
        '\tlua_getglobal(L, "package");',
        '\tlua_pushliteral(L, "' + CPATH + '");',
        '\tlua_setfield(L, -2, "cpath");',
        '\tlua_pop(L, 1);',
        '',
        '\tluaL_newmetatable(L, "ucode.value");'))
    assert original.count(old) == 1
    updated = original.replace(old, new)
    assert 'lua_setfield(L, -2, "path")' not in updated
    work.mkdir()
    patched = work / 'lua.c'
    patched.write_text(updated)
    patch = work / 'lua-child-paths.patch'
    patch.write_text(''.join(difflib.unified_diff(
        original.splitlines(True), updated.splitlines(True),
        fromfile='a/lua.c', tofile='b/lua.c')))
    export_map = PRIOR / 'ucode-module-exports.map'
    assert export_map.read_text() == '{ global: uc_module_entry; local: *; };\n'
    output = work / 'lua.so'
    command = [str(PRIOR / 'softcc'), '-O2', '-D_GNU_SOURCE', '-fPIC', '-shared',
        '-Wl,--version-script=' + str(export_map),
        '-I' + str(PRIOR / 'source-ucode-include'),
        '-I' + str(PRIOR / 'sysroot/usr/include'),
        '-I' + str(PRIOR / 'sysroot/usr/include/libnl-tiny'),
        '-L' + str(PRIOR / 'sysroot/usr/lib'), str(patched), '-llua', '-lucode',
        '-o', str(output)]
    env = dict(os.environ, SOURCE_DATE_EPOCH=EPOCH)
    built = subprocess.run(command, capture_output=True, text=True, env=env)
    (work / 'compile.log').write_text(built.stdout + built.stderr)
    assert built.returncode == 0, built.returncode
    gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
    prefix = str(gcc)[:-3]
    subprocess.run([prefix + 'strip', '--strip-debug', str(output)], check=True)
    dynamic = subprocess.check_output([prefix + 'readelf', '-dW', str(output)], text=True)
    program = subprocess.check_output([prefix + 'readelf', '-lW', str(output)], text=True)
    symbols = subprocess.check_output([prefix + 'readelf', '--dyn-syms', '--wide', str(output)], text=True)
    disassembly = subprocess.check_output([prefix + 'objdump', '-d', str(output)], text=True)
    header = subprocess.check_output([prefix + 'readelf', '-hW', str(output)], text=True)
    assert 'ELF64' in header and 'AArch64' in header
    assert not re.search(r'\((?:RPATH|RUNPATH)\)', dynamic)
    assert 'Requesting program interpreter:' not in program
    assert CPATH.encode() + b'\0' in output.read_bytes()
    for line in disassembly.splitlines():
        if '\t' not in line:
            continue
        instruction = line.split('\t', 2)[-1]
        if re.match(r'^(?:b(?:\.[a-z]+)?|bl|cbn?z|tbn?z)\s', instruction):
            continue
        assert not re.search(r'(?:^|[,\s\[])[vqdsbh](?:[0-9]|[12][0-9]|3[01])(?:[.,\s\]]|$)|\bfpcr\b|\bfpsr\b', instruction), instruction
    exports = set()
    undefined = set()
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].rstrip(':').isdigit():
            continue
        if fields[4] not in ('GLOBAL', 'WEAK'):
            continue
        if fields[6] != 'UND':
            exports.add(fields[7])
        elif fields[4] == 'GLOBAL':
            undefined.add(fields[7])
    assert exports == {'uc_module_entry'}, exports
    needed = re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)
    assert needed == ['liblua.so.5.1.5', 'libucode.so.0', 'libc.so'], needed
    proof = dict(schema=1, kind='native-lua-child-private-paths-v1',
        original_source_sha256=SOURCE_SHA256, patched_source_sha256=sha(patched),
        patch_sha256=sha(patch), output_sha256=sha(output), output_bytes=output.stat().st_size,
        output_path='opt/be6l-a64-soft/lib/ucode/lua.so', needed=needed,
        exported_symbols=sorted(exports), undefined_strong_symbols=sorted(undefined),
        softcc_sha256=sha(PRIOR / 'softcc'), compiler_wrapper_sha256=sha(PRIOR / 'cc'),
        export_map_sha256=sha(export_map), builder_sha256=sha(Path(__file__)),
        abi='AAPCS64-soft', fp_simd_register_uses=0, rpath_runpath=False,
        child_cpath=CPATH, text_package_path_unchanged=True,
        command=command, target_executed=False, installed=False,
        package_profile_admitted=False, default_services_promoted=False,
        pending=['Compare strong symbols against the exact existing runtime scope',
                 'Run an exact isolated fixture with a real child VM and no LUA_CPATH override',
                 'Create a new content-bound profile and normal signed package before promotion'])
    (work / 'build-receipt.json').write_text(json.dumps(proof, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(work=str(work), output_sha256=proof['output_sha256'],
        receipt_sha256=sha(work / 'build-receipt.json'), target_executed=False,
        installed=False), indent=2))


if __name__ == '__main__':
    main()
