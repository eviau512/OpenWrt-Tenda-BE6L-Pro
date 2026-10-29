# SPDX-License-Identifier: MIT
"""Create private original/corrected child-VM probes; no device operations."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile

from a64_soft_context import SDK
from native_services_admission_v1 import admit, admit_installed

CPATH = '/opt/be6l-a64-soft/lib/lua/?.so;/opt/be6l-a64-soft/lib/lua/?/init.so'
LEGACY_CPATH = './?.so;/usr/lib/lua/?.so;/usr/lib/lua/loadall.so'
TEXT_PATH = './?.lua;/usr/share/lua/?.lua;/usr/share/lua/?/init.lua;/usr/lib/lua/?.lua;/usr/lib/lua/?/init.lua'
BUNDLE = Path('/root/be6l-openwrt/native-services-apk-v1-20261029-r1')
PROFILE_SHA256 = 'c8b1a5461d60b0e09976286ce1e6efbf36dc2f32f01783425e1edd4a5a2c34f3'
FIXTURE_SHA256 = 'bf417139b386a052117b4eb32888e4cb3be8ee2582cc93dbc4bbc54768b2357d'
RUNNER_SHA256 = '52a4a6a103dfe72bedfed73368ca0502310ebe00b5276f6e84cdb0ab801a66e4'
BRIDGE_PATH = 'opt/be6l-a64-soft/lib/ucode/lua.so'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def dynamic_symbols(prefix, path):
    output = subprocess.check_output([prefix + 'readelf', '--dyn-syms', '--wide', str(path)], text=True)
    exports, undefined = set(), set()
    for line in output.splitlines():
        match = re.match(r'\s*\d+:\s+\S+\s+\d+\s+\S+\s+(GLOBAL|WEAK)\s+\S+\s+(\S+)\s+(\S+)', line)
        if not match:
            continue
        binding, section, name = match.groups()
        name = name.split('@')[0]
        if section != 'UND':
            exports.add(name)
        elif binding == 'GLOBAL':
            undefined.add(name)
    return exports, undefined


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bridge-work', type=Path, required=True)
    parser.add_argument('--trusted-receipt-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    work = args.bridge_work.resolve()
    output = args.output.resolve()
    assert output.parent == work and output.name == 'child-path-fixtures-v1'
    assert not output.exists()
    receipt_file = work / 'build-receipt.json'
    assert sha(receipt_file) == args.trusted_receipt_sha256
    receipt = json.loads(receipt_file.read_text())
    assert receipt['kind'] == 'native-lua-child-private-paths-v1'
    assert not receipt['installed'] and not receipt['target_executed']
    bridge = work / 'lua.so'
    assert sha(bridge) == receipt['output_sha256'] and receipt['child_cpath'] == CPATH
    result = json.loads((BUNDLE / 'result.json').read_text())
    assert result['passed'] and result['profile_lock_sha256'] == PROFILE_SHA256
    profile = admit(Path(result['profile_root']), PROFILE_SHA256)
    root = Path(result['root'])
    admit_installed(root, profile)
    original = BUNDLE / 'isolated-fixture'
    proof = json.loads((original / 'namespace-fixture.json').read_text())
    assert sha(original / 'namespace-fixture.tar') == FIXTURE_SHA256 == proof['namespace-fixture.tar']
    assert sha(original / 'namespace-runner') == RUNNER_SHA256 == proof['namespace-runner']
    assert proof['profile_lock_sha256'] == PROFILE_SHA256 and proof['native_paths'] == 90
    gcc, = SDK.glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
    prefix = str(gcc)[:-3]
    scope = profile['files'][BRIDGE_PATH]['symbol_scope']
    assert 'opt/be6l-a64-soft/bin/ucode' in scope
    exports = set()
    for name in scope:
        if name != BRIDGE_PATH:
            exports |= dynamic_symbols(prefix, root / name)[0]
    own_exports, undefined = dynamic_symbols(prefix, bridge)
    assert not undefined - (exports | own_exports), sorted(undefined - (exports | own_exports))
    output.mkdir()
    # Do not extract this credential-bearing fixture to a shared/public tree.
    members = []
    data = {}
    with tarfile.open(original / 'namespace-fixture.tar') as archive:
        for member in archive:
            assert not member.name.startswith('/') and '..' not in Path(member.name).parts
            assert member.name not in data
            if member.issym():
                assert not member.linkname.startswith('/') and '..' not in Path(member.linkname).parts
            assert member.isfile() or member.isdir() or member.issym()
            members.append(member)
            if member.isfile():
                data[member.name] = archive.extractfile(member).read()
    for name, item in profile['files'].items():
        assert hashlib.sha256(data[name]).hexdigest() == item['sha256'], name
    legacy = data['lib/aarch64-soft/liblua.so.5.1.5']
    assert LEGACY_CPATH.encode() + b'\0' in legacy
    assert TEXT_PATH.encode() + b'\0' in legacy
    handler = data['handler.uc']
    anchor = b'global.handle_request = function(env) {\n'
    assert handler.count(anchor) == 1
    variants = {}
    for kind in ('original', 'corrected'):
        folder = output / kind
        folder.mkdir()
        if kind == 'original':
            body = (' let child = require("lua").create();\n'
                ' assert(child.eval("return package.cpath") == ' + json.dumps(LEGACY_CPATH) + ');\n'
                ' assert(child.eval("return package.path") == ' + json.dumps(TEXT_PATH) + ');\n'
                ' assert(child.eval(\'return (pcall(require, "nixio"))\') == false);\n')
        else:
            body = (' let child = require("lua").create();\n'
                ' assert(child.eval("return package.cpath") == ' + json.dumps(CPATH) + ');\n'
                ' assert(child.eval("return package.path") == ' + json.dumps(TEXT_PATH) + ');\n'
                ' assert(child.eval(\'for _, name in ipairs({"iwinfo", "lucihttp", "luci.ip", "luci.jsonc", "luci.template.parser", "yaml", "nixio", "uci", "ubus", "uloop"}) do assert(require(name)) end; return true\') == true);\n')
        changed = dict(data)
        changed['handler.uc'] = handler.replace(anchor, anchor + body.encode())
        if kind == 'corrected':
            changed[BRIDGE_PATH] = bridge.read_bytes()
        archive_file = folder / 'namespace-fixture.tar'
        with tarfile.open(archive_file, 'w') as archive:
            for member in members:
                if member.isfile():
                    member.size = len(changed[member.name])
                    archive.addfile(member, io.BytesIO(changed[member.name]))
                else:
                    archive.addfile(member)
        shutil.copyfile(original / 'namespace-runner', folder / 'namespace-runner')
        case = dict(proof)
        case.update(schema=2, kind='native-lua-child-path-probe-v1', variant=kind,
            **{'namespace-fixture.tar':sha(archive_file)},
            original_fixture_sha256=FIXTURE_SHA256,
            exact_package_root_elf_paths=(90 if kind == 'original' else 89),
            all_native_paths_from_actual_package_root=(kind == 'original'),
            diagnostic_changed_elf_paths=([] if kind == 'original' else [BRIDGE_PATH]),
            child_cpath_expected=(LEGACY_CPATH if kind == 'original' else CPATH),
            child_text_path_expected=TEXT_PATH,
            child_missing_c_module_rejected=(kind == 'original'),
            child_native_module_imports_expected=(0 if kind == 'original' else 10),
            no_lua_cpath_environment_override=True, target_fixture_executed=False,
            diagnostic_bridge_sha256=(None if kind == 'original' else receipt['output_sha256']),
            diagnostic_bridge_receipt_sha256=args.trusted_receipt_sha256,
            package_profile_admitted=(kind == 'original'),
            source_fixture_remains_unchanged=True, defaults_promoted=False,
            new_native_image_admitted=False)
        (folder / 'namespace-fixture.json').write_text(json.dumps(case, sort_keys=True, indent=2) + '\n')
        variants[kind] = dict(path=str(folder), fixture_sha256=sha(archive_file),
            proof_sha256=sha(folder / 'namespace-fixture.json'))
    assert sha(original / 'namespace-fixture.tar') == FIXTURE_SHA256
    report = dict(schema=1, kind='native-lua-child-private-fixtures-v1', variants=variants,
        original_fixture_sha256=FIXTURE_SHA256, runner_sha256=RUNNER_SHA256,
        corrected_bridge_sha256=receipt['output_sha256'],
        exact_host_scoped_strong_symbols_closed=True,
        original_90_package_root_elf_paths_preserved=True,
        target_executed=False, sdk_or_root_modified=False,
        corrected_fixture_is_diagnostic_not_signed_package=True,
        default_services_promoted=False, preparer_sha256=sha(Path(__file__)))
    (output / 'preparation-receipt.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
