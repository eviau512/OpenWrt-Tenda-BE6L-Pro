# SPDX-License-Identifier: MIT
"""Repair only package-root file modes in NEW private namespace fixtures."""
from pathlib import Path, PurePosixPath
import argparse
import copy
import hashlib
import io
import json
import shutil
import struct
import tarfile

BUNDLE = Path('/root/be6l-openwrt/native-services-apk-v1-20261029-r1')
RUNNER_SHA256 = '52a4a6a103dfe72bedfed73368ca0502310ebe00b5276f6e84cdb0ab801a66e4'
PROFILE_SHA256 = 'c8b1a5461d60b0e09976286ce1e6efbf36dc2f32f01783425e1edd4a5a2c34f3'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def elf32_interpreter(data):
    assert data[:6] == b'\x7fELF\x01\x01'
    assert struct.unpack_from('<H', data, 18)[0] == 40
    offset = struct.unpack_from('<I', data, 28)[0]
    size, count = struct.unpack_from('<HH', data, 42)
    found = []
    for index in range(count):
        kind, begin, _, _, length = struct.unpack_from('<IIIII', data, offset + index * size)
        if kind == 3:
            found.append(data[begin:begin+length].rstrip(b'\0').decode())
    assert len(found) == 1
    return found[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--trusted-proof-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = args.fixture_dir.resolve()
    output = args.output.resolve()
    assert str(output).startswith('/root/be6l-openwrt/native-lua-child-paths-v1-20261029-r1/mode-corrected-fixtures-v1/')
    assert output.name in ('signed', 'original', 'corrected') and not output.exists()
    assert sha(original / 'namespace-fixture.json') == args.trusted_proof_sha256
    proof = json.loads((original / 'namespace-fixture.json').read_text())
    original_hash = sha(original / 'namespace-fixture.tar')
    assert original_hash == proof['namespace-fixture.tar']
    assert sha(original / 'namespace-runner') == RUNNER_SHA256 == proof['namespace-runner']
    assert proof['profile_lock_sha256'] == PROFILE_SHA256
    result = json.loads((BUNDLE / 'result.json').read_text())
    assert result['passed'] and result['profile_lock_sha256'] == PROFILE_SHA256
    root = Path(result['root'])
    output.mkdir(parents=True)
    changes = []
    regular = {}
    links = {}
    before_entries = []
    after_entries = []
    target = output / 'namespace-fixture.tar'
    with tarfile.open(original / 'namespace-fixture.tar') as source, tarfile.open(target, 'w') as archive:
        names = set()
        for item in source:
            name = PurePosixPath(item.name)
            assert not name.is_absolute() and '..' not in name.parts and str(name) not in names
            names.add(str(name))
            assert item.isfile() or item.isdir() or item.issym()
            changed = copy.copy(item)
            data = source.extractfile(item).read() if item.isfile() else None
            if item.isfile():
                regular[item.name] = (item.mode, data)
                path = root / item.name
                if item.name.startswith(('bin/', 'lib/')) and path.is_file() and not path.is_symlink():
                    assert path.read_bytes() == data, 'Source package root bytes differ: ' + item.name
                    expected_mode = path.stat().st_mode & 0o777
                    if item.mode != expected_mode:
                        changes.append(dict(path=item.name, old_mode=oct(item.mode),
                            package_root_mode=oct(expected_mode), sha256=hashlib.sha256(data).hexdigest()))
                        changed.mode = expected_mode
                before_entries.append((item.name, hashlib.sha256(data).hexdigest()))
                after_entries.append((changed.name, hashlib.sha256(data).hexdigest()))
                archive.addfile(changed, io.BytesIO(data))
            else:
                if item.issym():
                    assert not item.linkname.startswith('/') and '..' not in PurePosixPath(item.linkname).parts
                    links[item.name] = item.linkname
                archive.addfile(changed)
    assert before_entries == after_entries
    interpreter = elf32_interpreter(regular['bin/busybox'][1])
    assert interpreter == '/lib/ld-musl-arm.so.1' and links['lib/ld-musl-arm.so.1'] == 'libc.so'
    assert regular['lib/libc.so'][0] == 0o600
    assert (root / 'lib/libc.so').stat().st_mode & 0o777 == 0o755
    assert any(item['path'] == 'lib/libc.so' and item['package_root_mode'] == '0o755' for item in changes)
    assert len(changes) == 12
    with tarfile.open(target) as archive:
        assert archive.getmember('lib/libc.so').mode == 0o755
        assert archive.getmember('bin/busybox').mode == 0o755
    shutil.copyfile(original / 'namespace-runner', output / 'namespace-runner')
    repaired = dict(proof)
    repaired.update(schema=3, **{'namespace-fixture.tar':sha(target)}, fixture_mode_repair=dict(
        kind='restore-exact-package-root-ARM32-library-modes-v1',
        original_fixture_sha256=original_hash, original_proof_sha256=args.trusted_proof_sha256,
        original_fixture_dir=str(original), changes=changes,
        payload_file_bytes_and_symlinks_unchanged=True,
        busybox_pt_interp=interpreter, interpreter_link='libc.so',
        source_package_root_libc_mode='0o755', old_fixture_libc_mode='0o600',
        runner_unchanged=True, target_executed=False, preparer_sha256=sha(Path(__file__))))
    (output / 'namespace-fixture.json').write_text(json.dumps(repaired, sort_keys=True, indent=2) + '\n')
    assert sha(original / 'namespace-fixture.tar') == original_hash
    print(json.dumps(dict(output=str(output), fixture_sha256=sha(target),
        proof_sha256=sha(output / 'namespace-fixture.json'), changed_modes=len(changes),
        bytes_or_symbols_changed=False, source_archive_preserved=True, target_executed=False), indent=2))


if __name__ == '__main__':
    main()

