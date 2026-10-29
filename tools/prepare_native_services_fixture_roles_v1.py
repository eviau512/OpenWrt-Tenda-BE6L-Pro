# SPDX-License-Identifier: MIT
"""Create role-audited private fixture archives; preserve all payload bytes."""
from pathlib import Path, PurePosixPath
import argparse
import copy
import hashlib
import io
import json
import shutil
import tarfile

ROOT_WORK = Path('/root/be6l-openwrt/native-lua-child-paths-v1-20261029-r1')
BUNDLE = Path('/root/be6l-openwrt/native-services-apk-v1-20261029-r1')
PROFILE_SHA256 = 'c8b1a5461d60b0e09976286ce1e6efbf36dc2f32f01783425e1edd4a5a2c34f3'
RUNNER_SHA256 = '52a4a6a103dfe72bedfed73368ca0502310ebe00b5276f6e84cdb0ab801a66e4'
SOURCE = Path('/root/be6l-openwrt/native-service-paths-v1-20261029-r2/source-uhttpd')
SOURCES = {
    'file.c':'5afd262a8d295b1fee82f4db56adbf0167249b5b6cc5931b9bd96f430c165424',
    'cgi.c':'8a7749004c2eba2f20916a3822c457349ea90dd69b6cb0a834222fcbab78fc37',
}
ROOT_PRIVATE = {
    'etc/config/fixture':'root-read synthetic UCI data',
    'etc/config/rpcd':'root-read synthetic authentication configuration',
    'etc/group':'root-read synthetic group database',
    'etc/ld-musl-aarch64-soft.path':'root-read native interpreter configuration',
    'etc/passwd':'root-read synthetic passwd database',
    'etc/test-cert.pem':'root-read synthetic TLS certificate',
    'etc/test-key.pem':'private synthetic TLS key',
    'etc/unrelated-ca.pem':'root-read negative TLS trust input',
    'handler.lua':'root-read Lua source, not CGI',
    'handler.uc':'root-read ucode source, not CGI',
    'tmp/login-request.json':'private synthetic login request',
    'tmp/wrong-login.json':'private synthetic negative login request',
    'usr/share/rpcd/acl.d/fixture.json':'root-read synthetic ACL',
    'dev/null':'private standard-device bind placeholder',
    'dev/random':'private standard-device bind placeholder',
    'dev/urandom':'private standard-device bind placeholder',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--trusted-proof-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = args.fixture_dir.resolve()
    output = args.output.resolve()
    assert original.parent == ROOT_WORK / 'mode-corrected-fixtures-v1'
    assert output.parent == ROOT_WORK / 'role-corrected-fixtures-v1'
    assert original.name == output.name and output.name in ('signed', 'original', 'corrected')
    assert not output.exists()
    for name, expected in SOURCES.items():
        assert sha(SOURCE / name) == expected
    assert 'if (!(pi->stat.st_mode & S_IROTH))' in (SOURCE / 'file.c').read_text()
    assert 'unsigned int mode = S_IFREG | S_IXOTH;' in (SOURCE / 'cgi.c').read_text()
    assert sha(original / 'namespace-fixture.json') == args.trusted_proof_sha256
    proof = json.loads((original / 'namespace-fixture.json').read_text())
    before_hash = sha(original / 'namespace-fixture.tar')
    assert before_hash == proof['namespace-fixture.tar']
    assert proof['fixture_mode_repair']['payload_file_bytes_and_symlinks_unchanged']
    assert sha(original / 'namespace-runner') == RUNNER_SHA256 == proof['namespace-runner']
    assert proof['profile_lock_sha256'] == PROFILE_SHA256
    result = json.loads((BUNDLE / 'result.json').read_text())
    profile_path = Path(result['profile_root']) / 'profile-lock.json'
    assert sha(profile_path) == PROFILE_SHA256
    profile = json.loads(profile_path.read_text())
    root = Path(result['root'])
    output.mkdir(parents=True)
    roles = {}
    changes = []
    payloads = {}
    new_payloads = {}
    public_modes = {}
    with tarfile.open(original / 'namespace-fixture.tar') as source, tarfile.open(output / 'namespace-fixture.tar', 'w') as archive:
        seen = set()
        for item in source:
            name = PurePosixPath(item.name)
            assert not name.is_absolute() and '..' not in name.parts and str(name) not in seen
            seen.add(str(name))
            assert item.isfile() or item.isdir() or item.issym()
            changed = copy.copy(item)
            if item.isfile():
                data = source.extractfile(item).read()
                payloads[item.name] = hashlib.sha256(data).hexdigest()
                if item.name in profile['files']:
                    expected_mode = profile['files'][item.name]['mode']
                    expected_sha = profile['files'][item.name]['sha256']
                    if proof.get('variant') == 'corrected' and item.name == 'opt/be6l-a64-soft/lib/ucode/lua.so':
                        expected_sha = proof['diagnostic_bridge_sha256']
                    assert payloads[item.name] == expected_sha
                    role = 'exact native-profile ELF' if expected_sha == profile['files'][item.name]['sha256'] else 'single diagnostic native ELF'
                elif item.name == 'bin/busybox' or item.name.startswith('lib/'):
                    package_file = root / item.name
                    assert package_file.is_file() and not package_file.is_symlink()
                    assert package_file.read_bytes() == data
                    expected_mode = package_file.stat().st_mode & 0o777
                    assert expected_mode in (0o644, 0o755)
                    if item.name in ('bin/busybox', 'lib/libc.so'):
                        assert expected_mode == 0o755
                    role = 'exact package-root ARM32 executable/interpreter/library'
                elif item.name == 'www/payload.bin':
                    expected_mode, role = 0o644, 'public static payload; uhttpd S_IROTH required'
                    public_modes[item.name] = expected_mode
                elif item.name == 'www/cgi-bin/probe':
                    expected_mode, role = 0o755, 'public CGI; uhttpd S_IXOTH required'
                    public_modes[item.name] = expected_mode
                elif item.name == 'probe.sh':
                    expected_mode, role = 0o755, 'private namespace entry script'
                else:
                    assert item.name in ROOT_PRIVATE, 'Unclassified file role: ' + item.name
                    expected_mode, role = 0o600, ROOT_PRIVATE[item.name]
                roles[item.name] = dict(role=role, mode=oct(expected_mode), sha256=payloads[item.name])
                if item.mode != expected_mode:
                    changes.append(dict(path=item.name, before=oct(item.mode), after=oct(expected_mode), role=role))
                    changed.mode = expected_mode
                archive.addfile(changed, io.BytesIO(data))
            elif item.isdir():
                assert item.mode == 0o755, 'Unexpected directory mode'
                archive.addfile(changed)
            else:
                assert not item.linkname.startswith('/') and '..' not in PurePosixPath(item.linkname).parts
                assert item.mode == 0o777
                archive.addfile(changed)
    assert changes == [dict(path='www/payload.bin', before='0o600', after='0o644',
        role='public static payload; uhttpd S_IROTH required')]
    assert public_modes == {'www/cgi-bin/probe':0o755, 'www/payload.bin':0o644}
    assert all(roles[name]['mode'] == '0o600' for name in ROOT_PRIVATE)
    with tarfile.open(output / 'namespace-fixture.tar') as archive:
        for item in archive:
            if item.isfile():
                new_payloads[item.name] = hashlib.sha256(archive.extractfile(item).read()).hexdigest()
    assert payloads == new_payloads
    shutil.copyfile(original / 'namespace-runner', output / 'namespace-runner')
    repaired = dict(proof)
    repaired.update(schema=4, **{'namespace-fixture.tar':sha(output / 'namespace-fixture.tar')},
        fixture_role_audit=dict(kind='complete-public-exec-private-role-modes-v1',
            original_fixture_sha256=before_hash, original_proof_sha256=args.trusted_proof_sha256,
            changes=changes, file_roles=roles, sources=SOURCES, runner_unchanged=True,
            all_payload_bytes_unchanged=True, private_material_mode_0600=True,
            public_static_read_others=True, public_cgi_exec_others=True,
            target_executed=False, preparer_sha256=sha(Path(__file__))))
    (output / 'namespace-fixture.json').write_text(json.dumps(repaired, sort_keys=True, indent=2) + '\n')
    assert sha(original / 'namespace-fixture.tar') == before_hash
    print(json.dumps(dict(output=str(output), fixture_sha256=sha(output / 'namespace-fixture.tar'),
        proof_sha256=sha(output / 'namespace-fixture.json'), changed_modes=len(changes),
        audited_regular_file_roles=len(roles), private_material_0600=True,
        bytes_changed=False, target_executed=False), indent=2))


if __name__ == '__main__':
    main()

