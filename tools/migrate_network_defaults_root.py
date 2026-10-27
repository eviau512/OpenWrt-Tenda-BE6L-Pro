# SPDX-License-Identifier: MIT
"""Remove only reviewed unowned policy files from an offline mixed root.

APK protects an unowned /etc file by installing the new payload as .apk-new.
This narrow migration runs before the normal package transaction. It never
edits package records or forces replacement of owned or modified files.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

APPROVED = {
    'etc/uci-defaults/99-be6l-ram-ui': {
        '0fc2b032618ac675bce0ae88fc56904e3e6a6c1e62cbe046923989389a254dd1',
        '95e5c8e8b7de593c1a12096ea7b4dbfb9cb9912252536b64a2f66ab72389d885'},
    'usr/libexec/platform/packet-steering.sh': {
        '56caccba500ac9f67a16b30fa18759223b68c84eaef83604b93b484bf55a3059'},
}


def migrate(root, apk):
    root, apk = Path(root).resolve(), Path(apk).resolve()
    assert root.is_absolute() and root != Path('/') and root.is_dir()
    assert (root / 'etc/apk/arch').read_text().splitlines() == [
        'arm_cortex-a7', 'aarch64_be6l_soft_experimental']
    command = [str(apk), '--root', str(root), '--network=no', '--cache=no',
               'info', '--who-owns']
    pid1 = subprocess.run(command + ['/sbin/init'], capture_output=True, text=True)
    assert pid1.returncode == 0 and 'procd-' in pid1.stdout, 'Offline package database/PID1 ownership must be valid'
    remove, retained = [], []
    for name, hashes in APPROVED.items():
        file = root / name
        if not file.exists() and not file.is_symlink():
            continue
        assert file.is_file() and not file.is_symlink() and file.resolve().is_relative_to(root), name
        owner = subprocess.run(command + ['/' + name], capture_output=True, text=True)
        if owner.returncode == 0:
            assert 'be6l-network-defaults-' in owner.stdout, 'Policy path has another package owner: ' + name
            retained.append(name)
            continue
        expected_error = 'ERROR: /' + name + ': Could not find owner package'
        assert owner.returncode == 1 and not owner.stdout and owner.stderr.strip() == expected_error, 'Unexpected ownership-query failure: ' + name
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        assert digest in hashes, 'Refuse modified unowned policy file: ' + name
        remove.append(dict(path=name, before_sha256=digest))
    for item in remove:
        (root / item['path']).unlink()
    return dict(removed_reviewed_unowned_files=remove,
                retained_owned_files=retained, package_database_edited=False,
                force_overwrite_used=False, offline_only=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    report = migrate(args.root, args.apk)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
