# SPDX-License-Identifier: MIT
"""Measure sealed component roots with normal newc/gzip, without kernel changes.

Creates two new archive fixtures and checks their regular/symlink payloads.
This is a root-archive size comparison, not kernel/Image or loader admission.
"""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import os
import shutil
import stat
import subprocess
from cpio_selected_files import selected_files
from package_native_netifd_v3 import records, root_digest, sha

EPOCH = 1792420077


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--composition', type=Path, required=True)
    parser.add_argument('--base-root', type=Path, required=True)
    parser.add_argument('--cpio', type=Path, required=True)
    parser.add_argument('--gen-init-cpio', type=Path, required=True)
    parser.add_argument('--gzip', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-native-cpio-'):
        parser.error('Use a fresh /root/be6l-native-cpio-* directory')
    receipt = json.loads((args.composition / 'result.json').read_text())
    if not receipt['normal_signed_component_transaction'] or receipt['installed_packages'] != 218:
        raise ValueError('Wrong admitted component composition')
    candidate = args.composition / 'root'
    inputs = [('baseline', args.base_root, receipt['original_root_records_sha256']),
              ('native', candidate, receipt['installed_root_records_sha256'])]
    for label, root, pin in inputs:
        if root_digest(root) != pin:
            raise ValueError('Root no longer matches the component receipt: ' + label)
    work.mkdir()
    nodes = work / 'device-nodes.list'
    nodes.write_text('nod /dev/console 0600 0 0 c 5 1\nnod /dev/null 0666 0 0 c 1 3\n')
    results = {}
    for label, original, pin in inputs:
        root = work / (label + '-root')
        shutil.copytree(original, root, symlinks=True)
        if root_digest(root) != pin:
            raise ValueError('Root copy changed payloads or modes')
        expected = records(root)
        for path in [root, *root.rglob('*')]:
            mode = path.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
                raise ValueError('Unexpected root special node: ' + str(path))
            os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)
        paths = ['.'] + sorted(p.relative_to(root).as_posix() for p in root.rglob('*'))
        archive = work / (label + '.cpio')
        with archive.open('wb') as output:
            cp = subprocess.run([str(args.cpio), '--null', '--reproducible', '-o', '-H', 'newc', '-R', '0:0'],
                                cwd=root, input=('\0'.join(paths) + '\0').encode(), stdout=output,
                                stderr=subprocess.PIPE, check=True)
        (work / (label + '-cpio.log')).write_bytes(cp.stderr)
        with archive.open('ab') as output:
            subprocess.run([str(args.gen_init_cpio), '-t', str(EPOCH), str(nodes)], stdout=output, check=True)
        data = archive.read_bytes()
        actual = selected_files(data, set(expected))
        for name, item in expected.items():
            found = actual[name]
            if 'symlink' in item:
                if not stat.S_ISLNK(found['mode']) or found['data'].decode() != item['symlink']:
                    raise ValueError('Archive symlink mismatch: ' + name)
            elif not stat.S_ISREG(found['mode']) or found['mode'] & 0o7777 != item['mode'] or hashlib.sha256(found['data']).hexdigest() != item['sha256']:
                raise ValueError('Archive file bytes/mode mismatch: ' + name)
        packed = work / (label + '.cpio.gz')
        with packed.open('wb') as output:
            subprocess.run([str(args.gzip), '-n', '-9', '-c', str(archive)], stdout=output, check=True)
        if gzip.decompress(packed.read_bytes()) != data:
            raise ValueError('Compressed archive roundtrip failed')
        if root_digest(original) != pin:
            raise ValueError('Original input changed during archive creation')
        results[label] = dict(root_records_sha256=pin, cpio_bytes=len(data),
            cpio_sha256=sha(archive), gzip_bytes=packed.stat().st_size,
            gzip_sha256=sha(packed), regular_symlink_paths_verified=len(expected))
    report = dict(roots=results, gzip_growth_bytes=results['native']['gzip_bytes'] - results['baseline']['gzip_bytes'],
        composition_receipt_sha256=sha(args.composition / 'result.json'),
        host_tools_sha256={name: sha(path) for name, path in [('cpio', args.cpio),
            ('gen_init_cpio', args.gen_init_cpio), ('gzip', args.gzip)]},
        original_roots_unchanged=True, sdk_modified=False, image_built=False,
        image_bound_qualified=False, target_executed=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
