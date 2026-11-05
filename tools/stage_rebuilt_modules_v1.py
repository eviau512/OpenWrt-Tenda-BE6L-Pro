# SPDX-License-Identifier: MIT
"""Stage all freshly built kernel/external modules for an independent layout audit."""
from pathlib import Path
import argparse
import json
import shutil
from package_native_netifd_v3 import sha


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('kernel-build', 'external-build', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-module-stage-') or w.exists():
        p.error('Use a fresh /root/be6l-module-stage-*')
    built = json.loads((a.kernel_build/'result.json').read_text())
    external = json.loads((a.external_build/'result.json').read_text())
    if not built.get('integer_binfmt_builtin') or not external['all_external_modules_rebuilt']:
        raise ValueError('Complete new kernel/external build missing')
    if external['kernel_build_receipt_sha256'] != sha(a.kernel_build/'result.json'):
        raise ValueError('External modules belong to another kernel build')
    paths = {Path(name).name:(a.kernel_build/'build'/name, digest)
             for name,digest in built['in_tree_module_sha256'].items()}
    for name, item in external['modules'].items():
        if name in paths:
            raise ValueError('Duplicate rebuilt module name')
        paths[name] = (a.external_build/item['path'], item['sha256'])
    if len(paths) != 85:
        raise ValueError('Unexpected complete rebuilt module inventory')
    directory = w/'root/lib/modules/6.18.55'
    directory.mkdir(parents=True)
    output = {}
    for name,(source,digest) in sorted(paths.items()):
        if sha(source) != digest:
            raise ValueError('Compiled module changed: '+name)
        shutil.copyfile(source, directory/name)
        output[name] = digest
    (w/'result.json').write_text(json.dumps(dict(all_modules_freshly_built=True,
        module_count=85, module_sha256=output, previous_modules_reused=False,
        kernel_build_receipt_sha256=sha(a.kernel_build/'result.json'),
        external_build_receipt_sha256=sha(a.external_build/'result.json')), indent=2)+'\n')
    print('COMPLETE_FRESH_MODULE_AUDIT_STAGE', len(output), flush=True)


if __name__ == '__main__':
    main()
