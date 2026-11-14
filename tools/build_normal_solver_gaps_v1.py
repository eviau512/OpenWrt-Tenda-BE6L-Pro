# SPDX-License-Identifier: MIT
"""Build actual APK3-reported ordinary-package gaps in the isolated A53 SDK."""
from pathlib import Path
import argparse
import json
import os
import re
import subprocess
import time
from build_normal_a53_missing_modules_v1 import sha


def package_catalog(text):
    source, current, result = None, None, []
    for line in text.splitlines()+['Package: __END__']:
        if line.startswith('Source-Makefile: '):
            source = line.split(': ', 1)[1]
        if line.startswith('Package: '):
            if current:
                result.append(current)
            current = dict(name=line.split(': ', 1)[1], source=source)
        elif current and ': ' in line:
            key, value = line.split(': ', 1)
            if key in ('ABI-Version', 'Version', 'Depends'):
                current[key] = value
    return result


def abi_name(row):
    suffix = row.get('ABI-Version', '')
    return row['name']+(('-' if row['name'][-1:].isdigit() else '')+suffix if suffix else '')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'source-sdk', 'host-prefix', 'host-build', 'solver-work', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    sdk, w = a.sdk.resolve(), a.work.resolve()
    if (sdk.parent != Path('/root') or not sdk.name.startswith('be6l-normal-a53-sdk-') or
            w.parent != Path('/root') or not w.name.startswith('be6l-normal-solver-build-') or w.exists()):
        p.error('Use the isolated SDK and fresh /root/be6l-normal-solver-build-* work')
    prior = json.loads((a.host_build/'result.json').read_text())
    if not prior.get('all_requested_recipes_built') or not prior['terminal']:
        raise ValueError('Require the completed isolated host/tool configuration')
    probe = json.loads((a.solver_work/'result.json').read_text())
    wanted = re.findall(r'^  ([^ ]+) \(no such package\):', probe['solver_diagnostics'], re.M)
    if not wanted or not probe['simulator_root_unchanged']:
        raise ValueError('Require actual unresolved APK3 ordinary package diagnostics')
    index = a.source_sdk/'tmp/.packageinfo'
    catalog = package_catalog(index.read_text())
    selected = {}
    for name in wanted:
        found = [row for row in catalog if name in (row['name'], abi_name(row))]
        if len(found) != 1:
            raise ValueError('Missing/ambiguous actual source recipe: '+name)
        selected[name] = found[0]
    w.mkdir(mode=0o700)
    # Register existing local recipes, including host dependencies. No feeds
    # update/checkout/download and no external source mutation takes place here.
    for relative in sorted({row['source'] for row in catalog if row['source']}):
        source, target = a.source_sdk/relative, sdk/relative
        if not source.is_file():
            raise ValueError('Pinned current package recipe is absent: '+relative)
        if target.exists():
            continue
        if target.parent.is_symlink():
            raise ValueError('Refusing to write through an existing broken package link')
        target.parent.parent.mkdir(parents=True, exist_ok=True)
        target.parent.symlink_to(source.parent.resolve(), target_is_directory=True)
    original = (sdk/'.config').read_text()
    source_config = (a.source_sdk/'.config').read_text()
    source_values = {}
    for line in source_config.splitlines():
        match = re.match(r'^(CONFIG_[A-Za-z0-9_+.-]+)=|^# (CONFIG_[A-Za-z0-9_+.-]+) is not set$', line)
        if match:
            source_values[match.group(1) or match.group(2)] = line
    projects = {row['source'][:-len('/Makefile')] for row in selected.values()}
    changes = {}
    for row in catalog:
        if row['source'][:-len('/Makefile')] in projects:
            symbol = 'CONFIG_PACKAGE_'+row['name']
            if symbol in source_values:
                changes[symbol] = source_values[symbol]
    for symbol, line in source_values.items():
        if symbol.startswith(('CONFIG_PACKAGE_luci-app-passwall_', 'CONFIG_LUCI_LANG_')):
            changes[symbol] = line
    for row in selected.values():
        symbol = 'CONFIG_PACKAGE_'+row['name']
        changes[symbol] = symbol+'=m'
    text = original
    for symbol, replacement in changes.items():
        text, count = re.subn(r'^(?:'+re.escape(symbol)+r'=.*|# '+re.escape(symbol)+r' is not set)$',
                             replacement, text, flags=re.M)
        if not count:
            text += '\n'+replacement+'\n'
    (w/'before.config').write_text(original)
    (sdk/'.config').write_text(text)
    env = dict(os.environ, PATH=':'.join(map(str, [a.host_build/'host-bin', sdk/'staging_dir/host/bin',
        sdk/'staging_dir/hostpkg/bin', a.host_prefix/'usr/bin', Path('/usr/bin'), Path('/bin')])),
        LD_LIBRARY_PATH=str(a.host_prefix/'usr/lib/x86_64-linux-gnu'),
        BISON_PKGDATADIR=str(a.host_prefix/'usr/share/bison'), M4=str(a.host_prefix/'usr/bin/m4'),
        SOURCE_DATE_EPOCH='1792420077')
    for name in ('GZIP', 'XZ_DEFAULTS', 'XZ_OPT', 'PKG_CONFIG_SYSROOT_DIR', 'PKG_CONFIG_LIBDIR'):
        env.pop(name, None)
    make = [str(a.host_prefix/'usr/bin/make'), '-C', str(sdk), '-j4', 'V=s']
    state = dict(actual_solver_receipt_sha256=sha(a.solver_work/'result.json'),
        actual_source_index_sha256=sha(index), selected=selected, completed=[], terminal=False,
        active=None, ordinary_a53_profile=True, original_source_mutated=False,
        target_executed=False, normal_mainroot_composed=False)

    def save():
        (w/'result.json').write_text(json.dumps(state, indent=2)+'\n')

    def run(label, command):
        state['active'] = label; save(); print('START', label, flush=True)
        start = time.monotonic()
        with (w/(label+'.log')).open('wb') as output:
            r = subprocess.run(command, env=env, stdout=output, stderr=subprocess.STDOUT, timeout=1800)
        if r.returncode:
            raise RuntimeError(label+' failed; inspect retained log')
        state['completed'].append(dict(step=label, elapsed_seconds=time.monotonic()-start))
        save(); print('PASS', label, flush=True)

    try:
        run('defconfig', make+['defconfig'])
        actual = (sdk/'.config').read_text().splitlines()
        for required in ('CONFIG_ARCH="aarch64"', 'CONFIG_TARGET_ARCH_PACKAGES="aarch64_cortex-a53"',
                         'CONFIG_TARGET_OPTIMIZATION="-Os -pipe -mcpu=cortex-a53"'):
            if required not in actual:
                raise ValueError('Ordinary A53 architecture/compiler profile drift')
        for row in selected.values():
            if not any('CONFIG_PACKAGE_'+row['name']+'='+value in actual for value in ('m','y')):
                raise ValueError('Required selected package lost during defconfig: '+row['name'])
        if any('CONFIG_PACKAGE_'+name+'='+value in actual for name in ('xray-core','luci-app-opennds','nodogsplash') for value in ('m','y')):
            raise ValueError('Unrequested Xray/captive portal selection')
        state['sdk_configuration_sha256'] = sha(sdk/'.config')
        state['source_recipe_sha256'] = {project: sha(sdk/project/'Makefile') for project in projects}
        def order(project):
            if project.endswith('/toolchain'): return (0, project)
            if project.startswith('package/libs/') or project.endswith(('/acl','/attr')): return (1,project)
            if project.endswith(('/sing-box','/tailscale','/bridger')): return (3,project)
            return (2,project)
        for i, project in enumerate(sorted(projects, key=order)):
            run('compile-'+str(i+1)+'-'+project.split('/')[-1], make+[project+'/compile'])
        state['all_reported_recipe_projects_built'] = True
    except Exception as error:
        state['error'] = type(error).__name__+': '+str(error)
        raise
    finally:
        state.update(active=None, terminal=True); save()


if __name__ == '__main__':
    main()
