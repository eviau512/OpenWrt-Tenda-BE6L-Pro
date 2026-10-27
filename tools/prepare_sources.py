"""Prepare only the pinned sparse repositories listed in sources.json."""
from pathlib import Path
import argparse
import json
import shutil
import subprocess

BASE = Path(__file__).resolve().parents[1]
WORK = Path('/root/be6l-openwrt')
parser = argparse.ArgumentParser()
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument('--apply', action='store_true')
mode.add_argument('--check', action='store_true')
args = parser.parse_args()
manifest = json.loads((BASE / 'sources.json').read_text())

def run(argv, cwd=None, **kwargs):
    return subprocess.run(argv, cwd=cwd, check=True, **kwargs)

def capture(argv, cwd):
    return subprocess.check_output(argv, cwd=cwd, text=True).strip()

for relative, item in manifest['checkouts'].items():
    root = WORK / relative
    if not root.exists():
        assert args.apply, 'Missing sparse checkout: ' + relative
        root.mkdir(parents=True)
        run(['git', 'init', '-q'], root)
        run(['git', 'remote', 'add', 'origin', item['url']], root)
        run(['git', 'config', 'remote.origin.promisor', 'true'], root)
        run(['git', 'config', 'remote.origin.partialclonefilter', 'blob:none'], root)
        run(['git', 'fetch', '--depth=1', '--filter=blob:none', 'origin', item['commit']], root)
        run(['git', 'sparse-checkout', 'init', '--cone'], root)
        run(['git', 'sparse-checkout', 'set', *item['sparse_paths']], root)
        run(['git', 'checkout', '--detach', item['commit']], root)
    assert capture(['git', 'rev-parse', 'HEAD'], root) == item['commit'], relative
    assert capture(['git', 'remote', 'get-url', 'origin'], root).removesuffix('.git') == item['url'].removesuffix('.git'), relative
    if 'patch' in item:
        patch = (BASE / item['patch']).read_bytes()
        reverse = subprocess.run(['git', 'apply', '--unidiff-zero', '--reverse', '--check', '-'], cwd=root,
                                 input=patch, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if reverse.returncode:
            assert args.apply, 'Source delta does not match exported patch: ' + relative
            run(['git', 'apply', '--unidiff-zero', '--check', '-'], root, input=patch)
            run(['git', 'apply', '--unidiff-zero', '-'], root, input=patch)
        if args.apply:
            shutil.copyfile(BASE / item['config'], root / '.config')

if args.apply:
    for source_name in ('source', 'arm64-source'):
        src = WORK / source_name
        feeds = {'packages': WORK / 'source/feeds/packages',
                 'luci': WORK / 'source/feeds/luci', 'argon': WORK / 'argon-feed',
                 'passwall': WORK / 'passwall', 'passwall_packages': WORK / 'passwall_packages'}
        (src / 'feeds').mkdir(exist_ok=True)
        for name, target in feeds.items():
            link = src / 'feeds' / name
            if not link.exists():
                link.symlink_to(target, target_is_directory=True)
            assert link.resolve() == target.resolve(), str(link)
        (src / 'feeds.conf').write_text(''.join(f'src-link {k} {v}\n' for k, v in feeds.items()))
        for item in manifest['feed_links']:
            link = src / item['link']; target = WORK / item['target']
            assert target.is_dir(), str(target)
            link.parent.mkdir(parents=True, exist_ok=True)
            if not link.exists():
                link.symlink_to(target, target_is_directory=True)
            assert link.resolve() == target.resolve(), str(link)
    host = WORK / 'host/bin'; host.mkdir(parents=True, exist_ok=True)
    for name in ('bash', 'tar'):
        link = host / name
        if not link.exists():
            executable = shutil.which(name)
            assert executable, name
            link.symlink_to(executable)
    for name in ('logs/proxy-build-1213', 'logs/arm64-compat-build',
                 'logs/p5-hybrid-kernel-apks', 'artifacts/arm64-compat'):
        (BASE / name).mkdir(parents=True, exist_ok=True)
print('PINNED_SPARSE_INPUTS_CHECKED' if args.check else 'PINNED_SPARSE_BUILD_INPUTS_PREPARED')
