"""Provision UI defaults and remove the no-longer-requested portal payload."""
from pathlib import Path
import argparse
import hashlib
import shutil

base = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, default=Path('/root/be6l-openwrt/source'))
args = parser.parse_args()
src = args.source.resolve()
files = src / 'files'
# These reviewed scripts now belong to a normal APK. Only remove old managed
# TOPDIR/files duplicates if they exactly match a reviewed current/history hash.
managed = {
    'etc/uci-defaults/99-be6l-ram-ui': ('99-be6l-ram-ui', {
        '0fc2b032618ac675bce0ae88fc56904e3e6a6c1e62cbe046923989389a254dd1'}),
    'usr/libexec/platform/packet-steering.sh': ('packet-steering.sh', set()),
}
package_files = base / 'overlay/package/network/config/be6l-network-defaults/files'
remove = []
for relative, (package_name, historical) in managed.items():
    canonical = (base / 'overlay-files' / relative).read_bytes()
    assert (package_files / package_name).read_bytes() == canonical, relative
    target = files / relative
    if target.exists() or target.is_symlink():
        assert target.is_file() and not target.is_symlink(), 'Refuse changed managed input: ' + relative
        approved = historical | {hashlib.sha256(canonical).hexdigest()}
        assert hashlib.sha256(target.read_bytes()).hexdigest() in approved, 'Refuse changed managed input: ' + relative
        remove.append(target)
for target in remove:
    target.unlink()
for path in (base / 'overlay-files').rglob('*'):
    if path.is_file():
        relative = path.relative_to(base / 'overlay-files')
        if relative.as_posix() in managed:
            continue
        target = files / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        executable = ('uci-defaults' in path.parts or
                      path.relative_to(base / 'overlay-files').as_posix() ==
                      'usr/libexec/platform/packet-steering.sh')
        target.chmod(0o755 if executable else 0o600)

# Remove only the two earlier managed build-input paths; never open their content.
for name in ('portal_autologin_BE6L.sh', 'portal_autologin.sh'):
    target = files / 'usr/bin' / name
    if target.is_symlink() or target.exists():
        target.unlink()
print('Managed network/UI defaults use their APK; other overlays prepared; portal payload omitted without inspection.')
