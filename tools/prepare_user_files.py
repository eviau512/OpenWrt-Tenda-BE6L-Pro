"""Provision UI defaults and remove the no-longer-requested portal payload."""
from pathlib import Path
import shutil

base = Path(__file__).resolve().parents[1]
src = Path('/root/be6l-openwrt/source')
files = src / 'files'
for path in (base / 'overlay-files').rglob('*'):
    if path.is_file():
        target = files / path.relative_to(base / 'overlay-files')
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
print('Wired WAN defaults prepared; portal payload omitted without inspection.')
