"""Extract one pinned Ubuntu LLVM host-tools package without system installation."""
from pathlib import Path
import hashlib
import io
import json
import subprocess
import tarfile
import urllib.request

BASE = Path(__file__).resolve().parents[1]
ROOT = Path('/root/be6l-openwrt/host/llvm21-bpf-tools')
VERSION = '1:21.1.8-6ubuntu1'
URL = 'https://archive.ubuntu.com/ubuntu/pool/universe/l/llvm-toolchain-21/llvm-21_21.1.8-6ubuntu1_amd64.deb'
SHA256 = '9227b4149f0f553a58befd85bc905f1c91719dbae1c1971fade102f53692a40b'
SIZE = 20012922
ROOT.mkdir(parents=True, exist_ok=True)
deb = ROOT / 'llvm-21_21.1.8-6ubuntu1_amd64.deb'
if not deb.is_file():
    cached = Path('/var/cache/apt/archives') / deb.name
    if cached.is_file():
        data = cached.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=30) as response:
            data = response.read(SIZE + 1)
    assert len(data) == SIZE and hashlib.sha256(data).hexdigest() == SHA256
    deb.write_bytes(data)
assert deb.stat().st_size == SIZE
assert hashlib.sha256(deb.read_bytes()).hexdigest() == SHA256
metadata = subprocess.check_output(['apt-cache', 'show', 'llvm-21=' + VERSION], text=True)
assert 'SHA256: ' + SHA256 in metadata and 'Origin: Ubuntu' in metadata
installed = subprocess.check_output(['dpkg-query', '-W', '-f=${Version}', 'libllvm21'], text=True)
assert installed == VERSION, 'Use the matching already-installed libLLVM21'
marker = ROOT / 'extracted.json'
if marker.exists():
    assert json.loads(marker.read_text())['sha256'] == SHA256
else:
    # Old WSL kernels cannot implement some current GNU tar extraction calls.
    # Extract only the needed regular files with Python, after package hashing.
    archive = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', str(deb)])
    allow = {'usr/lib/llvm-21/bin/' + name for name in ('llc', 'opt', 'llvm-dis', 'llvm-objcopy')}
    allow.add('usr/share/doc/llvm-21/copyright')
    found = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as stream:
        for member in stream:
            name = member.name.removeprefix('./')
            if name not in allow:
                continue
            assert member.isfile() and name not in found
            found.add(name)
            target = ROOT / 'package' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(stream.extractfile(member).read())
            target.chmod(0o755 if '/bin/' in name else 0o644)
    assert found == allow
    strip = ROOT / 'package/usr/lib/llvm-21/bin/llvm-strip'
    if strip.is_symlink():
        assert str(strip.readlink()) == 'llvm-objcopy'
    else:
        assert not strip.exists()
        strip.symlink_to('llvm-objcopy')
    marker.write_text(json.dumps(dict(sha256=SHA256, url=URL, bytes=SIZE)) + '\n')
tools = ROOT / 'bin'
tools.mkdir(exist_ok=True)
for name in ('clang', 'llc', 'opt', 'llvm-dis', 'llvm-strip'):
    source = Path('/usr/lib/llvm-21/bin/clang') if name == 'clang' else ROOT / 'package/usr/lib/llvm-21/bin' / name
    assert source.is_file(), name
    dest = tools / name
    if dest.is_symlink():
        assert dest.resolve() == source.resolve()
    else:
        assert not dest.exists()
        dest.symlink_to(source)
dependencies = {}
for name in ('clang', 'llc', 'opt', 'llvm-dis', 'llvm-strip'):
    result = subprocess.run(['ldd', str(tools / name)], capture_output=True, text=True)
    dependencies[name] = result.stdout + result.stderr
    assert result.returncode == 0 and 'not found' not in dependencies[name], name
report = dict(version=VERSION, url=URL, sha256=SHA256, bytes=SIZE,
              system_packages_installed=False, extracted_privately=True,
              llvm_source_downloaded=False, dependencies=dependencies,
              tool_sha256={name: hashlib.sha256((tools / name).read_bytes()).hexdigest()
                           for name in ('clang', 'llc', 'opt', 'llvm-dis', 'llvm-strip')})
(BASE / 'logs/bridger-host-llvm-fetch.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
