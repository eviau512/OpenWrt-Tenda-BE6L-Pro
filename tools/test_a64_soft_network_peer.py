# SPDX-License-Identifier: MIT
"""Test the soft-float network closure on an authorized AArch64 Android peer.

This is NOT BE6L runtime qualification. USB reverse forwarding reaches temporary
loopback-only HTTP/TLS fixtures; saved Wi-Fi settings and PC routes are untouched.
"""
from pathlib import Path
import argparse
import hashlib
import http.server
import json
import re
import shlex
import ssl
import subprocess
import tarfile
import threading
import time
import uuid

BASE = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--adb', default='adb')
parser.add_argument('--serial', required=True)
args = parser.parse_args()
adb = [args.adb, '-s', args.serial]
artifact = BASE / 'artifacts/a64-soft-network'
manifest = json.loads((artifact / 'manifest.json').read_text())
assert manifest['abi'] == 'AAPCS64-soft' and manifest['dependency_closure_audited']
files = manifest['files']
assert all(re.fullmatch(r'[A-Za-z0-9_.-]+', name) for name in files)
with tarfile.open(artifact / 'network.tar') as archive:
    assert sorted(archive.getnames()) == sorted(files)
    for member in archive:
        assert member.isfile() and member.size < 16000000
        data = archive.extractfile(member).read()
        assert hashlib.sha256(data).hexdigest() == files[member.name]['sha256']
        assert data[:5] == b'\x7fELF\x02' and data[18:20] == b'\xb7\0'
        assert files[member.name]['fp_simd_register_uses'] == 0

stamp = time.strftime('%Y%m%d-%H%M%S')
run = BASE / 'logs' / ('soft-network-peer-' + stamp)
run.mkdir()
remote = '/data/local/tmp/be6l-soft-network-' + uuid.uuid4().hex
assert re.fullmatch('/data/local/tmp/be6l-soft-network-[0-9a-f]{32}', remote)

def execute(argv, text=None, expected=0, timeout=30):
    result = subprocess.run(argv, input=text.encode() if text is not None else None,
                            capture_output=True, timeout=timeout)
    output = (result.stdout + result.stderr).decode('utf-8', errors='replace')
    if expected is not None:
        assert result.returncode == expected, (argv[:3], result.returncode, output[-2000:])
    return result.returncode, output

def phone(script, expected=0, timeout=30):
    return execute(adb + ['shell', 'sh'], 'su -c ' + shlex.quote(script) + '\n', expected, timeout)

def push(local, name):
    execute(adb + ['push', str(local), remote + '/' + name])

payload = hashlib.shake_256(b'AAPCS64-soft HTTP and TLS fixture v1').digest(2 * 1024 * 1024)
digest = hashlib.sha256(payload).hexdigest()
observed_tls = []

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/payload':
            self.send_error(404)
            return
        tls = self.connection.version() if isinstance(self.connection, ssl.SSLSocket) else None
        observed_tls.append(tls)
        self.send_response(200)
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Content-Type', 'application/octet-stream')
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *unused):
        pass

servers, threads, reverse = [], [], []
created = False
report = {'peer': 'authorized AArch64 Android test peer', 'dut_runtime_qualified': False,
          'saved_wifi_changed': False, 'pc_routes_changed': False, 'cases': []}

try:
    _, architecture = phone('uname -m')
    assert architecture.strip() == 'aarch64'
    phone('test ! -e ' + remote + ' && mkdir -m 700 ' + remote +
          ' && printf be6l-soft-network-owned > ' + remote + '/owner')
    created = True
    push(artifact / 'network.tar', 'network.tar')
    phone('cd ' + remote + ' && toybox tar -xf network.tar && chmod 700 curl libc.so')
    # -q must be curl's first argument: do not load a peer's saved .curlrc.
    loader = remote + '/libc.so --library-path ' + remote + ' ' + remote + '/curl -q'
    _, version = phone(loader + ' --version')
    (run / 'version.txt').write_text(version)
    assert 'curl 8.23.0' in version and 'mbedTLS/3.6.7' in version
    assert re.search(r'^Protocols: http https\s*$', version, re.M), version
    report['version'] = version

    # New throwaway fixture keys only. Never inspect or reuse user credentials.
    for name in ('trusted', 'unrelated'):
        command = ['wsl', '-d', 'Ubuntu', '-u', 'root', '--', 'openssl', 'req',
                   '-x509', '-newkey', 'rsa:2048', '-noenc', '-days', '2',
                   '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                   '-keyout', '/mnt/' + run.drive[0].lower() + run.as_posix()[2:] + '/' + name + '.key',
                   '-out', '/mnt/' + run.drive[0].lower() + run.as_posix()[2:] + '/' + name + '.crt']
        execute(command)
        push(run / (name + '.crt'), name + '.crt')

    for secure in (False, True):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        if secure:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(run / 'trusted.crt', run / 'trusted.key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
        servers.append(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
        # adb chooses an unused device-side port; never overwrite an existing map.
        _, answer = execute(adb + ['reverse', 'tcp:0', 'tcp:' + str(server.server_port)])
        port = int(answer.strip())
        assert 1024 <= port <= 65535
        reverse.append(port)
        protocol = 'https' if secure else 'http'
        cases = [('valid-' + protocol, 'localhost', 'trusted', 0)]
        if secure:
            cases += [('reject-wrong-hostname', 'wrong.invalid', 'trusted', 60),
                      ('reject-untrusted-ca', 'localhost', 'unrelated', 60)]
        for label, hostname, ca, expected in cases:
            command = (loader + ' --noproxy \"*\" --connect-timeout 5 --max-time 20 --silent --show-error'
                       ' --cacert ' + remote + '/' + ca + '.crt'
                       ' --resolve ' + hostname + ':' + str(port) + ':127.0.0.1'
                       ' --output ' + remote + '/payload'
                       ' --write-out ' + shlex.quote('%{http_code}:%{size_download}:%{ssl_verify_result}:%{time_total}\n') +
                       ' ' + protocol + '://' + hostname + ':' + str(port) + '/payload')
            status, output = phone(command, expected=expected)
            (run / (label + '.txt')).write_text(output)
            if expected == 0:
                assert output.startswith('200:2097152:0:'), output
                _, checksum = phone('toybox sha256sum ' + remote + '/payload')
                assert checksum.split()[0] == digest
            report['cases'].append({'name': label, 'exit_status': status,
                                     'passed': True, 'payload_sha256': digest if expected == 0 else None})
            print(label + ' passed', flush=True)
    report['tls_versions_observed'] = sorted(set(x for x in observed_tls if x))
    report['passed'] = True
finally:
    for port in reverse:
        execute(adb + ['reverse', '--remove', 'tcp:' + str(port)])
    for server in servers:
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join(timeout=3)
    if created:
        # No recursive deletion: only the exact names staged by this invocation.
        names = list(files) + ['network.tar', 'trusted.crt', 'unrelated.crt', 'payload', 'owner']
        phone('test "$(cat ' + remote + '/owner)" = be6l-soft-network-owned && rm -f ' +
              ' '.join(remote + '/' + name for name in names) + ' && rmdir ' + remote)
    for name in ('trusted.key', 'unrelated.key'):
        path = run / name
        if path.exists():
            path.unlink()
    report['cleanup_complete'] = True
    (run / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print('SOFT_NETWORK_PEER_TEST_PASSED_DUT_PENDING', run, flush=True)
