# SPDX-License-Identifier: MIT
"""Sign the admitted integer-host emulator as a separate RAM-installable APK.

This never embeds the emulator in the FIT, installs it or registers binfmt.
The private ELF marker is applied only to this proven AAPCS64-soft build.
"""
from pathlib import Path
import argparse
import json
import subprocess
from package_native_netifd_v3 import copy_path, sha
from plan_integer_binfmt_v1 import tag_private, matches


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('emulator-build', 'apk', 'work'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--release', type=int, default=1)
    a = p.parse_args()
    if not 1 <= a.release <= 999:
        p.error('Use a positive package release')
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-emulator-apk-') or w.exists():
        p.error('Use a fresh /root/be6l-emulator-apk-* directory')
    receipt_path = a.emulator_build/'result.json'
    receipt = json.loads(receipt_path.read_text())
    info = receipt['static_elf_admission']['qemu-aarch64']
    source = a.emulator_build/'admitted/qemu-aarch64'
    defaults = receipt['source_preparation']
    if (not receipt['emulator_built'] or info['sha256'] != sha(source) or
            info['needed'] or info['interpreter'] or info['fp_simd_register_uses'] or
            not defaults.get('binfmt_defaults') or defaults['default_guest_cpu'] != 'cortex-a53' or
            defaults['default_tb_cache_mib'] != 4):
        raise ValueError('Missing complete integer-host/defaults/static ELF admission')
    w.mkdir(mode=0o700)

    def run(label, command):
        r = subprocess.run(list(map(str, command)), capture_output=True, timeout=120)
        (w/(label+'.log')).write_bytes(r.stdout+r.stderr)
        if r.returncode:
            raise RuntimeError(label+' failed; retained log is authoritative')
        return r.stdout

    relative = 'usr/libexec/be6l/qemu-aarch64'
    payload = w/'files'/relative
    payload.parent.mkdir(parents=True)
    payload.write_bytes(tag_private(source.read_bytes()))
    payload.chmod(0o555)
    key, public, trust = w/'temporary-signing.key', w/'public-key.pem', w/'trust'
    trust.mkdir()
    version = '11.1.3-r'+str(a.release)
    package = w/('be6l-integer-emulator-'+version+'.apk')
    try:
        run('key-generate', ['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', key])
        key.chmod(0o600)
        run('key-public', ['openssl', 'pkey', '-in', key, '-pubout', '-out', public])
        copy_path(public, trust/'be6l-integer-emulator.pem')
        command = [a.apk, 'mkpkg', '--sign-key', key, '--files', w/'files', '--output', package]
        for field, value in dict(name='be6l-integer-emulator', version=version,
            arch='aarch64_be6l_soft_experimental', license='GPL-2.0-only',
            description='Experimental integer-host standard A53 interpreter; explicit RAM activation only').items():
            command += ['--info', field+':'+value]
        run('mkpkg', command)
        run('verify', [a.apk, '--network=no', '--keys-dir', trust, 'verify', package])
        extracted = w/'verified'
        extracted.mkdir()
        run('extract', [a.apk, '--network=no', '--keys-dir', trust, 'extract', '--no-chown',
            '--destination', extracted, package])
        if sha(extracted/relative) != sha(payload) or matches((extracted/relative).read_bytes()[:64]):
            raise ValueError('Packaged interpreter bytes or private marker differ')
    finally:
        key.unlink(missing_ok=True)
    report = dict(normal_signed_emulator_package=True, package=package.name, version=version,
        package_sha256=sha(package), relative_interpreter_path=relative,
        interpreter_sha256=sha(payload), source_emulator_sha256=sha(source),
        source_build_receipt_sha256=sha(receipt_path), private_signing_key_removed=not key.exists(),
        marker_is_standard_arm_elf_flag=False, target_installed=False, binfmt_registered=False,
        standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    print('INTEGER_EMULATOR_SIGNED_APK_PREPARED', report['interpreter_sha256'], flush=True)


if __name__ == '__main__':
    main()
