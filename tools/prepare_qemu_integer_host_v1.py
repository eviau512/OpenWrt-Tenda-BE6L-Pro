# SPDX-License-Identifier: MIT
"""Prepare a gated QEMU ARM64 integer-host experiment from signed release bytes.

This is an optional emulation fallback. It does not qualify standard A53
packages, install an emulator, change a kernel or execute anything on a router.
The QEMU source files retain their original licenses and copyright notices.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import subprocess
import tarfile

VERSION = '11.1.3'
ARCHIVE_SHA = '5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22'
FINGERPRINT = 'CEACC9E15534EBABB82D3FA03353C9CEF108B584'


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Missing or ambiguous release context: '+before[:70])
    return text.replace(before, after, 1)


def prepare(verified_source, work):
    if work.exists():
        raise ValueError('Use a fresh experiment directory')
    archive = verified_source/'source.tar.xz'
    with archive.open('rb') as stream:
        actual_archive_sha = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual_archive_sha != ARCHIVE_SHA:
        raise ValueError('Wrong QEMU release archive')
    checked = subprocess.run(['gpgv', '--homedir', str(verified_source/'gnupg'),
        '--keyring', str(verified_source/'release-key.gpg'), '--status-fd', '1',
        str(verified_source/'source.tar.xz.sig'), str(archive)], capture_output=True)
    signatures = [x.decode().split() for x in checked.stdout.splitlines()
                  if x.startswith(b'[GNUPG:] VALIDSIG ')]
    if checked.returncode or not any(x[2] == FINGERPRINT or x[-1] == FINGERPRINT
                                     for x in signatures):
        raise ValueError('Release signature/fingerprint not verified')
    work.mkdir()
    (work/'signature.log').write_bytes(checked.stdout+checked.stderr)
    with tarfile.open(archive, 'r:xz') as incoming:
        members = incoming.getmembers()
        root = 'qemu-'+VERSION
        if any(x.name != root and not x.name.startswith(root+'/') for x in members):
            raise ValueError('Unexpected source archive root')
        members = [x for x in members if x.name != root+'/roms'
                   and not x.name.startswith(root+'/roms/')]
        incoming.extractall(work, members=members, filter='data')
    source = work/('qemu-'+VERSION)
    changes = {}
    patches = []

    def change(name, transform):
        path = source/name
        old = path.read_text()
        new = transform(old)
        if old == new:
            raise ValueError('No change: '+name)
        path.write_text(new)
        changes[name] = {'original_sha256': hashlib.sha256(old.encode()).hexdigest(),
                         'modified_sha256': hashlib.sha256(new.encode()).hexdigest()}
        patches.extend(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                            fromfile='a/'+name, tofile='b/'+name))

    def features(s):
        return replace_once(s,
            '#define TCG_TARGET_HAS_v64              1\n#define TCG_TARGET_HAS_v128             1',
            '''/* Guest vectors use scalar/helper lowering on this opt-in host. */
#ifdef BE6L_INTEGER_HOST
# if defined(__ARM_FP) || defined(__ARM_NEON)
#  error BE6L_INTEGER_HOST requires a no-FP/no-SIMD compiler target
# endif
# define TCG_TARGET_HAS_v64             0
# define TCG_TARGET_HAS_v128            0
#else
# define TCG_TARGET_HAS_v64             1
# define TCG_TARGET_HAS_v128            1
#endif''')

    change('tcg/aarch64/tcg-target-has.h', features)
    change('tcg/aarch64/tcg-target.c.inc', lambda s: replace_once(s,
        '    tcg_target_available_regs[TCG_TYPE_V64] = 0xffffffff00000000ull;\n'
        '    tcg_target_available_regs[TCG_TYPE_V128] = 0xffffffff00000000ull;',
        '''#ifdef BE6L_INTEGER_HOST
    tcg_target_available_regs[TCG_TYPE_V64] = 0;
    tcg_target_available_regs[TCG_TYPE_V128] = 0;
#else
    tcg_target_available_regs[TCG_TYPE_V64] = 0xffffffff00000000ull;
    tcg_target_available_regs[TCG_TYPE_V128] = 0xffffffff00000000ull;
#endif'''))
    change('fpu/softfloat.c', lambda s: replace_once(s,
        '# if defined(__FAST_MATH__)',
        '''#if defined(BE6L_INTEGER_HOST)
/* Preserve IEEE softfloat semantics; never use -ffast-math for this mode. */
# define QEMU_NO_HARDFLOAT 1
# define QEMU_SOFTFLOAT_ATTR QEMU_FLATTEN
#elif defined(__FAST_MATH__)'''))
    for name in ('aes-round.h', 'clmul.h'):
        change('host/include/aarch64/host/crypto/'+name,
               lambda s, name=name: '#ifdef BE6L_INTEGER_HOST\n'
               '#include "../../../generic/host/crypto/'+name+'"\n#else\n'+s+'\n#endif\n')
    patch = ''.join(patches)
    (work/'qemu-integer-host.patch').write_text(patch)
    result = dict(version=VERSION, release_archive_sha256=ARCHIVE_SHA,
        signing_primary_fingerprint=FINGERPRINT, official_signature_verified=True,
        mode='opt-in BE6L_INTEGER_HOST with AAPCS64-soft compiler and no FP/SIMD',
        changes=changes, patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        native_host_vector_emission_disabled=True, native_host_hardfloat_disabled=True,
        source_prepared=True, emulator_built=False, generated_code_audited=False,
        target_executed=False, standard_a53_package_compatibility_qualified=False,
        unresolved=['complete dependency build and ELF admission',
            'audit emitted TCG code and all helper call ABIs',
            'same-ISA execve child containment',
            'threads, atomics, signals, TLS, IEEE rounding and standard packages',
            'RAM budget and performance'])
    (work/'preparation.json').write_text(json.dumps(result, indent=2)+'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verified-source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.verified_source, args.work), indent=2))
