# SPDX-License-Identifier: MIT
"""Prepare an opt-in built-in binfmt executable-inode retention experiment.

The generated kernel changes are GPL-2.0 (the UAPI header keeps its syscall
exception). This is a private experimental contract, not an upstream ABI.
It does not qualify exec errno, privilege transitions, or package compatibility.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil

BASE = Path(__file__).resolve().parents[1]
LOCK = BASE / 'upstream/be6l-guest-exe-source-lock.json'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


CHANGES = {
    'include/linux/mm_types.h': [(
        '\t\tstruct file __rcu *exe_file;',
        '\t\tstruct file __rcu *exe_file;\n'
        '\t\t/* Private X interpreter pin; immutable until final mmput. */\n'
        '\t\tstruct file *be6l_binfmt_interpreter;')],
    'kernel/fork.c': [(
        '\tRCU_INIT_POINTER(mm->exe_file, NULL);',
        '\tRCU_INIT_POINTER(mm->exe_file, NULL);\n'
        '\tmm->be6l_binfmt_interpreter = NULL;'), (
        '\tset_mm_exe_file(mm, NULL);',
        '\tset_mm_exe_file(mm, NULL);\n'
        '\tif (mm->be6l_binfmt_interpreter) {\n'
        '\t\texe_file_allow_write_access(mm->be6l_binfmt_interpreter);\n'
        '\t\tfput(mm->be6l_binfmt_interpreter);\n'
        '\t\tmm->be6l_binfmt_interpreter = NULL;\n'
        '\t}'), (
        '\texe_file = get_mm_exe_file(oldmm);',
        '\t/* oldmm is live; the private interpreter pin is immutable.\n'
        '\t * As for exe_file below, its existing write denial must hold.\n'
        '\t */\n'
        '\tif (oldmm->be6l_binfmt_interpreter) {\n'
        '\t\tmm->be6l_binfmt_interpreter =\n'
        '\t\t\tget_file(oldmm->be6l_binfmt_interpreter);\n'
        '\t\tif (exe_file_deny_write_access(mm->be6l_binfmt_interpreter))\n'
        '\t\t\tpr_warn_once("BE6L interpreter deny failed in %s\\n", __func__);\n'
        '\t}\n\n'
        '\texe_file = get_mm_exe_file(oldmm);')],
    'include/uapi/linux/binfmts.h': [(
        '#define AT_FLAGS_PRESERVE_ARGV0 (1 << AT_FLAGS_PRESERVE_ARGV0_BIT)',
        '#define AT_FLAGS_PRESERVE_ARGV0 (1 << AT_FLAGS_PRESERVE_ARGV0_BIT)\n\n'
        '/* BE6L private experiment: mm->exe_file retains the binfmt O file. */\n'
        '#define AT_FLAGS_BE6L_EXECFD_EXE (1U << 16)')],
    'include/linux/binfmts.h': [(
        '\t\thave_execfd:1,',
        '\t\thave_execfd:1,\n\n'
        '\t\t/* Private built-in binfmt X experiment; never implies C. */\n'
        '\t\tbe6l_execfd_exe:1,')],
    'fs/binfmt_elf.c': [(
        '\tNEW_AUX_ENT(AT_FLAGS, flags);',
        '\tif (bprm->be6l_execfd_exe)\n'
        '\t\tflags |= AT_FLAGS_BE6L_EXECFD_EXE;\n'
        '\tNEW_AUX_ENT(AT_FLAGS, flags);')],
    'fs/exec.c': [(
        '\t/* Once we are committed compute the creds */',
        '\t/* Validate the private retention contract before committing exec. */\n'
        '\tif (bprm->be6l_execfd_exe &&\n'
        '\t    (!bprm->have_execfd || !bprm->executable ||\n'
        '\t     rcu_access_pointer(bprm->mm->exe_file) != bprm->executable ||\n'
        '\t     bprm->mm->be6l_binfmt_interpreter != bprm->file))\n'
        '\t\treturn -ENOEXEC;\n\n'
        '\t/* Once we are committed compute the creds */'), (
        '\tretval = set_mm_exe_file(bprm->mm, bprm->file);\n\tif (retval)\n\t\tgoto out;',
        '\t/* X already pinned the original before exec_binprm drops its deny. */\n'
        '\tif (!bprm->be6l_execfd_exe) {\n'
        '\t\tretval = set_mm_exe_file(bprm->mm, bprm->file);\n'
        '\t\tif (retval)\n\t\t\tgoto out;\n\t}')],
    'fs/binfmt_misc.c': [(
        '#include <linux/sched/mm.h>', '#include <linux/sched/mm.h>\n#include <linux/mm.h>'), (
        '#define MISC_FMT_OPEN_FILE (1UL << 28)',
        '#define MISC_FMT_OPEN_FILE (1UL << 28)\n'
        '#define MISC_FMT_BE6L_EXECFD_EXE (1UL << 27)'), (
        '\tif (bprm->interp_flags & BINPRM_FLAGS_PATH_INACCESSIBLE)',
        '\tif ((bprm->interp_flags & BINPRM_FLAGS_PATH_INACCESSIBLE) &&\n'
        '\t    !(fmt->flags & MISC_FMT_BE6L_EXECFD_EXE))'), (
        '\tbprm->interpreter = interp_file;',
        '#if IS_BUILTIN(CONFIG_BINFMT_MISC)\n'
        '\tif (fmt->flags & MISC_FMT_BE6L_EXECFD_EXE) {\n'
        '\t\t/* Pin before exec_binprm releases the original write denial.\n'
        '\t\t * mmput/free_bprm owns cleanup on every later failure path.\n'
        '\t\t * Do not support nested O dispatch or credential inheritance.\n'
        '\t\t */\n'
        '\t\tretval = -ENOEXEC;\n'
        '\t\tif (!bprm->mm || bprm->have_execfd || bprm->executable ||\n'
        '\t\t    bprm->be6l_execfd_exe || bprm->execfd_creds)\n'
        '\t\t\tgoto release_interp;\n'
        '\t\tretval = set_mm_exe_file(bprm->mm, bprm->file);\n'
        '\t\tif (retval)\n\t\t\tgoto release_interp;\n'
        '\t\t/* Retain the native interpreter denial as well as the guest. */\n'
        '\t\tretval = exe_file_deny_write_access(interp_file);\n'
        '\t\tif (retval)\n\t\t\tgoto release_interp;\n'
        '\t\tbprm->mm->be6l_binfmt_interpreter = get_file(interp_file);\n'
        '\t\tbprm->be6l_execfd_exe = 1;\n'
        '\t}\n'
        '#endif\n\n'
        '\tbprm->interpreter = interp_file;'), (
        '\tretval = 0;\nret:',
        '\tretval = 0;\n\tgoto ret;\n'
        '#if IS_BUILTIN(CONFIG_BINFMT_MISC)\n'
        'release_interp:\n'
        '\texe_file_allow_write_access(interp_file);\n'
        '\tfput(interp_file);\n'
        '#endif\nret:'), (
        "\t\tcase 'F':",
        '#if IS_BUILTIN(CONFIG_BINFMT_MISC)\n'
        "\t\tcase 'X':\n"
        '\t\t\tp++;\n'
        '\t\t\te->flags |= MISC_FMT_BE6L_EXECFD_EXE | MISC_FMT_OPEN_BINARY;\n'
        '\t\t\tbreak;\n'
        '#endif\n'
        "\t\tcase 'F':"), (
        '\tp = check_special_flags(p, e);',
        '\tp = check_special_flags(p, e);\n'
        '\t/* Secure credential inheritance needs a separate qualification. */\n'
        '\tif ((e->flags & MISC_FMT_BE6L_EXECFD_EXE) &&\n'
        '\t    (e->flags & MISC_FMT_CREDENTIALS))\n'
        '\t\tgoto einval;'), (
        "\tif (e->flags & MISC_FMT_OPEN_FILE)\n\t\t*dp++ = 'F';",
        "\tif (e->flags & MISC_FMT_OPEN_FILE)\n\t\t*dp++ = 'F';\n"
        "\tif (e->flags & MISC_FMT_BE6L_EXECFD_EXE)\n\t\t*dp++ = 'X';")],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if work.parent != Path('/root') or not work.name.startswith('be6l-guest-exe-source-'):
        parser.error('Use a fresh /root/be6l-guest-exe-source-* directory')
    lock = json.loads(LOCK.read_text())
    if sha(args.prepared / 'result.json') != lock['base_preparation_sha256']:
        raise ValueError('Wrong base source preparation')
    original = args.prepared / 'kernel-source/linux-6.18.55'
    changed = {}
    patches = []
    for name, expected in lock['source_files'].items():
        if sha(original / name) != expected:
            raise ValueError('Source pin differs: ' + name)
        before = (original / name).read_text()
        after = before
        for old, new in CHANGES[name]:
            if after.count(old) != 1:
                raise ValueError('Ambiguous source anchor: ' + name + ': ' + repr(old))
            after = after.replace(old, new, 1)
        changed[name] = after
        patches.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                           fromfile='a/' + name, tofile='b/' + name))
    if hashlib.sha256(''.join(patches).encode()).hexdigest() != sha(BASE / 'upstream/be6l-binfmt-guest-exe.patch'):
        raise ValueError('Generated patch differs from the reviewed public patch')
    work.mkdir(mode=0o700)
    kernel = work / 'kernel-source/linux-6.18.55'
    kernel.parent.mkdir()
    shutil.copytree(original, kernel, symlinks=True)
    (work / 'openwrt').symlink_to((args.prepared / 'openwrt').resolve(), target_is_directory=True)
    for name, after in changed.items():
        (kernel / name).write_text(after)
    patch = work / 'be6l-binfmt-guest-exe.patch'
    patch.write_text(''.join(patches))
    if any(sha(original / name) != expected for name, expected in lock['source_files'].items()):
        raise ValueError('Original preparation changed')
    report = json.loads((args.prepared / 'result.json').read_text())
    report.update(pristine_case_sensitive_source=False, case_sensitive_source=True,
        guest_exe_file=True, guest_exe_contract='BE6L_X_AT_FLAGS_16_v1',
        base_preparation_sha256=sha(args.prepared / 'result.json'),
        guest_exe_source_lock_sha256=sha(LOCK), guest_exe_patch_sha256=sha(patch),
        guest_exe_files={name: sha(kernel / name) for name in changed},
        built_in_binfmt_required=True, credentials_flag_with_x_rejected=True,
        original_executable_write_denial_continuous_by_design=True,
        interpreter_write_denial_continuous_by_design=True,
        fork_and_mmput_interpreter_reference_pairing_implemented=True,
        full_kernel_built=False, target_executed=False,
        standard_a53_package_compatibility_qualified=False)
    (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print('GUEST_EXE_KERNEL_SOURCE_PREPARED', sha(patch), flush=True)


if __name__ == '__main__':
    main()
