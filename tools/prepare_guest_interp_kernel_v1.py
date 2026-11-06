# SPDX-License-Identifier: MIT
"""Prepare the explicit BE6L V2 guest-loader fd experiment from locked inputs."""
from pathlib import Path
import argparse
import difflib
import hashlib
import json
import shutil
from prepare_guest_exe_kernel_v1 import CHANGES, sha, BASE

PATCH = 'be6l-binfmt-guest-interp.patch'
CONTRACT = 'BE6L_X_EXECFD_EXE_INTERPFD_V2'


def changes():
    helper = (BASE/'upstream/be6l-guest-interp-helper.c').read_text()
    return {
        'include/uapi/linux/auxvec.h': [('#define AT_EXECFD 2', '#define AT_BE6L_INTERPFD 0xbe6a /* private BE6L V2 loader descriptor */\n#define AT_EXECFD 2')],
        'include/linux/auxvec.h': [('AT_VECTOR_SIZE_BASE 24', 'AT_VECTOR_SIZE_BASE 25')],
        'include/uapi/linux/binfmts.h': [('#define AT_FLAGS_BE6L_EXECFD_EXE (1U << 16)', '#define AT_FLAGS_BE6L_EXECFD_EXE (1U << 16)\n#define AT_FLAGS_BE6L_INTERPFD (1U << 17)')],
        'include/linux/binfmts.h': [('\tint execfd;', '\tint be6l_interpfd;\n\tint execfd;')],
        'include/linux/mm_types.h': [('\t\tstruct file *be6l_binfmt_interpreter;', '\t\tstruct file *be6l_binfmt_interpreter;\n\t\tstruct file *be6l_guest_loader;')],
        'kernel/fork.c': [(
            '\tRCU_INIT_POINTER(mm->exe_file, NULL);\n\tmm->be6l_binfmt_interpreter = NULL;',
            '\tRCU_INIT_POINTER(mm->exe_file, NULL);\n\tmm->be6l_binfmt_interpreter = NULL;\n\tmm->be6l_guest_loader = NULL;'), (
            '\tset_mm_exe_file(mm, NULL);',
            '\tset_mm_exe_file(mm, NULL);\n'
            '\tif (mm->be6l_guest_loader) {\n'
            '\t\texe_file_allow_write_access(mm->be6l_guest_loader);\n'
            '\t\tfput(mm->be6l_guest_loader);\n\t\tmm->be6l_guest_loader = NULL;\n\t}'), (
            '\texe_file = get_mm_exe_file(oldmm);',
            '\tif (oldmm->be6l_guest_loader) {\n'
            '\t\tmm->be6l_guest_loader = get_file(oldmm->be6l_guest_loader);\n'
            '\t\tif (exe_file_deny_write_access(mm->be6l_guest_loader))\n'
            '\t\t\tpr_warn_once("BE6L guest loader deny failed in %s\\n", __func__);\n\t}\n\n'
            '\texe_file = get_mm_exe_file(oldmm);')],
        'fs/binfmt_misc.c': [(
            '#include <linux/mm.h>', '#include <linux/mm.h>\n#include <linux/elf.h>'), (
            'static int load_misc_binary(struct linux_binprm *bprm)',
            helper+'\nstatic int load_misc_binary(struct linux_binprm *bprm)'), (
            '\t\tretval = set_mm_exe_file(bprm->mm, bprm->file);',
            '\t\tretval = be6l_prepare_guest_interp(bprm);\n'
            '\t\tif (retval)\n\t\t\tgoto release_interp;\n'
            '\t\tretval = set_mm_exe_file(bprm->mm, bprm->file);')],
        'fs/exec.c': [(
            '\t\tbprm->execfd = retval;\n\t}',
            '\t\tbprm->execfd = retval;\n\t}\n'
            '\tif (bprm->be6l_execfd_exe && me->mm->be6l_guest_loader) {\n'
            '\t\tretval = get_unused_fd_flags(O_CLOEXEC);\n'
            '\t\tif (retval < 0)\n\t\t\tgoto out_unlock;\n'
            '\t\tfd_install(retval, get_file(me->mm->be6l_guest_loader));\n'
            '\t\tbprm->be6l_interpfd = retval;\n\t}')],
        'fs/binfmt_elf.c': [(
            '\tNEW_AUX_ENT(AT_FLAGS, flags);',
            '\tif (bprm->be6l_execfd_exe && mm->be6l_guest_loader)\n'
            '\t\tflags |= AT_FLAGS_BE6L_INTERPFD;\n\tNEW_AUX_ENT(AT_FLAGS, flags);'), (
            '\t\tNEW_AUX_ENT(AT_EXECFD, bprm->execfd);\n\t}',
            '\t\tNEW_AUX_ENT(AT_EXECFD, bprm->execfd);\n\t}\n'
            '\tif (bprm->be6l_execfd_exe && mm->be6l_guest_loader)\n'
            '\t\tNEW_AUX_ENT(AT_BE6L_INTERPFD, bprm->be6l_interpfd);')],
    }


def render(prepared):
    lock = json.loads((BASE/'upstream/be6l-guest-interp-source-lock.json').read_text())
    if sha(prepared/'result.json') != lock['base_preparation_sha256']:
        raise ValueError('Wrong base source preparation')
    original = prepared/'kernel-source/linux-6.18.55'
    extra, changed, patches = changes(), {}, []
    for name, digest in lock['source_files'].items():
        if sha(original/name) != digest:
            raise ValueError('Source pin differs: '+name)
        before = (original/name).read_text()
        after = before
        for old, new in CHANGES.get(name, []) + extra.get(name, []):
            if after.count(old) != 1:
                raise ValueError('Ambiguous V2 source anchor: '+name+': '+repr(old))
            after = after.replace(old, new, 1)
        changed[name] = after
        patches.extend(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='a/'+name, tofile='b/'+name))
    return lock, changed, ''.join(patches)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--render-only', action='store_true', help='Emit a patch for review; creates no source-preparation receipt')
    a = p.parse_args()
    w = a.work.resolve()
    if w.parent != Path('/root') or not w.name.startswith('be6l-guest-interp-source-'):
        p.error('Use a fresh /root/be6l-guest-interp-source-* directory')
    lock, changed, patch = render(a.prepared)
    if not a.render_only and hashlib.sha256(patch.encode()).hexdigest() != sha(BASE/'upstream'/PATCH):
        raise ValueError('Generated V2 patch differs from reviewed public source')
    w.mkdir(mode=0o700)
    (w/PATCH).write_text(patch)
    if a.render_only:
        print('V2_PATCH_RENDERED_ONLY_NO_SOURCE_ADMISSION', sha(w/PATCH), flush=True)
        return
    kernel = w/'kernel-source/linux-6.18.55'
    kernel.parent.mkdir()
    shutil.copytree(a.prepared/'kernel-source/linux-6.18.55', kernel, symlinks=True)
    (w/'openwrt').symlink_to((a.prepared/'openwrt').resolve(), target_is_directory=True)
    for name, value in changed.items():
        (kernel/name).write_text(value)
    result = json.loads((a.prepared/'result.json').read_text())
    result.update(pristine_case_sensitive_source=False, case_sensitive_source=True,
        guest_exe_file=True, guest_interp_fd=True, guest_exe_contract=CONTRACT,
        base_preparation_sha256=sha(a.prepared/'result.json'),
        guest_exe_source_lock_sha256=sha(BASE/'upstream/be6l-guest-interp-source-lock.json'),
        guest_exe_patch_sha256=sha(w/PATCH), guest_exe_files={name:sha(kernel/name) for name in changed},
        built_in_binfmt_required=True, credentials_flag_with_x_rejected=True,
        guest_loader_inode_retained=True, guest_loader_preflight_before_commit=True,
        full_kernel_built=False, target_executed=False, standard_a53_package_compatibility_qualified=False)
    (w/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print('V2_GUEST_INTERP_SOURCE_PREPARED', flush=True)


if __name__ == '__main__':
    main()
