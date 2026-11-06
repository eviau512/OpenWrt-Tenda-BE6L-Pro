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


def prepare(verified_source, work, binfmt_defaults=False, binfmt_fd_paths=False,
            binfmt_proc_stat=False, binfmt_guest_exe=False, binfmt_guest_interp=False):
    if binfmt_fd_paths and not binfmt_defaults:
        raise ValueError('FD dispatch changes require the explicit binfmt defaults profile')
    if binfmt_proc_stat and not binfmt_fd_paths:
        raise ValueError('Following proc-stat changes require the explicit FD-path profile')
    if binfmt_guest_exe and not binfmt_proc_stat:
        raise ValueError('Kernel executable retention requires the complete explicit proc-stat profile')
    if binfmt_guest_interp and not binfmt_guest_exe:
        raise ValueError('Kernel loader descriptor handoff requires the explicit executable-retention profile')
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
        changes.setdefault(name, {'original_sha256': hashlib.sha256(old.encode()).hexdigest()})
        changes[name]['modified_sha256'] = hashlib.sha256(new.encode()).hexdigest()
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
    if binfmt_defaults:
        # binfmt_misc supplies the interpreter path, without command-line options.
        # Keep defaults gated to this private host; normal builds retain upstream behavior.
        def defaults(s):
            s = replace_once(s, 'static unsigned long opt_tb_size;',
                '#ifdef BE6L_INTEGER_HOST\nstatic unsigned long opt_tb_size = 4;\n'
                '#else\nstatic unsigned long opt_tb_size;\n#endif')
            return replace_once(s, '    cpu_model = NULL;',
                '#ifdef BE6L_INTEGER_HOST\n    cpu_model = "cortex-a53";\n'
                '#else\n    cpu_model = NULL;\n#endif')
        change('linux-user/main.c', defaults)
    if binfmt_fd_paths:
        change('linux-user/main.c', lambda s: replace_once(s,
            '''    if (!realpath(exec_path, real_exec_path)) {
        printf("Could not resolve %s\\n", exec_path);
    }''',
            '''    if (!realpath(exec_path, real_exec_path)) {
#ifdef BE6L_INTEGER_HOST
        /* binfmt execveat may name /dev/fd without a guest /dev mount.
         * The kernel's O descriptor refers to the actual ELF, including an
         * unlinked inode. Preserve its (deleted) suffix for proc readlink.
         */
        char fd_path[64];
        ssize_t length;
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", execfd);
        length = readlink(fd_path, real_exec_path, sizeof(real_exec_path) - 1);
        if (length < 0 || length >= sizeof(real_exec_path) - 1) {
            error_report("Could not resolve executable descriptor for %s", exec_path);
            exit(EXIT_FAILURE);
        }
        real_exec_path[length] = 0;
#else
        printf("Could not resolve %s\\n", exec_path);
#endif
    }'''))
        def fd_exec(s):
            helper = r'''#ifdef BE6L_INTEGER_HOST
/* Linux binfmt_misc rejects PATH_INACCESSIBLE before honoring O. For the
 * project's standard A53 ELF only, retry a CLOEXEC execveat through a newly
 * opened CLOEXEC /proc fd. Both original and temporary descriptors retain
 * their close-on-exec semantics; the kernel repeats its execute/credential
 * checks and provides QEMU a separate O descriptor. Scripts are never retried.
 * A readable procfs is required; failures retain the original ENOENT.
 */
static int be6l_binfmt_execveat(int dirfd, const char *filename,
                              char **args, char **vars, int flags)
{
    int ret = safe_execveat(dirfd, filename, args, vars, flags);
    int fd_flags, fd, saved;
    char proc_path[64];
    unsigned char header[52];
    ssize_t count;

    if (ret != -1 || errno != ENOENT || dirfd == AT_FDCWD ||
        filename[0] == '/' || (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))) {
        return ret;
    }
    fd_flags = fcntl(dirfd, F_GETFD);
    if (fd_flags < 0 || !(fd_flags & FD_CLOEXEC)) {
        errno = ENOENT;
        return -1;
    }
    if (!filename[0]) {
        if (!(flags & AT_EMPTY_PATH)) {
            errno = ENOENT;
            return -1;
        }
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", dirfd);
        fd = open(proc_path, O_RDONLY | O_CLOEXEC);
    } else {
        fd = openat(dirfd, filename, O_RDONLY | O_CLOEXEC |
                    ((flags & AT_SYMLINK_NOFOLLOW) ? O_NOFOLLOW : 0));
    }
    if (fd < 0) {
        errno = ENOENT;
        return -1;
    }
    count = pread(fd, header, sizeof(header), 0);
    if (count != sizeof(header) || memcmp(header, "\177ELF\2\1\1", 7) ||
        (header[16] != 2 && header[16] != 3) || header[17] ||
        header[18] != 183 || header[19] ||
        header[48] || header[49] || header[50] || header[51]) {
        close(fd);
        errno = ENOENT;
        return -1;
    }
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ret = safe_execve(proc_path, args, vars);
    saved = errno;
    close(fd);
    errno = saved;
    return ret;
}
#endif

'''
            s = replace_once(s, 'static int do_execv(CPUArchState *cpu_env, int dirfd,\n',
                             helper+'static int do_execv(CPUArchState *cpu_env, int dirfd,\n')
            return replace_once(s,
                '''    ret = is_execveat
        ? safe_execveat(dirfd, exe, argp, envp, flags)
        : safe_execve(exe, argp, envp);''',
                '''    ret = is_execveat
#ifdef BE6L_INTEGER_HOST
        ? be6l_binfmt_execveat(dirfd, exe, argp, envp, flags)
#else
        ? safe_execveat(dirfd, exe, argp, envp, flags)
#endif
        : safe_execve(exe, argp, envp);''')
        change('linux-user/syscall.c', fd_exec)
    if binfmt_proc_stat:
        def following_proc_stat(s):
            helper = '''#ifdef BE6L_INTEGER_HOST
/* Match the existing guest open/readlink view for following stat operations.
 * Keep NOFOLLOW and NULL/empty-path behavior intact. This named-file fix does
 * not retain a deleted executable inode and does not qualify deleted proc exe.
 */
static const char *be6l_following_proc_stat_path(const char *filename, int flags)
{
    if (filename && !(flags & AT_SYMLINK_NOFOLLOW) &&
        is_proc_myself(filename, "exe")) {
        return real_exec_path;
    }
    return filename;
}
#endif

'''
            s = replace_once(s, 'static int do_execv(CPUArchState *cpu_env, int dirfd,\n',
                             helper+'static int do_execv(CPUArchState *cpu_env, int dirfd,\n')
            s = replace_once(s,
                '        ret = get_errno(fstatat(arg1, path(p), &st, arg4));',
                '''#ifdef BE6L_INTEGER_HOST
        ret = get_errno(fstatat(arg1, path(be6l_following_proc_stat_path(p, arg4)), &st, arg4));
#else
        ret = get_errno(fstatat(arg1, path(p), &st, arg4));
#endif''')
            return replace_once(s,
                '                ret = get_errno(sys_statx(dirfd, p, flags, mask, &host_stx));',
                '''#ifdef BE6L_INTEGER_HOST
                ret = get_errno(sys_statx(dirfd, be6l_following_proc_stat_path(p, flags),
                                         flags, mask, &host_stx));
#else
                ret = get_errno(sys_statx(dirfd, p, flags, mask, &host_stx));
#endif''')
        change('linux-user/syscall.c', following_proc_stat)
    if binfmt_guest_exe:
        change('linux-user/qemu.h', lambda s: replace_once(s,
            '#define QEMU_H', '''#define QEMU_H

#ifdef BE6L_INTEGER_HOST
/* Private BE6L X/AT_FLAGS bit16 contract, supplied only by the host kernel. */
extern bool be6l_kernel_execfd_exe;
#endif'''))
        def kernel_exe_main(s):
            s = replace_once(s, 'char real_exec_path[PATH_MAX];',
                '''char real_exec_path[PATH_MAX];
#ifdef BE6L_INTEGER_HOST
bool be6l_kernel_execfd_exe;
#define BE6L_AT_FLAGS_EXECFD_EXE (1U << 16)
#endif''')
            return replace_once(s,
                '    preserve_argv0 = !!(qemu_getauxval(AT_FLAGS) & AT_FLAGS_PRESERVE_ARGV0);',
                '''    preserve_argv0 = !!(qemu_getauxval(AT_FLAGS) & AT_FLAGS_PRESERVE_ARGV0);
#ifdef BE6L_INTEGER_HOST
    /* No environment/command-line switch: an O fd and kernel auxv are required.
     * Guest auxv remains produced by the ordinary ELF loader, without bit16.
     */
    errno = 0;
    (void)qemu_getauxval(AT_EXECFD);
    be6l_kernel_execfd_exe = !errno &&
        !!(qemu_getauxval(AT_FLAGS) & BE6L_AT_FLAGS_EXECFD_EXE);
#endif''')
        change('linux-user/main.c', kernel_exe_main)
        def kernel_exe_syscall(s):
            # Preserve upstream proc emulation in the legacy/CLI profile. Under
            # X the real kernel owns the original inode, permissions and ETXTBSY.
            for expression in ('pathname', '(const char *)pathname', 'filename',
                               'p', '(const char *)p'):
                s = replace_once(s, 'is_proc_myself(' + expression + ', "exe")',
                                 'be6l_named_proc_exe(' + expression + ')')
            return replace_once(s,
                'static void excp_dump_file(FILE *logfile, CPUArchState *env,',
                '''static int be6l_named_proc_exe(const char *filename)
{
#ifdef BE6L_INTEGER_HOST
    if (be6l_kernel_execfd_exe) {
        return 0;
    }
#endif
    return is_proc_myself(filename, "exe");
}

static void excp_dump_file(FILE *logfile, CPUArchState *env,''')
        change('linux-user/syscall.c', kernel_exe_syscall)
    if binfmt_guest_interp:
        change('linux-user/qemu.h', lambda s: replace_once(s,
            'extern bool be6l_kernel_execfd_exe;',
            'extern bool be6l_kernel_execfd_exe;\nextern int be6l_kernel_interp_fd;'))
        def guest_interp_main(s):
            s = replace_once(s, 'bool be6l_kernel_execfd_exe;',
                'bool be6l_kernel_execfd_exe;\nint be6l_kernel_interp_fd = -1;\n'
                '#define BE6L_AT_FLAGS_INTERPFD (1U << 17)\n#define BE6L_AT_INTERPFD 0xbe6a')
            return replace_once(s,
                '        !!(qemu_getauxval(AT_FLAGS) & BE6L_AT_FLAGS_EXECFD_EXE);',
                '''        !!(qemu_getauxval(AT_FLAGS) & BE6L_AT_FLAGS_EXECFD_EXE);
    if (be6l_kernel_execfd_exe &&
        (qemu_getauxval(AT_FLAGS) & BE6L_AT_FLAGS_INTERPFD)) {
        unsigned long loader_fd;
        errno = 0;
        loader_fd = qemu_getauxval(BE6L_AT_INTERPFD);
        if (errno || loader_fd > INT_MAX || loader_fd == execfd) {
            error_report("Invalid BE6L kernel loader descriptor");
            exit(EXIT_FAILURE);
        }
        be6l_kernel_interp_fd = loader_fd;
    }''')
        change('linux-user/main.c', guest_interp_main)
        change('linux-user/elfload.c', lambda s: replace_once(s,
            '    fd = open(path(filename), O_RDONLY);',
            '''#ifdef BE6L_INTEGER_HOST
    if (be6l_kernel_interp_fd >= 0) {
        /* The kernel validated and pinned this exact PT_INTERP inode before
         * committing exec. Consume once; existing close(fd) below owns it.
         */
        fd = be6l_kernel_interp_fd;
        be6l_kernel_interp_fd = -1;
    } else
#endif
    {
        fd = open(path(filename), O_RDONLY);
    }'''))
    patch = ''.join(patches)
    (work/'qemu-integer-host.patch').write_text(patch)
    result = dict(version=VERSION, release_archive_sha256=ARCHIVE_SHA,
        signing_primary_fingerprint=FINGERPRINT, official_signature_verified=True,
        mode='opt-in BE6L_INTEGER_HOST with AAPCS64-soft compiler and no FP/SIMD',
        changes=changes, patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        native_host_vector_emission_disabled=True, native_host_hardfloat_disabled=True,
        binfmt_defaults=binfmt_defaults,
        default_guest_cpu='cortex-a53' if binfmt_defaults else 'upstream ELF-selected',
        default_tb_cache_mib=4 if binfmt_defaults else 0,
        binfmt_fd_paths=binfmt_fd_paths,
        binfmt_following_proc_stat=binfmt_proc_stat,
        guest_exe_contract='BE6L_X_EXECFD_EXE_INTERPFD_V2' if binfmt_guest_interp else 'BE6L_X_AT_FLAGS_16_v1' if binfmt_guest_exe else None,
        kernel_execfd_exe_aware=binfmt_guest_exe,
        kernel_guest_interp_aware=binfmt_guest_interp,
        deleted_executable_inode_retained=False,
        cloexec_retry_scope='readable standard A53 ELF only; scripts excluded' if binfmt_fd_paths else None,
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
    parser.add_argument('--binfmt-defaults', action='store_true')
    parser.add_argument('--binfmt-fd-paths', action='store_true')
    parser.add_argument('--binfmt-proc-stat', action='store_true')
    parser.add_argument('--binfmt-guest-exe', action='store_true')
    parser.add_argument('--binfmt-guest-interp', action='store_true')
    args = parser.parse_args()
    print(json.dumps(prepare(args.verified_source, args.work, args.binfmt_defaults,
                              args.binfmt_fd_paths, args.binfmt_proc_stat,
                              args.binfmt_guest_exe, args.binfmt_guest_interp), indent=2))
