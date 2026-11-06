/* SPDX-License-Identifier: MIT
 * Negative execution semantics. No firmware/host changes; isolated RAM root only.
 */
#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *self = "/bin/be6l-exec-corners";
static char *const vars[] = {"PATH=/bin:/usr/bin", NULL};

static void copy_self(const char *to)
{
    int input = open(self, O_RDONLY), output = open(to, O_CREAT|O_TRUNC|O_RDWR, 0755);
    char data[16384];
    ssize_t length;
    if (input < 0 || output < 0) _exit(70);
    while ((length = read(input, data, sizeof(data))) > 0)
        if (write(output, data, length) != length) _exit(71);
    if (length < 0 || close(input) || close(output)) _exit(72);
}

static void bad_interpreter(void)
{
    const char *name = "/tmp/be6l-exec-bad-interpreter";
    copy_self(name);
    int fd = open(name, O_RDWR);
    Elf64_Ehdr header;
    Elf64_Phdr program;
    if (fd < 0 || pread(fd, &header, sizeof(header), 0) != sizeof(header)) _exit(73);
    int changed = 0;
    for (int i = 0; i < header.e_phnum; i++) {
        if (pread(fd, &program, sizeof(program), header.e_phoff+i*header.e_phentsize) != sizeof(program)) _exit(74);
        if (program.p_type == PT_INTERP) {
            const char missing[] = "/absent/be6l-ld.so";
            if (sizeof(missing) > program.p_filesz ||
                pwrite(fd, missing, sizeof(missing), program.p_offset) != sizeof(missing)) _exit(75);
            changed = 1;
        }
    }
    if (!changed || close(fd)) _exit(76);
    char *args[] = {"be6l-corners", "--noop", NULL};
    execve(name, args, vars);
    if (errno == ENOENT) _exit(0);
    fprintf(stderr, "BAD_INTERPRETER_ERRNO=%d\n", errno);
    _exit(77);
}

static int proc_checks(int deleted)
{
    struct stat expected, actual;
    int file = open("/proc/self/exe", O_RDONLY);
    if (file < 0) {
        printf("PROC_OPEN_FAILED deleted=%d errno=%d\n", deleted, errno);
        return 80;
    }
    unsigned char bytes[20];
    if (read(file, bytes, sizeof(bytes)) != sizeof(bytes) ||
        memcmp(bytes, "\177ELF\2\1", 6) || bytes[18] != 183 || bytes[19]) return 81;
    if (fstat(file, &expected) || stat("/proc/self/exe", &actual)) return 82;
    close(file);
    printf("PROC_STAT deleted=%d guest_size=%lld proc_size=%lld\n",
           deleted, (long long)expected.st_size, (long long)actual.st_size);
    fflush(stdout);
    return expected.st_size == actual.st_size && expected.st_ino == actual.st_ino ? 0 : 83;
}

static int proc_statx_checks(void)
{
    struct stat expected;
    struct statx actual;
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0 || fstat(fd, &expected)) return 89;
    int result = syscall(SYS_statx, AT_FDCWD, "/proc/self/exe", 0,
                         STATX_INO|STATX_SIZE, &actual);
    close(fd);
    if (result) return 90;
    printf("PROC_STATX guest_size=%lld proc_size=%llu\n",
           (long long)expected.st_size, (unsigned long long)actual.stx_size);
    fflush(stdout);
    return (unsigned long long)expected.st_size == actual.stx_size &&
           (unsigned long long)expected.st_ino == actual.stx_ino ? 0 : 91;
}

static int write_denied(const char *name)
{
    int fd = open(name, O_WRONLY); /* Never truncate or write a byte. */
    int saved = errno;
    if (fd >= 0) close(fd);
    return fd < 0 && saved == ETXTBSY ? 0 : 92;
}

static int renamed_exe(void)
{
    const char *from = "/tmp/be6l-corners-named", *to = "/tmp/be6l-corners-renamed";
    char name[256];
    if (rename(from, to)) return 93;
    ssize_t count = readlink("/proc/self/exe", name, sizeof(name)-1);
    if (count < 0 || count >= (ssize_t)sizeof(name)-1) return 94;
    name[count] = 0;
    int result = strcmp(name, to) ? 95 : proc_checks(0);
    if (!result) result = proc_statx_checks();
    if (!result) result = write_denied(to);
    unlink(to);
    return result;
}

static void exec_copy(const char *mode, const char *extra)
{
    const char *name = "/tmp/be6l-corners-named";
    copy_self(name);
    char *args[] = {"be6l-corners", (char *)mode, (char *)extra, NULL};
    execve(name, args, vars);
    _exit(96);
}

static int exit_releases_pin(void)
{
    pid_t child = fork();
    int status;
    if (child < 0) return 97;
    if (!child) exec_copy("--noop", NULL);
    if (waitpid(child, &status, 0) != child || status) return 98;
    int fd = open("/tmp/be6l-corners-named", O_WRONLY);
    if (fd < 0) return 99;
    close(fd);
    unlink("/tmp/be6l-corners-named");
    return 0;
}

static int fork_pin_owner(int fd)
{
    pid_t parent = getpid(), child = fork();
    if (child < 0) return 100;
    if (child) { close(fd); return 0; }
    /* The exec parent's mm must have gone away; keep only the forked mm. */
    for (int i = 0; i < 5000 && getppid() == parent; i++) usleep(1000);
    int result = getppid() == parent ? 101 : proc_checks(0);
    if (!result) result = write_denied("/tmp/be6l-corners-named");
    unsigned char value = result;
    if (write(fd, &value, 1) != 1) _exit(102);
    close(fd);
    _exit(result);
}

static int fork_inherits_pin(void)
{
    int pipefd[2], status;
    if (pipe(pipefd)) return 103;
    pid_t child = fork();
    if (child < 0) return 104;
    if (!child) {
        close(pipefd[0]);
        char descriptor[32];
        snprintf(descriptor, sizeof(descriptor), "%d", pipefd[1]);
        exec_copy("--fork-pin", descriptor);
    }
    close(pipefd[1]);
    if (waitpid(child, &status, 0) != child || status) return 105;
    unsigned char value = 255;
    alarm(8);
    ssize_t count = read(pipefd[0], &value, 1);
    alarm(0);
    close(pipefd[0]);
    unlink("/tmp/be6l-corners-named");
    return count == 1 ? value : 106;
}

static void setuid_exec(int no_new_privs)
{
    const char *name = "/tmp/be6l-corners-setuid";
    copy_self(name);
    if (chmod(name, 04755)) _exit(107);
    if (no_new_privs && prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) _exit(108);
    if (setgid(65534) || setuid(65534)) _exit(109);
    char *args[] = {"be6l-corners", no_new_privs ? "--ids-nnp" : "--ids-setuid", NULL};
    execve(name, args, vars);
    _exit(110);
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--noop")) return 0;
    if (argc == 2 && !strcmp(argv[1], "--deleted")) return proc_checks(1);
    if (argc == 2 && !strcmp(argv[1], "--deleted-statx")) return proc_statx_checks();
    if (argc == 2 && !strcmp(argv[1], "--renamed")) return renamed_exe();
    if (argc == 2 && !strcmp(argv[1], "--write-denial")) {
        if (getauxval(AT_FLAGS) & (3U << 16)) return 111;
        return write_denied("/proc/self/exe");
    }
    if (argc == 3 && !strcmp(argv[1], "--fork-pin")) return fork_pin_owner(atoi(argv[2]));
    if (argc == 2 && (!strcmp(argv[1], "--ids-nnp") || !strcmp(argv[1], "--ids-setuid"))) {
        int nnp = !strcmp(argv[1], "--ids-nnp");
        printf("GUEST_IDS uid=%u euid=%u secure=%lu nnp=%d\n", (unsigned)getuid(),
               (unsigned)geteuid(), getauxval(AT_SECURE), prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
        fflush(stdout);
        return getuid() == 65534 && geteuid() == (nnp ? 65534 : 0) &&
               getauxval(AT_SECURE) == (unsigned long)!nnp ? 0 : 112;
    }
    if (argc != 1) return 84;
    const char *names[] = {"missing-elf-interpreter-errno", "linked-proc-exe-stat", "deleted-proc-exe-open",
        "linked-proc-exe-statx", "renamed-proc-exe", "deleted-proc-exe-statx",
        "guest-executable-write-denial", "exit-releases-write-denial", "fork-inherits-write-denial",
        "setuid-guest-credentials", "no-new-privileges", "private-kernel-auxv-hidden"};
    const int count = sizeof(names)/sizeof(names[0]);
    int failed = 0;
    for (int i = 0; i < count; i++) {
        pid_t pid = fork();
        int status;
        if (pid < 0) return 85;
        if (!pid) {
            if (i == 0) bad_interpreter();
            if (i == 1) _exit(proc_checks(0));
            if (i == 3) _exit(proc_statx_checks());
            if (i == 4) exec_copy("--renamed", NULL);
            if (i == 6) exec_copy("--write-denial", NULL);
            if (i == 7) _exit(exit_releases_pin());
            if (i == 8) _exit(fork_inherits_pin());
            if (i == 9 || i == 10) setuid_exec(i == 10);
            if (i == 11) {
                unsigned long flags = getauxval(AT_FLAGS);
                errno = 0;
                unsigned long descriptor = getauxval(0xbe6a);
                _exit(!(flags & (3U << 16)) && !descriptor && errno == ENOENT ? 0 : 113);
            }
            if (i == 2 || i == 5) {
                const char *name = "/tmp/be6l-exec-corners-deleted";
                copy_self(name);
                int fd = open(name, O_RDONLY);
                if (fd < 0 || unlink(name)) _exit(86);
                char *args[] = {"be6l-corners", i == 2 ? "--deleted" : "--deleted-statx", NULL};
                syscall(SYS_execveat, fd, "", args, vars, AT_EMPTY_PATH);
                _exit(87);
            }
        }
        if (waitpid(pid, &status, 0) != pid) return 88;
        int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        printf("EXEC_CORNER %s %s status=%d\n", names[i], ok ? "PASS" : "FAIL", status);
        fflush(stdout);
        failed += !ok;
        unlink("/tmp/be6l-corners-named");
        unlink("/tmp/be6l-corners-renamed");
        unlink("/tmp/be6l-corners-setuid");
        unlink("/tmp/be6l-exec-bad-interpreter");
    }
    printf("EXEC_CORNERS cases=%d failures=%d\n", count, failed);
    return failed ? 1 : 0;
}
