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

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--noop")) return 0;
    if (argc == 2 && !strcmp(argv[1], "--deleted")) return proc_checks(1);
    if (argc != 1) return 84;
    const char *names[] = {"missing-elf-interpreter-errno", "linked-proc-exe-stat", "deleted-proc-exe-open",
        "linked-proc-exe-statx"};
    int failed = 0;
    for (int i = 0; i < 4; i++) {
        pid_t pid = fork();
        int status;
        if (pid < 0) return 85;
        if (!pid) {
            if (i == 0) bad_interpreter();
            if (i == 1) _exit(proc_checks(0));
            if (i == 3) _exit(proc_statx_checks());
            if (i == 2) {
                const char *name = "/tmp/be6l-exec-corners-deleted";
                copy_self(name);
                int fd = open(name, O_RDONLY);
                if (fd < 0 || unlink(name)) _exit(86);
                char *args[] = {"be6l-corners", "--deleted", NULL};
                syscall(SYS_execveat, fd, "", args, vars, AT_EMPTY_PATH);
                _exit(87);
            }
        }
        if (waitpid(pid, &status, 0) != pid) return 88;
        int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        printf("EXEC_CORNER %s %s status=%d\n", names[i], ok ? "PASS" : "FAIL", status);
        fflush(stdout);
        failed += !ok;
    }
    printf("EXEC_CORNERS cases=4 failures=%d\n", failed);
    return failed ? 1 : 0;
}
