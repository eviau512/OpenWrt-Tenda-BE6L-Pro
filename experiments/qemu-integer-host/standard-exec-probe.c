/* SPDX-License-Identifier: MIT
 * Standard A53 execution-chain fixture. Run only in an isolated RAM guest root.
 * Every successful child performs real FP/SIMD instructions and checks argv,
 * environment, credentials, inherited/reset signal dispositions and proc exe.
 */
#define _GNU_SOURCE
#include <arm_neon.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

static const char *self = "/bin/be6l-exec-probe";
static char *const env[] = {"BE6L_EXEC_ENV=preserved", "PATH=/bin:/usr/bin", "LC_ALL=C", NULL};
static char *const leaf_argv[] = {"be6l-custom-argv0", "--leaf", "token", NULL};
static void handler(int sig) { (void)sig; }
/* musl exposes fexecve; use the Linux syscall directly for execveat cases. */
static int execveat(int fd, const char *path, char *const args[], char *const vars[], int flags)
{
    return syscall(SYS_execveat, fd, path, args, vars, flags);
}

static int fp_and_state(uid_t expected_uid, int closed_fd)
{
    volatile double x = 1.25, y = 2.5;
    double sum = x + y;
    uint64_t in[2] = {17, 29}, out[2];
    uint64x2_t v = vld1q_u64(in);
    /* Force an actual vector operation, independent of compiler folding. */
    __asm__ volatile("add %0.2d, %0.2d, %0.2d" : "+w"(v));
    vst1q_u64(out, v);
    struct sigaction a, b;
    sigset_t blocked;
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe)-1);
    if (sum != 3.75 || out[0] != 34 || out[1] != 58 ||
        !getenv("BE6L_EXEC_ENV") || strcmp(getenv("BE6L_EXEC_ENV"), "preserved") ||
        sigaction(SIGUSR1, NULL, &a) || sigaction(SIGUSR2, NULL, &b) ||
        a.sa_handler != SIG_IGN || b.sa_handler != SIG_DFL || n <= 0 ||
        sigprocmask(SIG_SETMASK, NULL, &blocked) || !sigismember(&blocked, SIGTERM) ||
        getuid() != expected_uid || geteuid() != expected_uid ||
        (expected_uid == 65534 && (getgid() != 65534 || getegid() != 65534 || getgroups(0, NULL) != 0)))
        return 90;
    if (closed_fd >= 0 && (fcntl(closed_fd, F_GETFD) != -1 || errno != EBADF))
        return 97;
    exe[n] = 0;
    if (strstr(exe, "qemu") || !strstr(exe, "be6l-exec"))
        return 91;
    printf("LEAF_OK uid=%u euid=%u secure=%lu exe=%s\n",
           (unsigned)getuid(), (unsigned)geteuid(), getauxval(AT_SECURE), exe);
    fflush(stdout);
    return 0;
}

static void copy_self(const char *to, mode_t mode)
{
    int src = open(self, O_RDONLY), dst = open(to, O_WRONLY|O_CREAT|O_TRUNC, mode);
    char buf[16384];
    ssize_t n;
    if (src < 0 || dst < 0) _exit(80);
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        ssize_t done = 0;
        while (done < n) {
            ssize_t wrote = write(dst, buf+done, n-done);
            if (wrote <= 0) _exit(81);
            done += wrote;
        }
    }
    if (n < 0 || close(src) || close(dst) || chmod(to, mode)) _exit(82);
}

static void execute_case(int which)
{
    int fd = -1, wanted_errno = 0;
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, handler);
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &blocked, NULL)) _exit(89);
    switch (which) {
    case 0: execve(self, leaf_argv, env); break;
    case 1: execveat(AT_FDCWD, self, leaf_argv, env, 0); break;
    case 2:
        fd = open("/bin", O_RDONLY|O_DIRECTORY);
        execveat(fd, "be6l-exec-probe", leaf_argv, env, 0); break;
    case 3:
        fd = open(self, O_RDONLY);
        execveat(fd, "", leaf_argv, env, AT_EMPTY_PATH); break;
    case 4:
        fd = open(self, O_RDONLY);
        fexecve(fd, leaf_argv, env); break;
    case 5:
        copy_self("/tmp/be6l-exec-unlinked", 0755);
        fd = open("/tmp/be6l-exec-unlinked", O_RDONLY);
        if (unlink("/tmp/be6l-exec-unlinked")) _exit(83);
        execveat(fd, "", leaf_argv, env, AT_EMPTY_PATH); break;
    case 6: {
        int s = open("/tmp/be6l-exec-script", O_CREAT|O_TRUNC|O_WRONLY, 0755);
        const char script[] = "#!/bin/be6l-exec-probe --script\nignored fixture body\n";
        if (s < 0 || write(s, script, sizeof(script)-1) != sizeof(script)-1 || close(s)) _exit(84);
        char *args[] = {"script-custom-argv0", "token", NULL};
        execve("/tmp/be6l-exec-script", args, env); break;
    }
    case 7:
        if (chdir("/bin")) _exit(85);
        execve("./be6l-exec-probe", leaf_argv, env); break;
    case 8: execve("/proc/self/exe", leaf_argv, env); break;
    case 9:
        copy_self("/tmp/be6l-exec-no-x", 0644);
        wanted_errno = EACCES;
        execve("/tmp/be6l-exec-no-x", leaf_argv, env); break;
    case 10:
        wanted_errno = ENOENT;
        execve("/tmp/be6l-exec-nonexistent", leaf_argv, env); break;
    case 11:
        unlink("/tmp/be6l-exec-link");
        if (symlink(self, "/tmp/be6l-exec-link")) _exit(86);
        wanted_errno = ELOOP;
        execveat(AT_FDCWD, "/tmp/be6l-exec-link", leaf_argv, env, AT_SYMLINK_NOFOLLOW); break;
    case 12: {
        if (setgroups(0, NULL) || setgid(65534) || setuid(65534)) _exit(87);
        char *args[] = {"be6l-custom-argv0", "--leaf", "uid65534", NULL};
        execve(self, args, env); break;
    }
    case 13: {
        fd = open(self, O_RDONLY);
        int high = fcntl(fd, F_DUPFD_CLOEXEC, 200);
        if (high < 0 || close(fd)) _exit(98);
        char token[32];
        snprintf(token, sizeof(token), "closed:%d", high);
        char *args[] = {"be6l-custom-argv0", "--leaf", token, NULL};
        execveat(high, "", args, env, AT_EMPTY_PATH); break;
    }
    case 14:
        fd = open("/bin", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        execveat(fd, "be6l-exec-probe", leaf_argv, env, 0); break;
    case 15:
        fd = open("/bin", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        execveat(fd, "be6l-exec-probe", leaf_argv, env, AT_SYMLINK_NOFOLLOW); break;
    case 16:
        fd = open("/tmp/be6l-exec-script", O_RDONLY|O_CLOEXEC);
        wanted_errno = ENOENT; /* Native script interpreter cannot reopen this closed fd. */
        execveat(fd, "", leaf_argv, env, AT_EMPTY_PATH); break;
    case 17:
        fd = open("/tmp/be6l-exec-no-x", O_RDONLY|O_CLOEXEC);
        wanted_errno = EACCES;
        execveat(fd, "", leaf_argv, env, AT_EMPTY_PATH); break;
    case 18:
        fd = open("/tmp", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        wanted_errno = ELOOP;
        execveat(fd, "be6l-exec-link", leaf_argv, env, AT_SYMLINK_NOFOLLOW); break;
    case 19:
        fd = open(self, O_RDONLY|O_CLOEXEC);
        wanted_errno = EINVAL;
        execveat(fd, "", leaf_argv, env, AT_EMPTY_PATH|0x40000000); break;
    }
    int actual_errno = errno;
    if (wanted_errno && actual_errno == wanted_errno) {
        printf("EXPECTED_ERRNO_OK case=%d errno=%d\n", which, actual_errno);
        fflush(stdout);
        _exit(0);
    }
    fprintf(stderr, "EXEC_FAILED case=%d errno=%d wanted=%d\n", which, actual_errno, wanted_errno);
    _exit(88);
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--leaf")) {
        if (strcmp(argv[0], "be6l-custom-argv0")) return 92;
        uid_t uid = 0;
        int closed_fd = -1;
        if (!strcmp(argv[2], "uid65534")) uid = 65534;
        else if (!strncmp(argv[2], "closed:", 7)) closed_fd = atoi(argv[2]+7);
        else if (strcmp(argv[2], "token")) return 92;
        return fp_and_state(uid, closed_fd);
    }
    if (argc == 4 && !strcmp(argv[1], "--script")) {
        if (strcmp(argv[0], self) || strcmp(argv[2], "/tmp/be6l-exec-script") ||
            strcmp(argv[3], "token")) return 93;
        return fp_and_state(0, -1);
    }
    if (argc != 1) return 96; /* Never turn malformed child arguments into another matrix. */
    const char *names[] = {"execve", "execveat-absolute", "execveat-dirfd",
        "execveat-empty-path", "fexecve", "unlinked-fd", "shebang-script",
        "relative-path", "proc-self-exe", "no-exec-permission", "missing-file",
        "symlink-nofollow", "dropped-credentials", "cloexec-fd",
        "cloexec-dirfd", "cloexec-dirfd-nofollow", "cloexec-script-rejected",
        "cloexec-no-exec-permission", "cloexec-symlink-nofollow", "invalid-execveat-flags"};
    int failed = 0;
    for (int i = 0; i < (int)(sizeof(names)/sizeof(names[0])); i++) {
        pid_t child = fork();
        int status;
        if (child < 0) return 94;
        if (!child) execute_case(i);
        if (waitpid(child, &status, 0) != child) return 95;
        int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        printf("EXEC_CASE %s %s status=%d\n", names[i], ok ? "PASS" : "FAIL", status);
        fflush(stdout);
        failed += !ok;
    }
    printf("EXEC_MATRIX cases=20 failures=%d\n", failed);
    return failed ? 1 : 0;
}
