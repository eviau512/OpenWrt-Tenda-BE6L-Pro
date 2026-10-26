/* SPDX-License-Identifier: MIT */
/* Diagnostic-only launcher: private mount/network/PID namespaces and chroot.
 * No host network service, configuration file or device other than the three
 * standard character devices is passed into the fixture. */
#define _GNU_SOURCE
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t child_pid = -1;
static volatile sig_atomic_t expired;
static void deadline(int signal_number)
{
    (void)signal_number;
    expired = 1;
    if (child_pid > 0) kill(child_pid, SIGKILL);
}
static void fail(const char *label)
{
    perror(label);
    _exit(77);
}
int main(int argc, char **argv)
{
    static const char prefix[] = "/tmp/be6l-native-netifd-";
    const struct rlimit core = {0, 0};
    struct stat info;
    char path[PATH_MAX];
    int status;
    if (argc != 2 || geteuid() != 0 ||
        strncmp(argv[1], prefix, sizeof(prefix)-1) ||
        strlen(argv[1]) != sizeof(prefix)-1+32 ||
        strspn(argv[1]+sizeof(prefix)-1, "0123456789abcdef") != 32 ||
        lstat(argv[1], &info) || !S_ISDIR(info.st_mode) || info.st_uid != 0)
        return 64;
    if (setrlimit(RLIMIT_CORE, &core)) fail("core limit");
    if (unshare(CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWPID)) fail("private namespaces");
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) fail("private mount propagation");
    pid_t pid = fork();
    if (pid < 0) fail("fork");
    if (!pid) {
        if (getpid() != 1 || prctl(PR_SET_PDEATHSIG, SIGKILL)) fail("private PID1");
        snprintf(path, sizeof(path), "%s/proc", argv[1]);
        if (mount("proc", path, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL)) fail("private proc");
        snprintf(path, sizeof(path), "%s/sys", argv[1]);
        if (mount("sysfs", path, "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL)) fail("private sysfs");
        const char *names[] = {"null", "random", "urandom"};
        for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
            char device[32];
            snprintf(device, sizeof(device), "/dev/%s", names[i]);
            snprintf(path, sizeof(path), "%s/dev/%s", argv[1], names[i]);
            if (mount(device, path, NULL, MS_BIND, NULL)) fail("standard device bind");
        }
        if (chroot(argv[1]) || chdir("/")) fail("private chroot");
        clearenv();
        setenv("PATH", "/opt/be6l-a64-soft/bin:/bin:/usr/bin", 1);
        execl("/bin/sh", "sh", "/probe.sh", (char *)NULL);
        fail("private probe exec");
    }
    child_pid = pid;
    struct sigaction action = {0};
    action.sa_handler = deadline;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL)) {kill(pid, SIGKILL); fail("deadline handler");}
    alarm(60);
    while (waitpid(pid, &status, 0) < 0) if (errno != EINTR) fail("waitpid");
    alarm(0);
    if (expired) return 124;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
}
