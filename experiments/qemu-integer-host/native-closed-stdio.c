/* SPDX-License-Identifier: MIT
 * Native ARM32 parent: close child stdio, preserve a report pipe >=3, and
 * dispatch dynamic/synthetic-static A64 via execve or execveat(CLOEXEC).
 * Writes are confined to a fresh mkdtemp in the admitted guest RAM chroot.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "closed-stdio-wire.h"

#if !defined(__arm__) || defined(__aarch64__)
#error Native static ARM32 parent required.
#endif

static char scratch[] = "/tmp/cs-XXXXXX";
static char program[2][80], loader[80];
static int made_scratch, cleanup_done, cleanup_errors;
static volatile sig_atomic_t active_child, interrupted;
static const unsigned masks[] = {1, 2, 4, 7};
static char *const envp[] = {"PATH=/bin:/usr/bin", NULL};

static void signal_handler(int sig)
{
    interrupted = sig;
    if (active_child > 0) kill((pid_t)active_child, SIGKILL);
}

static void kill_child(void)
{
    pid_t child = active_child;
    if (child <= 0) return;
    kill(child, SIGKILL);
    for (int i = 0; i < 100; i++) {
        int status;
        pid_t got = waitpid(child, &status, WNOHANG);
        if (got == child || (got < 0 && errno == ECHILD)) { active_child = 0; return; }
        struct timespec delay = {0, 20000000}; nanosleep(&delay, NULL);
    }
    cleanup_errors++;
}

static void cleanup(void)
{
    if (cleanup_done) return;
    cleanup_done = 1; alarm(0); kill_child();
    if (!made_scratch) return;
    const char *paths[] = {program[0], program[1], loader};
    for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++)
        if (*paths[i] && unlink(paths[i]) && errno != ENOENT) cleanup_errors++;
    if (rmdir(scratch)) cleanup_errors++;
}

static void die(const char *what) { perror(what); exit(2); }

static int guest_path_ok(const char *s)
{
    const char prefix[] = "/tmp/be6l-binfmt-stage-";
    size_t n = strlen(s), start = sizeof(prefix)-1;
    if (strncmp(s, prefix, start) || n <= start+6 || strcmp(s+n-6, "/guest")) return 0;
    for (size_t i = start; i < n-6; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '-')) return 0;
    return 1;
}

static int high_fd(int fd)
{
    if (fd < 0) return -1;
    if (fd >= 3) return fd;
    int moved = fcntl(fd, F_DUPFD_CLOEXEC, 3), saved = errno;
    close(fd); errno = saved; return moved;
}

static int count_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e; int n = 0;
    if (!d) return -1;
    while ((e = readdir(d))) {
        char *end; long fd = strtol(e->d_name, &end, 10);
        if (*e->d_name && !*end && fd >= 0 && fd != dirfd(d)) n++;
    }
    return closedir(d) ? -1 : n;
}

static void copy_new(const char *from, const char *to)
{
    int input = open(from, O_RDONLY|O_CLOEXEC);
    struct stat status;
    if (input < 0 || fstat(input, &status) || !S_ISREG(status.st_mode)) die("regular source");
    int output = open(to, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0755);
    if (output < 0) die("exclusive fixture create");
    unsigned char data[16384];
    for (;;) {
        ssize_t n = read(input, data, sizeof(data));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) die("fixture read");
        if (!n) break;
        for (ssize_t done = 0; done < n;) {
            ssize_t wrote = write(output, data+done, (size_t)(n-done));
            if (wrote < 0 && errno == EINTR) continue;
            if (wrote <= 0) die("fixture write");
            done += wrote;
        }
    }
    if (fchmod(output, 0755) || close(output) || close(input)) die("fixture mode/close");
}

static Elf64_Phdr interp(int fd, int dynamic)
{
    Elf64_Ehdr h;
    Elf64_Phdr ph, answer = {0}; int found = 0;
    if (pread(fd, &h, sizeof(h), 0) != (ssize_t)sizeof(h) ||
        memcmp(h.e_ident, "\177ELF\2\1\1", 7) || h.e_machine != EM_AARCH64 || h.e_flags ||
        h.e_phentsize != sizeof(ph) || !h.e_phnum || h.e_phnum > 65536U/sizeof(ph) || h.e_phoff > LONG_MAX)
        die("A64 fixture ELF header");
    for (unsigned i = 0; i < h.e_phnum; i++) {
        uint64_t offset = h.e_phoff+i*sizeof(ph);
        if (offset > LONG_MAX || pread(fd, &ph, sizeof(ph), (off_t)offset) != (ssize_t)sizeof(ph)) die("fixture phdr");
        if (ph.p_type == PT_INTERP) { answer = ph; found++; }
    }
    if (found != dynamic || (dynamic && (answer.p_filesz < 2 || answer.p_filesz > PATH_MAX || answer.p_offset > LONG_MAX)))
        die("fixture PT_INTERP count/bounds");
    return answer;
}

static void prepare(void)
{
    if (!mkdtemp(scratch)) die("own mkdtemp");
    made_scratch = 1;
    snprintf(program[0], sizeof(program[0]), "%s/d", scratch);
    snprintf(program[1], sizeof(program[1]), "%s/s", scratch);
    snprintf(loader, sizeof(loader), "%s/l", scratch);
    copy_new("/bin/be6l-closed-stdio-dynamic", program[0]);
    copy_new("/bin/be6l-closed-stdio-static-synthetic", program[1]);
    int fd = open(program[1], O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) die("static fixture open");
    (void)interp(fd, 0);
    if (close(fd)) die("static fixture close");
    fd = open(program[0], O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) die("own dynamic fixture open");
    Elf64_Phdr ph = interp(fd, 1);
    char real_loader[PATH_MAX];
    if (pread(fd, real_loader, (size_t)ph.p_filesz, (off_t)ph.p_offset) != (ssize_t)ph.p_filesz ||
        real_loader[ph.p_filesz-1] || memchr(real_loader, 0, (size_t)ph.p_filesz-1) ||
        strncmp(real_loader, "/lib/", 5) || strstr(real_loader, "..") || strlen(loader)+1 > ph.p_filesz)
        die("normal dynamic fixture loader path");
    copy_new(real_loader, loader);
    char *replacement = calloc(1, (size_t)ph.p_filesz);
    if (!replacement) die("own PT_INTERP buffer");
    memcpy(replacement, loader, strlen(loader));
    if (pwrite(fd, replacement, (size_t)ph.p_filesz, (off_t)ph.p_offset) != (ssize_t)ph.p_filesz) die("own PT_INTERP patch");
    free(replacement);
    if (close(fd)) die("own dynamic fixture close");
}

static int writable(const char *path)
{
    int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW); /* never O_TRUNC or write */
    int saved = errno;
    if (fd >= 0 && close(fd)) return errno;
    return fd >= 0 ? 0 : saved;
}

static int run_one(int kind, int at, unsigned mask)
{
    int flags[3], expected_mask = (int)mask, channel[2], before = count_fds(), status = -1;
    struct stat original[3] = {{0}}, pstat, lstatbuf;
    if (stat(program[kind], &pstat) || stat(loader, &lstatbuf)) die("own fixture stat");
    for (int fd = 0; fd < 3; fd++) {
        flags[fd] = fcntl(fd, F_GETFD);
        if (flags[fd] < 0) {
            if (errno != EBADF) die("original stdio flags");
            expected_mask |= 1 << fd;
        } else if (flags[fd] & FD_CLOEXEC) expected_mask |= 1 << fd;
        else if (fstat(fd, &original[fd])) die("original stdio inode");
    }
    if (pipe2(channel, O_CLOEXEC)) die("report pipe");
    channel[0] = high_fd(channel[0]); channel[1] = high_fd(channel[1]);
    if (channel[0] < 3 || channel[1] < 3 || channel[1] >= CLOSED_STDIO_SCAN_LIMIT-8) die("report pipe >=3");
    pid_t caller = getpid(), child = fork();
    if (child < 0) die("fork");
    if (!child) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != caller) _exit(90);
        close(channel[0]);
        if (fcntl(channel[1], F_SETFD, 0)) _exit(91);
        int execfd = at ? high_fd(open(program[kind], O_RDONLY|O_CLOEXEC|O_NOFOLLOW)) : -1;
        if (at && (execfd < 3 || execfd >= CLOSED_STDIO_SCAN_LIMIT-8 || fcntl(execfd, F_GETFD) != FD_CLOEXEC)) _exit(92);
        char values[6][32];
        snprintf(values[0], sizeof(values[0]), "%d", channel[1]);
        snprintf(values[1], sizeof(values[1]), "%u", (unsigned)expected_mask);
        snprintf(values[2], sizeof(values[2]), "%llu", (unsigned long long)pstat.st_dev);
        snprintf(values[3], sizeof(values[3]), "%llu", (unsigned long long)pstat.st_ino);
        snprintf(values[4], sizeof(values[4]), "%llu", kind ? 0ULL : (unsigned long long)lstatbuf.st_dev);
        snprintf(values[5], sizeof(values[5]), "%llu", kind ? 0ULL : (unsigned long long)lstatbuf.st_ino);
        char *args[] = {"be6l-closed-stdio", values[0], values[1], values[2], values[3], values[4], values[5], NULL};
        for (int fd = 0; fd < 3; fd++) if (mask & (1U << fd)) close(fd);
        if (at) syscall(SYS_execveat, execfd, "", args, envp, AT_EMPTY_PATH);
        else execve(program[kind], args, envp);
        struct closed_stdio_report failed = {.magic = CLOSED_STDIO_MAGIC, .version = 1, .exec_errno = errno};
        (void)write(channel[1], &failed, sizeof(failed)); _exit(93);
    }
    active_child = child;
    close(channel[1]);
    struct closed_stdio_report report = {0};
    size_t size = 0;
    alarm(20);
    while (size < sizeof(report) && !interrupted) {
        ssize_t n = read(channel[0], (unsigned char *)&report+size, sizeof(report)-size);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) die("report read");
        if (!n) break;
        size += (size_t)n;
    }
    if (close(channel[0])) die("report close");
    pid_t got;
    do { got = waitpid(child, &status, 0); } while (got < 0 && errno == EINTR);
    if (got == child) active_child = 0;
    else kill_child();
    alarm(0);
    int after = count_fds(), program_write = writable(program[kind]), loader_write = writable(loader);
    int ok = size == sizeof(report) && report.magic == CLOSED_STDIO_MAGIC && report.version == 1 &&
        !report.exec_errno && report.report_fd >= 3 && report.report_fd < CLOSED_STDIO_SCAN_LIMIT &&
        report.helper_kind == (unsigned)kind && report.expected_mask == (unsigned)expected_mask &&
        WIFEXITED(status) && WEXITSTATUS(status) == 0 && !interrupted &&
        !report.program_aliases && !report.loader_aliases && !report.private_aux_entries && !report.private_aux_flags &&
        before >= 0 && before == after && !program_write && !loader_write;
    for (int fd = 0; fd < 3; fd++) {
        if (expected_mask & (1 << fd)) ok = ok && report.flags[fd] == -1 && report.errors[fd] == EBADF;
        else ok = ok && report.flags[fd] == 0 && !report.errors[fd] &&
            report.device[fd] == (uint64_t)original[fd].st_dev && report.inode[fd] == (uint64_t)original[fd].st_ino;
    }
    printf("NATIVE_CLOSED_STDIO %s-%s-close%u %s expected_mask=%u report_fd=%d guest_flags=%d/%d/%d guest_errno=%d/%d/%d aliases=%u/%u private_aux=%u/%u exec_errno=%d wait_status=%d parent_fds=%d/%d after_write_errno=%d/%d signal=%d\n",
        kind ? "synthetic-static" : "dynamic", at ? "execveat-cloexec" : "execve", mask, ok ? "PASS" : "FAIL",
        (unsigned)expected_mask, report.report_fd, report.flags[0], report.flags[1], report.flags[2],
        report.errors[0], report.errors[1], report.errors[2], report.program_aliases, report.loader_aliases,
        report.private_aux_entries, report.private_aux_flags, report.exec_errno, status, before, after,
        program_write, loader_write, (int)interrupted);
    fflush(stdout); return !ok;
}

int main(int argc, char **argv)
{
    struct stat directory;
    if (argc != 2 || geteuid() || !guest_path_ok(argv[1]) || lstat(argv[1], &directory) ||
        !S_ISDIR(directory.st_mode) || directory.st_uid != 0) {
        fprintf(stderr, "Use the owned /tmp/be6l-binfmt-stage-<id>/guest directory as root\n"); return 2;
    }
    if (chroot(argv[1]) || chdir("/")) die("isolated chroot");
    if (atexit(cleanup)) die("atexit");
    struct sigaction action = {.sa_handler = signal_handler};
    sigemptyset(&action.sa_mask);
    const int signals[] = {SIGALRM, SIGTERM, SIGINT, SIGHUP};
    for (unsigned i = 0; i < sizeof(signals)/sizeof(signals[0]); i++)
        if (sigaction(signals[i], &action, NULL)) die("signal handler");
    prepare();
    int completed = 0, failed = 0;
    for (int kind = 0; kind < 2 && !interrupted; kind++)
        for (int at = 0; at < 2 && !interrupted; at++)
            for (unsigned i = 0; i < sizeof(masks)/sizeof(masks[0]) && !interrupted; i++) {
                failed += run_one(kind, at, masks[i]); completed++;
            }
    cleanup();
    printf("NATIVE_CLOSED_STDIO_SUMMARY cases=%d failures=%d cleanup_errors=%d static_fixture_synthetic=1 secureexec_covered=0\n",
        completed, failed, cleanup_errors);
    return failed || completed != 16 || cleanup_errors ? 1 : 0;
}
