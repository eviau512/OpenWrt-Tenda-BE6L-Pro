/* SPDX-License-Identifier: MIT
 * Native ARM32 ptrace control of a standard-A64 guest exec. All mutations are
 * private mkdtemp fixtures inside a separately admitted guest RAM chroot.
 * TRACEEXEC stops after kernel exec dispatch and before the first native QEMU
 * user instruction. This does not exercise secureexec or grant qualification.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !defined(__arm__) || defined(__aarch64__)
#error Build this probe as a native static ARM32 control.
#endif

enum { CASES = 4 };
struct fixture { char program[80], loader[80], renamed[80]; };
static struct fixture fixtures[CASES];
static char scratch[] = "/tmp/ni-XXXXXX";
static char *const envp[] = { "PATH=/bin:/usr/bin", NULL };
static volatile sig_atomic_t active_child, interrupted;
static int scratch_created, cleanup_done, cleanup_errors;

static void on_signal(int sig)
{
    interrupted = sig;
    if (active_child > 0) kill((pid_t)active_child, SIGKILL);
}

static void kill_child(void)
{
    pid_t child = (pid_t)active_child;
    if (child <= 0) return;
    kill(child, SIGKILL);
    for (int i = 0; i < 100; i++) {
        int status;
        pid_t got = waitpid(child, &status, WNOHANG);
        if ((got == child && (WIFEXITED(status) || WIFSIGNALED(status))) ||
                (got < 0 && errno == ECHILD)) { active_child = 0; return; }
        if (got == child && WIFSTOPPED(status))
            ptrace(PTRACE_CONT, child, NULL, (void *)(uintptr_t)SIGKILL);
        struct timespec delay = {0, 20000000};
        nanosleep(&delay, NULL);
    }
    /* EXITKILL and child PDEATHSIG additionally bind it to tracer lifetime. */
    cleanup_errors++;
}

static void cleanup(void)
{
    if (cleanup_done) return;
    cleanup_done = 1;
    alarm(0);
    kill_child();
    if (!scratch_created) return;
    for (int i = 0; i < CASES; i++) {
        const char *paths[] = {fixtures[i].program, fixtures[i].loader, fixtures[i].renamed};
        for (unsigned j = 0; j < sizeof(paths)/sizeof(paths[0]); j++)
            if (*paths[j] && unlink(paths[j]) && errno != ENOENT) cleanup_errors++;
    }
    if (rmdir(scratch)) cleanup_errors++;
    if (cleanup_errors) fprintf(stderr, "own fixture cleanup errors=%d\n", cleanup_errors);
}

static void die(const char *what) { perror(what); exit(2); }

static int guest_path_ok(const char *path)
{
    const char prefix[] = "/tmp/be6l-binfmt-stage-";
    size_t length = strlen(path), start = sizeof(prefix)-1;
    if (strncmp(path, prefix, start) || length <= start+6 || strcmp(path+length-6, "/guest")) return 0;
    for (size_t i = start; i < length-6; i++)
        if (!((path[i] >= 'a' && path[i] <= 'z') ||
              (path[i] >= '0' && path[i] <= '9') || path[i] == '-')) return 0;
    return 1;
}

static int count_fds(void)
{
    DIR *directory = opendir("/proc/self/fd");
    struct dirent *entry;
    int count = 0;
    if (!directory) return -1;
    while ((entry = readdir(directory))) {
        char *end;
        long number = strtol(entry->d_name, &end, 10);
        if (*entry->d_name && !*end && number >= 0 && number != dirfd(directory)) count++;
    }
    return closedir(directory) ? -1 : count;
}

static void write_all(int fd, const void *data, size_t size)
{
    const unsigned char *p = data;
    while (size) {
        ssize_t written = write(fd, p, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) die("fixture write");
        p += written; size -= (size_t)written;
    }
}

static void copy_new(const char *from, const char *to)
{
    /* The real musl loader may be a symlink; input following stays in chroot. */
    int input = open(from, O_RDONLY|O_CLOEXEC);
    struct stat status;
    unsigned char data[16384];
    if (input < 0 || fstat(input, &status) || !S_ISREG(status.st_mode)) die("copy regular input");
    int output = open(to, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0755);
    if (output < 0) die("copy exclusive output");
    for (;;) {
        ssize_t size = read(input, data, sizeof(data));
        if (size < 0 && errno == EINTR) continue;
        if (size < 0) die("copy read");
        if (!size) break;
        write_all(output, data, (size_t)size);
    }
    if (fchmod(output, 0755) || close(output) || close(input)) die("copy close/mode");
}

static Elf64_Phdr read_interp(int fd)
{
    Elf64_Ehdr header;
    Elf64_Phdr answer = {0}, program;
    int found = 0;
    if (pread(fd, &header, sizeof(header), 0) != (ssize_t)sizeof(header) ||
        memcmp(header.e_ident, "\177ELF\2\1\1", 7) || header.e_machine != EM_AARCH64 ||
        header.e_flags || (header.e_type != ET_EXEC && header.e_type != ET_DYN) ||
        header.e_phentsize != sizeof(Elf64_Phdr) || !header.e_phnum ||
        header.e_phnum > 65536U/sizeof(Elf64_Phdr) || header.e_phoff > LONG_MAX) {
        fprintf(stderr, "Expected unmodified standard A64 ELF source\n"); exit(2);
    }
    for (unsigned i = 0; i < header.e_phnum; i++) {
        uint64_t offset = header.e_phoff + i*sizeof(program);
        if (offset > LONG_MAX || pread(fd, &program, sizeof(program), (off_t)offset) != (ssize_t)sizeof(program))
            die("program header read");
        if (program.p_type == PT_INTERP) { answer = program; found++; }
    }
    if (found != 1 || answer.p_filesz < 2 || answer.p_filesz > PATH_MAX || answer.p_offset > LONG_MAX) {
        fprintf(stderr, "Expected one bounded PT_INTERP\n"); exit(2);
    }
    return answer;
}

static void prepare(void)
{
    char loader[PATH_MAX];
    int source = open("/bin/be6l-exec-corners", O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (source < 0) die("standard probe input");
    Elf64_Phdr interp = read_interp(source);
    if (pread(source, loader, (size_t)interp.p_filesz, (off_t)interp.p_offset) != (ssize_t)interp.p_filesz ||
        loader[interp.p_filesz-1] || memchr(loader, 0, (size_t)interp.p_filesz-1) ||
        strncmp(loader, "/lib/", 5) || strstr(loader, "..")) {
        fprintf(stderr, "Unexpected standard loader path\n"); exit(2);
    }
    if (close(source)) die("source close");
    if (!mkdtemp(scratch)) die("mkdtemp");
    scratch_created = 1;
    for (int i = 0; i < CASES; i++) {
        struct fixture *f = &fixtures[i];
        if (snprintf(f->program, sizeof(f->program), "%s/p%d", scratch, i) >= (int)sizeof(f->program) ||
            snprintf(f->loader, sizeof(f->loader), "%s/l%d", scratch, i) >= (int)sizeof(f->loader) ||
            snprintf(f->renamed, sizeof(f->renamed), "%s/r%d", scratch, i) >= (int)sizeof(f->renamed)) die("fixture name");
        copy_new("/bin/be6l-exec-corners", f->program);
        copy_new(loader, f->loader);
        int fd = open(f->program, O_RDWR|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0) die("own program open");
        interp = read_interp(fd);
        size_t length = (size_t)interp.p_filesz;
        if (strlen(f->loader)+1 > length) { fprintf(stderr, "Own loader path exceeds PT_INTERP\n"); exit(2); }
        char *replacement = calloc(1, length);
        if (!replacement) die("path allocation");
        memcpy(replacement, f->loader, strlen(f->loader));
        if (pwrite(fd, replacement, length, (off_t)interp.p_offset) != (ssize_t)length) die("own PT_INTERP patch");
        free(replacement);
        if (close(fd)) die("own program close");
    }
}

static int nonwriting_open(const char *path)
{
    int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW); /* no truncation or write */
    int saved = errno;
    if (fd >= 0 && close(fd)) return errno;
    return fd >= 0 ? 0 : saved;
}

static pid_t wait_state(pid_t child, int *status)
{
    for (;;) {
        if (interrupted) { errno = EINTR; return -1; }
        pid_t got = waitpid(child, status, WUNTRACED);
        if (got < 0 && errno == EINTR) continue;
        if (got == child && (WIFEXITED(*status) || WIFSIGNALED(*status))) active_child = 0;
        return got;
    }
}

static int run_one(int index)
{
    const struct fixture *f = &fixtures[index];
    int at = index >= 2, swap = index & 1;
    int channel[2], status = -1, child_errno = -1, event = 0, setup_errno = 0;
    int before = count_fds(), held_before = -1, held_after = -1, replacement_write = -1;
    int program_after = -1, loader_after = -1, inode_preserved = 0, replacement_distinct = 0;
    struct stat original = {0}, renamed = {0}, replacement = {0};
    if (pipe2(channel, O_CLOEXEC|O_NONBLOCK)) die("report pipe");
    pid_t caller = getpid(), child = fork();
    if (child < 0) die("fork");
    if (!child) {
        close(channel[0]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != caller) _exit(90);
        int fd = at ? open(f->program, O_RDONLY|O_CLOEXEC|O_NOFOLLOW) : -1;
        if ((at && (fd < 0 || !(fcntl(fd, F_GETFD) & FD_CLOEXEC))) ||
            ptrace(PTRACE_TRACEME, 0, NULL, NULL) || raise(SIGSTOP)) {
            int saved = errno; (void)write(channel[1], &saved, sizeof(saved)); _exit(91);
        }
        char *args[] = {"be6l-corners", "--noop", NULL};
        if (at) syscall(SYS_execveat, fd, "", args, envp, AT_EMPTY_PATH);
        else execve(f->program, args, envp);
        int saved = errno; (void)write(channel[1], &saved, sizeof(saved)); _exit(92);
    }
    active_child = child;
    close(channel[1]);
    alarm(20);
    if (wait_state(child, &status) != child || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) goto finish;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)(uintptr_t)(PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL)) ||
        ptrace(PTRACE_CONT, child, NULL, NULL)) { setup_errno = errno; goto finish; }
    if (wait_state(child, &status) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGTRAP || ((unsigned)status >> 16) != PTRACE_EVENT_EXEC) goto finish;
    event = 1;
    held_before = nonwriting_open(f->loader);
    if (lstat(f->loader, &original) || !S_ISREG(original.st_mode)) die("own original loader stat");
    if (swap) {
        if (!lstat(f->renamed, &renamed) || errno != ENOENT) die("own renamed destination occupied");
        if (rename(f->loader, f->renamed)) die("own loader rename");
        int fd = open(f->loader, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0755);
        unsigned char bad[sizeof(Elf64_Ehdr)] = {0};
        if (fd < 0) die("own bad replacement create");
        write_all(fd, bad, sizeof(bad));
        if (fchmod(fd, 0755) || close(fd)) die("own bad replacement close");
        if (lstat(f->renamed, &renamed) || lstat(f->loader, &replacement)) die("own replacement stat");
        inode_preserved = original.st_dev == renamed.st_dev && original.st_ino == renamed.st_ino;
        replacement_distinct = original.st_dev != replacement.st_dev || original.st_ino != replacement.st_ino;
        held_after = nonwriting_open(f->renamed);
        replacement_write = nonwriting_open(f->loader);
    } else {
        inode_preserved = 1;
        held_after = nonwriting_open(f->loader);
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL)) { setup_errno = errno; goto finish; }
    if (wait_state(child, &status) != child) goto finish;
finish:
    alarm(0);
    if (active_child) kill_child();
    ssize_t got = read(channel[0], &child_errno, sizeof(child_errno));
    if (got != (ssize_t)sizeof(child_errno)) child_errno = -1;
    if (close(channel[0])) die("report close");
    int exited = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (!active_child) {
        program_after = nonwriting_open(f->program);
        loader_after = nonwriting_open(swap && event ? f->renamed : f->loader);
    }
    int after = count_fds();
    int ok = event && exited && !interrupted && !setup_errno && child_errno == -1 &&
        held_before == ETXTBSY && held_after == ETXTBSY && inode_preserved &&
        (!swap || (replacement_distinct && !replacement_write)) &&
        !program_after && !loader_after && before >= 0 && before == after && !cleanup_errors;
    printf("NATIVE_LOADER_INODE %s-%s %s exec_event=%d held_errno=%d/%d same_inode=%d replacement_distinct=%d replacement_write_errno=%d after_write_errno=%d/%d child_exec_errno=%d setup_errno=%d wait_status=%d parent_fds=%d/%d signal=%d\n",
        at ? "execveat-cloexec" : "execve", swap ? "rename-bad-path" : "control", ok ? "PASS" : "FAIL",
        event, held_before, held_after, inode_preserved, replacement_distinct, replacement_write,
        program_after, loader_after, child_errno, setup_errno, status, before, after, (int)interrupted);
    fflush(stdout);
    return !ok;
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
    struct sigaction action = {.sa_handler = on_signal};
    sigemptyset(&action.sa_mask);
    const int signals[] = {SIGALRM, SIGTERM, SIGINT, SIGHUP};
    for (unsigned i = 0; i < sizeof(signals)/sizeof(signals[0]); i++)
        if (sigaction(signals[i], &action, NULL)) die("signal handler");
    prepare();
    int failures = 0, completed = 0;
    for (int i = 0; i < CASES && !interrupted; i++) { failures += run_one(i); completed++; }
    cleanup();
    printf("NATIVE_LOADER_INODE_SUMMARY cases=%d failures=%d cleanup_errors=%d secureexec_covered=0\n",
        completed, failures, cleanup_errors);
    return failures || cleanup_errors || completed != CASES ? 1 : 0;
}
