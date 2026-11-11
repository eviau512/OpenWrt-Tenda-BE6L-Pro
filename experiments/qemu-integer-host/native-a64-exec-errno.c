/* SPDX-License-Identifier: MIT
 * Native ARM32 caller of standard A64 ELF, isolated guest RAM root only.
 * Every write/chmod is confined to a new mkdtemp fixture. Existing binaries,
 * interpreters, procfs and the host outside chroot are never modified.
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
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__arm__) || defined(__aarch64__)
#error Build this probe as the native ARM32 static control.
#endif

enum { CASES = 8, REPORT_MAGIC = 0x4e455252 };
struct fixture {
    const char *name;
    int expected_errno; /* zero means a successful --noop exec */
    int loader_exists;
    char program[96];
    char loader[96];
};
struct report {
    unsigned magic;
    int error, fds_before, fds_after, call_fd_before, call_fd_after;
    int program_write_open, loader_write_open;
};

static char scratch[] = "/tmp/ne-XXXXXX";
static char *const envp[] = { "PATH=/bin:/usr/bin", NULL };

static void die(const char *what)
{
    perror(what);
    exit(2);
}

static int guest_path_ok(const char *path)
{
    const char prefix[] = "/tmp/be6l-binfmt-stage-";
    size_t length = strlen(path), start = sizeof(prefix)-1;
    if (strncmp(path, prefix, start) || length <= start+6 ||
        strcmp(path+length-6, "/guest")) return 0;
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
    if (closedir(directory)) return -1;
    return count;
}

static void write_all(int fd, const void *data, size_t size)
{
    const unsigned char *p = data;
    while (size) {
        ssize_t written = write(fd, p, size);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) die("fixture write");
        p += written;
        size -= (size_t)written;
    }
}

static void copy_new(const char *from, const char *to, mode_t mode)
{
    /* A standard musl interpreter may be a symlink to libc.so. Reads remain
     * inside chroot; fstat below rejects devices and other non-regular inputs.
     * Exclusive destination creation never follows or replaces any old node.
     */
    int input = open(from, O_RDONLY|O_CLOEXEC);
    struct stat status;
    unsigned char data[16384];
    if (input < 0) die("copy input");
    if (fstat(input, &status) || !S_ISREG(status.st_mode)) die("copy input type");
    int output = open(to, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, mode);
    if (output < 0) die("copy exclusive output");
    for (;;) {
        ssize_t size = read(input, data, sizeof(data));
        if (size < 0 && errno == EINTR) continue;
        if (size < 0) die("copy read");
        if (!size) break;
        write_all(output, data, (size_t)size);
    }
    if (fchmod(output, mode) || close(output) || close(input)) die("copy close/mode");
}

static void read_elf64(int fd, Elf64_Ehdr *header)
{
    if (pread(fd, header, sizeof(*header), 0) != (ssize_t)sizeof(*header) ||
        memcmp(header->e_ident, "\177ELF\2\1", 6) || header->e_machine != EM_AARCH64 ||
        header->e_flags || header->e_phentsize != sizeof(Elf64_Phdr) ||
        !header->e_phnum || header->e_phnum > 65536U/sizeof(Elf64_Phdr)) {
        fprintf(stderr, "Expected unmodified standard A64 ELF64 source\n");
        exit(2);
    }
}

static Elf64_Phdr interp_header(int fd, const Elf64_Ehdr *header)
{
    Elf64_Phdr program;
    int found = 0;
    Elf64_Phdr answer = {0};
    for (unsigned i = 0; i < header->e_phnum; i++) {
        if (header->e_phoff > LONG_MAX ||
            pread(fd, &program, sizeof(program), (off_t)header->e_phoff+i*sizeof(program)) != (ssize_t)sizeof(program))
            die("read program header");
        if (program.p_type == PT_INTERP) { answer = program; found++; }
    }
    if (found != 1 || answer.p_filesz < 2 || answer.p_filesz > PATH_MAX || answer.p_offset > LONG_MAX) {
        fprintf(stderr, "Expected one bounded PT_INTERP\n");
        exit(2);
    }
    return answer;
}

static void source_loader(char loader[PATH_MAX])
{
    int fd = open("/bin/be6l-exec-corners", O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) die("open standard probe");
    Elf64_Ehdr header;
    read_elf64(fd, &header);
    Elf64_Phdr interp = interp_header(fd, &header);
    if (pread(fd, loader, (size_t)interp.p_filesz, (off_t)interp.p_offset) != (ssize_t)interp.p_filesz ||
        loader[interp.p_filesz-1] || strncmp(loader, "/lib/", 5) || strstr(loader, "..")) {
        fprintf(stderr, "Unexpected standard loader path\n");
        exit(2);
    }
    if (close(fd)) die("source close");
}

static void patch_interp(const char *program, const char *loader)
{
    int fd = open(program, O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) die("open own program");
    Elf64_Ehdr header;
    read_elf64(fd, &header);
    Elf64_Phdr interp = interp_header(fd, &header);
    size_t capacity = (size_t)interp.p_filesz;
    if (strlen(loader)+1 > capacity) { fprintf(stderr, "Fixture loader path too long\n"); exit(2); }
    char *replacement = calloc(1, capacity);
    if (!replacement) die("allocate path");
    memcpy(replacement, loader, strlen(loader));
    if (pwrite(fd, replacement, capacity, (off_t)interp.p_offset) != (ssize_t)capacity) die("patch own PT_INTERP");
    free(replacement);
    if (close(fd)) die("patch close");
}

static void prepare(struct fixture all[CASES])
{
    static const char *names[CASES] = { "success-control", "missing-loader", "loader-no-execute",
        "loader-bad-magic", "loader-short-header", "loader-not-directory",
        "original-no-execute", "original-bad-phentsize" };
    static const int errors[CASES] = {0, ENOENT, EACCES, ELIBBAD, EIO, ENOTDIR, EACCES, ENOEXEC};
    char real_loader[PATH_MAX];
    source_loader(real_loader);
    if (!mkdtemp(scratch)) die("mkdtemp");
    for (int i = 0; i < CASES; i++) {
        struct fixture *f = &all[i];
        f->name = names[i]; f->expected_errno = errors[i]; f->loader_exists = i != 1;
        if (snprintf(f->program, sizeof(f->program), "%s/p%d", scratch, i) >= (int)sizeof(f->program) ||
            snprintf(f->loader, sizeof(f->loader), "%s/l%d", scratch, i) >= (int)sizeof(f->loader)) die("fixture name");
        copy_new("/bin/be6l-exec-corners", f->program, 0755);
        if (i == 3 || i == 4 || i == 5) {
            int fd = open(f->loader, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW, 0755);
            unsigned char zero[sizeof(Elf64_Ehdr)] = {0};
            if (fd < 0) die("bad loader exclusive create");
            if (i != 5) write_all(fd, zero, i == 3 ? sizeof(zero) : 16);
            if (close(fd)) die("bad loader close");
        } else if (f->loader_exists) copy_new(real_loader, f->loader, i == 2 ? 0644 : 0755);
        char interp[100];
        if (snprintf(interp, sizeof(interp), "%s%s", f->loader, i == 5 ? "/x" : "") >= (int)sizeof(interp)) die("interp name");
        patch_interp(f->program, interp);
        if (i == 6 && chmod(f->program, 0644)) die("own program chmod");
        if (i == 7) {
            int fd = open(f->program, O_RDWR|O_CLOEXEC|O_NOFOLLOW);
            Elf64_Ehdr header; read_elf64(fd, &header); header.e_phentsize = 0;
            if (fd < 0 || pwrite(fd, &header, sizeof(header), 0) != (ssize_t)sizeof(header) || close(fd)) die("own phentsize");
        }
    }
}

static int nonwriting_open(const char *path)
{
    int fd = open(path, O_WRONLY|O_CLOEXEC|O_NOFOLLOW); /* no O_TRUNC, no write */
    int saved = errno;
    if (fd >= 0) close(fd);
    return fd >= 0 ? 0 : saved;
}

static int run_one(const struct fixture *f, int at)
{
    int channel[2], status;
    pid_t caller = getpid();
    int parent_fds_before = count_fds();
    if (pipe2(channel, O_CLOEXEC)) die("error pipe");
    pid_t child = fork();
    if (child < 0) die("fork");
    if (!child) {
        /* A timed out/terminated native parent must not leave a guest child. */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != caller) _exit(92);
        close(channel[0]);
        int fd = at ? open(f->program, O_RDONLY|O_CLOEXEC|O_NOFOLLOW) : -1;
        if (at && fd < 0) _exit(90);
        struct report r = {.magic = REPORT_MAGIC, .call_fd_before = at ? fcntl(fd, F_GETFD) : -1};
        r.fds_before = count_fds();
        char *args[] = {"be6l-corners", "--noop", NULL};
        if (at) syscall(SYS_execveat, fd, "", args, envp, AT_EMPTY_PATH);
        else execve(f->program, args, envp);
        r.error = errno;
        r.fds_after = count_fds();
        r.call_fd_after = at ? fcntl(fd, F_GETFD) : -1;
        r.program_write_open = nonwriting_open(f->program);
        r.loader_write_open = f->loader_exists ? nonwriting_open(f->loader) : -1;
        if (write(channel[1], &r, sizeof(r)) != (ssize_t)sizeof(r)) _exit(91);
        _exit(0);
    }
    close(channel[1]);
    struct report r = {0};
    unsigned char *destination = (void *)&r;
    size_t count = 0;
    alarm(20);
    while (count < sizeof(r)) {
        ssize_t got = read(channel[0], destination+count, sizeof(r)-count);
        if (got < 0 && errno == EINTR) continue;
        if (got < 0) die("error pipe read");
        if (!got) break;
        count += (size_t)got;
    }
    close(channel[0]);
    if (waitpid(child, &status, 0) != child) die("waitpid");
    alarm(0);
    int returned = count == sizeof(r) && r.magic == REPORT_MAGIC;
    int exited_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    int parent_fds_after = count_fds();
    int after_success_program = !f->expected_errno && exited_ok ? nonwriting_open(f->program) : -1;
    int after_success_loader = !f->expected_errno && exited_ok ? nonwriting_open(f->loader) : -1;
    int ok = !f->expected_errno ? !count && exited_ok :
        returned && exited_ok && r.error == f->expected_errno && r.fds_before >= 0 &&
        r.fds_before == r.fds_after && r.call_fd_before == r.call_fd_after &&
        (!at || (r.call_fd_after & FD_CLOEXEC)) && !r.program_write_open &&
        (!f->loader_exists || !r.loader_write_open);
    ok = ok && parent_fds_before >= 0 && parent_fds_before == parent_fds_after &&
         (f->expected_errno || (!after_success_program && !after_success_loader));
    printf("NATIVE_EXEC_ERRNO %s-%s %s expected=%d actual=%d caller_returned=%d fds=%d/%d fdflags=%d/%d program_write_errno=%d loader_write_errno=%d parent_fds=%d/%d after_success_write=%d/%d wait_status=%d\n",
        at ? "execveat-cloexec" : "execve", f->name, ok ? "PASS" : "FAIL", f->expected_errno,
        returned ? r.error : -1, returned, returned ? r.fds_before : -1, returned ? r.fds_after : -1,
        returned ? r.call_fd_before : -1, returned ? r.call_fd_after : -1,
        returned ? r.program_write_open : -1, returned ? r.loader_write_open : -1,
        parent_fds_before, parent_fds_after, after_success_program, after_success_loader, status);
    fflush(stdout);
    return !ok;
}

int main(int argc, char **argv)
{
    struct stat directory;
    if (argc != 2 || !guest_path_ok(argv[1]) || lstat(argv[1], &directory) ||
        !S_ISDIR(directory.st_mode) || directory.st_uid != 0) {
        fprintf(stderr, "Use the owned /tmp/be6l-binfmt-stage-<id>/guest directory\n");
        return 2;
    }
    if (chroot(argv[1]) || chdir("/")) die("isolated chroot");
    struct fixture all[CASES] = {0};
    prepare(all);
    int failed = 0;
    for (int at = 0; at < 2; at++)
        for (int i = 0; i < CASES; i++) failed += run_one(&all[i], at);
    for (int i = 0; i < CASES; i++) {
        if (unlink(all[i].program) || (all[i].loader_exists && unlink(all[i].loader))) die("own fixture cleanup");
    }
    if (rmdir(scratch)) die("own fixture directory cleanup");
    printf("NATIVE_EXEC_ERRNO_SUMMARY cases=%d failures=%d\n", CASES*2, failed);
    return failed ? 1 : 0;
}
