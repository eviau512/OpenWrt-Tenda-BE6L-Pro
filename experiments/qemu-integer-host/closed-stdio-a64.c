/* SPDX-License-Identifier: MIT
 * Observe guest descriptors using raw A64 syscalls. Dynamic mode uses normal
 * libc startup; static mode is a synthetic freestanding integer fixture and
 * deliberately links no libc or compiler runtime archive.
 */
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include "closed-stdio-wire.h"

#ifndef __aarch64__
#error A64 guest fixture required.
#endif

static long call3(long number, long a, long b, long c)
{
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
    return x0;
}

static int number(const char *s, uint64_t *value)
{
    uint64_t answer = 0;
    if (!*s) return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9' || answer > (UINT64_MAX-(unsigned)(*s-'0'))/10) return -1;
        answer = answer*10+(unsigned)(*s-'0');
    }
    *value = answer;
    return 0;
}

static int observe(int argc, char **argv, char **envp)
{
    uint64_t values[6];
    if (argc != 7) return 80;
    for (int i = 0; i < 6; i++) if (number(argv[i+1], &values[i])) return 81;
    if (values[0] < 3 || values[0] >= CLOSED_STDIO_SCAN_LIMIT || values[1] > 7) return 82;
    struct closed_stdio_report report;
    unsigned char *bytes = (void *)&report;
    for (unsigned i = 0; i < sizeof(report); i++) bytes[i] = 0;
    report.magic = CLOSED_STDIO_MAGIC; report.version = 1;
    report.report_fd = (int)values[0]; report.expected_mask = (unsigned)values[1];
#ifdef CLOSED_STDIO_FREESTANDING
    report.helper_kind = 1;
#endif
    for (int fd = 0; fd < 3; fd++) {
        long result = call3(SYS_fcntl, fd, F_GETFD, 0);
        report.flags[fd] = result < 0 ? -1 : (int)result;
        report.errors[fd] = result < 0 ? (int)-result : 0;
        if (result >= 0) {
            struct stat status;
            if (call3(SYS_fstat, fd, (long)&status, 0) < 0) return 83;
            report.device[fd] = status.st_dev; report.inode[fd] = status.st_ino;
        }
    }
    for (int fd = 0; fd < CLOSED_STDIO_SCAN_LIMIT; fd++) {
        struct stat status;
        if (call3(SYS_fstat, fd, (long)&status, 0) < 0) continue;
        if ((uint64_t)status.st_dev == values[2] && (uint64_t)status.st_ino == values[3]) report.program_aliases++;
        if (values[5] && (uint64_t)status.st_dev == values[4] && (uint64_t)status.st_ino == values[5]) report.loader_aliases++;
    }
    while (*envp) envp++;
    uintptr_t *aux = (uintptr_t *)(envp+1);
    for (unsigned i = 0; i < 128 && aux[0]; i++, aux += 2) {
        if (aux[0] == 2 || aux[0] == 0xbe6a) report.private_aux_entries++;
        if (aux[0] == 8) report.private_aux_flags |= aux[1] & (3U << 16);
    }
    long result = call3(SYS_write, report.report_fd, (long)&report, sizeof(report));
    return result == (long)sizeof(report) ? 0 : 84;
}

#ifdef CLOSED_STDIO_FREESTANDING
__attribute__((noreturn)) void closed_stdio_start(uintptr_t *stack)
{
    int argc = (int)stack[0];
    char **argv = (char **)(stack+1);
    int result = observe(argc, argv, argv+argc+1);
    call3(SYS_exit_group, result, 0, 0);
    for (;;) {}
}
__asm__(".global _start\n.type _start,%function\n_start:\nmov x0,sp\nbl closed_stdio_start\n");
#else
int main(int argc, char **argv, char **envp) { return observe(argc, argv, envp); }
#endif
