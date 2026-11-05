/* SPDX-License-Identifier: MIT */
/* Same RAM segment ABI as the previously qualified project handoff loader. */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#if !defined(KSIZE64) || !defined(MEMSIZE64) || !defined(DSIZE)
#error "Require audited Image, allocation and DTB sizes"
#endif
_Static_assert(KSIZE64 > 0 && KSIZE64 <= MEMSIZE64, "Invalid Image allocation");
_Static_assert(MEMSIZE64 <= 0x3e00000, "Image overlaps NPU reservation");
_Static_assert(DSIZE > 0 && DSIZE <= 0x10000, "Invalid DTB size");
struct segment { const void *buf; size_t bufsz; void *mem; size_t memsz; };
static void *map(const char *name, size_t expected)
{
    int fd = open(name, O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || st.st_size != expected) {
        perror(name); exit(1);
    }
    void *data = mmap(NULL, expected, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (data == MAP_FAILED) { perror("mmap"); exit(1); }
    return data;
}
int main(void)
{
    enum { KSIZE32 = 34657408, PAGE = 4096 };
    struct segment seg[] = {
        {map("Image", KSIZE64), KSIZE64, (void *)0x80200000, (MEMSIZE64 + PAGE - 1) & ~(PAGE - 1UL)},
        {map("board.dtb", DSIZE), DSIZE, (void *)0x86ee3000, (DSIZE + PAGE - 1) & ~(PAGE - 1UL)},
        {map("arm32-fallback", KSIZE32), KSIZE32, (void *)0x90000000, (KSIZE32 + PAGE - 1) & ~(PAGE - 1UL)},
        {map("entry.bin", PAGE), PAGE, (void *)0x87f00000, PAGE},
    };
    if (syscall(SYS_kexec_load, 0x87f00000UL, 4UL, seg, 0x280000UL)) {
        perror("kexec_load"); return 1;
    }
    puts("P3_LINUX64_AND_ARM32_BACKUP_LOADED");
    return 0;
}
