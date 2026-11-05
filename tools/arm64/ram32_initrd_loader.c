/* SPDX-License-Identifier: MIT */
/* RAM-only ARM32 intermediate: original kernel plus a signed-root delta initrd. */
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#if !defined(KSIZE) || !defined(DSIZE) || !defined(ISIZE)
#error "Require validated payload sizes"
#endif
struct segment { const void *buf; size_t bufsz; void *mem; size_t memsz; };
static void *map(const char *name, size_t expected)
{
    struct stat st;
    int fd = open(name, O_RDONLY);
    if (fd < 0 || fstat(fd, &st) || st.st_size != expected) {
        perror(name); exit(1);
    }
    void *p = mmap(NULL, expected, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { perror("mmap"); exit(1); }
    return p;
}
int main(void)
{
    const size_t split = 0x178000;
    const unsigned char *kernel = map("openwrt-kernel", KSIZE);
    struct segment seg[] = {
        {kernel, split, (void *)0x80088000, split},
        {kernel + split, KSIZE - split, (void *)0x80200000, (KSIZE - split + 4095) & ~4095UL},
        {map("board.dtb", DSIZE), DSIZE, (void *)0x86ee3000, (DSIZE + 4095) & ~4095UL},
        {map("extra.cpio", ISIZE), ISIZE, (void *)0x94000000, (ISIZE + 4095) & ~4095UL},
    };
    if (syscall(SYS_kexec_load, 0x80088000UL, 4UL, seg, 0x280000UL)) {
        perror("kexec_load"); return 1;
    }
    puts("BE6L_PROTECTED_ARM32_INITRD_LOADED");
    return 0;
}
