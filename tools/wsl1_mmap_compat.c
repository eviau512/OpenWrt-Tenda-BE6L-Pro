/* Host-test portability only: emulate NOREPLACE on WSL1 after proving a gap.
 * This code is never linked into router or NPU firmware.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

extern void *__real_mmap(void *, size_t, int, int, int, off_t);

void *__wrap_mmap(void *address, size_t length, int prot, int flags, int fd, off_t offset)
{
    void *result = __real_mmap(address, length, prot, flags, fd, offset);
    uintptr_t start = (uintptr_t)address, end = start + length;
    unsigned long low, high;
    char line[512];
    FILE *maps;
    int saved = errno;

    if (!(flags & MAP_FIXED_NOREPLACE) || result == address)
        return result;
    if (result != MAP_FAILED) {
        munmap(result, length);
        saved = EINVAL; /* WSL1 can ignore the unimplemented flag. */
    }
    if ((saved != EINVAL && saved != EOPNOTSUPP) || !length ||
        (start & 4095) || end <= start) {
        errno = saved;
        return MAP_FAILED;
    }
    maps = fopen("/proc/self/maps", "r");
    if (!maps)
        return MAP_FAILED;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx", &low, &high) != 2) {
            fclose(maps);
            errno = EIO;
            return MAP_FAILED;
        }
        if (start < high && low < end) {
            fclose(maps);
            errno = EEXIST;
            return MAP_FAILED;
        }
    }
    if (ferror(maps)) {
        fclose(maps);
        errno = EIO;
        return MAP_FAILED;
    }
    fclose(maps);
    return __real_mmap(address, length, prot,
                       (flags & ~MAP_FIXED_NOREPLACE) | MAP_FIXED, fd, offset);
}
