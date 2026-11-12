/* SPDX-License-Identifier: 0BSD
 * Supported userspace adaptation hook for the unchanged Linux XZ Embedded
 * decoder. Only allocation, basic memory and byte-order services live here.
 */
#ifndef BE6L_XZ_HOST_CONFIG_H
#define BE6L_XZ_HOST_CONFIG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <linux/xz.h>

void *be6l_xz_alloc(size_t size);
void be6l_xz_free(void *pointer);
#define GFP_KERNEL 0
#define kmalloc(size, flags) be6l_xz_alloc(size)
#define kfree(pointer) be6l_xz_free(pointer)
#define vmalloc(size) be6l_xz_alloc(size)
#define vfree(pointer) be6l_xz_free(pointer)
#define memeq(a, b, size) (memcmp(a, b, size) == 0)
#define memzero(buffer, size) memset(buffer, 0, size)
#define min_t(type, a, b) ({ type be6l_a = (a); type be6l_b = (b); be6l_a < be6l_b ? be6l_a : be6l_b; })
#define min(a, b) ({ __typeof__(a) be6l_a = (a); __typeof__(b) be6l_b = (b); be6l_a < be6l_b ? be6l_a : be6l_b; })
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#ifndef fallthrough
#define fallthrough __attribute__((fallthrough))
#endif

static inline uint32_t get_unaligned_le32(const void *pointer)
{
    const uint8_t *p = pointer;
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline void put_unaligned_le32(uint32_t value, void *pointer)
{
    uint8_t *p = pointer;
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (i*8));
}
#define get_le32(pointer) get_unaligned_le32(pointer)
#endif
