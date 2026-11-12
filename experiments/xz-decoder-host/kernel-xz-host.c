/* SPDX-License-Identifier: MIT
 * Runs actual, unmodified Linux decompress_unxz.c and its lib/xz sources via
 * their explicit userspace xz_config.h hook. Host services are adapted; this
 * proves neither target allocator behavior nor RAM boot or memory admission.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "xz_config.h"

union allocation_header { max_align_t alignment; struct { size_t size; } record; };
static size_t live_payload, live_total, peak_payload, peak_total, max_request;
static size_t live_blocks, peak_blocks, denied, allocation_cap;
static const uint8_t *input_data;
static size_t input_size, fill_position;
static FILE *output;
static uint64_t output_bytes;
static int output_error, wrapper_error;

void *be6l_xz_alloc(size_t size)
{
    if (size > max_request) max_request = size;
    if (size > SIZE_MAX-sizeof(union allocation_header) ||
        live_total > allocation_cap || size+sizeof(union allocation_header) > allocation_cap-live_total) {
        denied++; return NULL;
    }
    union allocation_header *header = malloc(sizeof(*header)+size);
    if (!header) { denied++; return NULL; }
    header->record.size = size;
    live_payload += size; live_total += size+sizeof(*header); live_blocks++;
    if (live_payload > peak_payload) peak_payload = live_payload;
    if (live_total > peak_total) peak_total = live_total;
    if (live_blocks > peak_blocks) peak_blocks = live_blocks;
    return header+1;
}

void be6l_xz_free(void *pointer)
{
    if (!pointer) return;
    union allocation_header *header = (union allocation_header *)pointer-1;
    if (!live_blocks || header->record.size > live_payload) abort();
    live_payload -= header->record.size;
    live_total -= header->record.size+sizeof(*header); live_blocks--;
    free(header);
}

/* Preboot selects the same unxz function body while avoiding kernel-only
 * slab headers. The allocator adapters above track every decoder request.
 * CONFIG_ARM64 selects the actual ARM64 BCJ implementation, though these
 * exact input streams use LZMA2 alone. libc supplies basic memmove semantics.
 */
#define STATIC static
#define INIT
#define CONFIG_ARM64 1
#define malloc(size) be6l_xz_alloc(size)
#define free(pointer) be6l_xz_free(pointer)
#define memmove memmove
#include BE6L_UNXZ_SOURCE
#undef malloc
#undef free

static long fill(void *buffer, unsigned long size)
{
    size_t remaining = input_size-fill_position;
    if (size > remaining) size = remaining;
    memcpy(buffer, input_data+fill_position, size);
    fill_position += size;
    return (long)size;
}

static long flush(void *buffer, unsigned long size)
{
    if (output && fwrite(buffer, 1, size, output) != size) {
        output_error = errno ? errno : EIO; return -1;
    }
    output_bytes += size;
    return (long)size;
}

static void report_error(char *message)
{
    wrapper_error = 1;
    fprintf(stderr, "ACTUAL_UNXZ_ERROR %s\n", message);
}

static uint64_t number(const char *text)
{
    char *end;
    errno = 0;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || !*text || *end || *text == '-') { fprintf(stderr, "Invalid number\n"); exit(90); }
    return value;
}

int main(int argc, char **argv)
{
    if (argc != 7) {
        fprintf(stderr, "Use: mode input output-or-- dict-max allocation-cap input-limit-or-0\n"); return 90;
    }
    uint64_t dict_max = number(argv[4]), cap = number(argv[5]), limit = number(argv[6]);
    if (dict_max > UINT32_MAX || cap > SIZE_MAX) return 90;
    allocation_cap = (size_t)cap;
    int fd = open(argv[2], O_RDONLY|O_CLOEXEC);
    struct stat status;
    if (fd < 0 || fstat(fd, &status) || !S_ISREG(status.st_mode) || status.st_size <= 0 ||
        (uint64_t)status.st_size > SIZE_MAX) { perror("regular input"); return 91; }
    size_t mapped_size = (size_t)status.st_size;
    input_data = mmap(NULL, mapped_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (input_data == MAP_FAILED || close(fd)) { perror("input map/close"); return 91; }
    input_size = limit ? (size_t)limit : mapped_size;
    if (limit > mapped_size || input_size > LONG_MAX) return 90;
    if (strcmp(argv[3], "-")) {
        output = fopen(argv[3], "wbx");
        if (!output) { perror("exclusive output"); return 92; }
    }
    int result;
    size_t consumed = 0;
    if (!strcmp(argv[1], "codec")) {
        uint8_t buffer[4096];
        struct xz_buf b = {.in = input_data, .in_size = input_size, .out = buffer, .out_size = sizeof(buffer)};
        xz_crc32_init();
        struct xz_dec *decoder = xz_dec_init(XZ_DYNALLOC, (uint32_t)dict_max);
        enum xz_ret ret = XZ_MEM_ERROR;
        if (decoder) {
            do {
                ret = xz_dec_run(decoder, &b);
                if (b.out_pos && flush(buffer, b.out_pos) != (long)b.out_pos) { ret = XZ_BUF_ERROR; break; }
                b.out_pos = 0;
            } while (ret == XZ_OK);
            consumed = b.in_pos;
            xz_dec_end(decoder);
        }
        result = ret;
    } else if (!strcmp(argv[1], "wrapper") || !strcmp(argv[1], "wrapper-fill")) {
        long used = 0;
        result = !strcmp(argv[1], "wrapper") ?
            unxz((unsigned char *)input_data, (long)input_size, NULL, flush, NULL, &used, report_error) :
            unxz(NULL, 0, fill, flush, NULL, &used, report_error);
        consumed = (size_t)used;
    } else {
        fprintf(stderr, "Unknown mode\n"); return 90;
    }
    if (output && fclose(output)) output_error = errno ? errno : EIO;
    if (munmap((void *)input_data, mapped_size)) return 93;
    printf("{\"mode\":\"%s\",\"return_code\":%d,\"consumed\":%zu,\"input_bytes\":%zu,"
           "\"output_bytes\":%" PRIu64 ",\"wrapper_error\":%d,\"output_error\":%d,"
           "\"peak_payload\":%zu,\"peak_with_adapter_headers\":%zu,\"peak_blocks\":%zu,"
           "\"max_request\":%zu,\"denied\":%zu,\"live_payload\":%zu,\"live_total\":%zu,"
           "\"live_blocks\":%zu,\"allocation_cap\":%zu}\n",
           argv[1], result, consumed, input_size, output_bytes, wrapper_error, output_error,
           peak_payload, peak_total, peak_blocks, max_request, denied,
           live_payload, live_total, live_blocks, allocation_cap);
    return output_error || live_total || live_blocks ? 94 : 0;
}
