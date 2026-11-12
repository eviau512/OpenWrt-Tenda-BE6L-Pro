/* SPDX-License-Identifier: MIT */
#ifndef BE6L_CLOSED_STDIO_WIRE_H
#define BE6L_CLOSED_STDIO_WIRE_H
#include <stdint.h>
#define CLOSED_STDIO_MAGIC 0x43534644U
#define CLOSED_STDIO_SCAN_LIMIT 256
struct closed_stdio_report {
    uint32_t magic, version;
    int32_t report_fd, exec_errno;
    uint32_t expected_mask, helper_kind;
    int32_t flags[3], errors[3];
    uint64_t device[3], inode[3];
    uint32_t program_aliases, loader_aliases, private_aux_entries, private_aux_flags;
};
_Static_assert(sizeof(struct closed_stdio_report) == 112, "ARM32/A64 report layout differs");
#endif
