/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "denied") && strcmp(argv[1], "allowed"))) return 2;
    /* Fixed target, no O_TRUNC, never a write or chmod. */
    int fd = open("/usr/libexec/be6l/qemu-aarch64", O_WRONLY);
    int saved = errno;
    if (fd >= 0) close(fd);
    int ok = !strcmp(argv[1], "denied") ? fd < 0 && saved == ETXTBSY : fd >= 0;
    printf("INTERPRETER_WRITE_PROBE expected=%s actual=%s errno=%d\n",
           argv[1], fd >= 0 ? "allowed" : "denied", fd >= 0 ? 0 : saved);
    return ok ? 0 : 1;
}
