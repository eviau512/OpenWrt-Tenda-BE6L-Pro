/* SPDX-License-Identifier: MIT */
/* Build with private AAPCS64-soft: records the actual native child's signal. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int status;
    pid_t child;
    if (argc != 2)
        return 2;
    child = fork();
    if (child < 0)
        return 3;
    if (!child) {
        execl(argv[1], argv[1], (char *)0);
        _exit(126);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return 4;
    }
    if (WIFSIGNALED(status)) {
        printf("NATIVE_CHILD_SIGNAL=%d\n", WTERMSIG(status));
        return WTERMSIG(status) == SIGILL ? 0 : 5;
    }
    printf("NATIVE_CHILD_EXIT=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return 6;
}
