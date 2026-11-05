/* SPDX-License-Identifier: MIT
 * Native ARM32 bounded PTY fixture, independent of SSH PTY permissions.
 * Writes terminal bytes to stdout and lifecycle markers to stderr.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long milliseconds(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(80);
    return (long long)t.tv_sec*1000+t.tv_nsec/1000000;
}

int main(int argc, char **argv)
{
    if (argc < 3) return 81;
    int seconds = atoi(argv[1]);
    if (seconds < 3 || seconds > 20 || argv[2][0] != '/') return 82;
    int master, slave, status = 0;
    struct winsize size = {.ws_row=40, .ws_col=120};
    if (openpty(&master, &slave, NULL, NULL, &size)) { perror("openpty"); return 83; }
    pid_t child = fork();
    if (child < 0) return 84;
    if (!child) {
        close(master);
        if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0)) _exit(85);
        for (int i=0; i<3; i++) if (dup2(slave, i) < 0) _exit(86);
        if (slave > 2) close(slave);
        execv(argv[2], argv+2);
        perror("execv");
        _exit(87);
    }
    close(slave);
    if (fcntl(master, F_SETFL, O_NONBLOCK)) { kill(child, SIGKILL); return 88; }
    long long start = milliseconds();
    int interrupted=0, forced=0, exited=0;
    unsigned long total=0;
    while (!exited) {
        long long elapsed = milliseconds()-start;
        if (!interrupted && elapsed >= seconds*1000) {
            kill(-child, SIGINT);
            interrupted=1;
        }
        if (!forced && elapsed >= (seconds+3)*1000) {
            kill(-child, SIGKILL);
            forced=1;
        }
        struct pollfd ready = {.fd=master, .events=POLLIN};
        if (poll(&ready, 1, 100) > 0) {
            char data[8192];
            ssize_t count;
            while ((count=read(master, data, sizeof(data))) > 0) {
                total += count;
                if (total > 4*1024*1024) { kill(-child, SIGKILL); forced=1; break; }
                ssize_t pos=0;
                while (pos<count) {
                    ssize_t written=write(STDOUT_FILENO, data+pos, count-pos);
                    if (written <= 0) { kill(-child, SIGKILL); _exit(89); }
                    pos += written;
                }
            }
        }
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child) exited=1;
        else if (done < 0 && errno != EINTR) return 90;
    }
    close(master);
    fprintf(stderr, "BE6L_PTY_DONE elapsed_ms=%lld interrupted=%d forced=%d wait_status=%d bytes=%lu\n",
            milliseconds()-start, interrupted, forced, status, total);
    return interrupted && !forced && WIFEXITED(status) && WEXITSTATUS(status)==0 ? 0 : 1;
}
