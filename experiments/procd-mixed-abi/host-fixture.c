/* SPDX-License-Identifier: MIT
 * Native host fixture, not a standard A53 package compatibility claim.
 * FD 3 is an independent report channel; FD 4 bounds the live buffer check.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include "bootstrap-mount.h"

int main(int argc, char **argv)
{
	if (argc > 1 && !strcmp(argv[1], "mount-policy")) {
		unsigned long p = 0x9fa0, s = 0x62656572, t = 0x01021994;
		if (!be6l_bootstrap_fs_matches(0,p,p) || !be6l_bootstrap_fs_matches(0,s,s) ||
		    !be6l_bootstrap_fs_matches(0,t,t) || be6l_bootstrap_fs_matches(-1,p,p) ||
		    be6l_bootstrap_fs_matches(0,s,p) || be6l_bootstrap_fs_matches(0,0,t)) return 1;
		return 0;
	}
	if (argc > 2 && !strcmp(argv[1], "exec")) {
		execv(argv[2], argv+2);
		return 120;
	}
	if (argc > 2 && !strcmp(argv[1], "descendant")) {
		pid_t p = fork(); int status;
		if (p < 0) return 121;
		if (!p) { execv(argv[2], argv+2); _exit(122); }
		if (waitpid(p,&status,0) != p || !WIFEXITED(status)) return 123;
		return WEXITSTATUS(status);
	}
	if (argc > 2 && !strcmp(argv[1], "cloexec-script")) {
		int fd = open(argv[2], O_RDONLY|O_CLOEXEC);
		char *args[] = { "script-custom-argv0", NULL };
		if (fd < 0) return 124;
		syscall(SYS_execveat,fd,"",args,environ,AT_EMPTY_PATH);
		int e = errno; close(fd);
		dprintf(2,"EXECVEAT_ERRNO=%d\n",e);
		return e == ENOENT ? 0 : e == ENOSYS ? 77 : 125;
	}
	char c;
	printf("LIVE_UNBUFFERED_TOKEN");
	dprintf(3,"READY pid=%ld argv0=%s execfn=%s preload=%s\n", (long)getpid(), argv[0],
		(char *)getauxval(AT_EXECFN), getenv("LD_PRELOAD") ?: "<unset>");
	if (read(4,&c,1) != 1) return 126;
	return 0;
}
