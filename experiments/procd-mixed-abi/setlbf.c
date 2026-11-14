/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Same observable buffering policy as procd service/setlbf.c.  The unique bare
 * SONAME is deliberately retained in the environment for helpers/descendants;
 * each musl ABI resolves its own copy. No environment or argv rewriting.
 */
#include <stdio.h>
static void __attribute__((constructor)) setlbf(void)
{
	setbuf(stdout, NULL);
}
