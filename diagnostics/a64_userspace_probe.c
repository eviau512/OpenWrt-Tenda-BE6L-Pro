/* SPDX-License-Identifier: MIT
 * Integer-only Linux EL0 diagnostic. No libc, firmware or device access.
 * Trace an explicitly supplied program and report its first fatal instruction.
 */
typedef unsigned long u64;
typedef long s64;
static s64 call6(s64 nr, s64 a, s64 b, s64 c, s64 d, s64 e, s64 f)
{
	register s64 x0 __asm__("x0") = a, x1 __asm__("x1") = b;
	register s64 x2 __asm__("x2") = c, x3 __asm__("x3") = d;
	register s64 x4 __asm__("x4") = e, x5 __asm__("x5") = f;
	register s64 x8 __asm__("x8") = nr;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
			 "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
	return x0;
}
#define C(n,a,b,c,d) call6(n,(s64)(a),(s64)(b),(s64)(c),(s64)(d),0,0)
static void put(const char *s)
{
	u64 n = 0;
	while (s[n]) n++;
	while (n) {
		s64 k = C(64, 1, s, n, 0);
		if (k <= 0) return;
		s += k; n -= k;
	}
}
static void hex(const char *label, u64 v)
{
	char text[19];
	put(label); text[0] = '0'; text[1] = 'x'; text[18] = 0;
	for (unsigned i = 0; i < 16; i++)
		text[2+i] = "0123456789abcdef"[(v >> ((15-i)*4)) & 15];
	put(text); put("\n");
}
static void maps(s64 pid)
{
	char path[64] = "/proc/", digits[24], buf[1024];
	unsigned n=0, at=6;
	do { digits[n++] = '0' + pid%10; pid/=10; } while (pid);
	while (n) path[at++] = digits[--n];
	const char *tail = "/maps";
	while (*tail) path[at++] = *tail++;
	path[at] = 0;
	s64 fd=C(56,-100,path,0,0);
	if (fd < 0) { hex("maps_error=",fd); return; }
	put("MAPS_BEGIN\n");
	s64 count;
	while ((count=C(63,fd,buf,sizeof(buf),0))>0) C(64,1,buf,count,0);
	C(57,fd,0,0,0); put("MAPS_END\n");
}
static int main(u64 argc, char **argv, char **envp)
{
	put("A64_INTEGER_EL0_OK\n");
	hex("pointer_bytes=", sizeof(void *));
	if (argc < 2) return 0;
	s64 pid=C(220,17,0,0,0);
	if (pid<0) { hex("clone_error=",pid); return 70; }
	if (!pid) {
		if (C(117,0,0,0,0)<0) C(94,71,0,0,0);
		s64 err=C(221,argv[1],argv+1,envp,0);
		hex("exec_error=",err); C(94,72,0,0,0);
	}
	for (int step=0; step<16; step++) {
		int status=0;
		s64 got=C(260,pid,&status,0,0);
		if (got!=pid) { hex("wait_error=",got); break; }
		hex("wait_status=",(unsigned)status);
		if (!(status&0x7f)) {
			hex("target_exit=",(status>>8)&255); return (status>>8)&255;
		}
		if ((status&255)!=127) { hex("target_signal=",status&127); return 73; }
		int sig=(status>>8)&255;
		if (sig!=5) {
			u64 regs[34], word=0;
			struct { void *base; u64 len; } iov={regs,sizeof(regs)};
			hex("target_stop_signal=",sig);
			s64 err=C(117,0x4204,pid,1,&iov);
			hex("getregset_status=",err);
			if (!err && iov.len==sizeof(regs)) {
				hex("pc=",regs[32]); hex("sp=",regs[31]); hex("pstate=",regs[33]);
				err=C(117,1,pid,regs[32]&~7UL,&word);
				hex("peek_status=",err);
				if (!err) hex("instruction=",(word >> ((regs[32]&7)*8)) & 0xffffffffUL);
			}
			maps(pid);
			C(129,pid,9,0,0); C(260,pid,&status,0,0);
			return sig==4 ? 4 : 74;
		}
		if (!step && C(117,0x4200,pid,0,0x100000)<0) break;
		if (C(117,7,pid,0,0)<0) break;
	}
	C(129,pid,9,0,0); int status; C(260,pid,&status,0,0);
	return 75;
}
__attribute__((noreturn)) void entry(u64 *stack)
{
	u64 argc=stack[0]; char **argv=(char **)(stack+1);
	int result=main(argc,argv,argv+argc+1);
	C(94,result,0,0,0);
	for (;;) {}
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl entry\n");
