/* SPDX-License-Identifier: MIT
 * Target acceptance for the isolated AAPCS64 soft-float runtime.
 * This is not a complete libc/IEEE-754 conformance suite.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>
#include <math.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fenv.h>

static int count;
#define CHECK(x) do { if (!(x)) {printf("FAIL line=%d: %s\n",__LINE__,#x);return 1;} count++;} while(0)
static _Thread_local unsigned thread_value;
static volatile sig_atomic_t received;
static void handler(int sig) { received=sig; }
static void *thread(void *arg)
{
	unsigned value=(uintptr_t)arg;
	thread_value=value;
	volatile double a=1.5,b=2.25;
	for (unsigned n=0;n<4000;n++) {
		if (a+b!=3.75 || thread_value!=value) return (void *)1;
	}
	return 0;
}
int main(int argc,char **argv)
{
	CHECK(sizeof(void *)==8);
	CHECK((getauxval(16)&3)==0); /* Kernel must not advertise absent FP/ASIMD. */
	CHECK(FE_ALL_EXCEPT==0);CHECK(fegetround()==FE_TONEAREST);
	CHECK(!fesetround(FE_TONEAREST));CHECK(fesetround(1)!=0);
	volatile float sf=1.5f,tf=2.25f;
	volatile double a=1.5,b=2.25,zero=0;
	volatile long double la=1.5L,lb=2.25L;
	CHECK(sf+tf==3.75f);CHECK(sf*tf==3.375f);CHECK(tf/sf==1.5f);
	CHECK(a+b==3.75);CHECK(a*b==3.375);CHECK(b/a==1.5);
	CHECK(la+lb==3.75L);CHECK(la*lb==3.375L);CHECK(lb/la==1.5L);
	CHECK(isnan(zero/zero));CHECK(isinf(a/zero));
	CHECK(signbit(-zero));CHECK(!signbit(zero));
	volatile double large=4294967297.0;
	CHECK((uint64_t)large==4294967297ULL);CHECK((int64_t)-large==-4294967297LL);
	char text[128],*end;
	snprintf(text,sizeof(text),"%d %.6f %.4Lf %llu",17,a+b,la+lb,4294967297ULL);
	CHECK(!strcmp(text,"17 3.750000 3.7500 4294967297"));
	CHECK(strtod("3.75",&end)==3.75 && !*end);
	CHECK(strtold("3.75",&end)==3.75L && !*end);
	CHECK(sqrt(4.0+a-a)==2.0);CHECK(fabs(log(exp(a))-a)<1e-12);
	CHECK(fabs(sin(a)*sin(a)+cos(a)*cos(a)-1)<1e-12);
	/* Indirect volatile calls must exercise libc, not compiler constant folding.
	 * Contracting fma's own x*y+z fallback into fma caused unbounded recursion.
	 */
	double (*volatile fused)(double,double,double)=fma;
	double (*volatile power)(double,double)=pow;
	CHECK(fused(a,b,zero)==3.375);
	CHECK(fused(a,b,-3.375)==0);
	CHECK(isnan(fused(NAN,a,b)));CHECK(isinf(fused(INFINITY,a,b)));
	CHECK(fused(1+0x1p-27,1-0x1p-27,-1)==-0x1p-54);
	CHECK(fused(0x1p-1022,0x1p-52,zero)==0x1p-1074);
	CHECK(fabs(power(sqrt(2+zero),2)-2)<1e-12);
	unsigned char *src=malloc(8192),*dst=malloc(8192);
	CHECK(src && dst);
	for (unsigned n=0;n<8192;n++) src[n]=(n*13+7)&255;
	for (unsigned size=1;size<=4096;size*=2) {
		memset(dst,0,8192);memcpy(dst+3,src+1,size);
		CHECK(!memcmp(dst+3,src+1,size));
		memmove(dst+4,dst+3,size);CHECK(!memcmp(dst+4,src+1,size));
	}
	free(src);free(dst);
	jmp_buf jump; int status=setjmp(jump);
	if (!status) longjmp(jump,42);
	CHECK(status==42);
	struct sigaction action={.sa_handler=handler};
	sigemptyset(&action.sa_mask);CHECK(!sigaction(SIGUSR1,&action,0));
	CHECK(!raise(SIGUSR1));CHECK(received==SIGUSR1);
	pthread_t workers[2];thread_value=77;
	for (uintptr_t n=0;n<2;n++) CHECK(!pthread_create(&workers[n],0,thread,(void *)(n+1)));
	for (unsigned n=0;n<2;n++) {void *result;CHECK(!pthread_join(workers[n],&result));CHECK(!result);}
	CHECK(thread_value==77);
	if (argc==2) {
		void *lib=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);CHECK(lib);
		double (*function)(double,double)=dlsym(lib,"soft_plugin_add");CHECK(function);
		CHECK(function(a,b)==3.75);CHECK(!dlclose(lib));
	}
	printf("A64_SOFT_RUNTIME_PASS checks=%d pointer_bytes=%zu hwcap=%lx\n",count,sizeof(void *),getauxval(16));
	return 0;
}
