/* SPDX-License-Identifier: MIT */
#include <fenv.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

static _Thread_local unsigned local_value = 9;
static _Atomic uint64_t count;
static _Atomic unsigned destructors;
static pthread_key_t key;
static volatile sig_atomic_t signals;

static void destructor(void *value)
{
    if (value)
        atomic_fetch_add(&destructors, 1);
}

static void *worker(void *argument)
{
    unsigned expected = (uintptr_t)argument + 100;
    if (local_value != 9 || pthread_setspecific(key, argument))
        return (void *)1;
    local_value = expected;
    for (unsigned i = 0; i < 10000; i++)
        atomic_fetch_add_explicit(&count, 1, memory_order_seq_cst);
    return local_value == expected ? 0 : (void *)2;
}

static void handler(int signal_number)
{
    uint64_t fpcr;
    (void)signal_number;
    __asm__ volatile("mrs %0, fpcr" : "=r"(fpcr));
    fpcr = (fpcr & ~(UINT64_C(3) << 22)) | (UINT64_C(2) << 22);
    __asm__ volatile("msr fpcr, %0" : : "r"(fpcr) : "memory");
    signals++;
}

int main(void)
{
    pthread_t threads[4];
    struct sigaction action = {.sa_handler = handler};
    if (pthread_key_create(&key, destructor))
        return 10;
    for (unsigned i = 0; i < 4; i++)
        if (pthread_create(&threads[i], 0, worker, (void *)(uintptr_t)(i + 1)))
            return 11;
    for (unsigned i = 0; i < 4; i++) {
        void *result;
        if (pthread_join(threads[i], &result) || result)
            return 12;
    }
    if (count != 40000 || destructors != 4 || local_value != 9)
        return 13;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, 0) || fesetround(FE_UPWARD) || raise(SIGUSR1))
        return 14;
    if (signals != 1 || fegetround() != FE_UPWARD)
        return 15;
    if (fesetround(FE_TONEAREST))
        return 16;
    for (unsigned i = 0; i < 2; i++) {
        int status;
        pid_t child = fork();
        if (child < 0)
            return 17;
        if (!child)
            _exit(local_value == 9 && count == 40000 ? 0 : 18);
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
            return 19;
    }
    puts("STANDARD_A53_THREAD_PASS threads=4 atomic64=40000 tls=ok destructors=4 signal_fpcr=restored fork=2");
    return 0;
}
