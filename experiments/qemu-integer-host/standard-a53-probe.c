/* SPDX-License-Identifier: MIT */
/* Build with the standard AArch64 ABI, never with the private soft ABI. */
#include <asm/hwcap.h>
#include <fenv.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>

static uint64_t bits(double value)
{
    uint64_t result;
    memcpy(&result, &value, sizeof(result));
    return result;
}

static double add(double left, double right)
{
    double result;
    __asm__ volatile("fadd %d0, %d1, %d2" : "=w"(result) : "w"(left), "w"(right));
    return result;
}

int main(void)
{
    const uint32_t a[4] = {1, 2, 0x12345678, 0xffffffff};
    const uint32_t b[4] = {7, 8, 0x11111111, 1};
    const uint32_t expected[4] = {8, 10, 0x23456789, 0};
    uint32_t result[4];
    double square, quotient, one = 1.0, zero = 0.0, two = 2.0;
    unsigned long caps = getauxval(AT_HWCAP);

    if ((caps & (HWCAP_FP | HWCAP_ASIMD)) != (HWCAP_FP | HWCAP_ASIMD))
        return 10;
    if (bits(add(1.25, 2.5)) != UINT64_C(0x400e000000000000))
        return 11;
    __asm__ volatile("ldr q0, [%0]\n\tldr q1, [%1]\n\t"
                     "add v2.4s, v0.4s, v1.4s\n\tstr q2, [%2]"
                     : : "r"(a), "r"(b), "r"(result) : "v0", "v1", "v2", "memory");
    if (memcmp(result, expected, sizeof(result)))
        return 12;
    if (fesetround(FE_TONEAREST) || bits(add(1.0, 0x1p-53)) != UINT64_C(0x3ff0000000000000))
        return 13;
    if (fesetround(FE_UPWARD) || bits(add(1.0, 0x1p-53)) != UINT64_C(0x3ff0000000000001))
        return 14;
    if (fesetround(FE_TONEAREST))
        return 15;
    __asm__ volatile("fsqrt %d0, %d1" : "=w"(square) : "w"(two));
    if (bits(square) != UINT64_C(0x3ff6a09e667f3bcd))
        return 16;
    if (feclearexcept(FE_ALL_EXCEPT))
        return 17;
    __asm__ volatile("fdiv %d0, %d1, %d2" : "=w"(quotient) : "w"(one), "w"(zero));
    if (bits(quotient) != UINT64_C(0x7ff0000000000000) || !(fetestexcept(FE_DIVBYZERO)))
        return 18;
    printf("STANDARD_A53_FP_SIMD_PASS hwcap=%lx scalar=3.75 neon=4x32 rounding=nearest,upward sqrt=ok fpsr=ok\n", caps);
    return 0;
}
