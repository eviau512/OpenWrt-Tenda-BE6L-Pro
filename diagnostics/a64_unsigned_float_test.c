/* SPDX-License-Identifier: MIT */
#include <stdint.h>
#include <stdio.h>
extern float __floatunsisf(unsigned int);
int main(void)
{
    static const struct { uint32_t input, bits; } vectors[] = {
        {0,0}, {1,0x3f800000}, {16777215,0x4b7fffff},
        {16777216,0x4b800000}, {16777217,0x4b800000},
        {16777219,0x4b800002}, {2147483647,0x4f000000},
        {2147483648u,0x4f000000}, {4294967295u,0x4f800000}
    };
    for (unsigned i=0;i<sizeof(vectors)/sizeof(vectors[0]);i++) {
        volatile uint32_t input=vectors[i].input;
        union {float f;uint32_t bits;} value;
        value.f=__floatunsisf(input);
        if (value.bits!=vectors[i].bits) return 10+i;
    }
    puts("UNSIGNED_FLOAT_SOFT_ABI_9_VECTORS_PASS");
    return 0;
}
