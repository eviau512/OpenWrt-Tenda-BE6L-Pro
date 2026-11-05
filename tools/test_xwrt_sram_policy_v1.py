# SPDX-License-Identifier: MIT
"""Fault-test actual ported table functions with register/allocator substitutes.

Host structures and register accesses are substituted. This does not qualify
the complete driver, kernel ABI, DMA lifetime or actual hardware reset/BIND.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess


def function(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\([^;{}]*\)\s*\{", text)
    if not match:
        raise ValueError("Function not found: " + name)
    start = text.rfind("\n\n", 0, match.start()) + 2
    opening = text.index("{", match.start())
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end] + "\n"


def defines(text):
    result = []
    continuation = False
    for line in text.splitlines():
        if continuation or line.startswith("#define "):
            result.append(line)
            continuation = line.rstrip().endswith("\\")
    return "\n".join(result) + "\n"


PRELUDE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint64_t dma_addr_t;
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define GENMASK(h,l) ((~0UL << (l)) & (~0UL >> (63-(h))))
#define GENMASK_ULL(h,l) GENMASK(h,l)
#define FIELD_PREP(m,v) (((u32)(v) << __builtin_ctzll(m)) & (m))
#define FIELD_GET(m,v) (((v) & (m)) >> __builtin_ctzll(m))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define ilog2(n) (31 - __builtin_clz((unsigned)(n)))
#define __ffs(n) __builtin_ctzl((unsigned long)(n))
#define GFP_KERNEL 0
#define lockdep_assert_held(x) do {} while (0)
#define wmb() do {} while (0)
#define rcu_read_lock() do {} while (0)
#define rcu_read_unlock() do {} while (0)
#define rcu_dereference(p) (p)
struct airoha_gdm_dev { int ignored; };
struct airoha_gdm_port { struct airoha_gdm_dev *devs[4]; };
struct airoha_eth_soc_data { unsigned version; int num_ppe; };
struct airoha_eth {
    void *dev;
    struct airoha_eth_soc_data *soc;
    struct airoha_gdm_port *ports[4];
};
struct airoha_ppe { struct airoha_eth *eth; void *foe; dma_addr_t foe_dma; };
struct airoha_foe_entry { u32 ib1; u32 data[19]; };
static u32 registers[1024 * 1024];
static unsigned writes, dma_allocations, cpu_allocations, checks;
static bool allocation_failure, ack_failure;
static bool airoha_is_7563(struct airoha_eth *eth) { return eth->soc->version == 0x7563; }
static int airoha_ppe_get_num_stats_entries(struct airoha_ppe *ppe) { return -EOPNOTSUPP; }
static int airoha_is_lan_gdm_dev(struct airoha_gdm_dev *dev) { return 1; }
static int airoha_ppe_is_enabled(struct airoha_eth *eth, int index) { return 0; }
static u8 airoha_get_fe_port(struct airoha_gdm_dev *dev) { return 0; }
static void airoha_ppe_set_cpu_port(struct airoha_gdm_dev *dev, int id, u8 port) {}
static void airoha_ppe_set_xmit_frame_size(struct airoha_gdm_dev *dev) {}
static void *devm_kzalloc(void *dev, size_t size, int flags) {
    cpu_allocations++;
    return allocation_failure ? NULL : calloc(1, size);
}
static void *dmam_alloc_coherent(void *dev, size_t size, dma_addr_t *addr, int flags) {
    dma_allocations++;
    *addr = 0x89abc000;
    return allocation_failure ? NULL : calloc(1, size);
}
#define CHECK(c) do { checks++; if (!(c)) { fprintf(stderr, "check failed at %d: %s\n", __LINE__, #c); return 1; } } while(0)
'''

IO = r'''
#undef airoha_fe_rr
#undef airoha_fe_wr
#undef airoha_fe_rmw
#undef airoha_fe_clear
static u32 airoha_fe_rr(struct airoha_eth *eth, u32 offset) {
    if (offset == REG_PPE_RAM_CTRL(0) || offset == REG_PPE_RAM_CTRL(1))
        return ack_failure ? 0 : PPE_SRAM_CTRL_ACK_MASK;
    if (offset / 4 >= ARRAY_SIZE(registers)) abort();
    return registers[offset / 4];
}
static void airoha_fe_wr(struct airoha_eth *eth, u32 offset, u32 value) {
    if (offset / 4 >= ARRAY_SIZE(registers)) abort();
    registers[offset / 4] = value;
    writes++;
}
static void airoha_fe_rmw(struct airoha_eth *eth, u32 offset, u32 mask, u32 value) {
    airoha_fe_wr(eth, offset, (airoha_fe_rr(eth, offset) & ~mask) | value);
}
static void airoha_fe_clear(struct airoha_eth *eth, u32 offset, u32 mask) {
    airoha_fe_rmw(eth, offset, mask, 0);
}
#define read_poll_timeout_atomic(op,val,condition,delay,timeout,sleep,eth,offset) \
    ({ (val) = op((eth),(offset)); (condition) ? 0 : -ETIMEDOUT; })
'''

MAIN = r'''
int main(void) {
    unsigned versions[] = { 0x7563, 0x7581, 0x7583 };
    for (unsigned v = 0; v < ARRAY_SIZE(versions); v++) {
        for (int banks = 1; banks <= 2; banks++) {
            struct airoha_eth_soc_data soc = { .version=versions[v], .num_ppe=banks };
            struct airoha_eth eth = { .soc=&soc };
            struct airoha_ppe ppe = { .eth=&eth };
            bool sram_only = versions[v] == 0x7563;
            u32 sram = (sram_only ? 512 : PPE_SRAM_NUM_ENTRIES) * banks;
            u32 total = sram + (sram_only ? 0 : PPE_DRAM_NUM_ENTRIES);
            CHECK(airoha_ppe_get_total_num_entries(&ppe) == total);
            cpu_allocations = dma_allocations = 0;
            allocation_failure = false;
            ppe.foe = airoha_ppe_alloc_foe(&ppe, total * sizeof(struct airoha_foe_entry));
            CHECK(ppe.foe != NULL);
            CHECK(cpu_allocations == (unsigned)sram_only);
            CHECK(dma_allocations == (unsigned)!sram_only);
            CHECK(sram_only ? ppe.foe_dma == 0 : ppe.foe_dma == 0x89abc000);
            memset(registers, 0xff, sizeof(registers));
            airoha_ppe_hw_init(&ppe);
            for (int bank = 0; bank < banks; bank++) {
                u32 dram_mask = PPE_DRAM_TABLE_EN_MASK | PPE_DRAM_HASH0_MODE_MASK |
                    PPE_DRAM_HASH1_MODE_MASK | PPE_DRAM_HASH1_EN_MASK;
                u32 expected_base = sram_only ? 0 : ppe.foe_dma + sram * sizeof(struct airoha_foe_entry);
                CHECK(airoha_fe_rr(&eth, REG_PPE_TB_BASE(bank)) == expected_base);
                CHECK(FIELD_GET(PPE_DRAM_TB_NUM_ENTRY_MASK,
                    airoha_fe_rr(&eth, REG_PPE_TB_CFG(bank))) ==
                    (sram_only ? 0 : PPE_RAM_NUM_ENTRIES_SHIFT(PPE_DRAM_NUM_ENTRIES)));
                if (sram_only)
                    CHECK((airoha_fe_rr(&eth, REG_PPE_TB_HASH_CFG(bank)) & dram_mask) == 0);
                else
                    CHECK(FIELD_GET(PPE_DRAM_HASH1_MODE_MASK,
                        airoha_fe_rr(&eth, REG_PPE_TB_HASH_CFG(bank))) == 3);
            }
            unsigned before = writes;
            CHECK(airoha_ppe_foe_get_entry_locked(&ppe, total) == NULL);
            CHECK(airoha_ppe_foe_get_entry_locked(&ppe, UINT32_MAX) == NULL);
            CHECK(writes == before);
            CHECK(airoha_ppe_foe_get_entry_locked(&ppe, 0) == ppe.foe);
            CHECK(airoha_ppe_foe_get_entry_locked(&ppe, sram - 1) ==
                  (char *)ppe.foe + (sram - 1) * sizeof(struct airoha_foe_entry));
            before = writes;
            CHECK(airoha_ppe_foe_commit_sram_entry(&ppe, sram) == -EINVAL);
            CHECK(airoha_ppe_foe_commit_sram_entry(&ppe, UINT32_MAX) == -EINVAL);
            CHECK(writes == before);
            CHECK(airoha_ppe_foe_commit_sram_entry(&ppe, sram - 1) == 0);
            ack_failure = true;
            CHECK(airoha_ppe_foe_get_entry_locked(&ppe, 0) == NULL);
            CHECK(airoha_ppe_foe_commit_sram_entry(&ppe, 0) == -ETIMEDOUT);
            ack_failure = false;
            free(ppe.foe);
            allocation_failure = true;
            CHECK(airoha_ppe_alloc_foe(&ppe, 80) == NULL);
            allocation_failure = false;
        }
    }
    printf("SRAM_POLICY_CHECKS %u\n", checks);
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ported-source", type=Path, required=True)
    parser.add_argument("--baseline-driver", type=Path, required=True)
    parser.add_argument("--host-prefix", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    args.work.mkdir()
    source = args.ported_source.read_text()
    names = ["airoha_ppe_get_sram_num_entries", "airoha_ppe_get_total_sram_num_entries",
             "airoha_ppe_get_total_num_entries", "airoha_ppe_hw_init",
             "airoha_ppe_foe_get_entry_locked", "airoha_ppe_foe_commit_sram_entry",
             "airoha_ppe_alloc_foe"]
    constants = "".join(defines((args.baseline_driver / name).read_text())
                        for name in ("airoha_regs.h", "airoha_eth.h"))
    fixture = PRELUDE + constants + IO + "\n".join(function(source, name) for name in names) + MAIN
    path = args.work / "actual-functions.c"
    path.write_text(fixture)
    env = dict(os.environ, PATH=str(args.host_prefix / "usr/bin") + ":/usr/bin:/bin",
               LD_LIBRARY_PATH=str(args.host_prefix / "usr/lib/x86_64-linux-gnu"))
    command = [str(args.host_prefix / "usr/bin/gcc"), "--sysroot=" + str(args.host_prefix),
               "-isystem", str(args.host_prefix / "usr/include/x86_64-linux-gnu"),
               "-std=gnu11", "-O1", "-g", "-fsanitize=undefined", "-fno-sanitize-recover=all",
               str(path), "-o", str(args.work / "actual-functions")]
    compiled = subprocess.run(command, capture_output=True, env=env)
    (args.work / "compile.log").write_bytes(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError("Actual-function compilation failed; inspect compile.log")
    tested = subprocess.run([str(args.work / "actual-functions")], capture_output=True, env=env, timeout=15)
    (args.work / "test.log").write_bytes(tested.stdout + tested.stderr)
    if tested.returncode:
        raise RuntimeError("Actual-function checks failed; inspect test.log")
    match = re.search(rb"SRAM_POLICY_CHECKS (\d+)", tested.stdout)
    if not match:
        raise RuntimeError("Missing policy test receipt")
    report = dict(checks=int(match[1]), actual_functions=names, ubsan_passed=True,
        source_sha256=hashlib.sha256(args.ported_source.read_bytes()).hexdigest(),
        host_types_and_registers_substituted=True, full_kernel_built=False,
        target_executed=False, hardware_qualified=False)
    (args.work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
