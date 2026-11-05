# SPDX-License-Identifier: MIT
"""Port X-Wrt's AN7563 SRAM-only table policy to the pinned local driver.

Creates a fresh source fragment and patch only. Routed admission and existing
flash/DMA shutdown protection remain in place. Full build and target tests
are separate gates; this is not a claim of complete NPU/NAT support.
"""
from pathlib import Path
import argparse
import difflib
import hashlib
import json

PIN = "6bf954bf5eef737a338978ec1af3a8e29538f9815398c06162f3d621a597d1d4"
UPSTREAM = "5ae8e6912e64682fcad54593467e84c80f170656"


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Pinned driver context missing/ambiguous: " + before[:70])
    return text.replace(before, after, 1)


def prepare(source, output):
    path = source / "airoha_ppe.c"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != PIN:
        raise ValueError("Unexpected baseline driver source")
    old = data.decode()
    new = replace_once(old, "#include <linux/rhashtable.h>",
                       "#include <linux/rhashtable.h>\n#include <linux/slab.h>")
    new = replace_once(new, "\treturn sram_num_entries + PPE_DRAM_NUM_ENTRIES;", '''	/* X-Wrt AN7563 policy: hardware uses SRAM; no DRAM FOE reservation. */
\treturn sram_num_entries + (airoha_is_7563(ppe->eth) ? 0 :
\t\t\t\t  PPE_DRAM_NUM_ENTRIES);''')
    new = replace_once(new, '''\tstruct airoha_eth *eth = ppe->eth;
\tint i, sram_num_stats_entries;''', '''\tstruct airoha_eth *eth = ppe->eth;
\tbool sram_only = airoha_is_7563(eth);
\tint i, sram_num_stats_entries;''')
    new = replace_once(new, "\tdram_num_entries = PPE_RAM_NUM_ENTRIES_SHIFT(PPE_DRAM_NUM_ENTRIES);", '''\tdram_num_entries = sram_only ? 0 :
\t\tPPE_RAM_NUM_ENTRIES_SHIFT(PPE_DRAM_NUM_ENTRIES);''')
    new = replace_once(new, "\t\t\t     ppe->foe_dma + sram_tb_size);", "\t\t\t     sram_only ? 0 : ppe->foe_dma + sram_tb_size);")
    new = replace_once(new, "\t\t\t      FIELD_PREP(PPE_DRAM_HASH1_MODE_MASK, 3));", '''\t\t\t      FIELD_PREP(PPE_DRAM_HASH1_MODE_MASK,
\t\t\t\t\t sram_only ? 0 : 3));
\t\tif (sram_only)
\t\t\tairoha_fe_clear(eth, REG_PPE_TB_HASH_CFG(i),
\t\t\t\tPPE_DRAM_TABLE_EN_MASK | PPE_DRAM_HASH0_MODE_MASK |
\t\t\t\tPPE_DRAM_HASH1_MODE_MASK | PPE_DRAM_HASH1_EN_MASK);''')
    needle = '''\tlockdep_assert_held(&ppe_lock);

\tif (hash < sram_num_entries) {'''
    new = replace_once(new, needle, '''\tlockdep_assert_held(&ppe_lock);

\tif (hash >= airoha_ppe_get_total_num_entries(ppe))
\t\treturn NULL;

\tif (hash < sram_num_entries) {''')
    new = replace_once(new, '''\tstruct airoha_foe_entry *hwe = ppe->foe + hash * sizeof(*hwe);
\tbool ppe2 = hash >= airoha_ppe_get_sram_num_entries(ppe);
\tu32 *ptr = (u32 *)hwe, val;
\tint i;

\tfor (i = 0; i < sizeof(*hwe) / sizeof(*ptr); i++)''', '''\tstruct airoha_foe_entry *hwe;
\tbool ppe2 = hash >= airoha_ppe_get_sram_num_entries(ppe);
\tu32 *ptr, val;
\tint i;

\tif (hash >= airoha_ppe_get_total_sram_num_entries(ppe))
\t\treturn -EINVAL;
\thwe = ppe->foe + hash * sizeof(*hwe);
\tptr = (u32 *)hwe;
\tfor (i = 0; i < sizeof(*hwe) / sizeof(*ptr); i++)''')
    new = replace_once(new, '''\tstruct airoha_foe_entry *hwe = ppe->foe + hash * sizeof(*hwe);
\tu32 ts = airoha_ppe_get_timestamp(ppe);''', '''\tstruct airoha_foe_entry *hwe;
\tu32 ts = airoha_ppe_get_timestamp(ppe);''')
    new = replace_once(new, '''\tint err = 0;

\tmemcpy(&hwe->d, &e->d, sizeof(*hwe) - sizeof(hwe->ib1));''', '''\tint err = 0;

\tif (hash >= airoha_ppe_get_total_num_entries(ppe))
\t\treturn -EINVAL;
\thwe = ppe->foe + hash * sizeof(*hwe);
\tmemcpy(&hwe->d, &e->d, sizeof(*hwe) - sizeof(hwe->ib1));''')
    insertion = "int airoha_ppe_init(struct airoha_eth *eth)"
    new = replace_once(new, insertion, '''static void *airoha_ppe_alloc_foe(struct airoha_ppe *ppe, size_t size)
{
\t/* The SRAM mirror is CPU memory and must not become a DMA table. */
\tif (airoha_is_7563(ppe->eth))
\t\treturn devm_kzalloc(ppe->eth->dev, size, GFP_KERNEL);

\treturn dmam_alloc_coherent(ppe->eth->dev, size, &ppe->foe_dma,
\t\t\t\t   GFP_KERNEL);
}

''' + insertion)
    new = replace_once(new, '''\tppe->foe = dmam_alloc_coherent(eth->dev, foe_size, &ppe->foe_dma,
\t\t\t\t       GFP_KERNEL);''', "\tppe->foe = airoha_ppe_alloc_foe(ppe, foe_size);")
    # Preserve the real baseline refusal and shutdown functions byte for byte.
    for marker in ("PPE_FLOW_CFG_L2_BRIDGE_MASK", "be6l_diag_driver_stop", "wired_dead"):
        if new.count(marker) != old.count(marker):
            raise ValueError("Unrelated driver behavior changed")
    output.mkdir()
    (output / "airoha_ppe.c").write_text(new, newline="\n")
    (output / "airoha_regs.h").write_bytes((source / "airoha_regs.h").read_bytes())
    patch = ("From: BE6L Pro project contributors\n"
             "Subject: [PATCH] net: airoha: port X-Wrt AN7563 SRAM-only policy\n\n"
             "Based on X-Wrt " + UPSTREAM + " 941-06, retaining its authorship\n"
             "and the existing GPL-2.0-only Airoha driver license. SRAM mirrors\n"
             "are ordinary CPU memory; no DRAM table address is published.\n"
             "This first port does not enable routed admission.\n\n")
    patch += "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
        fromfile="a/drivers/net/ethernet/airoha/airoha_ppe.c",
        tofile="b/drivers/net/ethernet/airoha/airoha_ppe.c"))
    (output / "979-xwrt-an7563-sram-only-policy.patch").write_text(patch, newline="\n")
    report = dict(upstream_repository="https://github.com/x-wrt/x-wrt", upstream_revision=UPSTREAM,
        upstream_patch="941-06-net-airoha-use-sram-only-ppe-on-an75xx.patch",
        baseline_source_sha256=PIN, source_sha256=hashlib.sha256(new.encode()).hexdigest(),
        patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
        changed_driver_files=["airoha_ppe.c"], an7563_cpu_sram_mirror=True,
        dram_table_disabled=True, routed_admission_enabled=False,
        sdk_modified=False, full_kernel_built=False, target_executed=False)
    (output / "preparation.json").write_text(json.dumps(report, indent=2) + "\n", newline="\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), indent=2))
