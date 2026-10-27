// SPDX-License-Identifier: GPL-2.0-only
/* Read the existing host shadow only. The owner first refreshes it through the
 * driver's serialized debugfs reader. No SRAM/MMIO command or hardware access
 * is performed here; equal double copies do not prove an atomic HW snapshot.
 */
#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include "airoha_eth.h"

#define SHADOW_SLOTS 512
#define SHADOW_WORDS 20
#define MAX_RECORDS 16

static const unsigned char expected_module_layout[sizeof(struct module)]
	__used __section(".be6l_module_layout") = {1};

struct shadow_record {
	u32 slot;
	bool equal;
	struct airoha_foe_entry first, second;
};
static struct shadow_record records[MAX_RECORDS];
static unsigned int record_count, candidates, scanned;
static const char *stage = "not-started";
static int snapshot_errno;
static struct dentry *report;

static bool requested_tuple(const struct airoha_foe_entry *entry)
{
	const struct airoha_foe_ipv4_tuple *tuple = &entry->ipv4.orig_tuple;

	if (FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, entry->ib1) != AIROHA_FOE_STATE_UNBIND ||
	    FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, entry->ib1) != PPE_PKT_TYPE_IPV4_HNAPT ||
	    (entry->ib1 & AIROHA_FOE_IB1_BIND_UDP))
		return false;
	return tuple->src_port == 5201 || tuple->src_port == 5202 ||
	       tuple->dest_port == 5201 || tuple->dest_port == 5202;
}

static void copy_entry(struct airoha_foe_entry *destination,
		       const struct airoha_foe_entry *source)
{
	u32 *out = (u32 *)destination;
	const u32 *in = (const u32 *)source;
	unsigned int i;

	for (i = 0; i < SHADOW_WORDS; i++)
		out[i] = READ_ONCE(in[i]);
}

/* Device/RTNL locks pin the typed driver lifetime only. The private SRAM lock
 * is not held. Driver shadow refreshes can race these best-effort host copies.
 */
static int collect_shadow(struct device *device)
{
	struct airoha_eth *eth;
	unsigned int slot;

	BUILD_BUG_ON(sizeof(struct airoha_foe_entry) != SHADOW_WORDS * sizeof(u32));
	stage = "driver";
	if (!device->driver || strcmp(device->driver->name, "airoha_eth"))
		return -ENODEV;
	stage = "compatible";
	if (!of_device_is_compatible(device->of_node, "airoha,an7563-eth"))
		return -ENODEV;
	eth = platform_get_drvdata(to_platform_device(device));
	stage = "typed-eth";
	if (!eth || eth->dev != device || !eth->soc)
		return -ENODEV;
	stage = "single-ppe-an7563";
	if (eth->soc->version != 0x7563 || eth->soc->num_ppe != 1)
		return -EOPNOTSUPP;
	stage = "typed-host-shadow";
	if (!eth->ppe || eth->ppe->eth != eth || !eth->ppe->foe)
		return -ENODEV;

	for (slot = 0; slot < SHADOW_SLOTS; slot++) {
		const struct airoha_foe_entry *source =
			(const struct airoha_foe_entry *)eth->ppe->foe + slot;
		struct airoha_foe_entry first, second;
		struct shadow_record *record;

		copy_entry(&first, source);
		smp_rmb();
		copy_entry(&second, source);
		scanned++;
		if (!requested_tuple(&first) && !requested_tuple(&second))
			continue;
		candidates++;
		if (record_count == MAX_RECORDS)
			continue;
		record = &records[record_count++];
		record->slot = slot;
		record->equal = !memcmp(&first, &second, sizeof(first));
		record->first = first;
		record->second = second;
	}
	stage = "host-shadow-copied";
	return 0;
}

static void print_copy(struct seq_file *s, const char *name,
		       const struct airoha_foe_entry *entry)
{
	const struct airoha_foe_ipv4_tuple *tuple = &entry->ipv4.orig_tuple;
	const u32 *words = (const u32 *)entry;
	unsigned int i;

	seq_printf(s, "%s state=%u type=%u udp=%u tuple=%pI4h:%u->%pI4h:%u raw=",
		   name, (u32)FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, entry->ib1),
		   (u32)FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, entry->ib1),
		   !!(entry->ib1 & AIROHA_FOE_IB1_BIND_UDP), &tuple->src_ip,
		   tuple->src_port, &tuple->dest_ip, tuple->dest_port);
	for (i = 0; i < SHADOW_WORDS; i++)
		seq_printf(s, "%s%08x", i ? "," : "", words[i]);
	seq_putc(s, '\n');
}

static int shadow_show(struct seq_file *s, void *unused)
{
	unsigned int i;

	seq_printf(s, "version=1 source=HOST_SHADOW read_only=1 snapshot_errno=%d stage=%s\n",
		   snapshot_errno, stage);
	seq_puts(s, "external_driver_debugfs_refresh_required=1 refresh_performed_by_module=0\n");
	seq_puts(s, "atomic_hardware_snapshot=0 private_driver_lock_held=0 equality_does_not_exclude_ABA=1\n");
	seq_puts(s, "mmio_access=0 sram_commands=0 packet_or_owner_writes=0\n");
	seq_printf(s, "slots_scanned=%u entry_words=%u candidates=%u records=%u truncated=%u\n",
		   scanned, SHADOW_WORDS, candidates, record_count,
		   candidates > record_count);
	for (i = 0; i < record_count; i++) {
		seq_printf(s, "slot=%u host_double_copy_equal=%u\n", records[i].slot, records[i].equal);
		print_copy(s, "first", &records[i].first);
		print_copy(s, "second", &records[i].second);
	}
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(shadow);

static int __init shadow_init(void)
{
	struct device *device;

	stage = "platform-lookup";
	device = bus_find_device_by_name(&platform_bus_type, NULL, "1fb50000.ethernet");
	if (!device) {
		snapshot_errno = -ENODEV;
	} else {
		device_lock(device);
		rtnl_lock();
		snapshot_errno = collect_shadow(device);
		rtnl_unlock();
		device_unlock(device);
		put_device(device);
	}
	report = debugfs_create_file("be6l_ppe_shadow_observer", 0400, NULL, NULL,
				   &shadow_fops);
	if (IS_ERR(report))
		return PTR_ERR(report);
	pr_info("be6l_ppe_shadow_observer: HOST SHADOW stage=%s errno=%d records=%u; no hardware access\n",
		stage, snapshot_errno, record_count);
	return 0;
}

static void __exit shadow_exit(void)
{
	debugfs_remove(report);
}
module_init(shadow_init);
module_exit(shadow_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Read-only bounded double-copy of existing AN7563 host FOE shadow");
