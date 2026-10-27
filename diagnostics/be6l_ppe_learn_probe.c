// SPDX-License-Identifier: GPL-2.0-only
/* Typed AN7563 classifier preflight; read-only unless enable AND lab_exclusive.
 * The lab window changes only known IPv4 learning bits, with no parent actions
 * and the running driver's routed-bind guards intact. RTNL does not replace its
 * private flow/SRAM locks. The owner must independently prove all banks have no
 * BND entries and exclude competing TC/driver/radio/configuration work.
 */
#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <net/net_namespace.h>
#include "airoha_eth.h"
#include "airoha_regs.h"

static const unsigned char expected_module_layout[sizeof(struct module)]
	__used __section(".be6l_module_layout") = {1};

static bool enable;
module_param(enable, bool, 0400);
MODULE_PARM_DESC(enable, "Enable bounded IPv4 UNB-learning lab window (default read-only)");
static bool lab_exclusive;
module_param(lab_exclusive, bool, 0400);
MODULE_PARM_DESC(lab_exclusive, "Owner verified all-bank no-BND/no-AP/no-TC/no competing writers; not an atomic kernel proof");
static unsigned int seconds = 1;
module_param(seconds, uint, 0400);
MODULE_PARM_DESC(seconds, "Synchronous kernel-controlled lab window, constrained to 1..5 seconds");

#define MAX_PORT_RECORDS (AIROHA_MAX_NUM_GDM_PORTS * AIROHA_MAX_NUM_GDM_DEVS)
struct bank_snapshot {
	u32 global, flow, table, hash, cpu[2];
};
struct port_snapshot {
	char name[IFNAMSIZ];
	u32 port, qdma, forward_port, cpu_port, expected_cpu_port;
};
/* This fixture requires the validated single-PPE AN7563 topology. Do not read
 * the second-bank address hole: the live one-bank device returns deadbeef.
 */
static struct bank_snapshot banks[1];
static unsigned int bank_count;
static struct port_snapshot ports[MAX_PORT_RECORDS];
static unsigned int port_count;
static bool preflight_passed;
static struct dentry *report;
static u32 config_before, config_active, config_restored;
static unsigned int flow_before, l2_before, flow_after, l2_after;
static bool register_written, restored_exact, ownership_conflict;
static const char *last_stage = "not-started";
static int preflight_errno;
static unsigned int checks_passed, failed_port = ~0U, failed_device = ~0U;
static char observed_driver[64];
static u32 observed_version, observed_ppe_count;
static u64 resource_start, resource_bytes;
static bool device_found, registers_read;

static int preflight_failure(const char *stage, int error)
{
	last_stage = stage;
	pr_info("be6l_ppe_learn_probe: preflight stage=%s errno=%d checks=%u port=%u device=%u enable=%u register_written=%u\n",
		stage, error, checks_passed, failed_port, failed_device,
		enable, register_written);
	return error;
}

#define REQUIRE_PREFLIGHT(condition, stage, error) do { \
	last_stage = (stage); \
	if (!(condition)) \
		return preflight_failure((stage), (error)); \
	checks_passed++; \
} while (0)

static int probe_show(struct seq_file *s, void *unused)
{
	unsigned int i;

	seq_printf(s, "version=1 read_only=%u requested_enable=%u requested_seconds=%u\n",
		   !register_written, enable, seconds);
	seq_printf(s, "preflight_errno=%d last_stage=%s checks_passed=%u device_found=%u registers_read=%u\n",
		   preflight_errno, last_stage, checks_passed, device_found, registers_read);
	seq_printf(s, "observed_driver=%s observed_soc=%04x observed_ppe_count=%u resource_start=%llx resource_bytes=%llu\n",
		   observed_driver[0] ? observed_driver : "unavailable",
		   observed_version, observed_ppe_count, resource_start, resource_bytes);
	seq_printf(s, "failed_port=%u failed_device=%u probe_loaded_does_not_imply_preflight_pass=1\n",
		   failed_port, failed_device);
	seq_printf(s, "configuration_preflight=%u sram_commands=0 descriptors_changed=0\n",
		   preflight_passed);
	seq_printf(s, "all_bank_bound_entries_verified_by_module=0 lab_exclusive_owner_assertion=%u\n",
		   lab_exclusive);
	seq_puts(s, "private_driver_lock_held=0 hardware_forward_admission_changed=0\n");
	seq_printf(s, "config_before=%08x config_active=%08x config_restored=%08x restored_exact=%u ownership_conflict=%u\n",
		   config_before, config_active, config_restored,
		   restored_exact, ownership_conflict);
	seq_printf(s, "flow_before=%u l2_before=%u flow_after=%u l2_after=%u\n",
		   flow_before, l2_before, flow_after, l2_after);
	seq_printf(s, "entry_bytes=%zu only_writable_mask=%08x\n",
		   sizeof(struct airoha_foe_entry),
		   (u32)(PPE_FLOW_CFG_IP4_NAT_MASK | PPE_FLOW_CFG_IP4_NAPT_MASK));
	for (i = 0; i < bank_count; i++)
		seq_printf(s, "bank=%u global=%08x flow=%08x table=%08x hash=%08x cpu0=%08x cpu1=%08x\n",
			   i, banks[i].global, banks[i].flow, banks[i].table,
			   banks[i].hash, banks[i].cpu[0], banks[i].cpu[1]);
	for (i = 0; i < port_count; i++)
		seq_printf(s, "netdev=%s port=%u qdma=%u forward_port=%u cpu=%u expected_cpu=%u\n",
			   ports[i].name, ports[i].port, ports[i].qdma,
			   ports[i].forward_port, ports[i].cpu_port,
			   ports[i].expected_cpu_port);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(probe);

/* No private helper lock pretends to serialize the driver. With no admitted
 * software parents, RX cannot install an action. Automatic routed attempts
 * remain refused by the unchanged running driver.
 */
static bool parents_empty(struct airoha_eth *eth)
{
	return !atomic_read(&eth->flow_table.nelems) &&
	       !atomic_read(&eth->ppe->l2_flows.nelems) &&
	       hlist_empty(&eth->ppe->ingress_flows) &&
	       hlist_empty(&eth->ppe->wlan_flows);
}

static bool configuration_owned(struct airoha_eth *eth)
{
	unsigned int i;

	for (i = 0; i < bank_count; i++)
		if ((readl(eth->fe_regs + REG_PPE_GLO_CFG(i)) & ~PPE_GLO_CFG_BUSY_MASK) !=
		    (banks[i].global & ~PPE_GLO_CFG_BUSY_MASK) ||
		    readl(eth->fe_regs + REG_PPE_TB_CFG(i)) != banks[i].table ||
		    readl(eth->fe_regs + REG_PPE_TB_HASH_CFG(i)) != banks[i].hash ||
		    readl(eth->fe_regs + REG_PPE_DFT_CPORT_BASE(i)) != banks[i].cpu[0] ||
		    readl(eth->fe_regs + REG_PPE_DFT_CPORT_BASE(i) + 4) != banks[i].cpu[1])
			return false;
	return readl(eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0)) == config_active;
}

/* Synchronous init retains device_lock -> RTNL until exact restoration. Host
 * disconnection cannot skip cleanup. There is no delayed or unjoined work.
 * The deadline is scheduler-bounded, not hard real time if the kernel stalls.
 * Existing aging retires UNB entries; no table or cache clear is performed.
 */
static int learning_window(struct airoha_eth *eth)
{
	ktime_t deadline;
	u32 observed_flow;
	int err = 0;

	flow_before = atomic_read(&eth->flow_table.nelems);
	l2_before = atomic_read(&eth->ppe->l2_flows.nelems);
	if (!lab_exclusive || !parents_empty(eth))
		return -EBUSY;
	config_before = readl(eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0));
	if (config_before != banks[0].flow)
		return -ESTALE;
	config_active = config_before | PPE_FLOW_CFG_IP4_NAT_MASK |
			PPE_FLOW_CFG_IP4_NAPT_MASK;
	if (!parents_empty(eth))
		return -EBUSY;
	register_written = true;
	writel(config_active, eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0));
	if (readl(eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0)) != config_active) {
		err = -EIO;
		goto restore;
	}
	deadline = ktime_add_ms(ktime_get(), seconds * 1000);
	pr_info("be6l_ppe_learn_probe: LAB LEARNING ONLY original=%08x active=%08x seconds=%u; external no-BND/no-writer preflight required\n",
		config_before, config_active, seconds);
	while (ktime_before(ktime_get(), deadline)) {
		if (!parents_empty(eth)) {
			err = -EBUSY;
			break;
		}
		if (!configuration_owned(eth)) {
			ownership_conflict = true;
			err = -ESTALE;
			break;
		}
		msleep(10);
	}
restore:
	observed_flow = readl(eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0));
	if (observed_flow != config_active) {
		ownership_conflict = true;
		if (!err)
			err = -ESTALE;
	}
	writel(config_before, eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0));
	config_restored = readl(eth->fe_regs + REG_PPE_PPE_FLOW_CFG(0));
	restored_exact = config_restored == config_before;
	if (!restored_exact)
		err = -EIO;
	flow_after = atomic_read(&eth->flow_table.nelems);
	l2_after = atomic_read(&eth->ppe->l2_flows.nelems);
	if (!parents_empty(eth) && !err)
		err = -EBUSY;
	pr_info("be6l_ppe_learn_probe: restored=%08x exact=%u conflict=%u flow=%u/%u l2=%u/%u result=%d; no BIND action or SRAM command issued\n",
		config_restored, restored_exact, ownership_conflict,
		flow_before, flow_after, l2_before, l2_after, err);
	return err;
}

/* Called under device_lock followed by RTNL. These locks pin typed lifetime,
 * not the private flow_offload_mutex or ppe_lock. No SRAM command is issued.
 */
static int collect_configuration(struct device *device)
{
	struct platform_device *pdev = to_platform_device(device);
	struct airoha_eth *eth = platform_get_drvdata(pdev);
	struct resource *resource;
	unsigned int i, j;

	REQUIRE_PREFLIGHT(device->driver, "driver-present", -ENODEV);
	strscpy(observed_driver, device->driver->name, sizeof(observed_driver));
	REQUIRE_PREFLIGHT(!strcmp(observed_driver, "airoha_eth"), "driver-name", -ENODEV);
	REQUIRE_PREFLIGHT(device->of_node, "of-node-present", -ENODEV);
	REQUIRE_PREFLIGHT(of_device_is_compatible(device->of_node, "airoha,an7563-eth"),
			  "of-compatible", -ENODEV);
	REQUIRE_PREFLIGHT(eth, "driver-data-present", -ENODEV);
	REQUIRE_PREFLIGHT(eth->dev == device, "eth-device-membership", -ENODEV);
	REQUIRE_PREFLIGHT(eth->soc, "soc-data-present", -ENODEV);
	observed_version = eth->soc->version;
	observed_ppe_count = eth->soc->num_ppe;
	REQUIRE_PREFLIGHT(observed_version == 0x7563, "soc-version", -ENODEV);
	REQUIRE_PREFLIGHT(observed_ppe_count == 1, "soc-ppe-count", -ENODEV);
	bank_count = observed_ppe_count;
	REQUIRE_PREFLIGHT(eth->fe_regs, "fe-mapping-present", -ENODEV);
	REQUIRE_PREFLIGHT(eth->ppe, "ppe-present", -ENODEV);
	REQUIRE_PREFLIGHT(eth->ppe->eth == eth, "ppe-eth-membership", -ENODEV);
	REQUIRE_PREFLIGHT(eth->ppe->foe, "foe-table-present", -ENODEV);
	REQUIRE_PREFLIGHT(eth->ppe->foe_flow, "foe-flow-table-present", -ENODEV);
	REQUIRE_PREFLIGHT(eth->ppe->foe_owner, "foe-owner-table-present", -ENODEV);
	resource = platform_get_resource_byname(pdev, IORESOURCE_MEM, "fe");
	REQUIRE_PREFLIGHT(resource, "fe-resource-present", -ENODEV);
	resource_start = resource->start;
	resource_bytes = resource_size(resource);
	REQUIRE_PREFLIGHT(resource_start == 0x1fb50000, "fe-resource-start", -ENODEV);
	REQUIRE_PREFLIGHT(resource_bytes >= REG_PPE_TB_HASH_CFG(bank_count - 1) + sizeof(u32),
			  "fe-resource-bounds", -ENODEV);

	BUILD_BUG_ON(sizeof(struct airoha_foe_entry) != 80);
	BUILD_BUG_ON((PPE_FLOW_CFG_IP4_NAT_MASK | PPE_FLOW_CFG_IP4_NAPT_MASK) != 0x3000);
	for (i = 0; i < bank_count; i++) {
		banks[i].global = readl(eth->fe_regs + REG_PPE_GLO_CFG(i));
		banks[i].flow = readl(eth->fe_regs + REG_PPE_PPE_FLOW_CFG(i));
		banks[i].table = readl(eth->fe_regs + REG_PPE_TB_CFG(i));
		banks[i].hash = readl(eth->fe_regs + REG_PPE_TB_HASH_CFG(i));
		banks[i].cpu[0] = readl(eth->fe_regs + REG_PPE_DFT_CPORT_BASE(i));
		banks[i].cpu[1] = readl(eth->fe_regs + REG_PPE_DFT_CPORT_BASE(i) + 4);
		pr_info("be6l_ppe_learn_probe: bank=%u global=%08x flow=%08x table=%08x hash=%08x cpu0=%08x cpu1=%08x\n",
			i, banks[i].global, banks[i].flow, banks[i].table,
			banks[i].hash, banks[i].cpu[0], banks[i].cpu[1]);
	}
	registers_read = true;
	REQUIRE_PREFLIGHT(banks[0].global & PPE_GLO_CFG_EN_MASK, "bank0-enabled", -EOPNOTSUPP);
	REQUIRE_PREFLIGHT(banks[0].flow == PPE_FLOW_CFG_L2_BRIDGE_MASK, "flow-l2-baseline", -EOPNOTSUPP);
	REQUIRE_PREFLIGHT(FIELD_GET(PPE_SRAM_TB_NUM_ENTRY_MASK, banks[0].table) == 7,
			  "sram-size-encoding", -EOPNOTSUPP);
	REQUIRE_PREFLIGHT(FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, banks[0].table) == 3,
			  "table-miss-policy", -EOPNOTSUPP);
	REQUIRE_PREFLIGHT(!(banks[0].table & PPE_TB_ENTRY_SIZE_MASK), "table-entry-size", -EOPNOTSUPP);
	REQUIRE_PREFLIGHT(banks[0].hash & PPE_SRAM_TABLE_EN_MASK, "sram-table-enabled", -EOPNOTSUPP);
	REQUIRE_PREFLIGHT(!(banks[0].hash & PPE_DRAM_TABLE_EN_MASK), "dram-table-disabled", -EOPNOTSUPP);

	for (i = 0; i < ARRAY_SIZE(eth->ports); i++) {
		struct airoha_gdm_port *port = eth->ports[i];

		if (!port)
			continue;
		failed_port = i;
		failed_device = ~0U;
		REQUIRE_PREFLIGHT(port->id >= AIROHA_GDM1_IDX && port->id <= AIROHA_GDM4_IDX,
				  "gdm-port-id", -EINVAL);
		for (j = 0; j < ARRAY_SIZE(port->devs); j++) {
			struct airoha_gdm_dev *gdm = port->devs[j];
			struct airoha_qdma *qdma;
			struct port_snapshot *record;
			struct net_device *netdev;
			u32 fport, qid, cport;

			if (!gdm)
				continue;
			failed_device = j;
			REQUIRE_PREFLIGHT(gdm->port == port, "gdm-port-membership", -EINVAL);
			REQUIRE_PREFLIGHT(gdm->eth == eth, "gdm-eth-membership", -EINVAL);
			REQUIRE_PREFLIGHT(port_count < MAX_PORT_RECORDS, "port-record-capacity", -EINVAL);
			netdev = netdev_from_priv(gdm);
			REQUIRE_PREFLIGHT(dev_net(netdev) == &init_net, "netdev-initial-netns", -EOPNOTSUPP);
			REQUIRE_PREFLIGHT(netdev->dev.parent == device, "netdev-device-parent", -EOPNOTSUPP);
			qdma = rcu_dereference_protected(gdm->qdma, lockdep_rtnl_is_held());
			if (qdma == &eth->qdma[0])
				qid = 0;
			else if (qdma == &eth->qdma[1])
				qid = 1;
			else
				return preflight_failure("qdma-membership", -EINVAL);
			checks_passed++;
			/* Exact pure mapping in the pinned airoha_get_fe_port(). */
			fport = port->id == AIROHA_GDM4_IDX ? FE_PSE_PORT_GDM4 : port->id;
			REQUIRE_PREFLIGHT(fport < 16, "forward-port-range", -EINVAL);
			cport = (banks[0].cpu[fport / 8] >> ((fport % 8) * 4)) & 0xf;
			record = &ports[port_count++];
			strscpy(record->name, netdev->name, sizeof(record->name));
			record->port = port->id;
			record->qdma = qid;
			record->forward_port = fport;
			record->cpu_port = cport;
			record->expected_cpu_port = qid ? FE_PSE_PORT_CDM2 : FE_PSE_PORT_CDM1;
			pr_info("be6l_ppe_learn_probe: netdev=%s port=%u qdma=%u fport=%u cpu=%u expected=%u\n",
				record->name, record->port, record->qdma, record->forward_port,
				record->cpu_port, record->expected_cpu_port);
			REQUIRE_PREFLIGHT(cport == record->expected_cpu_port, "cpu-port-mapping", -EOPNOTSUPP);
		}
	}
	flow_before = atomic_read(&eth->flow_table.nelems);
	l2_before = atomic_read(&eth->ppe->l2_flows.nelems);
	flow_after = flow_before;
	l2_after = l2_before;
	config_before = banks[0].flow;
	config_active = config_before;
	config_restored = config_before;
	REQUIRE_PREFLIGHT(port_count, "nonempty-gdm-topology", -ENODEV);
	failed_port = ~0U;
	failed_device = ~0U;
	last_stage = "configuration-complete";
	return 0;
}

static int __init learn_probe_init(void)
{
	struct device *device;
	int err;

	if (seconds < 1 || seconds > 5)
		return preflight_failure("seconds-range", -EINVAL);
	device = bus_find_device_by_name(&platform_bus_type, NULL, "1fb50000.ethernet");
	if (!device) {
		err = preflight_failure("platform-device-lookup", -ENODEV);
		goto preflight_finished;
	}
	device_found = true;
	device_lock(device);
	rtnl_lock();
	err = collect_configuration(device);
	preflight_errno = err;
	preflight_passed = !err;
	if (!err && enable) {
		last_stage = "learning-window";
		err = learning_window(platform_get_drvdata(to_platform_device(device)));
		if (!err)
			last_stage = "learning-restored";
	}
	rtnl_unlock();
	device_unlock(device);
	put_device(device);
	if (err && enable)
		return err;
preflight_finished:
	if (!device_found) {
		preflight_errno = err;
		if (enable)
			return err;
	}
	/* Read-only mode preserves a failed preflight as report data. It does not
	 * grant eligibility: active mode still returns the original error and can
	 * reach its write path only after every unchanged precondition passed.
	 */
	report = debugfs_create_file("be6l_ppe_learn_probe", 0400, NULL, NULL,
				   &probe_fops);
	if (IS_ERR(report))
		return PTR_ERR(report);
	pr_info("be6l_ppe_learn_probe: diagnostic available stage=%s preflight_errno=%d preflight_passed=%u register_written=%u restored_exact=%u; load success is not eligibility\n",
		last_stage, preflight_errno, preflight_passed,
		register_written, restored_exact);
	return 0;
}

static void __exit learn_probe_exit(void)
{
	debugfs_remove(report);
}

module_init(learn_probe_init);
module_exit(learn_probe_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Typed AN7563 preflight and bounded exclusive UNB-learning lab fixture");
