// SPDX-License-Identifier: GPL-2.0-only
/* Synthetic software-channel exercise; never changes a DMA/queue register. */
#include <linux/debugfs.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include "flow-abi.h"
#include "flow-actions.h"

static void __iomem *area;
static struct dentry *result_file;
static u32 sequence, requests, assertions, errors;
static u32 request[FA_WORDS];
static u32 response[2][FA_ACK_WORDS];
static bool identity_checked;

static bool ready(void)
{
	unsigned int core;
	for (core = 0; core < 2; core++) {
		void __iomem *p = area + core * FA_CORE_STRIDE;
		if (readl(p) != FA_MAGIC || readl(p + 4) != FA_VERSION ||
		    readl(p + 8) != core || readl(p + 12) != 1)
			return false;
	}
	return true;
}

static int transact(u32 operation, u32 expected)
{
	unsigned int core, i;
	u32 ack;
	int ret;

	if (!ready() || sequence > U32_MAX - 2)
		return -EIO;
	sequence += 2;
	request[1] = operation;
	/* Invalidate the request on both workers before updating any body. */
	for (core = 0; core < 2; core++)
		writel(sequence | 1, area + core * FA_CORE_STRIDE + FA_COMMAND);
	wmb();
	for (core = 0; core < 2; core++) {
		void __iomem *q = area + core * FA_CORE_STRIDE + FA_COMMAND;
		for (i = 1; i < FA_WORDS; i++)
			writel(request[i], q + i * 4);
	}
	wmb();
	for (core = 0; core < 2; core++)
		writel(sequence, area + core * FA_CORE_STRIDE + FA_COMMAND);
	for (core = 0; core < 2; core++) {
		void __iomem *a = area + core * FA_CORE_STRIDE + FA_RESPONSE;
		ret = readl_poll_timeout(a, ack, ack == sequence, 10, 100000);
		if (ret)
			return ret;
		rmb();
		for (i = 0; i < FA_ACK_WORDS; i++)
			response[core][i] = readl(a + i * 4);
		if (readl(a) != sequence || response[core][1] != expected ||
		    response[core][2] != core || response[core][3] != request[2] ||
		    response[core][4] != request[3] || response[core][11] != 1)
			return -EPROTO;
		for (i = 4; i < 8; i++)
			if (response[core][i + 2] != request[i])
				return -EPROTO;
		assertions++;
	}
	requests++;
	return 0;
}

static int exercise(void)
{
	unsigned int fixture, i, core;
	int ret;
#define CHECK(op, status) do { ret = transact((op), (status)); if (ret) return ret; } while (0)
	request[2] = 0;
	request[4] = 123; request[5] = 0x89abcdef;
	get_random_bytes(&request[6], 8);
	if (!request[6] && !request[7]) request[6] = 1;
	for (fixture = 0; fixture < ARRAY_SIZE(fa_actions); fixture++) {
		request[3] = fixture + 1; request[4]++;
		memcpy(&request[8], fa_actions[fixture], sizeof(fa_actions[fixture]));
		CHECK(FA_COMMIT, FA_GENERATION);
		CHECK(FA_PREPARE, FA_OK);
		CHECK(FA_SIMULATE, FA_STATE);
		CHECK(FA_COMMIT, FA_OK);
		CHECK(FA_SIMULATE, FA_STATE);
		/* Both workers have acknowledged READY. Only now publish one gate. */
		wmb(); writel(request[3], area + FA_GATES); wmb();
		for (i = 8; i <= 12; i++) {
			request[i]++; CHECK(FA_SIMULATE, FA_MISMATCH); request[i]--;
		}
		for (i = 0; i < 8; i++) CHECK(FA_SIMULATE, FA_OK);
		for (core = 0; core < 2; core++) {
			u64 packets = (u64)response[core][13] << 32 | response[core][12];
			u64 bytes = (u64)response[core][15] << 32 | response[core][14];
			if (packets != 8 || bytes != 8 * fa_lengths[fixture])
				return -ERANGE;
			assertions++;
		}
		CHECK(FA_REVOKE, FA_STATE);
		writel(0, area + FA_GATES); wmb();
		CHECK(FA_REVOKE, FA_OK); CHECK(FA_SIMULATE, FA_STATE);
		CHECK(FA_FENCE, FA_OK); CHECK(FA_SIMULATE, FA_STATE);
		CHECK(FA_RELEASE, FA_OK); CHECK(FA_PREPARE, FA_GENERATION);
	}
	request[3]++;
	request[40] = 1; CHECK(FA_PREPARE, FA_INVALID); request[40] = 0;
	request[2] = FA_SLOTS; CHECK(FA_PREPARE, FA_INVALID); request[2] = 0;
	request[6]++; CHECK(FA_PREPARE, FA_SESSION); request[6]--;
#undef CHECK
	return 0;
}

static int channel_show(struct seq_file *s, void *unused)
{
	seq_printf(s, "FLOW_SOFTWARE_CHANNEL version=%u ready=%u requests=%u assertions=%u errors=%u\n",
		   FA_VERSION, ready(), requests, assertions, errors);
	seq_puts(s, "synthetic_only=1 live_nat=0 live_dma_hooks=0 hardware_drain_proven=0\n");
	seq_printf(s, "gate0=%u last_sequence=%u\n", readl(area + FA_GATES), sequence);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(channel);

static int __init channel_init(void)
{
	struct device *dev;
	struct device_node *node;
	struct resource resource;
	int ret;

	if (!of_machine_is_compatible("tenda,be6l-pro"))
		return -ENODEV;
	dev = bus_find_device_by_name(&platform_bus_type, NULL, "1e900000.npu");
	if (!dev || !dev->of_node) {
		if (dev) put_device(dev);
		return -ENODEV;
	}
	node = of_parse_phandle(dev->of_node, "memory-region", 0);
	put_device(dev);
	if (!node) return -ENODEV;
	ret = of_address_to_resource(node, 0, &resource);
	of_node_put(node);
	if (ret || resource.start != 0x84000000U || resource.end < FA_HOST + FA_BYTES - 1)
		return -EINVAL;
	area = ioremap(FA_HOST, FA_BYTES);
	if (!area) return -ENOMEM;
	if (!ready()) { iounmap(area); return -ENODEV; }
	identity_checked = true;
	ret = exercise();
	if (ret) {
		errors++;
		pr_err("BE6L synthetic flow channel test failed: %d\n", ret);
	}
	/* No live data hooks exist. Close synthetic admission even after failure. */
	writel(0, area + FA_GATES); wmb();
	result_file = debugfs_create_file("be6l_flow_channel", 0400, NULL, NULL, &channel_fops);
	if (IS_ERR_OR_NULL(result_file)) {
		iounmap(area);
		return -ENOMEM;
	}
	return 0;
}

static void __exit channel_exit(void)
{
	debugfs_remove(result_file);
	if (identity_checked) { writel(0, area + FA_GATES); wmb(); }
	iounmap(area);
}
module_init(channel_init);
module_exit(channel_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("BE6L synthetic two-core software flow-channel exercise; no live DMA");
