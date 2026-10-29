/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BE6L_WIRED_DIAG_V1_H
#define BE6L_WIRED_DIAG_V1_H
#include <linux/types.h>
#include <net/flow_offload.h>
#define BD_SLOTS 4
#define BD_ACTIONS 16
struct airoha_ppe;
struct be6l_diag;
struct sk_buff;
struct bd_config {
	bool enabled; /* A zero-initialized configuration is inert. */
	int lan_ifindex, wan_ifindex, expected_dsa_port;
	u64 generation, duration_ns;
};
struct bd_action_copy {
	u32 id, htype, offset, mask, value, checksum_flags;
};
struct bd_row {
	bool used, rx_matched;
	u8 direction, tos;
	u16 tcp_flags, tcp_mask;
	u32 key[3], output_ifindex, action_count;
	u32 unbound[20];
	u64 observed_ns, rx_ns;
	struct flow_rule_ct_context context;
	struct bd_action_copy actions[BD_ACTIONS];
};
struct bd_snapshot {
	bool active, spent, can_publish;
	u32 unresolved, reason, input_ifindex[3], refs_owned;
	u64 generation, created_ns, deadline_ns, accepted, rejected;
	struct bd_row rows[BD_SLOTS];
};
/* Internal library API only: no exported symbol, module entry, debugfs write,
 * arming interface or production driver hook is installed by this experiment.
 * Calls must finish before destroy; the future owning driver must drain taps.
 */
struct be6l_diag *be6l_diag_create(struct airoha_ppe *, const struct bd_config *);
void be6l_diag_destroy(struct be6l_diag *);
int be6l_diag_note_ct(struct be6l_diag *, const struct flow_rule *);
bool be6l_diag_note_rx(struct be6l_diag *, struct sk_buff *, const u32 unbound[20]);
void be6l_diag_snapshot(struct be6l_diag *, struct bd_snapshot *);
#endif
