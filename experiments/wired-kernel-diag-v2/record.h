/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BE6L_DIAG_RECORD_V2_H
#define BE6L_DIAG_RECORD_V2_H
/* Called under the adapter's lock. No pointers are dereferenced or retained.
 * These are diagnostic identities, never authority to publish a hardware rule.
 */
static bool bd_identity_valid(const struct flow_rule_ct_context *c)
{
	return c->valid == 1 && c->version == 2 && c->producer == 1 &&
	       c->direction < 2 && c->generation && c->ct_cookie && c->flow_cookie &&
	       c->tuple_cookie[0] && c->tuple_cookie[1] &&
	       c->tuple_cookie[0] != c->tuple_cookie[1];
}
/* 0 duplicate, 1 new row, 2 newer producer generation replacing the same key. */
static void bd_record_revoke_pair(struct bd_row rows[BD_SLOTS],
				  const struct flow_rule_ct_context *context)
{
	unsigned int i;
	for (i = 0; i < BD_SLOTS; i++) {
		struct bd_row *row = &rows[i];
		if (row->used && row->context.generation == context->generation &&
		    row->context.flow_cookie == context->flow_cookie &&
		    row->context.ct_cookie == context->ct_cookie) {
			row->used = false;
			row->revoked = true;
		}
	}
}
static int bd_record_replace(struct bd_row rows[BD_SLOTS], const struct bd_row *row)
{
	int i, slot = -1, result = 1;
	if (!bd_identity_valid(&row->context) || !row->used || row->revoked ||
	    row->direction != row->context.direction || row->action_count > BD_ACTIONS)
		return -EINVAL;
	for (i = 0; i < BD_SLOTS; i++) {
		struct bd_row *old = &rows[i];
		if (!old->used && !old->revoked) {
			if (slot < 0)
				slot = i;
			continue;
		}
		if (memcmp(old->key, row->key, sizeof(row->key)))
			continue;
		if (old->context.generation == row->context.generation) {
			if (old->revoked)
				return -ESTALE;
			if (memcmp(&old->context, &row->context, sizeof(row->context)) ||
			    old->direction != row->direction || old->tos != row->tos ||
			    old->output_ifindex != row->output_ifindex ||
			    old->action_count != row->action_count ||
			    memcmp(old->actions, row->actions, sizeof(row->actions))) {
				bd_record_revoke_pair(rows, &old->context);
				return -EEXIST;
			}
			return 0;
		}
		if (row->context.generation < old->context.generation)
			return -ESTALE;
		bd_record_revoke_pair(rows, &old->context);
		slot = i;
		result = 2;
		break;
	}
	if (slot < 0)
		return -ENOSPC;
	memcpy(&rows[slot], row, sizeof(*row));
	/* A newly observed producer cannot inherit packet evidence from an older
	 * generation, even if a future caller accidentally supplies such fields.
	 */
	rows[slot].rx_matched = false;
	rows[slot].rx_ns = 0;
	memset(rows[slot].unbound, 0, sizeof(rows[slot].unbound));
	memset(&rows[slot].egress, 0, sizeof(rows[slot].egress));
	return result;
}
static unsigned int bd_record_destroy(struct bd_row rows[BD_SLOTS],
				     const struct flow_rule_ct_context *context,
				     unsigned long cookie)
{
	unsigned int i, removed = 0;
	if (!bd_identity_valid(context) || cookie != context->tuple_cookie[context->direction])
		return 0;
	for (i = 0; i < BD_SLOTS; i++) {
		struct bd_row *row = &rows[i];
		if (row->used && !memcmp(&row->context, context, sizeof(*context))) {
			row->used = false;
			row->revoked = true;
			removed++;
		}
	}
	return removed;
}
/* Correlate a software egress with the same borrowed CT and both Linux rule
 * directions. This does not establish a per-packet generation or admit BIND.
 */
static bool bd_record_egress(struct bd_row rows[BD_SLOTS], const struct bd_egress *sample)
{
	unsigned int i, j;
	if (sample->direction > 1 || !sample->ct_cookie || sample->delivered)
		return false;
	for (i = 0; i < BD_SLOTS; i++) {
		struct bd_row *row = &rows[i];
		const struct flow_rule_ct_context *c = &row->context;
		if (!row->used || row->direction != sample->direction ||
		    c->ct_cookie != sample->ct_cookie ||
		    row->output_ifindex != sample->logical_output_ifindex)
			continue;
		for (j = 0; j < BD_SLOTS; j++) {
			const struct bd_row *opposite = &rows[j];
			const struct flow_rule_ct_context *other = &opposite->context;
			u32 ports;
			if (!opposite->used || opposite->direction == row->direction ||
			    other->generation != c->generation || other->ct_cookie != c->ct_cookie ||
			    other->flow_cookie != c->flow_cookie ||
			    memcmp(other->tuple_cookie, c->tuple_cookie, sizeof(c->tuple_cookie)))
				continue;
			ports = (opposite->key[2] << 16) | (opposite->key[2] >> 16);
			if (sample->key[0] != opposite->key[1] || sample->key[1] != opposite->key[0] ||
			    sample->key[2] != ports)
				continue;
			memcpy(&row->egress, sample, sizeof(*sample));
			return true;
		}
	}
	return false;
}
#endif
