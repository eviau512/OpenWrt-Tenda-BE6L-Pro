/* The owner publishes once and unpublishes before draining/freeing. RX/TC
 * readers cannot extend the finite lease. Callback return values never change
 * a TC result, routed refusal, PPE owner, or hardware state.
 */
int be6l_diag_driver_arm(struct airoha_ppe *ppe, const struct bd_config *cfg)
{
	struct be6l_diag *d;
	int error = 0;
	mutex_lock(&ppe->diag_mutex);
	if (ppe->diag_spent) {
		error = -EALREADY;
		goto out;
	}
	d = be6l_diag_create(ppe, cfg);
	if (IS_ERR(d)) {
		error = PTR_ERR(d);
		goto out;
	}
	ppe->diag_spent = true;
	rcu_assign_pointer(ppe->route_diag, d);
out:
	mutex_unlock(&ppe->diag_mutex);
	return error;
}
void be6l_diag_driver_command(struct airoha_ppe *ppe, const struct flow_cls_offload *f)
{
	const struct flow_rule_ct_context *c = &f->ct_context;
	struct be6l_diag *d;
	rcu_read_lock();
	d = rcu_dereference(ppe->route_diag);
	if (!d)
		goto out;
	if (!bd_identity_valid(c) || f->cookie != c->tuple_cookie[c->direction])
		goto out;
	if (f->command == FLOW_CLS_REPLACE && f->rule &&
	    !memcmp(c, &f->rule->ct_context, sizeof(*c))) {
		int error = be6l_diag_note_ct(d, f->rule);
		spin_lock_bh(&d->lock);
		if (bd_epoch_live(&d->epoch, ktime_get_ns())) {
			d->snapshot.ct_callbacks++;
			d->snapshot.last_ct_errno = error;
			if (error)
				d->snapshot.ct_callback_rejected++;
		}
		spin_unlock_bh(&d->lock);
	}
	else if (f->command == FLOW_CLS_DESTROY) {
		spin_lock_bh(&d->lock);
		if (bd_epoch_live(&d->epoch, ktime_get_ns()))
			d->snapshot.destroyed += bd_record_destroy(d->snapshot.rows, c, f->cookie);
		spin_unlock_bh(&d->lock);
	}
out:
	rcu_read_unlock();
}
void be6l_diag_driver_rx(struct airoha_ppe *ppe, struct sk_buff *skb, const u32 unbound[20])
{
	struct be6l_diag *d;
	rcu_read_lock();
	d = rcu_dereference(ppe->route_diag);
	if (d)
		be6l_diag_note_rx(d, skb, unbound);
	rcu_read_unlock();
}
void be6l_diag_driver_stop(struct airoha_ppe *ppe)
{
	struct be6l_diag *d;
	mutex_lock(&ppe->diag_mutex);
	/* Prevent an arm racing with removal when no session had been opened. */
	ppe->diag_spent = true;
	d = rcu_replace_pointer(ppe->route_diag, NULL, lockdep_is_held(&ppe->diag_mutex));
	if (d) {
		synchronize_rcu();
		/* Actual create/destroy register and withdraw the notifier, cancel
		 * delayed expiry, release netdev refs and finally free the observer.
		 */
		be6l_diag_destroy(d);
	}
	mutex_unlock(&ppe->diag_mutex);
}
