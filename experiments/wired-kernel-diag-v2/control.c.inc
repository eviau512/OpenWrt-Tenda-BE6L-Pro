/* CPU-only opt-in. This does not enable UNB classification or a BIND path.
 * The existing independent learning-window preflight remains required.
 */
static int bd_parse_arm(const char *buffer, struct bd_config *cfg)
{
	unsigned long long generation;
	char extra;
	memset(cfg, 0, sizeof(*cfg));
	if (sscanf(buffer, "arm %d %d %d %llu %c", &cfg->lan_ifindex,
		   &cfg->wan_ifindex, &cfg->expected_dsa_port, &generation, &extra) != 4 ||
	    cfg->lan_ifindex <= 0 || cfg->wan_ifindex <= 0 ||
	    cfg->lan_ifindex == cfg->wan_ifindex || cfg->expected_dsa_port < 0 ||
	    cfg->expected_dsa_port >= 5 || !generation)
		return -EINVAL;
	cfg->enabled = true;
	cfg->generation = generation;
	cfg->duration_ns = 5ULL * 1000 * 1000 * 1000;
	return 0;
}
static int bd_control_show(struct seq_file *seq, void *unused)
{
	struct airoha_ppe *ppe = seq->private;
	struct bd_snapshot *s;
	struct be6l_diag *d;
	unsigned int i, j;
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->version = 2;
	rcu_read_lock();
	d = rcu_dereference(ppe->route_diag);
	if (d)
		be6l_diag_snapshot(d, s);
	else
		s->spent = READ_ONCE(ppe->diag_spent);
	rcu_read_unlock();
	seq_printf(seq, "version=%u can_publish=%u active=%u spent=%u reason=%u unresolved=%u refs_owned=%u\n",
		   s->version, s->can_publish, s->active, s->spent, s->reason, s->unresolved, s->refs_owned);
	seq_printf(seq, "lease_generation=%llu created_ns=%llu deadline_ns=%llu lan=%u wan=%u conduit=%u\n",
		   s->generation, s->created_ns, s->deadline_ns, s->input_ifindex[0], s->input_ifindex[1], s->input_ifindex[2]);
	seq_printf(seq, "accepted=%llu rejected=%llu replaced=%llu destroyed_rows=%llu ct_calls=%llu ct_rejected=%llu last_ct_errno=%d egress_accepted=%llu egress_rejected=%llu\n",
		   s->accepted, s->rejected, s->replaced, s->destroyed, s->ct_callbacks,
		   s->ct_callback_rejected, s->last_ct_errno, s->egress_accepted, s->egress_rejected);
	for (i = 0; i < BD_SLOTS; i++) {
		const struct bd_row *r = &s->rows[i];
		const struct bd_egress *e = &r->egress;
		seq_printf(seq, "row=%u used=%u revoked=%u direction=%u flow_generation=%llu producer=%u version=%u initial_netns=%u zone=%u raw_zone=%u zone_dir=%u zone_flags=%u key=%08x,%08x,%08x out=%u rx=%u rx_ns=%llu observed_ns=%llu\n",
			i, r->used, r->revoked, r->direction, r->context.generation, r->context.producer,
			r->context.version, r->context.initial_netns, r->context.zone_id,
			r->context.zone_raw_id, r->context.zone_dir, r->context.zone_flags,
			r->key[0], r->key[1], r->key[2], r->output_ifindex, r->rx_matched, r->rx_ns, r->observed_ns);
		for (j = 0; j < min_t(u32, r->action_count, BD_ACTIONS); j++) {
			const struct bd_action_copy *a = &r->actions[j];
			seq_printf(seq, "row=%u action=%u id=%u htype=%u offset=%u mask=%08x value=%08x csum=%u\n",
				i, j, a->id, a->htype, a->offset, a->mask, a->value, a->checksum_flags);
		}
		seq_printf(seq, "row=%u egress_ns=%llu same_ct=%u ct_direction=%u actual_if=%u logical_if=%u tag=%x key=%08x,%08x,%08x bytes=%u original_gso=%u summed_before=%u summed_after=%u format_complete=%u delivered=%u ttl=%u seq=%u ack_seq=%u\n",
			i, e->observed_ns, e->ct_cookie && e->ct_cookie == r->context.ct_cookie, e->direction,
			e->actual_ifindex, e->logical_output_ifindex, e->tag, e->key[0], e->key[1], e->key[2],
			e->frame_bytes, e->was_gso, e->summed_before, e->summed_after, e->format_complete,
			e->delivered, e->ttl, e->seq, e->ack_seq);
	}
	/* No raw kernel pointer cookies, credentials, or hardware owners exported. */
	kfree(s);
	return 0;
}
static int bd_control_open(struct inode *inode, struct file *file)
{
	return single_open(file, bd_control_show, inode->i_private);
}
static ssize_t bd_control_write(struct file *file, const char __user *data,
				size_t length, loff_t *position)
{
	struct seq_file *seq = file->private_data;
	struct airoha_ppe *ppe = seq->private;
	struct bd_config cfg;
	struct be6l_diag *d;
	char buffer[128];
	int error;
	if (!length || length >= sizeof(buffer))
		return -EINVAL;
	if (copy_from_user(buffer, data, length))
		return -EFAULT;
	if (memchr(buffer, 0, length))
		return -EINVAL;
	buffer[length] = 0;
	if (!strcmp(strim(buffer), "stop")) {
		rcu_read_lock();
		d = rcu_dereference(ppe->route_diag);
		if (d)
			bd_revoke(d, BD_DESTROYED);
		rcu_read_unlock();
		return length;
	}
	error = bd_parse_arm(buffer, &cfg);
	if (error)
		return error;
	error = be6l_diag_driver_arm(ppe, &cfg);
	return error ? error : length;
}
static const struct file_operations bd_control_fops = {
	.owner = THIS_MODULE,
	.open = bd_control_open,
	.read = seq_read,
	.write = bd_control_write,
	.llseek = seq_lseek,
	.release = single_release,
};
void be6l_diag_debugfs_init(struct airoha_ppe *ppe)
{
	if (airoha_is_7563(ppe->eth))
		debugfs_create_file("route_diag", 0600, ppe->debugfs_dir, ppe, &bd_control_fops);
}
