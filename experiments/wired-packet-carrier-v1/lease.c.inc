/* SPDX-License-Identifier: GPL-2.0-only */
/* Software observation gate only. No hardware lock, owner, rule or CT ref. */
static DEFINE_SPINLOCK(flow_diag_lease_lock);
static struct {
 u64 generation, deadline_ns;
 int lan, wan;
} flow_diag_lease;
int flow_offload_diag_lease_begin(u64 generation, u64 deadline_ns, int lan, int wan)
{
 u64 now;
 int error = 0;
 spin_lock_bh(&flow_diag_lease_lock);
 now = ktime_get_ns();
 if (!generation || lan <= 0 || wan <= 0 || lan == wan ||
     deadline_ns <= now || deadline_ns - now > 5ULL * NSEC_PER_SEC)
  error = -EINVAL;
 else if (flow_diag_lease.generation && now < flow_diag_lease.deadline_ns)
  error = -EBUSY;
 else {
  flow_diag_lease.generation = generation;
  flow_diag_lease.deadline_ns = deadline_ns;
  flow_diag_lease.lan = lan;
  flow_diag_lease.wan = wan;
 }
 spin_unlock_bh(&flow_diag_lease_lock);
 return error;
}
EXPORT_SYMBOL_GPL(flow_offload_diag_lease_begin);
void flow_offload_diag_lease_end(u64 generation, u64 deadline_ns)
{
 spin_lock_bh(&flow_diag_lease_lock);
 /* A delayed cleanup cannot close a newer or different observation lease. */
 if (generation && flow_diag_lease.generation == generation &&
     flow_diag_lease.deadline_ns == deadline_ns)
  memset(&flow_diag_lease, 0, sizeof(flow_diag_lease));
 spin_unlock_bh(&flow_diag_lease_lock);
}
EXPORT_SYMBOL_GPL(flow_offload_diag_lease_end);
bool flow_offload_diag_lease_packet(struct flow_diag_packet *packet, int ingress, int output)
{
 bool active = false;
 if (!packet)
  return false;
 memset(packet, 0, sizeof(*packet));
 spin_lock_bh(&flow_diag_lease_lock);
 if (flow_diag_lease.generation && ktime_get_ns() < flow_diag_lease.deadline_ns &&
     ((ingress == flow_diag_lease.lan && output == flow_diag_lease.wan) ||
      (ingress == flow_diag_lease.wan && output == flow_diag_lease.lan))) {
  packet->magic = FLOW_DIAG_PACKET_MAGIC;
  packet->version = FLOW_DIAG_PACKET_VERSION;
  packet->lease_generation = flow_diag_lease.generation;
  packet->deadline_ns = flow_diag_lease.deadline_ns;
  packet->ingress_ifindex = ingress;
  packet->output_ifindex = output;
  active = true;
 }
 spin_unlock_bh(&flow_diag_lease_lock);
 return active;
}
EXPORT_SYMBOL_GPL(flow_offload_diag_lease_packet);
