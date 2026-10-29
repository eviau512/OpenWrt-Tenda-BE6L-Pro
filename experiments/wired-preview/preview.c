/* SPDX-License-Identifier: MIT */
/* No publisher, MMIO interface, BIND-state constructor or kernel adapter exists. */
static void hold(struct preview_device *dev) { assert(dev); dev->references++; }
static void put(struct preview_device *dev) { assert(dev && dev->references); dev->references--; }
static void empty_plan(struct preview_plan *plan)
{
 memset(plan, 0, sizeof(*plan));
 plan->unresolved = PREVIEW_UNRESOLVED_ALL;
 plan->can_publish = false;
}
static void release_entry(struct preview_entry *entry)
{
 if (entry->present) { put(entry->input); put(entry->output); }
 memset(entry, 0, sizeof(*entry));
}
static void revoke_lease(struct preview_lease *lease)
{
 for (unsigned int i = 0; i < PREVIEW_SLOTS; i++) release_entry(&lease->entries[i]);
 if (lease->active) { put(lease->lan3); put(lease->wan); put(lease->conduit); }
 lease->active = false;
}
static bool device_live(const struct preview_device *dev, unsigned int incarnation)
{
 return dev && dev->registered && dev->initial_netns == 1 &&
        dev->incarnation == incarnation && !dev->vlan && !dev->opaque_upper;
}
static int open_lease(struct preview_lease *lease, struct preview_device *lan3,
                      struct preview_device *wan, uint64_t generation,
                      uint64_t now, uint64_t deadline)
{
 if (lease->active) return -EBUSY;
 if (generation <= lease->generation || deadline <= now || !lan3 || !wan || lan3 == wan ||
     !device_live(lan3, lan3->incarnation) || !device_live(wan, wan->incarnation) ||
     lan3->role != DEVICE_LAN || lan3->logical_port != 3 || lan3->dsa_index != 2 ||
     wan->role != DEVICE_WAN || wan->dsa_index != -1 || wan->conduit ||
     !lan3->conduit || lan3->conduit == lan3 || lan3->conduit == wan ||
     lan3->conduit->role != DEVICE_CONDUIT ||
     !device_live(lan3->conduit, lan3->conduit->incarnation) ||
     lan3->pse_port != 1 || wan->pse_port != 2) return -EOPNOTSUPP;
 memset(lease, 0, sizeof(*lease));
 lease->active = true; lease->generation = generation; lease->created = now; lease->deadline = deadline;
 lease->lan3 = lan3; lease->wan = wan; lease->conduit = lan3->conduit;
 lease->lan_incarnation = lan3->incarnation; lease->wan_incarnation = wan->incarnation;
 lease->conduit_incarnation = lan3->conduit->incarnation;
 lease->lan_ifindex = lan3->ifindex; lease->wan_ifindex = wan->ifindex;
 lease->conduit_ifindex = lan3->conduit->ifindex;
 hold(lan3); hold(wan); hold(lease->conduit);
 return 0;
}
static bool lease_live(struct preview_lease *lease, uint64_t now)
{
 if (!lease->active) return false;
 if (now < lease->created || now >= lease->deadline ||
     !device_live(lease->lan3, lease->lan_incarnation) ||
     !device_live(lease->wan, lease->wan_incarnation) ||
     !device_live(lease->conduit, lease->conduit_incarnation) ||
     lease->lan3->conduit != lease->conduit ||
     lease->lan3->role != DEVICE_LAN || lease->lan3->logical_port != 3 ||
     lease->lan3->dsa_index != 2 || lease->lan3->pse_port != 1 ||
     lease->wan->role != DEVICE_WAN || lease->wan->dsa_index != -1 ||
     lease->wan->pse_port != 2 || lease->wan->conduit ||
     lease->conduit->role != DEVICE_CONDUIT) { revoke_lease(lease); return false; }
 if (lease->lan3->ifindex != lease->lan_ifindex || lease->wan->ifindex != lease->wan_ifindex ||
     lease->conduit->ifindex != lease->conduit_ifindex) { revoke_lease(lease); return false; }
 return true;
}
static bool masks_exact(const struct preview_masks *m)
{
 return m->has_meta && m->has_control && m->has_ipv4 && m->has_ports && m->has_basic &&
        !m->extra_keys && m->ingress_ifindex == UINT32_MAX && !m->ingress_iftype &&
        !m->l2_miss && m->ipv4_src == UINT32_MAX && m->ipv4_dst == UINT32_MAX &&
        m->source_port == UINT16_MAX && m->dest_port == UINT16_MAX &&
        m->ethernet_protocol == UINT16_MAX && m->ip_protocol == UINT8_MAX;
}
static bool valid_mac(const u8 mac[6])
{
 u8 any = 0;
 for (unsigned int i = 0; i < 6; i++) any |= mac[i];
 return any && !(mac[0] & 1);
}
static int scoped_mangle(const struct flow_action_entry *action, struct airoha_flow_data *data)
{
 if (action->id != FLOW_ACTION_MANGLE) return -EOPNOTSUPP;
 if (action->mangle.htype == FLOW_ACT_MANGLE_HDR_TYPE_IP4) {
  if (action->mangle.mask) return -EOPNOTSUPP;
  return airoha_ppe_flow_mangle_ipv4(action, data);
 }
 if (action->mangle.htype != FLOW_ACT_MANGLE_HDR_TYPE_TCP || action->mangle.offset ||
     (action->mangle.mask != ~htonl(0xffff0000U) && action->mangle.mask != ~htonl(0x0000ffffU)) ||
     (action->mangle.mask & action->mangle.val)) return -EOPNOTSUPP;
 return airoha_ppe_flow_mangle_ports(action, data);
}
static int partial_plan(const struct preview_request *request, struct preview_plan *plan)
{
 const unsigned int dir = request->context.direction;
 const struct flow_offload_tuple *in = &request->flow.tuplehash[dir].tuple;
 const struct flow_offload_tuple *opposite = &request->flow.tuplehash[!dir].tuple;
 struct airoha_flow_data data = {.v4 = {in->src_v4.s_addr, in->dst_v4.s_addr},
                                .src_port = in->src_port, .dst_port = in->dst_port};
 struct airoha_foe_entry scratch;
 struct flow_rule storage = {0};
 struct nf_flow_rule rule = {&storage};
 int error;
 if (in->l4proto != IPPROTO_TCP || opposite->l4proto != IPPROTO_TCP ||
     request->nat_flags > 3 || !valid_mac(request->source_mac) || !valid_mac(request->dest_mac))
  return -EOPNOTSUPP;
 if ((request->observed_unbound[0] & 0x7e000000U) != 0x10000000U ||
     request->observed_unbound[1] != ntohl(in->src_v4.s_addr) ||
     request->observed_unbound[2] != ntohl(in->dst_v4.s_addr) ||
     request->observed_unbound[3] != ((u32)ntohs(in->src_port) << 16 | ntohs(in->dst_port)))
  return -ESTALE;
 /* Only existing UNB is copied to a private typed scratch for real encoders. */
 memcpy(&scratch, request->observed_unbound, sizeof(scratch));
 if (request->nat_flags & 1) {
  error = flow_offload_ipv4_snat(NULL, &request->flow, dir, &rule);
  if (error) return error;
  error = flow_offload_port_snat(NULL, &request->flow, dir, &rule);
  if (error) return error;
 }
 if (request->nat_flags & 2) {
  error = flow_offload_ipv4_dnat(NULL, &request->flow, dir, &rule);
  if (error) return error;
  error = flow_offload_port_dnat(NULL, &request->flow, dir, &rule);
  if (error) return error;
 }
 for (unsigned int i = 0; i < storage.action.num_entries; i++) {
  error = scoped_mangle(&storage.action.entries[i], &data);
  if (error) return error;
 }
 if (data.v4.src_addr != opposite->dst_v4.s_addr || data.v4.dst_addr != opposite->src_v4.s_addr ||
     data.src_port != opposite->dst_port || data.dst_port != opposite->src_port) return -EINVAL;
 error = airoha_ppe_foe_entry_set_ipv4_tuple(&scratch, &data, true);
 if (error) return error;
 memcpy(data.eth.h_source, request->source_mac, 6);
 memcpy(data.eth.h_dest, request->dest_mac, 6);
 real_mac_fields(&scratch, &data);
 empty_plan(plan);
 memcpy(plan->observed_unbound, request->observed_unbound, sizeof(plan->observed_unbound));
 for (unsigned int i = 5; i <= 7; i++) { plan->value[i] = scratch.words[i]; plan->mask[i] = UINT32_MAX; }
 plan->mask[4] = 0x1e0U; plan->value[4] = request->output->pse_port << 5;
 plan->mask[12] = plan->mask[14] = UINT32_MAX;
 plan->mask[13] = plan->mask[15] = 0xffff0000U;
 for (unsigned int i = 12; i <= 15; i++) plan->value[i] = scratch.words[i] & plan->mask[i];
 return 0;
}
static int preview_request(struct preview_lease *lease, const struct preview_request *request,
                           uint64_t now, struct preview_plan *output)
{
 struct preview_plan candidate;
 struct preview_entry *free_slot = NULL;
 unsigned int direction;
 int error;
 empty_plan(output);
 if (!lease_live(lease, now)) return -ESTALE;
 if (request->generation != lease->generation ||
     !airoha_ppe_wired_context_valid(&request->context) || !masks_exact(&request->masks))
  return -EOPNOTSUPP;
 direction = request->context.direction;
 if (request->input != (direction ? lease->wan : lease->lan3) ||
     request->output != (direction ? lease->lan3 : lease->wan) ||
     request->input_incarnation != request->input->incarnation ||
     request->output_incarnation != request->output->incarnation ||
     request->ingress_ifindex != request->input->ifindex || request->addr_type != 4 ||
     request->ethernet_protocol != 0x0800 || request->ip_protocol != IPPROTO_TCP) return -EOPNOTSUPP;
 error = partial_plan(request, &candidate);
 if (error) return error;
 candidate.generation = lease->generation;
 candidate.deadline = lease->deadline;
 for (unsigned int i = 0; i < PREVIEW_SLOTS; i++) {
  struct preview_entry *entry = &lease->entries[i];
  if (!entry->present) { if (!free_slot) free_slot = entry; continue; }
  if (memcmp(entry->key, request->observed_unbound + 1, sizeof(entry->key))) continue;
  if (entry->direction != direction || entry->input != request->input || entry->output != request->output ||
      memcmp(entry->plan.value, candidate.value, sizeof(candidate.value)) ||
      memcmp(entry->plan.mask, candidate.mask, sizeof(candidate.mask))) return -EEXIST;
  *output = entry->plan; /* Identical duplicate: no new references or lease extension. */
  return 0;
 }
 if (!free_slot) return -ENOSPC;
 hold(request->input); hold(request->output);
 free_slot->present = true; free_slot->direction = direction;
 free_slot->input = request->input; free_slot->output = request->output;
 memcpy(free_slot->key, request->observed_unbound + 1, sizeof(free_slot->key));
 free_slot->plan = candidate; *output = candidate;
 return 0;
}
