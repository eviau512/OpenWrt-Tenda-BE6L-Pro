/* SPDX-License-Identifier: MIT */
/* Non-publishing software contract. These are not kernel or firmware ABI types. */
#define PREVIEW_SLOTS 4
#define PREVIEW_UNRESOLVED_ALL 0x3fU
enum preview_role { DEVICE_CONDUIT, DEVICE_LAN, DEVICE_WAN };
struct preview_device {
 unsigned int ifindex, incarnation, references, initial_netns;
 enum preview_role role;
 int dsa_index;
 unsigned int logical_port, pse_port;
 bool registered, vlan, opaque_upper;
 struct preview_device *conduit;
};
struct preview_masks {
 u32 ingress_ifindex, ingress_iftype, l2_miss, ipv4_src, ipv4_dst;
 u16 source_port, dest_port, ethernet_protocol;
 u8 ip_protocol;
 bool has_meta, has_control, has_ipv4, has_ports, has_basic, extra_keys;
};
struct preview_request {
 struct preview_device *input, *output;
 unsigned int input_incarnation, output_incarnation;
 unsigned int ingress_ifindex, addr_type, ethernet_protocol, ip_protocol;
 uint64_t generation;
 struct flow_rule_ct_context context;
 struct preview_masks masks;
 struct flow_offload flow;
 unsigned int nat_flags;
 u8 source_mac[6], dest_mac[6];
 u32 observed_unbound[20];
};
struct preview_plan {
 u32 observed_unbound[20], value[20], mask[20];
 uint64_t generation, deadline;
 unsigned int unresolved;
 bool can_publish;
};
struct preview_entry {
 bool present;
 unsigned int direction;
 u32 key[3];
 struct preview_plan plan;
 struct preview_device *input, *output;
};
struct preview_lease {
 bool active;
 uint64_t generation, created, deadline;
 struct preview_device *lan3, *wan, *conduit;
 unsigned int lan_incarnation, wan_incarnation, conduit_incarnation;
 unsigned int lan_ifindex, wan_ifindex, conduit_ifindex;
 struct preview_entry entries[PREVIEW_SLOTS];
};
