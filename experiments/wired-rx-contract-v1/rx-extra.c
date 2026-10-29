/* SPDX-License-Identifier: MIT */
/* CPU-only diagnostic contract; not installed in a kernel or a publisher. */
static unsigned int rx_sum_bytes(unsigned int sum, const unsigned char *bytes,
                                 unsigned int length)
{
 for (unsigned int i = 0; i + 1 < length; i += 2)
  sum += (unsigned int)bytes[i] << 8 | bytes[i + 1];
 if (length & 1) sum += (unsigned int)bytes[length - 1] << 8;
 return sum;
}
static unsigned int rx_fold(unsigned int sum)
{
 while (sum >> 16) sum = (sum & 0xffffU) + (sum >> 16);
 return sum;
}
static bool rx_sum_skb(struct sk_buff *skb, int offset, unsigned int length,
                       unsigned int seed)
{
 unsigned char buffer[64];
 unsigned int sum = seed;
 while (length) {
  unsigned int count = length < sizeof(buffer) ? length : sizeof(buffer);
  const unsigned char *bytes = skb_header_pointer(skb, offset, count, buffer);
  if (!bytes) return false;
  sum = rx_sum_bytes(sum, bytes, count);
  length -= count;
  offset += count;
 }
 return rx_fold(sum) == 0xffffU;
}
static bool rx_tcp_options_valid(struct sk_buff *skb, int offset,
                                 unsigned int length)
{
 unsigned char buffer[40];
 const unsigned char *bytes;
 if (!length) return true;
 if (length > sizeof(buffer)) return false;
 bytes = skb_header_pointer(skb, offset, length, buffer);
 if (!bytes) return false;
 for (unsigned int i = 0; i < length;) {
  unsigned int kind = bytes[i];
  if (!kind) return true;
  if (kind == 1) { i++; continue; }
  if (i + 1 >= length || bytes[i + 1] < 2 || bytes[i + 1] > length - i)
   return false;
  i += bytes[i + 1];
 }
 return true;
}
static bool rx_contract_v1(struct airoha_ppe *ppe,
                           struct airoha_flow_table_entry *entry,
                           struct airoha_foe_entry *hwe,
                           struct sk_buff *skb)
{
 unsigned char ip_buffer[20], tcp_buffer[20];
 const unsigned char *ip, *tcp;
 unsigned int length, tcp_length, tcp_header, pseudo;
 int offset;
 /* This is the unmodified, extracted patch974 function. */
 if (!airoha_ppe_wired_l4_packet_match(ppe, entry, hwe, skb)) return false;
 if (skb_is_gso(skb) || skb->ip_summed == CHECKSUM_PARTIAL) return false;
 offset = skb_mac_offset(skb) + ETH_HLEN;
 ip = skb_header_pointer(skb, offset, sizeof(ip_buffer), ip_buffer);
 if (!ip) return false;
 length = (unsigned int)ip[2] << 8 | ip[3];
 if (length > entry->wired_egress_dev->mtu) return false;
 tcp = skb_header_pointer(skb, offset + 20, sizeof(tcp_buffer), tcp_buffer);
 if (!tcp || !(tcp[13] & 0x10) || tcp[13] & 0x20) return false;
 tcp_header = (tcp[12] >> 4) * 4;
 tcp_length = length - 20;
 if (!rx_tcp_options_valid(skb, offset + 40, tcp_header - 20)) return false;
 /* Never treat CHECKSUM_UNNECESSARY as independent hardware evidence. */
 if (!rx_sum_skb(skb, offset, 20, 0)) return false;
 pseudo = rx_sum_bytes(0, ip + 12, 8) + IPPROTO_TCP + tcp_length;
 return rx_sum_skb(skb, offset + 20, tcp_length, pseudo);
}
