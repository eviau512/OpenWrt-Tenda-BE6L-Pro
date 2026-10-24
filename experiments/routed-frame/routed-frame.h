/* SPDX-License-Identifier: MIT */
/* Offline packet-action primitive. Not connected to Linux or NPU queues.
 * The caller must supply an immutable, firewall/conntrack-approved action,
 * authenticate and recheck its complete identity, and retain DMA ownership.
 * A successful rewrite is not permission to publish a DMA descriptor.
 */
#ifndef BE6L_ROUTED_FRAME_H
#define BE6L_ROUTED_FRAME_H
#include <stddef.h>
#include <stdint.h>

struct rf_identity {
	uint32_t port, vlan, wcid, replay_generation, ct_zone;
};
struct rf_action {
	uint64_t cookie;
	struct rf_identity ingress;
	uint32_t established;
	uint8_t version, protocol;
	uint16_t mtu;
	uint8_t src_mac[6], dst_mac[6], out_src_mac[6], out_dst_mac[6];
	uint8_t src_ip[16], dst_ip[16], out_src_ip[16], out_dst_ip[16];
	uint16_t src_port, dst_port, out_src_port, out_dst_port;
};

static inline uint16_t rf_be16(const volatile uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}
static inline void rf_put16(volatile uint8_t *p, uint16_t value)
{
	p[0] = value >> 8;
	p[1] = value;
}
static inline int rf_equal(const volatile uint8_t *p, const uint8_t *q, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (p[i] != q[i])
			return 0;
	return 1;
}
static inline int rf_unicast_mac(const uint8_t *p)
{
	uint8_t nonzero = 0;
	for (unsigned int i = 0; i < 6; i++)
		nonzero |= p[i];
	return nonzero && !(p[0] & 1);
}
static inline int rf_unicast_ip(const uint8_t *p, uint32_t version)
{
	uint8_t prefix = 0;
	if (version == 4)
		return p[0] && p[0] < 224 && p[0] != 127;
	for (unsigned int i = 0; i < 15; i++)
		prefix |= p[i];
	return p[0] != 255 && (prefix || p[15] > 1);
}
static inline uint32_t rf_sum(const volatile uint8_t *p, size_t n)
{
	uint32_t sum = 0;
	while (n > 1) {
		sum += rf_be16(p);
		p += 2;
		n -= 2;
	}
	if (n)
		sum += (uint32_t)p[0] << 8;
	return sum;
}
static inline uint16_t rf_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 65535) + (sum >> 16);
	return (uint16_t)sum;
}
static inline uint32_t rf_pseudo(const volatile uint8_t *ip, uint32_t version,
				 uint32_t protocol, uint32_t length)
{
	return rf_sum(ip + (version == 4 ? 12 : 8), version == 4 ? 8 : 32) +
		protocol + length;
}

/* Return 1 only after a complete rewrite. Every return 0 preserves all bytes. */
static inline int routed_frame_apply(volatile uint8_t *frame, size_t length,
				    const struct rf_action *a,
				    const struct rf_identity *identity)
{
	volatile uint8_t *ip, *transport;
	uint32_t version, protocol, header, payload, total, checksum_offset;
	int udp_zero;

	if (!frame || !a || !identity || length < 14 || length > 2048 ||
	    !a->cookie || a->established != 1 || identity->vlan ||
	    !identity->replay_generation ||
	    identity->port != a->ingress.port || identity->vlan != a->ingress.vlan ||
	    identity->wcid != a->ingress.wcid ||
	    identity->replay_generation != a->ingress.replay_generation ||
	    identity->ct_zone != a->ingress.ct_zone ||
	    !rf_unicast_mac(a->src_mac) || !rf_unicast_mac(a->dst_mac) ||
	    !rf_unicast_mac(a->out_src_mac) || !rf_unicast_mac(a->out_dst_mac) ||
	    !rf_equal(frame, a->dst_mac, 6) || !rf_equal(frame + 6, a->src_mac, 6))
		return 0;
	ip = frame + 14;
	version = a->version;
	if (version == 4) {
		if (rf_be16(frame + 12) != 0x0800 || length < 34 || ip[0] != 0x45 ||
		    ip[8] <= 1 || (rf_be16(ip + 6) & ~0x4000U) || a->mtu < 68 ||
		    !rf_unicast_ip(a->src_ip, 4) || !rf_unicast_ip(a->dst_ip, 4) ||
		    !rf_unicast_ip(a->out_src_ip, 4) || !rf_unicast_ip(a->out_dst_ip, 4))
			return 0;
		total = rf_be16(ip + 2);
		header = 20;
		if (total < header || total > a->mtu || total > length - 14 ||
		    rf_fold(rf_sum(ip, header)) != 65535 ||
		    !rf_equal(ip + 12, a->src_ip, 4) || !rf_equal(ip + 16, a->dst_ip, 4))
			return 0;
		protocol = ip[9];
	} else if (version == 6) {
		if (rf_be16(frame + 12) != 0x86dd || length < 54 || ip[0] >> 4 != 6 ||
		    ip[7] <= 1 || a->mtu < 1280 ||
		    !rf_unicast_ip(a->src_ip, 6) || !rf_unicast_ip(a->dst_ip, 6))
			return 0;
		header = 40;
		total = header + rf_be16(ip + 4);
		if (total == header || total > a->mtu || total > length - 14 ||
		    !rf_equal(ip + 8, a->src_ip, 16) || !rf_equal(ip + 24, a->dst_ip, 16) ||
		    !rf_equal(a->src_ip, a->out_src_ip, 16) ||
		    !rf_equal(a->dst_ip, a->out_dst_ip, 16) ||
		    a->src_port != a->out_src_port || a->dst_port != a->out_dst_port)
			return 0; /* IPv6 routing only; no NAT66 or extension-header walk. */
		protocol = ip[6];
	} else {
		return 0;
	}
	if (protocol != a->protocol || (protocol != 6 && protocol != 17))
		return 0;
	payload = total - header;
	transport = ip + header;
	if (payload < (protocol == 6 ? 20U : 8U) ||
	    rf_be16(transport) != a->src_port || rf_be16(transport + 2) != a->dst_port)
		return 0;
	if (protocol == 6) {
		uint32_t tcp_header = (transport[12] >> 4) * 4;
		if (tcp_header < 20 || tcp_header > payload ||
		    !(transport[13] & 0x10) || (transport[13] & 0x27))
			return 0; /* Linux handles SYN/FIN/RST/URG and non-established TCP. */
		checksum_offset = 16;
	} else {
		if (rf_be16(transport + 4) != payload)
			return 0;
		checksum_offset = 6;
	}
	udp_zero = protocol == 17 && rf_be16(transport + checksum_offset) == 0;
	if ((udp_zero && version == 6) || (!udp_zero &&
	    rf_fold(rf_pseudo(ip, version, protocol, payload) + rf_sum(transport, payload)) != 65535))
		return 0;

	/* Every structural, checksum, identity and action check precedes writes. */
	for (unsigned int i = 0; i < 6; i++) {
		frame[i] = a->out_dst_mac[i];
		frame[6 + i] = a->out_src_mac[i];
	}
	if (version == 6) {
		ip[7]--;
		return 1;
	}
	ip[8]--;
	for (unsigned int i = 0; i < 4; i++) {
		ip[12 + i] = a->out_src_ip[i];
		ip[16 + i] = a->out_dst_ip[i];
	}
	rf_put16(transport, a->out_src_port);
	rf_put16(transport + 2, a->out_dst_port);
	rf_put16(ip + 10, 0);
	rf_put16(ip + 10, (uint16_t)~rf_fold(rf_sum(ip, 20)));
	if (!udp_zero) {
		uint16_t value;
		rf_put16(transport + checksum_offset, 0);
		value = (uint16_t)~rf_fold(rf_pseudo(ip, version, protocol, payload) + rf_sum(transport, payload));
		rf_put16(transport + checksum_offset, protocol == 17 && !value ? 65535 : value);
	}
	return 1;
}
#endif
