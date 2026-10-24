/* SPDX-License-Identifier: MIT */
#ifndef BE6L_ROUTED_SELFTEST_H
#define BE6L_ROUTED_SELFTEST_H
#include "routed-frame.h"
#include "routed-selftest-vectors.h"
#define RF_SELFTEST_MAGIC 0x52465431U

static inline void rf_copy(uint8_t *out, const uint8_t *in, uint32_t length)
{
	for (uint32_t i = 0; i < length; i++)
		out[i] = in[i];
}
static inline void routed_selftest_run(uint32_t core, volatile uint32_t *result)
{
	static const uint8_t smac[6] = {2, 0x11, 0x22, 0x33, 0x44, 0x55};
	static const uint8_t dmac[6] = {2, 0x66, 0x77, 0x88, 0x99, 0xaa};
	static const uint8_t osmac[6] = {2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
	static const uint8_t odmac[6] = {2, 0xff, 0xee, 0xdd, 0xcc, 0xbb};
	uint32_t checks = 0, failures = 0;
	uint8_t frame[128];
	result[3] = 0;
	barrier();
	for (uint32_t i = 0; i < sizeof(rf_vectors) / sizeof(rf_vectors[0]); i++) {
		const struct rf_vector *v = &rf_vectors[i];
		struct rf_action a = {0};
		struct rf_identity identity;
		uint32_t ip = v->version == 4 ? 26 : 22;
		uint32_t n = v->version == 4 ? 4 : 16;
		a.cookie = 1;
		a.ingress = (struct rf_identity){7, 0, 11, 0x45678, 42};
		a.established = 1; a.version = v->version; a.protocol = v->protocol; a.mtu = 1500;
		rf_copy(a.src_mac, smac, 6); rf_copy(a.dst_mac, dmac, 6);
		rf_copy(a.out_src_mac, osmac, 6); rf_copy(a.out_dst_mac, odmac, 6);
		rf_copy(a.src_ip, v->before + ip, n); rf_copy(a.dst_ip, v->before + ip + n, n);
		rf_copy(a.out_src_ip, v->after + ip, n); rf_copy(a.out_dst_ip, v->after + ip + n, n);
		a.src_port = 33445; a.dst_port = 443;
		a.out_src_port = v->version == 4 ? 50123 : 33445;
		a.out_dst_port = v->version == 4 ? 12345 : 443;
		identity = a.ingress;
		rf_copy(frame, v->before, v->length);
		failures += routed_frame_apply(frame, v->length, &a, &identity) != 1 ||
			    !rf_equal(frame, v->after, v->length);
		checks++;
		for (uint32_t negative = 0; negative < 5; negative++) {
			struct rf_action wrong = a;
			struct rf_identity id = identity;
			uint32_t length = v->length;
			if (negative == 0) id.ct_zone++;
			if (negative == 1) id.replay_generation++;
			if (negative == 2) wrong.cookie = 0;
			if (negative == 3) wrong.established = 0;
			if (negative == 4) length--;
			rf_copy(frame, v->before, v->length);
			failures += routed_frame_apply(frame, length, &wrong, &id) != 0 ||
				    !rf_equal(frame, v->before, v->length);
			checks++;
		}
		if (v->version == 6) {
			a.out_dst_port++;
			rf_copy(frame, v->before, v->length);
			failures += routed_frame_apply(frame, v->length, &a, &identity) != 0 ||
				    !rf_equal(frame, v->before, v->length);
			checks++;
		}
	}
	result[0] = RF_SELFTEST_MAGIC; result[1] = 1; result[2] = checks;
	result[4] = failures; result[5] = 15; result[6] = core; result[7] = 1;
	barrier();
	result[3] = 1;
}
#endif
