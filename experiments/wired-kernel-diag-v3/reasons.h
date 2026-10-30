/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BE6L_N1_REASONS_H
#define BE6L_N1_REASONS_H
/* Bounded CPU counters only. Never authority to admit a packet or BIND. */
#define BD_REASON_LIST(X) \
 X(RX_SEEN) X(RX_BASIC) X(RX_OFFSET) X(RX_ETH) X(RX_IPV4) \
 X(RX_LENGTH) X(RX_TCP) X(RX_CSUM_OPTIONS) X(RX_UNB_KEY) \
 X(RX_NO_ROW) X(RX_ACCEPTED) \
 X(TX_SEEN) X(TX_BASIC) X(TX_NO_CT) X(TX_NETNS) X(TX_ZONE) \
 X(TX_ETH) X(TX_IPV4) X(TX_LENGTH) X(TX_TCP_OPTIONS) \
 X(TX_OUTPUT) X(TX_NO_PAIR) X(TX_ACCEPTED)
#define BD_REASON_ENUM(name) BD_REASON_##name,
enum bd_reason_id { BD_REASON_LIST(BD_REASON_ENUM) BD_REASON_COUNT };
#undef BD_REASON_ENUM
struct bd_reasons {
 u64 count[BD_REASON_COUNT];
 u32 last;
};
/* Caller owns synchronization and the live-lease check. */
static inline bool bd_reason_add(struct bd_reasons *state, unsigned int reason)
{
 if (reason >= BD_REASON_COUNT)
  return false;
 if (state->count[reason] != ~(u64)0)
  state->count[reason]++;
 state->last = reason;
 return true;
}
#endif
