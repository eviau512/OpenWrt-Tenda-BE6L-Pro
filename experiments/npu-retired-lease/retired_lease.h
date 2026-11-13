/* SPDX-License-Identifier: MIT */
/* Host source prototype only. No hardware provider, driver hooks or admission. */
#ifndef BE6L_RETIRED_LEASE_H
#define BE6L_RETIRED_LEASE_H
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#define BE6L_LEASE_SLOTS 4
#define BE6L_LEASE_RESOURCES 4
enum be6l_coverage {
 BE6L_COVER_FOE = 1U << 0,
 BE6L_COVER_NATIVE_WRITERS = 1U << 1,
 BE6L_COVER_OUTPUT_DMA = 1U << 2,
 BE6L_COVER_IRQ_CALLBACKS = 1U << 3,
 BE6L_COVER_RX_CPU_CACHES = 1U << 4,
 BE6L_COVER_REMOVE_SETUP = 1U << 5,
 BE6L_COVER_ALL = (1U << 6) - 1
};
enum be6l_lease_state { BE6L_PREPARED, BE6L_LIVE, BE6L_RETIRING, BE6L_RELEASED };
enum be6l_resource_kind { BE6L_FOE_OWNER, BE6L_SMAC_OWNER, BE6L_DESTINATION, BE6L_DMA_BACKING };
struct be6l_identity {
 uint64_t epoch;
 uint16_t wcid;
 uint8_t band, bss, mac[6];
 uint32_t replay_cookie;
};
/* Represents a reference to an already independently owned resource. It is
 * deliberately not a sta, WCID, key-conf or driver-private station object. */
struct be6l_resource {
 enum be6l_resource_kind kind;
 unsigned refs;
};
struct be6l_manager;
struct be6l_lease {
 struct be6l_identity id;
 struct be6l_manager *manager;
 atomic_uint refs;
 enum be6l_lease_state state;
 bool cpu_detached;
 struct be6l_resource *resource[BE6L_LEASE_RESOURCES];
 unsigned resource_count;
};
struct be6l_manager {
 struct be6l_lease *slot[BE6L_LEASE_SLOTS];
 uint64_t epoch;
 unsigned objects_alive, setup_users;
 bool closing;
};
struct be6l_evidence {
 uint64_t epoch;
 uint16_t wcid;
 uint8_t band;
 unsigned coverage;
};
struct be6l_provider {
 /* A real implementation must establish all named domains. An SRAM write ACK,
  * RCU grace, a delay, and ABI5 native-token-only drain are insufficient.
  * No implementation is supplied here. Tests use explicit synthetic evidence. */
 int (*lease_evidence)(void *, const struct be6l_identity *, struct be6l_evidence *);
 int (*device_evidence)(void *, uint64_t, struct be6l_evidence *);
 void *context;
};

/* All state/slot/provider operations require one external process-context
 * serialization domain. Atomic refs alone do NOT implement IRQ/RCU locking.
 * The eventual kernel adapter needs refcount_t and its actual lock ordering. */
int be6l_lease_prepare(struct be6l_manager *, const struct be6l_identity *, struct be6l_lease **);
int be6l_lease_attach(struct be6l_lease *, struct be6l_resource *);
int be6l_lease_publish(struct be6l_lease *);
int be6l_lease_abort_unpublished(struct be6l_lease *);
void be6l_lease_get(struct be6l_lease *);
void be6l_lease_put(struct be6l_lease *);
int be6l_lease_retire(struct be6l_lease *);
int be6l_lease_cpu_detached(struct be6l_lease *);
int be6l_lease_finalize(struct be6l_lease *, const struct be6l_provider *);
bool be6l_lease_is_current(const struct be6l_lease *);
struct be6l_lease *be6l_lookup_untagged(struct be6l_manager *, uint16_t);
int be6l_setup_enter(struct be6l_manager *);
void be6l_setup_exit(struct be6l_manager *);
void be6l_shutdown_begin(struct be6l_manager *);
int be6l_devres_release_gate(struct be6l_manager *, const struct be6l_provider *);
#endif
