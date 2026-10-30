/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "packet.h"
#define NSEC_PER_SEC 1000000000ULL
#define DEFINE_SPINLOCK(name) int name
#define spin_lock_bh(lock) do { assert(!*(lock)); *(lock)=1; } while (0)
#define spin_unlock_bh(lock) do { assert(*(lock)); *(lock)=0; } while (0)
#define EXPORT_SYMBOL_GPL(name)
static u64 test_now;
static u64 ktime_get_ns(void) { return test_now; }
#include "lease.c.inc"
static unsigned int checks;
#define CHECK(expr) do { assert(expr); checks++; assert(!flow_diag_lease_lock); } while (0)
static bool zero(const void *data, size_t bytes)
{
 const unsigned char *p=data;
 while (bytes--) if (*p++) return false;
 return true;
}
int main(void)
{
 struct flow_diag_packet packet;
 const u64 start=1000000, deadline=start+5ULL*NSEC_PER_SEC;
 _Static_assert(sizeof(packet)==88,"packet must remain bounded");
 test_now=start;
 memset(&packet,0xff,sizeof(packet));
 CHECK(!flow_offload_diag_lease_packet(&packet,5,3));
 CHECK(zero(&packet,sizeof(packet)));
 CHECK(flow_offload_diag_lease_begin(0,deadline,5,3)==-EINVAL);
 CHECK(flow_offload_diag_lease_begin(1,deadline,0,3)==-EINVAL);
 CHECK(flow_offload_diag_lease_begin(1,deadline,5,5)==-EINVAL);
 CHECK(flow_offload_diag_lease_begin(1,start,5,3)==-EINVAL);
 CHECK(flow_offload_diag_lease_begin(1,start-1,5,3)==-EINVAL);
 CHECK(flow_offload_diag_lease_begin(1,deadline+1,5,3)==-EINVAL);
 CHECK(flow_offload_diag_lease_begin(1,deadline,5,3)==0);
 CHECK(flow_offload_diag_lease_begin(2,deadline,5,3)==-EBUSY);
 CHECK(!flow_offload_diag_lease_packet(NULL,5,3));
 CHECK(flow_offload_diag_lease_packet(&packet,5,3));
 CHECK(packet.magic==FLOW_DIAG_PACKET_MAGIC && packet.version==1 && !packet.reserved);
 CHECK(packet.lease_generation==1 && packet.deadline_ns==deadline);
 CHECK(packet.ingress_ifindex==5 && packet.output_ifindex==3);
 CHECK(zero(packet.context_words,sizeof(packet.context_words)));
 CHECK(flow_offload_diag_lease_packet(&packet,3,5));
 CHECK(packet.ingress_ifindex==3 && packet.output_ifindex==5);
 CHECK(!flow_offload_diag_lease_packet(&packet,5,5));
 CHECK(zero(&packet,sizeof(packet)));
 CHECK(!flow_offload_diag_lease_packet(&packet,6,3));
 CHECK(!flow_offload_diag_lease_packet(&packet,5,4));
 flow_offload_diag_lease_end(2,deadline);
 CHECK(flow_offload_diag_lease_packet(&packet,5,3));
 flow_offload_diag_lease_end(1,deadline+1);
 CHECK(flow_offload_diag_lease_packet(&packet,5,3));
 test_now=deadline;
 CHECK(!flow_offload_diag_lease_packet(&packet,5,3));
 CHECK(zero(&packet,sizeof(packet)));
 CHECK(flow_offload_diag_lease_begin(2,deadline+100,5,3)==0);
 flow_offload_diag_lease_end(1,deadline);
 CHECK(flow_offload_diag_lease_packet(&packet,5,3));
 CHECK(packet.lease_generation==2 && packet.deadline_ns==deadline+100);
 flow_offload_diag_lease_end(2,deadline+100);
 CHECK(!flow_offload_diag_lease_packet(&packet,5,3));
 CHECK(zero(&packet,sizeof(packet)));
 printf("{\"checks\":%u,\"actual_lease_source\":true,\"concurrency_qualified\":false}\n",checks);
 return 0;
}
