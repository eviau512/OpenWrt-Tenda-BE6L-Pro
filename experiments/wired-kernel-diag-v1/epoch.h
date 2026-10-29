/* SPDX-License-Identifier: MIT */
/* Same finite epoch logic is compiled by the real kernel adapter and host test. */
#define BD_MAX_NS 5000000000ULL
struct bd_epoch {
	bool active, spent;
	u64 generation, created, deadline;
};
static inline bool bd_epoch_open(struct bd_epoch *e, u64 generation,
				u64 now, u64 duration)
{
	if (e->active || e->spent || !generation || !duration ||
	    duration > BD_MAX_NS || now > (~(u64)0) - duration)
		return false;
	e->active = e->spent = true;
	e->generation = generation;
	e->created = now;
	e->deadline = now + duration;
	return true;
}
static inline bool bd_epoch_live(const struct bd_epoch *e, u64 now)
{
	return e->active && now >= e->created && now < e->deadline;
}
static inline bool bd_epoch_close(struct bd_epoch *e)
{
	bool owned = e->active;
	e->active = false;
	return owned;
}
