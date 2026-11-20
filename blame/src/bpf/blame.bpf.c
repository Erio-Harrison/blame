// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
#include "kernel.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "blame.h"
#include "pidns.h"

/* Power-of-two multiple of the page size; the agent can override it. */
#define RINGBUF_BYTES (256 * 1024)

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_BYTES);
} EVENTS SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, COUNTER_MAX);
	__type(key, u32);
	__type(value, u64);
} COUNTERS SEC(".maps");

/* Per-CPU slots are not shared between CPUs, so no atomics. */
static __always_inline void bump(enum counter c)
{
	u32 key = c;
	u64 *slot = bpf_map_lookup_elem(&COUNTERS, &key);

	if (slot)
		*slot += 1;
}

static __always_inline void bump_by(enum counter c, u64 n)
{
	u32 key = c;
	u64 *slot = bpf_map_lookup_elem(&COUNTERS, &key);

	if (slot)
		*slot += n;
}

static __always_inline void fill_header(struct event_header *hdr, enum event_kind kind)
{
	u64 pid_tgid = cur_pid_tgid();

	hdr->version = EVENT_VERSION;
	hdr->kind = kind;
	hdr->cpu = bpf_get_smp_processor_id();
	hdr->_pad = 0;
	hdr->ts_boot_ns = bpf_ktime_get_boot_ns();
	hdr->cgroup_id = bpf_get_current_cgroup_id();
	hdr->netns_id = 0;
	hdr->ifindex = 0;
	hdr->pid = pid_tgid >> 32;
	hdr->tid = (u32)pid_tgid;
}

/*
 * A __data_loc field packs the payload's offset from the start of the record
 * (low 16 bits) and its length (high 16 bits).
 */
static __always_inline const void *data_loc(const void *ctx, u32 loc)
{
	return (const char *)ctx + (loc & 0xFFFF);
}

SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	/* Built on the stack and copied in, so no reservation is held across reads. */
	struct exec_event event = {};
	long copied;

	fill_header(&event.hdr, EVENT_EXEC);
	event.old_pid = ctx->old_pid;
	if (bpf_get_current_comm(event.comm, sizeof(event.comm)))
		bump(FIELD_READ_FAILED);

	copied = bpf_probe_read_kernel_str(event.filename, sizeof(event.filename),
					   data_loc(ctx, ctx->__data_loc_filename));
	/* The count includes the NUL, so a full buffer means a longer source. */
	if (copied < 0)
		bump(FIELD_READ_FAILED);
	else if (copied == FILENAME_LEN)
		bump(FILENAME_TRUNCATED);

	if (bpf_ringbuf_output(&EVENTS, &event, sizeof(event), 0)) {
		bump(RINGBUF_FULL);
		return 0;
	}
	bump(EVENTS_PRODUCED);
	return 0;
}

/*
 * cgroup creation, so that a cgroup can still be named after it is removed:
 * its path is only readable from cgroupfs while it exists.
 */
SEC("tracepoint/cgroup/cgroup_mkdir")
int cgroup_mkdir(struct trace_event_raw_cgroup *ctx)
{
	/* Too large for the stack, so it is filled in place. */
	struct cgroup_mkdir_event *event = bpf_ringbuf_reserve(&EVENTS, sizeof(*event), 0);
	long copied;

	if (!event) {
		bump(RINGBUF_FULL);
		return 0;
	}
	fill_header(&event->hdr, EVENT_CGROUP_MKDIR);
	event->id = ctx->id;
	event->root = ctx->root;
	event->_pad2 = 0;
	copied = bpf_probe_read_kernel_str(event->path, sizeof(event->path),
					   data_loc(ctx, ctx->__data_loc_path));
	if (copied < 0) {
		bump(FIELD_READ_FAILED);
		bpf_ringbuf_discard(event, 0);
		return 0;
	}
	if (copied >= CGROUP_PATH_LEN)
		bump(CGROUP_PATH_TRUNCATED);
	bpf_ringbuf_submit(event, 0);
	bump(EVENTS_PRODUCED);
	return 0;
}

/*
 * Run-queue latency: from the moment a thread becomes runnable (a wakeup is
 * issued, it is created, or it is preempted) until it gets a CPU.
 * RUNQ_START[tid] holds the start (0 = not waiting), settled into RUNQ_HIST
 * and the thread's cgroup histogram when the thread is switched in.
 *
 * The start of a wakeup is taken at sched_waking, in the waker's context:
 * sched_wakeup fires only once the target CPU has queued the thread, which
 * for a cross-CPU wakeup can be tens of microseconds later.
 *
 * The per-thread arrays are indexed by tid and sized to pid_max by the agent.
 * Left at 1, every thread is out of range, so a missed resize shows up in
 * runq_start_insert_failed.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} RUNQ_START SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, RUNQ_BUCKETS);
	__type(key, u32);
	__type(value, u64);
} RUNQ_HIST SEC(".maps");

/*
 * tid -> cgroup id, written when a thread leaves the CPU (it is `current`
 * then) and read when it comes back. 0 = not known yet.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
} RUNQ_CGROUP SEC(".maps");

/* cgroup id -> wait histogram. Key 0 collects threads whose cgroup is unknown. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, struct runq_hist);
} RUNQ_GROUP_HIST SEC(".maps");

/*
 * Set in a start taken while the woken thread was still switching out: its
 * switch-out, which normally clears the start of a sleeping thread, comes
 * after the wakeup and must keep it.
 */
#define RUNQ_RACE (1ULL << 63)

static __always_inline u32 runq_bucket(u64 delta_ns)
{
	u64 us = delta_ns / 1000;
	u32 bits = 0, top;

	if (us >= RUNQ_OVERFLOW_US)
		return RUNQ_BUCKETS - 1;
	if (us < 4)
		return us;
	/* Bit length by halving; clang 18 cannot lower ctlz for BPF. */
	top = us;
	if (top >> 16) { bits += 16; top >>= 16; }
	if (top >> 8) { bits += 8; top >>= 8; }
	if (top >> 4) { bits += 4; top >>= 4; }
	if (top >> 2) { bits += 2; top >>= 2; }
	if (top >> 1) { bits += 1; top >>= 1; }
	/* bits = floor(log2(us)) >= 2; the two bits below the top pick the quarter. */
	return ((bits - 1) << 2) | ((us >> (bits - 2)) & 3);
}

/* Too large for the stack; never written. */
struct runq_hist runq_zero_hist;

/* Count one sample in `group`'s histogram of a per-group map. */
static __always_inline void hist_add(void *map, u64 group, u32 bucket, enum counter full)
{
	struct runq_hist *hist;

	if (bucket >= RUNQ_BUCKETS)
		return;
	hist = bpf_map_lookup_elem(map, &group);
	if (!hist) {
		if (bpf_map_update_elem(map, &group, &runq_zero_hist, BPF_ANY)) {
			bump(full);
			return;
		}
		hist = bpf_map_lookup_elem(map, &group);
		if (!hist)
			return;
	}
	hist->bucket[bucket] += 1;
}

static __always_inline u32 task_state(struct task_struct *p)
{
	if (bpf_core_field_exists(p->__state))
		return p->__state;
	return ((struct task_struct___pre514 *)p)->state;
}

static __always_inline bool runnable_now(struct task_struct *p)
{
	return task_state(p) == 0;
}

/* On the run queue: running, or queued after a preemption. */
static __always_inline bool queued(struct task_struct *p)
{
	if (!p->on_rq)
		return false;
	/* With delayed dequeue a sleeping thread can stay on the queue. */
	if (bpf_core_field_exists(p->se.sched_delayed) && p->se.sched_delayed)
		return false;
	return true;
}

SEC("tp_btf/sched_waking")
int BPF_PROG(runq_wakeup, struct task_struct *p)
{
	u32 key = p->pid;
	u64 *slot;

	/* Waking a thread that is running or already waiting starts nothing. */
	if (key == 0 || queued(p))
		return 0;
	slot = bpf_map_lookup_elem(&RUNQ_START, &key);
	if (!slot) {
		bump(RUNQ_START_INSERT_FAILED);
		return 0;
	}
	/* Keep the first time if woken again before it runs. */
	if (*slot == 0)
		*slot = bpf_ktime_get_boot_ns() | (p->on_cpu ? RUNQ_RACE : 0);
	return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(runq_wakeup_new, struct task_struct *p)
{
	u32 key = p->pid;
	u64 *slot, *group;

	if (key == 0)
		return 0;
	slot = bpf_map_lookup_elem(&RUNQ_START, &key);
	if (slot)
		*slot = bpf_ktime_get_boot_ns();
	else
		bump(RUNQ_START_INSERT_FAILED);
	/* A new thread is woken by its creator, which is `current`. */
	group = bpf_map_lookup_elem(&RUNQ_CGROUP, &key);
	if (group)
		*group = bpf_get_current_cgroup_id();
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(runq_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	u32 prev_tid = prev->pid, next_tid = next->pid;
	u64 now = bpf_ktime_get_boot_ns();

	/* Switch-in: settle the wait. tid 0 is idle. */
	if (next_tid != 0) {
		u32 key = next_tid;
		u64 *slot = bpf_map_lookup_elem(&RUNQ_START, &key);

		if (slot && *slot != 0) {
			u64 start = *slot & ~RUNQ_RACE;

			*slot = 0;
			if (now < start) {
				bump(RUNQ_NEGATIVE_DELTA);
			} else {
				u32 bucket = runq_bucket(now - start);
				u64 *count = bpf_map_lookup_elem(&RUNQ_HIST, &bucket);
				u64 *group = bpf_map_lookup_elem(&RUNQ_CGROUP, &key);
				u64 cgroup = group ? *group : 0;

				/*
				 * Not recorded yet: a thread that has not left a CPU
				 * since the agent started and was not seeded, such as
				 * one outside the agent's PID namespace, which its
				 * procfs does not show (kernel threads, under WSL2).
				 * Read off the task, once.
				 */
				if (!cgroup && group) {
					cgroup = BPF_CORE_READ(next, cgroups, dfl_cgrp, kn, id);
					*group = cgroup;
				}
				if (count)
					*count += 1;
				hist_add(&RUNQ_GROUP_HIST, cgroup, bucket, RUNQ_GROUP_INSERT_FAILED);
			}
		}
	}

	if (prev_tid != 0) {
		u32 key = prev_tid;
		u64 *group = bpf_map_lookup_elem(&RUNQ_CGROUP, &key);
		u64 *slot = bpf_map_lookup_elem(&RUNQ_START, &key);

		/* `prev` is `current`: record which cgroup it belongs to. */
		if (group)
			*group = bpf_get_current_cgroup_id();
		if (!slot) {
			bump(RUNQ_START_INSERT_FAILED);
		} else if (preempt || runnable_now(prev)) {
			/*
			 * Still runnable: waiting starts now. The live state, not the
			 * tracepoint's prev_state, which still says "sleeping" when a
			 * pending signal kept the thread on the queue.
			 */
			*slot = now;
		} else if (*slot & RUNQ_RACE) {
			*slot &= ~RUNQ_RACE;
		} else {
			/* Going to sleep: a start left by an earlier wakeup is stale. */
			*slot = 0;
		}
	}
	return 0;
}

#include "request/request.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";
