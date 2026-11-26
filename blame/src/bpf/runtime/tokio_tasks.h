/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * tokio, with probes: which task a thread polls, exactly, and which task
 * serves which HTTP/2 stream.
 *
 * - Every task is polled through one of a few small functions
 *   (task::raw::poll::<T, S>, one per kind of task) whose argument is the
 *   task's header. A probe at their entry and one at their return bracket
 *   the time a thread spends in a task.
 * - hyper serves each HTTP/2 stream in a task of its own, spawned by the
 *   task that reads the connection (OwnedTasks::bind_inner sees the new
 *   task's header). The new task holds a reference to its stream, and with
 *   it the stream id, at a place the compiler chose. User space finds that
 *   place from samples of new tasks (task_sample_event) and records it per
 *   kind of task in TASK_STREAM_OFF; from then on the id is read here and
 *   (connection, stream id) -> request binds the task.
 *
 * - Any other task bound to a request that spawns one makes the new task a
 *   helper of that request (bind_spawned), when the user asked for spawned
 *   units to be followed (PROC_F_SPAWN). A closure given to
 *   tokio::task::spawn_blocking (and so every tokio::fs call) becomes a task
 *   that does not go through bind_inner: blocking::pool::Spawner::spawn_task
 *   sees its header instead (up_tokio_spawn_blocking), and it is followed
 *   the same way. The blocking pool's threads poll it through the same
 *   task::raw::poll functions.
 *
 * The id is held at two places; they must agree, be odd, and name a stream
 * the connection has open, or nothing is bound. If it could not even be a
 * stream that is over already, that is counted (GRPC_HANDOFF_UNMATCHED).
 *
 * Offsets within tokio's task header (1.25-1.54): the vtable pointer at 16;
 * in the vtable, the offset of the task id at 72.
 */
#ifndef BLAME_RUNTIME_TOKIO_TASKS_H
#define BLAME_RUNTIME_TOKIO_TASKS_H

static __always_inline u64 tokio_header_id(u64 header, u64 *vtable)
{
	u64 vt = header ? user_u64(header + 16) : 0;
	u64 id_off = vt ? user_u64(vt + 72) : 0;

	if (vtable)
		*vtable = vt;
	/* Headers are small; anything else is not a vtable. */
	if (!id_off || id_off > 4096)
		return 0;
	return user_u64(header + id_off);
}

static __always_inline struct unit_key tokio_task(u32 tgid, u64 id)
{
	struct unit_key unit = {};

	unit.tgid = tgid;
	unit.kind = id ? UNIT_TOKIO_TASK : UNIT_RUNTIME;
	unit.id = id;
	return unit;
}

/* A thread starts polling the task whose header is `header` (`blocking`: of the blocking pool). */
static __always_inline int tokio_poll_enter(u64 header, bool blocking)
{
	struct carrier *cr = carrier_of_current(true);
	struct unit_key unit;
	u64 id;

	if (!cr)
		return 0;
	carrier_cfg(cr);
	cr->in_blocking = blocking;
	id = tokio_header_id(header, NULL);
	if (!id)
		return 0;
	unit = tokio_task(cr->unit.tgid, id);
	if (!blocking && (cr->rt.flags & PROC_F_TOKIO_BLOCKING) &&
	    bpf_map_lookup_elem(&TOKIO_BLOCKING, &unit))
		cr->in_blocking = 1;
	unit_set(cr, &unit, bpf_ktime_get_boot_ns());
	return 0;
}

static __always_inline int tokio_poll_leave(void)
{
	struct carrier *cr = carrier_of_current(false);
	struct unit_key unit;

	if (!cr)
		return 0;
	cr->in_blocking = 0;
	unit = tokio_task(cr->unit.tgid, 0);
	unit_set(cr, &unit, bpf_ktime_get_boot_ns());
	return 0;
}

SEC("uprobe")
int up_tokio_poll(struct pt_regs *ctx)
{
	return tokio_poll_enter(c_arg(ctx, 0), false);
}

SEC("uretprobe")
int up_tokio_poll_ret(struct pt_regs *ctx)
{
	return tokio_poll_leave();
}

/* The same for the poll functions of blocking-pool tasks, which also say so. */
SEC("uprobe")
int up_tokio_poll_blocking(struct pt_regs *ctx)
{
	return tokio_poll_enter(c_arg(ctx, 0), true);
}

SEC("uretprobe")
int up_tokio_poll_blocking_ret(struct pt_regs *ctx)
{
	return tokio_poll_leave();
}

SEC("uprobe")
int up_tokio_spawn(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(false);
	struct task_kind kind = {};
	struct stream_key skey = {};
	struct task_stream_off *off;
	struct unit_key unit;
	u64 header, child, *sk, *req_id;
	u32 a = 0, b = 0, zero = 0;

	if (!cr || cr->unit.kind != UNIT_TOKIO_TASK)
		return 0;
	header = c_arg(ctx, 1);
	sk = bpf_map_lookup_elem(&UNIT_READS, &cr->unit);
	if (!sk) {
		/*
		 * Not the task that reads an HTTP/2 connection: a task working
		 * for a request spawned another one for it (tokio::spawn, also
		 * onto another runtime), if that is followed.
		 */
		carrier_cfg(cr);
		if (cr->req_id && (cr->rt.flags & PROC_F_SPAWN)) {
			child = tokio_header_id(header, NULL);
			if (child) {
				unit = tokio_task(cr->unit.tgid, child);
				bind_spawned(&unit, cr->req_id);
			}
		}
		return 0;
	}
	child = tokio_header_id(header, &kind.vtable);
	if (!child)
		return 0;
	kind.tgid = cr->unit.tgid;
	off = bpf_map_lookup_elem(&TASK_STREAM_OFF, &kind);
	if (!off) {
		struct task_sample_event *e = bpf_map_lookup_elem(&REQ_SCRATCH_TASK, &zero);

		if (!e)
			return 0;
		if (bpf_probe_read_user(e->mem, sizeof(e->mem), (void *)header)) {
			bump(FIELD_READ_FAILED);
			return 0;
		}
		e->hdr.version = EVENT_VERSION;
		e->hdr.kind = EVENT_TASK_SAMPLE;
		e->hdr.cpu = 0;
		e->hdr._pad = 0;
		e->hdr.ts_boot_ns = bpf_ktime_get_boot_ns();
		e->hdr.cgroup_id = 0;
		e->hdr.netns_id = 0;
		e->hdr.ifindex = 0;
		e->hdr.pid = kind.tgid;
		e->hdr.tid = (u32)cur_pid_tgid();
		e->conn = *sk;
		e->parent = cr->unit.id;
		e->child = child;
		e->vtable = kind.vtable;
		if (bpf_ringbuf_output(&EVENTS, e, sizeof(*e), 0))
			bump(RINGBUF_FULL);
		return 0;
	}
	if (off->a == TASK_OFF_NONE)
		return 0;
	bpf_probe_read_user(&a, sizeof(a), (void *)(header + off->a));
	bpf_probe_read_user(&b, sizeof(b), (void *)(header + off->b));
	skey.sk = *sk;
	skey.sid = a;
	req_id = a == b && (a & 1) ? bpf_map_lookup_elem(&REQ_STREAMS, &skey) : NULL;
	if (!req_id) {
		if (a != b || !h2_stream_plausible(skey.sk, a))
			bump(GRPC_HANDOFF_UNMATCHED);
		return 0;
	}
	unit = tokio_task(kind.tgid, child);
	bind_handler(&unit, *req_id, skey.sk);
	return 0;
}

/*
 * blocking::pool::Spawner::spawn_task(spawner, task, mandatory, handle): a
 * closure for the blocking pool became a task. A task bound to a request
 * that does this hands the request work to do on another thread: the new
 * task is a helper of the request, as one it spawned. With
 * PROC_F_TOKIO_BLOCKING the task is also noted as the pool's, bound or not.
 */
SEC("uprobe")
int up_tokio_spawn_blocking(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(false);
	struct unit_key unit;
	u64 child;
	u8 one = 1;

	if (!cr || cr->unit.kind != UNIT_TOKIO_TASK)
		return 0;
	carrier_cfg(cr);
	if (!cr->req_id && !(cr->rt.flags & PROC_F_TOKIO_BLOCKING))
		return 0;
	child = tokio_header_id(c_arg(ctx, 1), NULL);
	if (!child)
		return 0;
	unit = tokio_task(cr->unit.tgid, child);
	if (cr->rt.flags & PROC_F_TOKIO_BLOCKING)
		bpf_map_update_elem(&TOKIO_BLOCKING, &unit, &one, BPF_ANY);
	if (!cr->req_id || !(cr->rt.flags & PROC_F_SPAWN))
		return 0;
	bind_spawned(&unit, cr->req_id);
	return 0;
}

/*
 * Why a request's task was on no thread (PROC_F_PARK). A task that returns
 * Pending says nothing of what it waits for, but whatever wakes it puts it
 * back on a run queue: the multi-thread scheduler's Handle::schedule_task,
 * the current-thread one's Schedule::schedule (the task's header the second
 * argument of both). What the waking thread was doing
 * then tells what the task waited for: the I/O driver's turn (DRV_IO), a
 * socket or another event source; firing timers (DRV_TIME), a timer
 * (PARK_SLEEP); polling a task of the blocking pool, its result
 * (PARK_BLOCKING); polling another task, whatever that one gave it (a
 * channel, a lock, a join handle: PARK_TASK); anything else (a thread of no
 * runtime, a future run by block_on): PARK_OTHER. Checked against a server
 * whose every kind of request waits on one of these
 * (tests/scenarios/m4_acceptance.sh, section 13).
 * The time from leaving its thread to the wake goes to that reason; from
 * the wake to its next poll, to waiting to be run (PARK_QUEUE), which is
 * also where it goes when it was woken while still running.
 */
enum { DRV_IO = 1, DRV_TIME = 2 };

static __always_inline int tokio_drv(u8 drv)
{
	struct carrier *cr = carrier_of_current(false);

	if (cr)
		cr->drv = drv;
	return 0;
}

SEC("uprobe")
int up_tokio_io_turn(struct pt_regs *ctx)
{
	return tokio_drv(DRV_IO);
}

SEC("uretprobe")
int up_tokio_io_turn_ret(struct pt_regs *ctx)
{
	return tokio_drv(0);
}

SEC("uprobe")
int up_tokio_timers(struct pt_regs *ctx)
{
	return tokio_drv(DRV_TIME);
}

SEC("uretprobe")
int up_tokio_timers_ret(struct pt_regs *ctx)
{
	return tokio_drv(0);
}

SEC("uprobe")
int up_tokio_wake(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(false);
	struct req_state *req;
	struct binding *b;
	struct unit_key unit;
	u64 now, id;
	u32 tgid = cur_pid_tgid() >> 32;
	u8 why;

	id = tokio_header_id(c_arg(ctx, 1), NULL);
	if (!id)
		return 0;
	unit = tokio_task(tgid, id);
	b = bpf_map_lookup_elem(&UNIT_BINDING, &unit);
	/* Only a request's own task, while it is off every thread. */
	if (!b || b->source == SRC_SPAWN || !b->off_ns || b->woke)
		return 0;
	if (!cr)
		why = PARK_OTHER;
	else if (cr->drv == DRV_IO)
		why = PARK_NET;
	else if (cr->drv == DRV_TIME)
		why = PARK_SLEEP;
	else if (cr->unit.kind == UNIT_TOKIO_TASK)
		why = cr->in_blocking ? PARK_BLOCKING : PARK_TASK;
	else
		why = PARK_OTHER;
	now = bpf_ktime_get_boot_ns();
	req = bpf_map_lookup_elem(&REQ_TABLE, &b->req_id);
	if (req && now > b->off_ns)
		__sync_fetch_and_add(&req->park[why], now - b->off_ns);
	b->off_ns = now;
	b->off_why = PARK_QUEUE;
	b->woke = 1;
	return 0;
}

#endif
