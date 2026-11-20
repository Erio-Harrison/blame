/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Execution units: which request a thread or runtime unit works for, and
 * how its CPU, run-queue and sleeping time is given to that request.
 */
#ifndef BLAME_REQUEST_UNITS_H
#define BLAME_REQUEST_UNITS_H

/* A thread is its own unit until its process turns out to have a runtime. */
static __always_inline struct unit_key thread_unit(u32 tgid, u32 tid)
{
	struct unit_key unit = {};

	unit.tgid = tgid;
	unit.kind = UNIT_THREAD;
	unit.id = tid;
	return unit;
}

static __always_inline struct carrier *carrier_of_current(bool create)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct carrier *cr;

	cr = bpf_task_storage_get(&REQ_CARRIER, task, 0, create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
	if (!cr) {
		if (create)
			bump(REQ_CARRIER_FAILED);
		return NULL;
	}
	if (cr->unit.kind == 0) {
		u64 pid_tgid = cur_pid_tgid();

		cr->unit = thread_unit(pid_tgid >> 32, (u32)pid_tgid);
		cr->self_tid = (u32)pid_tgid;
		/*
		 * Created from a call the thread is making, so it is running;
		 * one made when the thread was (req_wakeup_new) knows since when.
		 */
		if (!cr->on_ns)
			cr->on_ns = bpf_ktime_get_boot_ns();
	}
	return cr;
}

static __always_inline bool acc_empty(const struct seg_acc *acc)
{
	return !(acc->ns[SEG_CPU] | acc->ns[SEG_RUNQ] | acc->ns[SEG_BLK_DOWN] |
		 acc->ns[SEG_BLK_CLIENT] | acc->ns[SEG_BLK_IO] | acc->ns[SEG_BLK_MEM] |
		 acc->ns[SEG_BLK_OTHER] | acc->ns[SEG_BLK_FSVC] | acc->ns[SEG_BLK_FSVC_LOCK]);
}

static __always_inline void acc_clear(struct seg_acc *acc)
{
	__builtin_memset(acc, 0, sizeof(*acc));
}

/*
 * Move accumulated time into a request. Threads on other CPUs do the same.
 * False if the request is gone.
 */
static __always_inline bool req_add(u64 req_id, struct seg_acc *acc, u8 source)
{
	struct req_state *req;
	u64 total;

	if (acc_empty(acc))
		return true;
	total = acc->ns[SEG_CPU] + acc->ns[SEG_RUNQ] + acc->ns[SEG_BLK_DOWN] +
		acc->ns[SEG_BLK_CLIENT] + acc->ns[SEG_BLK_IO] + acc->ns[SEG_BLK_MEM] +
		acc->ns[SEG_BLK_OTHER] + acc->ns[SEG_BLK_FSVC] + acc->ns[SEG_BLK_FSVC_LOCK];
	req = bpf_map_lookup_elem(&REQ_TABLE, &req_id);
	if (!req) {
		/*
		 * A handler the runtime pointed out goes on for a moment after
		 * the response has left (it returns, it is dropped): expected.
		 * Work spawned for a request may run on in the background.
		 */
		if (source == SRC_SPAWN)
			bump_by(HELPER_LATE_NS, total);
		else if (source != SRC_RUNTIME)
			bump(REQ_LATE_TIME);
		acc_clear(acc);
		return false;
	}
	if (source == SRC_SPAWN) {
		__sync_fetch_and_add(&req->helper.ns[SEG_CPU], acc->ns[SEG_CPU]);
		__sync_fetch_and_add(&req->helper.ns[SEG_RUNQ], acc->ns[SEG_RUNQ]);
		__sync_fetch_and_add(&req->helper.ns[SEG_BLK_DOWN], acc->ns[SEG_BLK_DOWN]);
		__sync_fetch_and_add(&req->helper.ns[SEG_BLK_CLIENT], acc->ns[SEG_BLK_CLIENT]);
		__sync_fetch_and_add(&req->helper.ns[SEG_BLK_IO], acc->ns[SEG_BLK_IO]);
		__sync_fetch_and_add(&req->helper.ns[SEG_BLK_MEM], acc->ns[SEG_BLK_MEM]);
		__sync_fetch_and_add(&req->helper.ns[SEG_BLK_OTHER], acc->ns[SEG_BLK_OTHER]);
		__sync_fetch_and_add(&req->helper.ns[SEG_BLK_FSVC], acc->ns[SEG_BLK_FSVC]);
		__sync_fetch_and_add(&req->helper.ns[SEG_BLK_FSVC_LOCK], acc->ns[SEG_BLK_FSVC_LOCK]);
		acc_clear(acc);
		return true;
	}
	__sync_fetch_and_add(&req->acc.ns[SEG_CPU], acc->ns[SEG_CPU]);
	__sync_fetch_and_add(&req->acc.ns[SEG_RUNQ], acc->ns[SEG_RUNQ]);
	__sync_fetch_and_add(&req->acc.ns[SEG_BLK_DOWN], acc->ns[SEG_BLK_DOWN]);
	__sync_fetch_and_add(&req->acc.ns[SEG_BLK_CLIENT], acc->ns[SEG_BLK_CLIENT]);
	__sync_fetch_and_add(&req->acc.ns[SEG_BLK_IO], acc->ns[SEG_BLK_IO]);
	__sync_fetch_and_add(&req->acc.ns[SEG_BLK_MEM], acc->ns[SEG_BLK_MEM]);
	__sync_fetch_and_add(&req->acc.ns[SEG_BLK_OTHER], acc->ns[SEG_BLK_OTHER]);
	__sync_fetch_and_add(&req->acc.ns[SEG_BLK_FSVC], acc->ns[SEG_BLK_FSVC]);
	__sync_fetch_and_add(&req->acc.ns[SEG_BLK_FSVC_LOCK], acc->ns[SEG_BLK_FSVC_LOCK]);
	if (source == SRC_RETRO)
		__sync_fetch_and_add(&req->retro_ns, total);
	else
		__sync_fetch_and_add(&req->observed_ns, total);
	acc_clear(acc);
	return true;
}

static __always_inline void add_time(struct carrier *cr, u32 seg, u64 ns)
{
	if (seg >= SEG_MAX)
		return;
	if (cr->req_id)
		cr->acc.ns[seg] += ns;
	else
		cr->pend.ns[seg] += ns;
	/* A thread of an OpenMP team between its pieces of work (runtime/omp.h). */
	if (seg == SEG_CPU && cr->omp_team && !cr->req_id)
		bump_by(OMP_TEAM_IDLE_CPU_NS, ns);
}

/*
 * A thread of an OpenMP team (runtime/omp.h) that works for no request right
 * now waited for a CPU from `from` to `now`. If the thread whose team it is
 * has a region open, it was most likely woken for it: the wait is kept, and
 * is the region's once the thread takes up a piece of its work (up_omp_fn).
 * Not before: libgomp wakes a whole team for a region that needs part of it
 * and sends the rest away, and a thread on its way back to idle waits too.
 */
static __always_inline void omp_team_wait(struct carrier *cr, u64 from, u64 now)
{
	struct omp_key key = { .at = cr->omp_team, .tgid = cr->unit.tgid };
	struct omp_region *open = bpf_map_lookup_elem(&OMP_OPEN, &key);

	if (!open)
		return;
	if (from < open->open_ns)
		from = open->open_ns;
	if (now <= from)
		return;
	if (cr->omp_wait_open != open->open_ns) {
		cr->omp_wait_open = open->open_ns;
		cr->omp_wait_ns = 0;
	}
	cr->omp_wait_ns += now - from;
}

/* Charge the CPU time up to now, before the binding changes. */
static __always_inline void settle_cpu(struct carrier *cr, u64 now)
{
	if (cr->on_ns && now > cr->on_ns)
		add_time(cr, SEG_CPU, now - cr->on_ns);
	if (cr->on_ns)
		cr->on_ns = now;
}

/* Whether a unit's binding has to outlive its stay on one thread. */
static __always_inline bool unit_moves(const struct unit_key *unit)
{
	return unit->kind == UNIT_GOROUTINE || unit->kind == UNIT_TOKIO_TASK;
}

static __always_inline void unbind(struct carrier *cr)
{
	if (!cr->req_id)
		return;
	req_add(cr->req_id, &cr->acc, cr->source);
	if (unit_moves(&cr->unit))
		bpf_map_delete_elem(&UNIT_BINDING, &cr->unit);
	cr->req_id = 0;
	cr->req_sk = 0;
	cr->source = SRC_NONE;
}

/* The unit read the request itself. What it did before was not for it. */
static __always_inline void bind_observed(struct carrier *cr, u64 req_id, u64 sk)
{
	unbind(cr);
	acc_clear(&cr->pend);
	cr->req_id = req_id;
	cr->req_sk = sk;
	cr->source = SRC_OBSERVED;
	if (unit_moves(&cr->unit)) {
		struct binding b = {};

		b.req_id = req_id;
		b.req_sk = sk;
		b.source = SRC_OBSERVED;
		/* It is on this thread: it read the request here. */
		b.on_tid = (u32)cur_pid_tgid();
		bpf_map_update_elem(&UNIT_BINDING, &cr->unit, &b, BPF_ANY);
	}
}

/*
 * The process's entry in REQ_PROCS, refreshed when user space changed it.
 * A thread can get here before the entry is there (probes are attached to
 * a process before its entry is written): it asks again until it is.
 */
static __always_inline void carrier_cfg(struct carrier *cr)
{
	if (cr->rt_gen != rt_gen) {
		struct proc_cfg *cfg = bpf_map_lookup_elem(&REQ_PROCS, &cr->unit.tgid);

		if (!cfg)
			return;
		cr->rt = *cfg;
		cr->rt_gen = rt_gen;
	}
}

/*
 * Where a request's own goroutine was while it was on no thread (Go, with
 * the park and execute probes, which say exactly when it leaves a thread
 * and when it is back). Its binding holds since when and why it left: why it
 * parked, set by the park probe; if it left without parking (preempted,
 * yielding, back from a syscall whose P was taken), it was waiting to be
 * run again. When it is back, that time goes
 * to the request. Units spawned for a request run beside its handler: their
 * waits are not the handler's, and are not counted.
 */
static __always_inline bool park_followed(const struct carrier *cr)
{
	return (cr->rt.flags & PROC_F_PARK) &&
	       (cr->unit.kind == UNIT_GOROUTINE || cr->unit.kind == UNIT_TOKIO_TASK);
}

/*
 * Probes in the runtime report every switch (PROC_F_UNIT_PROBES, and Go's
 * PROC_F_GO_EXECUTE): when a
 * request's handler first ran for it and when it last left its thread are
 * exact, and give the parts of the request it was not in its handler's
 * hands (request_event.before_handler_ns, after_handler_ns).
 */
static __always_inline bool switches_exact(const struct carrier *cr)
{
	return cr->rt.flags & (PROC_F_UNIT_PROBES | PROC_F_GO_EXECUTE);
}

/* The thread's unit leaves it now (`why`: if no probe said it parked). */
static __always_inline void unit_off(struct carrier *cr, u64 now, u8 why)
{
	bool park = park_followed(cr), exact = switches_exact(cr), other;
	struct binding *b;
	u64 taken;

	if (!cr->req_id || !unit_moves(&cr->unit) || (!park && !exact))
		return;
	b = bpf_map_lookup_elem(&UNIT_BINDING, &cr->unit);
	if (!b)
		return;
	/*
	 * Whether another thread has it (or had it and left it), then whether
	 * it took it from this one: the taker writes those in the other order,
	 * with a barrier between (unit_on), so a take is seen if its owner is.
	 */
	other = b->off_ns || (b->on_tid && b->on_tid != (u32)cur_pid_tgid());
	taken = __sync_fetch_and_add(&b->taken_ns, 0);
	/*
	 * Taken by another thread after this one left it (`now`), before this
	 * one got to say so: kept off its CPU in between, inside the probe.
	 * The unit waited to be run from `now` to the take.
	 */
	if (taken && cr->self_tid && b->taken_from == cr->self_tid) {
		if (park && taken > now) {
			struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &b->req_id);

			if (req)
				__sync_fetch_and_add(&req->park[PARK_QUEUE], taken - now);
		}
		b->taken_ns = 0;
		return;
	}
	if (other)
		return;
	if ((park && b->source != SRC_SPAWN) || (exact && b->source == SRC_RUNTIME)) {
		b->off_ns = now;
		b->off_why = why;
		b->doing = BIND_OFF;
	}
}

/*
 * The thread a request's unit is on says what it does with it from now on,
 * and hands the request what it has done so far.
 */
static __always_inline void unit_doing(struct carrier *cr, u64 now, u8 doing)
{
	struct binding *b;

	if (!cr->req_id || !unit_moves(&cr->unit) || !cr->self_tid || cr->taken)
		return;
	b = bpf_map_lookup_elem(&UNIT_BINDING, &cr->unit);
	if (b && b->on_tid == cr->self_tid && !b->off_ns) {
		b->since = now;
		b->doing = doing;
	}
	if (!req_add(cr->req_id, &cr->acc, cr->source))
		unbind(cr);
}

/* `b`, the binding of the unit the thread runs from now on: it is back. */
static __always_inline void unit_on(const struct carrier *cr, struct binding *b, u64 now)
{
	struct req_state *req;
	u8 why;

	if (!b)
		return;
	/* The thread it was taken from has it again: that is over. */
	if (b->taken_ns && b->taken_from == (u32)cur_pid_tgid())
		b->taken_ns = 0;
	/* On a thread by its own account, and that thread is not this one. */
	if (!b->off_ns && b->on_tid && b->on_tid != (u32)cur_pid_tgid()) {
		u32 doing = b->doing;
		u8 paid = 0;

		/*
		 * That thread is off its CPU: the unit has waited to be run since
		 * it left the CPU. Counted now, not when that thread gets a CPU
		 * again: by then the request may be over.
		 */
		if ((doing == BIND_WAITING || doing == BIND_ASLEEP) && b->since && now > b->since &&
		    __sync_val_compare_and_swap(&b->doing, doing, BIND_TAKEN) == doing) {
			struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &b->req_id);

			if (req && park_followed(cr))
				__sync_fetch_and_add(&req->park[PARK_QUEUE], now - b->since);
			paid = 1;
		}
		/*
		 * The take is seen by that thread on another CPU, which reads
		 * taken_paid once it sees taken_ns: the rest first, taken_ns
		 * last, with a barrier.
		 */
		b->taken_from = b->on_tid;
		b->taken_paid = paid;
		__sync_lock_test_and_set(&b->taken_ns, now);
	}
	b->on_tid = (u32)cur_pid_tgid();
	b->since = now;
	b->doing = BIND_RUNNING;
	if (b->source == SRC_RUNTIME && !b->ran && switches_exact(cr)) {
		b->ran = 1;
		req = bpf_map_lookup_elem(&REQ_TABLE, &b->req_id);
		if (req && !req->handler_on_ns)
			req->handler_on_ns = now;
	}
	if (!b->off_ns)
		return;
	why = b->off_why;
	if (park_followed(cr) && now > b->off_ns && why < PARK_MAX) {
		req = bpf_map_lookup_elem(&REQ_TABLE, &b->req_id);
		if (req)
			__sync_fetch_and_add(&req->park[why], now - b->off_ns);
	}
	b->off_ns = 0;
	b->woke = 0;
}

/*
 * Another thread took the unit before this one said it had left it: a tokio
 * task becomes idle inside its poll, and can be polled again elsewhere while
 * this thread is kept off its CPU on its way out of the poll; a goroutine
 * queued on its way back from a system call can be run elsewhere before this
 * thread has gone on to anything else. What this thread did since then was
 * not the unit's. Called when the thread turns to another unit, before what
 * it ran is settled.
 */
static __always_inline void taken_settle(struct carrier *cr, u64 now)
{
	if (cr->taken) {
		/* It was off its CPU then, or left it since: settled there (req_switch). */
		cr->taken = 0;
		if (cr->on_ns && cr->on_ns < now)
			cr->on_ns = now;
	} else if (unit_moves(&cr->unit) && cr->self_tid) {
		struct binding *was = bpf_map_lookup_elem(&UNIT_BINDING, &cr->unit);

		if (was && was->taken_ns && was->taken_from == cr->self_tid) {
			if (was->taken_ns >= now) {
				/*
				 * It left before the unit was taken, and gets to
				 * say so only now: the unit waited to be run in
				 * between, and nothing is to be taken back.
				 */
				struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &was->req_id);

				if (req && park_followed(cr))
					__sync_fetch_and_add(&req->park[PARK_QUEUE], was->taken_ns - now);
				was->taken_ns = 0;
				return;
			}
			/* It was running then: the unit's until then, nobody's since. */
			if (cr->on_ns && was->taken_ns > cr->on_ns)
				settle_cpu(cr, was->taken_ns);
			was->taken_ns = 0;
			if (cr->on_ns && cr->on_ns < now)
				cr->on_ns = now;
		}
	}
}

/*
 * A probe in the runtime says the thread runs `unit` from now on: what it
 * did until now was the previous unit's, and the new unit's binding is
 * taken over. Exact, unlike what unit_sync() has to work out.
 */
static __always_inline void unit_set(struct carrier *cr, const struct unit_key *unit, u64 now)
{
	struct binding *b = unit_moves(unit) ? bpf_map_lookup_elem(&UNIT_BINDING, unit) : NULL;
	u64 req_id = b ? b->req_id : 0;

	if (unit->kind == cr->unit.kind && unit->id == cr->unit.id && req_id == cr->req_id)
		return;
	taken_settle(cr, now);
	settle_cpu(cr, now);
	if (unit->kind != cr->unit.kind || unit->id != cr->unit.id)
		unit_off(cr, now, PARK_QUEUE);
	/*
	 * The request the thread was working for is gone: so is the binding
	 * that led to it, unless the unit has been handed another since (a
	 * pooled handler picks up its next request the moment it is done).
	 */
	if (cr->req_id && !req_add(cr->req_id, &cr->acc, cr->source) && unit_moves(&cr->unit)) {
		struct binding *old = bpf_map_lookup_elem(&UNIT_BINDING, &cr->unit);

		if (old && old->req_id == cr->req_id)
			bpf_map_delete_elem(&UNIT_BINDING, &cr->unit);
	}
	if (unit->kind != cr->unit.kind || unit->id != cr->unit.id)
		acc_clear(&cr->pend);
	cr->would_block = 0;
	cr->unit = *unit;
	cr->req_id = req_id;
	cr->req_sk = b ? b->req_sk : 0;
	cr->source = b ? b->source : SRC_NONE;
	/*
	 * The thread it was on said it left later than `now`: this thread
	 * was kept off its CPU between reading the time and getting here, and
	 * the unit was still on the other thread meanwhile. It is this one's
	 * from then on.
	 */
	if (b && b->off_ns > now && cr->on_ns)
		cr->on_ns = b->off_ns;
	unit_on(cr, b, now);
}

/*
 * The runtime handed a request to `unit`: its time is the request's from
 * its next step on, wherever it runs. The request is shown with it.
 */
static __always_inline void bind_handler(const struct unit_key *unit, u64 req_id, u64 sk)
{
	struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &req_id);
	struct binding b = {}, *old;

	if (!req)
		return;
	old = bpf_map_lookup_elem(&UNIT_BINDING, unit);
	/*
	 * Told a second time: Go starts a function over once it has grown the
	 * stack for it, and the probe at its entry is hit again. The binding
	 * holds what has happened since the first time (the handler ran).
	 */
	if (old && old->source == SRC_RUNTIME && old->req_id == req_id) {
		return;
	}
	/* A handler moving on from a request still in flight: it left that one now. */
	if (old && old->source == SRC_RUNTIME && old->ran && old->req_id != req_id) {
		struct req_state *prev = bpf_map_lookup_elem(&REQ_TABLE, &old->req_id);

		if (prev && !prev->handler_left_ns)
			prev->handler_left_ns = old->off_ns ? old->off_ns : bpf_ktime_get_boot_ns();
	}
	req->first_unit = *unit;
	b.req_id = req_id;
	b.req_sk = sk;
	b.source = SRC_RUNTIME;
	bpf_map_update_elem(&UNIT_BINDING, unit, &b, BPF_ANY);
}

/*
 * A unit bound to `req_id` (directly or as a helper) spawned `unit`: the new
 * unit works for the same request, as a helper, from its first step on and
 * wherever it runs, until the request is over. What it spawns in turn is
 * the request's too. The request is the one of the spawning unit at the
 * moment it spawned, not when the new unit first runs: by then a pooled
 * handler may have moved on to another request.
 */
static __always_inline void bind_spawned(const struct unit_key *unit, u64 req_id)
{
	struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &req_id);
	struct binding b = {};

	if (!req)
		return;
	b.req_id = req_id;
	b.source = SRC_SPAWN;
	if (bpf_map_update_elem(&UNIT_BINDING, unit, &b, BPF_ANY))
		return;
	__sync_fetch_and_add(&req->helpers, 1);
	bump(SPAWN_FOLLOWED);
}

/*
 * Ask the runtime which unit `task` (the current thread) is running, and
 * take over that unit's binding. Runtimes switch units without telling the
 * kernel, so this is asked at every event, and when the answer has changed
 * the switch happened somewhere since the last event. Whose that stretch of
 * CPU time was:
 * - a unit, then the runtime itself (the thread is about to idle): the
 *   unit's. It ran until it parked; the scheduler found nothing after it.
 * - the runtime, then a unit: the unit's. It was picked up and got here.
 * - one unit, then another: the first parked and the second was resumed
 *   with no kernel event in between. If the second parked on a socket and is
 *   now repeating the call (`resumed`), it has done nothing else yet: the
 *   first unit's. If the first unit's last act was a socket call that found
 *   nothing to do, it parked right there: the second's. Otherwise where one
 *   stopped and the other started is not visible from here (a unit that
 *   computes and then parks on a lock, a channel or a timer, next to one
 *   resumed from the same): the stretch is charged to neither and added up
 *   in unit_cpu_unseen_ns.
 *
 * `in_call`: asked on entry to a socket call, which is where a unit that
 * parked on a socket picks up again.
 */
static __always_inline void unit_sync(struct carrier *cr, struct task_struct *task, u64 now,
				      bool in_call)
{
	bool resumed = false;
	struct unit_key unit = cr->unit;
	struct binding *b = NULL;
	u64 id, req_id;
	u8 kind;

	carrier_cfg(cr);
	/* Probes keep cr->unit exact; what the runtime would say is less so. */
	if (cr->rt.flags & PROC_F_UNIT_PROBES)
		return;
	if (cr->rt.runtime == RT_GO) {
		id = go_goid(&cr->rt, task);
		/* Not told: the thread runs what it ran, as far as is known. */
		if (id == GO_GOID_UNKNOWN) {
			bump(UNIT_READ);
			return;
		}
		/*
		 * runtime.execute says exactly when a goroutine goes on a
		 * thread, and the thread's memory lags behind the probes: it
		 * still names a goroutine for a moment after runtime.gopark
		 * took the thread off it, and names none for the first
		 * instructions of runtime.execute, after its probe put one
		 * on. An event in that moment (the thread preempted on its
		 * way back from the probe) must not undo what the probe
		 * said. So memory never puts a thread on a goroutine here,
		 * and does not take it off one while the thread is at the
		 * start of runtime.execute.
		 */
		if (cr->rt.flags & PROC_F_GO_EXECUTE) {
			if (id && !(cr->unit.kind == UNIT_GOROUTINE && cr->unit.id == id)) {
				bump(UNIT_READ);
				return;
			}
			if (!id && cr->go_execute_pc) {
				u64 pc = go_user_pc(task);

				if (pc >= cr->go_execute_pc && pc < cr->go_execute_pc + GO_EXECUTE_HEAD) {
					bump(UNIT_READ);
					return;
				}
			}
		}
		kind = UNIT_GOROUTINE;
	} else if (cr->rt.runtime == RT_TOKIO) {
		id = tokio_task_id(&cr->rt, task);
		kind = UNIT_TOKIO_TASK;
	} else {
		return;
	}
	bump(UNIT_READ);
	unit.kind = id ? kind : UNIT_RUNTIME;
	unit.id = id;
	if (id)
		b = bpf_map_lookup_elem(&UNIT_BINDING, &unit);
	req_id = b ? b->req_id : 0;
	if (b && b->io_parked) {
		resumed = true;
		if (in_call)
			b->io_parked = 0;
	}
	if (unit.kind == cr->unit.kind && unit.id == cr->unit.id && req_id == cr->req_id)
		return;
	taken_settle(cr, now);
	if (unit_moves(&cr->unit)) {
		if (unit.kind == UNIT_RUNTIME || (unit.id != cr->unit.id && resumed)) {
			settle_cpu(cr, now);
		} else if (unit.id != cr->unit.id && !cr->would_block && cr->on_ns &&
			   now > cr->on_ns) {
			bump_by(UNIT_CPU_UNSEEN_NS, now - cr->on_ns);
			cr->on_ns = now;
		}
	}
	cr->would_block = 0;
	/* What was settled stays with the unit seen before; a binding to a request that is gone is dropped. */
	if (cr->req_id && !req_add(cr->req_id, &cr->acc, cr->source) && unit_moves(&cr->unit))
		bpf_map_delete_elem(&UNIT_BINDING, &cr->unit);
	if (unit.kind != cr->unit.kind || unit.id != cr->unit.id) {
		acc_clear(&cr->pend);
		unit_off(cr, now, PARK_QUEUE);
	}
	cr->unit = unit;
	cr->req_id = req_id;
	cr->req_sk = b ? b->req_sk : 0;
	cr->source = b ? b->source : SRC_NONE;
	settle_cpu(cr, now);
	/*
	 * The thread it was on said it left later than `now`: this thread
	 * was kept off its CPU between reading the time and getting here, and
	 * the unit was still on the other thread meanwhile. It is this one's
	 * from then on.
	 */
	if (b && b->off_ns > now && cr->on_ns)
		cr->on_ns = b->off_ns;
	unit_on(cr, b, now);
}

#endif
