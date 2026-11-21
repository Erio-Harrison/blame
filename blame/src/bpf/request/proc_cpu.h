/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * What a traced process's threads waited for a CPU, whatever they were doing.
 *
 * A request's own wait for a CPU is only that of a thread while it works for
 * the request. A thread of a runtime that waits for a CPU before it can read
 * an answer and wake the goroutine or task the answer is for works for no
 * request yet: the request waits longer on a channel or a lock, and nothing
 * above says the CPU was the reason. So every wait of every thread of the
 * process is summed here, per process, and split by what had the CPU the
 * thread was queued on meanwhile: a thread of the same process (the process
 * has more to run than CPUs to run it on) or anything else (the CPU was
 * taken from it).
 *
 * For that, each CPU keeps what the threads of each process have run on it
 * (PROC_CPU.ran_ns, with the stretch still running in CPU_NOW). A thread
 * that starts to wait notes that figure for its process on its CPU; when it
 * runs, the difference is what its own process ran there meanwhile. A thread
 * moved to another CPU's queue while it waits (sched_migrate_task, also at a
 * wakeup that picks another CPU) settles the first queue and starts on the
 * next.
 *
 * The rest of the wait is not all the others': a thread can be runnable
 * while nothing runs on its CPU. Two more figures are kept the same way.
 * What the CPU was idle (CPU_NOW.idle_ns): a wait counts from the wakeup,
 * and an idle CPU takes a while to be woken. And what the queue of the
 * thread's control group on that CPU was throttled by a CPU limit with
 * threads in it, which the kernel counts itself (kernel.h): the group's
 * threads are runnable then and kept off the CPU, idle or not. So a wait is
 * four parts: own threads, the limit, the CPU idle outside the limit, and
 * the others, which is what is left: something else did run.
 */
#ifndef BLAME_REQUEST_PROC_CPU_H
#define BLAME_REQUEST_PROC_CPU_H

static __always_inline bool proc_bit(u32 tgid)
{
	return proc_bits[(tgid % PROC_BITS) / 64] & (1ULL << (tgid % 64));
}

/* The CPU a thread is on, or queued on. */
static __always_inline u32 cpu_of(struct task_struct *p)
{
	if (bpf_core_field_exists(p->thread_info.cpu))
		return p->thread_info.cpu;
	return BPF_CORE_READ((struct task_struct___pre516 *)p, cpu);
}

static __always_inline struct proc_cpu *proc_cpu_at(u32 tgid, u32 cpu, bool create)
{
	struct proc_cpu_key key = { .tgid = tgid, .cpu = cpu };
	struct proc_cpu *pc = bpf_map_lookup_elem(&PROC_CPU, &key);

	if (!pc && create) {
		struct proc_cpu zero = {};

		/* Another CPU may have made it meanwhile: only a lookup tells. */
		bpf_map_update_elem(&PROC_CPU, &key, &zero, BPF_NOEXIST);
		pc = bpf_map_lookup_elem(&PROC_CPU, &key);
		if (!pc)
			bump(PROC_CPU_INSERT_FAILED);
	}
	return pc;
}

/* A sum that may be open (maps.h), as of now. */
static __always_inline u64 proc_sum(u64 word, u64 now)
{
	if (word & PROC_OPEN)
		return (word + now) & ~PROC_OPEN;
	return word;
}

/* The same sum, opened at `since` or closed at `now`. */
static __always_inline u64 proc_open(u64 sum, u64 since)
{
	return ((sum - since) & ~PROC_OPEN) | PROC_OPEN;
}

/* What threads of a process have run on a CPU, up to now. */
static __always_inline u64 proc_ran(u32 tgid, u32 cpu, u64 now)
{
	struct proc_cpu *pc = proc_cpu_at(tgid, cpu, false);

	return pc ? proc_sum(pc->ran_ns, now) : 0;
}

/* What a CPU has been idle, up to now. */
static __always_inline u64 proc_idle(u32 cpu, u64 now)
{
	struct cpu_now *cn = bpf_map_lookup_elem(&CPU_NOW, &cpu);

	return cn ? proc_sum(cn->idle_ns, now) : 0;
}

/* Whether the kernel keeps the throttled time of a group's queue. */
static __always_inline bool proc_limit_kept(void)
{
	struct task_struct *p = NULL;
	struct cfs_rq *q = NULL;

	return bpf_core_field_exists(p->se.cfs_rq) && bpf_core_field_exists(p->sched_task_group) &&
	       bpf_core_field_exists(q->throttled_clock_self_time);
}

/*
 * What a group's queue on `cpu` has been throttled with threads in it, up to
 * now: the kernel's sum, and the stretch still open. That one began at a
 * time of the run queue's clock, which is behind ours by what it was at the
 * CPU's last switch.
 */
static __always_inline u64 proc_limit(struct cfs_rq *q, u32 cpu, u64 now)
{
	u64 total, since;

	if (!proc_limit_kept() || !q)
		return 0;
	/*
	 * The kernel moves an open stretch into the sum in two steps, on the
	 * queue's own CPU. Read around the sum: if the stretch was closed or
	 * opened meanwhile, read again.
	 */
	since = BPF_CORE_READ(q, throttled_clock_self);
	total = BPF_CORE_READ(q, throttled_clock_self_time);
	if (BPF_CORE_READ(q, throttled_clock_self) != since) {
		since = BPF_CORE_READ(q, throttled_clock_self);
		total = BPF_CORE_READ(q, throttled_clock_self_time);
	}
	if (since) {
		struct cpu_now *cn = bpf_map_lookup_elem(&CPU_NOW, &cpu);
		u64 off = cn ? cn->clock_off : 0;

		if (off && now > off + since)
			total += now - off - since;
	}
	return total;
}

/*
 * Whether a CPU limit applies to a thread: the limit is the fair class's.
 * A real-time or deadline thread of a limited group is not kept off the CPU
 * by it, though the group's queue is throttled around it.
 */
static __always_inline bool proc_limited(struct task_struct *p)
{
	unsigned int policy = p->policy;

	return proc_limit_kept() && policy != 1 && policy != 2 && policy != 6;
}

/* The queue of a thread's group on the CPU it is on, or queued on. */
static __always_inline struct cfs_rq *proc_queue(struct task_struct *p)
{
	return proc_limited(p) ? p->se.cfs_rq : NULL;
}

/*
 * This CPU goes from `prev` to the next thread; `tgid`: the next one's
 * process, if traced; `idle`: the next one is the idle thread.
 */
static __always_inline void proc_cpu_switch(u32 cpu, u64 now, struct task_struct *prev, u32 tgid, bool idle)
{
	struct cpu_now *cn = bpf_map_lookup_elem(&CPU_NOW, &cpu);

	if (!cn)
		return;
	/* Close the sum of what ran until now, open that of what runs from now. */
	if (cn->tgid) {
		struct proc_cpu *pc = proc_cpu_at(cn->tgid, cpu, false);

		if (pc)
			pc->ran_ns = proc_sum(pc->ran_ns, now);
	} else if (cn->idle) {
		cn->idle_ns = proc_sum(cn->idle_ns, now);
	}
	if (tgid) {
		struct proc_cpu *pc = proc_cpu_at(tgid, cpu, true);

		if (pc)
			pc->ran_ns = proc_open(pc->ran_ns, now);
		else
			tgid = 0;
	} else if (idle) {
		cn->idle_ns = proc_open(cn->idle_ns, now);
	}
	cn->tgid = tgid;
	cn->idle = idle;
	cn->since = now;
	if (proc_limit_kept()) {
		/* The scheduler read the run queue's clock on its way here. */
		u64 clock = BPF_CORE_READ(prev, se.cfs_rq, rq, clock);

		if (clock && now > clock)
			cn->clock_off = now - clock;
		proc_limit_known = 1;
	}
}

/* The thread starts to wait for `cpu`, in the queue `q` of its group there. */
static __always_inline void proc_wait_begin(struct carrier *cr, struct cfs_rq *q, u32 cpu, u64 now)
{
	cr->rq_cpu = cpu;
	cr->rq_own0 = proc_ran(cr->unit.tgid, cpu, now);
	cr->rq_own = 0;
	cr->rq_idle0 = proc_idle(cpu, now);
	cr->rq_idle = 0;
	cr->rq_limit0 = proc_limit(q, cpu, now);
	cr->rq_limit = 0;
	cr->rq_snap = 1;
}

/* What its own process ran on the queue it is on since it joined it. */
static __always_inline u64 proc_wait_own(struct carrier *cr, u64 now)
{
	u64 ran = proc_ran(cr->unit.tgid, cr->rq_cpu, now);

	return ran > cr->rq_own0 ? ran - cr->rq_own0 : 0;
}

/* The same for the CPU being idle, and for the group's queue `q` there being throttled. */
static __always_inline u64 proc_wait_idle(struct carrier *cr, u64 now)
{
	u64 idle = proc_idle(cr->rq_cpu, now);

	return idle > cr->rq_idle0 ? idle - cr->rq_idle0 : 0;
}

static __always_inline u64 proc_wait_limit(struct carrier *cr, struct cfs_rq *q, u64 now)
{
	u64 limit = proc_limit(q, cr->rq_cpu, now);

	return limit > cr->rq_limit0 ? limit - cr->rq_limit0 : 0;
}

/* The thread `p` runs on `cpu` after waiting `wait` ns. */
static __always_inline void proc_wait_end(struct carrier *cr, struct task_struct *p, u32 cpu, u64 now, u64 wait)
{
	struct proc_cpu *pc;
	u64 own, limit, idle, rest;

	if (!cr->rq_snap)
		return;
	cr->rq_snap = 0;
	if (!wait)
		return;
	own = cr->rq_own + proc_wait_own(cr, now);
	if (own > wait)
		own = wait;
	limit = cr->rq_limit + proc_wait_limit(cr, proc_queue(p), now);
	if (limit > wait - own)
		limit = wait - own;
	rest = wait - own - limit;
	/*
	 * The CPU was idle through most of a throttled stretch: only what it
	 * was idle beyond that is the wait for an idle CPU.
	 */
	idle = cr->rq_idle + proc_wait_idle(cr, now);
	idle = idle > limit ? idle - limit : 0;
	if (idle > rest)
		idle = rest;
	pc = proc_cpu_at(cr->unit.tgid, cpu, true);
	if (!pc)
		return;
	pc->wait_own_ns += own;
	pc->wait_limit_ns += limit;
	pc->wait_idle_ns += idle;
	pc->wait_others_ns += rest - idle;
}

SEC("tp_btf/sched_migrate_task")
int BPF_PROG(req_migrate, struct task_struct *p, int dest_cpu)
{
	struct carrier *cr = bpf_task_storage_get(&REQ_CARRIER, p, 0, 0);
	u64 now;

	if (!cr || !cr->rq_snap)
		return 0;
	now = bpf_ktime_get_boot_ns();
	cr->rq_own += proc_wait_own(cr, now);
	cr->rq_idle += proc_wait_idle(cr, now);
	/* It is still in the first queue's books here. */
	cr->rq_limit += proc_wait_limit(cr, proc_queue(p), now);
	cr->rq_cpu = dest_cpu;
	cr->rq_own0 = proc_ran(cr->unit.tgid, dest_cpu, now);
	cr->rq_idle0 = proc_idle(dest_cpu, now);
	cr->rq_limit0 = 0;
	if (proc_limited(p)) {
		struct cfs_rq **queues = BPF_CORE_READ(p, sched_task_group, cfs_rq);
		struct cfs_rq *q = NULL;

		if (queues && (u32)dest_cpu < PROC_CPUS_MAX)
			bpf_probe_read_kernel(&q, sizeof(q), &queues[dest_cpu]);
		cr->rq_limit0 = proc_limit(q, dest_cpu, now);
	}
	return 0;
}

#endif
