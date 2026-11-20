/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/* Why a sleeping thread woke, and the scheduler hooks that keep time. */
#ifndef BLAME_REQUEST_WAKE_H
#define BLAME_REQUEST_WAKE_H

/*
 * Data arriving on a socket. The socket is remembered for the duration of
 * the call, so that a wakeup issued from inside it can be traced back to it.
 */
SEC("fentry/sock_def_readable")
int BPF_PROG(req_readable, struct sock *sk)
{
	u64 key = (u64)sk;
	u32 zero = 0;
	struct wake_ctx *wake = bpf_map_lookup_elem(&REQ_WAKE, &zero);
	struct conn *c = bpf_map_lookup_elem(&REQ_CONNS, &key);

	if (wake) {
		wake->sk = key;
		wake->state = sk->__sk_common.skc_state;
	}
	if (!c)
		return 0;
	if (c->cls == CONN_CLIENT) {
		if (!c->ready_ns)
			c->ready_ns = bpf_ktime_get_boot_ns();
	} else if (c->sent_ns) {
		u64 now = bpf_ktime_get_boot_ns();

		if (!c->answer_ns)
			c->answer_ns = now;
		c->arrived_ns = now;
	}
	return 0;
}

SEC("fexit/sock_def_readable")
int BPF_PROG(req_readable_done, struct sock *sk)
{
	u32 zero = 0;
	struct wake_ctx *wake = bpf_map_lookup_elem(&REQ_WAKE, &zero);

	if (wake)
		wake->sk = 0;
	return 0;
}

/*
 * Whether `current` is only the thread that happened to be interrupted. Known
 * where the preempt count is per thread (arm64); elsewhere the answer is "no".
 */
static __always_inline bool in_interrupt(struct task_struct *current)
{
	if (bpf_core_field_exists(current->thread_info.preempt_count)) {
		u32 count = current->thread_info.preempt_count;

		/* NMI, hard interrupt, or serving a soft interrupt. */
		return count & 0x00ff0100;
	}
	return false;
}

/* The same question for hard interrupts and NMIs alone. */
static __always_inline bool in_hard_interrupt(struct task_struct *current)
{
	if (bpf_core_field_exists(current->thread_info.preempt_count))
		return current->thread_info.preempt_count & 0x00ff0000;
	return false;
}

/*
 * Flushing to disk. A thread in fsync, fdatasync, a write to a file opened
 * with O_SYNC or O_DSYNC, or msync(MS_SYNC) goes through vfs_fsync_range();
 * syncfs() through sync_filesystem(). Its sleeps there are waits for the
 * disk, but the kernel marks only those in io_schedule(): on ext4 and xfs the
 * wait for the journal commit is a plain sleep (jbd2_log_wait_commit on
 * ext4), and it is most of the time of an fsync after an append: by the
 * io_schedule() mark alone, 6 to 9% of such an fsync was the disk's.
 *
 * Only filesystems on a block device count as the disk here. On a file
 * service (fsvc.h: NFS, FUSE, virtiofs, ...) the same sleeps are waits for
 * the service: also those for the file's lock, which the filesystem takes
 * while it flushes (fuse_fsync), when another thread holds it to write or
 * flush the same file. overlayfs is not on a block device itself, but
 * flushes through the filesystem underneath, which is counted by the nested
 * call. sync(2) and io_uring's fsync, done by a kernel worker, are not
 * covered.
 *
 * An fsync on NFS still waits in io_schedule(), which the kernel marks as a
 * wait for the disk; what keeps it apart is the file service mark, which
 * comes first.
 */
/* What a flush waits for: carrier.sync_sys. */
enum { SYNC_NONE = 0, SYNC_DISK = 1, SYNC_FSVC = 2 };

/* Read, not dereferenced: also given a file found from an fd (sync_sys_enter). */
static __always_inline bool sb_on_disk(struct super_block *sb)
{
	struct file_system_type *type = sb ? BPF_CORE_READ(sb, s_type) : NULL;

	return type && (BPF_CORE_READ(type, fs_flags) & FS_REQUIRES_DEV);
}

static __always_inline u8 sync_kind(struct super_block *sb)
{
	if (!sb)
		return SYNC_NONE;
	if (sb_on_disk(sb))
		return SYNC_DISK;
	if (sb_fsvc(sb))
		return SYNC_FSVC;
	return SYNC_NONE;
}

static __always_inline void sync_depth(struct carrier *cr, u8 kind, bool enter)
{
	u8 *depth;

	if (kind == SYNC_DISK)
		depth = &cr->in_sync;
	else if (kind == SYNC_FSVC)
		depth = &cr->in_sync_fsvc;
	else
		return;
	/* A call entered before the agent started leaves without having entered. */
	if (enter) {
		if (*depth < 255)
			(*depth)++;
	} else if (*depth) {
		(*depth)--;
	}
}

static __always_inline void sync_step(struct super_block *sb, bool enter)
{
	struct carrier *cr;

	if (!sb)
		return;
	cr = bpf_task_storage_get(&REQ_CARRIER, bpf_get_current_task_btf(), 0, 0);
	if (!cr)
		return;
	sync_depth(cr, sync_kind(sb), enter);
}

static __always_inline struct super_block *file_sb(struct file *file)
{
	struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : NULL;

	return inode ? BPF_CORE_READ(inode, i_sb) : NULL;
}

SEC("fentry/vfs_fsync_range")
int BPF_PROG(req_fsync, struct file *file)
{
	sync_step(file_sb(file), true);
	return 0;
}

SEC("fexit/vfs_fsync_range")
int BPF_PROG(req_fsync_done, struct file *file)
{
	sync_step(file_sb(file), false);
	return 0;
}

/*
 * fsync and fdatasync, also at the system call: a kernel may inline
 * vfs_fsync_range() into it, and the fentry above then never runs (6.6 on
 * x86-64, WSL2's build: fdatasync calls ext4_sync_file() itself; fsync
 * still goes through vfs_fsync_range()). Where it does run, the two nest,
 * and the depths count both. The file is only known on the way in: which
 * depth was raised is kept for the way out.
 */
static __always_inline int sync_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	struct carrier *cr = bpf_task_storage_get(&REQ_CARRIER, bpf_get_current_task_btf(), 0, 0);

	if (!cr)
		return 0;
	cr->sync_sys = sync_kind(file_sb(fd_file((int)ctx->args[0])));
	sync_depth(cr, cr->sync_sys, true);
	return 0;
}

static __always_inline int sync_sys_exit(void)
{
	struct carrier *cr = bpf_task_storage_get(&REQ_CARRIER, bpf_get_current_task_btf(), 0, 0);

	if (!cr)
		return 0;
	sync_depth(cr, cr->sync_sys, false);
	cr->sync_sys = SYNC_NONE;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int req_sys_fsync(struct trace_event_raw_sys_enter *ctx)
{
	return sync_sys_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fsync")
int req_sys_fsync_done(struct trace_event_raw_sys_exit *ctx)
{
	return sync_sys_exit();
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int req_sys_fdatasync(struct trace_event_raw_sys_enter *ctx)
{
	return sync_sys_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_fdatasync")
int req_sys_fdatasync_done(struct trace_event_raw_sys_exit *ctx)
{
	return sync_sys_exit();
}

SEC("fentry/sync_filesystem")
int BPF_PROG(req_syncfs, struct super_block *sb)
{
	sync_step(sb, true);
	return 0;
}

SEC("fexit/sync_filesystem")
int BPF_PROG(req_syncfs_done, struct super_block *sb)
{
	sync_step(sb, false);
	return 0;
}

/*
 * What a thread going to sleep is waiting for, where that is known: memory
 * (the thread is inside a memory stall section), a file service (fsvc.h),
 * or the disk (it is flushing to disk, see above, or sleeps in
 * io_schedule()). An io_uring wait carries
 * the same disk mark whatever it waits for, a socket included; it is the only
 * marked sleep that signals can interrupt, and is left out.
 */
static __always_inline u8 sleep_seg(struct task_struct *task, const struct carrier *cr)
{
	if (bpf_core_field_exists(task->in_memstall) && BPF_CORE_READ_BITFIELD(task, in_memstall))
		return SEG_BLK_MEM;
	/* Before the disk: the kernel marks some of these waits as for the disk. */
	if (cr->in_fsvc || cr->in_sync_fsvc)
		return cr->in_lock ? SEG_BLK_FSVC_LOCK : SEG_BLK_FSVC;
	if (cr->in_sync)
		return SEG_BLK_IO;
	if (BPF_CORE_READ_BITFIELD(task, in_iowait) && !(task_state(task) & TASK_INTERRUPTIBLE))
		return SEG_BLK_IO;
	return 0;
}

/* The sleep that just ended, `asleep` ns long: what was the thread waiting for? */
static __always_inline void classify_sleep(struct carrier *cr, u64 asleep)
{
	u8 wake = WAKE_OTHER;
	/* The client socket that woke it is in the middle of a request. */
	bool mid_request = false;
	u64 owner = 0;

	/*
	 * The kernel marked the sleep itself: the thread was working, whatever
	 * woke it, so this comes before the wake source.
	 */
	if (cr->off_seg) {
		add_time(cr, cr->off_seg, asleep);
		return;
	}
	if (cr->wake_sk) {
		if (cr->wake_state == TCP_LISTEN) {
			wake = WAKE_LISTEN;
		} else {
			struct conn *c = bpf_map_lookup_elem(&REQ_CONNS, &cr->wake_sk);

			if (c) {
				wake = c->cls == CONN_CLIENT ? WAKE_CLIENT : WAKE_DOWN;
				owner = c->owner_req;
				mid_request = c->rx.st != HS_START && c->rx.st != HS_UNSYNC;
			}
		}
	}
	if (cr->req_id) {
		if (wake == WAKE_DOWN && owner == cr->req_id)
			cr->acc.ns[SEG_BLK_DOWN] += asleep;
		else if (wake == WAKE_CLIENT && cr->wake_sk == cr->req_sk && mid_request)
			/* More of the request it is reading; the next one would be new work. */
			cr->acc.ns[SEG_BLK_CLIENT] += asleep;
		else if (wake != WAKE_OTHER && !(unit_moves(&cr->unit) && switches_exact(cr)))
			/* New work arrived: it was idle, and done with the request. */
			unbind(cr);
		else
			/*
			 * Also a thread whose runtime says exactly when a unit is
			 * on it, whatever woke it: it slept with the request's unit
			 * on it, and what woke it does not make it idle (an idle
			 * one has no unit).
			 */
			cr->acc.ns[SEG_BLK_OTHER] += asleep;
		return;
	}
	if (cr->waker_req || wake == WAKE_CLIENT || wake == WAKE_LISTEN)
		/* Handed work by a thread serving a request, or new work arrived: idle. */
		acc_clear(&cr->pend);
	else if (wake == WAKE_DOWN)
		cr->pend.ns[SEG_BLK_DOWN] += asleep;
	else
		cr->pend.ns[SEG_BLK_OTHER] += asleep;
}

/*
 * A thread of a traced process that is not followed yet and is not
 * `current`: one that was there when the agent started, seen being woken or
 * given a CPU before it made a call or left a CPU itself. Its numbers are the
 * kernel's, which are the agent's only in the initial PID namespace; in
 * another, such a thread is followed from the first time it is `current`.
 */
static __always_inline struct carrier *carrier_of_other(struct task_struct *p)
{
	struct carrier *cr;
	u32 tgid = p->tgid;

	if (pidns_ino || !p->pid || !proc_bit(tgid) || !traced(tgid))
		return NULL;
	cr = bpf_task_storage_get(&REQ_CARRIER, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cr) {
		bump(REQ_CARRIER_FAILED);
		return NULL;
	}
	if (!cr->unit.kind) {
		cr->unit = thread_unit(tgid, p->pid);
		cr->self_tid = p->pid;
	}
	return cr;
}

SEC("tp_btf/sched_waking")
int BPF_PROG(req_waking, struct task_struct *p)
{
	struct carrier *cr = bpf_task_storage_get(&REQ_CARRIER, p, 0, 0);
	struct task_struct *current;
	struct wake_ctx *wake;
	u32 zero = 0;

	if (!cr)
		cr = carrier_of_other(p);
	if (!cr)
		return 0;
	/* As in the run-queue programs: the wait starts when the wakeup is issued. */
	if (!queued(p) && cr->runq_ns == 0) {
		u64 now = bpf_ktime_get_boot_ns();

		cr->runq_ns = now | (p->on_cpu ? RUNQ_RACE : 0);
		proc_wait_begin(cr, proc_queue(p), cpu_of(p), now);
	}
	if (!cr->off_ns || cr->woken)
		return 0;
	cr->woken = 1;
	current = bpf_get_current_task_btf();
	/*
	 * Data is delivered in a soft interrupt or by the sender itself. A hard
	 * interrupt that cuts in, a timer expiring say, issues wakeups that have
	 * nothing to do with the socket being served underneath it.
	 */
	wake = in_hard_interrupt(current) ? NULL : bpf_map_lookup_elem(&REQ_WAKE, &zero);
	cr->wake_sk = wake ? wake->sk : 0;
	cr->wake_state = wake ? wake->state : 0;
	cr->waker_req = 0;
	/* A thread of the same process waking it on purpose: a handoff. */
	if (!cr->wake_sk && current->tgid == p->tgid && !in_interrupt(current)) {
		struct carrier *waker = bpf_task_storage_get(&REQ_CARRIER, current, 0, 0);

		if (waker)
			cr->waker_req = waker->req_id;
	}
	return 0;
}

/*
 * A traced process starts a thread. It is followed from here, not from the
 * first time it leaves a CPU: its wait for its first turn is a wait like any
 * other, and what it runs in that turn is its process's on that CPU (a
 * server with a thread per connection is mostly such turns).
 */
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(req_wakeup_new, struct task_struct *p)
{
	struct task_struct *current = bpf_get_current_task_btf();
	struct carrier *cr;
	u32 tgid;
	u64 now;

	/* A new process is not one of its creator's threads. */
	if (p->tgid != current->tgid)
		return 0;
	tgid = cur_pid_tgid() >> 32;
	if (!proc_bit(tgid) || !traced(tgid))
		return 0;
	cr = bpf_task_storage_get(&REQ_CARRIER, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!cr) {
		bump(REQ_CARRIER_FAILED);
		return 0;
	}
	if (cr->unit.kind || cr->unit.tgid)
		return 0;
	/* Its own number it says itself, the first time it is `current` (carrier_of_current). */
	cr->unit.tgid = tgid;
	now = bpf_ktime_get_boot_ns();
	cr->runq_ns = now;
	proc_wait_begin(cr, proc_queue(p), cpu_of(p), now);
	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(req_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
	u64 now = bpf_ktime_get_boot_ns();
	u32 cpu = bpf_get_smp_processor_id();
	struct carrier *cr, *in;

	cr = prev->pid ? bpf_task_storage_get(&REQ_CARRIER, prev, 0, 0) : NULL;
	/*
	 * Every thread of a traced process is followed from the first time it
	 * leaves a CPU, not only those that make socket calls: what the others
	 * wait for a CPU counts for the process too (proc_cpu.h).
	 */
	if (!cr && prev->pid) {
		u32 tgid = cur_pid_tgid() >> 32;

		if (proc_bit(tgid) && traced(tgid))
			cr = carrier_of_current(true);
	} else if (cr && !cr->unit.kind) {
		/* Followed since it was started: it is `current` here for the first time. */
		cr = carrier_of_current(false);
	}
	in = next->pid ? bpf_task_storage_get(&REQ_CARRIER, next, 0, 0) : NULL;
	if (!in)
		in = carrier_of_other(next);
	proc_cpu_switch(cpu, now, prev, in ? in->unit.tgid : 0, !next->pid);
	if (cr) {
		if (cr->rt.runtime > RT_NONE)
			unit_sync(cr, prev, now, false);
		if (cr->on_ns && now > cr->on_ns) {
			u64 until = now;

			/*
			 * Its unit was taken by another thread (units.h): what it
			 * ran since then, on its way to say it had left the unit,
			 * was not the unit's.
			 */
			if (cr->taken) {
				until = cr->on_ns;
			} else if (cr->req_id && unit_moves(&cr->unit) && cr->self_tid) {
				struct binding *b = bpf_map_lookup_elem(&UNIT_BINDING, &cr->unit);

				if (b && b->taken_ns && b->taken_from == cr->self_tid) {
					if (b->taken_ns < until) {
						until = b->taken_ns > cr->on_ns ? b->taken_ns : cr->on_ns;
					} else {
						/* Taken as it left the CPU: it waited to be run in between. */
						struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &b->req_id);

						if (req && park_followed(cr))
							__sync_fetch_and_add(&req->park[PARK_QUEUE], b->taken_ns - until);
					}
					b->taken_ns = 0;
					cr->taken = 1;
				}
			}
			if (until > cr->on_ns)
				add_time(cr, SEG_CPU, until - cr->on_ns);
		}
		cr->on_ns = 0;
		if (preempt || runnable_now(prev)) {
			cr->runq_ns = now;
			cr->off_ns = 0;
			proc_wait_begin(cr, proc_queue(prev), cpu, now);
		} else if (cr->runq_ns & RUNQ_RACE) {
			/*
			 * Woken while switching out: it never really slept. It
			 * waits for a CPU from here, not from the wakeup: until
			 * here it was on one, and that time is counted as such.
			 */
			cr->runq_ns = now;
			cr->off_ns = 0;
			/* What its process ran until now was this thread itself. */
			proc_wait_begin(cr, proc_queue(prev), cpu, now);
		} else {
			cr->runq_ns = 0;
			cr->off_ns = now;
			cr->off_seg = sleep_seg(prev, cr);
			cr->woken = 0;
			cr->wake_sk = 0;
			cr->waker_req = 0;
			cr->rq_snap = 0;
			/* Keep the request up to date while its thread sleeps. */
			if (cr->req_id && !req_add(cr->req_id, &cr->acc, cr->source))
				unbind(cr);
		}
		unit_doing(cr, now, cr->off_ns ? BIND_ASLEEP : BIND_WAITING);
	}

	cr = in;
	if (cr) {
		u64 runnable = cr->runq_ns & ~RUNQ_RACE, wait;

		if (!runnable || runnable > now)
			runnable = now;
		/*
		 * Its unit was taken by another thread while this one was off its
		 * CPU (units.h): asleep, as a thread can be on its way through a
		 * probe, or waiting for a CPU. It has run nothing since it left
		 * the CPU, so the unit had left it by then: the unit waited to be
		 * run from there to when it was taken, and neither this sleep nor
		 * this wait is the unit's.
		 */
		if (cr->req_id && unit_moves(&cr->unit) && cr->self_tid) {
			struct binding *b = bpf_map_lookup_elem(&UNIT_BINDING, &cr->unit);
			/* With a barrier: taken_paid is read after it (unit_on). */
			u64 taken = b ? __sync_fetch_and_add(&b->taken_ns, 0) : 0;

			if (b && taken && b->taken_from == cr->self_tid) {
				u64 left = cr->off_ns ? cr->off_ns : runnable;
				struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &b->req_id);

				if (req && park_followed(cr) && b->taken_ns > left && !b->taken_paid)
					__sync_fetch_and_add(&req->park[PARK_QUEUE], b->taken_ns - left);
				b->taken_ns = 0;
				cr->taken = 1;
			} else if (b && b->on_tid == cr->self_tid && !b->off_ns) {
				u32 doing = b->doing;

				/*
				 * Back on a CPU with the unit still its own: its wait
				 * is its own unless the unit is being taken right now,
				 * by a thread that counts the wait itself (unit_on).
				 */
				if ((doing == BIND_WAITING || doing == BIND_ASLEEP) &&
				    __sync_val_compare_and_swap(&b->doing, doing, BIND_RUNNING) != doing)
					cr->taken = 1;
				else if (doing == BIND_TAKEN)
					cr->taken = 1;
			}
		}
		if (cr->off_ns) {
			if (runnable < cr->off_ns)
				runnable = cr->off_ns;
			if (!cr->taken)
				classify_sleep(cr, runnable - cr->off_ns);
			cr->off_ns = 0;
		}
		wait = cr->taken ? 0 : now - runnable;
		add_time(cr, SEG_RUNQ, wait);
		unit_doing(cr, now, BIND_RUNNING);
		proc_wait_end(cr, next, cpu, now, now - runnable);
		cr->rq_from = runnable;
		cr->rq_to = now;
		if (cr->omp_team && !cr->req_id)
			omp_team_wait(cr, runnable, now);
		cr->runq_ns = 0;
		cr->on_ns = now;
	}
	return 0;
}

/*
 * A process is gone when its main thread is. The tracepoint fires in the
 * exiting thread, so its number in the agent's namespace is current's.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(req_process_exit, struct task_struct *p)
{
	u32 tgid = cur_pid_tgid() >> 32;

	if (tgid && p->pid == p->tgid)
		bpf_map_delete_elem(&REQ_PROCS, &tgid);
	return 0;
}

#endif
