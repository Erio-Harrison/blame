/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * OpenMP parallel regions (GNU libgomp): the threads that take up a
 * request's work.
 *
 * A handler that computes in parallel is not alone on the request: the
 * threads of its team do most of it, and they are not the request's thread.
 * Which request a team thread works for is in no kernel event. It is in the
 * calls: the thread that opens a region calls GOMP_parallel(fn, data, ...),
 * `data` pointing to what the region shares (on its own stack), and every
 * thread of the team then calls fn(data). So:
 *
 * - at the entry of GOMP_parallel and its like, in a thread that works for
 *   a request: `data` is that request's until the call returns;
 * - at the entry of a region's function, in another thread: the thread is a
 *   helper of the request `data` is for, until the function returns. Its
 *   time is the request's as that of a spawned goroutine or task is.
 *
 * The functions of regions are many (libtorch_cpu has thousands) and only
 * those a process runs get probes: the first region that runs one says so
 * (OMP_FNS) and user space puts them there. Until then the region's team is
 * not followed (OMP_REGION_UNFOLLOWED).
 *
 * A team thread also waits for a CPU before it gets to its work: woken for
 * the region, it is behind whatever else runs. Once it has been seen to work
 * for a thread it is of that thread's team (libgomp keeps a team per thread
 * that opens regions), and what it waits while that thread has a region open
 * is the region's if it then takes up a piece of it (omp_team_wait). The
 * first time, only the wait that ended when it was last put on a CPU is
 * known.
 *
 * What a team thread does outside the functions (it spins for the next
 * region, or for the rest of its team to finish) is nobody's.
 */
#ifndef BLAME_RUNTIME_OMP_H
#define BLAME_RUNTIME_OMP_H

static __always_inline void omp_close(u32 tgid, u32 tid)
{
	struct omp_key by_thread = { .at = tid, .tgid = tgid };
	struct omp_region *open = bpf_map_lookup_elem(&OMP_OPEN, &by_thread);
	struct omp_key by_data = { .tgid = tgid };

	if (!open)
		return;
	by_data.at = open->data;
	bpf_map_delete_elem(&OMP_REGIONS, &by_data);
	bpf_map_delete_elem(&OMP_OPEN, &by_thread);
}

/* GOMP_parallel(fn, data, ...) and its like: a region opens. */
SEC("uprobe")
int up_omp_parallel(struct pt_regs *ctx)
{
	u64 pid_tgid = cur_pid_tgid();
	struct carrier *cr = carrier_of_current(false);
	struct omp_key key = { .tgid = pid_tgid >> 32 };
	struct omp_region region = {};
	u8 fresh = OMP_FN_NEW, *fn;

	/* A region left open (its return was not seen) is over by now. */
	omp_close(key.tgid, (u32)pid_tgid);
	if (!cr || !cr->req_id)
		return 0;
	key.at = c_arg(ctx, 0);
	fn = bpf_map_lookup_elem(&OMP_FNS, &key);
	if (!fn)
		bpf_map_update_elem(&OMP_FNS, &key, &fresh, BPF_NOEXIST);
	region.req_id = cr->req_id;
	region.open_ns = bpf_ktime_get_boot_ns();
	region.data = c_arg(ctx, 1);
	region.master = (u32)pid_tgid;
	/* Nothing shared: nothing to tell its work by. */
	if (!fn || *fn != OMP_FN_PROBED || !region.data) {
		bump(OMP_REGION_UNFOLLOWED);
		return 0;
	}
	key.at = region.data;
	if (bpf_map_update_elem(&OMP_REGIONS, &key, &region, BPF_ANY))
		return 0;
	key.at = region.master;
	bpf_map_update_elem(&OMP_OPEN, &key, &region, BPF_ANY);
	return 0;
}

SEC("uprobe")
int up_omp_parallel_ret(struct pt_regs *ctx)
{
	u64 pid_tgid = cur_pid_tgid();

	omp_close(pid_tgid >> 32, (u32)pid_tgid);
	return 0;
}

/* fn(data): a thread takes up a piece of a region's work. */
SEC("uprobe")
int up_omp_fn(struct pt_regs *ctx)
{
	u64 pid_tgid = cur_pid_tgid();
	u64 now = bpf_ktime_get_boot_ns();
	struct omp_key key = { .at = c_arg(ctx, 0), .tgid = pid_tgid >> 32 };
	struct omp_region *region = bpf_map_lookup_elem(&OMP_REGIONS, &key);
	struct req_state *req;
	struct carrier *cr;

	/* The thread that opened it does its own share as the request's thread. */
	if (!region || region->master == (u32)pid_tgid)
		return 0;
	cr = carrier_of_current(true);
	/* Working for a request already (a region inside a region): it stays that one's. */
	if (!cr || cr->req_id)
		return 0;
	req = bpf_map_lookup_elem(&REQ_TABLE, &region->req_id);
	if (!req)
		return 0;
	/* What it did until here was no request's. */
	settle_cpu(cr, now);
	acc_clear(&cr->pend);
	cr->req_id = region->req_id;
	cr->req_sk = 0;
	cr->source = SRC_SPAWN;
	cr->omp_bound = 1;
	if (cr->omp_team == region->master) {
		if (cr->omp_wait_open == region->open_ns)
			add_time(cr, SEG_RUNQ, cr->omp_wait_ns);
	} else {
		if (cr->rq_to > region->open_ns)
			add_time(cr, SEG_RUNQ,
				 cr->rq_to - (cr->rq_from > region->open_ns ? cr->rq_from :
									       region->open_ns));
		cr->omp_team = region->master;
	}
	cr->omp_wait_ns = 0;
	cr->omp_wait_open = 0;
	__sync_fetch_and_add(&req->helpers, 1);
	bump(SPAWN_FOLLOWED);
	return 0;
}

SEC("uprobe")
int up_omp_fn_ret(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(false);

	if (!cr || !cr->omp_bound)
		return 0;
	cr->omp_bound = 0;
	settle_cpu(cr, bpf_ktime_get_boot_ns());
	unbind(cr);
	return 0;
}

#endif
