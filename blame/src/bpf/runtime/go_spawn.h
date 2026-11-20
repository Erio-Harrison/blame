/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Go, with probes: goroutines started for a request work for it.
 *
 * runtime.newproc1(fn, callergp, ...) creates every goroutine (a `go`
 * statement, and the runtime's own) and returns the new g. It runs on the
 * thread's system stack, where `g` is g0 and m.curg is the goroutine that
 * executes the `go` statement: the parent. On entry the parent's binding is
 * taken (unit_sync brings the thread's unit up to date first, where no probe
 * keeps it so); on return the new goroutine gets it, as a helper
 * (bind_spawned). Taking it at creation, not when the child first runs,
 * matters for a handler that moves on to its next request at once.
 *
 * The return probe is safe here, unlike on goroutine stacks: the system
 * stack is never moved, so the return address the kernel swaps in is not
 * copied away, and the garbage collector does not walk it.
 *
 * The result is in the first result register of Go's internal ABI: R0 on
 * arm64, AX on x86-64 (go_arg(…, 0) at return).
 *
 * The runtime starts goroutines of its own from whatever goroutine needs
 * them first: the garbage collector's workers from one that allocates, the
 * finalizer goroutine from one that sets a finalizer, and so on. They are
 * not the request's. The first argument is the funcval whose first word is
 * where the new goroutine starts; a start at one of the runtime's functions
 * (SPAWN_SKIP, link-time addresses, shifted by where the binary is loaded)
 * is not followed.
 */

#ifndef BLAME_RUNTIME_GO_SPAWN_H
#define BLAME_RUNTIME_GO_SPAWN_H

static __always_inline u64 probe_pc(struct pt_regs *regs)
{
	if (bpf_core_field_exists(regs->pc))
		return BPF_CORE_READ(regs, pc);
	return BPF_CORE_READ((struct pt_regs___x86 *)regs, ip);
}

/* Whether the goroutine about to be created starts in the runtime itself. */
static __always_inline bool runtime_goroutine(struct pt_regs *ctx, u32 tgid)
{
	struct spawn_skip_key key = {};
	u64 *link = bpf_map_lookup_elem(&SPAWN_BASE, &tgid);
	u64 fn = go_arg(ctx, 0);

	if (!link || !fn)
		return false;
	key.addr = user_u64(fn) - (probe_pc(ctx) - *link);
	key.tgid = tgid;
	return bpf_map_lookup_elem(&SPAWN_SKIP, &key) != NULL;
}
SEC("uprobe")
int up_go_newproc(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(true);
	struct task_struct *task = bpf_get_current_task_btf();

	if (!cr)
		return 0;
	carrier_cfg(cr);
	cr->spawn_req = 0;
	if (cr->rt.runtime != RT_GO || !(cr->rt.flags & PROC_F_SPAWN))
		return 0;
	unit_sync(cr, task, bpf_ktime_get_boot_ns(), false);
	if (cr->unit.kind == UNIT_GOROUTINE && cr->req_id && !runtime_goroutine(ctx, cr->unit.tgid))
		cr->spawn_req = cr->req_id;
	return 0;
}

SEC("uretprobe")
int up_go_newproc_ret(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(false);
	struct unit_key unit;
	u64 newg, goid, req_id;

	if (!cr || !cr->spawn_req)
		return 0;
	req_id = cr->spawn_req;
	cr->spawn_req = 0;
	newg = go_arg(ctx, 0);
	goid = newg ? user_u64(newg + cr->rt.go_g_goid) : 0;
	if (!goid)
		return 0;
	unit = goroutine(cr->unit.tgid, goid);
	bind_spawned(&unit, req_id);
	return 0;
}

#endif
