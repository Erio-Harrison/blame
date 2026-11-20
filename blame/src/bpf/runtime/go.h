/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Go keeps the running goroutine `g` in a register (R28 on arm64, R14 on
 * x86_64). On the scheduler's or the signal stack that is g0 or gsignal, and
 * the goroutine the thread carries is m.curg; none means the thread is idle
 * or in the scheduler. The field offsets depend on the Go version and come
 * from user space (runtime/go.rs).
 */
#ifndef BLAME_RUNTIME_GO_H
#define BLAME_RUNTIME_GO_H

/* Not read: the register did not hold a g of the thread. */
#define GO_GOID_UNKNOWN (~0ULL)

/*
 * The id of the goroutine `task` is running; 0 = none; GO_GOID_UNKNOWN when
 * it cannot be told, which is not "none": C code may use the register for
 * something else for a while (the vDSO's clock functions do), and the
 * goroutine goes on afterwards. `task` must be current.
 */
/*
 * runtime.execute writes the goroutine into its thread's memory within its
 * first instructions (mp.curg = gp, after the stack check): this many bytes
 * of code are more than those.
 */
#define GO_EXECUTE_HEAD 256

/* Where a probe's thread is in its program: the probed instruction. */
static __always_inline u64 go_probe_pc(struct pt_regs *ctx)
{
	if (bpf_core_field_exists(ctx->pc))
		return BPF_CORE_READ(ctx, pc);
	return BPF_CORE_READ((struct pt_regs___x86 *)ctx, ip);
}

/* The same for a thread caught anywhere; `task` must be current. */
static __always_inline u64 go_user_pc(struct task_struct *task)
{
	return go_probe_pc((struct pt_regs *)bpf_task_pt_regs(task));
}

static __always_inline u64 go_goid(const struct proc_cfg *cfg, struct task_struct *task)
{
	struct pt_regs *regs = (struct pt_regs *)bpf_task_pt_regs(task);
	u64 g, m, curg;

	if (bpf_core_field_exists(regs->regs))
		g = BPF_CORE_READ(regs, regs[28]);
	else
		g = BPF_CORE_READ((struct pt_regs___x86 *)regs, r14);
	m = g ? user_u64(g + cfg->go_g_m) : 0;
	if (!m) {
		bump(UNIT_READ_INCONSISTENT);
		return GO_GOID_UNKNOWN;
	}
	curg = user_u64(m + cfg->go_m_curg);
	if (g == curg)
		return user_u64(g + cfg->go_g_goid);
	if (g == user_u64(m + cfg->go_m_g0) || g == user_u64(m + cfg->go_m_gsignal))
		return curg ? user_u64(curg + cfg->go_g_goid) : 0;
	/* Not a g of this m: the offsets are wrong, or C code owns the register. */
	bump(UNIT_READ_INCONSISTENT);
	return GO_GOID_UNKNOWN;
}

#endif
