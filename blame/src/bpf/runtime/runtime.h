/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Runtime adapters, kernel side: which execution unit is running on a thread
 * right now, read from the runtime's own state in the process's memory. No
 * probe is placed in the process; the reads happen inside kernel events that
 * are hooked anyway (socket calls, thread switches).
 *
 * One file per runtime (go.h, tokio.h): each answers with the
 * id of the unit a thread is running, 0 for none. request/units.h picks the one for
 * the process and turns the id into a unit (unit_sync).
 *
 * Where to look (struct proc_cfg) comes from user space, per process.
 */
#ifndef BLAME_RUNTIME_H
#define BLAME_RUNTIME_H

static __always_inline u64 user_u64(u64 addr)
{
	u64 value = 0;

	bpf_probe_read_user(&value, sizeof(value), (void *)addr);
	return value;
}

#include "go.h"
#include "tokio.h"

/* The n-th argument (0 to 3) of a function following the C register order. */
static __always_inline u64 c_arg(struct pt_regs *regs, int n)
{
	struct pt_regs___x86 *x86 = (struct pt_regs___x86 *)regs;

	if (bpf_core_field_exists(regs->regs)) {
		switch (n) {
		case 0:
			return BPF_CORE_READ(regs, regs[0]);
		case 1:
			return BPF_CORE_READ(regs, regs[1]);
		case 2:
			return BPF_CORE_READ(regs, regs[2]);
		default:
			return BPF_CORE_READ(regs, regs[3]);
		}
	}
	switch (n) {
	case 0:
		return BPF_CORE_READ(x86, di);
	case 1:
		return BPF_CORE_READ(x86, si);
	case 2:
		return BPF_CORE_READ(x86, dx);
	default:
		return BPF_CORE_READ(x86, cx);
	}
}

/* The stack pointer: the stack grows down, so a call made inside another has a lower one. */
static __always_inline u64 c_sp(struct pt_regs *regs)
{
	struct pt_regs___x86 *x86 = (struct pt_regs___x86 *)regs;

	if (bpf_core_field_exists(regs->regs))
		return BPF_CORE_READ(regs, sp);
	return BPF_CORE_READ(x86, sp);
}

/* What a function following the C register order returns. */
static __always_inline u64 c_ret(struct pt_regs *regs)
{
	struct pt_regs___x86 *x86 = (struct pt_regs___x86 *)regs;

	if (bpf_core_field_exists(regs->regs))
		return BPF_CORE_READ(regs, regs[0]);
	return BPF_CORE_READ(x86, ax);
}

#endif
