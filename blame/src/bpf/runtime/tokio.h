/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * tokio keeps the id of the task being polled in a thread-local; it is 0
 * outside a poll. Where that is relative to the thread pointer comes from
 * user space (runtime/tokio.rs).
 */
#ifndef BLAME_RUNTIME_TOKIO_H
#define BLAME_RUNTIME_TOKIO_H

/* The id of the tokio task `task` is polling; 0 = none. `task` must be current. */
static __always_inline u64 tokio_task_id(const struct proc_cfg *cfg, struct task_struct *task)
{
	u64 tp;

	if (bpf_core_field_exists(task->thread.uw.tp_value))
		tp = task->thread.uw.tp_value;
	else
		tp = ((struct thread_struct___x86 *)&task->thread)->fsbase;
	return tp ? user_u64(tp + cfg->tokio_task_id) : 0;
}

#endif
