/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Pids as the agent's PID namespace numbers them.
 *
 * bpf_get_current_pid_tgid() answers in the kernel's initial namespace.
 * An agent in another one (a WSL2 distribution, a container without the
 * host's PID namespace) knows the same processes by other numbers: those
 * of its procfs, of --pid, of the probes it attaches. So every pid that
 * user space hands in or is handed comes from cur_pid_tgid().
 *
 * User space sets the namespace from /proc/self/ns/pid; ino 0 means it is
 * the initial one, and the constant lets the verifier drop the other branch.
 * A task outside the namespace has no number in it: 0, which is never a
 * traced process.
 *
 * Pids read from a task_struct other than current (the scheduler hooks)
 * stay in the initial namespace. They only index the kernel side's own
 * tables, and are never compared with these.
 */
#ifndef BLAME_PIDNS_H
#define BLAME_PIDNS_H

const volatile u64 pidns_dev = 0;
const volatile u64 pidns_ino = 0;

static __always_inline u64 cur_pid_tgid(void)
{
	struct bpf_pidns_info ns;

	if (!pidns_ino)
		return bpf_get_current_pid_tgid();
	if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
		return 0;
	return ((u64)ns.tgid << 32) | ns.pid;
}

#endif
