/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Go, with probes: why a goroutine is on no thread.
 *
 * runtime.gopark(unlockf, lock, reason, ...) is where a goroutine parks:
 * on a channel, a sync primitive, a timer, the network poller, the garbage
 * collector. It runs on the goroutine's own stack, so `g` is the goroutine
 * parking; `reason` is the third argument (a waitReason, whose values
 * change between Go versions: user space writes what each one is for the
 * process's version into GO_WAIT_KIND). The goroutine's binding notes when
 * and why (unit_off), and the thread is taken off it at once: what the
 * scheduler does next is not the goroutine's time. runtime.execute puts it
 * back on a thread, and the time in between goes to its request by that
 * reason (unit_on). The time includes, after it was woken, any wait for a
 * thread to run it on.
 *
 * Only an entry probe: a return probe on a goroutine stack would break when
 * the stack is moved.
 */
#ifndef BLAME_RUNTIME_GO_PARK_H
#define BLAME_RUNTIME_GO_PARK_H

SEC("uprobe")
int up_go_park(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(false);
	struct go_wait_key key = {};
	struct unit_key unit;
	u64 now = bpf_ktime_get_boot_ns(), goid;
	u8 *kind, why;

	if (!cr)
		return 0;
	carrier_cfg(cr);
	if (cr->rt.runtime != RT_GO || !(cr->rt.flags & PROC_F_PARK))
		return 0;
	goid = go_current_goid(ctx, &cr->rt);
	/* The thread's unit, as the execute probe set it, is the one parking. */
	if (!goid || cr->unit.kind != UNIT_GOROUTINE || cr->unit.id != goid)
		return 0;
	key.tgid = cr->unit.tgid;
	key.reason = (u8)go_arg(ctx, 2);
	kind = bpf_map_lookup_elem(&GO_WAIT_KIND, &key);
	why = kind && *kind < PARK_MAX ? *kind : PARK_OTHER;
	unit_off(cr, now, why);
	unit = cr->unit;
	unit.kind = UNIT_RUNTIME;
	unit.id = 0;
	unit_set(cr, &unit, now);
	return 0;
}

/*
 * runtime.goexit0(gp) is where a goroutine that has returned is taken off
 * its thread for good (on the thread's own stack, `gp` its first argument).
 * Without this the thread is the goroutine's until it runs another or goes
 * to sleep: a handler that has returned, and whose response another
 * goroutine writes in that moment, had not left its thread when its request
 * ended, and what it did last was counted nowhere.
 */
SEC("uprobe")
int up_go_exit(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(false);
	struct unit_key unit;
	u64 now = bpf_ktime_get_boot_ns(), gp, goid;

	if (!cr)
		return 0;
	carrier_cfg(cr);
	if (cr->rt.runtime != RT_GO)
		return 0;
	gp = go_arg(ctx, 0);
	goid = gp ? user_u64(gp + cr->rt.go_g_goid) : 0;
	if (!goid || cr->unit.kind != UNIT_GOROUTINE || cr->unit.id != goid)
		return 0;
	unit_off(cr, now, PARK_QUEUE);
	unit = cr->unit;
	unit.kind = UNIT_RUNTIME;
	unit.id = 0;
	unit_set(cr, &unit, now);
	return 0;
}

#endif
