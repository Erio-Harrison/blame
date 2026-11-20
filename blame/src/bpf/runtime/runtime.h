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

#endif
