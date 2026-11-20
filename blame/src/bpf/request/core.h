/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/* A request's life: started, finished or given up. */
#ifndef BLAME_REQUEST_CORE_H
#define BLAME_REQUEST_CORE_H

static __always_inline u64 req_start(struct conn *c, struct carrier *cr, u64 now, u64 ready)
{
	u64 pid_tgid = cur_pid_tgid();
	u32 zero = 0;
	struct req_state *req = bpf_map_lookup_elem(&REQ_SCRATCH_REQ, &zero);
	u64 id;

	if (!req)
		return 0;
	__builtin_memset(req, 0, sizeof(*req));
	req->start_ns = now;
	req->ready_ns = ready;
	req->cgroup_id = bpf_get_current_cgroup_id();
	req->first_unit = cr->unit;
	req->tgid = pid_tgid >> 32;
	req->first_tid = (u32)pid_tgid;
	req->lport = c->lport;
	req->rport = c->rport;
	id = __sync_fetch_and_add(&req_next_id, 1) + 1;
	if (bpf_map_update_elem(&REQ_TABLE, &id, req, BPF_NOEXIST)) {
		bump(REQ_INSERT_FAILED);
		return 0;
	}
	bump(REQ_STARTED);
	return id;
}

static __always_inline void req_abort(u64 id)
{
	if (!bpf_map_delete_elem(&REQ_TABLE, &id))
		bump(REQ_ABORTED);
}

/*
 * The parts of a request its handler had nothing to do with, when a runtime
 * bound one to it (SRC_RUNTIME) and its switches are exact (units.h): until
 * the handler first ran, and from when it last left its thread to the end,
 * if it did not run again. While it is off its thread at the end, the time
 * since is no park of it (that would be counted when it is back, after the
 * request is gone), so the two never overlap with request_event.parked_ns.
 * REQ_F_HANDLER_TIMED if known.
 */
static __always_inline u8 handler_times(u64 id, const struct req_state *req, u64 end_ns,
					u64 *before, u64 *after)
{
	struct binding *b;
	u64 on = req->handler_on_ns;

	u64 left;

	*before = 0;
	*after = 0;
	if (!on || !unit_moves(&req->first_unit))
		return 0;
	b = bpf_map_lookup_elem(&UNIT_BINDING, &req->first_unit);
	if (b && b->req_id == id && b->source == SRC_RUNTIME && b->ran)
		left = b->off_ns;
	else if (req->handler_left_ns)
		/* It moved on to another request. */
		left = req->handler_left_ns;
	else
		return 0;
	*before = on > req->start_ns ? on - req->start_ns : 0;
	if (left && left >= on && left < end_ns)
		*after = end_ns - left;
	return REQ_F_HANDLER_TIMED;
}

/*
 * The request is over: report it if slow, forget it. `answered`: its
 * response is complete, and it counts in its service's latencies. Otherwise
 * it was given up while in flight (an HTTP/2 stream that was reset): it is
 * reported all the same, since the calls a client gives up on are often
 * the slowest, and counted apart.
 */
/*
 * Not inlined, and not static: the verifier checks a global function once,
 * on its own, and at each call only its arguments. Inlined into every exit
 * of a socket call, in the loops that end several requests at once, this was
 * walked again on each path that got there, and req_exit_readv took 927,271
 * of the 1,000,000 instructions the verifier allows a program: four more
 * counters here, and nothing loaded.
 *
 *
 * It is handed the request's id and reads how the request ended from its
 * state (req_end() writes that first): arguments to carry, on the stack or
 * in registers that then spill to it, add to a chain of frames that has 512
 * bytes in all, and with them it had 544.
 */
__noinline int req_end_of(u64 id)
{
	struct req_state *req;
	struct request_event *event;
	u64 end_ns, latency, unread, before, after;
	u8 timed;
	bool answered;

	req = bpf_map_lookup_elem(&REQ_TABLE, &id);
	if (!req)
		return 0;
	end_ns = req->end_ns;
	answered = req->end_answered;
	latency = end_ns > req->start_ns ? end_ns - req->start_ns : 0;
	timed = handler_times(id, req, end_ns, &before, &after);
	if (answered)
		hist_add(&REQ_GROUP_HIST, req->cgroup_id, runq_bucket(latency),
			 REQ_GROUP_INSERT_FAILED);
	/*
	 * Slow requests are reported; HTTP/2 requests all are. What an HTTP/2
	 * request was is only known in user space, which sums them up by that.
	 * `blame slow` sets req_slow_ns to 0: it sums up HTTP/1 requests by
	 * route too, and lists the slow ones itself.
	 */
	if (latency >= req_slow_ns || (req->flags & REQ_F_HTTP2)) {
		event = bpf_ringbuf_reserve(&EVENTS, sizeof(*event), 0);
		if (!event) {
			bump(RINGBUF_FULL);
		} else {
			event->hdr.version = EVENT_VERSION;
			event->hdr.kind = EVENT_REQUEST;
			event->hdr.cpu = bpf_get_smp_processor_id();
			event->hdr._pad = 0;
			event->hdr.ts_boot_ns = req->start_ns;
			event->hdr.cgroup_id = req->cgroup_id;
			event->hdr.netns_id = 0;
			event->hdr.ifindex = 0;
			event->hdr.pid = req->tgid;
			event->hdr.tid = req->first_tid;
			event->req_id = id;
			event->end_boot_ns = end_ns;
			event->ready_boot_ns = req->ready_ns;
			event->first_unit = req->first_unit;
			event->last_unit = req->end_unit;
			/*
			 * A handler the runtime pointed out can be on its thread
			 * still when another unit writes the last of its response:
			 * what it is doing there since that thread last said so is
			 * the request's up to here.
			 */
			if (unit_moves(&req->first_unit)) {
				struct binding *hb = bpf_map_lookup_elem(&UNIT_BINDING, &req->first_unit);

				if (hb && hb->req_id == id && hb->source == SRC_RUNTIME && !hb->off_ns &&
				    hb->since && end_ns > hb->since) {
					u64 open = end_ns - hb->since;

					if (hb->doing == BIND_RUNNING)
						req->acc.ns[SEG_CPU] += open;
					else if (hb->doing == BIND_WAITING)
						req->acc.ns[SEG_RUNQ] += open;
					else if (hb->doing == BIND_ASLEEP)
						req->acc.ns[SEG_BLK_OTHER] += open;
				}
			}
			event->cpu_ns = req->acc.ns[SEG_CPU];
			event->runq_ns = req->acc.ns[SEG_RUNQ];
			event->blocked_down_ns = req->acc.ns[SEG_BLK_DOWN];
			event->blocked_client_ns = req->acc.ns[SEG_BLK_CLIENT];
			event->blocked_io_ns = req->acc.ns[SEG_BLK_IO];
			event->blocked_mem_ns = req->acc.ns[SEG_BLK_MEM];
			event->blocked_other_ns = req->acc.ns[SEG_BLK_OTHER];
			event->blocked_fsvc_ns = req->acc.ns[SEG_BLK_FSVC] + req->acc.ns[SEG_BLK_FSVC_LOCK];
			event->blocked_fsvc_lock_ns = req->acc.ns[SEG_BLK_FSVC_LOCK];
			event->observed_ns = req->observed_ns;
			event->retro_ns = req->retro_ns;
			event->down_wait_ns = req->down_wait_ns;
			event->down_service_ns = req->down_service_ns;
			event->down_transfer_ns = req->down_transfer_ns;
			event->down_calls = (u32)req->down_calls;
			event->last_tid = req->end_tid;
			event->stream_id = req->stream_id;
			event->_pad2 = 0;
			event->lport = req->lport;
			event->rport = req->rport;
			event->status = req->end_status;
			event->flags = req->flags | req->end_flags | timed;
			event->line_len = req->line_len;
			__builtin_memcpy(event->line, req->line, REQ_LINE_LEN);
			event->conn = req->conn;
			event->helper_cpu_ns = req->helper.ns[SEG_CPU];
			event->helper_runq_ns = req->helper.ns[SEG_RUNQ];
			event->helper_down_ns = req->helper.ns[SEG_BLK_DOWN];
			event->helper_client_ns = req->helper.ns[SEG_BLK_CLIENT];
			event->helper_io_ns = req->helper.ns[SEG_BLK_IO];
			event->helper_mem_ns = req->helper.ns[SEG_BLK_MEM];
			event->helper_other_ns = req->helper.ns[SEG_BLK_OTHER];
			event->helper_fsvc_ns = req->helper.ns[SEG_BLK_FSVC] + req->helper.ns[SEG_BLK_FSVC_LOCK];
			event->helper_fsvc_lock_ns = req->helper.ns[SEG_BLK_FSVC_LOCK];
			for (int i = 0; i < PARK_TASK; i++)
				event->parked_ns[i] = req->park[i];
			event->parked_task_ns = req->park[PARK_TASK];
			event->parked_blocking_ns = req->park[PARK_BLOCKING];
			event->helpers = (u32)req->helpers;
			event->_pad3 = 0;
			event->before_handler_ns = before;
			event->after_handler_ns = after;
			__builtin_memcpy(event->trace, req->trace, 16);
			/*
			 * A wakeup per request costs more than everything else here, so
			 * the agent polls. It is woken early only when the buffer is
			 * filling up: by the record that takes the unread bytes past a
			 * multiple of REQ_WAKE_BYTES, not by every one after it.
			 */
			unread = bpf_ringbuf_query(&EVENTS, BPF_RB_AVAIL_DATA);
			bpf_ringbuf_submit(event, unread / REQ_WAKE_BYTES !=
							  (unread - REQ_EVENT_BYTES) / REQ_WAKE_BYTES ?
							  BPF_RB_FORCE_WAKEUP :
							  BPF_RB_NO_WAKEUP);
			bump(EVENTS_PRODUCED);
		}
	}
	bpf_map_delete_elem(&REQ_TABLE, &id);
	bump(answered ? REQ_FINISHED : REQ_RESET);
	return 0;
}

static __always_inline void req_end(u64 id, u64 end_ns, u16 status, u8 flags,
				    const struct unit_key *last_unit, u32 last_tid, bool answered)
{
	struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &id);

	if (!req)
		return;
	req->end_ns = end_ns;
	req->end_status = status;
	req->end_flags = flags;
	req->end_tid = last_tid;
	req->end_answered = answered;
	if (last_unit)
		req->end_unit = *last_unit;
	else
		__builtin_memset(&req->end_unit, 0, sizeof(req->end_unit));
	req_end_of(id);
}

static __always_inline void req_finish(u64 id, u64 end_ns, u16 status, u8 flags,
				       const struct unit_key *last_unit, u32 last_tid)
{
	req_end(id, end_ns, status, flags, last_unit, last_tid, true);
}

/* Give up on every request still awaiting a response. */
static __always_inline void conn_abort_pending(struct conn *c)
{
	for (int i = 0; i < REQ_QUEUE; i++) {
		if (c->popped == c->pushed)
			break;
		req_abort(c->queue[c->popped & (REQ_QUEUE - 1)]);
		c->popped++;
	}
	c->skip = 0;
}

/*
 * The parser lost track of the connection: which response answers which
 * request is no longer known. Pending requests are given up, and both sides
 * wait for a message start; requests are taken up again only once a whole
 * response has been seen, so a response still owed to a lost request cannot
 * be paired with a new one (bar pipelining across the loss).
 */
static __always_inline void conn_lose(struct conn *c)
{
	conn_abort_pending(c);
	c->rx.st = HS_UNSYNC;
	c->tx.st = HS_UNSYNC;
}

#endif
