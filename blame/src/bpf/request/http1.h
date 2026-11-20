/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * What a call's bytes mean for HTTP/1.1: client reads and writes become
 * requests (the parser is proto/http1.h), downstream writes and reads
 * become calls.
 */
#ifndef BLAME_REQUEST_HTTP1_H
#define BLAME_REQUEST_HTTP1_H

/* Run one direction's parser over the call. NULL if there is no scratch. */
static __always_inline struct http_run *http_parse(struct conn *c, struct call_data *d, bool resp)
{
	u32 zero = 0;
	struct http_run *x = bpf_map_lookup_elem(&REQ_SCRATCH_HTTP, &zero);

	if (!x)
		return NULL;
	x->h = resp ? c->tx : c->rx;
	x->is_resp = resp;
	x->nstart = 0;
	x->head_new = 0;
	x->nlines = 0;
	x->trace_mask = 0;
	x->trace_prev_ok = 0;
	x->ndone = 0;
	x->desync = 0;
	x->upgraded = 0;
	x->si = 0;
	x->so = 0;
	x->buf_si = ~0u;
	x->buf_len = 0;
	x->nseg = d->nseg > HTTP_SEGS ? HTTP_SEGS : d->nseg;
	for (int i = 0; i < HTTP_SEGS; i++) {
		x->seg_base[i] = d->base[i];
		x->seg_len[i] = d->len[i];
	}
	/* Which of the responses still to finish answer a HEAD. */
	x->head_mask = (c->head_mask >> (c->popped & (REQ_QUEUE - 1))) |
		       (c->head_mask << (REQ_QUEUE - (c->popped & (REQ_QUEUE - 1))));
	/* Only the queued ones are known; skipped requests are never a HEAD. */
	{
		u32 queued = c->pushed - c->popped;

		x->head_mask &= queued >= REQ_QUEUE ? (1u << REQ_QUEUE) - 1 : (1u << queued) - 1;
	}
	if (!resp && x->h.st == HS_LINE)
		__builtin_memcpy(x->cur_line, c->rx_line, REQ_LINE_LEN);

	/*
	 * Requests are looked for again only once the response side is between
	 * messages: until then, a response may still be owed to one not seen.
	 */
	if (x->h.st == HS_UNSYNC && (resp || c->tx.st == HS_START) && d->nseg && d->len[0] >= 4 &&
	    d->base[0]) {
		u32 word = 0;

		bpf_probe_read_user(&word, sizeof(word), (void *)d->base[0]);
		if (resp ? word == FOURCC('H', 'T', 'T', 'P') : http_method(word)) {
			http_reset(&x->h);
			bump(REQ_PARSE_RESYNC);
		}
	}
	bpf_loop(HTTP_STEPS, http_step, &x, 0);
	/* The last step may have used up a segment without moving past it. */
	for (int i = 0; i < HTTP_SEGS; i++) {
		if (x->si >= x->nseg || x->si >= HTTP_SEGS ||
		    x->so < x->seg_len[x->si & (HTTP_SEGS - 1)])
			break;
		x->si++;
		x->so = 0;
	}
	/* Out of steps with data left: the rest of the call was not looked at. */
	if (x->si < x->nseg && x->h.st != HS_UNSYNC)
		http_lost(x);
	if (x->desync)
		bump(REQ_PARSE_DESYNC);

	if (resp) {
		c->tx = x->h;
	} else {
		c->rx = x->h;
		if (x->h.st == HS_LINE)
			__builtin_memcpy(c->rx_line, x->cur_line, REQ_LINE_LEN);
	}
	return x;
}

static __always_inline void on_client_read(struct conn *c, u64 sk, struct carrier *cr,
					   struct call_data *d, u64 now)
{
	/* A request line begun by an earlier call belongs to the last request started. */
	u32 carried = c->rx.st == HS_LINE && c->rx.lpos >= 4;
	bool carried_queued = !c->skip;
	u32 pushed_before = c->pushed;
	u64 ready = c->ready_ns;
	struct http_run *x;

	c->ready_ns = 0;
	x = http_parse(c, d, false);
	if (!x)
		return;
	if (x->nstart)
		c->proto = PROTO_HTTP1;

	if (x->desync || x->nstart > HTTP_BATCH) {
		/* A request start may have gone unseen, or more came than are acted on. */
		if (!x->desync)
			bump(REQ_PARSE_DESYNC);
		conn_lose(c);
		return;
	}
	for (int i = 0; i < HTTP_BATCH; i++) {
		u64 id;

		if (i >= x->nstart)
			break;
		/* Once one request is left out, so are those behind it, to keep the order. */
		if (c->skip || c->pushed - c->popped >= REQ_QUEUE) {
			bump(REQ_QUEUE_FULL);
			id = 0;
		} else {
			id = req_start(c, cr, now, ready);
		}
		if (!id) {
			/* A skipped HEAD: where its response ends is not known. */
			if ((x->head_new >> (i & (HTTP_BATCH - 1))) & 1) {
				bump(REQ_PARSE_DESYNC);
				conn_lose(c);
				return;
			}
			/* The writer side counts these down, possibly on another CPU. */
			__sync_fetch_and_add(&c->skip, 1);
			continue;
		}
		c->queue[c->pushed & (REQ_QUEUE - 1)] = id;
		if ((x->head_new >> (i & (HTTP_BATCH - 1))) & 1)
			c->head_mask |= 1u << (c->pushed & (REQ_QUEUE - 1));
		else
			c->head_mask &= ~(1u << (c->pushed & (REQ_QUEUE - 1)));
		c->pushed++;
	}

	/* Lines complete in the order the requests started; queued ones come first. */
	for (int i = 0; i < REQ_QUEUE; i++) {
		struct req_state *req;
		u32 seq;
		u64 id;

		if (i >= x->nlines)
			break;
		if (i < carried) {
			if (!carried_queued)
				continue;
			seq = pushed_before - 1;
		} else {
			seq = pushed_before + (i - carried);
		}
		/* Not queued, or answered already. */
		if (seq - c->popped >= c->pushed - c->popped)
			continue;
		id = c->queue[seq & (REQ_QUEUE - 1)];
		req = bpf_map_lookup_elem(&REQ_TABLE, &id);
		if (!req)
			continue;
		__builtin_memcpy(req->line, x->lines[i & (REQ_QUEUE - 1)], REQ_LINE_LEN);
		req->line_len = x->line_len[i & (REQ_QUEUE - 1)];
		if (x->line_trunc[i & (REQ_QUEUE - 1)])
			req->flags |= REQ_F_LINE_TRUNCATED;
		if ((x->trace_mask >> i) & 1) {
			__builtin_memcpy(req->trace, x->traces[i & (REQ_QUEUE - 1)], 16);
			req->flags |= REQ_F_TRACE;
		}
	}
	/*
	 * A trace id in headers that came after the request's line, in a later
	 * call: the request is the last one started then, if it was queued and
	 * not answered.
	 */
	if (x->trace_prev_ok && carried_queued && pushed_before != c->popped &&
	    pushed_before - 1 - c->popped < c->pushed - c->popped) {
		u64 id = c->queue[(pushed_before - 1) & (REQ_QUEUE - 1)];
		struct req_state *req = bpf_map_lookup_elem(&REQ_TABLE, &id);

		if (req) {
			__builtin_memcpy(req->trace, x->trace_prev, 16);
			req->flags |= REQ_F_TRACE;
		}
	}

	/*
	 * Reading a request, or more of one, is working for it: for the oldest
	 * request on this connection that has no response yet. That is the one
	 * just read, unless requests were pipelined.
	 */
	if (c->popped != c->pushed) {
		u64 head = c->queue[c->popped & (REQ_QUEUE - 1)];

		if (cr->req_id != head)
			bind_observed(cr, head, sk);
	}
}

static __always_inline void on_client_write(struct conn *c, struct carrier *cr,
					    struct call_data *d, u64 now)
{
	u32 tid = (u32)cur_pid_tgid();
	struct http_run *x;

	c->last_tx_ns = now;
	if (c->popped != c->pushed) {
		u64 head = c->queue[c->popped & (REQ_QUEUE - 1)];

		/* Writing another request's response: no longer working for its own. */
		if (cr->req_id && cr->req_id != head)
			unbind(cr);
		/* Not bound: what it did since its last response was for this one. */
		if (!cr->req_id)
			req_add(head, &cr->pend, SRC_RETRO);
	}

	x = http_parse(c, d, true);
	if (!x)
		return;
	if (x->desync || x->ndone > HTTP_BATCH) {
		/* Which response belongs to which request is no longer known. */
		if (!x->desync)
			bump(REQ_PARSE_DESYNC);
		conn_lose(c);
		return;
	}
	for (int i = 0; i < HTTP_BATCH; i++) {
		u64 id;

		if (i >= x->ndone)
			break;
		if (c->popped == c->pushed) {
			if (c->skip)
				__sync_fetch_and_sub(&c->skip, 1);
			else
				bump(REQ_RESPONSE_UNMATCHED);
			continue;
		}
		id = c->queue[c->popped & (REQ_QUEUE - 1)];
		if (cr->req_id == id)
			unbind(cr);
		req_finish(id, now, i < REQ_QUEUE ? x->status[i & (REQ_QUEUE - 1)] : 0, 0, &cr->unit,
			   tid);
		c->popped++;
	}
	if (x->upgraded) {
		/* Anything pipelined behind the upgrade is not HTTP after all. */
		bump(REQ_UPGRADED);
		conn_abort_pending(c);
		c->rx.st = HS_OPAQUE;
		c->tx.st = HS_OPAQUE;
	}
}

/*
 * A write on a downstream socket, entered at `start`. It opens a call unless
 * the answer to the one before is still outstanding: nothing of it read yet,
 * or bytes of it unread. Then it is more of the same call (a request sent in
 * pieces, or several pipelined), which is only timed if one request made all
 * of it.
 */
static __always_inline void on_down_write(struct sock *sk, struct conn *c, struct carrier *cr,
					  u64 start)
{
	if (c->sent_ns) {
		struct tcp_sock *tp = (struct tcp_sock *)sk;
		u32 unread = BPF_CORE_READ(tp, rcv_nxt) - BPF_CORE_READ(tp, copied_seq);

		if (!c->read_ns || unread) {
			if (c->owner_req != cr->req_id && !c->mixed) {
				c->mixed = 1;
				bump(REQ_DOWN_MIXED);
			}
			return;
		}
	}
	c->owner_req = cr->req_id;
	c->sent_ns = start;
	c->answer_ns = 0;
	c->arrived_ns = 0;
	c->read_ns = 0;
	c->read_arrived_ns = 0;
	c->mixed = 0;
}

/*
 * A read on a downstream socket. The call it belongs to may not be over, so
 * its request is charged as far as this read: the next one adds the rest.
 */
static __always_inline void on_down_read(struct conn *c, struct carrier *cr, u64 now)
{
	struct req_state *req;
	u64 arrived;

	/*
	 * Reading another request's answer: no longer working for its own. Not
	 * a unit whose runtime says exactly what a thread runs: it is the same
	 * task or goroutine whatever it reads, and one connection carries the
	 * calls of many requests.
	 */
	if (cr->req_id && c->owner_req && c->owner_req != cr->req_id &&
	    !(unit_moves(&cr->unit) && switches_exact(cr)))
		unbind(cr);
	if (!c->sent_ns || now <= c->sent_ns)
		return;
	/*
	 * A call no request was known to make (its thread was serving one begun
	 * before the agent attached, or none): not timed, but its answer is being
	 * read, so the next write opens a call of its own. Left open, every later
	 * write would count as more of it, and the connection's calls would
	 * belong to no request for good.
	 */
	if (!c->owner_req) {
		c->read_ns = now;
		return;
	}
	if (c->mixed)
		return;
	req = bpf_map_lookup_elem(&REQ_TABLE, &c->owner_req);
	if (!req)
		return;
	/* What was read had arrived; an arrival not seen counts as this moment. */
	arrived = c->arrived_ns > c->sent_ns && c->arrived_ns < now ? c->arrived_ns : now;
	if (!c->read_ns) {
		u64 answer = c->answer_ns > c->sent_ns && c->answer_ns < arrived ? c->answer_ns :
										    arrived;

		__sync_fetch_and_add(&req->down_calls, 1);
		__sync_fetch_and_add(&req->down_wait_ns, now - c->sent_ns);
		__sync_fetch_and_add(&req->down_service_ns, answer - c->sent_ns);
		__sync_fetch_and_add(&req->down_transfer_ns, arrived - answer);
	} else {
		if (now > c->read_ns)
			__sync_fetch_and_add(&req->down_wait_ns, now - c->read_ns);
		if (arrived > c->read_arrived_ns)
			__sync_fetch_and_add(&req->down_transfer_ns, arrived - c->read_arrived_ns);
		else
			arrived = c->read_arrived_ns;
	}
	c->read_ns = now;
	c->read_arrived_ns = arrived;
}

#endif
