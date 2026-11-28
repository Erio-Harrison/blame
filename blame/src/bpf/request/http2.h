/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * What a call's bytes mean for HTTP/2: stream events (the frame parser is
 * proto/http2.h) become requests.
 */
#ifndef BLAME_REQUEST_HTTP2_H
#define BLAME_REQUEST_HTTP2_H

struct h2_abort_ctx {
	u64 sk;
};

struct bpf_map;

static long h2_abort_stream(struct bpf_map *map, struct stream_key *key, u64 *id, void *data)
{
	struct h2_abort_ctx *ctx = data;
	u64 req = *id;

	/* Only if this took it: a reset on another CPU may be ending it. */
	if (key->sk == ctx->sk && !bpf_map_delete_elem(map, key))
		req_abort(req);
	return 0;
}

/*
 * Give up on every stream still open on a connection. Streams are not kept
 * per connection, so the whole table is walked: only done when the
 * connection has some.
 */
static __always_inline void h2_abort_streams(u64 sk, struct conn *c)
{
	struct h2_abort_ctx ctx = { .sk = sk };

	if (!c->h2_open)
		return;
	bpf_for_each_map_elem(&REQ_STREAMS, h2_abort_stream, &ctx, 0);
	c->h2_open = 0;
}

/*
 * Whether a stream id that names no open stream of a connection could
 * still be one of its streams: one that is over already (reset before its
 * handler got to it), or one opened before the connection was followed.
 * Otherwise the id was not read from where a stream id is.
 */
static __always_inline bool h2_stream_plausible(u64 sk, u32 sid)
{
	struct conn *c = bpf_map_lookup_elem(&REQ_CONNS, &sk);

	return c && (sid & 1) && sid <= c->h2_max_sid;
}

/*
 * Get one direction in step with the frames, if this call shows how: the
 * client's connection preface, or bytes that are frames from first to last.
 */
static __always_inline bool h2_sync(struct h2_dir *dir, bool rx, struct call_data *d)
{
	u64 base = d->base[0], len = d->len[0];
	u32 word = 0;

	if (!d->nseg || !base || len < 4)
		return false;
	bpf_probe_read_user(&word, sizeof(word), (void *)base);
	if (rx && word == FOURCC('P', 'R', 'I', ' ')) {
		__builtin_memset(dir, 0, sizeof(*dir));
		/* "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", then frames. */
		dir->skip = 24;
	} else if (len == d->total && h2_chain(base, len)) {
		__builtin_memset(dir, 0, sizeof(*dir));
	} else {
		return false;
	}
	dir->synced = 1;
	return true;
}

/* What a call's rounds work on. */
struct h2_pass {
	struct conn *c;
	struct carrier *cr;
	struct h2_run *x;
	u64 sk;
	u64 now;
	u64 ready;
	u32 tid;
};

/* Act on the stream events gathered so far, in order. */
static __always_inline void h2_apply(struct h2_pass *p, struct conn *c, struct carrier *cr,
				     struct h2_run *x)
{
	for (int i = 0; i < H2_BATCH; i++) {
		struct stream_key key = { .sk = p->sk };
		u64 id, *found;
		bool reset;

		if (i >= x->nev)
			break;
		key.sid = x->ev[i].sid;
		if (x->ev[i].kind == H2_EV_OPEN) {
			struct req_state *req;

			id = req_start(c, cr, p->now, p->ready);
			req = id ? bpf_map_lookup_elem(&REQ_TABLE, &id) : NULL;
			if (!req)
				continue;
			req->flags |= REQ_F_HTTP2;
			req->stream_id = key.sid;
			req->conn = p->sk;
			if (bpf_map_update_elem(&REQ_STREAMS, &key, &id, BPF_ANY)) {
				bump(REQ_STREAM_INSERT_FAILED);
				req_abort(id);
				continue;
			}
			c->h2_open++;
			continue;
		}
		found = bpf_map_lookup_elem(&REQ_STREAMS, &key);
		if (!found)
			continue;
		id = *found;
		/*
		 * Both sides can reset a stream at once (a client's deadline,
		 * which the server is told too): the reading and the writing
		 * thread then both find it. Only the one whose delete takes ends
		 * the request; once, it was reported twice, the first time with
		 * no name.
		 */
		if (bpf_map_delete_elem(&REQ_STREAMS, &key))
			continue;
		if (c->h2_open)
			c->h2_open--;
		/* Answered, or reset by the side whose bytes these are. */
		reset = x->ev[i].kind != H2_EV_END;
		req_end(id, p->now, 0,
			!reset ? 0 : x->is_tx ? REQ_F_RESET_SERVER : REQ_F_RESET_CLIENT, &cr->unit,
			p->tid, !reset);
	}
	x->nev = 0;
}

/*
 * bpf_loop callback, one round of a call: parse until the call's data is
 * used up or a batch of events is gathered, then act on those. Returns 1
 * when there is nothing more to do.
 */
static long h2_round(u32 i, void *ctx)
{
	struct h2_pass *p = ctx;
	struct conn *c = p->c;
	struct carrier *cr = p->cr;
	struct h2_run *x = p->x;
	long done;

	if (!c || !cr || !x || x->steps >= H2_STEPS)
		return 1;
	done = bpf_loop(H2_STEPS - x->steps, h2_step, &p->x, 0);
	if (done > 0)
		x->steps += done;
	if (x->lost)
		return 1;
	h2_apply(p, c, cr, x);
	return !x->left;
}

/*
 * A call on a client-facing connection that speaks HTTP/2, or may. False if
 * it does not: the call is then HTTP/1's to look at.
 *
 * Streams are requests: one starts at the client's HEADERS frame and ends
 * at the server's END_STREAM. Many are in flight on one connection and the
 * unit that reads their frames serves none of them in particular, so
 * reading binds nobody: which unit works for a stream is for the runtime's
 * own adapter to say.
 *
 * A call can carry any number of stream events (a server refusing a burst
 * of streams resets them all in one write), so it is taken in rounds. What
 * the rounds before a loss did stands: the loss ends every stream of the
 * connection anyway.
 */
static __always_inline bool h2_call(struct conn *c, u64 sk, struct carrier *cr, bool rx,
				    struct call_data *d, u64 now)
{
	struct h2_dir *dir = rx ? &c->h2rx : &c->h2tx;
	struct h2_pass pass = {
		.c = c,
		.cr = cr,
		.sk = sk,
		.now = now,
		.tid = (u32)cur_pid_tgid(),
	};
	bool owner = false;
	u32 zero = 0;
	struct h2_run *x;

	if (!dir->synced) {
		if (!h2_sync(dir, rx, d))
			return c->proto == PROTO_HTTP2;
		c->proto = PROTO_HTTP2;
		owner = rx;
	}
	x = bpf_map_lookup_elem(&REQ_SCRATCH_H2, &zero);
	if (!x)
		return true;
	x->h = *dir;
	x->iov = d->iov;
	x->iovcnt = d->iovcnt;
	x->seg_base = d->iov ? 0 : d->base[0];
	x->seg_len = d->iov ? 0 : d->len[0];
	x->so = 0;
	x->left = d->total;
	/* Given buffers: the first is in seg_base already. */
	x->si = d->iov ? 0 : 1;
	x->nseg = d->iov ? 0 : d->nseg;
#pragma unroll
	for (int i = 0; i < HTTP_SEGS; i++) {
		x->sb[i] = d->base[i];
		x->sl[i] = d->len[i];
	}
	x->max_sid = c->h2_max_sid;
	x->nev = 0;
	x->steps = 0;
	x->is_tx = !rx;
	x->lost = 0;
	x->fresh = c->fresh;
	x->opened = 0;
	x->sk = sk;
	x->cgroup_id = bpf_get_current_cgroup_id();
	x->tgid = c->tgid;
	x->tid = pass.tid;
	pass.x = x;
	pass.ready = c->ready_ns;
	if (rx)
		c->ready_ns = 0;
	bpf_loop(H2_ROUNDS, h2_round, &pass, 0);
	/* Out of steps with data left, or frames that make no sense. */
	if (x->left || x->lost) {
		bump(REQ_H2_LOST);
		h2_abort_streams(sk, c);
		c->h2rx.synced = 0;
		c->h2tx.synced = 0;
		/* Header blocks went by unseen: later ones cannot be decoded. */
		c->fresh = 0;
		return true;
	}
	*dir = x->h;
	c->h2_max_sid = x->max_sid;
	/*
	 * Whoever reads new streams off a connection owns it: the runtime's
	 * adapter finds the connection of a handler through it.
	 */
	if ((owner || x->opened) && unit_moves(&cr->unit)) {
		u64 *known = bpf_map_lookup_elem(&UNIT_READS, &cr->unit);

		if (!known || *known != sk)
			bpf_map_update_elem(&UNIT_READS, &cr->unit, &sk, BPF_ANY);
	}
	return true;
}

#endif
