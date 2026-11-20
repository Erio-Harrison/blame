/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Where HTTP/2 streams start and end, from frame headers alone.
 *
 * One state per direction of a connection, fed the bytes of each read or
 * write call as it returns. Only the 9-byte frame headers are looked at;
 * payloads are passed over by length, so a call costs one step per frame
 * however large the frames are. That is enough to say when a stream opens (a
 * client HEADERS frame on a new odd stream), when the server ends it
 * (the last byte of its HEADERS or DATA frame with END_STREAM) and when
 * either side resets it.
 * What the request is (method, path, status) is in the compressed header
 * blocks. Those are not read here either, only passed on: decoding them
 * needs the compression state of the whole connection, which user space
 * keeps (h2_headers_event).
 *
 * The rules, checked offline against captures of gRPC and plain HTTP/2
 * traffic before this was written:
 * - END_STREAM on a HEADERS frame without END_HEADERS takes effect at the
 *   last CONTINUATION frame, and nothing may come between those;
 * - PRIORITY, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, PUSH_PROMISE and unknown
 *   frame types are passed over.
 *
 * A direction is in step from the start of the connection: the client's
 * preface, or the server's first frame. On a connection that was already
 * open it gets in step at a call whose bytes are a chain of plausible frame
 * headers ending exactly where the call ends.
 */
#ifndef BLAME_HTTP2_H
#define BLAME_HTTP2_H

/* Frames and vector segments looked at per call; more than that loses the connection. */
#define H2_STEPS 4096
/*
 * Stream events gathered before they are acted on. A call with more is taken
 * in rounds: parse until this many are gathered, act on them, go on from
 * where the parsing stopped.
 */
#define H2_BATCH 128
/* Rounds per call: enough for an event at every step. */
#define H2_ROUNDS (H2_STEPS / H2_BATCH)
/* Frames a call must chain through to get an unknown connection in step. */
#define H2_CHAIN 16
/* The largest frame a peer may send without negotiating a larger one. */
#define H2_FRAME_MAX 16384

enum { H2_DATA = 0, H2_HEADERS = 1, H2_RST_STREAM = 3, H2_SETTINGS = 4, H2_PING = 6,
       H2_GOAWAY = 7, H2_WINDOW_UPDATE = 8, H2_CONTINUATION = 9 };
#define H2_END_STREAM 1
#define H2_END_HEADERS 4
/* The agent is woken once for every this many unread bytes in the ring buffer. */
#define H2_WAKE_BYTES (64 * 1024)

/* What happened to a stream in one call. */
enum { H2_EV_OPEN = 1, H2_EV_END, H2_EV_RST };

struct h2_event {
	u32 sid;
	u32 kind;
};

/* One direction of a connection, kept between calls. */
struct h2_dir {
	/* In step with the frames. */
	u8 synced;
	/* Bytes of the current frame header gathered so far. */
	u8 hlen;
	/* The HEADERS frame being continued carried END_STREAM. */
	u8 cont_end;
	u8 hdr[9];
	/* Bytes still to pass before the next frame header. */
	u32 skip;
	/* The stream whose header block is being continued; 0 = none. */
	u32 cont_sid;
	/* The payload being passed is a header block's: it goes to user space. */
	u8 hb;
	u8 _pad[3];
	/* Parts of header blocks seen in this direction so far. */
	u32 hseq;
	/* The frame being passed ends this stream, once all of it has gone by; 0 = none. */
	u32 end_sid;
};

/* One call's worth of parsing; lives in a per-CPU scratch slot. */
struct h2_run {
	struct h2_dir h;
	/* The call's data: `iov` 0 means one buffer, already in seg_base/seg_len. */
	u64 iov;
	u64 iovcnt;
	u64 seg_base;
	u64 seg_len;
	u64 so;
	/* Bytes of the call not passed yet. */
	u64 left;
	u32 si;
	/* The highest stream the client has opened (in and out). */
	u32 max_sid;
	u32 nev;
	/* Steps of the call's allowance used so far. */
	u32 steps;
	u8 is_tx;
	u8 lost;
	/* The connection was followed from its first byte. */
	u8 fresh;
	/* The call opened a stream. */
	u8 opened;
	u8 _pad[4];
	/* The connection, for the header events. */
	u64 sk;
	u64 cgroup_id;
	u32 tgid;
	u32 tid;
	struct h2_event ev[H2_BATCH];
	/* A header event being put together. */
	struct h2_headers_event hev;
};

/*
 * Send the next `n` bytes of the header block being passed to user space.
 * The part is counted whether or not it gets there.
 */
static __always_inline void h2_export(struct h2_run *x, u64 n)
{
	struct h2_dir *h = &x->h;
	struct h2_headers_event *e = &x->hev;
	u32 frame_len = (u32)h->hdr[0] << 16 | (u32)h->hdr[1] << 8 | h->hdr[2];
	u32 len = n;
	u64 unread;

	e->seq = h->hseq++;
	if (len > H2_HDR_CHUNK)
		len = H2_HDR_CHUNK;
	if (!x->seg_base || bpf_probe_read_user(e->data, len, (void *)(x->seg_base + x->so))) {
		bump(FIELD_READ_FAILED);
		return;
	}
	e->hdr.version = EVENT_VERSION;
	e->hdr.kind = EVENT_H2_HEADERS;
	e->hdr.cpu = 0;
	e->hdr._pad = 0;
	e->hdr.ts_boot_ns = 0;
	e->hdr.cgroup_id = x->cgroup_id;
	e->hdr.netns_id = 0;
	e->hdr.ifindex = 0;
	e->hdr.pid = x->tgid;
	e->hdr.tid = x->tid;
	e->conn = x->sk;
	e->sid = ((u32)h->hdr[5] << 24 | (u32)h->hdr[6] << 16 | (u32)h->hdr[7] << 8 | h->hdr[8]) &
		 0x7fffffff;
	e->tx = x->is_tx;
	e->frame_type = h->hdr[3];
	e->frame_flags = h->hdr[4];
	e->bits = (h->skip == frame_len ? H2H_FRAME_START : 0) | (x->fresh ? H2H_FROM_START : 0);
	e->len = len;
	e->left = h->skip - len > 0xffff ? 0xffff : h->skip - len;
	/* Woken like for requests: only when the buffer is filling up. */
	unread = bpf_ringbuf_query(&EVENTS, BPF_RB_AVAIL_DATA);
	if (bpf_ringbuf_output(&EVENTS, e, __builtin_offsetof(struct h2_headers_event, data) + len,
			       unread / H2_WAKE_BYTES != (unread + sizeof(*e)) / H2_WAKE_BYTES ?
				       BPF_RB_FORCE_WAKEUP :
				       BPF_RB_NO_WAKEUP))
		bump(RINGBUF_FULL);
}

static __always_inline void h2_emit(struct h2_run *x, u32 kind, u32 sid)
{
	if (x->nev < H2_BATCH) {
		x->ev[x->nev & (H2_BATCH - 1)].sid = sid;
		x->ev[x->nev & (H2_BATCH - 1)].kind = kind;
	}
	x->nev++;
}

/*
 * The server's END_STREAM ends the request; the client's only ends its half.
 * The request is over when the last byte of the frame that says so has been
 * written, not when its header has: a frame can be cut across two writes,
 * and what it carries (the trailers, with the status) belongs to the
 * request.
 */
static __always_inline void h2_stream_end(struct h2_run *x, u32 sid)
{
	if (x->is_tx)
		x->h.end_sid = sid;
}

/* The frame that was being passed has gone by. */
static __always_inline void h2_frame_done(struct h2_run *x)
{
	if (x->h.end_sid) {
		h2_emit(x, H2_EV_END, x->h.end_sid);
		x->h.end_sid = 0;
	}
}

static __always_inline void h2_frame(struct h2_run *x, u8 type, u8 flags, u32 sid)
{
	struct h2_dir *h = &x->h;

	if (h->cont_sid) {
		if (type != H2_CONTINUATION || sid != h->cont_sid) {
			x->lost = 1;
			return;
		}
		if (flags & H2_END_HEADERS) {
			if (h->cont_end)
				h2_stream_end(x, sid);
			h->cont_sid = 0;
		}
		return;
	}
	switch (type) {
	case H2_HEADERS:
		/* Client streams are odd and only ever go up. */
		if (!x->is_tx && (sid & 1) && sid > x->max_sid) {
			x->max_sid = sid;
			x->opened = 1;
			h2_emit(x, H2_EV_OPEN, sid);
		}
		if (!(flags & H2_END_HEADERS)) {
			h->cont_sid = sid;
			h->cont_end = flags & H2_END_STREAM;
		} else if (flags & H2_END_STREAM) {
			h2_stream_end(x, sid);
		}
		break;
	case H2_DATA:
		if (flags & H2_END_STREAM)
			h2_stream_end(x, sid);
		break;
	case H2_RST_STREAM:
		h2_emit(x, H2_EV_RST, sid);
		break;
	case H2_CONTINUATION:
		/* With no header block open. */
		x->lost = 1;
		break;
	}
}

/*
 * bpf_loop callback: returns 1 when the call's data is used up or lost, or
 * when the events gathered have to be acted on first (a frame gives at most
 * one).
 */
static long h2_step(u32 i, void *ctx)
{
	struct h2_run *x = *(struct h2_run **)ctx;
	struct h2_dir *h;
	u8 part[16];
	u64 avail;
	u32 k;

	if (!x || !x->left || x->lost || x->nev >= H2_BATCH)
		return 1;
	h = &x->h;
	if (x->so >= x->seg_len) {
		struct iovec v;

		/* The next segment of a vectored call. */
		if (!x->iov || x->si >= x->iovcnt ||
		    bpf_probe_read_user(&v, sizeof(v), (void *)(x->iov + x->si * sizeof(v)))) {
			/* Bytes that cannot be seen: fine inside a payload. */
			if (h->skip >= x->left && !h->hlen) {
				/* A header block that cannot be seen is a part lost. */
				if (h->hb)
					h->hseq++;
				h->skip -= x->left;
				x->left = 0;
				if (!h->skip)
					h2_frame_done(x);
			} else {
				x->lost = 1;
			}
			return 1;
		}
		x->si++;
		x->seg_base = (u64)v.iov_base;
		x->seg_len = v.iov_len;
		x->so = 0;
		return 0;
	}
	avail = x->seg_len - x->so;
	if (avail > x->left)
		avail = x->left;
	if (h->skip) {
		u64 pass = h->skip < avail ? h->skip : avail;

		if (h->hb) {
			if (pass > H2_HDR_CHUNK)
				pass = H2_HDR_CHUNK;
			h2_export(x, pass);
		}
		h->skip -= pass;
		x->so += pass;
		x->left -= pass;
		if (!h->skip)
			h2_frame_done(x);
		return 0;
	}
	if (h->hlen >= 9) {
		x->lost = 1;
		return 1;
	}
	k = 9 - h->hlen;
	if (k > avail)
		k = avail;
	if (!x->seg_base || bpf_probe_read_user(part, k & 15, (void *)(x->seg_base + x->so))) {
		x->lost = 1;
		return 1;
	}
	for (int j = 0; j < 9; j++) {
		if (j < k && h->hlen + j < 9)
			h->hdr[(h->hlen + j) & 15] = part[j];
	}
	h->hlen += k;
	x->so += k;
	x->left -= k;
	if (h->hlen < 9)
		return 0;
	h->hlen = 0;
	h->skip = (u32)h->hdr[0] << 16 | (u32)h->hdr[1] << 8 | h->hdr[2];
	h->hb = h->hdr[3] == H2_HEADERS || h->hdr[3] == H2_CONTINUATION;
	h2_frame(x, h->hdr[3], h->hdr[4],
		 ((u32)h->hdr[5] << 24 | (u32)h->hdr[6] << 16 | (u32)h->hdr[7] << 8 | h->hdr[8]) &
			 0x7fffffff);
	/* A frame with no payload is over with its header. */
	if (!h->skip)
		h2_frame_done(x);
	return 0;
}

/* Whether a frame header could be one, going by what never varies. */
static __always_inline bool h2_plausible(const u8 *hdr, u32 *len)
{
	u32 sid = (u32)hdr[5] << 24 | (u32)hdr[6] << 16 | (u32)hdr[7] << 8 | hdr[8];
	u8 type = hdr[3];

	*len = (u32)hdr[0] << 16 | (u32)hdr[1] << 8 | hdr[2];
	if (type > H2_CONTINUATION || *len > H2_FRAME_MAX || (sid & 0x80000000))
		return false;
	/* Connection-level frames are on stream 0, stream frames are not. */
	if (type == H2_SETTINGS || type == H2_PING || type == H2_GOAWAY)
		return sid == 0;
	if (type == H2_WINDOW_UPDATE)
		return true;
	return sid != 0;
}

/*
 * Whether `len` bytes at `base` are frames from the first byte to the last:
 * how a direction of a connection that was already open gets in step.
 */
static __always_inline bool h2_chain(u64 base, u64 len)
{
	u64 off = 0;

	for (int i = 0; i < H2_CHAIN; i++) {
		u8 hdr[9];
		u32 payload;

		if (off + 9 > len || bpf_probe_read_user(hdr, sizeof(hdr), (void *)(base + off)))
			return false;
		if (!h2_plausible(hdr, &payload))
			return false;
		off += 9 + payload;
		if (off == len)
			return true;
	}
	return false;
}

#endif
