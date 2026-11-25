/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Rust (the h2 crate, as tonic and hyper use it): the headers of a stream
 * as the process has decoded them, for connections whose header blocks
 * cannot be decoded here (see runtime/go_grpc.h; the event is the same).
 *
 * Two functions that no build profile measured inlines or drops (default,
 * codegen-units=1, thin and fat LTO, opt-level=s, panic=abort; h2 0.3.27,
 * 0.4.7, 0.4.14, 0.4.20): they are called from several places.
 *
 * - server::Peer::convert_poll_message(pseudo, fields: HeaderMap,
 *   stream_id) turns a request's decoded header block into a request, once
 *   per request, in the task that reads the connection (UNIT_READS gives
 *   the connection). It returns a Result too large for registers: the
 *   caller passes where to put it, and the arguments are either in the
 *   first three argument registers (arm64, where that place has a register
 *   of its own, x8) or one further on (x86-64, rdi; and arm64 builds with
 *   fat LTO, where the function is given another calling convention).
 *   Which, is told per call by where a path is: the stream id cannot tell,
 *   the register after it holds the same id most of the time.
 * - Prioritize::queue_frame(self, frame: Frame, buffer, stream: &mut
 *   store::Ptr, task) queues every frame of a stream to be sent: headers,
 *   data, trailers; generic, one instance per body type, and never shifted
 *   (it returns nothing). A response's grpc-status is in a headers frame:
 *   its trailers, or its headers when it has no body. It runs in the task
 *   that serves the stream, which the stream's request is bound to
 *   (runtime/tokio_tasks.h): the binding gives the request and its
 *   connection, and the stream id in `stream` has to be that request's.
 *   A task that is not bound (spawned before blame knew where such tasks
 *   keep their stream id: runtime/tasks.rs) gives nothing, as it gives no
 *   time to its request either.
 *
 * Pseudo.path is an Option<BytesStr> (None: the vtable word is 0). A
 * HeaderMap keeps its fields in a Vec of buckets; each bucket holds the
 * name and the value as `Bytes` (vtable, pointer, length, data) at fixed
 * places, 104 bytes apart. Where the Vec is inside the map depends on the
 * compiler (proc_cfg.rs_entries_ptr / rs_entries_len). What is read here is
 * checked again by user space (h2meta.rs) before it is used.
 */
#ifndef BLAME_RUNTIME_RUST_H2_H
#define BLAME_RUNTIME_RUST_H2_H

/* http::header::map::Bucket<HeaderValue>. */
#define RS_BUCKET_SIZE 104
#define RS_BUCKET_KEY 64
#define RS_BUCKET_VALUE 24
/* bytes::Bytes: vtable +0, pointer +8, length +16. */
#define RS_BYTES_PTR 8
#define RS_BYTES_LEN 16
/* store::Ptr: the store, then the key {index, stream id}. */
#define RS_PTR_STREAM_ID 12
/* Header fields looked at per request, from the first. */
#define RS_MAX_FIELDS 24
/* Pseudo.path, a BytesStr: vtable, pointer, length. */
#define RS_PSEUDO_PATH 88
/* Frame<B>: which frame, in its first byte (1: Headers); a Headers frame's header map at 8. */
#define RS_FRAME_HEADERS 1
#define RS_FRAME_MAP 8
/* Bytes of a path looked at to tell where the arguments are. */
#define RS_PATH_PEEK 16

static __always_inline bool is_grpc_status(const char *n)
{
	return n[0] == 'g' && n[1] == 'r' && n[2] == 'p' && n[3] == 'c' && n[4] == '-' && n[5] == 's' &&
	       n[6] == 't' && n[7] == 'a' && n[8] == 't' && n[9] == 'u' && n[10] == 's';
}

/*
 * The fields of `frame`'s header map: the trace id and the status, into `e`.
 * Whatever is there is checked by user space; this reads only as far as the
 * header map and the buckets say.
 */
static __always_inline void rs_scan(u64 map, const struct proc_cfg *cfg, struct h2_fields_event *e)
{
	u64 entries, n;
	int i;

	entries = user_u64(map + cfg->rs_entries_ptr);
	n = user_u64(map + cfg->rs_entries_len);
	if (!entries || n > 4096)
		return;
#pragma unroll
	for (i = 0; i < RS_MAX_FIELDS; i++) {
		u64 bucket = entries + (u64)i * RS_BUCKET_SIZE;
		u64 name, value, value_len;
		char key[H2F_NAME11];

		if (i >= n)
			break;
		if (user_u64(bucket + RS_BUCKET_KEY + RS_BYTES_LEN) != H2F_NAME11)
			continue;
		name = user_u64(bucket + RS_BUCKET_KEY + RS_BYTES_PTR);
		value = user_u64(bucket + RS_BUCKET_VALUE + RS_BYTES_PTR);
		value_len = user_u64(bucket + RS_BUCKET_VALUE + RS_BYTES_LEN);
		if (!name || !value || bpf_probe_read_user(key, sizeof(key), (void *)name))
			continue;
		if (is_traceparent(key)) {
			if (value_len >= 55 && !bpf_probe_read_user(e->trace, sizeof(e->trace), (void *)(value + 3)))
				e->has_trace = 1;
		} else if (is_grpc_status(key)) {
			char digits[2] = {};

			/* One or two decimal digits. */
			if ((value_len == 1 || value_len == 2) &&
			    !bpf_probe_read_user(digits, value_len == 1 ? 1 : 2, (void *)value) &&
			    digits[0] >= '0' && digits[0] <= '9' &&
			    (value_len == 1 || (digits[1] >= '0' && digits[1] <= '9'))) {
				e->status = digits[0] - '0';
				if (value_len == 2)
					e->status = e->status * 10 + (digits[1] - '0');
				e->has_status = 1;
			}
		}
	}
}

/* The request's :path, if `pseudo` has one. */
static __always_inline void rs_path(u64 pseudo, struct h2_fields_event *e)
{
	u64 len;

	if (!user_u64(pseudo + RS_PSEUDO_PATH))
		return;
	len = user_u64(pseudo + RS_PSEUDO_PATH + RS_BYTES_LEN);
	if (len > H2F_PATH_LEN)
		len = H2F_PATH_LEN;
	if (len && !bpf_probe_read_user(e->path, len, (void *)user_u64(pseudo + RS_PSEUDO_PATH + RS_BYTES_PTR)))
		e->path_len = len;
}

/*
 * Whether `pseudo` can be a request's pseudo-headers: a path there that
 * starts with '/', and is printable as far as it is looked at.
 */
static __always_inline bool rs_pseudo_plausible(u64 pseudo)
{
	char peek[RS_PATH_PEEK] = {};
	u64 ptr, len;
	u32 n;
	int i;

	if (pseudo < 4096 || !user_u64(pseudo + RS_PSEUDO_PATH))
		return false;
	ptr = user_u64(pseudo + RS_PSEUDO_PATH + RS_BYTES_PTR);
	len = user_u64(pseudo + RS_PSEUDO_PATH + RS_BYTES_LEN);
	if (!ptr || len < 2 || len > 4096)
		return false;
	n = len < RS_PATH_PEEK ? len : RS_PATH_PEEK;
	if (bpf_probe_read_user(peek, n, (void *)ptr) || peek[0] != '/')
		return false;
#pragma unroll
	for (i = 1; i < RS_PATH_PEEK; i++) {
		if (i < n && (peek[i] < 0x21 || peek[i] > 0x7e))
			return false;
	}
	return true;
}

/* The stream a `store::Ptr` names: its store and its id. */
static __always_inline bool rs_stream(u64 ptr, u64 *store, u32 *sid)
{
	if (!ptr)
		return false;
	*store = user_u64(ptr);
	return *store && !bpf_probe_read_user(sid, sizeof(*sid), (void *)(ptr + RS_PTR_STREAM_ID)) && *sid;
}

SEC("uprobe")
int up_rs_request(struct pt_regs *ctx)
{
	struct h2_fields_event *e;
	struct proc_cfg *cfg;
	struct carrier *cr;
	bool first, next;
	u64 *sk;
	u32 tgid, sid;
	int at;

	tgid = cur_pid_tgid() >> 32;
	cfg = bpf_map_lookup_elem(&REQ_PROCS, &tgid);
	if (!cfg || cfg->runtime != RT_TOKIO || !cfg->rs_entries_ptr)
		return 0;
	cr = carrier_of_current(false);
	if (!cr || cr->unit.kind != UNIT_TOKIO_TASK)
		return 0;
	sk = bpf_map_lookup_elem(&UNIT_READS, &cr->unit);
	if (!sk || !h2_undecoded(*sk))
		return 0;
	/* The arguments from the first register, or from the second. */
	first = rs_pseudo_plausible(c_arg(ctx, 0));
	next = rs_pseudo_plausible(c_arg(ctx, 1));
	if (first == next) {
		bump(H2_PROCESS_UNREAD);
		return 0;
	}
	at = next ? 1 : 0;
	sid = (u32)c_arg(ctx, at + 2);
	/* Client streams are odd. */
	if (!(sid & 1)) {
		bump(H2_PROCESS_UNREAD);
		return 0;
	}
	e = h2_fields_begin(tgid, *sk, sid, H2F_REQUEST);
	if (!e)
		return 0;
	rs_scan(c_arg(ctx, at + 1), cfg, e);
	rs_path(c_arg(ctx, at), e);
	bpf_ringbuf_submit(e, 0);
	bump(EVENTS_PRODUCED);
	return 0;
}

SEC("uprobe")
int up_rs_queue_frame(struct pt_regs *ctx)
{
	struct stream_key skey = {};
	struct h2_fields_event *e;
	struct proc_cfg *cfg;
	struct carrier *cr;
	u64 frame, store, *req_id;
	u32 tgid, sid;
	u8 kind = 0;

	/* Most frames are data: those first, at the cost of one read. */
	frame = c_arg(ctx, 1);
	if (bpf_probe_read_user(&kind, sizeof(kind), (void *)frame) || kind != RS_FRAME_HEADERS)
		return 0;
	tgid = cur_pid_tgid() >> 32;
	cfg = bpf_map_lookup_elem(&REQ_PROCS, &tgid);
	if (!cfg || cfg->runtime != RT_TOKIO || !cfg->rs_entries_ptr)
		return 0;
	cr = carrier_of_current(false);
	if (!cr || cr->unit.kind != UNIT_TOKIO_TASK || !cr->req_id || !h2_undecoded(cr->req_sk))
		return 0;
	if (!rs_stream(c_arg(ctx, 3), &store, &sid))
		return 0;
	e = h2_fields_begin(tgid, cr->req_sk, sid, H2F_RESPONSE);
	if (!e)
		return 0;
	rs_scan(frame + RS_FRAME_MAP, cfg, e);
	/*
	 * Response headers that are not the end of it have no status, nor
	 * have the requests of calls the task makes itself.
	 */
	if (!e->has_status) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	/*
	 * A status: the stream has to be the request's the task serves. One
	 * that is over already (a status written after the client gave up)
	 * is not: nothing is wrong there.
	 */
	skey.sk = cr->req_sk;
	skey.sid = sid;
	req_id = bpf_map_lookup_elem(&REQ_STREAMS, &skey);
	if (!req_id || *req_id != cr->req_id) {
		bpf_ringbuf_discard(e, 0);
		if (req_id)
			bump(H2_PROCESS_UNREAD);
		return 0;
	}
	/* The trace id is the request's. */
	e->has_trace = 0;
	__builtin_memset(e->trace, 0, sizeof(e->trace));
	bpf_ringbuf_submit(e, 0);
	bump(EVENTS_PRODUCED);
	return 0;
}

#endif
