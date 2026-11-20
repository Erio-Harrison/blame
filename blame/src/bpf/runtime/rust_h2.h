/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Rust (the h2 crate, as tonic and hyper use it): the headers of a stream
 * as the process has decoded them, for connections whose header blocks
 * cannot be decoded here (see runtime/go_grpc.h; the event is the same).
 *
 * - Recv::recv_headers(&mut self, frame: Headers, stream: &mut store::Ptr,
 *   counts) is given the request's HEADERS frame. `frame` is passed by
 *   reference and starts with its http::HeaderMap; `stream` points at the
 *   stream's key: the connection's stream store (one per connection) and
 *   the stream id (at +12). It runs in the task that reads the connection,
 *   which is how the connection is known (UNIT_READS), and records which
 *   store belongs to it.
 * - Send::send_headers / send_trailers(&mut self, frame: Headers, buffer,
 *   stream: &mut store::Ptr, ...) is given the response's headers, or its
 *   trailers: grpc-status is in one of them (in the headers when there is no
 *   body). They run in the task that serves the stream, which reads nothing:
 *   the stream's store gives the connection.
 *
 * The request's :path is not in the map but in the frame's pseudo-headers,
 * an Option<BytesStr> (None: the vtable word is 0), at fixed places in the
 * frame (same in every rustc measured, as for the buckets below).
 *
 * A HeaderMap keeps its fields in a Vec of buckets; each bucket holds the
 * name and the value as `Bytes` (vtable, pointer, length, data) at fixed
 * places, 104 bytes apart (the same in every rustc and `http` measured).
 * Where the Vec is inside the map depends on the compiler
 * (proc_cfg.rs_entries_ptr / rs_entries_len).
 *
 * Arguments are in the registers of the C calling convention, as for the
 * tokio probes.
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
/* frame::Headers: header_block.pseudo.path, a BytesStr: vtable, pointer, length. */
#define RS_FRAME_PATH 0xb8

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
static __always_inline void rs_scan(u64 frame, const struct proc_cfg *cfg, struct h2_fields_event *e)
{
	u64 entries, n;
	int i;

	entries = user_u64(frame + cfg->rs_entries_ptr);
	n = user_u64(frame + cfg->rs_entries_len);
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

/* The request's :path, if the frame has one. */
static __always_inline void rs_path(u64 frame, struct h2_fields_event *e)
{
	u64 len;

	if (!user_u64(frame + RS_FRAME_PATH))
		return;
	len = user_u64(frame + RS_FRAME_PATH + RS_BYTES_LEN);
	if (len > H2F_PATH_LEN)
		len = H2F_PATH_LEN;
	if (len && !bpf_probe_read_user(e->path, len, (void *)user_u64(frame + RS_FRAME_PATH + RS_BYTES_PTR)))
		e->path_len = len;
}

/* The stream a `store::Ptr` names: its store and its id. */
static __always_inline bool rs_stream(u64 ptr, u64 *store, u32 *sid)
{
	if (!ptr)
		return false;
	*store = user_u64(ptr);
	return *store && !bpf_probe_read_user(sid, sizeof(*sid), (void *)(ptr + RS_PTR_STREAM_ID)) && *sid;
}

/*
 * The n-th argument of Recv::recv_headers. It returns a Result too large
 * for registers (an error can carry the frame back), so the caller passes
 * where to put it: in a register of its own on arm64 (x8), as the first
 * argument on x86-64 (rdi), which moves the others up one. Seen in the code
 * on x86-64: the stream pointer is read from rcx, not rdx. send_headers and
 * send_trailers return a small Result in registers and are not shifted.
 */
static __always_inline u64 rs_recv_arg(struct pt_regs *ctx, int n)
{
	if (bpf_core_field_exists(ctx->regs))
		return c_arg(ctx, n);
	return c_arg(ctx, n + 1);
}

SEC("uprobe")
int up_rs_recv_headers(struct pt_regs *ctx)
{
	struct transport_key key = {};
	struct h2_fields_event *e;
	struct proc_cfg *cfg;
	struct carrier *cr;
	u64 *sk, store;
	u32 sid;

	key.tgid = cur_pid_tgid() >> 32;
	cfg = bpf_map_lookup_elem(&REQ_PROCS, &key.tgid);
	if (!cfg || cfg->runtime != RT_TOKIO || !cfg->rs_entries_ptr)
		return 0;
	cr = carrier_of_current(false);
	if (!cr || cr->unit.kind != UNIT_TOKIO_TASK)
		return 0;
	sk = bpf_map_lookup_elem(&UNIT_READS, &cr->unit);
	if (!sk || !h2_undecoded(*sk) || !rs_stream(rs_recv_arg(ctx, 2), &store, &sid))
		return 0;
	/* Client streams are odd. */
	if (!(sid & 1))
		return 0;
	/* The responses are written by tasks that read nothing: the store tells whose they are. */
	key.addr = store;
	bpf_map_update_elem(&GO_TRANSPORTS, &key, sk, BPF_ANY);
	e = h2_fields_begin(key.tgid, *sk, sid, H2F_REQUEST);
	if (!e)
		return 0;
	rs_scan(rs_recv_arg(ctx, 1), cfg, e);
	rs_path(rs_recv_arg(ctx, 1), e);
	/* A request's trailers come the same way, with neither: not a request. */
	if (!e->has_trace && !e->path_len) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_ringbuf_submit(e, 0);
	bump(EVENTS_PRODUCED);
	return 0;
}

SEC("uprobe")
int up_rs_send(struct pt_regs *ctx)
{
	struct transport_key key = {};
	struct h2_fields_event *e;
	struct proc_cfg *cfg;
	u64 *sk, store;
	u32 sid;

	key.tgid = cur_pid_tgid() >> 32;
	cfg = bpf_map_lookup_elem(&REQ_PROCS, &key.tgid);
	if (!cfg || cfg->runtime != RT_TOKIO || !cfg->rs_entries_ptr)
		return 0;
	if (!rs_stream(c_arg(ctx, 3), &store, &sid))
		return 0;
	key.addr = store;
	sk = bpf_map_lookup_elem(&GO_TRANSPORTS, &key);
	if (!sk || !h2_undecoded(*sk))
		return 0;
	e = h2_fields_begin(key.tgid, *sk, sid, H2F_RESPONSE);
	if (!e)
		return 0;
	rs_scan(c_arg(ctx, 1), cfg, e);
	if (!e->has_status) {
		bpf_ringbuf_discard(e, 0);
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
