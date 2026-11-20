/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Go, with probes: which goroutine a thread runs, exactly, and which
 * goroutine a grpc-go server hands each HTTP/2 stream to.
 *
 * - runtime.execute(gp) is where the scheduler puts a goroutine on a
 *   thread. With a probe there the thread's unit is known from the moment
 *   it changes; without, only at the next socket call or switch-out (go.h).
 * - (*Server).addConn(addr, st) registers a new connection's transport. It
 *   runs in the goroutine that has just read the client's preface off the
 *   socket, so that goroutine's connection (UNIT_READS) is the transport's.
 *   (The goroutine that reads the connection from then on is another one,
 *   and the first requests may already have been read by this one.)
 * - (*Server).handleStream(t, stream) runs in the goroutine that will serve
 *   the stream. The stream id is read behind `stream`, at a place that
 *   depends on the grpc-go version (user space knows it; GRPC_ID_*).
 *   transport -> connection, (connection, stream id) -> request: the
 *   goroutine is bound to it.
 * - (*http2Server).writeStatus(...) is how a handler's goroutine ends the
 *   stream. The frame itself is written by another goroutine, possibly on
 *   another thread at once, and the request is over when it is: what the
 *   handler's thread has measured so far is handed in here, before that.
 *
 * A stream id read at the wrong place finds no open stream on the
 * connection and binds nothing. If it could not even be a stream that is
 * over already (reset before its handler got to it), that is counted
 * (GRPC_HANDOFF_UNMATCHED).
 *
 * A connection that was open before the probes were attached was never
 * seen being registered. (*http2Server).operateHeaders(frame, ...) runs for
 * every HEADERS frame in the goroutine that reads the connection, which by
 * then is the only one that does: a transport not known yet is tied to that
 * goroutine's connection there.
 *
 * A connection that was not followed from its first byte has header blocks
 * that cannot be decoded here (the compression state is unknown). The
 * process has decoded them: operateHeaders is given the frame with the
 * decoded fields (names and values), writeStatus the status. Both are read
 * there and sent as an h2_fields_event, for the connection the transport
 * belongs to. Where the fields are is the same in every grpc-go version
 * that has the probes (x/net's MetaHeadersFrame and hpack.HeaderField,
 * genproto's Status); which register holds the frame is not
 * (proc_cfg.grpc_frame_arg).
 *
 * Arguments are in the registers of Go's internal ABI: R0.. on arm64,
 * AX, BX, CX, DI, SI on x86-64. The current g is in R28 / R14.
 */
#ifndef BLAME_RUNTIME_GO_GRPC_H
#define BLAME_RUNTIME_GO_GRPC_H

static __always_inline u64 go_arg(struct pt_regs *regs, int n)
{
	struct pt_regs___x86 *x86 = (struct pt_regs___x86 *)regs;

	if (bpf_core_field_exists(regs->regs)) {
		switch (n) {
		case 0:
			return BPF_CORE_READ(regs, regs[0]);
		case 1:
			return BPF_CORE_READ(regs, regs[1]);
		case 2:
			return BPF_CORE_READ(regs, regs[2]);
		case 3:
			return BPF_CORE_READ(regs, regs[3]);
		default:
			return BPF_CORE_READ(regs, regs[4]);
		}
	}
	switch (n) {
	case 0:
		return BPF_CORE_READ(x86, ax);
	case 1:
		return BPF_CORE_READ(x86, bx);
	case 2:
		return BPF_CORE_READ(x86, cx);
	case 3:
		return BPF_CORE_READ(x86, di);
	default:
		return BPF_CORE_READ(x86, si);
	}
}

/* The goroutine running the probed function. */
static __always_inline u64 go_current_goid(struct pt_regs *regs, const struct proc_cfg *cfg)
{
	u64 g;

	if (bpf_core_field_exists(regs->regs))
		g = BPF_CORE_READ(regs, regs[28]);
	else
		g = BPF_CORE_READ((struct pt_regs___x86 *)regs, r14);
	return g ? user_u64(g + cfg->go_g_goid) : 0;
}

static __always_inline struct unit_key goroutine(u32 tgid, u64 goid)
{
	struct unit_key unit = {};

	unit.tgid = tgid;
	unit.kind = UNIT_GOROUTINE;
	unit.id = goid;
	return unit;
}

/* Go's MetaHeadersFrame{*HeadersFrame; Fields []hpack.HeaderField; ...}, HeaderField{Name, Value string; Sensitive bool}. */
#define GO_FRAME_FIELDS 8
#define GO_HEADERS_FRAME_STREAM_ID 8
#define GO_HEADER_FIELD_SIZE 40
/* status.Status{s *spb.Status}; spb.Status{state, sizeCache, unknownFields, Code int32, ...}. */
#define GO_STATUS_CODE 40
/* Header fields looked at per request, from the first. */
#define H2F_MAX_FIELDS 24
/* The length of "traceparent" and "grpc-status" */
#define H2F_NAME11 11

static __always_inline bool is_traceparent(const char *n)
{
	return n[0] == 't' && n[1] == 'r' && n[2] == 'a' && n[3] == 'c' && n[4] == 'e' && n[5] == 'p' &&
	       n[6] == 'a' && n[7] == 'r' && n[8] == 'e' && n[9] == 'n' && n[10] == 't';
}

/* The connection the process's own view of a stream is about, if it cannot be decoded here. */
static __always_inline bool h2_undecoded(u64 sk)
{
	struct conn *c = bpf_map_lookup_elem(&REQ_CONNS, &sk);

	return c && !c->fresh;
}

static __always_inline struct h2_fields_event *h2_fields_begin(u32 tgid, u64 sk, u32 sid, u8 what)
{
	struct h2_fields_event *e = bpf_ringbuf_reserve(&EVENTS, sizeof(*e), 0);

	if (!e) {
		bump(RINGBUF_FULL);
		return NULL;
	}
	__builtin_memset(e, 0, sizeof(*e));
	e->hdr.version = EVENT_VERSION;
	e->hdr.kind = EVENT_H2_FIELDS;
	e->hdr.ts_boot_ns = bpf_ktime_get_boot_ns();
	e->hdr.pid = tgid;
	e->hdr.tid = (u32)cur_pid_tgid();
	e->conn = sk;
	e->sid = sid;
	e->what = what;
	return e;
}

/*
 * operateHeaders: the request's decoded headers. The stream id is in the
 * frame header, the trace id in the "traceparent" field, the method in the
 * ":path" pseudo-header.
 */
static __always_inline void go_request_fields(struct pt_regs *ctx, const struct proc_cfg *cfg, u32 tgid, u64 sk)
{
	struct h2_fields_event *e;
	u64 frame, fields, n, headers_frame;
	u32 sid = 0;
	int i;

	if (!h2_undecoded(sk))
		return;
	frame = go_arg(ctx, cfg->grpc_frame_arg);
	if (!frame)
		return;
	fields = user_u64(frame + GO_FRAME_FIELDS);
	n = user_u64(frame + GO_FRAME_FIELDS + 8);
	headers_frame = user_u64(frame);
	if (!fields || !n || !headers_frame ||
	    bpf_probe_read_user(&sid, sizeof(sid), (void *)(headers_frame + GO_HEADERS_FRAME_STREAM_ID)) || !sid)
		return;
	e = h2_fields_begin(tgid, sk, sid, H2F_REQUEST);
	if (!e)
		return;
#pragma unroll
	for (i = 0; i < H2F_MAX_FIELDS; i++) {
		struct {
			u64 name, name_len, value, value_len;
		} f;
		char name[H2F_NAME11];

		if (i >= n)
			break;
		if (bpf_probe_read_user(&f, sizeof(f), (void *)(fields + (u64)i * GO_HEADER_FIELD_SIZE)))
			break;
		if (f.name_len == H2F_NAME11) {
			if (bpf_probe_read_user(name, sizeof(name), (void *)f.name))
				continue;
			/* 00-<32 hex>-<16 hex>-<2 hex>: the trace id is at 3. */
			if (is_traceparent(name) && f.value_len >= 55 &&
			    !bpf_probe_read_user(e->trace, sizeof(e->trace), (void *)(f.value + 3)))
				e->has_trace = 1;
		} else if (f.name_len == 5) {
			char p5[5];

			if (bpf_probe_read_user(p5, sizeof(p5), (void *)f.name))
				continue;
			if (p5[0] == ':' && p5[1] == 'p' && p5[2] == 'a' && p5[3] == 't' && p5[4] == 'h') {
				u64 len = f.value_len;

				if (len > H2F_PATH_LEN)
					len = H2F_PATH_LEN;
				if (len && !bpf_probe_read_user(e->path, len, (void *)f.value))
					e->path_len = len;
			}
		}
	}
	bpf_ringbuf_submit(e, 0);
	bump(EVENTS_PRODUCED);
}

SEC("uprobe")
int up_go_execute(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(true);
	struct unit_key unit;
	u64 gp, goid;

	if (!cr)
		return 0;
	carrier_cfg(cr);
	if (cr->rt.runtime != RT_GO)
		return 0;
	gp = go_arg(ctx, 0);
	goid = gp ? user_u64(gp + cr->rt.go_g_goid) : 0;
	if (!goid)
		return 0;
	unit = goroutine(cr->unit.tgid, goid);
	unit_set(cr, &unit, bpf_ktime_get_boot_ns());
	/* Its memory names the goroutine a few instructions from here (units.h). */
	cr->go_execute_pc = go_probe_pc(ctx);
	return 0;
}

SEC("uprobe")
int up_go_grpc_conn(struct pt_regs *ctx)
{
	struct transport_key key = {};
	struct proc_cfg *cfg;
	struct unit_key unit;
	u64 goid, *sk;

	key.tgid = cur_pid_tgid() >> 32;
	cfg = bpf_map_lookup_elem(&REQ_PROCS, &key.tgid);
	if (!cfg || cfg->runtime != RT_GO)
		return 0;
	/* The transport is an interface value: its data word is the pointer. */
	key.addr = go_arg(ctx, 4);
	goid = go_current_goid(ctx, cfg);
	if (!key.addr || !goid)
		return 0;
	unit = goroutine(key.tgid, goid);
	sk = bpf_map_lookup_elem(&UNIT_READS, &unit);
	if (sk)
		bpf_map_update_elem(&GO_TRANSPORTS, &key, sk, BPF_ANY);
	return 0;
}

SEC("uprobe")
int up_go_grpc_headers(struct pt_regs *ctx)
{
	struct transport_key key = {};
	struct proc_cfg *cfg;
	struct unit_key unit;
	u64 goid, *sk;

	key.tgid = cur_pid_tgid() >> 32;
	key.addr = go_arg(ctx, 0);
	if (!key.addr)
		return 0;
	cfg = bpf_map_lookup_elem(&REQ_PROCS, &key.tgid);
	if (!cfg || cfg->runtime != RT_GO)
		return 0;
	sk = bpf_map_lookup_elem(&GO_TRANSPORTS, &key);
	if (!sk) {
		/* Not registered, nor seen in an earlier frame: the goroutine that reads the connection is its. */
		goid = go_current_goid(ctx, cfg);
		if (!goid)
			return 0;
		unit = goroutine(key.tgid, goid);
		sk = bpf_map_lookup_elem(&UNIT_READS, &unit);
		if (!sk)
			return 0;
		bpf_map_update_elem(&GO_TRANSPORTS, &key, sk, BPF_ANY);
	}
	if (cfg->grpc_frame_arg)
		go_request_fields(ctx, cfg, key.tgid, *sk);
	return 0;
}

SEC("uprobe")
int up_go_grpc_handle(struct pt_regs *ctx)
{
	struct transport_key tkey = {};
	struct stream_key skey = {};
	struct unit_key unit;
	struct proc_cfg *cfg;
	struct carrier *cr;
	u64 stream, goid, *sk, *req_id;
	u32 sid = 0;

	tkey.tgid = cur_pid_tgid() >> 32;
	cfg = bpf_map_lookup_elem(&REQ_PROCS, &tkey.tgid);
	if (!cfg || cfg->runtime != RT_GO || cfg->grpc_id_how == GRPC_ID_NONE)
		return 0;
	tkey.addr = go_arg(ctx, 2);
	stream = go_arg(ctx, 3);
	if (cfg->grpc_id_how == GRPC_ID_BEHIND_PTR)
		stream = user_u64(stream);
	if (stream)
		bpf_probe_read_user(&sid, sizeof(sid), (void *)(stream + cfg->grpc_id_off));
	goid = go_current_goid(ctx, cfg);
	/* A connection the probes have seen nothing of yet. */
	sk = bpf_map_lookup_elem(&GO_TRANSPORTS, &tkey);
	if (!sk)
		return 0;
	skey.sk = *sk;
	skey.sid = sid;
	req_id = bpf_map_lookup_elem(&REQ_STREAMS, &skey);
	if (!req_id || !goid) {
		if (!h2_stream_plausible(skey.sk, sid))
			bump(GRPC_HANDOFF_UNMATCHED);
		return 0;
	}
	unit = goroutine(tkey.tgid, goid);
	bind_handler(&unit, *req_id, skey.sk);
	/* The goroutine is already running: take the binding over now. */
	cr = carrier_of_current(true);
	if (cr) {
		carrier_cfg(cr);
		unit_set(cr, &unit, bpf_ktime_get_boot_ns());
	}
	return 0;
}

/* writeStatus(t, s, st): the status the handler answers with; nil is OK. */
static __always_inline void go_status_field(struct pt_regs *ctx, const struct proc_cfg *cfg, u32 tgid)
{
	struct transport_key tkey = {};
	struct h2_fields_event *e;
	u64 stream, st, status, *sk;
	u32 sid = 0, code = 0;

	tkey.tgid = tgid;
	tkey.addr = go_arg(ctx, 0);
	stream = go_arg(ctx, 1);
	if (!tkey.addr || !stream || cfg->grpc_id_how == GRPC_ID_NONE)
		return;
	sk = bpf_map_lookup_elem(&GO_TRANSPORTS, &tkey);
	if (!sk || !h2_undecoded(*sk))
		return;
	if (cfg->grpc_id_how == GRPC_ID_BEHIND_PTR)
		stream = user_u64(stream);
	if (!stream || bpf_probe_read_user(&sid, sizeof(sid), (void *)(stream + cfg->grpc_id_off)) || !sid)
		return;
	st = go_arg(ctx, 2);
	status = st ? user_u64(st) : 0;
	if (status && bpf_probe_read_user(&code, sizeof(code), (void *)(status + GO_STATUS_CODE)))
		return;
	e = h2_fields_begin(tgid, *sk, sid, H2F_RESPONSE);
	if (!e)
		return;
	e->has_status = 1;
	e->status = code;
	bpf_ringbuf_submit(e, 0);
	bump(EVENTS_PRODUCED);
}

SEC("uprobe")
int up_go_grpc_end(struct pt_regs *ctx)
{
	struct carrier *cr = carrier_of_current(false);
	struct proc_cfg *cfg;
	u32 tgid = cur_pid_tgid() >> 32;
	u64 now;

	cfg = bpf_map_lookup_elem(&REQ_PROCS, &tgid);
	if (cfg && cfg->runtime == RT_GO && cfg->grpc_frame_arg)
		go_status_field(ctx, cfg, tgid);
	if (!cr || !cr->req_id)
		return 0;
	now = bpf_ktime_get_boot_ns();
	settle_cpu(cr, now);
	/* The request has it, and its open stretch starts again here (unit_doing). */
	unit_doing(cr, now, BIND_RUNNING);
	if (cr->req_id)
		req_add(cr->req_id, &cr->acc, cr->source);
	return 0;
}

#endif
