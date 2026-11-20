/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/* The socket system calls of traced processes, at entry and at exit. */
#ifndef BLAME_REQUEST_CALLS_H
#define BLAME_REQUEST_CALLS_H

/* What one call moved on a traced socket, handed to the protocol its connection speaks. */
static __always_inline void on_data(struct sock *sk, struct carrier *cr, bool rx,
				    struct call_data *d)
{
	u64 key = (u64)sk;
	u64 now = bpf_ktime_get_boot_ns();
	struct conn *c = bpf_map_lookup_elem(&REQ_CONNS, &key);

	if (!c) {
		c = conn_new(sk, 0);
		if (!c)
			return;
	}
	settle_cpu(cr, now);
	/* What was settled is the request's now: its unit's open stretch starts again here. */
	unit_doing(cr, now, BIND_RUNNING);
	if (c->cls == CONN_DOWN) {
		if (rx)
			on_down_read(c, cr, now);
		else
			on_down_write(sk, c, cr, cr->sc_ns && cr->sc_ns < now ? cr->sc_ns : now);
	} else if (c->proto != PROTO_HTTP1 && h2_call(c, key, cr, rx, d, now)) {
		/* HTTP/2. */
	} else {
		if (d->truncated)
			bump(REQ_IOV_TRUNCATED);
		if (rx)
			on_client_read(c, key, cr, d, now);
		else
			on_client_write(c, cr, d, now);
	}
}

enum {
	NR_READ = 1,
	NR_READV,
	NR_RECVFROM,
	NR_RECVMSG,
	NR_WRITE,
	NR_WRITEV,
	NR_SENDTO,
	NR_SENDMSG,
	NR_SENDFILE,
	NR_CONNECT,
};

static __always_inline int call_enter(struct trace_event_raw_sys_enter *ctx, u8 nr)
{
	struct carrier *cr = carrier_of_current(false);

	if (!cr) {
		if (!traced(cur_pid_tgid() >> 32))
			return 0;
		cr = carrier_of_current(true);
		if (!cr)
			return 0;
	}
	if (cr->rt.runtime > RT_NONE || cr->rt_gen != rt_gen)
		unit_sync(cr, bpf_get_current_task_btf(), bpf_ktime_get_boot_ns(), true);
	cr->sc_nr = nr;
	cr->sc_fd = ctx->args[0];
	cr->sc_a1 = ctx->args[1];
	cr->sc_a2 = ctx->args[2];
	/*
	 * Only recvfrom's flags are wanted. Reading past a call's own arguments
	 * makes the kernel refuse to attach the program, so `nr`, a constant in
	 * each program, keeps the read out of the others.
	 */
	if (nr == NR_RECVFROM)
		cr->sc_a3 = ctx->args[3];
	/* A downstream call starts when its write does, not when that returns. */
	if (nr >= NR_WRITE && nr <= NR_SENDFILE)
		cr->sc_ns = bpf_ktime_get_boot_ns();
	return 0;
}

/*
 * A socket call found nothing to read, or no room to write. A unit of a
 * runtime parks on that, and the thread moves on without telling the kernel.
 */
static __always_inline void call_would_block(struct carrier *cr)
{
	struct binding *b;

	if (!unit_moves(&cr->unit))
		return;
	cr->would_block = 1;
	b = cr->req_id ? bpf_map_lookup_elem(&UNIT_BINDING, &cr->unit) : NULL;
	if (b)
		b->io_parked = 1;
}

/*
 * The user buffers of a vectored call, cut down to the bytes transferred. A
 * segment with no address stands for bytes that are counted but not seen.
 */
static __always_inline void call_iovecs(struct call_data *d, u64 iov, u64 count, u64 total)
{
	u64 left = total;

	for (int i = 0; i < HTTP_SEGS - 1; i++) {
		struct iovec v;

		if (i >= count || !left)
			break;
		if (bpf_probe_read_user(&v, sizeof(v), (void *)(iov + i * sizeof(v))))
			break;
		d->base[i] = (u64)v.iov_base;
		d->len[i] = v.iov_len < left ? v.iov_len : left;
		left -= d->len[i];
		d->nseg = i + 1;
	}
	d->iov = iov;
	d->iovcnt = count;
	if (left) {
		/* Present but not looked at: fine inside a body, a desync in headers. */
		d->truncated = 1;
		d->base[d->nseg & (HTTP_SEGS - 1)] = 0;
		d->len[d->nseg & (HTTP_SEGS - 1)] = left;
		d->nseg++;
	}
}

static __always_inline int call_exit(struct trace_event_raw_sys_exit *ctx, u8 nr)
{
	struct carrier *cr = carrier_of_current(false);
	struct call_data d = {};
	struct sock *sk;
	long ret = ctx->ret;

	if (!cr || cr->sc_nr != nr)
		return 0;
	cr->sc_nr = 0;
	if (ret == -EAGAIN)
		call_would_block(cr);
	if (ret <= 0)
		return 0;
	sk = fd_to_sk((int)cr->sc_fd);
	if (!sk)
		return 0;

	switch (nr) {
	case NR_RECVFROM:
		/* A peek leaves the bytes to be read again. */
		if (cr->sc_a3 & MSG_PEEK)
			return 0;
		/* fallthrough */
	case NR_READ:
	case NR_WRITE:
	case NR_SENDTO:
		d.nseg = 1;
		d.base[0] = cr->sc_a1;
		d.len[0] = ret;
		break;
	case NR_READV:
	case NR_WRITEV:
		call_iovecs(&d, cr->sc_a1, cr->sc_a2, ret);
		break;
	case NR_RECVMSG:
		if (cr->sc_a2 & MSG_PEEK)
			return 0;
		/* fallthrough */
	case NR_SENDMSG: {
		struct user_msghdr msg;

		if (bpf_probe_read_user(&msg, sizeof(msg), (void *)cr->sc_a1))
			return 0;
		call_iovecs(&d, (u64)msg.msg_iov, msg.msg_iovlen, ret);
		break;
	}
	case NR_SENDFILE:
		/* The bytes come from a file: counted, not seen. */
		d.nseg = 1;
		d.len[0] = ret;
		break;
	}
	d.total = ret;
	on_data(sk, cr, nr <= NR_RECVMSG, &d);
	return 0;
}

#define SOCKET_CALL(name, nr)                                                   \
	SEC("tracepoint/syscalls/sys_enter_" #name)                              \
	int req_enter_##name(struct trace_event_raw_sys_enter *ctx)              \
	{                                                                        \
		return call_enter(ctx, nr);                                      \
	}                                                                        \
	SEC("tracepoint/syscalls/sys_exit_" #name)                               \
	int req_exit_##name(struct trace_event_raw_sys_exit *ctx)                \
	{                                                                        \
		return call_exit(ctx, nr);                                       \
	}

SOCKET_CALL(read, NR_READ)
SOCKET_CALL(readv, NR_READV)
SOCKET_CALL(recvfrom, NR_RECVFROM)
SOCKET_CALL(recvmsg, NR_RECVMSG)
SOCKET_CALL(write, NR_WRITE)
SOCKET_CALL(writev, NR_WRITEV)
SOCKET_CALL(sendto, NR_SENDTO)
SOCKET_CALL(sendmsg, NR_SENDMSG)
SOCKET_CALL(sendfile64, NR_SENDFILE)

/*
 * Only the return value is needed, so an accept that was already blocked
 * when the agent attached is still seen. A process that accepts a TCP
 * connection is a server: it is traced from here on.
 */
static __always_inline int accepted(struct trace_event_raw_sys_exit *ctx)
{
	u32 tgid = cur_pid_tgid() >> 32;
	struct sock *sk;
	long fd = ctx->ret;

	/* tgid 0: a process outside the agent's PID namespace. */
	if (fd < 0 || !tgid)
		return 0;
	if (req_only_listed && !traced(tgid))
		return 0;
	sk = fd_to_sk(fd);
	if (!sk)
		return 0;
	if (!req_only_listed && !trace_proc(tgid)) {
		bump(REQ_PROC_INSERT_FAILED);
		return 0;
	}
	conn_new(sk, CONN_CLIENT);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int req_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
	return accepted(ctx);
}

SEC("tracepoint/syscalls/sys_exit_accept")
int req_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
	return accepted(ctx);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int req_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
	return call_enter(ctx, NR_CONNECT);
}

SEC("tracepoint/syscalls/sys_exit_connect")
int req_exit_connect(struct trace_event_raw_sys_exit *ctx)
{
	struct carrier *cr = carrier_of_current(false);
	struct sock *sk;

	if (!cr || cr->sc_nr != NR_CONNECT)
		return 0;
	cr->sc_nr = 0;
	/* A non-blocking connect is still in progress when the call returns. */
	if (ctx->ret != 0 && ctx->ret != -EINPROGRESS)
		return 0;
	if (ctx->ret)
		call_would_block(cr);
	sk = fd_to_sk((int)cr->sc_fd);
	if (sk)
		conn_new(sk, CONN_DOWN);
	return 0;
}

/* Every way a TCP socket with a file goes away ends here. */
SEC("fentry/tcp_close")
int BPF_PROG(req_tcp_close, struct sock *sk)
{
	u64 key = (u64)sk;
	struct conn *c = bpf_map_lookup_elem(&REQ_CONNS, &key);

	if (!c)
		return 0;
	if (c->cls == CONN_CLIENT) {
		h2_abort_streams(key, c);
		/* A response without a length ends with the connection. */
		if (c->tx.st == HS_BODY_EOF && c->popped != c->pushed) {
			req_finish(c->queue[c->popped & (REQ_QUEUE - 1)], c->last_tx_ns, c->tx.status,
				   REQ_F_ENDED_BY_CLOSE, NULL, 0);
			c->popped++;
		}
		conn_abort_pending(c);
	}
	bpf_map_delete_elem(&REQ_CONNS, &key);
	return 0;
}

#endif
