/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * TLS, whatever the library: on a TLS connection the socket calls carry
 * ciphertext, so the bytes a request is read from and its response is written
 * with are taken where the library hands them over instead, and fed to the
 * same parsers (on_data). One file per library (openssl.h) probes its calls
 * and tells this one what each was given (tls_begin) and moved (tls_end).
 *
 * - A session is the library's object for one connection, known by its
 *   address in the process. Which socket it is on is told by the library
 *   (tls_place, at SSL_set_fd), or by a socket call made inside one of its
 *   calls (call_exit sets the carrier's tls_sk), which is trusted over what
 *   was known: so are placed sessions set up before the probes were there and
 *   sessions given their socket another way. A call that made none on a
 *   session not placed yet is not looked at (TLS_NO_SOCKET); one over memory
 *   buffers (Python's asyncio) never is. A session freed is forgotten.
 * - A client connection seen in a session is a TLS one from then on: its
 *   socket calls' bytes are passed over (on_data).
 * - Only client connections: a downstream call is timed from its socket
 *   calls, which the protocol does not matter to.
 * - One call of the library per thread is followed, in the carrier's tls_*
 *   fields; tls_fn 0 = none.
 */
#ifndef BLAME_TLS_H
#define BLAME_TLS_H

/*
 * A TLS session of a traced process: which socket it is on. Taken out when
 * the library frees it; least recently used first out otherwise, so that the
 * sessions of processes that are gone do not fill it.
 */
struct tls_key {
	u32 tgid;
	u32 _pad;
	u64 ssl;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct tls_key);
	__type(value, u64);
} TLS_SESSIONS SEC(".maps");

/* A client connection on `sk` is a TLS one from now on. */
static __always_inline void tls_mark(struct sock *sk)
{
	u64 key = (u64)sk;
	struct conn *c = bpf_map_lookup_elem(&REQ_CONNS, &key);

	if (!c) {
		c = conn_new(sk, 0);
		if (!c)
			return;
	}
	/* 2: seen to begin with a handshake, not read yet (request/calls.h). */
	if (c->cls != CONN_CLIENT || c->tls == 1)
		return;
	c->tls = 1;
	bump(TLS_FOLLOWED);
	/*
	 * What the parsers made of the bytes until now was ciphertext (a session
	 * placed by its socket calls: its handshake went through them). The
	 * plaintext starts at its first byte on a connection followed from its
	 * start; otherwise somewhere in the middle.
	 */
	conn_abort_pending(c);
	c->proto = PROTO_UNKNOWN;
	__builtin_memset(&c->h2rx, 0, sizeof(c->h2rx));
	__builtin_memset(&c->h2tx, 0, sizeof(c->h2tx));
	http_reset(&c->rx);
	http_reset(&c->tx);
	if (!c->fresh) {
		c->rx.st = HS_UNSYNC;
		c->tx.st = HS_UNSYNC;
	}
}

/* Session `ssl` of process `tgid` is on `sk`. */
static __always_inline void tls_place(u32 tgid, u64 ssl, struct sock *sk)
{
	struct tls_key key = { .tgid = tgid, .ssl = ssl };
	u64 v = (u64)sk;

	bpf_map_update_elem(&TLS_SESSIONS, &key, &v, BPF_ANY);
	tls_mark(sk);
}

/* Session `ssl` of the current process is gone; its object's memory may be another's next. */
static __always_inline void tls_forget(u64 ssl)
{
	struct tls_key key = { .tgid = cur_pid_tgid() >> 32, .ssl = ssl };

	bpf_map_delete_elem(&TLS_SESSIONS, &key);
}

/*
 * A call of the library begins: `fn`, the library's own kind of call
 * (nonzero), on session `ssl`, with the caller's buffer `buf` (0: none, the
 * bytes are not seen), `outp` where the library will write how many bytes
 * it moved (0: it returns that), and the stack pointer `sp` at its entry.
 */
static __always_inline void tls_begin(u8 fn, u64 ssl, u64 buf, u64 outp, u64 sp)
{
	struct carrier *cr = carrier_of_current(false);

	if (!cr) {
		if (!traced(cur_pid_tgid() >> 32))
			return;
		cr = carrier_of_current(true);
		if (!cr)
			return;
	}
	/*
	 * One the library makes itself, on the same session, further down the
	 * stack (LibreSSL's SSL_write_ex through SSL_write): the outer one
	 * counts. Anything else found here is a call whose return never came (left
	 * by longjmp): forgotten, or every later call of the thread would be
	 * taken for one inside it.
	 */
	if (cr->tls_fn && cr->tls_ssl == ssl && sp < cr->tls_sp)
		return;
	if (cr->rt.runtime > RT_NONE || cr->rt_gen != rt_gen)
		unit_sync(cr, bpf_get_current_task_btf(), bpf_ktime_get_boot_ns(), true);
	cr->tls_fn = fn;
	cr->tls_ssl = ssl;
	cr->tls_buf = buf;
	cr->tls_outp = outp;
	cr->tls_sk = 0;
	cr->tls_sp = sp;
}

/* Where the call followed said it would write how many bytes it moved; 0: none. */
static __always_inline u64 tls_outp(void)
{
	struct carrier *cr = carrier_of_current(false);

	return cr ? cr->tls_outp : 0;
}

/*
 * The call tls_feed() describes: not on its stack, which a socket call's
 * own (rustls: tls/rustls.h) is under, with the parsers' on top.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct call_data);
} TLS_CALL SEC(".maps");

/*
 * `n` bytes of plaintext at `buf`, moved on client socket `sk` (marked as a
 * TLS one), received if `read`. Not inlined: with the parsers on_data
 * brings in, a probe's own stack would not fit.
 */
static __always_inline void tls_feed_here(struct carrier *cr, u64 sk, u64 buf, u64 n, bool read)
{
	u32 zero = 0;
	struct call_data *d = bpf_map_lookup_elem(&TLS_CALL, &zero);

	if (!d)
		return;
	__builtin_memset(d, 0, sizeof(*d));
	d->nseg = 1;
	d->base[0] = buf;
	d->len[0] = n;
	d->total = n;
	on_data((struct sock *)sk, cr, read, d, true);
}

static __noinline void tls_feed(struct carrier *cr, u64 sk, u64 buf, u64 n, bool read)
{
	tls_feed_here(cr, sk, buf, n, read);
}

/*
 * `n` bytes of plaintext (<= 0: none) at `buf`, moved by a TLS library's
 * call on the session `key` names (of the current process), received if
 * `read`. `sk`: the socket a socket call made inside that call went to (0:
 * none), which places the session; otherwise the session's known socket.
 * `key` is the caller's, so that a probe's stack holds one.
 */
static __always_inline void tls_deliver(struct carrier *cr, struct tls_key *key, u64 buf, s64 n,
					u64 sk, bool read)
{
	u64 *skp;

	if (!cr || n <= 0)
		return;
	skp = bpf_map_lookup_elem(&TLS_SESSIONS, key);
	if (sk) {
		/*
		 * The socket call it just made shows where it is: a session set up
		 * before the probes, or given its socket other than by the library
		 * call that tells (SSL_set_bio), whose object may sit where one of
		 * another connection was freed.
		 */
		if (!skp || *skp != sk) {
			bpf_map_update_elem(&TLS_SESSIONS, key, &sk, BPF_ANY);
			tls_mark((struct sock *)sk);
		}
	} else if (skp) {
		sk = *skp;
	} else {
		bump(TLS_NO_SOCKET);
		return;
	}
	tls_feed(cr, sk, buf, n, read);
}

/*
 * The call `fn` returns with the stack pointer `sp`, having moved `n` bytes
 * of plaintext (<= 0: none), received if `read`.
 */
static __always_inline void tls_end(u8 fn, bool read, s64 n, u64 sp)
{
	struct carrier *cr = carrier_of_current(false);
	struct tls_key key = {};

	/* Not the one followed: a call made inside it returns further down the stack. */
	if (!cr || cr->tls_fn != fn || sp < cr->tls_sp)
		return;
	cr->tls_fn = 0;
	key.tgid = cur_pid_tgid() >> 32;
	key.ssl = cr->tls_ssl;
	tls_deliver(cr, &key, cr->tls_buf, n, cr->tls_sk, read);
}

#endif
