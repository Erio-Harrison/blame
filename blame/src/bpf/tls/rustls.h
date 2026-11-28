/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * TLS through rustls (0.23): where it takes in the plaintext of a record it
 * received and the plaintext it is given to send, for tls.h. The user side
 * is src/tls/rustls.rs.
 *
 * - `CommonState::take_received_plaintext(&mut self, bytes: Payload)`: a
 *   record's plaintext, by reference in the second argument: a word, then
 *   the pointer and the length (Payload::Borrowed and Owned alike).
 * - `CommonState::send_appdata_encrypt(&mut self, payload: OutboundChunks,
 *   limit)`: plaintext to send, by reference in the second argument. A zero
 *   first word is OutboundChunks::Single: pointer and length follow;
 *   otherwise Multiple: the first word points to a list of (pointer, length),
 *   then its length, and the range of the concatenation that is sent.
 * - Both are reached at entry only. The library holds no socket: rustls
 *   reads and writes through its caller. A record's plaintext is taken in
 *   right after the read that brought it, by the same unit on the same
 *   thread (cr->rs_rd_*); what it is given to send goes out in the next
 *   socket call of that unit on that thread, a write (cr->rs_tx, taken in
 *   call_exit by rs_tx_take() in place of the write's ciphertext). The
 *   list of buffers of a Multiple is rustls's own, gone by the write: it
 *   is copied here, cut to the range sent. The buffers are the caller's,
 *   there until its write returns.
 * - rustls takes in at most what its buffer limit allows at a time (some
 *   64 KiB): a longer response ends at the write that sends its last part,
 *   not at the last byte of that part. Anything else: not looked at (TLS_NO_SOCKET). The
 *   connection object moves after its handshake, so it identifies nothing.
 */
#ifndef BLAME_TLS_RUSTLS_H
#define BLAME_TLS_RUSTLS_H

/* A record's plaintext is at most 2^14 bytes; what is handed to send, far less than this. */
#define RS_RECORD_MAX (1 << 15)
#define RS_SEND_MAX (1 << 26)

/*
 * The current thread's carrier. Which unit it runs was told at the socket
 * call before (the read that brought the record), or by the runtime's
 * probes around the poll the call is in.
 */
static __always_inline struct carrier *rs_carrier(bool create)
{
	struct carrier *cr = carrier_of_current(false);

	if (!cr) {
		if (!create || !traced(cur_pid_tgid() >> 32))
			return NULL;
		cr = carrier_of_current(true);
		if (!cr)
			return NULL;
	}
	return cr;
}

SEC("uprobe")
int up_rs_tls_rx(struct pt_regs *ctx)
{
	struct carrier *cr = rs_carrier(false);
	u64 w[3] = {};

	if (!cr || bpf_probe_read_user(w, sizeof(w), (void *)c_arg(ctx, 1)))
		return 0;
	if (!w[1] || !w[2] || w[2] > RS_RECORD_MAX)
		return 0;
	if (!cr->rs_rd_sk || !unit_eq(&cr->rs_rd_unit, &cr->unit)) {
		bump(TLS_NO_SOCKET);
		return 0;
	}
	tls_mark((struct sock *)cr->rs_rd_sk);
	tls_feed(cr, cr->rs_rd_sk, w[1], w[2], true);
	return 0;
}

/* Buffers of an OutboundChunks::Multiple looked at; more are counted, not seen. */
#define RS_CHUNKS 16

SEC("uprobe")
int up_rs_tls_tx(struct pt_regs *ctx)
{
	struct carrier *cr = rs_carrier(true);
	u64 w[4] = {}, pos = 0;
	u8 n = 0;

	if (!cr || bpf_probe_read_user(w, sizeof(w), (void *)c_arg(ctx, 1)))
		return 0;
	/*
	 * Which unit hands it over, as tls_begin() asks: without the runtime's
	 * probes the thread may have gone on to another task since its last
	 * socket call, and the write's own call will ask again.
	 */
	if (cr->rt.runtime > RT_NONE || cr->rt_gen != rt_gen)
		unit_sync(cr, bpf_get_current_task_btf(), bpf_ktime_get_boot_ns(), true);
	/* One handed over before never went out in a write of its own. */
	if (cr->rs_tx)
		bump(TLS_NO_SOCKET);
	cr->rs_tx = 0;
	if (!w[0]) {
		/* Single: one buffer. */
		if (!w[1] || !w[2] || w[2] > RS_SEND_MAX)
			return 0;
		cr->rs_tx_base[0] = w[1];
		cr->rs_tx_len[0] = w[2];
		cr->rs_tx_total = w[2];
		n = 1;
	} else {
		/* Multiple: [start, end) of the concatenation of the w[1] buffers listed at w[0]. */
		u64 list = w[0], count = w[1], start = w[2], end = w[3];

		if (!count || end <= start || end - start > RS_SEND_MAX)
			return 0;
		cr->rs_tx_total = end - start;
		for (int i = 0; i < RS_CHUNKS; i++) {
			u64 piece[2], lo, hi, from, to;

			if (i >= count || pos >= end)
				break;
			if (bpf_probe_read_user(piece, sizeof(piece), (void *)(list + 16 * i)))
				return 0;
			lo = pos;
			hi = pos + piece[1];
			pos = hi;
			if (hi <= start || !piece[1])
				continue;
			from = start > lo ? start - lo : 0;
			to = (end < hi ? end : hi) - lo;
			if (n < HTTP_SEGS - 1) {
				cr->rs_tx_base[n & (HTTP_SEGS - 1)] = piece[0] + from;
				cr->rs_tx_len[n & (HTTP_SEGS - 1)] = to - from;
				n++;
			} else {
				/* The rest, counted, not seen. */
				cr->rs_tx_base[HTTP_SEGS - 1] = 0;
				cr->rs_tx_len[HTTP_SEGS - 1] = end - (lo + from);
				n = HTTP_SEGS;
				break;
			}
		}
		/* The list says less than the range: not what it was taken for. */
		if (n < HTTP_SEGS && pos < end)
			return 0;
	}
	cr->rs_tx = n;
	cr->rs_tx_unit = cr->unit;
	return 0;
}

#endif
