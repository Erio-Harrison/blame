/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * TLS through Go's crypto/tls: where `(*Conn).Read` and `(*Conn).Write`
 * hand over the plaintext of a connection, for tls.h. The user side is
 * src/tls/go.rs.
 *
 * - Read(b []byte) (n int, err error) and Write the same: the receiver, the
 *   buffer's pointer and its length are the first three arguments of Go's
 *   internal ABI; n is the first result.
 * - Go moves goroutine stacks, so a return probe would break the runtime's
 *   unwinding: the probes are at entry and at every return instruction of
 *   the function (user space finds them), the call kept by goroutine (its
 *   g) in between. A goroutine can park inside Read and go on on another
 *   thread: the g, not the thread, is what ties the two.
 * - The entry can run twice for one call: when the goroutine's stack is too
 *   small the prologue grows it and starts the function again. The later
 *   entry stands (the buffer may have moved with the stack).
 * - Which socket a connection is on is shown by a socket call the
 *   goroutine makes inside the call (call_exit -> go_tls_saw_socket): every
 *   Write makes one, and most Reads, and the handshake (probed as well for
 *   that); a session seen so is remembered (TLS_SESSIONS) for those that do
 *   not.
 */
#ifndef BLAME_TLS_GO_TLS_H
#define BLAME_TLS_GO_TLS_H

enum {
	GO_TLS_READ = 1,
	GO_TLS_WRITE,
	/*
	 * (*Conn).handshakeContext: no plaintext, but socket calls inside it
	 * place the session. net/http shakes hands before its first Read, and
	 * what the client sent right after may be read from what the handshake
	 * took in, with no socket call in that Read.
	 */
	GO_TLS_HANDSHAKE,
};

struct go_tls_call {
	u64 conn;
	u64 buf;
	/* The socket a socket call made inside it went to; 0 = none yet. */
	u64 sk;
	u8 fn;
	u8 _pad[7];
};

/* Calls of crypto/tls in flight, by process, g and function (key._pad): a handshake is made inside a Read or a Write. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct tls_key);
	__type(value, struct go_tls_call);
} GO_TLS_CALLS SEC(".maps");

/* The g of the goroutine whose registers these are (R28 / R14). */
static __always_inline u64 go_regs_g(struct pt_regs *regs)
{
	if (bpf_core_field_exists(regs->regs))
		return BPF_CORE_READ(regs, regs[28]);
	return BPF_CORE_READ((struct pt_regs___x86 *)regs, r14);
}

/* A socket call of the current thread: the crypto/tls call of its goroutine, if one is in flight, is on that socket. */
static __always_inline void go_tls_saw_socket(u64 sk)
{
	struct tls_key key = {};
	struct go_tls_call *call;

	key.tgid = cur_pid_tgid() >> 32;
	key.ssl = go_regs_g((struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf()));
	if (!key.ssl)
		return;
#pragma unroll
	for (u32 fn = GO_TLS_READ; fn <= GO_TLS_HANDSHAKE; fn++) {
		key._pad = fn;
		call = bpf_map_lookup_elem(&GO_TLS_CALLS, &key);
		if (call)
			call->sk = sk;
	}
}

static __always_inline void go_tls_enter(struct pt_regs *ctx, u8 fn)
{
	struct go_tls_call call = {};
	struct tls_key key = {};
	struct carrier *cr;

	key.tgid = cur_pid_tgid() >> 32;
	if (!traced(key.tgid))
		return;
	key.ssl = go_regs_g(ctx);
	key._pad = fn;
	if (!key.ssl)
		return;
	/*
	 * The thread is told which unit it runs here, as tls_begin() does: at
	 * the return it runs the same one, or the goroutine parked inside and
	 * its socket call on the thread it went on with said so.
	 */
	cr = carrier_of_current(true);
	if (cr && (cr->rt.runtime > RT_NONE || cr->rt_gen != rt_gen))
		unit_sync(cr, bpf_get_current_task_btf(), bpf_ktime_get_boot_ns(), true);
	call.fn = fn;
	call.conn = go_arg(ctx, 0);
	call.buf = go_arg(ctx, 1);
	bpf_map_update_elem(&GO_TLS_CALLS, &key, &call, BPF_ANY);
}

static __always_inline void go_tls_return(struct pt_regs *ctx, u8 fn)
{
	struct go_tls_call *found;
	struct tls_key key = {};
	struct carrier *cr;
	u64 conn, buf, sk;

	key.tgid = cur_pid_tgid() >> 32;
	key.ssl = go_regs_g(ctx);
	key._pad = fn;
	if (!key.ssl)
		return;
	found = bpf_map_lookup_elem(&GO_TLS_CALLS, &key);
	if (!found || found->fn != fn)
		return;
	conn = found->conn;
	buf = found->buf;
	sk = found->sk;
	bpf_map_delete_elem(&GO_TLS_CALLS, &key);
	/* The same key, for the session now: one on the stack. */
	key._pad = 0;
	key.ssl = conn;
	if (fn == GO_TLS_HANDSHAKE) {
		/* Its socket calls show where the session is: the plaintext after it is placed. */
		if (sk) {
			bpf_map_update_elem(&TLS_SESSIONS, &key, &sk, BPF_ANY);
			tls_mark((struct sock *)sk);
		}
		return;
	}
	cr = carrier_of_current(true);
	if (!cr)
		return;
	tls_deliver(cr, &key, buf, (s64)go_arg(ctx, 0), sk, fn == GO_TLS_READ);
}

SEC("uprobe")
int up_go_tls_read(struct pt_regs *ctx)
{
	go_tls_enter(ctx, GO_TLS_READ);
	return 0;
}

/* At each return instruction of (*Conn).Read. */
SEC("uprobe")
int up_go_tls_read_ret(struct pt_regs *ctx)
{
	go_tls_return(ctx, GO_TLS_READ);
	return 0;
}

SEC("uprobe")
int up_go_tls_write(struct pt_regs *ctx)
{
	go_tls_enter(ctx, GO_TLS_WRITE);
	return 0;
}

SEC("uprobe")
int up_go_tls_write_ret(struct pt_regs *ctx)
{
	go_tls_return(ctx, GO_TLS_WRITE);
	return 0;
}

SEC("uprobe")
int up_go_tls_handshake(struct pt_regs *ctx)
{
	go_tls_enter(ctx, GO_TLS_HANDSHAKE);
	return 0;
}

SEC("uprobe")
int up_go_tls_handshake_ret(struct pt_regs *ctx)
{
	go_tls_return(ctx, GO_TLS_HANDSHAKE);
	return 0;
}

#endif
