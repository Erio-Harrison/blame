/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * TLS through OpenSSL's API (libssl, and libraries that keep its names):
 * where it hands over the plaintext of a connection, for tls.h. The user
 * side is src/tls/openssl.rs.
 *
 * - SSL_set_fd(ssl, fd) tells which socket a session is on; SSL_free that
 *   it is gone. A session given its socket through SSL_set_bio is placed by
 *   the socket calls made inside its calls (tls.h).
 * - SSL_read / SSL_write return the bytes moved (<= 0: none, e.g. the
 *   socket had nothing yet); SSL_read_ex / SSL_write_ex return 1 and write the
 *   count through their fourth argument. The buffer is the caller's, as at a
 *   socket call, and is parsed where it is.
 * - SSL_sendfile (kernel TLS): bytes sent from a file: counted, not seen, as
 *   a sendfile call is.
 *
 * Arguments are in the C ABI's registers: x0.. on arm64; RDI, RSI, RDX,
 * RCX on x86-64. What a function returns is in x0 / RAX.
 */
#ifndef BLAME_TLS_OPENSSL_H
#define BLAME_TLS_OPENSSL_H

enum {
	TLS_FN_WRITE = 1,
	TLS_FN_WRITE_EX,
	TLS_FN_READ,
	TLS_FN_READ_EX,
	TLS_FN_SENDFILE,
};

SEC("uprobe")
int up_ssl_set_fd(struct pt_regs *ctx)
{
	u32 tgid = cur_pid_tgid() >> 32;
	struct sock *sk;

	if (!traced(tgid))
		return 0;
	sk = fd_to_sk((int)c_arg(ctx, 1));
	if (sk)
		tls_place(tgid, c_arg(ctx, 0), sk);
	return 0;
}

/* void SSL_free(SSL *ssl) */
SEC("uprobe")
int up_ssl_free(struct pt_regs *ctx)
{
	tls_forget(c_arg(ctx, 0));
	return 0;
}

static __always_inline void ossl_enter(struct pt_regs *ctx, u8 fn)
{
	bool ex = fn == TLS_FN_WRITE_EX || fn == TLS_FN_READ_EX;

	tls_begin(fn, c_arg(ctx, 0), fn == TLS_FN_SENDFILE ? 0 : c_arg(ctx, 1),
		  ex ? c_arg(ctx, 3) : 0, c_sp(ctx));
}

static __always_inline void ossl_exit(struct pt_regs *ctx, u8 fn, s64 n)
{
	tls_end(fn, fn == TLS_FN_READ || fn == TLS_FN_READ_EX, n, c_sp(ctx));
}

/* int SSL_write(SSL *ssl, const void *buf, int num) and SSL_read(SSL *ssl, void *buf, int num) */
SEC("uprobe")
int up_ssl_write(struct pt_regs *ctx)
{
	ossl_enter(ctx, TLS_FN_WRITE);
	return 0;
}

SEC("uretprobe")
int up_ssl_write_ret(struct pt_regs *ctx)
{
	ossl_exit(ctx, TLS_FN_WRITE, (s32)c_ret(ctx));
	return 0;
}

SEC("uprobe")
int up_ssl_read(struct pt_regs *ctx)
{
	ossl_enter(ctx, TLS_FN_READ);
	return 0;
}

SEC("uretprobe")
int up_ssl_read_ret(struct pt_regs *ctx)
{
	ossl_exit(ctx, TLS_FN_READ, (s32)c_ret(ctx));
	return 0;
}

/* int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written), SSL_read_ex(..., size_t *readbytes) */
static __always_inline s64 ossl_ex_count(struct pt_regs *ctx)
{
	u64 outp = tls_outp(), n = 0;

	if ((s32)c_ret(ctx) != 1 || !outp)
		return 0;
	if (bpf_probe_read_user(&n, sizeof(n), (void *)outp))
		return 0;
	return (s64)n;
}

SEC("uprobe")
int up_ssl_write_ex(struct pt_regs *ctx)
{
	ossl_enter(ctx, TLS_FN_WRITE_EX);
	return 0;
}

SEC("uretprobe")
int up_ssl_write_ex_ret(struct pt_regs *ctx)
{
	ossl_exit(ctx, TLS_FN_WRITE_EX, ossl_ex_count(ctx));
	return 0;
}

SEC("uprobe")
int up_ssl_read_ex(struct pt_regs *ctx)
{
	ossl_enter(ctx, TLS_FN_READ_EX);
	return 0;
}

SEC("uretprobe")
int up_ssl_read_ex_ret(struct pt_regs *ctx)
{
	ossl_exit(ctx, TLS_FN_READ_EX, ossl_ex_count(ctx));
	return 0;
}

/* ossl_ssize_t SSL_sendfile(SSL *s, int fd, off_t offset, size_t size, int flags) */
SEC("uprobe")
int up_ssl_sendfile(struct pt_regs *ctx)
{
	ossl_enter(ctx, TLS_FN_SENDFILE);
	return 0;
}

SEC("uretprobe")
int up_ssl_sendfile_ret(struct pt_regs *ctx)
{
	ossl_exit(ctx, TLS_FN_SENDFILE, (s64)c_ret(ctx));
	return 0;
}

#endif
