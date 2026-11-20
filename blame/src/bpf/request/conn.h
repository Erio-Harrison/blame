/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/* Sockets of traced processes and the connections followed on them. */
#ifndef BLAME_REQUEST_CONN_H
#define BLAME_REQUEST_CONN_H

static __always_inline bool traced(u32 tgid)
{
	return bpf_map_lookup_elem(&REQ_PROCS, &tgid) != NULL;
}

/* A process found by what it does; user space looks at its binary later. */
static __always_inline bool trace_proc(u32 tgid)
{
	struct proc_cfg cfg = {};
	long err = bpf_map_update_elem(&REQ_PROCS, &tgid, &cfg, BPF_NOEXIST);

	if (!err)
		__sync_fetch_and_or(&proc_bits[(tgid % PROC_BITS) / 64], 1ULL << (tgid % 64));
	return !err || err == -EEXIST;
}

/* The file behind an fd of the current process, by walking its fd table. */
static __always_inline struct file *fd_file(int fd)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(task, files, fdt);
	unsigned int max = BPF_CORE_READ(fdt, max_fds);
	struct file **slots, *file;

	if (fd < 0 || (unsigned int)fd >= max)
		return NULL;
	slots = BPF_CORE_READ(fdt, fd);
	if (bpf_probe_read_kernel(&file, sizeof(file), &slots[fd]))
		return NULL;
	return file;
}

/* The TCP socket behind an fd of the current process. */
static __always_inline struct sock *fd_to_sk(int fd)
{
	struct file *file = fd_file(fd);
	struct socket *sock;
	struct sock *sk;

	if (!file)
		return NULL;
	if ((const void *)BPF_CORE_READ(file, f_op) != &socket_file_ops)
		return NULL;
	sock = BPF_CORE_READ(file, private_data);
	sk = BPF_CORE_READ(sock, sk);
	if (!sk || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP)
		return NULL;
	return sk;
}

/*
 * Start tracking a connection. `cls` 0 means it was open before it was first
 * seen: it is classified by its local port, and its parsers wait for a
 * message start.
 */
static __always_inline struct conn *conn_new(struct sock *sk, u8 cls)
{
	u64 key = (u64)sk;
	u32 zero = 0;
	struct conn *c = bpf_map_lookup_elem(&REQ_SCRATCH_CONN, &zero);

	if (!c)
		return NULL;
	__builtin_memset(c, 0, sizeof(*c));
	c->tgid = cur_pid_tgid() >> 32;
	c->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	c->rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	if (cls) {
		c->cls = cls;
		c->fresh = 1;
		c->rx.st = HS_START;
		c->tx.st = HS_START;
	} else {
		struct listen_key lk = {};

		lk.netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
		lk.port = c->lport;
		c->cls = bpf_map_lookup_elem(&REQ_LISTEN, &lk) ? CONN_CLIENT : CONN_DOWN;
		c->rx.st = HS_UNSYNC;
		c->tx.st = HS_UNSYNC;
	}
	if (bpf_map_update_elem(&REQ_CONNS, &key, c, BPF_ANY)) {
		bump(REQ_CONN_INSERT_FAILED);
		return NULL;
	}
	return bpf_map_lookup_elem(&REQ_CONNS, &key);
}

#endif
