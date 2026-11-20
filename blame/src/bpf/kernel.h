/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * The few kernel types the programs need, instead of a generated vmlinux.h.
 *
 * The structs list only the fields that are read. Their layout here is
 * irrelevant: `preserve_access_index` makes every access a CO-RE relocation,
 * which libbpf resolves by name against the running kernel's BTF at load time.
 * A field that is missing or has changed type fails the load instead of
 * reading the wrong bytes, unless the access is guarded by
 * bpf_core_field_exists().
 */
#ifndef BLAME_KERNEL_H
#define BLAME_KERNEL_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;
typedef unsigned long size_t;
typedef int pid_t;
typedef _Bool bool;
#define true 1
#define false 0

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
};

enum {
	BPF_F_NO_PREALLOC = 1,
	BPF_LOCAL_STORAGE_GET_F_CREATE = 1,
	BPF_RB_NO_WAKEUP = 1,
	BPF_RB_FORCE_WAKEUP = 2,
	BPF_RB_AVAIL_DATA = 0,
};

#define IPPROTO_TCP 6
#define TCP_LISTEN 10
#define EAGAIN 11
#define EEXIST 17
#define EINPROGRESS 115
#define MSG_PEEK 2
#define TASK_INTERRUPTIBLE 1

/* User-space ABI of the vectored calls; fixed, so not relocated. */
struct iovec {
	void *iov_base;
	size_t iov_len;
};

struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	size_t msg_iovlen;
	void *msg_control;
	size_t msg_controllen;
	unsigned int msg_flags;
};

/* What bpf_get_ns_current_pid_tgid() fills in; BPF ABI, so not relocated. */
struct bpf_pidns_info {
	__u32 pid;
	__u32 tgid;
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

struct trace_event_raw_sched_process_exec {
	u32 __data_loc_filename;
	pid_t old_pid;
};

/* A CPU's run queue: its clock, as the scheduler last read it. */
struct rq {
	u64 clock;
};

/*
 * A control group's queue on one CPU (only with group scheduling). The two
 * clocks, since 6.6: since when the queue has been throttled by a CPU limit
 * with threads queued in it (0: it is not), and how long that has been so
 * in all. A limit on a group above counts too.
 */
struct cfs_rq {
	struct rq *rq;
	u64 throttled_clock_self;
	u64 throttled_clock_self_time;
};

struct task_group {
	struct cfs_rq **cfs_rq;
};

struct sched_entity {
	/* The queue the thread is in, or was last in. */
	struct cfs_rq *cfs_rq;
	/* Only on kernels with delayed dequeue (6.12+). */
	unsigned char sched_delayed;
};

struct ns_common {
	unsigned int inum;
};

struct net {
	struct ns_common ns;
};

typedef struct {
	struct net *net;
} possible_net_t;

struct sock_common {
	__be16 skc_dport;
	__u16 skc_num;
	volatile unsigned char skc_state;
	possible_net_t skc_net;
};

struct sock {
	struct sock_common __sk_common;
	u16 sk_protocol;
};

struct socket {
	struct sock *sk;
};

/* A TCP socket starts with its struct sock. */
struct tcp_sock {
	u32 rcv_nxt;
	u32 copied_seq;
};

struct file_operations;

struct file_system_type {
	const char *name;
	int fs_flags;
};

struct super_block {
	struct file_system_type *s_type;
};

struct inode {
	struct super_block *i_sb;
};

struct file {
	const struct file_operations *f_op;
	void *private_data;
	struct inode *f_inode;
};

/* The filesystem keeps its data on a block device (not NFS, FUSE, tmpfs, overlayfs). */
#define FS_REQUIRES_DEV 1

struct vm_area_struct {
	struct file *vm_file;
};

/* A page fault on a mapping; `vma` sits in an anonymous struct, which CO-RE sees through. */
struct vm_fault {
	struct vm_area_struct *vma;
};

struct address_space {
	struct inode *host;
};

/* A page of a file; `mapping` has its low bit set for anonymous memory. */
struct folio {
	struct address_space *mapping;
};
#define PAGE_MAPPING_ANON 1

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
};

struct files_struct {
	struct fdtable *fdt;
};

/* Only where the preempt count is kept per thread (arm64); x86 keeps it per CPU. */
struct thread_info {
	u64 preempt_count;
	/* The CPU the thread is on, or queued on (since 5.16). */
	u32 cpu;
};

/* User registers saved at kernel entry. arm64 names them by number... */
struct pt_regs {
	u64 regs[31];
	u64 pc;
};

/* ... x86_64 by name. */
struct pt_regs___x86 {
	unsigned long r14;
	unsigned long ax;
	unsigned long bx;
	unsigned long cx;
	unsigned long dx;
	unsigned long di;
	unsigned long si;
	unsigned long ip;
};

/* Where a thread's TLS starts: arm64 keeps the thread pointer here... */
struct thread_struct {
	struct {
		unsigned long tp_value;
	} uw;
};

/* ... x86_64 here. */
struct thread_struct___x86 {
	unsigned long fsbase;
};

struct task_struct {
	struct thread_info thread_info;
	struct thread_struct thread;
	unsigned int __state;
	int on_cpu;
	int on_rq;
	struct sched_entity se;
	struct task_group *sched_task_group;
	/* SCHED_NORMAL 0, FIFO 1, RR 2, BATCH 3, IDLE 5, DEADLINE 6. */
	unsigned int policy;
	pid_t pid;
	pid_t tgid;
	struct files_struct *files;
	/* Asleep in io_schedule(), or with an io_uring request in flight. */
	unsigned int in_iowait : 1;
	/* Stalled on memory: reclaim, throttling, refault. Only with CONFIG_PSI. */
	unsigned int in_memstall : 1;
	struct css_set *cgroups;
};

/* A task's cgroup v2 id: task->cgroups->dfl_cgrp->kn->id, as bpf_get_current_cgroup_id(). */
struct kernfs_node {
	u64 id;
};

struct cgroup {
	struct kernfs_node *kn;
};

struct css_set {
	struct cgroup *dfl_cgrp;
};

struct trace_event_raw_sys_enter {
	long id;
	unsigned long args[6];
};

struct trace_event_raw_sys_exit {
	long id;
	long ret;
};

/* Before 5.16 the CPU a thread is on was kept here. */
struct task_struct___pre516 {
	unsigned int cpu;
};

/* Before 5.14 the state field was `long state`. */
struct task_struct___pre514 {
	long state;
};

/* cgroup_mkdir */
struct trace_event_raw_cgroup {
	int root;
	u64 id;
	u32 __data_loc_path;
};

#pragma clang attribute pop

#endif
