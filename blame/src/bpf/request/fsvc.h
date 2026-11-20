/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Waits for a file service: a file that a server or another process keeps,
 * reached through a path like any other (NFS, SMB, FUSE, virtiofs, 9p,
 * Ceph). A thread waiting on one is not waiting for this machine's disk,
 * but the kernel often marks the sleep as such: the NFS client waits for
 * its pages in io_schedule() like a local filesystem. So the thread is
 * marked (carrier.in_fsvc) while it is inside a function that waits, where
 * what is waited for is known, and its sleeps there count as SEG_BLK_FSVC
 * (wake.h).
 *
 * Where (measured on NFS 4.2 and virtiofs):
 * - reads and writes, in the file service's own read and write functions
 *   (nfs_file_read, fuse_file_write_iter, ...), and page faults on a mapping
 *   of a file on such a filesystem (filemap_fault). A write takes the file's
 *   lock: a thread waiting for it while another one writes or flushes the
 *   same file waits for the service too;
 * - waits on a page of such a file outside of those: writeback (fsync),
 *   page locks (folio_wait_bit and its kin);
 * - an NFS client waiting for a reply (rpc_wait_bit_killable in sunrpc:
 *   open, stat, create, commit, locks) or for a direct read or write
 *   (nfs_direct_wait);
 * - a FUSE request waiting for its daemon (request_wait_answer; virtiofs
 *   too);
 * - flushes (fsync and the like): marked in wake.h, with the flushes to a
 *   disk.
 * Of those waits, the ones for a lock are told apart (FSVC_LOCK_HOOK below).
 * Functions that are not in this kernel (a module not loaded) are left
 * out by user space.
 *
 * Which filesystems: by the name of their type, looked at once per
 * filesystem (SB_KIND).
 */
#ifndef BLAME_REQUEST_FSVC_H
#define BLAME_REQUEST_FSVC_H

enum { FSVC_UNKNOWN = 0, FSVC_YES = 1, FSVC_NO = 2 };

#define FS_NAME_LEN 16

/* Whether a filesystem type is a file service, by its name. */
static __always_inline bool fsvc_name(const char *n)
{
	/* nfs, nfs4 */
	if (n[0] == 'n' && n[1] == 'f' && n[2] == 's' && (n[3] == 0 || (n[3] == '4' && n[4] == 0)))
		return true;
	/* cifs, smb3 */
	if (n[0] == 'c' && n[1] == 'i' && n[2] == 'f' && n[3] == 's' && n[4] == 0)
		return true;
	if (n[0] == 's' && n[1] == 'm' && n[2] == 'b' && n[3] == '3' && n[4] == 0)
		return true;
	/* fuse, fuseblk: a daemon answers */
	if (n[0] == 'f' && n[1] == 'u' && n[2] == 's' && n[3] == 'e' && (n[4] == 0 || n[4] == 'b'))
		return true;
	/* virtiofs: the host answers */
	if (n[0] == 'v' && n[1] == 'i' && n[2] == 'r' && n[3] == 't' && n[4] == 'i' && n[5] == 'o' &&
	    n[6] == 'f' && n[7] == 's' && n[8] == 0)
		return true;
	/* 9p, ceph */
	if (n[0] == '9' && n[1] == 'p' && n[2] == 0)
		return true;
	return n[0] == 'c' && n[1] == 'e' && n[2] == 'p' && n[3] == 'h' && n[4] == 0;
}

static __always_inline bool sb_fsvc(struct super_block *sb)
{
	u64 key = (u64)sb;
	u8 *known, kind;
	char name[FS_NAME_LEN] = {};
	const char *type_name;

	if (!sb)
		return false;
	known = bpf_map_lookup_elem(&SB_KIND, &key);
	if (known)
		return *known == FSVC_YES;
	type_name = BPF_CORE_READ(sb, s_type, name);
	if (!type_name || bpf_probe_read_kernel_str(name, sizeof(name), type_name) < 0)
		return false;
	kind = fsvc_name(name) ? FSVC_YES : FSVC_NO;
	bpf_map_update_elem(&SB_KIND, &key, &kind, BPF_ANY);
	return kind == FSVC_YES;
}

static __always_inline bool file_fsvc(struct file *file)
{
	struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : NULL;

	return inode && sb_fsvc(BPF_CORE_READ(inode, i_sb));
}

/* Anonymous memory has no filesystem, and its mapping field is not one. */
static __always_inline bool folio_fsvc(struct folio *folio)
{
	/* Read as a number: the verifier allows no bit tests on a pointer. */
	u64 mapping = folio ? (u64)BPF_CORE_READ(folio, mapping) : 0;
	struct inode *host;

	if (!mapping || (mapping & PAGE_MAPPING_ANON))
		return false;
	host = BPF_CORE_READ((struct address_space *)mapping, host);
	return host && sb_fsvc(BPF_CORE_READ(host, i_sb));
}

/*
 * The hooks: on every function an fentry and an fexit program, made by
 * FSVC_HOOK below. Not kprobe and kretprobe: a kretprobe has a fixed number
 * of returns it can be waiting for at once (maxactive, 12 on a 6-CPU
 * machine), and a return it misses leaves the thread marked for good: with
 * 32 threads writing one file, the sleeps of requests that never touched a
 * file were counted as file-service waits (38.7 s). An fexit is never
 * missed. What the first argument tells:
 */
enum {
	/* A page: waits on a page of a file service's file (folio_wait_bit, ...). */
	FSVC_ARG_FOLIO = 1,
	/* A page fault (filemap_fault): on a mapping of a file service's file. */
	FSVC_ARG_FAULT = 2,
	/* Nothing to look at: the function only ever waits for a file service. */
	FSVC_ALWAYS = 3,
};

/*
 * At return what entry decided is kept per depth (carrier.fsvc_levels): the
 * argument may have changed meanwhile (a page taken from its file). A return
 * whose entry was not seen (the agent attached in between) finds the depth
 * at 0 and does nothing.
 */
#define FSVC_DEPTH_MAX 32

static __always_inline int fsvc_enter(u64 how, u64 arg)
{
	struct carrier *cr = bpf_task_storage_get(&REQ_CARRIER, bpf_get_current_task_btf(), 0, 0);
	bool waits;

	if (!cr)
		return 0;
	if (cr->fsvc_depth >= FSVC_DEPTH_MAX) {
		cr->fsvc_depth++;
		return 0;
	}
	if (how == FSVC_ALWAYS)
		waits = true;
	else if (how == FSVC_ARG_FOLIO)
		waits = folio_fsvc((struct folio *)arg);
	else if (how == FSVC_ARG_FAULT)
		waits = arg && file_fsvc(BPF_CORE_READ((struct vm_fault *)arg, vma, vm_file));
	else
		waits = false;
	if (waits) {
		cr->fsvc_levels |= 1u << cr->fsvc_depth;
		if (cr->in_fsvc < 255)
			cr->in_fsvc++;
	}
	cr->fsvc_depth++;
	return 0;
}

static __always_inline int fsvc_leave(void)
{
	struct carrier *cr = bpf_task_storage_get(&REQ_CARRIER, bpf_get_current_task_btf(), 0, 0);
	u32 depth;

	if (!cr || !cr->fsvc_depth)
		return 0;
	depth = --cr->fsvc_depth;
	if (depth < FSVC_DEPTH_MAX && (cr->fsvc_levels & (1u << depth))) {
		cr->fsvc_levels &= ~(1u << depth);
		if (cr->in_fsvc)
			cr->in_fsvc--;
	}
	return 0;
}

/*
 * Programs named req_fsvc_<function> (entry) and req_fsvcx_<function>
 * (return). Those in modules (sunrpc, nfs, fuse, cifs, 9p, ceph) are loaded
 * only when the module is (user space, slow/attach.rs).
 */
#define FSVC_HOOK(fn, how)                                                     \
	SEC("fentry/" #fn)                                                     \
	int BPF_PROG(req_fsvc_##fn, u64 arg)                                   \
	{                                                                      \
		return fsvc_enter(how, arg);                                   \
	}                                                                      \
	SEC("fexit/" #fn)                                                      \
	int BPF_PROG(req_fsvcx_##fn)                                           \
	{                                                                      \
		return fsvc_leave();                                           \
	}

/* Waits on a page of a file, by the file's filesystem. */
FSVC_HOOK(folio_wait_bit, FSVC_ARG_FOLIO)
FSVC_HOOK(folio_wait_bit_killable, FSVC_ARG_FOLIO)
FSVC_HOOK(folio_wait_writeback, FSVC_ARG_FOLIO)
FSVC_HOOK(__folio_lock, FSVC_ARG_FOLIO)
FSVC_HOOK(__folio_lock_killable, FSVC_ARG_FOLIO)
/* Page faults on a mapping of a file. */
FSVC_HOOK(filemap_fault, FSVC_ARG_FAULT)
/* NFS: a reply to an RPC, a direct read or write; its reads and writes. */
FSVC_HOOK(rpc_wait_bit_killable, FSVC_ALWAYS)
FSVC_HOOK(nfs_direct_wait, FSVC_ALWAYS)
FSVC_HOOK(nfs_file_read, FSVC_ALWAYS)
FSVC_HOOK(nfs_file_write, FSVC_ALWAYS)
/* FUSE, virtiofs: a request to the daemon; reads and writes. */
FSVC_HOOK(request_wait_answer, FSVC_ALWAYS)
FSVC_HOOK(fuse_file_read_iter, FSVC_ALWAYS)
FSVC_HOOK(fuse_file_write_iter, FSVC_ALWAYS)
/* SMB, 9p, Ceph: reads and writes (not tested). */
FSVC_HOOK(cifs_strict_readv, FSVC_ALWAYS)
FSVC_HOOK(cifs_loose_read_iter, FSVC_ALWAYS)
FSVC_HOOK(cifs_strict_writev, FSVC_ALWAYS)
FSVC_HOOK(cifs_file_write_iter, FSVC_ALWAYS)
FSVC_HOOK(v9fs_file_read_iter, FSVC_ALWAYS)
FSVC_HOOK(v9fs_file_write_iter, FSVC_ALWAYS)
FSVC_HOOK(ceph_read_iter, FSVC_ALWAYS)
FSVC_HOOK(ceph_write_iter, FSVC_ALWAYS)

/*
 * Locks: a thread inside one of these sleeps for a lock someone else holds.
 * In a file service's call, its sleeps there count as SEG_BLK_FSVC_LOCK
 * (wake.h): on virtiofs with 16 threads writing and flushing one file, 95%
 * of the wait for the service was for the file's lock (i_rwsem, taken by
 * fuse_cache_write_iter and fuse_fsync), held by another thread's write or
 * flush. Only contended locks get here, so these run rarely. Optimistic
 * spinning in them is time on a CPU, as before.
 */
static __always_inline int lock_step(bool enter)
{
	struct carrier *cr = bpf_task_storage_get(&REQ_CARRIER, bpf_get_current_task_btf(), 0, 0);

	if (!cr)
		return 0;
	if (enter) {
		if (cr->in_lock < 255)
			cr->in_lock++;
	} else if (cr->in_lock) {
		/* A return whose entry was not seen (attached in between) finds 0. */
		cr->in_lock--;
	}
	return 0;
}

#define FSVC_LOCK_HOOK(fn)                                                     \
	SEC("fentry/" #fn)                                                     \
	int BPF_PROG(req_fsvc_##fn)                                            \
	{                                                                      \
		return lock_step(true);                                        \
	}                                                                      \
	SEC("fexit/" #fn)                                                      \
	int BPF_PROG(req_fsvcx_##fn)                                           \
	{                                                                      \
		return lock_step(false);                                       \
	}

/* Read-write semaphores (a file's i_rwsem) and mutexes. */
FSVC_LOCK_HOOK(rwsem_down_write_slowpath)
FSVC_LOCK_HOOK(rwsem_down_read_slowpath)
FSVC_LOCK_HOOK(__mutex_lock_slowpath)
FSVC_LOCK_HOOK(__mutex_lock_killable_slowpath)
FSVC_LOCK_HOOK(__mutex_lock_interruptible_slowpath)

#endif
