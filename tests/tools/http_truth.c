// HTTP/1.1 servers that know the answer: each logs, for every request, when
// its first byte was read and its last response byte written, how much CPU
// the thread serving it used, and what every blocking call was waiting for.
// `blame slow` is checked against that log (tests/scenarios/m4_acceptance.sh).
// Times are CLOCK_BOOTTIME, the clock the kernel side stamps events with.
//
//   http_truth MODE PORT LOGFILE [opts]
//     MODE: tpc   thread per connection (read/write/writev)
//           epoll single-thread epoll loop (recv/send), async downstream
//           pool  acceptor thread (epoll + recvmsg) + N workers (sendmsg)
//     opts: -b PORT   downstream backend port (requests with d=US go there)
//           -w N      workers for pool (default 4)
//
// Query parameters on the request path:
//   size=N  body bytes   chunked=1   status=N   wchunk=N (bytes per write)
//   cpu=US  spin         sleep=US    d=US (downstream call, backend sleeps US)
//   wgap=US pause between writes (blocks the thread: for the backend)
//   dchunk=N, dgap=US    the backend answers the downstream call N bytes per
//                        write, pausing US between writes
//   io=KB   read KB from a file, bypassing the page cache (tpc only)
//   fsync=KB append KB to a file and flush it to disk (tpc only); how=0 fsync
//           (default), 1 fdatasync, 2 a write with O_DSYNC, 3 syncfs;
//           shared=1: all threads write and flush one file (they wait for
//           each other's lock on it), each in a 1 MB slot of its own
//   rd=KB   read KB through the page cache, dropped from it first (tpc only)
//   mm=KB   touch KB of a mapping of a file, dropped from the page cache and
//           unmapped first: page faults (tpc only)
//   st=N    stat a file N times (tpc only)
//   The files for io, fsync, rd, mm and st are next to the log. Where that is
//   a file service (NFS, SMB, FUSE, virtiofs, 9p, Ceph), the waits are logged
//   as such (L_FSVC), else as disk waits (L_IO).
//   mem=KB  map, touch and unmap KB of memory (tpc only); it stalls when the
//           server runs in a cgroup held below its memory.high
//   omp=N   an OpenMP parallel region of N threads, the handler's among them,
//           each computing ocpu=US; oreg=K: K regions one after another
//           (tpc only, built with -fopenmp). What the other threads computed
//           is logged apart (R_HELP), as the Go and tokio servers log what
//           spawned units did. oq=1: also how long they waited for a CPU
//           (R_POOL), from /proc/thread-self/schedstat read around each piece
//           of work: inside the pieces (they were preempted), and between one
//           piece and the next (waiting to start, and on the way back to idle).
//
// Log: binary records (struct rec), written out on SIGTERM or SIGINT and read
// by tests/scenarios/workloads/http_check.py.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>
#ifdef _OPENMP
#include <omp.h>
#endif

// 4 and 5 are the Go and tokio servers' (go_truth, tokio_truth).
enum { R_REQ = 1, R_BLK = 2, R_HELP = 3, R_POOL = 6 };
enum { L_IDLE = 1, L_DOWN = 2, L_CLIENT = 3, L_WAKE_CLIENT = 4, L_SLEEP = 5, L_WRITE = 6, L_IO = 7, L_MEM = 8, L_FSVC = 9 };
enum { F_HEAD = 1, F_CHUNKED = 2, F_100 = 4, F_DOWN = 8, F_CLOSE = 16 };

struct rec {
    uint8_t type, label;
    uint16_t flags;
    uint32_t tid;
    uint64_t t0, t1;       // req: first byte read, last byte written; blk: interval
    uint32_t port, seq;    // client port and per-connection seq (blk: req it is for)
    uint64_t cpu_ns;       // req: thread CPU spent serving it, reads excluded
    uint64_t blk_ns;       // req: worker blocked ns (sleep + downstream)
    uint64_t t_deq;        // req: dequeue time (pool), downstream send ts
    uint64_t t_down_end;   // req: downstream response complete
    uint32_t tid_read, outstanding;
};

static struct rec *LOG;
static uint64_t LOG_N, LOG_CAP = 4u << 20;
static const char *LOG_PATH;
static int BACKEND_PORT = 0;
static const char *MODE;

static inline uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_BOOTTIME, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}
static inline uint64_t cpu_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}
static inline uint32_t gettid_(void) { return syscall(SYS_gettid); }

static struct rec *log_new(void) {
    uint64_t i = __atomic_fetch_add(&LOG_N, 1, __ATOMIC_RELAXED);
    if (i >= LOG_CAP) return NULL;
    return &LOG[i];
}
static void log_blk(int label, uint64_t t0, uint64_t t1, uint32_t port, uint32_t seq, uint32_t outst) {
    struct rec *r = log_new();
    if (!r) return;
    *r = (struct rec){.type = R_BLK, .label = label, .tid = gettid_(), .t0 = t0, .t1 = t1,
                      .port = port, .seq = seq, .outstanding = outst};
}

static void dump_and_exit(int sig) {
    (void)sig;
    FILE *f = fopen(LOG_PATH, "w");
    uint64_t n = LOG_N < LOG_CAP ? LOG_N : LOG_CAP;
    if (f) { fwrite(LOG, sizeof(struct rec), n, f); fclose(f); }
    _exit(0);
}

/* ---------------- request parsing ---------------- */

struct req {
    int head, close, expect100, chunked, status;
    long clen, size, wchunk, wgap_us, cpu_us, sleep_us, down_us, down_chunk, down_gap_us, io_kb, mem_kb, sync_kb, sync_how, sync_shared,
        rd_kb, mm_kb, st_n, omp_n, omp_us, omp_regions, omp_waits;
    size_t hdr_len;            // bytes of start line + headers
};

static long qparam(const char *path, size_t plen, const char *name) {
    size_t nl = strlen(name);
    const char *q = memchr(path, '?', plen);
    if (!q) return -1;
    const char *p = q + 1, *end = path + plen;
    while (p < end) {
        if ((size_t)(end - p) > nl && !memcmp(p, name, nl) && p[nl] == '=') return atol(p + nl + 1);
        const char *a = memchr(p, '&', end - p);
        if (!a) break;
        p = a + 1;
    }
    return -1;
}

static const char *memmem_(const char *h, size_t hl, const char *n) { return memmem(h, hl, n, strlen(n)); }

// Returns 1 when the headers are complete (fills r), 0 if more bytes needed, -1 on error.
static int parse_req(const char *b, size_t n, struct req *r) {
    const char *e = memmem_(b, n, "\r\n\r\n");
    if (!e) return n > 65536 ? -1 : 0;
    memset(r, 0, sizeof(*r));
    r->hdr_len = e - b + 4;
    const char *sp = memchr(b, ' ', r->hdr_len);
    if (!sp) return -1;
    r->head = (sp - b == 4 && !memcmp(b, "HEAD", 4));
    const char *path = sp + 1, *sp2 = memchr(path, ' ', b + r->hdr_len - path);
    if (!sp2) return -1;
    size_t plen = sp2 - path;
    r->size = qparam(path, plen, "size"); if (r->size < 0) r->size = 64;
    r->chunked = qparam(path, plen, "chunked") > 0;
    r->status = qparam(path, plen, "status"); if (r->status < 0) r->status = 200;
    r->wchunk = qparam(path, plen, "wchunk");
    r->cpu_us = qparam(path, plen, "cpu");
    r->sleep_us = qparam(path, plen, "sleep");
    r->down_us = qparam(path, plen, "d");
    r->wgap_us = qparam(path, plen, "wgap");
    r->down_chunk = qparam(path, plen, "dchunk");
    r->down_gap_us = qparam(path, plen, "dgap");
    r->io_kb = qparam(path, plen, "io");
    r->mem_kb = qparam(path, plen, "mem");
    r->sync_kb = qparam(path, plen, "fsync");
    r->sync_how = qparam(path, plen, "how"); if (r->sync_how < 0) r->sync_how = 0;
    r->sync_shared = qparam(path, plen, "shared") > 0;
    r->rd_kb = qparam(path, plen, "rd");
    r->mm_kb = qparam(path, plen, "mm");
    r->st_n = qparam(path, plen, "st");
    r->omp_n = qparam(path, plen, "omp");
    r->omp_us = qparam(path, plen, "ocpu");
    r->omp_regions = qparam(path, plen, "oreg");
    r->omp_waits = qparam(path, plen, "oq");
    // headers (case-insensitive)
    const char *p = memchr(b, '\n', r->hdr_len) + 1;
    while (p < b + r->hdr_len - 2) {
        const char *eol = memchr(p, '\n', b + r->hdr_len - p);
        if (!eol) break;
        size_t ll = eol - p;
        if (ll > 15 && !strncasecmp(p, "content-length:", 15)) r->clen = atol(p + 15);
        else if (ll > 11 && !strncasecmp(p, "connection:", 11) && memmem_(p, ll, "close")) r->close = 1;
        else if (ll > 7 && !strncasecmp(p, "expect:", 7) && memmem_(p, ll, "100-continue")) r->expect100 = 1;
        p = eol + 1;
    }
    return 1;
}

/* ---------------- per-connection read buffer with read timestamps ---------------- */

#define RING 256
struct conn {
    int fd;
    uint32_t port, seq;
    char *buf;
    size_t len, cap;
    uint64_t base;               // absolute stream offset of buf[0]
    uint64_t seg_end[RING], seg_ts[RING];
    unsigned nseg;
    // epoll mode state
    int busy;                    // waiting for downstream
    struct req cur;
    uint64_t cur_start;
    uint64_t cur_cpu;            // thread CPU spent on the current request so far
    int sent100;
    void *down;
};

static void conn_init(struct conn *c, int fd) {
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->cap = 1 << 16;
    c->buf = malloc(c->cap);
    struct sockaddr_in a; socklen_t al = sizeof(a);
    getpeername(fd, (struct sockaddr *)&a, &al);
    c->port = ntohs(a.sin_port);
}
static void conn_free(struct conn *c) { free(c->buf); }

static void conn_got(struct conn *c, size_t n, uint64_t ts) {
    c->len += n;
    c->seg_end[c->nseg % RING] = c->base + c->len;
    c->seg_ts[c->nseg % RING] = ts;
    c->nseg++;
}
static uint64_t ts_of(struct conn *c, uint64_t off) {
    unsigned lo = c->nseg > RING ? c->nseg - RING : 0;
    for (unsigned i = lo; i < c->nseg; i++)
        if (c->seg_end[i % RING] > off) return c->seg_ts[i % RING];
    return 0;
}
static void conn_consume(struct conn *c, size_t n) {
    memmove(c->buf, c->buf + n, c->len - n);
    c->len -= n;
    c->base += n;
}
static void conn_room(struct conn *c) {
    if (c->cap - c->len < 16384) { c->cap *= 2; c->buf = realloc(c->buf, c->cap); }
}

/* ---------------- response ---------------- */

static char BODY[1 << 20];

typedef ssize_t (*writefn)(int fd, const struct iovec *iov, int n);

static ssize_t w_writev(int fd, const struct iovec *iov, int n) { return writev(fd, iov, n); }
static ssize_t w_send(int fd, const struct iovec *iov, int n) {
    // flatten into send() calls (sendto syscall)
    ssize_t tot = 0;
    for (int i = 0; i < n; i++) {
        size_t off = 0;
        while (off < iov[i].iov_len) {
            ssize_t r = send(fd, (char *)iov[i].iov_base + off, iov[i].iov_len - off, MSG_NOSIGNAL);
            if (r < 0) {
                if (errno == EAGAIN) {
                    struct pollfd p = {.fd = fd, .events = POLLOUT};
                    uint64_t t0 = now_ns();
                    poll(&p, 1, -1);
                    log_blk(L_WRITE, t0, now_ns(), 0, 0, 0);
                    continue;
                }
                return -1;
            }
            off += r; tot += r;
        }
    }
    return tot;
}
static ssize_t w_sendmsg(int fd, const struct iovec *iov, int n) {
    struct msghdr m = {.msg_iov = (struct iovec *)iov, .msg_iovlen = n};
    return sendmsg(fd, &m, MSG_NOSIGNAL);
}
// Write everything (handles partial writes for blocking-ish writers).
static int write_all(writefn wf, int fd, struct iovec *iov, int n) {
    while (n > 0) {
        ssize_t r = wf(fd, iov, n);
        if (r < 0) return -1;
        while (n > 0 && (size_t)r >= iov->iov_len) { r -= iov->iov_len; iov++; n--; }
        if (n > 0) { iov->iov_base = (char *)iov->iov_base + r; iov->iov_len -= r; }
    }
    return 0;
}

static const char *reason(int s) {
    switch (s) { case 200: return "OK"; case 204: return "No Content"; case 304: return "Not Modified";
    case 404: return "Not Found"; default: return "X"; }
}

// Writes the response; returns timestamp after the last write, 0 on error.
static uint64_t respond(writefn wf, int fd, struct req *r) {
    char hdr[512];
    int bodyless = r->head || r->status == 204 || r->status == 304;
    long size = r->size > (long)sizeof(BODY) ? (long)sizeof(BODY) : r->size;
    int hl;
    if (r->chunked && !bodyless)
        hl = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\nServer: gt\r\nTransfer-Encoding: chunked\r\n%s\r\n",
                      r->status, reason(r->status), r->close ? "Connection: close\r\n" : "");
    else if (r->status == 204 || r->status == 304)
        hl = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\nServer: gt\r\n%s\r\n", r->status,
                      reason(r->status), r->close ? "Connection: close\r\n" : "");
    else
        hl = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\nServer: gt\r\nContent-Length: %ld\r\n%s\r\n",
                      r->status, reason(r->status), size, r->close ? "Connection: close\r\n" : "");
    if (bodyless) {
        struct iovec v = {hdr, hl};
        if (write_all(wf, fd, &v, 1)) return 0;
        return now_ns();
    }
    long wch = r->wchunk > 0 ? r->wchunk : size;
    if (wch <= 0) wch = 1;
    if (!r->chunked) {
        // first write: headers + first piece
        long first = size < wch ? size : wch;
        struct iovec v[2] = {{hdr, hl}, {BODY, first}};
        if (write_all(wf, fd, v, first ? 2 : 1)) return 0;
        long off = first;
        while (off < size) {
            long k = size - off < wch ? size - off : wch;
            struct iovec b = {BODY + off, k};
            if (r->wgap_us > 0) usleep(r->wgap_us);
            if (write_all(wf, fd, &b, 1)) return 0;
            off += k;
        }
        return now_ns();
    }
    struct iovec h = {hdr, hl};
    if (write_all(wf, fd, &h, 1)) return 0;
    long off = 0;
    while (off < size) {
        long k = size - off < wch ? size - off : wch;
        char cl[32];
        int cll = snprintf(cl, sizeof(cl), "%lx\r\n", k);
        struct iovec v[3] = {{cl, cll}, {BODY + off, k}, {"\r\n", 2}};
        if (write_all(wf, fd, v, 3)) return 0;
        off += k;
    }
    struct iovec z = {"0\r\n\r\n", 5};
    if (write_all(wf, fd, &z, 1)) return 0;
    return now_ns();
}

static void spin_us(long us) {
    if (us <= 0) return;
    uint64_t c0 = cpu_ns();
    while (cpu_ns() - c0 < (uint64_t)us * 1000) {}
}
// How long this thread has waited for a CPU so far, as the kernel counts it.
static uint64_t run_delay_ns(void) {
    char b[96] = {0};
    unsigned long long run = 0, delay = 0;
    int fd = open("/proc/thread-self/schedstat", O_RDONLY);
    if (fd < 0) return 0;
    if (read(fd, b, sizeof(b) - 1) > 0) sscanf(b, "%llu %llu", &run, &delay);
    close(fd);
    return delay;
}

// Parallel regions of n threads, each computing `us`. Logged for the request:
// the CPU of the threads other than this one (cpu_ns), how many pieces of
// work they took up (t_deq); and with `waits`, in a record of its own, how
// long they waited for a CPU inside their pieces (cpu_ns) and from one piece
// to the next (blk_ns).
static void omp_work(long n, long us, long regions, long waits, uint32_t port, uint32_t seq) {
#ifdef _OPENMP
    static __thread uint64_t idle_since_delay;
    if (n <= 0) return;
    uint64_t help = 0, pieces = 0, inside = 0, between = 0;
    for (long k = 0; k < (regions > 0 ? regions : 1); k++) {
        #pragma omp parallel num_threads(n) reduction(+ : help, pieces, inside, between)
        {
            int helper = omp_get_thread_num() != 0;
            uint64_t d0 = helper && waits > 0 ? run_delay_ns() : 0;
            uint64_t c0 = cpu_ns();
            spin_us(us);
            if (helper) {
                help += cpu_ns() - c0;
                pieces++;
                if (waits > 0) {
                    uint64_t d1 = run_delay_ns();
                    inside += d1 - d0;
                    // A thread at its first piece was made for this region
                    // (a team that grows gets new threads): all it has waited
                    // since it was created was on its way here.
                    between += d0 - idle_since_delay;
                    idle_since_delay = d1;
                }
            }
        }
    }
    struct rec *x = log_new();
    if (x)
        *x = (struct rec){.type = R_HELP, .tid = gettid_(), .port = port, .seq = seq,
                          .cpu_ns = help, .t_deq = pieces};
    if (waits > 0 && (x = log_new()))
        *x = (struct rec){.type = R_POOL, .tid = gettid_(), .port = port, .seq = seq,
                          .cpu_ns = inside, .blk_ns = between, .t_deq = pieces};
#else
    (void)n; (void)us; (void)regions; (void)waits; (void)port; (void)seq;
#endif
}
static void sleep_us(long us, uint32_t port, uint32_t seq) {
    if (us <= 0) return;
    uint64_t t0 = now_ns();
    struct timespec ts = {us / 1000000, (us % 1000000) * 1000};
    nanosleep(&ts, NULL);
    log_blk(L_SLEEP, t0, now_ns(), port, seq, 0);
}


// What waiting on the file behind `fd` is: a file service or the disk.
static int store_label(int fd) {
    struct statfs fs;
    if (fstatfs(fd, &fs) != 0) return L_IO;
    switch ((unsigned long)fs.f_type) {
    case 0x6969:     // NFS
    case 0x65735546: // FUSE, virtiofs
    case 0xFF534D42: // CIFS
    case 0xFE534D42: // SMB2
    case 0x01021997: // 9p
    case 0x00c36400: // Ceph
        return L_FSVC;
    default:
        return L_IO;
    }
}

// The file next to the log that io, rd, mm and st use, written on first use.
#define IO_FILE_BYTES (8 << 20)
#define IO_CHUNK (1 << 20)
static const char *data_file(void) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static char path[4096];
    pthread_mutex_lock(&lock);
    if (!path[0]) {
        snprintf(path, sizeof(path), "%s.dat", LOG_PATH);
        int w = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        for (long off = 0; w >= 0 && off < IO_FILE_BYTES; off += sizeof(BODY))
            if (write(w, BODY, sizeof(BODY)) < 0) break;
        if (w >= 0) { fsync(w); close(w); }
    }
    pthread_mutex_unlock(&lock);
    return path;
}

// Opens the data file once, `flags` as asked; its label in *label.
static int data_fd(int *fdp, int flags, int *label) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    const char *path = data_file();
    pthread_mutex_lock(&lock);
    if (*fdp < 0) {
        *fdp = open(path, flags);
        if (*fdp < 0) { perror("data file"); exit(1); }
        *label = store_label(*fdp);
    }
    pthread_mutex_unlock(&lock);
    return *fdp;
}

// Reads `kb` from the data file with O_DIRECT, so that every read waits for
// the store.
static void disk_read(long kb, uint32_t port, uint32_t seq) {
    static int fd = -1, label;
    static __thread char *buf;
    if (kb <= 0) return;
    data_fd(&fd, O_RDONLY | O_DIRECT, &label);
    if (!buf && posix_memalign((void **)&buf, 4096, IO_CHUNK)) return;
    long bytes = kb * 1024, off = 0;
    uint64_t t0 = now_ns();
    while (off < bytes) {
        long k = bytes - off < IO_CHUNK ? bytes - off : IO_CHUNK;
        k = (k + 4095) & ~4095L;
        if (pread(fd, buf, k, off % IO_FILE_BYTES) <= 0) break;
        off += k;
    }
    log_blk(label, t0, now_ns(), port, seq, 0);
}

// Reads `kb` of the data file through the page cache, dropped from it first
// (outside the timed part).
static void cached_read(long kb, uint32_t port, uint32_t seq) {
    static int fd = -1, label;
    static __thread char *buf;
    static __thread long at;
    if (kb <= 0) return;
    data_fd(&fd, O_RDONLY, &label);
    if (!buf && !(buf = malloc(IO_CHUNK))) return;
    long bytes = kb * 1024;
    at = (at + bytes) % IO_FILE_BYTES;
    long start = at + bytes > IO_FILE_BYTES ? 0 : at;
    posix_fadvise(fd, start, bytes, POSIX_FADV_DONTNEED);
    uint64_t t0 = now_ns();
    for (long off = 0; off < bytes;) {
        long k = bytes - off < IO_CHUNK ? bytes - off : IO_CHUNK;
        if (pread(fd, buf, k, start + off) <= 0) break;
        off += k;
    }
    log_blk(label, t0, now_ns(), port, seq, 0);
}

// Touches `kb` of a mapping of the data file, a byte a page, after dropping
// that part from the page cache and from this mapping (outside the timed
// part): every touch is a page fault that reads the store.
static void map_read(long kb, uint32_t port, uint32_t seq) {
    static int fd = -1, label;
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static volatile char *map;
    static __thread long at;
    if (kb <= 0) return;
    data_fd(&fd, O_RDONLY, &label);
    pthread_mutex_lock(&lock);
    if (!map) {
        void *m = mmap(NULL, IO_FILE_BYTES, PROT_READ, MAP_SHARED, fd, 0);
        if (m == MAP_FAILED) { perror("map data file"); exit(1); }
        map = m;
    }
    pthread_mutex_unlock(&lock);
    long bytes = kb * 1024;
    at = (at + bytes) % IO_FILE_BYTES;
    long start = (at + bytes > IO_FILE_BYTES ? 0 : at) & ~4095L;
    madvise((void *)(map + start), bytes, MADV_DONTNEED);
    posix_fadvise(fd, start, bytes, POSIX_FADV_DONTNEED);
    uint64_t t0 = now_ns();
    char sink = 0;
    for (long off = 0; off < bytes; off += 4096) sink += map[start + off];
    (void)sink;
    log_blk(label, t0, now_ns(), port, seq, 0);
}

// Looks the data file up `n` times.
static void stat_file(long n, uint32_t port, uint32_t seq) {
    static int fd = -1, label;
    if (n <= 0) return;
    data_fd(&fd, O_RDONLY, &label);
    const char *path = data_file();
    struct stat st;
    uint64_t t0 = now_ns();
    for (long i = 0; i < n; i++) stat(path, &st);
    log_blk(label, t0, now_ns(), port, seq, 0);
}

// Appends `kb` to a file of the thread's own (no lock to wait for) and
// flushes it to disk: how=0 fsync, 1 fdatasync, 2 a write with O_DSYNC,
// 3 syncfs. The whole write-and-flush is logged as a disk wait. The file
// starts over at 32 MB, outside the timed part. With `shared`, the file is
// one for all threads, each writing over a 1 MB slot of its own: the waits
// for the file's lock, held by another thread writing or flushing, are part
// of the logged wait.
#define SYNC_FILE_BYTES (32 << 20)
#define SHARED_SLOT_BYTES (1 << 20)
static void shared_sync(long kb, long how, uint32_t port, uint32_t seq) {
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    static int fds[4] = {-1, -1, -1, -1}, labels[4], slots;
    static __thread long slot = -1, off;
    pthread_mutex_lock(&lock);
    if (fds[how] < 0) {
        char path[4096];
        snprintf(path, sizeof(path), "%s.shared%ld", LOG_PATH, how);
        fds[how] = open(path, O_CREAT | O_TRUNC | O_WRONLY | (how == 2 ? O_DSYNC : 0), 0644);
        if (fds[how] < 0) { perror("sync file"); exit(1); }
        labels[how] = store_label(fds[how]);
    }
    if (slot < 0) slot = slots++;
    int fd = fds[how], label = labels[how];
    pthread_mutex_unlock(&lock);
    long bytes = kb * 1024;
    if (bytes > SHARED_SLOT_BYTES) bytes = SHARED_SLOT_BYTES;
    if (off + bytes > SHARED_SLOT_BYTES) off = 0;
    uint64_t t0 = now_ns();
    for (long done = 0; done < bytes;) {
        long k = bytes - done < (long)sizeof(BODY) ? bytes - done : (long)sizeof(BODY);
        if (pwrite(fd, BODY, k, slot * SHARED_SLOT_BYTES + off + done) <= 0) break;
        done += k;
    }
    if (how == 0) fsync(fd);
    else if (how == 1) fdatasync(fd);
    else if (how == 3) syncfs(fd);
    log_blk(label, t0, now_ns(), port, seq, 0);
    off += bytes;
}

static void disk_sync(long kb, long how, long shared, uint32_t port, uint32_t seq) {
    static __thread int fds[4] = {-1, -1, -1, -1}, labels[4];
    static __thread long off[4];
    if (kb <= 0 || how < 0 || how > 3) return;
    if (shared) {
        shared_sync(kb, how, port, seq);
        return;
    }
    if (fds[how] < 0) {
        char path[4096];
        snprintf(path, sizeof(path), "%s.sync%ld.%d", LOG_PATH, how, gettid_());
        fds[how] = open(path, O_CREAT | O_TRUNC | O_WRONLY | (how == 2 ? O_DSYNC : 0), 0644);
        if (fds[how] < 0) { perror("sync file"); exit(1); }
        labels[how] = store_label(fds[how]);
    }
    int fd = fds[how];
    long bytes = kb * 1024;
    if (off[how] + bytes > SYNC_FILE_BYTES) {
        if (ftruncate(fd, 0) == 0) fsync(fd);
        off[how] = 0;
    }
    uint64_t t0 = now_ns();
    for (long done = 0; done < bytes;) {
        long k = bytes - done < (long)sizeof(BODY) ? bytes - done : (long)sizeof(BODY);
        if (pwrite(fd, BODY, k, off[how] + done) <= 0) break;
        done += k;
    }
    if (how == 0) fsync(fd);
    else if (how == 1) fdatasync(fd);
    else if (how == 3) syncfs(fd);
    log_blk(labels[how], t0, now_ns(), port, seq, 0);
    off[how] += bytes;
}

static void mem_touch(long kb, uint32_t port, uint32_t seq) {
    if (kb <= 0) return;
    size_t bytes = (size_t)kb * 1024;
    uint64_t t0 = now_ns();
    char *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return;
    for (size_t off = 0; off < bytes; off += 4096) p[off] = 1;
    munmap(p, bytes);
    log_blk(L_MEM, t0, now_ns(), port, seq, 0);
}

/* ---------------- blocking downstream client (tpc, pool) ---------------- */

static int down_connect(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(BACKEND_PORT)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a))) { perror("connect backend"); close(fd); return -1; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return fd;
}

// Parses a backend response from buf; returns total length if complete, 0 otherwise.
static size_t resp_complete(const char *b, size_t n) {
    const char *e = memmem_(b, n, "\r\n\r\n");
    if (!e) return 0;
    size_t hl = e - b + 4;
    long cl = 0;
    const char *p = memmem_(b, hl, "Content-Length: ");
    if (p) cl = atol(p + 16);
    return n >= hl + cl ? hl + cl : 0;
}

// The request to the backend for a request with d=US.
static int down_query(char *q, size_t cap, const struct req *r) {
    if (r->down_chunk > 0)
        return snprintf(q, cap, "GET /x?sleep=%ld&size=100&wchunk=%ld&wgap=%ld HTTP/1.1\r\nHost: b\r\n\r\n",
                        r->down_us, r->down_chunk, r->down_gap_us > 0 ? r->down_gap_us : 0);
    return snprintf(q, cap, "GET /x?sleep=%ld&size=100 HTTP/1.1\r\nHost: b\r\n\r\n", r->down_us);
}

static __thread int tl_down = -1;
// Blocking downstream call; logs the blocked interval as L_DOWN for (port, seq).
static void down_call(const struct req *r, uint32_t port, uint32_t seq, uint64_t *blk) {
    if (tl_down < 0) tl_down = down_connect();
    if (tl_down < 0) return;
    char q[160], b[4096];
    int ql = down_query(q, sizeof(q), r);
    if (write(tl_down, q, ql) != ql) { close(tl_down); tl_down = -1; return; }
    size_t n = 0;
    for (;;) {
        uint64_t t0 = now_ns();
        ssize_t r = read(tl_down, b + n, sizeof(b) - n);
        uint64_t t1 = now_ns();
        log_blk(L_DOWN, t0, t1, port, seq, 0);
        if (blk) *blk += t1 - t0;
        if (r <= 0) { close(tl_down); tl_down = -1; return; }
        n += r;
        if (resp_complete(b, n)) return;
    }
}

/* ---------------- mode tpc ---------------- */

static void log_req(struct conn *c, struct req *r, uint64_t t0, uint64_t t1, uint32_t tid_read,
                    uint64_t cpu, uint64_t blk, uint64_t tdeq, uint64_t tdown) {
    struct rec *x = log_new();
    if (!x) return;
    *x = (struct rec){.type = R_REQ, .tid = gettid_(), .t0 = t0, .t1 = t1, .port = c->port, .seq = c->seq,
                      .cpu_ns = cpu, .blk_ns = blk, .t_deq = tdeq, .t_down_end = tdown, .tid_read = tid_read};
    x->flags = (r->head ? F_HEAD : 0) | (r->chunked ? F_CHUNKED : 0) | (r->expect100 ? F_100 : 0) |
               (r->down_us >= 0 ? F_DOWN : 0) | (r->close ? F_CLOSE : 0);
}

static void *tpc_conn(void *arg) {
    struct conn *c = arg;
    uint32_t me = gettid_();
    for (;;) {
        struct req r;
        int pr, sent100 = 0;
        // read until headers are complete
        while ((pr = parse_req(c->buf, c->len, &r)) == 0) {
            conn_room(c);
            uint64_t t0 = now_ns();
            ssize_t n = read(c->fd, c->buf + c->len, c->cap - c->len);
            uint64_t t1 = now_ns();
            log_blk(c->len == 0 ? L_IDLE : L_CLIENT, t0, t1, c->port, c->seq, 0);
            if (n <= 0) goto out;
            conn_got(c, n, t1);
        }
        if (pr < 0) goto out;
        uint64_t start = ts_of(c, c->base);
        // body
        while (c->len < r.hdr_len + r.clen) {
            if (r.expect100 && !sent100) {
                if (write(c->fd, "HTTP/1.1 100 Continue\r\n\r\n", 25) != 25) goto out;
                sent100 = 1;
            }
            conn_room(c);
            uint64_t t0 = now_ns();
            ssize_t n = read(c->fd, c->buf + c->len, c->cap - c->len);
            uint64_t t1 = now_ns();
            log_blk(L_CLIENT, t0, t1, c->port, c->seq, 0);
            if (n <= 0) goto out;
            conn_got(c, n, t1);
        }
        conn_consume(c, r.hdr_len + r.clen);
        uint64_t c0 = cpu_ns();
        spin_us(r.cpu_us);
        sleep_us(r.sleep_us, c->port, c->seq);
        disk_read(r.io_kb, c->port, c->seq);
        disk_sync(r.sync_kb, r.sync_how, r.sync_shared, c->port, c->seq);
        cached_read(r.rd_kb, c->port, c->seq);
        map_read(r.mm_kb, c->port, c->seq);
        stat_file(r.st_n, c->port, c->seq);
        mem_touch(r.mem_kb, c->port, c->seq);
        omp_work(r.omp_n, r.omp_us, r.omp_regions, r.omp_waits, c->port, c->seq);
        if (r.down_us >= 0) down_call(&r, c->port, c->seq, NULL);
        uint64_t end = respond(w_writev, c->fd, &r);
        if (!end) goto out;
        log_req(c, &r, start, end, me, cpu_ns() - c0, 0, 0, 0);
        c->seq++;
        if (r.close) goto out;
    }
out:
    close(c->fd);
    conn_free(c);
    free(c);
    return NULL;
}

static int listen_on(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) || listen(fd, 4096)) { perror("listen"); exit(1); }
    return fd;
}

static void run_tpc(int lfd) {
    for (;;) {
        int fd = accept4(lfd, NULL, NULL, 0);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        struct conn *c = malloc(sizeof(*c));
        conn_init(c, fd);
        pthread_t t;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&at, 256 << 10);
        pthread_create(&t, &at, tpc_conn, c);
    }
}

/* ---------------- mode epoll ---------------- */

#define MAXFD 65536
static struct conn *CONNS[MAXFD];
struct down { int fd; struct conn *owner; char buf[4096]; size_t n; uint64_t t_send; struct down *next; };
static struct down *DOWNS[MAXFD];
static struct down *DOWN_FREE;
static int EP;
static int OUTSTANDING;

// Try to serve requests from c's buffer. Returns -1 to close.
static int epoll_serve(struct conn *c) {
    while (!c->busy) {
        struct req r;
        int pr = parse_req(c->buf, c->len, &r);
        if (pr < 0) return -1;
        if (pr == 0) return 0;
        if (c->len < r.hdr_len + r.clen) {
            if (r.expect100 && !c->sent100) { send(c->fd, "HTTP/1.1 100 Continue\r\n\r\n", 25, MSG_NOSIGNAL); c->sent100 = 1; }
            return 0;
        }
        c->sent100 = 0;
        c->cur = r;
        c->cur_start = ts_of(c, c->base);
        conn_consume(c, r.hdr_len + r.clen);
        uint64_t c0 = cpu_ns();
        spin_us(r.cpu_us);
        if (r.down_us >= 0) {
            struct down *d = DOWN_FREE;
            if (d) DOWN_FREE = d->next;
            else {
                d = calloc(1, sizeof(*d));
                d->fd = down_connect();
                if (d->fd < 0) return -1;
                fcntl(d->fd, F_SETFL, O_NONBLOCK);
                struct epoll_event ev = {.events = EPOLLIN, .data.fd = d->fd};
                epoll_ctl(EP, EPOLL_CTL_ADD, d->fd, &ev);
                DOWNS[d->fd] = d;
            }
            d->owner = c; d->n = 0;
            char q[160];
            int ql = down_query(q, sizeof(q), &r);
            d->t_send = now_ns();
            send(d->fd, q, ql, MSG_NOSIGNAL);
            c->busy = 1; c->down = d;
            c->cur_cpu = cpu_ns() - c0;
            OUTSTANDING++;
            return 0;
        }
        uint64_t end = respond(w_send, c->fd, &r);
        if (!end) return -1;
        log_req(c, &r, c->cur_start, end, gettid_(), cpu_ns() - c0, 0, 0, 0);
        c->seq++;
        if (r.close) return -1;
    }
    return 0;
}

static void epoll_close(struct conn *c) {
    epoll_ctl(EP, EPOLL_CTL_DEL, c->fd, NULL);
    CONNS[c->fd] = NULL;
    close(c->fd);
    conn_free(c);
    free(c);
}

static void run_epoll(int lfd) {
    EP = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = lfd};
    epoll_ctl(EP, EPOLL_CTL_ADD, lfd, &ev);
    fcntl(lfd, F_SETFL, O_NONBLOCK);
    struct epoll_event evs[256];
    for (;;) {
        int outst = OUTSTANDING;
        uint64_t t0 = now_ns();
        int n = epoll_wait(EP, evs, 256, -1);
        uint64_t t1 = now_ns();
        // ground-truth label of this wait
        int label = outst ? L_WAKE_CLIENT : L_IDLE;
        uint32_t lport = 0, lseq = 0;
        for (int i = 0; i < n; i++) {
            struct down *d = DOWNS[evs[i].data.fd];
            if (d && d->owner) { label = L_DOWN; lport = d->owner->port; lseq = d->owner->seq; break; }
        }
        log_blk(label, t0, t1, lport, lseq, outst);
        for (int i = 0; i < n; i++) {
            int fd = evs[i].data.fd;
            if (fd == lfd) {
                for (;;) {
                    int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK);
                    if (cfd < 0) break;
                    int one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    struct conn *c = malloc(sizeof(*c));
                    conn_init(c, cfd);
                    CONNS[cfd] = c;
                    struct epoll_event e2 = {.events = EPOLLIN, .data.fd = cfd};
                    epoll_ctl(EP, EPOLL_CTL_ADD, cfd, &e2);
                }
                continue;
            }
            struct down *d = DOWNS[fd];
            if (d) {
                ssize_t r = recv(fd, d->buf + d->n, sizeof(d->buf) - d->n, 0);
                if (r <= 0) continue;
                d->n += r;
                if (!resp_complete(d->buf, d->n) || !d->owner) continue;
                struct conn *c = d->owner;
                uint64_t tdown = now_ns();
                d->owner = NULL; d->next = DOWN_FREE; DOWN_FREE = d;
                OUTSTANDING--;
                c->busy = 0; c->down = NULL;
                uint64_t c0 = cpu_ns();
                // the same work again after the answer, so both halves can be told apart from none
                spin_us(c->cur.cpu_us);
                uint64_t end = respond(w_send, c->fd, &c->cur);
                if (!end) { epoll_close(c); continue; }
                log_req(c, &c->cur, c->cur_start, end, gettid_(), c->cur_cpu + cpu_ns() - c0, 0, d->t_send, tdown);
                c->seq++;
                if (c->cur.close || epoll_serve(c) < 0) epoll_close(c);
                continue;
            }
            struct conn *c = CONNS[fd];
            if (!c) continue;
            int closeit = 0;
            for (;;) {
                conn_room(c);
                ssize_t r = recv(fd, c->buf + c->len, c->cap - c->len, 0);
                if (r < 0 && errno == EAGAIN) break;
                if (r <= 0) { closeit = 1; break; }
                conn_got(c, r, now_ns());
            }
            if (epoll_serve(c) < 0 || (closeit && !c->busy)) epoll_close(c);
        }
    }
}

/* ---------------- mode pool ---------------- */

struct job { struct conn *c; struct req r; uint64_t start; uint32_t tid_read; struct job *next; };
static struct job *QH, *QT;
static pthread_mutex_t QM = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t QC = PTHREAD_COND_INITIALIZER;
static int PEP;

static void *pool_worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&QM);
        uint64_t t0 = now_ns();
        int waited = 0;
        while (!QH) { pthread_cond_wait(&QC, &QM); waited = 1; }
        struct job *j = QH;
        QH = j->next;
        if (!QH) QT = NULL;
        pthread_mutex_unlock(&QM);
        uint64_t tdeq = now_ns();
        if (waited) log_blk(L_IDLE, t0, tdeq, 0, 0, 0);
        uint64_t c0 = cpu_ns(), blk = 0;
        struct conn *c = j->c;
        spin_us(j->r.cpu_us);
        if (j->r.sleep_us > 0) {
            uint64_t s0 = now_ns();
            sleep_us(j->r.sleep_us, c->port, c->seq);
            blk += now_ns() - s0;
        }
        if (j->r.down_us >= 0) down_call(&j->r, c->port, c->seq, &blk);
        spin_us(j->r.cpu_us / 2);
        uint64_t end = respond(w_sendmsg, c->fd, &j->r);
        uint64_t c1 = cpu_ns();
        if (end) log_req(c, &j->r, j->start, end, j->tid_read, c1 - c0, blk, tdeq, 0);
        c->seq++;
        if (!end || j->r.close) {
            epoll_ctl(PEP, EPOLL_CTL_DEL, c->fd, NULL);
            close(c->fd);
            conn_free(c); free(c);
        } else {
            struct epoll_event ev = {.events = EPOLLIN | EPOLLONESHOT, .data.ptr = c};
            epoll_ctl(PEP, EPOLL_CTL_MOD, c->fd, &ev);
        }
        free(j);
    }
    return NULL;
}

static void run_pool(int lfd, int nworkers) {
    PEP = epoll_create1(0);
    struct epoll_event ev = {.events = EPOLLIN, .data.ptr = NULL};
    epoll_ctl(PEP, EPOLL_CTL_ADD, lfd, &ev);
    fcntl(lfd, F_SETFL, O_NONBLOCK);
    for (int i = 0; i < nworkers; i++) { pthread_t t; pthread_create(&t, NULL, pool_worker, NULL); }
    struct epoll_event evs[256];
    uint32_t me = gettid_();
    for (;;) {
        uint64_t t0 = now_ns();
        int n = epoll_wait(PEP, evs, 256, -1);
        log_blk(L_IDLE, t0, now_ns(), 0, 0, 0);
        for (int i = 0; i < n; i++) {
            struct conn *c = evs[i].data.ptr;
            if (!c) {
                for (;;) {
                    int cfd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK);
                    if (cfd < 0) break;
                    int one = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    // workers write with blocking semantics
                    fcntl(cfd, F_SETFL, 0);
                    c = malloc(sizeof(*c));
                    conn_init(c, cfd);
                    struct epoll_event e2 = {.events = EPOLLIN | EPOLLONESHOT, .data.ptr = c};
                    epoll_ctl(PEP, EPOLL_CTL_ADD, cfd, &e2);
                }
                continue;
            }
            conn_room(c);
            struct iovec v = {c->buf + c->len, c->cap - c->len};
            struct msghdr m = {.msg_iov = &v, .msg_iovlen = 1};
            ssize_t r = recvmsg(c->fd, &m, MSG_DONTWAIT);
            if (r <= 0) {
                if (r < 0 && errno == EAGAIN) goto rearm;
                close(c->fd); conn_free(c); free(c);
                continue;
            }
            conn_got(c, r, now_ns());
            struct req rq;
            int pr = parse_req(c->buf, c->len, &rq);
            if (pr < 0) { close(c->fd); conn_free(c); free(c); continue; }
            if (pr == 0 || c->len < rq.hdr_len + rq.clen) goto rearm;
            struct job *j = calloc(1, sizeof(*j));
            j->c = c; j->r = rq; j->start = ts_of(c, c->base); j->tid_read = me;
            conn_consume(c, rq.hdr_len + rq.clen);
            pthread_mutex_lock(&QM);
            if (QT) QT->next = j; else QH = j;
            QT = j;
            pthread_cond_signal(&QC);
            pthread_mutex_unlock(&QM);
            continue;
        rearm:;
            struct epoll_event e3 = {.events = EPOLLIN | EPOLLONESHOT, .data.ptr = c};
            epoll_ctl(PEP, EPOLL_CTL_MOD, c->fd, &e3);
        }
    }
}

// Writes the log from its own thread, so no handler runs on a thread that is mid-record.
static void *wait_for_signal(void *arg) {
    int sig;
    sigwait(arg, &sig);
    dump_and_exit(sig);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: http_truth tpc|epoll|pool PORT LOG [-b PORT] [-w N]\n"); return 2; }
    MODE = argv[1];
    int port = atoi(argv[2]);
    LOG_PATH = argv[3];
    int nworkers = 4;
    for (int i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "-b") && i + 1 < argc) BACKEND_PORT = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i + 1 < argc) nworkers = atoi(argv[++i]);
    }
    memset(BODY, 'x', sizeof(BODY));
    LOG = mmap(NULL, LOG_CAP * sizeof(struct rec), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    signal(SIGPIPE, SIG_IGN);
    static sigset_t signals;
    sigemptyset(&signals); sigaddset(&signals, SIGTERM); sigaddset(&signals, SIGINT);
    pthread_sigmask(SIG_BLOCK, &signals, NULL);
    int lfd = listen_on(port);
    fprintf(stderr, "http_truth %s pid %d port %d\n", MODE, getpid(), port);
    pthread_t t;
    pthread_create(&t, NULL, wait_for_signal, &signals);
    if (!strcmp(MODE, "tpc")) run_tpc(lfd);
    else if (!strcmp(MODE, "epoll")) run_epoll(lfd);
    else if (!strcmp(MODE, "pool")) run_pool(lfd, nworkers);
    return 0;
}
