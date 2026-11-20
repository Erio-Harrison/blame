// A plain C HTTP/1.1 server, one thread per connection, and its load: what
// blame tells about a service written in a language it has no adapter for.
// One binary, three roles:
//
//   server -role front   -addr PORT -backend PORT -file PATH -log FILE
//   server -role backend -addr PORT -log FILE
//   server -role load    -addr PORT -conns N -secs S
//
// front:
//   GET  /compute   2 ms of computing
//   GET  /lock      waits for a mutex, then computes 1 ms holding it
//   POST /save      writes 16 KB to PATH and flushes it (fsync)
//   GET  /backend   asks the backend (GET /sleep) over a connection of its own
// backend:
//   GET  /sleep     sleeps 5 ms
//
// Each request's traceparent is passed on. On SIGTERM each server writes what it
// measured itself, one line per request:
//
//   T <trace id> <route> wall=<ns> cpu=<ns> runq=<ns> [lock=<ns>] [save=<ns>] [backend=<ns>] [sleep=<ns>]
//
// wall is from the request read to the answer about to be written; cpu is the
// handling thread's own CPU time in it (CLOCK_THREAD_CPUTIME_ID), runq its time
// waiting for a CPU (the second field of /proc/thread-self/schedstat). What is
// left, wall - cpu - runq, the thread was asleep.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int64_t now(clockid_t clock)
{
	struct timespec ts;
	clock_gettime(clock, &ts);
	return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void compute(int64_t ns)
{
	int64_t t0 = now(CLOCK_MONOTONIC);
	while (now(CLOCK_MONOTONIC) - t0 < ns)
		;
}

// ---- the records, written on SIGTERM ----

struct record {
	char trace[33];
	char route[24];
	int64_t wall, cpu, runq, lock, save, backend, sleep;
};

static pthread_mutex_t records_mu = PTHREAD_MUTEX_INITIALIZER;
static struct record *records;
static size_t nrecords, caprecords;
static const char *log_path;

static void keep(const struct record *r)
{
	pthread_mutex_lock(&records_mu);
	if (nrecords == caprecords) {
		caprecords = caprecords ? caprecords * 2 : 4096;
		records = realloc(records, caprecords * sizeof(*records));
	}
	records[nrecords++] = *r;
	pthread_mutex_unlock(&records_mu);
}

static void write_records(void)
{
	pthread_mutex_lock(&records_mu);
	FILE *f = fopen(log_path, "w");
	for (size_t i = 0; f && i < nrecords; i++) {
		struct record *r = &records[i];
		fprintf(f, "T %s %s wall=%lld cpu=%lld runq=%lld", r->trace, r->route, (long long)r->wall,
			(long long)r->cpu, (long long)r->runq);
		if (r->lock >= 0)
			fprintf(f, " lock=%lld", (long long)r->lock);
		if (r->save >= 0)
			fprintf(f, " save=%lld", (long long)r->save);
		if (r->backend >= 0)
			fprintf(f, " backend=%lld", (long long)r->backend);
		if (r->sleep >= 0)
			fprintf(f, " sleep=%lld", (long long)r->sleep);
		fputc('\n', f);
	}
	if (f)
		fclose(f);
}

// Time this thread has waited for a CPU, in ns.
static int64_t runq_ns(void)
{
	char b[128] = {0};
	int fd = open("/proc/thread-self/schedstat", O_RDONLY);
	ssize_t n = read(fd, b, sizeof(b) - 1);
	close(fd);
	long long run = 0, wait = 0;
	if (n > 0)
		sscanf(b, "%lld %lld", &run, &wait);
	return wait;
}

// ---- HTTP ----

// Reads one request or response head (and a body of Content-Length) from fd,
// keeping what came after it in buf. Returns the head's length, 0 at EOF.
struct conn {
	int fd;
	char buf[8192];
	size_t len;
};

static ssize_t read_message(struct conn *c, char *head, size_t cap)
{
	for (;;) {
		char *end = memmem(c->buf, c->len, "\r\n\r\n", 4);
		if (end) {
			size_t hlen = end + 4 - c->buf;
			size_t body = 0;
			char *cl = memmem(c->buf, hlen, "Content-Length:", 15);
			if (cl)
				body = strtoul(cl + 15, NULL, 10);
			while (c->len < hlen + body) {
				ssize_t n = read(c->fd, c->buf + c->len, sizeof(c->buf) - c->len);
				if (n <= 0)
					return 0;
				c->len += n;
			}
			size_t n = hlen < cap - 1 ? hlen : cap - 1;
			memcpy(head, c->buf, n);
			head[n] = 0;
			memmove(c->buf, c->buf + hlen + body, c->len - hlen - body);
			c->len -= hlen + body;
			return hlen;
		}
		if (c->len == sizeof(c->buf))
			return 0;
		ssize_t n = read(c->fd, c->buf + c->len, sizeof(c->buf) - c->len);
		if (n <= 0)
			return 0;
		c->len += n;
	}
}

static void header(const char *head, const char *name, char *out, size_t cap)
{
	out[0] = 0;
	const char *h = strcasestr(head, name);
	if (!h)
		return;
	h += strlen(name);
	while (*h == ' ')
		h++;
	size_t n = strcspn(h, "\r\n");
	if (n >= cap)
		n = cap - 1;
	memcpy(out, h, n);
	out[n] = 0;
}

static int write_all(int fd, const char *p, size_t n)
{
	while (n) {
		ssize_t w = write(fd, p, n);
		if (w <= 0)
			return -1;
		p += w;
		n -= w;
	}
	return 0;
}

static int dial(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
		perror("connect");
		exit(1);
	}
	return fd;
}

// ---- the servers ----

static int backend_port;
static const char *save_path;
static pthread_mutex_t hot = PTHREAD_MUTEX_INITIALIZER;
static char block[16 << 10];

static void *serve(void *arg)
{
	struct conn c = {.fd = (int)(intptr_t)arg};
	struct conn down = {.fd = -1};
	char head[4096], tp[128], reply[4096];
	while (read_message(&c, head, sizeof(head)) > 0) {
		int64_t wall0 = now(CLOCK_MONOTONIC), cpu0 = now(CLOCK_THREAD_CPUTIME_ID), runq0 = runq_ns();
		struct record r = {.lock = -1, .save = -1, .backend = -1, .sleep = -1};
		header(head, "traceparent:", tp, sizeof(tp));
		snprintf(r.trace, sizeof(r.trace), "%.32s", strlen(tp) >= 35 ? tp + 3 : "-");
		sscanf(head, "%*s %23s", r.route);
		if (!strcmp(r.route, "/compute")) {
			compute(2000000);
		} else if (!strcmp(r.route, "/lock")) {
			int64_t t = now(CLOCK_MONOTONIC);
			pthread_mutex_lock(&hot);
			r.lock = now(CLOCK_MONOTONIC) - t;
			compute(1000000);
			pthread_mutex_unlock(&hot);
		} else if (!strcmp(r.route, "/save")) {
			int64_t t = now(CLOCK_MONOTONIC);
			int fd = open(save_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
			write_all(fd, block, sizeof(block));
			fsync(fd);
			close(fd);
			r.save = now(CLOCK_MONOTONIC) - t;
		} else if (!strcmp(r.route, "/backend")) {
			int64_t t = now(CLOCK_MONOTONIC);
			if (down.fd < 0)
				down.fd = dial(backend_port);
			int n = snprintf(reply, sizeof(reply), "GET /sleep HTTP/1.1\r\nHost: backend\r\ntraceparent: %s\r\n\r\n", tp);
			if (write_all(down.fd, reply, n) < 0 || read_message(&down, reply, sizeof(reply)) <= 0)
				break;
			r.backend = now(CLOCK_MONOTONIC) - t;
		} else if (!strcmp(r.route, "/sleep")) {
			int64_t t = now(CLOCK_MONOTONIC);
			struct timespec ts = {0, 5000000};
			nanosleep(&ts, NULL);
			r.sleep = now(CLOCK_MONOTONIC) - t;
		}
		r.runq = runq_ns() - runq0;
		r.cpu = now(CLOCK_THREAD_CPUTIME_ID) - cpu0;
		r.wall = now(CLOCK_MONOTONIC) - wall0;
		static const char ok[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
		if (write_all(c.fd, ok, sizeof(ok) - 1) < 0)
			break;
		keep(&r);
	}
	close(c.fd);
	if (down.fd >= 0)
		close(down.fd);
	return NULL;
}

static void *on_term(void *arg)
{
	sigset_t *set = arg;
	int sig;
	sigwait(set, &sig);
	write_records();
	_exit(0);
}

static void run_server(int port)
{
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	pthread_t t;
	pthread_create(&t, NULL, on_term, &set);

	int l = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(l, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(l, 128) < 0) {
		perror("listen");
		exit(1);
	}
	printf("ready %d\n", port);
	fflush(stdout);
	for (;;) {
		int fd = accept(l, NULL, NULL);
		if (fd < 0)
			continue;
		setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
		pthread_create(&t, NULL, serve, (void *)(intptr_t)fd);
		pthread_detach(t);
	}
}

// ---- the load ----

static int load_port;
static int64_t load_end;
static atomic_long seq;
static uint32_t run_id;

static const char *routes[] = {"GET /compute", "GET /lock", "POST /save", "GET /backend"};

static void *client(void *arg)
{
	(void)arg;
	struct conn c = {.fd = dial(load_port)};
	char req[512], head[4096];
	while (now(CLOCK_MONOTONIC) < load_end) {
		long n = atomic_fetch_add(&seq, 1);
		const char *route = routes[n % 4];
		int len = snprintf(req, sizeof(req),
				   "%s HTTP/1.1\r\nHost: front\r\ntraceparent: 00-%08x%024lx-%016lx-01\r\n%s\r\n", route,
				   run_id, n, n, route[0] == 'P' ? "Content-Length: 0\r\n" : "");
		if (write_all(c.fd, req, len) < 0 || read_message(&c, head, sizeof(head)) <= 0)
			break;
		struct timespec think = {0, 2000000};
		nanosleep(&think, NULL);
	}
	close(c.fd);
	return NULL;
}

int main(int argc, char **argv)
{
	const char *role = "", *addr = "0";
	int conns = 16, backend = 0;
	double secs = 20;
	for (int i = 1; i + 1 < argc; i += 2) {
		if (!strcmp(argv[i], "-role"))
			role = argv[i + 1];
		else if (!strcmp(argv[i], "-addr"))
			addr = argv[i + 1];
		else if (!strcmp(argv[i], "-backend"))
			backend = atoi(argv[i + 1]);
		else if (!strcmp(argv[i], "-file"))
			save_path = argv[i + 1];
		else if (!strcmp(argv[i], "-log"))
			log_path = argv[i + 1];
		else if (!strcmp(argv[i], "-conns"))
			conns = atoi(argv[i + 1]);
		else if (!strcmp(argv[i], "-secs"))
			secs = atof(argv[i + 1]);
	}
	if (!strcmp(role, "front") || !strcmp(role, "backend")) {
		backend_port = backend;
		run_server(atoi(addr));
	} else if (!strcmp(role, "load")) {
		load_port = atoi(addr);
		load_end = now(CLOCK_MONOTONIC) + (int64_t)(secs * 1e9);
		run_id = (uint32_t)now(CLOCK_REALTIME);
		pthread_t t[256];
		for (int i = 0; i < conns && i < 256; i++)
			pthread_create(&t[i], NULL, client, NULL);
		for (int i = 0; i < conns && i < 256; i++)
			pthread_join(t[i], NULL);
		printf("load: %ld requests\n", (long)atomic_load(&seq));
	} else {
		fprintf(stderr, "-role front|backend|load\n");
		return 2;
	}
	return 0;
}
