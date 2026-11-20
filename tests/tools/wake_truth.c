// Known-answer wake-up latency. Pairs of threads in two processes share futex
// words in a shared memory file; the waker stamps the time just before each
// wake, the wakee stamps it on return, so each wakee records how long it took
// from "woken" to "running again". Run the two sides in different cgroups to
// compare a per-cgroup histogram against what the wakees saw.
//
//     wake_truth wakee SHM PAIRS SECS OUT   writes one latency in ns per line
//     wake_truth waker SHM PAIRS SECS       start after the wakee
//     wake_truth hog THREADS SECS           spin 2 ms, nap 300 us, repeat
//
// Build: cc -O2 -pthread -o wake_truth wake_truth.c

#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static uint64_t now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000000000ull + t.tv_nsec;
}

/* One cache line per pair. */
struct slot {
	_Atomic uint32_t word;
	_Atomic uint32_t done;
	_Atomic uint64_t tw;
	char pad[48];
};

struct shared {
	_Atomic uint32_t ready;
	_Atomic uint32_t stop;
	char pad[56];
	struct slot slot[];
};

#define MAX_EVENTS 4000000
static struct shared *sh;
static uint64_t end_ns;
static int pairs;

static void futex(_Atomic uint32_t *w, int op, uint32_t val)
{
	syscall(SYS_futex, w, op, val, NULL, NULL, 0);
}

struct wakee_arg {
	int i;
	uint64_t *lat;
	long n;
};

static void *wakee(void *p)
{
	struct wakee_arg *a = p;
	struct slot *s = &sh->slot[a->i];

	while (!atomic_load(&sh->stop)) {
		while (atomic_load(&s->word) == 0 && !atomic_load(&sh->stop))
			futex(&s->word, FUTEX_WAIT, 0);
		uint64_t tr = now();
		if (atomic_load(&sh->stop))
			break;
		atomic_store(&s->word, 0);
		if (a->n < MAX_EVENTS)
			a->lat[a->n++] = tr - atomic_load(&s->tw);
		atomic_store(&s->done, 1);
	}
	return 0;
}

static void *waker(void *p)
{
	int i = (int)(long)p;
	struct slot *s = &sh->slot[i];
	unsigned seed = i * 7919 + 1;

	while (now() < end_ns) {
		struct timespec ts = { 0, (50 + rand_r(&seed) % 950) * 1000 };
		nanosleep(&ts, 0);
		if (!atomic_load(&s->done))
			continue;
		atomic_store(&s->done, 0);
		atomic_store(&s->tw, now());
		atomic_store(&s->word, 1);
		futex(&s->word, FUTEX_WAKE, 1);
	}
	return 0;
}

static void *hog(void *p)
{
	while (now() < end_ns) {
		uint64_t t = now();
		while (now() - t < 2000000)
			;
		usleep(300);
	}
	return p;
}

static struct shared *map(const char *path, int create)
{
	size_t size = sizeof(struct shared) + pairs * sizeof(struct slot);
	int fd = open(path, O_RDWR | (create ? O_CREAT | O_TRUNC : 0), 0600);
	if (fd < 0 || (create && ftruncate(fd, size))) {
		perror(path);
		exit(1);
	}
	void *m = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	return m;
}

int main(int argc, char **argv)
{
	pthread_t t[256];

	if (argc >= 4 && !strcmp(argv[1], "hog")) {
		int n = atoi(argv[2]);
		end_ns = now() + atoll(argv[3]) * 1000000000ull;
		for (int i = 0; i < n && i < 256; i++)
			pthread_create(&t[i], 0, hog, 0);
		for (int i = 0; i < n && i < 256; i++)
			pthread_join(t[i], 0);
		return 0;
	}
	if (argc < 5) {
		fprintf(stderr, "usage: see the comment at the top of %s\n", __FILE__);
		return 2;
	}
	pairs = atoi(argv[3]);
	if (pairs < 1 || pairs > 128)
		return 2;
	end_ns = now() + atoll(argv[4]) * 1000000000ull;

	if (!strcmp(argv[1], "wakee") && argc >= 6) {
		struct wakee_arg a[128];
		sh = map(argv[2], 1);
		for (int i = 0; i < pairs; i++) {
			atomic_store(&sh->slot[i].done, 1);
			a[i] = (struct wakee_arg){ .i = i, .lat = malloc(MAX_EVENTS * 8) };
			pthread_create(&t[i], 0, wakee, &a[i]);
		}
		atomic_store(&sh->ready, 1);
		while (now() < end_ns + 2000000000ull && !atomic_load(&sh->stop))
			usleep(100000);
		atomic_store(&sh->stop, 1);
		for (int i = 0; i < pairs; i++) {
			futex(&sh->slot[i].word, FUTEX_WAKE, 1);
			pthread_join(t[i], 0);
		}
		FILE *f = fopen(argv[5], "w");
		for (int i = 0; i < pairs; i++)
			for (long k = 0; k < a[i].n; k++)
				fprintf(f, "%lu\n", a[i].lat[k]);
		fclose(f);
		return 0;
	}
	if (!strcmp(argv[1], "waker")) {
		sh = map(argv[2], 0);
		while (!atomic_load(&sh->ready))
			usleep(10000);
		for (long i = 0; i < pairs; i++)
			pthread_create(&t[i], 0, waker, (void *)i);
		for (int i = 0; i < pairs; i++)
			pthread_join(t[i], 0);
		atomic_store(&sh->stop, 1);
		return 0;
	}
	return 2;
}
