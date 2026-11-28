// Keep-alive GET load against an HTTP/1.1 server; one connection per thread,
// each request's path picked at random from the list.
//
//   http_load PORT CONNS SECS THINK_US PATH[,PATH...] [HEADER_BYTES]
//
// THINK_US: mean pause between a response and the next request (0 = none).
// HEADER_BYTES: pad every request with browser-like headers of about this size.
// With HTTP_LOAD_TRACE set, every request carries a traceparent of its own.
// With HTTP_LOAD_TLS set, it speaks HTTPS (TLS 1.3, the certificate not
// checked): built with -DWITH_TLS and OpenSSL.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#ifdef WITH_TLS
#include <openssl/ssl.h>
static SSL_CTX *CTX;
#endif

static int PORT, SECS, THINK;
static char *PATHS[32];
static int NP;
static char EXTRA[8192];
static long TOTAL;
static int TRACE, TLS;

/* One connection: its socket and, over TLS, its session. */
struct link {
    int fd;
#ifdef WITH_TLS
    SSL *ssl;
#endif
};

static ssize_t link_send(struct link *l, const char *p, size_t n) {
#ifdef WITH_TLS
    if (l->ssl) { size_t w = 0; return SSL_write_ex(l->ssl, p, n, &w) == 1 ? (ssize_t)w : -1; }
#endif
    return send(l->fd, p, n, 0);
}

static ssize_t link_recv(struct link *l, char *p, size_t n) {
#ifdef WITH_TLS
    if (l->ssl) { size_t r = 0; return SSL_read_ex(l->ssl, p, n, &r) == 1 ? (ssize_t)r : -1; }
#endif
    return recv(l->fd, p, n, 0);
}

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }

static void *run(void *arg) {
    unsigned seed = (unsigned)(long)arg * 7919 + 1;
    int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(PORT)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a))) { perror("connect"); return NULL; }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    struct link link = {.fd = fd};
#ifdef WITH_TLS
    if (TLS) {
        link.ssl = SSL_new(CTX);
        SSL_set_fd(link.ssl, fd);
        if (SSL_connect(link.ssl) != 1) { fprintf(stderr, "http_load: TLS handshake failed\n"); close(fd); return NULL; }
    }
#endif
    char q[9000], buf[1 << 16];
    double end = now() + SECS;
    long n = 0;
    while (now() < end) {
        char *p = PATHS[rand_r(&seed) % NP];
        char tp[80] = "";
        if (TRACE)
            snprintf(tp, sizeof(tp), "traceparent: 00-%016lx%016lx-%016lx-01\r\n", (long)arg + 1, n + 1, n + 1);
        int ql = snprintf(q, sizeof(q), "GET %s HTTP/1.1\r\nHost: l\r\n%s%s\r\n", p, tp, EXTRA);
        if (link_send(&link, q, ql) != ql) break;
        size_t got = 0, need = 0;
        for (;;) {
            ssize_t r = link_recv(&link, buf + got, sizeof(buf) - got);
            if (r <= 0) goto out;
            got += r;
            char *e = memmem(buf, got, "\r\n\r\n", 4);
            if (!e) continue;
            if (!need) {
                char *cl = memmem(buf, e - buf, "Content-Length: ", 16);
                need = (e - buf) + 4 + (cl ? atol(cl + 16) : 0);
            }
            if (got >= need) break;
        }
        n++;
        if (THINK) {
            int t = rand_r(&seed) % (2 * THINK + 1);
            struct timespec ts = {t / 1000000, (t % 1000000) * 1000};
            nanosleep(&ts, NULL);
        }
    }
out:
    __atomic_fetch_add(&TOTAL, n, __ATOMIC_RELAXED);
#ifdef WITH_TLS
    if (link.ssl) SSL_free(link.ssl);
#endif
    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "usage: http_load PORT CONNS SECS THINK_US PATHS [HEADER_BYTES]\n"); return 2; }
    PORT = atoi(argv[1]);
    TRACE = getenv("HTTP_LOAD_TRACE") != NULL;
    TLS = getenv("HTTP_LOAD_TLS") != NULL;
#ifdef WITH_TLS
    if (TLS) {
        CTX = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(CTX, SSL_VERIFY_NONE, NULL);
    }
#else
    if (TLS) { fprintf(stderr, "http_load: built without TLS\n"); return 2; }
#endif
    int conns = atoi(argv[2]);
    SECS = atoi(argv[3]);
    THINK = atoi(argv[4]);
    for (char *p = strtok(argv[5], ","); p && NP < 32; p = strtok(NULL, ",")) PATHS[NP++] = p;
    if (argc > 6) {
        int n = atoi(argv[6]);
        // browser-like headers of about n bytes
        int off = snprintf(EXTRA, sizeof(EXTRA), "User-Agent: Mozilla/5.0 (X11; Linux aarch64) Gecko/20100101 Firefox/130.0\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nCookie: ");
        for (; off < n - 2 && off < (int)sizeof(EXTRA) - 3; off++) EXTRA[off] = 'a' + off % 26;
        EXTRA[off++] = '\r'; EXTRA[off++] = '\n'; EXTRA[off] = 0;
    }
    pthread_t t[1024];
    for (int i = 0; i < conns; i++) pthread_create(&t[i], NULL, run, (void *)(long)i);
    for (int i = 0; i < conns; i++) pthread_join(t[i], NULL);
    printf("http_load: %ld requests\n", TOTAL);
    return 0;
}
