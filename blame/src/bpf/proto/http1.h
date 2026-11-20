/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Where HTTP/1.1 messages start and end, and nothing more.
 *
 * One parser state per direction of a connection, fed the bytes of each read
 * or write call as it returns. Start lines and headers are scanned a byte at
 * a time; bodies are skipped by length. From a request it keeps the method
 * and path, from a response the status code, and from a request's
 * `traceparent` header the trace id (W3C trace context: "00-" then 32 hex
 * digits; anything else is not taken). Anything it cannot follow puts it in
 * HS_UNSYNC, where it waits for a call whose data begins a new message.
 */
#ifndef BLAME_HTTP1_H
#define BLAME_HTTP1_H

/* Segments of one call that are looked at: three iovecs and "the rest". */
#define HTTP_SEGS 4
/* Bytes fetched from user memory at a time; a power of two. */
#define HTTP_BUF 256
/* Parser steps per call. A step is one scanned byte or one skipped body. */
#define HTTP_STEPS 4096
/* Requests that can await a response on one connection; a power of two. */
#define REQ_QUEUE 16
/* Messages of one call that are acted on; more than that is a desync. */
#define HTTP_BATCH 64

enum http_state {
	HS_START = 0,
	HS_LINE,
	HS_HNAME,
	HS_HVAL,
	HS_HEND,
	HS_CHUNK_SIZE,
	HS_CHUNK_EXT,
	HS_CHUNK_DATA,
	HS_TRAILER,
	HS_BODY,
	/* A response with no length: it ends when the connection closes. */
	HS_BODY_EOF,
	HS_UNSYNC,
	/* The connection switched protocols: nothing more is parsed on it. */
	HS_OPAQUE,
};

#define HF_LENGTH 1
#define HF_CHUNKED 2

/* Header names looked for: bits of http_dir.cand, values of http_dir.hk. */
#define HK_LENGTH 1
#define HK_ENCODING 2
#define HK_TRACE 3
#define HK_ALL 7

/* Bytes of a traceparent value up to the end of its trace id: "00-" and 32 hex digits. */
#define TRACE_VALUE_END 35

/* One direction of a connection, kept between calls. */
struct http_dir {
	u8 st;
	/* Header names still matching: bit 0 content-length, bit 1 transfer-encoding, bit 2 traceparent. */
	u8 cand;
	u8 npos;
	/* Which of them the current header value belongs to (HK_*); 0 = none. */
	u8 hk;
	u8 tpos;
	u8 lpos;
	u8 flags;
	/* Spaces seen in a request line: 0 in the method, 1 in the path, 2 done. */
	u8 lsp;
	u16 status;
	u8 line_len;
	u8 line_trunc;
	/* First four bytes of the start line. */
	u32 m4;
	u64 num;
	u64 remain;
	/* The trace id of a traceparent value being read; any digit not zero. */
	u8 trace[16];
	u8 trace_nonzero;
	u8 _pad[7];
};

/* One call's worth of parsing; lives in a per-CPU scratch slot. */
struct http_run {
	struct http_dir h;
	u64 seg_base[HTTP_SEGS];
	u64 seg_len[HTTP_SEGS];
	u32 nseg;
	u32 si;
	u64 so;
	u64 buf_so;
	u64 buf_len;
	u32 buf_si;
	u32 desync;
	/* Requests whose start line began (request side). */
	u32 nstart;
	/* Request lines completed (request side). */
	u32 nlines;
	/* Bit i: the i-th of them is a HEAD. */
	u64 head_new;
	/* Responses finished (response side). */
	u32 ndone;
	/* Bit i: the i-th response still to finish answers a HEAD. */
	u32 head_mask;
	u8 is_resp;
	/* A response switched protocols (101). */
	u8 upgraded;
	u8 _pad[2];
	u16 status[REQ_QUEUE];
	u8 line_len[REQ_QUEUE];
	u8 line_trunc[REQ_QUEUE];
	/*
	 * Trace ids read (request side): bit i of trace_mask, that of the
	 * request whose line is lines[i]; trace_prev, that of a request whose
	 * line came in an earlier call.
	 */
	u32 trace_mask;
	u8 trace_prev_ok;
	u8 _pad2[3];
	u8 traces[REQ_QUEUE][16];
	u8 trace_prev[16];
	char cur_line[REQ_LINE_LEN];
	char lines[REQ_QUEUE][REQ_LINE_LEN];
	u8 buf[HTTP_BUF * 2];
};

#define FOURCC(a, b, c, d) ((u32)(a) | ((u32)(b) << 8) | ((u32)(c) << 16) | ((u32)(d) << 24))

static __always_inline bool http_method(u32 w)
{
	return w == FOURCC('G', 'E', 'T', ' ') || w == FOURCC('P', 'O', 'S', 'T') ||
	       w == FOURCC('P', 'U', 'T', ' ') || w == FOURCC('H', 'E', 'A', 'D') ||
	       w == FOURCC('D', 'E', 'L', 'E') || w == FOURCC('O', 'P', 'T', 'I') ||
	       w == FOURCC('P', 'A', 'T', 'C') || w == FOURCC('C', 'O', 'N', 'N') ||
	       w == FOURCC('T', 'R', 'A', 'C');
}

static __always_inline u8 http_lower(u8 ch)
{
	return (ch >= 'A' && ch <= 'Z') ? ch + 32 : ch;
}

static __always_inline int http_hex(u8 ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	ch = http_lower(ch);
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	return -1;
}

static __always_inline void http_reset(struct http_dir *h)
{
	h->st = HS_START;
	h->flags = 0;
	h->num = 0;
	h->status = 0;
	h->lpos = 0;
}

static __always_inline void http_lost(struct http_run *x)
{
	x->h.st = HS_UNSYNC;
	x->desync++;
}

static __always_inline void http_message_done(struct http_run *x)
{
	if (x->is_resp) {
		if (x->ndone < REQ_QUEUE)
			x->status[x->ndone & (REQ_QUEUE - 1)] = x->h.status;
		x->ndone++;
	}
	http_reset(&x->h);
}

static __always_inline void http_headers_done(struct http_run *x)
{
	struct http_dir *h = &x->h;

	if (x->is_resp) {
		/* The request is answered; what follows is not HTTP. */
		if (h->status == 101) {
			http_message_done(x);
			h->st = HS_OPAQUE;
			x->upgraded = 1;
			return;
		}
		/* An interim response; the real one follows. */
		if (h->status >= 100 && h->status < 200) {
			http_reset(h);
			return;
		}
		if (h->status == 204 || h->status == 304 ||
		    ((x->head_mask >> (x->ndone & (REQ_QUEUE - 1))) & 1)) {
			http_message_done(x);
			return;
		}
		if (h->flags & HF_CHUNKED) {
			h->st = HS_CHUNK_SIZE;
			h->num = 0;
		} else if (!(h->flags & HF_LENGTH)) {
			h->st = HS_BODY_EOF;
		} else if (h->num == 0) {
			http_message_done(x);
		} else {
			h->remain = h->num;
			h->st = HS_BODY;
		}
		return;
	}
	if (h->flags & HF_CHUNKED) {
		h->st = HS_CHUNK_SIZE;
		h->num = 0;
	} else if ((h->flags & HF_LENGTH) && h->num) {
		h->remain = h->num;
		h->st = HS_BODY;
	} else {
		http_message_done(x);
	}
}

/* One byte of a start line. */
static __always_inline void http_line_byte(struct http_run *x, u8 ch)
{
	struct http_dir *h = &x->h;

	if (ch == '\n') {
		if (h->lpos < 4) {
			http_lost(x);
			return;
		}
		if (!x->is_resp) {
			/* Only as many as can be queued are kept; all are counted. */
			if (x->nlines < REQ_QUEUE) {
				u32 k = x->nlines & (REQ_QUEUE - 1);

				__builtin_memcpy(x->lines[k], x->cur_line, REQ_LINE_LEN);
				x->line_len[k] = h->line_len;
				x->line_trunc[k] = h->line_trunc;
			}
			x->nlines++;
		}
		h->st = HS_HNAME;
		h->npos = 0;
		h->cand = HK_ALL;
		return;
	}
	if (h->lpos < 4)
		h->m4 |= (u32)ch << (8 * h->lpos);
	if (h->lpos == 3) {
		/* The fourth byte says whether this is HTTP/1 at all. */
		if (x->is_resp ? h->m4 != FOURCC('H', 'T', 'T', 'P') : !http_method(h->m4)) {
			http_lost(x);
			return;
		}
		if (!x->is_resp) {
			if (h->m4 == FOURCC('H', 'E', 'A', 'D') && x->nstart < HTTP_BATCH)
				x->head_new |= 1ull << (x->nstart & (HTTP_BATCH - 1));
			x->nstart++;
		}
	}
	if (x->is_resp) {
		/* "HTTP/1.1 200": the status is bytes 9 to 11. */
		if (h->lpos >= 9 && h->lpos <= 11 && ch >= '0' && ch <= '9')
			h->status = h->status * 10 + (ch - '0');
	} else if (h->lsp < 2) {
		/* Method and path; the query string and the version are left out. */
		if (ch == ' ')
			h->lsp++;
		else if (ch == '?' || ch == '\r')
			h->lsp = 2;
		if (h->lsp < 2) {
			if (h->line_len < REQ_LINE_LEN) {
				x->cur_line[h->line_len & (REQ_LINE_LEN - 1)] = ch;
				h->line_len++;
			} else {
				h->line_trunc = 1;
			}
		}
	}
	if (h->lpos < 255)
		h->lpos++;
}

static const char HTTP_H_LENGTH[16] = "content-length";
static const char HTTP_H_ENCODING[32] = "transfer-encoding";
static const char HTTP_CHUNKED[8] = "chunked";
static const char HTTP_H_TRACE[16] = "traceparent";

/*
 * One byte of a traceparent value; tpos counts the bytes after leading
 * blanks, 255 once the value is found not to be one. The version is not
 * checked beyond being two hex digits: later versions start the same way.
 * The trace id goes to the request whose header this is: the last whose
 * line ended in this call, or one whose line came in an earlier call.
 */
static __always_inline void http_trace_byte(struct http_run *x, u8 ch)
{
	struct http_dir *h = &x->h;
	u8 p = h->tpos;
	int v;

	if (p == 255)
		return;
	if (p == 0 && (ch == ' ' || ch == '\t'))
		return;
	if (p == 2 || p == TRACE_VALUE_END) {
		if (ch != '-') {
			h->tpos = 255;
			return;
		}
		if (p == TRACE_VALUE_END) {
			h->tpos = 255;
			if (!h->trace_nonzero)
				return;
			if (x->nlines) {
				u32 k = (x->nlines - 1) & (REQ_QUEUE - 1);

				if (x->nlines <= REQ_QUEUE) {
					__builtin_memcpy(x->traces[k], h->trace, 16);
					x->trace_mask |= 1u << k;
				}
			} else {
				__builtin_memcpy(x->trace_prev, h->trace, 16);
				x->trace_prev_ok = 1;
			}
			return;
		}
		h->tpos++;
		return;
	}
	v = http_hex(ch);
	if (v < 0) {
		h->tpos = 255;
		return;
	}
	if (p >= 3) {
		u8 i = ((p - 3) >> 1) & 15;

		if ((p - 3) & 1)
			h->trace[i] |= v;
		else
			h->trace[i] = v << 4;
		if (v)
			h->trace_nonzero = 1;
	}
	h->tpos++;
}

static __always_inline void http_byte(struct http_run *x, u8 ch)
{
	struct http_dir *h = &x->h;

	switch (h->st) {
	case HS_START:
		/* Blank lines between messages are allowed. */
		if (ch == '\r' || ch == '\n')
			return;
		h->st = HS_LINE;
		h->lpos = 0;
		h->lsp = 0;
		h->m4 = 0;
		h->status = 0;
		h->line_len = 0;
		h->line_trunc = 0;
		http_line_byte(x, ch);
		return;
	case HS_LINE:
		http_line_byte(x, ch);
		return;
	case HS_HNAME:
		if (h->npos == 0 && ch == '\r') {
			h->st = HS_HEND;
			return;
		}
		if (h->npos == 0 && ch == '\n') {
			http_headers_done(x);
			return;
		}
		if (ch == ':') {
			h->hk = 0;
			if ((h->cand & 1) && h->npos == 14)
				h->hk = HK_LENGTH;
			if ((h->cand & 2) && h->npos == 17)
				h->hk = HK_ENCODING;
			if ((h->cand & 4) && h->npos == 11 && !x->is_resp) {
				h->hk = HK_TRACE;
				h->trace_nonzero = 0;
			}
			if (h->hk == HK_LENGTH) {
				h->num = 0;
				h->flags |= HF_LENGTH;
			}
			h->tpos = 0;
			h->st = HS_HVAL;
			return;
		}
		if (ch == '\n') {
			h->npos = 0;
			h->cand = HK_ALL;
			return;
		}
		{
			u8 lc = http_lower(ch), n = h->npos;

			if (n >= 14 || HTTP_H_LENGTH[n & 15] != lc)
				h->cand &= ~1;
			if (n >= 17 || HTTP_H_ENCODING[n & 31] != lc)
				h->cand &= ~2;
			if (n >= 11 || HTTP_H_TRACE[n & 15] != lc)
				h->cand &= ~4;
		}
		if (h->npos < 255)
			h->npos++;
		return;
	case HS_HVAL:
		if (ch == '\n') {
			h->st = HS_HNAME;
			h->npos = 0;
			h->cand = HK_ALL;
			return;
		}
		if (h->hk == HK_LENGTH && ch >= '0' && ch <= '9') {
			h->num = h->num * 10 + (ch - '0');
		} else if (h->hk == HK_TRACE) {
			http_trace_byte(x, ch);
		} else if (h->hk == HK_ENCODING) {
			u8 lc = http_lower(ch);

			if (h->tpos < 7 && HTTP_CHUNKED[h->tpos & 7] == lc) {
				h->tpos++;
				if (h->tpos == 7)
					h->flags |= HF_CHUNKED;
			} else {
				h->tpos = (lc == 'c') ? 1 : 0;
			}
		}
		return;
	case HS_HEND:
		if (ch == '\n')
			http_headers_done(x);
		else
			h->st = HS_HNAME;
		return;
	case HS_CHUNK_SIZE: {
		int v = http_hex(ch);

		if (v >= 0) {
			h->num = h->num * 16 + v;
			return;
		}
		if (ch == ';') {
			h->st = HS_CHUNK_EXT;
			return;
		}
		if (ch != '\n')
			return;
	}
		/* fallthrough */
	case HS_CHUNK_EXT:
		if (ch != '\n')
			return;
		if (h->num == 0) {
			h->st = HS_TRAILER;
			h->npos = 0;
			return;
		}
		/* The data and the CRLF after it. */
		h->remain = h->num + 2;
		h->st = HS_CHUNK_DATA;
		return;
	case HS_TRAILER:
		if (ch == '\r')
			return;
		if (ch == '\n') {
			if (h->npos == 0) {
				http_message_done(x);
				return;
			}
			h->npos = 0;
			return;
		}
		h->npos = 1;
		return;
	}
}

/* bpf_loop callback: returns 1 when the call's data is used up or lost. */
static long http_step(u32 i, void *ctx)
{
	struct http_run *x = *(struct http_run **)ctx;
	struct http_dir *h;
	u64 left;
	u32 si;

	if (!x)
		return 1;
	h = &x->h;
	si = x->si;
	if (si >= x->nseg || si >= HTTP_SEGS)
		return 1;
	left = x->seg_len[si & (HTTP_SEGS - 1)] - x->so;
	if (left == 0) {
		x->si++;
		x->so = 0;
		return 0;
	}
	if (h->st == HS_UNSYNC || h->st == HS_OPAQUE) {
		/* A new message is only looked for at the start of a call. */
		x->si = x->nseg;
		return 1;
	}
	if (h->st == HS_BODY || h->st == HS_CHUNK_DATA) {
		u64 k = h->remain < left ? h->remain : left;

		x->so += k;
		h->remain -= k;
		if (h->remain == 0) {
			if (h->st == HS_BODY) {
				http_message_done(x);
			} else {
				h->st = HS_CHUNK_SIZE;
				h->num = 0;
			}
		}
		return 0;
	}
	if (h->st == HS_BODY_EOF) {
		x->so += left;
		return 0;
	}
	if (!x->seg_base[si & (HTTP_SEGS - 1)]) {
		/* Bytes the parser needs but cannot see. */
		http_lost(x);
		return 1;
	}
	if (x->buf_si != si || x->so < x->buf_so || x->so >= x->buf_so + x->buf_len) {
		u32 n = left < HTTP_BUF ? left : HTTP_BUF;

		if (bpf_probe_read_user(x->buf, n & (2 * HTTP_BUF - 1),
					(void *)(x->seg_base[si & (HTTP_SEGS - 1)] + x->so))) {
			http_lost(x);
			return 1;
		}
		x->buf_si = si;
		x->buf_so = x->so;
		x->buf_len = n;
	}
	http_byte(x, x->buf[(x->so - x->buf_so) & (HTTP_BUF - 1)]);
	x->so++;
	return 0;
}

#endif
