/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
/*
 * Requests: where each one starts and ends on a client-facing TCP socket, and
 * which time belongs to it. The
 * execution unit is the thread, or what the process's runtime runs on it
 * (runtime/runtime.h); "thread" below stands for either.
 *
 * - Socket calls of traced processes feed an HTTP/1.1 parser per connection
 *   (proto/http1.h). A request starts at the read that brings its first byte and
 *   ends at the write that carries the last byte of its response.
 * - A thread is bound to the request it reads. While bound, its CPU time,
 *   run-queue time and sleeps go to that request. A thread that is not bound
 *   keeps the same time as "pending", and hands it to a request when it
 *   writes that request's response.
 * - A binding ends when the response is written, and also when the thread
 *   turns to something else: it reads another request, reads the answer to
 *   another request's downstream call, or writes another request's response.
 * - Why a sleeping thread woke decides what the sleep was: data on the
 *   request's own downstream socket, more of the request from the client, or
 *   new work, which means the thread was idle and the binding ends. A thread
 *   woken by one that is serving a request was waiting for work: its pending
 *   time is dropped.
 * - A downstream call made while bound is also timed on its own socket, which
 *   is the only way to time it in an event loop. The protocol is not parsed:
 *   a call is the writes on the socket and everything read after them, until
 *   a write that follows a read which left nothing unread. That is exact
 *   while the connection carries one call at a time; requests pipelined by
 *   one request count as one call; calls of different requests overlapping
 *   on one connection are not timed.
 * - A finished request goes into its cgroup's latency histogram; one slower
 *   than req_slow_ns (0 under `blame slow`: every one) is also sent to user
 *   space.
 * - A connection that speaks HTTP/2 (proto/http2.h) has one request per stream.
 *   Nothing above about threads applies to it yet: see h2_call() in request/http2.h.
 */
#ifndef BLAME_REQUEST_H
#define BLAME_REQUEST_H

#include "../proto/http1.h"
#include "../proto/http2.h"
#include "../runtime/runtime.h"

#include "maps.h"
#include "units.h"
#include "conn.h"
#include "core.h"
#include "http1.h"
#include "http2.h"
#include "calls.h"
#include "fsvc.h"
#include "proc_cpu.h"
#include "wake.h"

/* Probes inside runtimes and libraries; they use everything above. */
#include "../runtime/go_grpc.h"
#include "../runtime/go_spawn.h"
#include "../runtime/go_park.h"
#include "../runtime/tokio_tasks.h"
#include "../runtime/rust_h2.h"
#include "../runtime/omp.h"

#endif
