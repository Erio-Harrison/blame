// An HTTP/1.1 server on net/http that knows the answer, for the Go runtime
// adapter: it writes the same log as http_truth.c (one record per request:
// first byte read, last byte written, time spent computing, time parked), so
// `blame slow` can be checked against it with http_check.py.
//
//	go_truth PORT LOGFILE [-b BACKEND_PORT] [-p GOMAXPROCS]
//
// With TLS_CERT and TLS_KEY set (PEM files), it serves HTTPS.
//
// Query parameters: size=N body bytes, cpu=US spin, sleep=US (time.Sleep: the
// goroutine parks, its thread goes on to other goroutines), d=US (a call to
// the backend, an http_truth server, on a connection of the goroutine's own),
// cpu2=US spin after those, in that order.
//
// Parking, after sleep and before d: pch=US waits on a channel a timer closes US
// later, pmu=US for a mutex a timer unlocks US later. For requests that
// sleep, call the backend or do these, a record (type 4) holds how long the
// goroutine waited on each: channel, mutex, sleep, network.
//
// Spawned goroutines, before cpu2: kids=N goroutines, each spinning kcpu=US
// and, with kfsync=KB, appending KB to a file and flushing it to disk; with
// knest=1 each starts one more that does the same. The handler waits for
// them all. bg=US starts one more that waits 5 ms, then spins US: after the
// response, so none of it is the request's. For such requests a second
// record (type 3) holds what the spawned goroutines did: the CPU of their
// spins, their write-and-flush time, and how many were started.
//
// Clock readings go through the vDSO, so the server makes no system calls
// beyond the ones net/http makes anyway. The log is written on SIGTERM or
// SIGINT.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	recReq  = 1
	recHelp = 3
	recPark = 4
	fDown   = 8
)

// struct rec of http_truth.c.
type rec struct {
	Type, Label uint8
	Flags       uint16
	Tid         uint32
	T0, T1      uint64
	Port, Seq   uint32
	CPU, Blk    uint64
	TDeq, TDown uint64
	TidRead     uint32
	Outstanding uint32
}

var (
	base       time.Time
	bootAtBase int64
	logMu      sync.Mutex
	logRecs    []rec
	connsMu    sync.Mutex
	conns      = map[*conn]struct{}{}
	backend    string
	body       = bytes.Repeat([]byte("x"), 1<<20)
	logPath    string
	syncFiles  = sync.Pool{New: func() any {
		f, err := os.CreateTemp(filepath.Dir(logPath), filepath.Base(logPath)+".sync")
		if err != nil {
			panic(err)
		}
		os.Remove(f.Name())
		return f
	}}
)

// CLOCK_BOOTTIME, the clock the kernel side stamps events with.
func now() uint64 { return uint64(bootAtBase + int64(time.Since(base))) }

func bootClock() int64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&ts)), 0)
	return ts.Nano()
}

// What the handler did for the request being answered.
type work struct {
	cpu, blk, tdeq, tdown uint64
	down                  bool
	// What the goroutines it spawned did; spawned 0: none.
	helpCPU, helpIO, spawned uint64
	// How long the handler's goroutine waited, by why; parked: any of these.
	parkChan, parkSync, parkSleep, parkNet uint64
	parked                                bool
}

// What a spawned goroutine does; it adds what it did to `did`.
func kid(did *work, mu *sync.Mutex, cpu, fsyncKB int, nest bool) {
	var child sync.WaitGroup
	if nest {
		mu.Lock()
		did.spawned++
		mu.Unlock()
		child.Add(1)
		go func() {
			defer child.Done()
			kid(did, mu, cpu, fsyncKB, false)
		}()
	}
	c := spin(cpu)
	var io uint64
	if fsyncKB > 0 {
		f := syncFiles.Get().(*os.File)
		t0 := time.Now()
		f.Write(body[:fsyncKB*1024])
		f.Sync()
		io = uint64(time.Since(t0))
		syncFiles.Put(f)
	}
	child.Wait()
	mu.Lock()
	did.helpCPU += c
	did.helpIO += io
	mu.Unlock()
}

// A client connection that notes when requests start and responses end. A
// request starts at the first read that brings data after the previous
// response; that response ended at the last write before it.
type conn struct {
	net.Conn
	mu        sync.Mutex
	port, seq uint32
	start     uint64
	// Written by the handler's goroutine, read by whoever ends the request:
	// atomic, so that the handler takes no lock of the server's own while
	// it answers (it would be a wait the log does not show).
	lastWrite uint64
	// The handler has returned: the next data is a new request.
	answered bool
	open     bool
	done     work
	down     net.Conn
	// Records of the requests it has carried.
	recs []rec
}

func (c *conn) finish() {
	if !c.answered {
		return
	}
	r := rec{Type: recReq, T0: c.start, T1: atomic.LoadUint64(&c.lastWrite), Port: c.port, Seq: c.seq,
		CPU: c.done.cpu, Blk: c.done.blk, TDeq: c.done.tdeq, TDown: c.done.tdown}
	if c.done.down {
		r.Flags = fDown
	}
	// Kept with the connection, under its own lock: a log shared by all
	// connections would make every request that starts while it grows wait
	// on its lock, a wait the log itself does not show.
	c.recs = append(c.recs, r)
	if c.done.parked {
		c.recs = append(c.recs, rec{Type: recPark, Port: c.port, Seq: c.seq,
			CPU: c.done.parkChan, Blk: c.done.parkSync, TDeq: c.done.parkSleep, TDown: c.done.parkNet})
	}
	if c.done.spawned > 0 {
		c.recs = append(c.recs, rec{Type: recHelp, Port: c.port, Seq: c.seq,
			CPU: c.done.helpCPU, Blk: c.done.helpIO, TDeq: c.done.spawned})
	}
	c.seq++
	c.answered = false
	c.open = false
}

func (c *conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		ts := now()
		c.mu.Lock()
		c.finish()
		if !c.open {
			c.open = true
			c.start = ts
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *conn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	ts := now()
	atomic.StoreUint64(&c.lastWrite, ts)
	return n, err
}

func (c *conn) Close() error {
	c.mu.Lock()
	c.finish()
	if c.down != nil {
		c.down.Close()
	}
	c.mu.Unlock()
	// Under connsMu, as the SIGTERM writer takes it: a connection is either
	// still in conns or its records are already in logRecs.
	connsMu.Lock()
	delete(conns, c)
	logMu.Lock()
	logRecs = append(logRecs, c.recs...)
	logMu.Unlock()
	connsMu.Unlock()
	return c.Conn.Close()
}

type listener struct{ net.Listener }

func (l listener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c := &conn{Conn: raw, port: uint32(raw.RemoteAddr().(*net.TCPAddr).Port)}
	connsMu.Lock()
	conns[c] = struct{}{}
	connsMu.Unlock()
	return c, nil
}

type connKey struct{}

// One call to the backend on the goroutine's own connection; false if it failed.
func (c *conn) call(us int) bool {
	if c.down == nil {
		d, err := net.Dial("tcp", backend)
		if err != nil {
			return false
		}
		c.down = d
	}
	if _, err := fmt.Fprintf(c.down, "GET /x?sleep=%d&size=100 HTTP/1.1\r\nHost: b\r\n\r\n", us); err != nil {
		return false
	}
	buf := make([]byte, 0, 4096)
	for {
		n, err := c.down.Read(buf[len(buf):cap(buf)])
		if n <= 0 || err != nil {
			return false
		}
		buf = buf[:len(buf)+n]
		head := bytes.Index(buf, []byte("\r\n\r\n"))
		if head < 0 {
			continue
		}
		length := 0
		if at := bytes.Index(buf[:head], []byte("Content-Length: ")); at >= 0 {
			rest := buf[at+16 : head]
			if end := bytes.IndexByte(rest, '\r'); end >= 0 {
				rest = rest[:end]
			}
			length, _ = strconv.Atoi(string(rest))
		}
		if len(buf) >= head+4+length {
			return true
		}
	}
}

func param(r *http.Request, name string) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return -1
	}
	return v
}

// Compute for `us` microseconds without a system call; the time it computed.
//
// A gap between two readings of the clock is time the goroutine was not
// running: the garbage collector preempts goroutines in the middle of a spin,
// and one waits milliseconds for a thread again when all are busy. Counted as
// computing (as it was: the wall time of the spin), that made the server's
// total 5-10% more than the CPU its requests had. The gap is left out, and the
// spin goes on until it has computed its time.
func spin(us int) uint64 {
	if us <= 0 {
		return 0
	}
	want := time.Duration(us) * time.Microsecond
	var done time.Duration
	last := time.Now()
	for done < want {
		now := time.Now()
		if d := now.Sub(last); d < spinGap {
			done += d
		}
		last = now
	}
	return uint64(done)
}

// Longer than an interrupt takes, shorter than any wait for a thread.
const spinGap = 100 * time.Microsecond

func handle(w http.ResponseWriter, r *http.Request) {
	c := r.Context().Value(connKey{}).(*conn)
	var did work
	did.cpu = spin(param(r, "cpu"))
	if us := param(r, "sleep"); us > 0 {
		t0 := time.Now()
		time.Sleep(time.Duration(us) * time.Microsecond)
		did.blk += uint64(time.Since(t0))
		did.parkSleep += uint64(time.Since(t0))
		did.parked = true
	}
	// Waits on a channel that a timer closes US later.
	if us := param(r, "pch"); us > 0 {
		ch := make(chan struct{})
		time.AfterFunc(time.Duration(us)*time.Microsecond, func() { close(ch) })
		t0 := time.Now()
		<-ch
		did.parkChan += uint64(time.Since(t0))
		did.parked = true
	}
	// Waits for a mutex that a timer unlocks US later.
	if us := param(r, "pmu"); us > 0 {
		var m sync.Mutex
		m.Lock()
		time.AfterFunc(time.Duration(us)*time.Microsecond, m.Unlock)
		t0 := time.Now()
		m.Lock()
		did.parkSync += uint64(time.Since(t0))
		did.parked = true
	}
	if us := param(r, "d"); us >= 0 && backend != "" {
		did.down = true
		did.tdeq = now()
		if c.call(us) {
			did.tdown = now()
			did.blk += did.tdown - did.tdeq
			did.parkNet += did.tdown - did.tdeq
			did.parked = true
		}
	}
	if n := param(r, "kids"); n > 0 {
		var all sync.WaitGroup
		var mu sync.Mutex
		cpu, fsyncKB, nest := param(r, "kcpu"), param(r, "kfsync"), param(r, "knest") > 0
		for i := 0; i < n; i++ {
			mu.Lock()
			did.spawned++
			mu.Unlock()
			all.Add(1)
			go func() {
				defer all.Done()
				kid(&did, &mu, cpu, fsyncKB, nest)
			}()
		}
		all.Wait()
	}
	if us := param(r, "bg"); us > 0 {
		did.spawned++
		go func() {
			time.Sleep(5 * time.Millisecond)
			spin(us)
		}()
	}
	did.cpu += spin(param(r, "cpu2"))
	size := param(r, "size")
	if size < 0 {
		size = 64
	}
	if size > len(body) {
		size = len(body)
	}
	w.Header().Set("Content-Length", strconv.Itoa(size))
	// The one lock of the server's own the handler takes: a wait for it is a
	// wait on a sync primitive like the others.
	t0 := time.Now()
	c.mu.Lock()
	if waited := uint64(time.Since(t0)); did.parked {
		did.parkSync += waited
	}
	c.done = did
	c.answered = true
	c.mu.Unlock()
	w.Write(body[:size])
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: go_truth PORT LOGFILE [-b BACKEND_PORT] [-p GOMAXPROCS]")
		os.Exit(2)
	}
	for i := 3; i+1 < len(os.Args); i += 2 {
		switch os.Args[i] {
		case "-b":
			backend = "127.0.0.1:" + os.Args[i+1]
		case "-p":
			n, _ := strconv.Atoi(os.Args[i+1])
			runtime.GOMAXPROCS(n)
		}
	}
	logPath = os.Args[2]
	bootAtBase, base = bootClock(), time.Now()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		connsMu.Lock()
		logMu.Lock()
		for c := range conns {
			c.mu.Lock()
			c.finish()
			logRecs = append(logRecs, c.recs...)
			c.mu.Unlock()
		}
		connsMu.Unlock()
		var out bytes.Buffer
		binary.Write(&out, binary.LittleEndian, logRecs)
		os.WriteFile(os.Args[2], out.Bytes(), 0o644)
		os.Exit(0)
	}()

	l, err := net.Listen("tcp", "127.0.0.1:"+os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// With TLS_CERT and TLS_KEY: HTTPS. The connection the log is kept by
	// wraps the TLS one, so that a request starts when its plaintext is read
	// and ends when its answer is handed to TLS, as without TLS.
	if crt := os.Getenv("TLS_CERT"); crt != "" {
		cert, err := tls.LoadX509KeyPair(crt, os.Getenv("TLS_KEY"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		l = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}})
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(handle),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, c)
		},
	}
	srv.Serve(listener{l})
}
