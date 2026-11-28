// A gRPC server that says what it did, to check `blame slow` against.
//
//	server PORT LOGFILE [GOMAXPROCS]
//
// No generated code, so it builds against any grpc-go version: messages are
// raw bytes, "cpu_us,sleep_us,cpu2_us,code" (compute, sleep, compute, then
// answer with that gRPC status code). Methods of service x.S: U (unary), SS
// (three answers), CS (answers when the client is done), BI (one answer per
// message).
//
// On SIGTERM it writes one line per call:
//
//	T <trace id> <method path> <status> <goroutine> <start> <end> <cpu ns> <client port> <stream>
//
// The trace id is from the call's traceparent header; start and end are when
// the handler ran (CLOCK_BOOTTIME ns); cpu is how long it computed; the
// stream is the call's HTTP/2 stream id on the connection from that port.
// And one line per call whose headers it read, handled or not (a call the
// client gave up on may never reach a handler), with when it read them
// (CLOCK_BOOTTIME ns):
//
//	H <trace id> <method path> <read>
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

type raw struct{}

func (raw) Marshal(v interface{}) ([]byte, error) { return *v.(*[]byte), nil }
func (raw) Unmarshal(d []byte, v interface{}) error {
	*v.(*[]byte) = append([]byte(nil), d...)
	return nil
}
func (raw) Name() string { return "proto" }

var (
	base     time.Time
	bootBase int64
	mu       sync.Mutex
	out      bytes.Buffer
)

func now() int64 { return bootBase + int64(time.Since(base)) }

func goid() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	id, _ := strconv.ParseUint(strings.Fields(string(buf[:n]))[1], 10, 64)
	return id
}

// Compute for `us` microseconds; the time it computed. A gap between two
// readings of the clock is time the goroutine was not running (the garbage
// collector preempts it in a spin, and it waits milliseconds for a thread
// when all are busy): left out, as in go_truth, and the spin goes on until
// it has computed its time.
func spin(us int) int64 {
	if us <= 0 {
		return 0
	}
	want := time.Duration(us) * time.Microsecond
	var done time.Duration
	last := time.Now()
	for done < want {
		now := time.Now()
		if d := now.Sub(last); d < 100*time.Microsecond {
			done += d
		}
		last = now
	}
	return int64(done)
}

func trace(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("traceparent"); len(v) > 0 {
		if p := strings.Split(v[0], "-"); len(p) == 4 {
			return p[1]
		}
	}
	return "-"
}

// where is the client's port and the HTTP/2 stream id of the call. The id is
// not part of grpc-go's interface: it is read out of the transport's stream.
func where(ctx context.Context) (int, uint64) {
	port := 0
	if p, ok := peer.FromContext(ctx); ok {
		if a, ok := p.Addr.(*net.TCPAddr); ok {
			port = a.Port
		}
	}
	v := reflect.ValueOf(grpc.ServerTransportStreamFromContext(ctx))
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return port, 0
	}
	id := v.Elem().FieldByName("id")
	if !id.IsValid() {
		return port, 0
	}
	return port, id.Uint()
}

// work does what one message asks for; it returns the CPU time spent and
// the status code the message asks the call to end with.
func work(msg []byte) (int64, codes.Code) {
	p := strings.Split(string(msg), ",")
	n := func(i int) int {
		if i >= len(p) {
			return 0
		}
		v, _ := strconv.Atoi(p[i])
		return v
	}
	cpu := spin(n(0))
	if us := n(1); us > 0 {
		time.Sleep(time.Duration(us) * time.Microsecond)
	}
	return cpu + spin(n(2)), codes.Code(n(3))
}

func record(ctx context.Context, kind string, code codes.Code, g uint64, t0, cpu int64) error {
	t1 := now()
	mu.Lock()
	port, sid := where(ctx)
	fmt.Fprintf(&out, "T %s /x.S/%s %d %d %d %d %d %d %d\n", trace(ctx), kind, code, g, t0, t1, cpu, port, sid)
	mu.Unlock()
	if code != codes.OK {
		return status.Error(code, "as asked")
	}
	return nil
}

func unary(srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
	var in []byte
	if err := dec(&in); err != nil {
		return nil, err
	}
	g, t0 := goid(), now()
	cpu, code := work(in)
	if err := record(ctx, "U", code, g, t0, cpu); err != nil {
		return nil, err
	}
	r := []byte("ok")
	return &r, nil
}

func stream(kind string) grpc.StreamHandler {
	return func(srv interface{}, ss grpc.ServerStream) error {
		g, t0 := goid(), now()
		var cpu int64
		code := codes.OK
		r := []byte("ok")
		for {
			var in []byte
			if err := ss.RecvMsg(&in); err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			c, asked := work(in)
			cpu += c
			if asked != codes.OK {
				code = asked
			}
			switch kind {
			case "SS":
				for i := 0; i < 3; i++ {
					cpu += spin(50)
					ss.SendMsg(&r)
				}
			case "BI":
				ss.SendMsg(&r)
			}
		}
		if kind == "CS" && code == codes.OK {
			ss.SendMsg(&r)
		}
		return record(ss.Context(), kind, code, g, t0, cpu)
	}
}

// heard logs every call whose headers the server read off the connection.
type heard struct{}

func (heard) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context { return ctx }
func (heard) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}
func (heard) HandleConn(context.Context, stats.ConnStats) {}
func (heard) HandleRPC(_ context.Context, s stats.RPCStats) {
	h, ok := s.(*stats.InHeader)
	if !ok {
		return
	}
	t := "-"
	if v := h.Header.Get("traceparent"); len(v) > 0 {
		if p := strings.Split(v[0], "-"); len(p) == 4 {
			t = p[1]
		}
	}
	at := now()
	mu.Lock()
	fmt.Fprintf(&out, "H %s %s %d\n", t, h.FullMethod, at)
	mu.Unlock()
}

func main() {
	// CLOCK_BOOTTIME, the clock the agent stamps requests with, lined up with
	// Go's: read between two readings of Go's clock, and the closest pair of
	// a few kept. One reading after the other left this server's times early
	// by the time between the two, a microsecond when it was unlucky.
	var gap time.Duration
	for i := 0; i < 32; i++ {
		var ts syscall.Timespec
		before := time.Now()
		syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&ts)), 0)
		if d := time.Since(before); i == 0 || d < gap {
			gap, bootBase, base = d, ts.Nano(), before.Add(d/2)
		}
	}
	if len(os.Args) > 3 {
		p, _ := strconv.Atoi(os.Args[3])
		runtime.GOMAXPROCS(p)
	}
	encoding.RegisterCodec(raw{})
	lis, err := net.Listen("tcp", "127.0.0.1:"+os.Args[1])
	if err != nil {
		panic(err)
	}
	opts := []grpc.ServerOption{grpc.StatsHandler(heard{})}
	// With TLS_CERT and TLS_KEY set (PEM files): over TLS.
	if crt := os.Getenv("TLS_CERT"); crt != "" {
		creds, err := credentials.NewServerTLSFromFile(crt, os.Getenv("TLS_KEY"))
		if err != nil {
			panic(err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	if v, _ := strconv.Atoi(os.Getenv("WORKERS")); v > 0 {
		opts = append(opts, grpc.NumStreamWorkers(uint32(v)))
	}
	s := grpc.NewServer(opts...)
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "x.S",
		HandlerType: (*interface{})(nil),
		Methods:     []grpc.MethodDesc{{MethodName: "U", Handler: unary}},
		Streams: []grpc.StreamDesc{
			{StreamName: "SS", Handler: stream("SS"), ServerStreams: true},
			{StreamName: "CS", Handler: stream("CS"), ClientStreams: true},
			{StreamName: "BI", Handler: stream("BI"), ServerStreams: true, ClientStreams: true},
		},
	}, struct{}{})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stop
		mu.Lock()
		os.WriteFile(os.Args[2], out.Bytes(), 0o644)
		os.Exit(0)
	}()
	s.Serve(lis)
}
