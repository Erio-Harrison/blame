// Load for the gRPC ground-truth servers.
//
//	client PORT CONNS WORKERS_PER_CONN SECONDS KINDS PARAMS[;PARAMS...] [hello]
//
// KINDS is a comma list of U, SS, CS, BI, T: each call picks one and one
// PARAMS ("cpu_us,sleep_us,cpu2_us,code", see the servers) at random. Every
// call carries a traceparent header with a trace id of its own, which is how
// the servers' records and the agent's are matched. With the environment
// variable NO_TRACEPARENT set they carry none.
//
// T is a unary call the client gives up on: the server is asked to sleep
// 150 ms and the call's deadline is 20 ms. Each one is printed as
// `X <trace id> <method path>`.
//
// With `hello`, every call is a unary /helloworld.Greeter/SayHello with the
// parameters as the name of a protobuf HelloRequest: what the tonic server
// speaks.
//
// With GRPC_TLS set, the calls go over TLS (the certificate not checked).
package main

import (
	"crypto/tls"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type raw struct{}

func (raw) Marshal(v interface{}) ([]byte, error) { return *v.(*[]byte), nil }
func (raw) Unmarshal(d []byte, v interface{}) error {
	*v.(*[]byte) = append([]byte(nil), d...)
	return nil
}
func (raw) Name() string { return "proto" }

func main() {
	conns, _ := strconv.Atoi(os.Args[2])
	workers, _ := strconv.Atoi(os.Args[3])
	secs, _ := strconv.ParseFloat(os.Args[4], 64)
	kinds := strings.Split(os.Args[5], ",")
	params := strings.Split(os.Args[6], ";")
	hello := len(os.Args) > 7 && os.Args[7] == "hello"
	var total, failed, uniq int64
	var mu sync.Mutex
	run := uint64(time.Now().UnixNano())
	// With NO_TRACEPARENT set, calls carry no trace header: the headers of every
	// call are then the same, and HPACK never spells the method out again.
	noTrace := os.Getenv("NO_TRACEPARENT") != ""
	var wg sync.WaitGroup
	end := time.Now().Add(time.Duration(secs * float64(time.Second)))
	co := grpc.ForceCodec(raw{})
	for c := 0; c < conns; c++ {
		creds := insecure.NewCredentials()
		if os.Getenv("GRPC_TLS") != "" {
			creds = credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
		}
		cc, err := grpc.NewClient("127.0.0.1:"+os.Args[1], grpc.WithTransportCredentials(creds))
		if err != nil {
			panic(err)
		}
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				r := rand.New(rand.NewSource(seed))
				for time.Now().Before(end) {
					n := uint64(atomic.AddInt64(&uniq, 1))
					traceID := fmt.Sprintf("%016x%016x", run, n)
					ctx := context.Background()
					if !noTrace {
						ctx = metadata.AppendToOutgoingContext(ctx,
							"traceparent", fmt.Sprintf("00-%s-%016x-01", traceID, n))
					}
					msg := func() *[]byte {
						b := []byte(params[r.Intn(len(params))])
						if hello {
							b = append([]byte{0x0a, byte(len(b))}, b...)
						}
						return &b
					}
					kind := kinds[r.Intn(len(kinds))]
					var rep []byte
					var err error
					if kind == "T" {
						path := "/x.S/U"
						if hello {
							path = "/helloworld.Greeter/SayHello"
						}
						b := []byte("0,150000,0,0")
						if hello {
							b = append([]byte{0x0a, byte(len(b))}, b...)
						}
						short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
						err = cc.Invoke(short, path, &b, &rep, co)
						cancel()
						// Past its deadline, or told so by a server that
						// got there first (CANCELLED, DEADLINE_EXCEEDED).
						if err != nil {
							mu.Lock()
							fmt.Printf("X %s %s\n", traceID, path)
							mu.Unlock()
						}
						time.Sleep(time.Duration(r.Intn(1000)) * time.Microsecond)
						continue
					}
					if hello {
						err = cc.Invoke(ctx, "/helloworld.Greeter/SayHello", msg(), &rep, co)
					} else if kind == "U" {
						err = cc.Invoke(ctx, "/x.S/U", msg(), &rep, co)
					} else {
						d := &grpc.StreamDesc{ServerStreams: kind != "CS", ClientStreams: kind != "SS"}
						var st grpc.ClientStream
						st, err = cc.NewStream(ctx, d, "/x.S/"+kind, co)
						if err == nil {
							sends := 1
							if kind != "SS" {
								sends = 3
							}
							for i := 0; i < sends; i++ {
								st.SendMsg(msg())
								if kind == "BI" {
									st.RecvMsg(&rep)
								}
								time.Sleep(time.Duration(r.Intn(300)) * time.Microsecond)
							}
							st.CloseSend()
							for err == nil {
								err = st.RecvMsg(&rep)
							}
							if err == io.EOF {
								err = nil
							}
						}
					}
					if err == nil {
						atomic.AddInt64(&total, 1)
					} else {
						atomic.AddInt64(&failed, 1)
					}
					time.Sleep(time.Duration(r.Intn(1000)) * time.Microsecond)
				}
			}(int64(c*100 + w))
		}
	}
	wg.Wait()
	fmt.Printf("calls ok=%d error=%d\n", total, failed)
}
