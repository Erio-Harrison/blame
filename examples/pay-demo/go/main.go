// The Go services of the pay demo, and its load. One binary, four roles:
//
//	pay -role payment -addr A -account A -ledger A [-risk HOST:PORT] -log FILE
//	pay -role account -addr A -http A -statements DIR [-lock-work D] -log FILE
//	pay -role ledger  -addr A -db FILE [-hold D] -log FILE
//	pay -role load    -addr GATEWAY -workers N -secs S [-think D]
//
// payment.Payments/Charge  300 us of computing; then, at the same time, the debit
//                          (account.Accounts/Debit) and, with -risk, the score
//                          (GET /score of the risk service, HTTP/1.1, at most 4
//                          at a time); then the entry (ledger.Ledger/Append)
// account.Accounts/Debit   100 us (or -lock-work) of computing under the balances'
//                          lock, then a 16 KB statement written to DIR and flushed
// account.Accounts/Balance 100 us of computing
// account, GET /features/N (HTTP/1.1, on -http): 50 us of computing; what the risk
//                          service asks for before it scores
// ledger.Ledger/Append     a row in SQLite (synchronous=FULL, one connection: one writer);
//                          with -hold, the transaction keeps the database locked that long
//
// Every call's traceparent is passed on, so one payment can be followed across the
// services. On SIGTERM each service writes what it measured itself, one line per call:
//
//	T <trace id> <method> <name>=<ns> ...
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	_ "modernc.org/sqlite"
)

// Messages are opaque bytes: no generated code.
type raw struct{}

func (raw) Marshal(v any) ([]byte, error) { return *v.(*[]byte), nil }
func (raw) Unmarshal(d []byte, v any) error {
	*v.(*[]byte) = append([]byte(nil), d...)
	return nil
}
func (raw) Name() string { return "proto" }

// compute spins for d.
func compute(d time.Duration) time.Duration {
	t0 := time.Now()
	for time.Since(t0) < d {
	}
	return time.Since(t0)
}

func traceparent(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("traceparent"); len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func traceID(tp string) string {
	if p := strings.Split(tp, "-"); len(p) == 4 {
		return p[1]
	}
	return "-"
}

// What a call measured, by name.
type record struct {
	trace, method string
	parts         []string
}

func (r *record) add(name string, d time.Duration) {
	r.parts = append(r.parts, fmt.Sprintf("%s=%d", name, d.Nanoseconds()))
}

var (
	logMu sync.Mutex
	logs  []*record
)

func method(name string, fn func(context.Context, *record) error) grpc.MethodDesc {
	return grpc.MethodDesc{MethodName: name, Handler: func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		var in []byte
		if err := dec(&in); err != nil {
			return nil, err
		}
		r := &record{trace: traceID(traceparent(ctx)), method: name}
		err := fn(ctx, r)
		logMu.Lock()
		logs = append(logs, r)
		logMu.Unlock()
		out := []byte{} // an empty protobuf message
		return &out, err
	}}
}

// call makes a unary call, passing the traceparent on.
func call(ctx context.Context, cc *grpc.ClientConn, full string) error {
	if tp := traceparent(ctx); tp != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "traceparent", tp)
	}
	in, out := []byte("x"), []byte{}
	return cc.Invoke(ctx, full, &in, &out)
}

func dial(addr string) *grpc.ClientConn {
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	return cc
}

func main() {
	role := flag.String("role", "", "payment | account | ledger | load")
	addr := flag.String("addr", "", "listen address (load: the gateway)")
	httpAddr := flag.String("http", "", "account: listen address of GET /features")
	accountAddr := flag.String("account", "", "payment: account address")
	ledgerAddr := flag.String("ledger", "", "payment: ledger address")
	riskAddr := flag.String("risk", "", "payment: the risk service, host:port (none: no score)")
	statements := flag.String("statements", "", "account: directory for statements")
	dbPath := flag.String("db", "", "ledger: SQLite file")
	hold := flag.Duration("hold", 0, "ledger: how long each transaction keeps the database locked")
	lockWork := flag.Duration("lock-work", 100*time.Microsecond, "account: computing done under the balances' lock")
	logPath := flag.String("log", "", "where to write the records")
	workers := flag.Int("workers", 8, "load: workers")
	secs := flag.Float64("secs", 20, "load: seconds")
	think := flag.Duration("think", 2*time.Millisecond, "load: pause between a worker's requests")
	flag.Parse()
	encoding.RegisterCodec(raw{})
	var desc grpc.ServiceDesc
	switch *role {
	case "load":
		load(*addr, *workers, *secs, *think)
		return
	case "payment":
		account, ledger := dial(*accountAddr), dial(*ledgerAddr)
		scores := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4, MaxConnsPerHost: 4}}
		desc = grpc.ServiceDesc{ServiceName: "payment.Payments", HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{
			method("Charge", func(ctx context.Context, r *record) error {
				r.add("compute", compute(300*time.Microsecond))
				t := time.Now()
				var wg sync.WaitGroup
				var debitErr, riskErr error
				var debit, risk time.Duration
				wg.Add(1)
				go func() {
					defer wg.Done()
					t := time.Now()
					debitErr = call(ctx, account, "/account.Accounts/Debit")
					debit = time.Since(t)
				}()
				if *riskAddr != "" {
					wg.Add(1)
					go func() {
						defer wg.Done()
						t := time.Now()
						req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+*riskAddr+"/score", nil)
						req.Header.Set("traceparent", traceparent(ctx))
						resp, err := scores.Do(req)
						if err == nil {
							io.Copy(io.Discard, resp.Body)
							resp.Body.Close()
						}
						riskErr = err
						risk = time.Since(t)
					}()
				}
				wg.Wait()
				r.add("debit", debit)
				if *riskAddr != "" {
					r.add("risk", risk)
				}
				r.add("checks", time.Since(t))
				if debitErr != nil {
					return debitErr
				}
				if riskErr != nil {
					return riskErr
				}
				t = time.Now()
				err := call(ctx, ledger, "/ledger.Ledger/Append")
				r.add("ledger", time.Since(t))
				return err
			}),
		}}
	case "account":
		var balances sync.Mutex
		statement := make([]byte, 16<<10)
		var seq atomic.Int64
		desc = grpc.ServiceDesc{ServiceName: "account.Accounts", HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{
			method("Debit", func(ctx context.Context, r *record) error {
				t := time.Now()
				balances.Lock()
				r.add("lock", time.Since(t))
				r.add("compute", compute(*lockWork))
				balances.Unlock()
				t = time.Now()
				f, err := os.Create(filepath.Join(*statements, fmt.Sprintf("statement-%d", seq.Add(1)%256)))
				if err != nil {
					return err
				}
				if _, err = f.Write(statement); err == nil {
					err = f.Sync()
				}
				f.Close()
				r.add("statement", time.Since(t))
				return err
			}),
			method("Balance", func(ctx context.Context, r *record) error {
				r.add("compute", compute(100*time.Microsecond))
				return nil
			}),
		}}
		mux := http.NewServeMux()
		mux.HandleFunc("/features/", func(w http.ResponseWriter, _ *http.Request) {
			compute(50 * time.Microsecond)
			io.WriteString(w, `{"age_days":412,"payments_30d":9}`)
		})
		hl, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			panic(err)
		}
		go http.Serve(hl, mux)
	case "ledger":
		db, err := sql.Open("sqlite", "file:"+*dbPath+"?_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)&_pragma=busy_timeout(10000)")
		if err != nil {
			panic(err)
		}
		db.SetMaxOpenConns(1)
		if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY AUTOINCREMENT, amount INTEGER, trace TEXT)`); err != nil {
			panic(err)
		}
		desc = grpc.ServiceDesc{ServiceName: "ledger.Ledger", HandlerType: (*any)(nil), Methods: []grpc.MethodDesc{
			method("Append", func(ctx context.Context, r *record) error {
				t := time.Now()
				tx, err := db.BeginTx(ctx, nil)
				if err == nil {
					_, err = tx.ExecContext(ctx, `INSERT INTO entries(amount, trace) VALUES(?, ?)`, rand.Intn(10000), r.trace)
					if err == nil && *hold > 0 {
						time.Sleep(*hold)
					}
					if err == nil {
						err = tx.Commit()
					} else {
						tx.Rollback()
					}
				}
				r.add("db", time.Since(t))
				return err
			}),
		}}
	default:
		panic("-role payment|account|ledger|load")
	}
	s := grpc.NewServer()
	s.RegisterService(&desc, nil)
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		panic(err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go s.Serve(l)
	fmt.Println("ready", *role, *addr)
	<-stop
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.Create(*logPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for _, r := range logs {
		fmt.Fprintf(f, "T %s %s %s\n", r.trace, r.method, strings.Join(r.parts, " "))
	}
}

// load sends HTTP to the gateway: 40% POST /pay, 60% GET /balance/N, each with its own trace id.
func load(addr string, workers int, secs float64, think time.Duration) {
	cl := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: workers, MaxConnsPerHost: workers}}
	end := time.Now().Add(time.Duration(secs * float64(time.Second)))
	run := time.Now().UnixNano() & 0xffffffff
	var seq atomic.Int64
	var mu sync.Mutex
	lat := map[string][]time.Duration{}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; time.Now().Before(end); i++ {
				n := seq.Add(1)
				var req *http.Request
				route := "GET /balance"
				if i%5 < 2 {
					route = "POST /pay"
					req, _ = http.NewRequest("POST", "http://"+addr+"/pay", strings.NewReader("amount=42"))
				} else {
					req, _ = http.NewRequest("GET", fmt.Sprintf("http://%s/balance/%d", addr, n), nil)
				}
				req.Header.Set("traceparent", fmt.Sprintf("00-%08x%024x-%016x-01", run, n, n))
				t0 := time.Now()
				resp, err := cl.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.StatusCode != 200 {
						route += fmt.Sprintf(" %d", resp.StatusCode)
					}
				} else {
					route += " error"
				}
				mu.Lock()
				lat[route] = append(lat[route], time.Since(t0))
				mu.Unlock()
				time.Sleep(think)
			}
		}(w)
	}
	wg.Wait()
	routes := make([]string, 0, len(lat))
	for r := range lat {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	for _, r := range routes {
		l := lat[r]
		sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
		fmt.Printf("load %-14s n=%-6d p50=%-12v p99=%v\n", r, len(l), l[len(l)/2], l[len(l)*99/100])
	}
}
