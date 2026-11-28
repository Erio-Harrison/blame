//! A tonic gRPC server that says what it did, to check `blame slow` against.
//!
//!     tonic_truth PORT LOGFILE [WORKERS]
//!
//! One method, /helloworld.Greeter/SayHello. The request's name is
//! "cpu_us,sleep_us,cpu2_us,code": compute, sleep, compute, then answer
//! with that gRPC status code. WORKERS 0 runs a current-thread runtime.
//!
//! On SIGTERM it writes one line per call:
//!
//!     T <trace id> <method path> <status> <task id> <start> <end> <cpu ns> <client port> 0
//!
//! The trace id is from the call's traceparent header; start and end are
//! when the handler ran (CLOCK_BOOTTIME ns); cpu is how long it computed.
//! (The last field is the HTTP/2 stream id in the Go server's log; tonic
//! does not let a handler see it.)
use std::{
    io::Write as _,
    sync::Mutex,
    time::Duration,
};

use tonic::{transport::Server, Code, Request, Response, Status};

#[allow(clippy::all, clippy::pedantic)]
mod pb {
    include!("helloworld.rs");
}
use pb::greeter_server::{Greeter, GreeterServer};

static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[repr(C)]
struct Timespec {
    sec: i64,
    nsec: i64,
}
extern "C" {
    fn clock_gettime(clock: i32, ts: *mut Timespec) -> i32;
}

/// CLOCK_BOOTTIME, the clock the agent stamps requests with.
fn now() -> u64 {
    let mut ts = Timespec { sec: 0, nsec: 0 };
    unsafe { clock_gettime(7, &mut ts) };
    ts.sec as u64 * 1_000_000_000 + ts.nsec as u64
}

/// CPU time this thread has used, in ns (CLOCK_THREAD_CPUTIME_ID).
fn thread_cpu_ns() -> u64 {
    let mut ts = Timespec { sec: 0, nsec: 0 };
    unsafe { clock_gettime(3, &mut ts) };
    ts.sec as u64 * 1_000_000_000 + ts.nsec as u64
}

/// Compute for `us` microseconds of this thread's CPU; the CPU it took.
/// Timed by the thread's CPU clock: time it was preempted is not computing,
/// and counting it would make a run-queue wait read as CPU.
fn spin(us: u64) -> u64 {
    if us == 0 {
        return 0;
    }
    let want = us * 1000;
    let start = thread_cpu_ns();
    while thread_cpu_ns() - start < want {
        std::hint::spin_loop();
    }
    thread_cpu_ns() - start
}

struct Hello;

#[tonic::async_trait]
impl Greeter for Hello {
    async fn say_hello(
        &self,
        request: Request<pb::HelloRequest>,
    ) -> Result<Response<pb::HelloReply>, Status> {
        let trace = request
            .metadata()
            .get("traceparent")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split('-').nth(1))
            .unwrap_or("-")
            .to_string();
        let port = request.remote_addr().map_or(0, |addr| addr.port());
        let task: u64 = tokio::task::id().to_string().parse().unwrap_or(0);
        let name = request.into_inner().name;
        let p: Vec<u64> = name.split(',').map(|v| v.parse().unwrap_or(0)).collect();
        let at = |i: usize| p.get(i).copied().unwrap_or(0);
        let t0 = now();
        let mut cpu = spin(at(0));
        if at(1) > 0 {
            tokio::time::sleep(Duration::from_micros(at(1))).await;
        }
        cpu += spin(at(2));
        let code = at(3) as i32;
        let t1 = now();
        LOG.lock().unwrap().push(format!(
            "T {trace} /helloworld.Greeter/SayHello {code} {task} {t0} {t1} {cpu} {port} 0"
        ));
        if code != 0 {
            return Err(Status::new(Code::from(code), "as asked"));
        }
        Ok(Response::new(pb::HelloReply { message: "ok".into() }))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let workers: usize = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(2);
    let rt = if workers == 0 {
        tokio::runtime::Builder::new_current_thread().enable_all().build()
    } else {
        tokio::runtime::Builder::new_multi_thread().worker_threads(workers).enable_all().build()
    }
    .unwrap();
    let path = args[2].clone();
    rt.block_on(async move {
        tokio::spawn(async move {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
            term.recv().await;
            let lines = LOG.lock().unwrap().join("\n") + "\n";
            let _ = std::fs::File::create(&path).and_then(|mut f| f.write_all(lines.as_bytes()));
            std::process::exit(0);
        });
        // With TLS_CERT and TLS_KEY set (PEM files): over TLS, through rustls.
        let mut builder = Server::builder();
        if let Ok(cert) = std::env::var("TLS_CERT") {
            let identity = tonic::transport::Identity::from_pem(
                std::fs::read(cert).expect("TLS_CERT"),
                std::fs::read(std::env::var("TLS_KEY").expect("TLS_KEY")).expect("TLS_KEY"),
            );
            builder = builder
                .tls_config(tonic::transport::ServerTlsConfig::new().identity(identity))
                .expect("TLS");
        }
        builder
            .add_service(GreeterServer::new(Hello))
            .serve(format!("127.0.0.1:{}", args[1]).parse().unwrap())
            .await
            .unwrap();
    });
}
