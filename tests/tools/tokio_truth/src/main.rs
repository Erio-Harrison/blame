//! An HTTP/1.1 server on tokio that knows the answer, for the tokio runtime
//! adapter: it writes the same log as http_truth.c (one record per request:
//! first byte read, last byte written, time spent computing, time parked), so
//! `blame slow` can be checked against it with http_check.py.
//!
//!     tokio_truth PORT LOGFILE [-b BACKEND_PORT] [-p WORKER_THREADS]
//!
//! `-p 0`: the current-thread runtime instead of the multi-thread one.
//!
//! One task per connection reads, handles and answers its requests, as hyper
//! does. Query parameters: size=N body bytes, cpu=US spin, sleep=US (the task
//! parks on a timer, its thread goes on to other tasks), d=US (a call to the
//! backend, an http_truth server, on a connection of the task's own), cpu2=US
//! spin after those, in that order.
//!
//! Spawned tasks, before cpu2: kids=N tasks (tokio::spawn), each spinning
//! kcpu=US and, with kfsync=KB, appending KB to a file and flushing it to
//! disk (blocking its thread); with knest=1 each spawns one more that does
//! the same. The handler waits for them all. blk=N closures run on the
//! blocking pool (tokio::task::spawn_blocking), each spinning bcpu=US and,
//! with bfsync=KB, appending and flushing as above; the handler waits for
//! them too. bg=US spawns one more that
//! waits 5 ms, then spins US: after the response, so none of it is the
//! request's. For such requests a second record (type 3) holds what the
//! spawned tasks did: the CPU of their spins, their write-and-flush time,
//! and how many were spawned. For requests that wait on something, a record
//! (type 5) holds how long the handler's task waited on each kind: tasks it
//! spawned (their join handles), the blocking pool, a timer, the backend.
//!
//! Clock readings go through the vDSO, so the server makes no system calls
//! beyond its socket calls. The log is written on SIGTERM or SIGINT.

use std::{
    io::Write as _,
    sync::Mutex,
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    signal::unix::{signal, SignalKind},
};

const REC_REQ: u8 = 1;
const REC_HELP: u8 = 3;
const REC_WAIT: u8 = 5;
const F_DOWN: u16 = 8;

/// `struct rec` of http_truth.c.
#[derive(Default)]
struct Rec {
    flags: u16,
    t0: u64,
    t1: u64,
    port: u32,
    seq: u32,
    cpu: u64,
    blk: u64,
    tdeq: u64,
    tdown: u64,
    /// What the tasks it spawned did; `spawned` 0: none.
    help_cpu: u64,
    help_io: u64,
    spawned: u64,
    /// How long the handler's task waited: on the tasks it spawned, on the
    /// blocking pool, on a timer, on the backend.
    wait_task: u64,
    wait_blocking: u64,
    wait_sleep: u64,
    wait_net: u64,
}

impl Rec {
    fn write(&self, out: &mut Vec<u8>) {
        self.write_as(out, REC_REQ, [self.cpu, self.blk, self.tdeq, self.tdown]);
        if self.spawned > 0 {
            self.write_as(out, REC_HELP, [self.help_cpu, self.help_io, self.spawned, 0]);
        }
        let waits = [self.wait_task, self.wait_blocking, self.wait_sleep, self.wait_net];
        if waits.iter().any(|&w| w > 0) {
            self.write_as(out, REC_WAIT, waits);
        }
    }

    fn write_as(&self, out: &mut Vec<u8>, kind: u8, values: [u64; 4]) {
        out.extend([kind, 0]);
        out.extend(self.flags.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        for value in [self.t0, self.t1] {
            out.extend(value.to_le_bytes());
        }
        out.extend(self.port.to_le_bytes());
        out.extend(self.seq.to_le_bytes());
        for value in values {
            out.extend(value.to_le_bytes());
        }
        out.extend(0u64.to_le_bytes());
    }
}

static LOG: Mutex<Vec<Rec>> = Mutex::new(Vec::new());

/// CLOCK_BOOTTIME, the clock the kernel side stamps events with.
fn now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec to write to.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Compute for `us` microseconds without a system call; the time it took.
fn spin(us: i64) -> u64 {
    if us <= 0 {
        return 0;
    }
    let start = Instant::now();
    let want = Duration::from_micros(us as u64);
    while start.elapsed() < want {
        std::hint::spin_loop();
    }
    start.elapsed().as_nanos() as u64
}

/// Files to append to and flush, one per spawned task at a time.
static SYNC_FILES: Mutex<Vec<std::fs::File>> = Mutex::new(Vec::new());
static SYNC_DIR: Mutex<String> = Mutex::new(String::new());

/// Append `kb` to a file and flush it to disk; the time it took.
fn write_and_flush(kb: i64) -> u64 {
    if kb <= 0 {
        return 0;
    }
    let pooled = SYNC_FILES.lock().unwrap().pop();
    let mut file = pooled.unwrap_or_else(|| {
        let n = now();
        let path = format!("{}.sync{n}", SYNC_DIR.lock().unwrap());
        let file = std::fs::File::create(&path).expect("sync file");
        let _ = std::fs::remove_file(&path);
        file
    });
    let start = Instant::now();
    let _ = file.write_all(&vec![b'x'; kb as usize * 1024]);
    let _ = file.sync_all();
    let took = start.elapsed().as_nanos() as u64;
    SYNC_FILES.lock().unwrap().push(file);
    took
}

/// What a spawned task did: (CPU, write-and-flush time, tasks it spawned).
fn kid(cpu: i64, fsync_kb: i64, nest: bool) -> std::pin::Pin<Box<dyn std::future::Future<Output = (u64, u64, u64)> + Send>> {
    Box::pin(async move {
        let child = nest.then(|| tokio::spawn(kid(cpu, fsync_kb, false)));
        let mut did = (spin(cpu), write_and_flush(fsync_kb), u64::from(nest));
        if let Some(child) = child {
            let (c, io, n) = child.await.unwrap_or_default();
            did = (did.0 + c, did.1 + io, did.2 + n);
        }
        did
    })
}

fn param(path: &str, name: &str) -> i64 {
    path.split_once('?')
        .and_then(|(_, query)| {
            query
                .split('&')
                .filter_map(|pair| pair.split_once('='))
                .find(|(key, _)| *key == name)
        })
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(-1)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// One call to the backend on the task's own connection; false if it failed.
async fn call(down: &mut Option<TcpStream>, backend: u16, us: i64) -> bool {
    if down.is_none() {
        match TcpStream::connect(("127.0.0.1", backend)).await {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                *down = Some(stream);
            }
            Err(_) => return false,
        }
    }
    let stream = down.as_mut().unwrap();
    let query = format!("GET /x?sleep={us}&size=100 HTTP/1.1\r\nHost: b\r\n\r\n");
    if stream.write_all(query.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk).await {
            Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
            _ => return false,
        }
        let Some(head) = find(&buf, b"\r\n\r\n") else {
            continue;
        };
        let length = find(&buf[..head], b"Content-Length: ")
            .map(|at| &buf[at + 16..head])
            .map(|rest| &rest[..find(rest, b"\r").unwrap_or(rest.len())])
            .and_then(|digits| {
                std::str::from_utf8(digits)
                    .ok()?
                    .trim()
                    .parse::<usize>()
                    .ok()
            })
            .unwrap_or(0);
        if buf.len() >= head + 4 + length {
            return true;
        }
    }
}

async fn serve(mut stream: TcpStream, backend: Option<u16>) {
    let port = stream.peer_addr().map_or(0, |addr| u32::from(addr.port()));
    let _ = stream.set_nodelay(true);
    let mut down = None;
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let body = vec![b'x'; 1 << 20];
    let mut seq = 0u32;
    loop {
        // A request starts at the read that brings its first byte.
        let mut start = 0;
        let head = loop {
            if let Some(end) = find(&buf, b"\r\n\r\n") {
                break end + 4;
            }
            match stream.read(&mut chunk).await {
                Ok(n) if n > 0 => {
                    if buf.is_empty() {
                        start = now();
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                _ => return,
            }
        };
        let line = String::from_utf8_lossy(&buf[..head]).into_owned();
        buf.drain(..head);
        let path = line.split(' ').nth(1).unwrap_or("/");

        let mut rec = Rec {
            t0: start,
            port,
            seq,
            ..Rec::default()
        };
        rec.cpu = spin(param(path, "cpu"));
        let us = param(path, "sleep");
        if us > 0 {
            let before = Instant::now();
            tokio::time::sleep(Duration::from_micros(us as u64)).await;
            rec.blk += before.elapsed().as_nanos() as u64;
            rec.wait_sleep += before.elapsed().as_nanos() as u64;
        }
        let us = param(path, "d");
        if let (true, Some(backend)) = (us >= 0, backend) {
            rec.flags = F_DOWN;
            rec.tdeq = now();
            if call(&mut down, backend, us).await {
                rec.tdown = now();
                rec.blk += rec.tdown - rec.tdeq;
                rec.wait_net += rec.tdown - rec.tdeq;
            }
        }
        let kids = param(path, "kids");
        if kids > 0 {
            let (cpu, fsync_kb, nest) = (param(path, "kcpu"), param(path, "kfsync"), param(path, "knest") > 0);
            let handles: Vec<_> = (0..kids).map(|_| tokio::spawn(kid(cpu, fsync_kb, nest))).collect();
            rec.spawned += kids as u64;
            let waiting = Instant::now();
            for handle in handles {
                let (c, io, n) = handle.await.unwrap_or_default();
                rec.help_cpu += c;
                rec.help_io += io;
                rec.spawned += n;
            }
            rec.wait_task += waiting.elapsed().as_nanos() as u64;
        }
        let blocking = param(path, "blk");
        if blocking > 0 {
            let (cpu, fsync_kb) = (param(path, "bcpu"), param(path, "bfsync"));
            let handles: Vec<_> = (0..blocking)
                .map(|_| tokio::task::spawn_blocking(move || (spin(cpu), write_and_flush(fsync_kb))))
                .collect();
            rec.spawned += blocking as u64;
            let waiting = Instant::now();
            for handle in handles {
                let (c, io) = handle.await.unwrap_or_default();
                rec.help_cpu += c;
                rec.help_io += io;
            }
            rec.wait_blocking += waiting.elapsed().as_nanos() as u64;
        }
        let us = param(path, "bg");
        if us > 0 {
            rec.spawned += 1;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(5)).await;
                spin(us);
            });
        }
        rec.cpu += spin(param(path, "cpu2"));
        let size = match param(path, "size") {
            n if n < 0 => 64,
            n => (n as usize).min(body.len()),
        };
        let mut response =
            format!("HTTP/1.1 200 OK\r\nServer: tt\r\nContent-Length: {size}\r\n\r\n").into_bytes();
        response.extend_from_slice(&body[..size]);
        if stream.write_all(&response).await.is_err() {
            return;
        }
        rec.t1 = now();
        LOG.lock().unwrap().push(rec);
        seq += 1;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: tokio_truth PORT LOGFILE [-b BACKEND_PORT] [-p WORKER_THREADS]");
        std::process::exit(2);
    }
    let port: u16 = args[1].parse().expect("PORT");
    let log_path = args[2].clone();
    *SYNC_DIR.lock().unwrap() = log_path.clone();
    let mut backend = None;
    let mut workers = None;
    for pair in args[3..].chunks(2) {
        match (pair[0].as_str(), pair.get(1)) {
            ("-b", Some(value)) => backend = value.parse().ok(),
            ("-p", Some(value)) => workers = value.parse().ok(),
            _ => {}
        }
    }
    // -p 0: the current-thread runtime, all tasks on the main thread.
    let mut builder = if workers == Some(0) {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    };
    builder.enable_all();
    if let Some(workers) = workers.filter(|&n| n > 0) {
        builder.worker_threads(workers);
    }
    let runtime = builder.build().expect("runtime");
    runtime.block_on(async move {
        for kind in [SignalKind::terminate(), SignalKind::interrupt()] {
            let log_path = log_path.clone();
            tokio::spawn(async move {
                signal(kind).expect("signal handler").recv().await;
                let mut out = Vec::new();
                for rec in LOG.lock().unwrap().iter() {
                    rec.write(&mut out);
                }
                let _ = std::fs::File::create(&log_path).and_then(|mut file| file.write_all(&out));
                std::process::exit(0);
            });
        }
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("listen");
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, backend));
            }
        }
    });
}
