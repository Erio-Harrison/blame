//! The pay demo's gateway: HTTP/1.1 in, gRPC out.
//!
//!   POST /pay            -> payment.Payments/Charge
//!   GET  /balance/{id}   -> account.Accounts/Balance
//!
//!   pay-gateway ADDR PAYMENT_URL ACCOUNT_URL AUDIT_FILE TRUTH_FILE
//!
//! `traceparent` is passed on. Each payment that went through is appended to
//! AUDIT_FILE and flushed (`sync_data`) with `tokio::fs`, which runs every step
//! on tokio's blocking pool; on SIGTERM the time each payment spent on that is
//! written to TRUTH_FILE, one line per payment: `T <trace id> POST /pay audit=<ns>`.
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use tokio::io::AsyncWriteExt;
use tonic::{client::Grpc, codegen::http::uri::PathAndQuery, transport::Channel, Request};
use tonic_prost::ProstCodec;

#[derive(Clone, PartialEq, prost::Message)]
struct Msg {
    #[prost(string, tag = "1")]
    text: String,
}

#[derive(Clone)]
struct App {
    payment: Channel,
    account: Channel,
    audit: Arc<str>,
    truth: Arc<Mutex<Vec<(String, u128)>>>,
}

fn trace_id(headers: &HeaderMap) -> Option<&str> {
    let tp = headers.get("traceparent")?.to_str().ok()?;
    tp.split('-').nth(1)
}

async fn forward(to: Channel, headers: &HeaderMap, path: &'static str, text: String) -> (StatusCode, String) {
    let mut req = Request::new(Msg { text });
    if let Some(tp) = headers.get("traceparent").and_then(|v| v.to_str().ok()) {
        if let Ok(v) = tp.parse() {
            req.metadata_mut().insert("traceparent", v);
        }
    }
    let mut grpc = Grpc::new(to);
    if grpc.ready().await.is_err() {
        return (StatusCode::BAD_GATEWAY, "unavailable".into());
    }
    match grpc.unary(req, PathAndQuery::from_static(path), ProstCodec::<Msg, Msg>::default()).await {
        Ok(_) => (StatusCode::OK, "{\"ok\":true}".into()),
        Err(s) => (StatusCode::BAD_GATEWAY, s.message().to_owned()),
    }
}

async fn audit(file: &str, line: String) -> std::io::Result<()> {
    let mut f = tokio::fs::OpenOptions::new().create(true).append(true).open(file).await?;
    f.write_all(line.as_bytes()).await?;
    f.sync_data().await
}

async fn pay(State(app): State<App>, headers: HeaderMap, body: String) -> (StatusCode, String) {
    let line = format!("{} {}\n", trace_id(&headers).unwrap_or("-"), body);
    let answer = forward(app.payment, &headers, "/payment.Payments/Charge", body).await;
    if answer.0 == StatusCode::OK {
        let t = Instant::now();
        if let Err(e) = audit(&app.audit, line).await {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
        if let Some(id) = trace_id(&headers) {
            app.truth.lock().unwrap().push((id.to_owned(), t.elapsed().as_nanos()));
        }
    }
    answer
}

async fn balance(State(app): State<App>, headers: HeaderMap, Path(id): Path<String>) -> (StatusCode, String) {
    forward(app.account, &headers, "/account.Accounts/Balance", id).await
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [addr, payment, account, audit, truth_file] = &args[..] else {
        eprintln!("pay-gateway ADDR PAYMENT_URL ACCOUNT_URL AUDIT_FILE TRUTH_FILE");
        std::process::exit(2);
    };
    let app = App {
        payment: Channel::from_shared(payment.clone()).unwrap().connect_lazy(),
        account: Channel::from_shared(account.clone()).unwrap().connect_lazy(),
        audit: audit.as_str().into(),
        truth: Arc::default(),
    };
    let (truth, truth_file) = (Arc::clone(&app.truth), truth_file.clone());
    tokio::spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        term.recv().await;
        let out: String = truth.lock().unwrap().iter().map(|(id, ns)| format!("T {id} POST /pay audit={ns}\n")).collect();
        std::fs::write(truth_file, out).unwrap();
        std::process::exit(0);
    });
    let router = Router::new()
        .route("/pay", post(pay))
        .route("/balance/{id}", get(balance))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("ready gateway {addr}");
    axum::serve(listener, router).await.unwrap();
}
