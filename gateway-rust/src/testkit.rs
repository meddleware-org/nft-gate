//! Hermetic test fixtures (compiled only for tests): protobuf `Value` builders, a scripted local
//! HTTP server standing in for the Sui full node (gRPC-web) and for the upstream, and a signer that
//! produces real access-proof tokens for the test gateway. Nothing here touches the network beyond
//! `127.0.0.1`.

use crate::grpc::{frame, ProtoWriter};
use crate::proof::{personal_message, MessageContext};
use crate::verify::{derive_address, normalize_address, signing_digest, FLAG_ED25519};
use base64::prelude::*;
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ── google.protobuf.Value builders ───────────────────────────────────────────────────────────
// Value { bool_value = 4; string_value = 3; struct_value = 5 }; Struct { fields = 1 { key = 1;
// value = 2 } }.

/// A `Value` holding a string.
pub fn string_value(s: &str) -> Vec<u8> {
    let mut v = ProtoWriter::new();
    v.string_field(3, s);
    v.into_bytes()
}

/// A `Value` holding a bool.
pub fn bool_value(b: bool) -> Vec<u8> {
    let mut v = ProtoWriter::new();
    v.uint_field(4, u64::from(b));
    v.into_bytes()
}

/// A struct `Value` from (key, `Value`-bytes) entries.
pub fn struct_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut s = ProtoWriter::new();
    for (k, v) in entries {
        let mut entry = ProtoWriter::new();
        entry.string_field(1, k);
        entry.bytes_field(2, v);
        s.bytes_field(1, &entry.into_bytes());
    }
    let mut value = ProtoWriter::new();
    value.bytes_field(5, &s.into_bytes());
    value.into_bytes()
}

/// A struct `Value` of string fields.
pub fn string_struct(fields: &[(&str, &str)]) -> Vec<u8> {
    let entries: Vec<(&str, Vec<u8>)> = fields.iter().map(|(k, v)| (*k, string_value(v))).collect();
    struct_of(&entries)
}

/// A `Gate` object's JSON.
pub fn gate_json(paused: bool, policy_blocks_access: Option<bool>) -> Vec<u8> {
    let mut entries = vec![("paused", bool_value(paused))];
    if let Some(blocks) = policy_blocks_access {
        entries.push((
            "policy",
            struct_of(&[
                ("pause_blocks_decryption", bool_value(false)),
                ("pause_blocks_access", bool_value(blocks)),
            ]),
        ));
    }
    struct_of(&entries)
}

// ── scripted local HTTP server ───────────────────────────────────────────────────────────────

/// One request the stub received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    /// Request headers, names lower-cased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    /// The first value of header `name` (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// What the stub answers.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
    /// Wait this long before answering (a stalled peer).
    pub delay: Duration,
}

impl Reply {
    /// The same reply, sent after `delay`.
    pub fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// A reply with `status`, `headers` and a plain body.
    pub fn status(status: u16, headers: &[(&'static str, &str)], body: &str) -> Self {
        Self {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| (*k, (*v).to_string()))
                .collect(),
            body: body.as_bytes().to_vec(),
            delay: Duration::ZERO,
        }
    }

    /// `200` with a plain body.
    pub fn ok(body: &str) -> Self {
        Self::status(200, &[], body)
    }

    /// A gRPC-web success: one data frame carrying `msg`, then a `grpc-status: 0` trailer frame.
    pub fn grpc(msg: &[u8]) -> Self {
        let mut body = frame(msg);
        let trailer = b"grpc-status:0\r\n";
        body.push(0x80);
        body.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
        body.extend_from_slice(trailer);
        Self {
            status: 200,
            headers: vec![("content-type", "application/grpc-web+proto".into())],
            body,
            delay: Duration::ZERO,
        }
    }

    /// A trailers-only gRPC-web failure (how full nodes answer, e.g., NOT_FOUND).
    pub fn grpc_status(code: i64) -> Self {
        Self {
            status: 200,
            headers: vec![
                ("content-type", "application/grpc-web+proto".into()),
                ("grpc-status", code.to_string()),
            ],
            body: Vec::new(),
            delay: Duration::ZERO,
        }
    }
}

/// A running scripted server on an ephemeral `127.0.0.1` port; stops when dropped.
pub struct Stub {
    /// `http://127.0.0.1:<port>`.
    pub url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Stub {
    /// Start a server that answers each request with `handler(&request)`.
    pub async fn spawn(handler: impl Fn(&Seen) -> Reply + Send + Sync + 'static) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(handler);
        let log = seen.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let handler = handler.clone();
                let log = log.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let handler = handler.clone();
                        let log = log.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let body = body.collect().await.map(|b| b.to_bytes().to_vec());
                            let seen = Seen {
                                method: parts.method.to_string(),
                                path: parts.uri.path().to_string(),
                                headers: parts
                                    .headers
                                    .iter()
                                    .map(|(k, v)| {
                                        (
                                            k.as_str().to_string(),
                                            String::from_utf8_lossy(v.as_bytes()).into_owned(),
                                        )
                                    })
                                    .collect(),
                                body: body.unwrap_or_default(),
                            };
                            let reply = handler(&seen);
                            log.lock().unwrap().push(seen);
                            if !reply.delay.is_zero() {
                                tokio::time::sleep(reply.delay).await;
                            }
                            let mut resp = Response::builder().status(reply.status);
                            for (k, v) in reply.headers {
                                resp = resp.header(k, v);
                            }
                            Ok::<_, std::convert::Infallible>(
                                resp.body(Full::new(Bytes::from(reply.body))).unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        Self { url, seen, task }
    }

    /// Every request received so far, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// The requests received for `path`.
    pub fn seen_at(&self, path: &str) -> Vec<Seen> {
        self.seen().into_iter().filter(|s| s.path == path).collect()
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The command names (upper-cased) in a buffer of RESP arrays; a pipelined write holds several.
fn resp_commands(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    let line = |i: &mut usize| -> Option<String> {
        let end = buf[*i..].windows(2).position(|w| w == b"\r\n")? + *i;
        let l = String::from_utf8_lossy(&buf[*i..end]).into_owned();
        *i = end + 2;
        Some(l)
    };
    while i < buf.len() {
        let Some(head) = line(&mut i) else { break };
        let Some(n) = head.strip_prefix('*').and_then(|n| n.parse::<usize>().ok()) else {
            break;
        };
        let mut name = String::new();
        for k in 0..n {
            let Some(len) = line(&mut i).and_then(|l| l.strip_prefix('$')?.parse::<usize>().ok())
            else {
                return out;
            };
            if k == 0 {
                name =
                    String::from_utf8_lossy(&buf[i..(i + len).min(buf.len())]).to_ascii_uppercase();
            }
            i += len + 2;
        }
        out.push(name);
    }
    out
}

/// A TCP server that speaks just enough RESP to fail every Redis command except `GETDEL` (which it
/// answers with a value, so a nonce reads as valid): a store that is reachable but broken. One
/// reply is sent per command, pipelined or not.
pub async fn broken_redis() -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("redis://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let Ok(n) = stream.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    let mut reply = Vec::new();
                    for cmd in resp_commands(&buf[..n]) {
                        reply.extend_from_slice(if cmd == "GETDEL" {
                            b"$1\r\n1\r\n"
                        } else {
                            b"-ERR stub failure\r\n"
                        });
                    }
                    if stream.write_all(&reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (url, task)
}

// ── real access proofs for the test gateway ──────────────────────────────────────────────────

/// A fixed ed25519 test key and its Sui address.
pub fn test_signer() -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let address = derive_address(FLAG_ED25519, sk.verifying_key().as_bytes());
    (sk, address)
}

/// The base64 proof token a client would send to the gateway configured by `crate::tests_support::
/// test_cfg` (origin, gate and network from it): `nonce` signed by `sk`, plus the consume digest in
/// single-use mode.
pub fn proof_token(sk: &SigningKey, address: &str, nonce: &str, consume: Option<&str>) -> String {
    let cfg = crate::tests_support::test_cfg();
    let message = personal_message(&MessageContext {
        origin: &cfg.gateway_origin,
        gate_id: &normalize_address(&cfg.gate_id),
        network: &cfg.network,
        nonce,
        consume_digest: consume,
    })
    .unwrap();
    let sig = sk.sign(&signing_digest(&message));
    let mut serialized = vec![FLAG_ED25519];
    serialized.extend_from_slice(&sig.to_bytes());
    serialized.extend_from_slice(sk.verifying_key().as_bytes());
    let mut obj = serde_json::json!({
        "address": address,
        "nonce": nonce,
        "signature": BASE64_STANDARD.encode(serialized),
    });
    if let Some(d) = consume {
        obj["consumeDigest"] = serde_json::json!(d);
    }
    BASE64_STANDARD.encode(serde_json::to_vec(&obj).unwrap())
}
