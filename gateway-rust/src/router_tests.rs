//! Router-level tests (audit F47): the whole `build_router` stack against a scripted local Sui node
//! and a recording upstream, with real signed proofs. They pin the status-code and conflict-code
//! mapping of the dispatcher (`409` redeemed/leased, `503` store errors, `502` chain errors and
//! lost leases, `403` denials) and the proxy limits (`413`, `408`, `504`, redirects, path policy).
//! Hermetic: only `127.0.0.1` sockets.

use super::*;
use crate::testkit::{
    broken_redis, gate_json, proof_token, string_struct, string_value, struct_of, test_signer,
    Reply, Seen, Stub,
};
use axum::body::Body;
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use tower::ServiceExt;

const DIGEST: &str = "5Wq9tE4gXz8hEvFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdL";
const DIGEST_2: &str = "7Hk2pQ9mXz4vBnFhYt8KkTJb2Pp6qXqj8cRk3xN1mYdM";
const CONSUMED: &str = "0x1::access_gate::AccessConsumedEvent";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// `GetObject` answer: the gate, not paused.
fn gate_reply() -> Reply {
    let mut obj = crate::grpc::ProtoWriter::new();
    obj.bytes_field(100, &gate_json(false, Some(true)));
    let mut resp = crate::grpc::ProtoWriter::new();
    resp.bytes_field(1, &obj.into_bytes());
    Reply::grpc(&resp.into_bytes())
}

/// `GetTransaction` answer: a transaction with `success` status and a consume event by `sender`.
fn tx_reply(sender: &str, success: bool) -> Reply {
    use crate::grpc::ProtoWriter;
    let json = string_struct(&[("gate_id", "0x2"), ("timestamp_ms", &now_ms().to_string())]);
    let mut ev = ProtoWriter::new();
    ev.string_field(3, sender);
    ev.string_field(4, CONSUMED);
    ev.bytes_field(6, &json);
    let mut events = ProtoWriter::new();
    events.bytes_field(3, &ev.into_bytes());
    let mut status = ProtoWriter::new();
    status.uint_field(1, u64::from(success));
    let mut effects = ProtoWriter::new();
    effects.bytes_field(4, &status.into_bytes());
    let mut tx = ProtoWriter::new();
    tx.bytes_field(4, &effects.into_bytes());
    tx.bytes_field(5, &events.into_bytes());
    let mut resp = ProtoWriter::new();
    resp.bytes_field(1, &tx.into_bytes());
    Reply::grpc(&resp.into_bytes())
}

/// `ListOwnedObjects` answer: one usable pass for gate `0x2`.
fn owned_reply() -> Reply {
    let nft = struct_of(&[(
        "data",
        struct_of(&[
            ("gate_id", string_value("0x2")),
            ("variant", string_struct(&[("@variant", "UnlimitedPass")])),
        ]),
    )]);
    let mut obj = crate::grpc::ProtoWriter::new();
    obj.bytes_field(100, &nft);
    let mut resp = crate::grpc::ProtoWriter::new();
    resp.bytes_field(1, &obj.into_bytes());
    Reply::grpc(&resp.into_bytes())
}

/// How the scripted Sui node behaves.
#[derive(Clone, Copy)]
enum Node {
    /// Gate not paused; the consume transaction succeeded; the address owns a pass.
    Healthy,
    /// The consume transaction aborted (its events are still in the answer).
    FailedTransaction,
    /// Every call fails with gRPC `UNAVAILABLE`.
    Down,
}

async fn node(kind: Node, sender: String) -> Stub {
    Stub::spawn(move |seen| {
        if matches!(kind, Node::Down) {
            return Reply::grpc_status(14);
        }
        match seen.path.as_str() {
            "/sui.rpc.v2.LedgerService/GetObject" => gate_reply(),
            "/sui.rpc.v2.LedgerService/GetTransaction" => {
                tx_reply(&sender, matches!(kind, Node::Healthy))
            }
            "/sui.rpc.v2.StateService/ListOwnedObjects" => owned_reply(),
            other => panic!("unexpected call {other}"),
        }
    })
    .await
}

struct Rig {
    app: Router,
    state: Arc<AppState>,
    sk: ed25519_dalek::SigningKey,
    address: String,
}

impl Rig {
    /// A gateway wired to `node` and `upstream`; `tweak` adjusts the config, `store` the nonce store.
    async fn new(
        single_use: bool,
        node: &Stub,
        upstream: &Stub,
        store: NonceStore,
        tweak: impl FnOnce(&mut GatewayConfig),
    ) -> Self {
        let (sk, address) = test_signer();
        let mut cfg = tests_support::test_cfg();
        cfg.single_use = single_use;
        cfg.sui_rpc_url = node.url.clone();
        cfg.upstream_url = upstream.url.clone();
        tweak(&mut cfg);
        let http = HttpClient::new().unwrap();
        let state = Arc::new(AppState {
            chain: SuiRpc::new(
                http.clone(),
                cfg.sui_rpc_url.clone(),
                0,
                None,
                std::time::Duration::from_secs(5),
            ),
            store,
            limiter: RateLimiter::new(1000),
            ip_limiter: RateLimiter::new(1000),
            preauth_limiter: RateLimiter::new(1000),
            http,
            cfg,
        });
        Self {
            app: build_router(state.clone()),
            state,
            sk,
            address,
        }
    }

    async fn send(&self, req: axum::http::Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes().to_vec();
        (parts.status, parts.headers, bytes)
    }

    /// A fresh challenge nonce from the gateway.
    async fn nonce(&self) -> String {
        let (status, _, body) = self
            .send(
                axum::http::Request::get("/v1/challenge")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        serde_json::from_slice::<Value>(&body).unwrap()["nonce"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// A gated `POST path` carrying a proof for a fresh nonce (and `consume` in single-use mode).
    async fn gated(&self, path: &str, consume: Option<&str>) -> (StatusCode, HeaderMap, Value) {
        let nonce = self.nonce().await;
        let token = proof_token(&self.sk, &self.address, &nonce, consume);
        let req = axum::http::Request::post(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from("payload"))
            .unwrap();
        let (status, headers, body) = self.send(req).await;
        let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
        (status, headers, json)
    }
}

fn ok_upstream() -> impl Fn(&Seen) -> Reply {
    |_| Reply::ok("stored")
}

#[tokio::test]
async fn a_spent_or_in_flight_consume_is_a_coded_409() {
    let node = node(Node::Healthy, test_signer().1).await;
    let upstream = Stub::spawn(ok_upstream()).await;
    let rig = Rig::new(
        true,
        &node,
        &upstream,
        NonceStore::in_memory(300, 100),
        |_| {},
    )
    .await;

    // First use: lease, upload, commit.
    let (status, _, _) = rig.gated("/v1/blob-upload-relay", Some(DIGEST)).await;
    assert_eq!(status, StatusCode::OK);
    // The same consume again: spent.
    let (status, _, body) = rig.gated("/v1/blob-upload-relay", Some(DIGEST)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "redeemed");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("already been redeemed"));

    // A consume whose upload is still in flight (a held lease): not spent, not available.
    let held = rig
        .state
        .store
        .try_lease_redemption(DIGEST_2, 600)
        .await
        .unwrap();
    assert!(matches!(held, challenge::Lease::Ok(_)));
    let (status, _, body) = rig.gated("/v1/blob-upload-relay", Some(DIGEST_2)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "leased");
    // Both conflicts were answered without reaching the upstream a second time.
    assert_eq!(upstream.seen().len(), 1);
}

#[tokio::test]
async fn a_failed_upload_releases_the_consume_for_a_retry() {
    let node = node(Node::Healthy, test_signer().1).await;
    let healthy = Arc::new(AtomicBool::new(false));
    let flag = healthy.clone();
    let upstream = Stub::spawn(move |_| {
        if flag.load(Ordering::SeqCst) {
            Reply::ok("stored")
        } else {
            Reply::status(500, &[], "boom")
        }
    })
    .await;
    let rig = Rig::new(
        true,
        &node,
        &upstream,
        NonceStore::in_memory(300, 100),
        |_| {},
    )
    .await;
    let (status, _, _) = rig.gated("/v1/blob-upload-relay", Some(DIGEST)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR); // the upstream's own failure, passed on
    healthy.store(true, Ordering::SeqCst);
    // Nothing was spent: the same consume uploads now (a lease left behind would be a 409 `leased`).
    let (status, _, _) = rig.gated("/v1/blob-upload-relay", Some(DIGEST)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_lease_lost_before_the_commit_is_a_502_not_a_success() {
    let node = node(Node::Healthy, test_signer().1).await;
    let upstream = Stub::spawn(ok_upstream()).await;
    // A zero-second lease has lapsed by the time the upload finishes and the commit is attempted.
    let rig = Rig::new(
        true,
        &node,
        &upstream,
        NonceStore::in_memory(300, 100),
        |c| {
            c.redemption_lease_ttl_secs = 0;
        },
    )
    .await;
    let (status, _, body) = rig.gated("/v1/blob-upload-relay", Some(DIGEST)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "redemption lease lost");
}

#[tokio::test]
async fn a_broken_state_store_is_a_503_never_a_conflict() {
    let node = node(Node::Healthy, test_signer().1).await;
    let upstream = Stub::spawn(ok_upstream()).await;
    let (url, redis) = broken_redis().await;
    let store = NonceStore::redis(&url, 300).await.unwrap();
    let rig = Rig::new(true, &node, &upstream, store, |_| {}).await;

    // The challenge cannot be recorded.
    let (status, _, body) = rig
        .send(
            axum::http::Request::get("/v1/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(String::from_utf8_lossy(&body).contains("gateway state unavailable"));

    // The nonce reads as valid (the stub answers GETDEL), but the redemption lease then fails.
    let token = proof_token(&rig.sk, &rig.address, "any-nonce", Some(DIGEST));
    let (status, _, body) = rig
        .send(
            axum::http::Request::post("/v1/blob-upload-relay")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from("payload"))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(String::from_utf8_lossy(&body).contains("gateway state unavailable"));
    assert!(upstream.seen().is_empty(), "nothing reaches the upstream");
    redis.abort();
}

#[tokio::test]
async fn a_failed_or_unreadable_consume_never_reaches_the_upstream() {
    let upstream = Stub::spawn(ok_upstream()).await;
    // The consume aborted on-chain although its events are in the answer (audit F21): 403.
    let failed = node(Node::FailedTransaction, test_signer().1).await;
    let rig = Rig::new(
        true,
        &failed,
        &upstream,
        NonceStore::in_memory(300, 100),
        |_| {},
    )
    .await;
    let (status, _, body) = rig.gated("/v1/blob-upload-relay", Some(DIGEST)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("no matching single-use consume"));
    // The consume belongs to someone else: 403.
    let other = node(Node::Healthy, "0xbeef".to_string()).await;
    let rig = Rig::new(
        true,
        &other,
        &upstream,
        NonceStore::in_memory(300, 100),
        |_| {},
    )
    .await;
    assert_eq!(
        rig.gated("/v1/blob-upload-relay", Some(DIGEST)).await.0,
        StatusCode::FORBIDDEN
    );
    // The node is down: a chain error is 502 (and still denied).
    let down = node(Node::Down, test_signer().1).await;
    let rig = Rig::new(
        true,
        &down,
        &upstream,
        NonceStore::in_memory(300, 100),
        |_| {},
    )
    .await;
    let (status, _, body) = rig.gated("/v1/blob-upload-relay", Some(DIGEST)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "on-chain verification failed");
    assert!(upstream.seen().is_empty());
}

/// An ownership-mode gateway (the node says the address owns a pass) in front of `upstream`.
async fn owner_rig(upstream: &Stub, tweak: impl FnOnce(&mut GatewayConfig)) -> (Rig, Stub) {
    let node = node(Node::Healthy, test_signer().1).await;
    let rig = Rig::new(
        false,
        &node,
        upstream,
        NonceStore::in_memory(300, 100),
        tweak,
    )
    .await;
    (rig, node)
}

#[tokio::test]
async fn the_upstream_sees_the_request_but_no_credential_and_its_cors_grants_are_dropped() {
    let upstream = Stub::spawn(|_| {
        Reply::status(
            200,
            &[("access-control-allow-origin", "*"), ("x-relay", "yes")],
            "stored",
        )
    })
    .await;
    let (rig, _node) = owner_rig(&upstream, |_| {}).await;
    let (status, headers, _) = rig.gated("/v1/blob-upload-relay?epochs=1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    assert_eq!(headers["x-relay"], "yes");
    let seen = &upstream.seen()[0];
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/v1/blob-upload-relay");
    assert!(seen.header("authorization").is_none());
    assert!(seen.header("x-access-proof").is_none());
    assert_eq!(seen.body, b"payload");
}

#[tokio::test]
async fn an_upstream_redirect_is_refused_and_never_followed() {
    let elsewhere = Stub::spawn(ok_upstream()).await;
    let target = format!("{}/login", elsewhere.url);
    let upstream =
        Stub::spawn(move |_| Reply::status(302, &[("location", target.as_str())], "")).await;
    let (rig, _node) = owner_rig(&upstream, |_| {}).await;
    let (status, headers, body) = rig.gated("/v1/blob-upload-relay", None).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(headers.get(header::LOCATION).is_none());
    assert_eq!(body["error"], "upstream error");
    assert!(
        elsewhere.seen().is_empty(),
        "the redirect target was contacted"
    );
}

#[tokio::test]
async fn unsafe_paths_and_oversize_or_stalled_bodies_are_refused_before_the_upstream() {
    let upstream = Stub::spawn(ok_upstream()).await;
    let (rig, _node) = owner_rig(&upstream, |c| {
        c.max_body_bytes = 16;
        c.body_read_timeout_secs = 1;
    })
    .await;
    // A path that could be re-interpreted by the upstream (dot segments, encoded separators) is a 400.
    for bad in ["/v1/%2e%2e/admin", "/v1/a%2fb", "/v1/../x"] {
        let (status, _, _) = rig.gated(bad, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    // A declared length over the cap is refused before reading.
    let nonce = rig.nonce().await;
    let token = proof_token(&rig.sk, &rig.address, &nonce, None);
    let (status, _, _) = rig
        .send(
            axum::http::Request::post("/v1/blob-upload-relay")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::CONTENT_LENGTH, "17")
                .body(Body::from(vec![0u8; 17]))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    // A chunked body that outgrows the cap while being read is refused too.
    let nonce = rig.nonce().await;
    let token = proof_token(&rig.sk, &rig.address, &nonce, None);
    let chunks = futures_chunks(&[&[1u8; 10], &[2u8; 10]]);
    let (status, _, _) = rig
        .send(
            axum::http::Request::post("/v1/blob-upload-relay")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from_stream(chunks))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    // A body that never finishes is a 408 at the body deadline.
    let nonce = rig.nonce().await;
    let token = proof_token(&rig.sk, &rig.address, &nonce, None);
    let stalled = futures_stalled();
    let (status, _, _) = rig
        .send(
            axum::http::Request::post("/v1/blob-upload-relay")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from_stream(stalled))
                .unwrap(),
        )
        .await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert!(
        upstream.seen().is_empty(),
        "no refused request reached the upstream"
    );
}

#[tokio::test]
async fn a_stalled_upstream_is_a_504_at_its_deadline() {
    let upstream =
        Stub::spawn(|_| Reply::ok("late").after(std::time::Duration::from_secs(3))).await;
    let (rig, _node) = owner_rig(&upstream, |c| c.upstream_timeout_secs = 1).await;
    let (status, _, body) = rig.gated("/v1/blob-upload-relay", None).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(body["error"], "upstream timed out");
}

/// A request body of the given chunks (no `Content-Length`).
fn futures_chunks(
    chunks: &[&[u8]],
) -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    futures_util::stream::iter(
        chunks
            .iter()
            .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
            .collect::<Vec<_>>(),
    )
}

/// A request body that sends one byte and then never finishes.
fn futures_stalled() -> impl futures_util::Stream<Item = Result<bytes::Bytes, std::io::Error>> {
    use futures_util::StreamExt;
    futures_util::stream::iter([Ok(bytes::Bytes::from_static(b"x"))])
        .chain(futures_util::stream::pending())
}
