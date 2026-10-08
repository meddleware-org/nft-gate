//! Production [`ChainQuery`] implementation over the Sui **gRPC** API (`sui.rpc.v2`), via the
//! hand-rolled gRPC-web client in [`crate::grpc`] (no `tonic`/`prost`). Public JSON-RPC is
//! deprecated; this replaces it. The pure response-parse helpers are unit-tested; the network
//! round-trips are covered by the localnet/integration loop.
//!
//! Single-use verification is **digest-first**, mirroring the Workers gateway: the proof carries
//! the `access_gate::consume` transaction digest, so we fetch that transaction and confirm it
//! emitted an `AccessConsumedEvent` for this sender + gate. It is NOT bound to the challenge nonce,
//! so an interrupted upload can resume with a fresh challenge while reusing the same consume.

use crate::grpc::{
    field_bytes, field_str, value_as_bool, value_field, value_find_string, Field, GrpcStatus,
    GrpcWeb, ProtoReader, ProtoWriter, GRPC_NOT_FOUND,
};
use crate::http_client::HttpClient;
use crate::verify::{normalize_address, normalize_move_type, ChainQuery};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ── pinned sui.rpc.v2 field numbers (validated against live responses) ───────────────────────
const LEDGER_GET_TRANSACTION: &str = "sui.rpc.v2.LedgerService/GetTransaction";
const STATE_LIST_OWNED_OBJECTS: &str = "sui.rpc.v2.StateService/ListOwnedObjects";
const LEDGER_GET_OBJECT: &str = "sui.rpc.v2.LedgerService/GetObject";

// GetObjectRequest { object_id = 1; version = 2; FieldMask read_mask = 3 }
const GO_OBJECT_ID: u32 = 1;
const GO_READ_MASK: u32 = 3;
// GetObjectResponse { Object object = 1 }
const GO_OBJECT: u32 = 1;

// GetTransactionRequest { digest = 1; FieldMask read_mask = 2 { repeated string paths = 1 } }
const REQ_DIGEST: u32 = 1;
const REQ_READ_MASK: u32 = 2;
const FIELDMASK_PATHS: u32 = 1;
// GetTransactionResponse { ExecutedTransaction transaction = 1 }
const RESP_TRANSACTION: u32 = 1;
// ExecutedTransaction { ... TransactionEvents events = 5 }
const EXECUTED_EVENTS: u32 = 5;
// TransactionEvents { ... repeated Event events = 3 }
const EVENTS_EVENTS: u32 = 3;
// Event { package_id=1; module=2; sender=3; event_type=4; Bcs contents=5; Value json=6 }
const EVENT_SENDER: u32 = 3;
const EVENT_TYPE: u32 = 4;
const EVENT_JSON: u32 = 6;

// ListOwnedObjectsRequest { owner=1; uint32 page_size=2; FieldMask read_mask=4; object_type=5 }
const LOO_OWNER: u32 = 1;
const LOO_PAGE_SIZE: u32 = 2;
const LOO_READ_MASK: u32 = 4;
const LOO_OBJECT_TYPE: u32 = 5;
// ListOwnedObjectsResponse { repeated Object objects = 1 }
const LOO_OBJECTS: u32 = 1;
// Object { ... Value json = 100 }
const OBJECT_JSON: u32 = 100;

/// `GetTransaction` attempts while the node still reports the digest as unknown (indexing lag).
const TX_FETCH_ATTEMPTS: u32 = 4;
/// Entries kept by the ownership cache; the oldest is dropped past it.
const MAX_CACHE_ENTRIES: usize = 10_000;
/// Clock skew tolerated between a consume event's timestamp and this host's clock.
const CLOCK_SKEW_MS: u64 = 60_000;
/// Delay between `GetTransaction` attempts.
const TX_FETCH_RETRY: Duration = Duration::from_millis(500);

/// A cached result of an ownership query.
struct CacheEntry {
    owns: bool,
    expiry: Instant,
}

/// Production [`ChainQuery`] backed by the Sui gRPC API (gRPC-web transport).
pub struct SuiRpc {
    grpc: GrpcWeb,
    cache_ttl: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl SuiRpc {
    /// Create a new client. `rpc_url` is the full-node origin (gRPC-web is served there). Set
    /// `cache_ttl_ms` to `0` to disable the ownership cache (default — every gated check is live).
    pub fn new(
        client: HttpClient,
        rpc_url: String,
        cache_ttl_ms: u64,
        auth: Option<crate::config::AuthHeader>,
        timeout: Duration,
    ) -> Self {
        Self {
            grpc: GrpcWeb::new(client, rpc_url, auth, timeout),
            cache_ttl: Duration::from_millis(cache_ttl_ms),
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cache_key(address: &str, nft_type: &str, gate_id: Option<&str>) -> String {
        format!("{address}|{nft_type}|{}", gate_id.unwrap_or("-"))
    }

    /// Uncached, live ownership query via `StateService/ListOwnedObjects`.
    async fn owns_nft_live(
        &self,
        address: &str,
        nft_type: &str,
        gate_id: Option<&str>,
    ) -> anyhow::Result<bool> {
        let mut mask = ProtoWriter::new();
        mask.string_field(FIELDMASK_PATHS, "object_type");
        mask.string_field(FIELDMASK_PATHS, "json");
        let mut req = ProtoWriter::new();
        req.string_field(LOO_OWNER, address);
        req.uint_field(LOO_PAGE_SIZE, 50);
        req.bytes_field(LOO_READ_MASK, &mask.into_bytes());
        req.string_field(LOO_OBJECT_TYPE, nft_type);
        let resp = self
            .grpc
            .call(STATE_LIST_OWNED_OBJECTS, req.into_bytes())
            .await?;
        Ok(response_has_owned(&resp, gate_id))
    }
}

/// True if a `Gate`'s JSON (`google.protobuf.Value`) is paused AND its `policy` has
/// `pause_blocks_access`. Fails closed: JSON without a boolean `paused` and a `policy` with a boolean
/// `pause_blocks_access` is not understood and is an error (→ deny), never "not paused" — a rendering
/// change must not silently disable an admin's pause.
pub fn gate_blocks_access(json: &[u8]) -> anyhow::Result<bool> {
    let unrecognised = || anyhow::anyhow!("gate JSON has an unrecognised shape");
    let paused = value_field(json, "paused")
        .and_then(value_as_bool)
        .ok_or_else(unrecognised)?;
    let blocks = value_field(json, "policy")
        .and_then(|p| value_field(p, "pause_blocks_access"))
        .and_then(value_as_bool)
        .ok_or_else(unrecognised)?;
    Ok(paused && blocks)
}

/// Parse a `GetObjectResponse` for a gate; errors (fail closed) if the object or its JSON is absent.
fn response_gate_blocks_access(resp: &[u8]) -> anyhow::Result<bool> {
    let object =
        field_bytes(resp, GO_OBJECT).ok_or_else(|| anyhow::anyhow!("gate object not found"))?;
    let json = field_bytes(object, OBJECT_JSON)
        .ok_or_else(|| anyhow::anyhow!("gate object has no json"))?;
    gate_blocks_access(json)
}

/// Build the `GetTransactionRequest` for `digest`, requesting only the events.
fn build_get_transaction(digest: &str) -> Vec<u8> {
    let mut mask = ProtoWriter::new();
    mask.string_field(FIELDMASK_PATHS, "events");
    let mut req = ProtoWriter::new();
    req.string_field(REQ_DIGEST, digest);
    req.bytes_field(REQ_READ_MASK, &mask.into_bytes());
    req.into_bytes()
}

/// True if the event's `timestamp_ms` is at most `max_age_secs` old and not in the future (beyond
/// clock skew). A missing or malformed timestamp is not recent: fail closed. The age bound keeps a
/// consume from becoming redeemable again once the redemption store has forgotten it.
pub fn event_is_recent(event_json: &[u8], now_ms: u64, max_age_secs: u64) -> bool {
    let Some(ts) = value_find_string(event_json, "timestamp_ms")
        .filter(|t| !t.is_empty() && t.len() <= 16 && t.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|t| t.parse::<u64>().ok())
    else {
        return false;
    };
    ts <= now_ms.saturating_add(CLOCK_SKEW_MS)
        && now_ms.saturating_sub(ts) <= max_age_secs.saturating_mul(1000)
}

/// True if an access NFT's JSON describes a usable pass: an unlimited pass, or a single-use pass
/// with uses left. The variant is read as a full node renders the `AccessVariant` enum
/// (`{ "@variant": "SingleUse", "uses_remaining": "8" }`); an unknown tag or a missing or non-u64
/// count is not usable (fail closed), so an exhausted receipt never grants access.
pub fn pass_is_usable(nft_json: &[u8]) -> bool {
    match value_find_string(nft_json, "@variant").as_deref() {
        Some("UnlimitedPass") => true,
        Some("SingleUse") => value_find_string(nft_json, "uses_remaining")
            .filter(|n| !n.is_empty() && n.len() <= 20 && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<u64>().ok())
            .is_some_and(|n| n > 0),
        _ => false,
    }
}

/// Milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// True if `a` and `b` name the same address (normalised form).
fn same_address(a: Option<&str>, b: &str) -> bool {
    a.is_some_and(|a| normalize_address(a) == normalize_address(b))
}

/// True if a `GetTransactionResponse` contains an event of exactly `consumed_type` sent by
/// `address` for `gate_id` (when constrained). A failed transaction emits no events, so the
/// presence of a matching event already implies success — no separate status check is needed.
fn response_has_consume(
    resp: &[u8],
    address: &str,
    consumed_type: &str,
    gate_id: Option<&str>,
    now_ms: u64,
    max_age_secs: u64,
) -> bool {
    let want_type = normalize_move_type(consumed_type);
    let Some(tx) = field_bytes(resp, RESP_TRANSACTION) else {
        return false;
    };
    let Some(events) = field_bytes(tx, EXECUTED_EVENTS) else {
        return false;
    };
    for f in ProtoReader::new(events) {
        let Field::Len(EVENTS_EVENTS, ev) = f else {
            continue;
        };
        let is_consume =
            field_str(ev, EVENT_TYPE).is_some_and(|t| normalize_move_type(t) == want_type);
        if !is_consume || !same_address(field_str(ev, EVENT_SENDER), address) {
            continue;
        }
        let json = field_bytes(ev, EVENT_JSON).unwrap_or(&[]);
        if !event_is_recent(json, now_ms, max_age_secs) {
            continue;
        }
        match gate_id {
            None => return true,
            Some(g) => {
                if same_address(value_find_string(json, "gate_id").as_deref(), g) {
                    return true;
                }
            }
        }
    }
    false
}

/// True if a `ListOwnedObjectsResponse` contains a USABLE owned pass (see [`pass_is_usable`])
/// matching `gate_id` (when constrained). The object type is already constrained by the request's
/// `object_type` filter.
fn response_has_owned(resp: &[u8], gate_id: Option<&str>) -> bool {
    for f in ProtoReader::new(resp) {
        let Field::Len(LOO_OBJECTS, obj) = f else {
            continue;
        };
        let json = field_bytes(obj, OBJECT_JSON).unwrap_or(&[]);
        if !pass_is_usable(json) {
            continue;
        }
        match gate_id {
            None => return true,
            Some(g) => {
                if same_address(value_find_string(json, "gate_id").as_deref(), g) {
                    return true;
                }
            }
        }
    }
    false
}

impl ChainQuery for SuiRpc {
    async fn owns_nft(
        &self,
        address: &str,
        nft_type: &str,
        gate_id: Option<&str>,
    ) -> anyhow::Result<bool> {
        // Cache is OFF by default (cache_ttl == 0) so a gated action is confirmed live.
        if !self.cache_ttl.is_zero() {
            let key = Self::cache_key(address, nft_type, gate_id);
            if let Some(e) = self.cache.lock().unwrap().get(&key) {
                if e.expiry > Instant::now() {
                    return Ok(e.owns);
                }
            }
            let owns = self.owns_nft_live(address, nft_type, gate_id).await?;
            let now = Instant::now();
            let mut cache = self.cache.lock().unwrap();
            cache.retain(|_, e| e.expiry > now); // drop expired entries
            if cache.len() >= MAX_CACHE_ENTRIES {
                // Past the cap: drop the soonest-to-expire entry.
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, e)| e.expiry)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&oldest);
                }
            }
            cache.insert(
                key,
                CacheEntry {
                    owns,
                    expiry: now + self.cache_ttl,
                },
            );
            return Ok(owns);
        }
        self.owns_nft_live(address, nft_type, gate_id).await
    }

    async fn gate_access_blocked(&self, gate_id: &str) -> anyhow::Result<bool> {
        // Live read (not cached) so pausing takes effect on the next request.
        let mut mask = ProtoWriter::new();
        mask.string_field(FIELDMASK_PATHS, "json");
        let mut req = ProtoWriter::new();
        req.string_field(GO_OBJECT_ID, gate_id);
        req.bytes_field(GO_READ_MASK, &mask.into_bytes());
        let resp = self.grpc.call(LEDGER_GET_OBJECT, req.into_bytes()).await?;
        response_gate_blocks_access(&resp)
    }

    async fn consume_tx_valid(
        &self,
        consume_digest: &str,
        address: &str,
        consumed_event_type: &str,
        gate_id: Option<&str>,
        max_age_secs: u64,
    ) -> anyhow::Result<bool> {
        // Only "not found" is retried (a node can lag behind the client's finality wait: 4 attempts,
        // 500 ms apart, the same policy as the Workers gateway); the final not-found is `Ok(false)`
        // (denied, 403). Any other failure (network, auth, server, timeout) is returned at once as a
        // chain error (502): no amplification, and never a silent "no consume".
        let mut attempt = 1;
        let resp = loop {
            match self
                .grpc
                .call(
                    LEDGER_GET_TRANSACTION,
                    build_get_transaction(consume_digest),
                )
                .await
            {
                Ok(resp) => break resp,
                Err(e)
                    if e.downcast_ref::<GrpcStatus>()
                        .is_some_and(|s| s.0 == GRPC_NOT_FOUND) =>
                {
                    if attempt >= TX_FETCH_ATTEMPTS {
                        return Ok(false);
                    }
                    tracing::debug!(attempt, "GetTransaction not found; retrying");
                    tokio::time::sleep(TX_FETCH_RETRY).await;
                    attempt += 1;
                }
                Err(e) => return Err(e),
            }
        };
        Ok(response_has_consume(
            &resp,
            address,
            consumed_event_type,
            gate_id,
            now_ms(),
            max_age_secs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::ProtoWriter;

    // google.protobuf.Value { string_value=3; struct_value=5 } / Struct { fields=1 { key=1; value=2 } }
    const NOW: u64 = 1_800_000_000_000;
    const MAX_AGE: u64 = 3600;

    /// A struct `Value` of string fields.
    fn string_struct(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut s = ProtoWriter::new();
        for (k, v) in fields {
            let mut val = ProtoWriter::new();
            val.string_field(3, v); // string_value
            let mut entry = ProtoWriter::new();
            entry.string_field(1, k);
            entry.bytes_field(2, &val.into_bytes());
            s.bytes_field(1, &entry.into_bytes());
        }
        let mut value = ProtoWriter::new();
        value.bytes_field(5, &s.into_bytes()); // struct_value
        value.into_bytes()
    }

    /// An event / NFT json with a gate id (and, for events, a recent timestamp).
    fn json_gate(gate: &str) -> Vec<u8> {
        string_struct(&[
            ("gate_id", gate),
            ("timestamp_ms", &(NOW - 1000).to_string()),
        ])
    }

    fn event(etype: &str, sender: &str, gate: &str) -> Vec<u8> {
        let mut ev = ProtoWriter::new();
        ev.string_field(3, sender); // sender
        ev.string_field(4, etype); // event_type
        ev.bytes_field(6, &json_gate(gate)); // json
        ev.into_bytes()
    }

    /// Build a GetTransactionResponse { transaction { events { events: [event...] } } }.
    fn tx_response(events: &[Vec<u8>]) -> Vec<u8> {
        let mut te = ProtoWriter::new();
        for e in events {
            te.bytes_field(EVENTS_EVENTS, e);
        }
        let mut tx = ProtoWriter::new();
        tx.bytes_field(EXECUTED_EVENTS, &te.into_bytes());
        let mut resp = ProtoWriter::new();
        resp.bytes_field(RESP_TRANSACTION, &tx.into_bytes());
        resp.into_bytes()
    }

    const CONSUMED: &str = "0xabc::access_gate::AccessConsumedEvent";
    const OWNER: &str = "0xa11ce";
    const GATE: &str = "0x6a7e";

    #[test]
    fn matches_a_valid_consume_for_sender_and_gate() {
        let resp = tx_response(&[event(CONSUMED, OWNER, GATE)]);
        assert!(response_has_consume(
            &resp,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
        assert!(response_has_consume(
            &resp, OWNER, CONSUMED, None, NOW, MAX_AGE
        ));
    }

    #[test]
    fn rejects_wrong_sender_gate_or_event_type() {
        let resp = tx_response(&[event(CONSUMED, OWNER, GATE)]);
        assert!(!response_has_consume(
            &resp,
            "0xa77ac",
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        )); // wrong sender
        assert!(!response_has_consume(
            &resp,
            OWNER,
            CONSUMED,
            Some("0xbad"),
            NOW,
            MAX_AGE
        )); // wrong gate
        let other = tx_response(&[event("0xabc::access_gate::PurchasedEvent", OWNER, GATE)]);
        assert!(!response_has_consume(
            &other,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        )); // wrong event
    }

    #[test]
    fn rejects_a_look_alike_package_consume_event() {
        // Any package can declare `access_gate::AccessConsumedEvent`; only the configured one counts.
        let forged = tx_response(&[event(
            "0xbad::access_gate::AccessConsumedEvent",
            OWNER,
            GATE,
        )]);
        assert!(!response_has_consume(
            &forged,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
    }

    #[test]
    fn compares_types_and_ids_in_normalised_form() {
        let long_type = format!("0x{}abc::access_gate::AccessConsumedEvent", "0".repeat(61));
        let long_owner = format!("0x{}a11ce", "0".repeat(59));
        let resp = tx_response(&[event(&long_type, &long_owner, "0x06A7E")]);
        assert!(response_has_consume(
            &resp,
            "0xA11CE",
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
    }

    #[test]
    fn rejects_when_no_events() {
        assert!(!response_has_consume(
            &tx_response(&[]),
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
        assert!(!response_has_consume(
            &[],
            OWNER,
            CONSUMED,
            None,
            NOW,
            MAX_AGE
        )); // empty/failed tx
    }

    #[test]
    fn owned_response_matches_gate() {
        // ListOwnedObjectsResponse { objects: [ Object { json } ] }
        let mut obj = ProtoWriter::new();
        obj.bytes_field(OBJECT_JSON, &nft_json(&[("@variant", "UnlimitedPass")]));
        let mut resp = ProtoWriter::new();
        resp.bytes_field(LOO_OBJECTS, &obj.into_bytes());
        let bytes = resp.into_bytes();
        assert!(response_has_owned(&bytes, Some(GATE)));
        assert!(response_has_owned(&bytes, None));
        assert!(!response_has_owned(&bytes, Some("0x07e4")));
        assert!(!response_has_owned(&[], Some(GATE)));
    }

    #[test]
    fn build_get_transaction_encodes_digest_and_mask() {
        let req = build_get_transaction("DIGEST123");
        assert_eq!(field_str(&req, REQ_DIGEST), Some("DIGEST123"));
        let mask = field_bytes(&req, REQ_READ_MASK).unwrap();
        assert_eq!(field_str(mask, FIELDMASK_PATHS), Some("events"));
    }

    #[test]
    fn old_or_future_or_missing_timestamps_are_not_recent() {
        let at = |ms: u64| string_struct(&[("timestamp_ms", &ms.to_string())]);
        assert!(event_is_recent(&at(NOW - 60_000), NOW, MAX_AGE));
        assert!(!event_is_recent(&at(NOW - 3_600_001), NOW, MAX_AGE));
        assert!(event_is_recent(&at(NOW + 30_000), NOW, MAX_AGE)); // within clock skew
        assert!(!event_is_recent(&at(NOW + 600_000), NOW, MAX_AGE));
        for bad in ["", "soon", "-5", "1.5", "99999999999999999999"] {
            assert!(
                !event_is_recent(&string_struct(&[("timestamp_ms", bad)]), NOW, MAX_AGE),
                "{bad}"
            );
        }
        assert!(!event_is_recent(
            &string_struct(&[("gate_id", "0x1")]),
            NOW,
            MAX_AGE
        ));
        assert!(!event_is_recent(&[], NOW, MAX_AGE));
    }

    #[test]
    fn a_consume_older_than_the_bound_is_refused() {
        let old = string_struct(&[
            ("gate_id", GATE),
            ("timestamp_ms", &(NOW - 7_200_000).to_string()),
        ]);
        let mut ev = ProtoWriter::new();
        ev.string_field(3, OWNER);
        ev.string_field(4, CONSUMED);
        ev.bytes_field(6, &old);
        let resp = tx_response(&[ev.into_bytes()]);
        assert!(!response_has_consume(
            &resp,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            MAX_AGE
        ));
        assert!(response_has_consume(
            &resp,
            OWNER,
            CONSUMED,
            Some(GATE),
            NOW,
            10_000
        ));
    }

    /// An `AccessNFT` json: `data { gate_id, variant { "@variant", uses_remaining? } }`.
    fn nft_json(variant: &[(&str, &str)]) -> Vec<u8> {
        let data = struct_of(&[
            ("gate_id", string_value(GATE)),
            ("variant", string_struct(variant)),
        ]);
        struct_of(&[("data", data)])
    }

    fn string_value(s: &str) -> Vec<u8> {
        let mut v = ProtoWriter::new();
        v.string_field(3, s);
        v.into_bytes()
    }

    #[test]
    fn only_usable_passes_count() {
        assert!(pass_is_usable(&nft_json(&[("@variant", "UnlimitedPass")])));
        assert!(pass_is_usable(&nft_json(&[
            ("@variant", "SingleUse"),
            ("uses_remaining", "8")
        ])));
        assert!(!pass_is_usable(&nft_json(&[
            ("@variant", "SingleUse"),
            ("uses_remaining", "0")
        ])));
        for bad in [
            nft_json(&[("@variant", "Mystery")]),
            nft_json(&[("@variant", "SingleUse")]),
            nft_json(&[("@variant", "SingleUse"), ("uses_remaining", "lots")]),
            nft_json(&[("@variant", "SingleUse"), ("uses_remaining", "-1")]),
            nft_json(&[("variant", "UnlimitedPass")]),
            Vec::new(),
        ] {
            assert!(!pass_is_usable(&bad));
        }
    }

    #[test]
    fn an_exhausted_receipt_is_not_ownership() {
        let owned = |variant: &[(&str, &str)]| {
            let mut obj = ProtoWriter::new();
            obj.bytes_field(OBJECT_JSON, &nft_json(variant));
            let mut resp = ProtoWriter::new();
            resp.bytes_field(LOO_OBJECTS, &obj.into_bytes());
            resp.into_bytes()
        };
        assert!(response_has_owned(
            &owned(&[("@variant", "SingleUse"), ("uses_remaining", "2")]),
            Some(GATE)
        ));
        assert!(!response_has_owned(
            &owned(&[("@variant", "SingleUse"), ("uses_remaining", "0")]),
            Some(GATE)
        ));
        assert!(!response_has_owned(
            &owned(&[("@variant", "Mystery")]),
            None
        ));
    }

    // Live end-to-end check against Sui testnet — the Rust analogue of the Workers real-chain
    // harness. Ignored by default (network); run with `cargo test -- --ignored`. Uses a known
    // `access_gate::consume` on the current testnet package/gate (0xa55789… / 0xfd6c3b…). Public
    // fullnodes prune old checkpoints: when this digest ages out (NOT_FOUND), replace it with a
    // recent one (`listEvents` on the AccessConsumedEvent type, descending).
    #[tokio::test]
    #[ignore = "hits Sui testnet gRPC; run with --ignored"]
    async fn live_consume_tx_valid() {
        use crate::http_client::HttpClient;
        use crate::verify::{consumed_event_type, ChainQuery};
        let rpc = SuiRpc::new(
            HttpClient::new().unwrap(),
            "https://fullnode.testnet.sui.io:443".to_string(),
            0,
            None,
            Duration::from_secs(15),
        );
        let pkg = "0xa55789d77b8ae41e604c1c2e9ad9f7b034ca69b028ad0f1eee7d7cc8ad886d41";
        let consumed = consumed_event_type(&format!("{pkg}::access_gate::SoulboundAccessNFT"));
        let digest = "8br5PGrzidRpW6NJ5s4KHAar6j9ct3AkuMNeJh3TgUkP";
        let addr = "0xa991ae11b0785718cd3ad1c616e804a4c083f431b3144bb845bdec651164864a";
        let gate = "0xfd6c3b2a2baefcd8c3e08a2cddac942478e0527c421f4dc739917b01560ab8a6";
        assert!(rpc
            .consume_tx_valid(digest, addr, &consumed, Some(gate), 31_536_000)
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(digest, "0x01", &consumed, Some(gate), 31_536_000)
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(digest, addr, &consumed, Some("0xdead"), 31_536_000)
            .await
            .unwrap());
        // A look-alike package's event type never matches.
        assert!(!rpc
            .consume_tx_valid(
                digest,
                addr,
                "0xbad::access_gate::AccessConsumedEvent",
                Some(gate),
                31_536_000
            )
            .await
            .unwrap());
    }

    // ── gate_blocks_access ──────────────────────────────────────────────────────────────────

    /// A struct `Value` from (key, Value-bytes) entries.
    fn struct_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
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

    fn bool_value(b: bool) -> Vec<u8> {
        let mut v = ProtoWriter::new();
        v.uint_field(4, u64::from(b)); // bool_value
        v.into_bytes()
    }

    fn gate_json(paused: bool, policy: Option<bool>) -> Vec<u8> {
        let mut entries = vec![("paused", bool_value(paused))];
        if let Some(blocks) = policy {
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

    #[test]
    fn gate_blocks_only_when_paused_and_policy_opts_in() {
        assert!(gate_blocks_access(&gate_json(true, Some(true))).unwrap());
        assert!(!gate_blocks_access(&gate_json(false, Some(true))).unwrap());
        assert!(!gate_blocks_access(&gate_json(true, Some(false))).unwrap());
        // A gate without a policy is not a shape this version understands: fail closed.
        assert!(gate_blocks_access(&gate_json(true, None)).is_err());
    }

    #[test]
    fn unrecognised_gate_json_is_an_error_not_unpaused() {
        let not_bool = struct_of(&[("paused", Vec::new())]);
        for bad in [Vec::new(), not_bool] {
            assert!(gate_blocks_access(&bad).is_err());
        }
    }

    #[test]
    fn get_object_response_without_object_fails_closed() {
        assert!(response_gate_blocks_access(&[]).is_err());
        let mut obj = ProtoWriter::new();
        obj.bytes_field(OBJECT_JSON, &gate_json(true, Some(true)));
        let mut resp = ProtoWriter::new();
        resp.bytes_field(GO_OBJECT, &obj.into_bytes());
        assert!(response_gate_blocks_access(&resp.into_bytes()).unwrap());
    }
}
