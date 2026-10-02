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
    field_bytes, field_str, value_as_bool, value_field, value_find_string, Field, GrpcWeb,
    ProtoReader, ProtoWriter,
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

/// `GetTransaction` attempts before a consume check reports a chain error (Workers parity).
const TX_FETCH_ATTEMPTS: u32 = 4;
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
    ) -> Self {
        Self {
            grpc: GrpcWeb::new(client, rpc_url, auth),
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
/// `pause_blocks_access`. A gate without a `policy` (pre-policy package version) never blocks.
pub fn gate_blocks_access(json: &[u8]) -> bool {
    let paused = value_field(json, "paused")
        .and_then(value_as_bool)
        .unwrap_or(false);
    let blocks = value_field(json, "policy")
        .and_then(|p| value_field(p, "pause_blocks_access"))
        .and_then(value_as_bool)
        .unwrap_or(false);
    paused && blocks
}

/// Parse a `GetObjectResponse` for a gate; errors (fail closed) if the object or its JSON is absent.
fn response_gate_blocks_access(resp: &[u8]) -> anyhow::Result<bool> {
    let object =
        field_bytes(resp, GO_OBJECT).ok_or_else(|| anyhow::anyhow!("gate object not found"))?;
    let json = field_bytes(object, OBJECT_JSON)
        .ok_or_else(|| anyhow::anyhow!("gate object has no json"))?;
    Ok(gate_blocks_access(json))
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
        match gate_id {
            None => return true,
            Some(g) => {
                let json = field_bytes(ev, EVENT_JSON).unwrap_or(&[]);
                if same_address(value_find_string(json, "gate_id").as_deref(), g) {
                    return true;
                }
            }
        }
    }
    false
}

/// True if a `ListOwnedObjectsResponse` contains an owned object matching `gate_id` (when
/// constrained). The object type is already constrained by the request's `object_type` filter, so
/// with no gate constraint any returned object means ownership.
fn response_has_owned(resp: &[u8], gate_id: Option<&str>) -> bool {
    for f in ProtoReader::new(resp) {
        let Field::Len(LOO_OBJECTS, obj) = f else {
            continue;
        };
        match gate_id {
            None => return true,
            Some(g) => {
                let json = field_bytes(obj, OBJECT_JSON).unwrap_or(&[]);
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
            self.cache.lock().unwrap().insert(
                key,
                CacheEntry {
                    owns,
                    expiry: Instant::now() + self.cache_ttl,
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
    ) -> anyhow::Result<bool> {
        // Retry briefly to absorb fullnode indexing lag after the client's finality wait — the same
        // policy as the Workers gateway (4 attempts, 500 ms apart); every attempt failing is a
        // chain error (502), never a silent "no consume".
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
                Err(e) if attempt < TX_FETCH_ATTEMPTS => {
                    tracing::debug!(error = %e, attempt, "GetTransaction failed; retrying");
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
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::ProtoWriter;

    // google.protobuf.Value { string_value=3; struct_value=5 } / Struct { fields=1 { key=1; value=2 } }
    fn json_gate(gate: &str) -> Vec<u8> {
        let mut val = ProtoWriter::new();
        val.string_field(3, gate); // string_value
        let mut entry = ProtoWriter::new();
        entry.string_field(1, "gate_id");
        entry.bytes_field(2, &val.into_bytes());
        let mut s = ProtoWriter::new();
        s.bytes_field(1, &entry.into_bytes());
        let mut value = ProtoWriter::new();
        value.bytes_field(5, &s.into_bytes()); // struct_value
        value.into_bytes()
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
        assert!(response_has_consume(&resp, OWNER, CONSUMED, Some(GATE)));
        assert!(response_has_consume(&resp, OWNER, CONSUMED, None));
    }

    #[test]
    fn rejects_wrong_sender_gate_or_event_type() {
        let resp = tx_response(&[event(CONSUMED, OWNER, GATE)]);
        assert!(!response_has_consume(
            &resp,
            "0xa77ac",
            CONSUMED,
            Some(GATE)
        )); // wrong sender
        assert!(!response_has_consume(&resp, OWNER, CONSUMED, Some("0xbad"))); // wrong gate
        let other = tx_response(&[event("0xabc::access_gate::PurchasedEvent", OWNER, GATE)]);
        assert!(!response_has_consume(&other, OWNER, CONSUMED, Some(GATE))); // wrong event
    }

    #[test]
    fn rejects_a_look_alike_package_consume_event() {
        // Any package can declare `access_gate::AccessConsumedEvent`; only the configured one counts.
        let forged = tx_response(&[event(
            "0xbad::access_gate::AccessConsumedEvent",
            OWNER,
            GATE,
        )]);
        assert!(!response_has_consume(&forged, OWNER, CONSUMED, Some(GATE)));
    }

    #[test]
    fn compares_types_and_ids_in_normalised_form() {
        let long_type = format!("0x{}abc::access_gate::AccessConsumedEvent", "0".repeat(61));
        let long_owner = format!("0x{}a11ce", "0".repeat(59));
        let resp = tx_response(&[event(&long_type, &long_owner, "0x06A7E")]);
        assert!(response_has_consume(&resp, "0xA11CE", CONSUMED, Some(GATE)));
    }

    #[test]
    fn rejects_when_no_events() {
        assert!(!response_has_consume(
            &tx_response(&[]),
            OWNER,
            CONSUMED,
            Some(GATE)
        ));
        assert!(!response_has_consume(&[], OWNER, CONSUMED, None)); // empty/failed tx
    }

    #[test]
    fn owned_response_matches_gate() {
        // ListOwnedObjectsResponse { objects: [ Object { json } ] }
        let mut obj = ProtoWriter::new();
        obj.bytes_field(OBJECT_JSON, &json_gate(GATE));
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
        );
        let pkg = "0xa55789d77b8ae41e604c1c2e9ad9f7b034ca69b028ad0f1eee7d7cc8ad886d41";
        let consumed = consumed_event_type(&format!("{pkg}::access_gate::SoulboundAccessNFT"));
        let digest = "8br5PGrzidRpW6NJ5s4KHAar6j9ct3AkuMNeJh3TgUkP";
        let addr = "0xa991ae11b0785718cd3ad1c616e804a4c083f431b3144bb845bdec651164864a";
        let gate = "0xfd6c3b2a2baefcd8c3e08a2cddac942478e0527c421f4dc739917b01560ab8a6";
        assert!(rpc
            .consume_tx_valid(digest, addr, &consumed, Some(gate))
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(digest, "0x01", &consumed, Some(gate))
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(digest, addr, &consumed, Some("0xdead"))
            .await
            .unwrap());
        // A look-alike package's event type never matches.
        assert!(!rpc
            .consume_tx_valid(
                digest,
                addr,
                "0xbad::access_gate::AccessConsumedEvent",
                Some(gate)
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
        assert!(gate_blocks_access(&gate_json(true, Some(true))));
        assert!(!gate_blocks_access(&gate_json(false, Some(true))));
        assert!(!gate_blocks_access(&gate_json(true, Some(false))));
        assert!(!gate_blocks_access(&gate_json(true, None))); // pre-policy gate
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
