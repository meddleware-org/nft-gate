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
    field_bytes, field_str, value_find_string, Field, GrpcWeb, ProtoReader, ProtoWriter,
};
use crate::http_client::HttpClient;
use crate::verify::ChainQuery;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ── pinned sui.rpc.v2 field numbers (validated against live responses) ───────────────────────
const LEDGER_GET_TRANSACTION: &str = "sui.rpc.v2.LedgerService/GetTransaction";
const STATE_LIST_OWNED_OBJECTS: &str = "sui.rpc.v2.StateService/ListOwnedObjects";

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
    pub fn new(client: HttpClient, rpc_url: String, cache_ttl_ms: u64) -> Self {
        Self {
            grpc: GrpcWeb::new(client, rpc_url),
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

/// Build the `GetTransactionRequest` for `digest`, requesting only the events.
fn build_get_transaction(digest: &str) -> Vec<u8> {
    let mut mask = ProtoWriter::new();
    mask.string_field(FIELDMASK_PATHS, "events");
    let mut req = ProtoWriter::new();
    req.string_field(REQ_DIGEST, digest);
    req.bytes_field(REQ_READ_MASK, &mask.into_bytes());
    req.into_bytes()
}

/// True if a `GetTransactionResponse` contains an `AccessConsumedEvent` sent by `address` for
/// `gate_id` (when constrained). A failed transaction emits no events, so the presence of a
/// matching event already implies success — no separate status check is needed.
fn response_has_consume(resp: &[u8], address: &str, gate_id: Option<&str>) -> bool {
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
        let is_consume = field_str(ev, EVENT_TYPE)
            .map(|t| t.ends_with("::access_gate::AccessConsumedEvent"))
            .unwrap_or(false);
        if !is_consume || field_str(ev, EVENT_SENDER) != Some(address) {
            continue;
        }
        match gate_id {
            None => return true,
            Some(g) => {
                let json = field_bytes(ev, EVENT_JSON).unwrap_or(&[]);
                if value_find_string(json, "gate_id").as_deref() == Some(g) {
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
                if value_find_string(json, "gate_id").as_deref() == Some(g) {
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

    async fn consume_tx_valid(
        &self,
        consume_digest: &str,
        address: &str,
        gate_id: Option<&str>,
    ) -> anyhow::Result<bool> {
        let resp = self
            .grpc
            .call(
                LEDGER_GET_TRANSACTION,
                build_get_transaction(consume_digest),
            )
            .await?;
        Ok(response_has_consume(&resp, address, gate_id))
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

    const CONSUMED: &str = "0xpkg::access_gate::AccessConsumedEvent";

    #[test]
    fn matches_a_valid_consume_for_sender_and_gate() {
        let resp = tx_response(&[event(CONSUMED, "0xowner", "0xgate")]);
        assert!(response_has_consume(&resp, "0xowner", Some("0xgate")));
        assert!(response_has_consume(&resp, "0xowner", None));
    }

    #[test]
    fn rejects_wrong_sender_gate_or_event_type() {
        let resp = tx_response(&[event(CONSUMED, "0xowner", "0xgate")]);
        assert!(!response_has_consume(&resp, "0xattacker", Some("0xgate"))); // wrong sender
        assert!(!response_has_consume(&resp, "0xowner", Some("0xwrong"))); // wrong gate
        let other = tx_response(&[event(
            "0xpkg::access_gate::PurchasedEvent",
            "0xowner",
            "0xgate",
        )]);
        assert!(!response_has_consume(&other, "0xowner", Some("0xgate"))); // wrong event type
    }

    #[test]
    fn rejects_when_no_events() {
        assert!(!response_has_consume(
            &tx_response(&[]),
            "0xowner",
            Some("0xgate")
        ));
        assert!(!response_has_consume(&[], "0xowner", None)); // empty/failed tx
    }

    #[test]
    fn owned_response_matches_gate() {
        // ListOwnedObjectsResponse { objects: [ Object { json } ] }
        let mut obj = ProtoWriter::new();
        obj.bytes_field(OBJECT_JSON, &json_gate("0xgate"));
        let mut resp = ProtoWriter::new();
        resp.bytes_field(LOO_OBJECTS, &obj.into_bytes());
        let bytes = resp.into_bytes();
        assert!(response_has_owned(&bytes, Some("0xgate")));
        assert!(response_has_owned(&bytes, None));
        assert!(!response_has_owned(&bytes, Some("0xother")));
        assert!(!response_has_owned(&[], Some("0xgate")));
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
    // on-chain `access_gate::consume` transaction.
    #[tokio::test]
    #[ignore = "hits Sui testnet gRPC; run with --ignored"]
    async fn live_consume_tx_valid() {
        use crate::http_client::HttpClient;
        use crate::verify::ChainQuery;
        let rpc = SuiRpc::new(
            HttpClient::new().unwrap(),
            "https://fullnode.testnet.sui.io:443".to_string(),
            0,
        );
        let digest = "BbsLUnQGoWSDg6Kd1Hy8vGnyotJtz4hcp45sMv7cGHwU";
        let addr = "0xe6b2810abfc5a6f37a375f73e3ba76cfc37584196e453255ad3c9ca2f0ede0ed";
        let gate = "0x0485c1fa80e4c355c85ab99c0281a328d8fb5c60ac50ab64f10be0f8be792aba";
        assert!(rpc
            .consume_tx_valid(digest, addr, Some(gate))
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(digest, "0x01", Some(gate))
            .await
            .unwrap());
        assert!(!rpc
            .consume_tx_valid(digest, addr, Some("0xdead"))
            .await
            .unwrap());
    }
}
