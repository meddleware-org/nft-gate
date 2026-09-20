//! Access verification: Sui personal-message signature checking (done directly, no heavy
//! SDK) plus the allow/deny decision. The on-chain lookups are abstracted behind
//! [`ChainQuery`] so the decision is unit-testable without a network.

use crate::challenge::NonceStore;
use crate::config::GatewayConfig;
use crate::proof::{decode_access_proof, personal_message_for_nonce};
use base64::prelude::*;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

type Blake2b256 = Blake2b<U32>;

// Sui signature-scheme flag bytes (first byte of a serialized signature).
const FLAG_ED25519: u8 = 0x00;
const FLAG_SECP256K1: u8 = 0x01;
const FLAG_SECP256R1: u8 = 0x02;
const FLAG_MULTISIG: u8 = 0x03;
const FLAG_ZKLOGIN: u8 = 0x05;

/// Compute the 32-byte Blake2b-256 digest of `data`.
fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2b256::new();
    h.update(data);
    h.finalize().into()
}

/// Append `v` to `out` in unsigned LEB-128 encoding. Used to BCS-encode the message-length
/// prefix in the Sui personal-message signing digest.
fn write_uleb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

/// blake2b256( intent(PersonalMessage,V0,Sui) || bcs(Vec<u8> message) ). This is exactly
/// what a Sui wallet signs for a personal message.
fn signing_digest(message: &[u8]) -> [u8; 32] {
    let mut data = vec![3u8, 0, 0]; // IntentScope::PersonalMessage, V0, AppId::Sui
    write_uleb128(&mut data, message.len() as u64);
    data.extend_from_slice(message);
    blake2b256(&data)
}

/// Sui address for a scheme: blake2b256(flag || pubkey), hex, 0x-prefixed. `pubkey` is the
/// 32-byte ed25519 key or the 33-byte SEC1-compressed secp256k1/r1 key.
fn derive_address(flag: u8, pk: &[u8]) -> String {
    let mut d = Vec::with_capacity(1 + pk.len());
    d.push(flag);
    d.extend_from_slice(pk);
    format!("0x{}", hex::encode(blake2b256(&d)))
}

/// Normalise a Sui address to lowercase, 0x-prefixed, zero-padded to 64 hex digits.
fn normalize_address(a: &str) -> String {
    let s = a.trim().trim_start_matches("0x").to_lowercase();
    format!("0x{s:0>64}")
}

/// Verify a Sui personal-message signature recovers `address` over `message`, dispatching on
/// the scheme flag byte. Serialized layout: `flag(1) || signature || pubkey` (base64).
///
/// Supported: **ed25519** (0x00), **secp256k1** (0x01), **secp256r1** (0x02) — the schemes used
/// by every current Sui browser/hardware wallet keypair. **multisig** (0x03) and **zkLogin**
/// (0x05) are recognised but not yet verified here (they require the official Sui verifier —
/// see the gateway audit F1 integration plan) and fail **closed**.
pub fn verify_personal_message_signature(
    address: &str,
    message: &[u8],
    signature_b64: &str,
) -> bool {
    let raw = match BASE64_STANDARD.decode(signature_b64.trim()) {
        Ok(r) => r,
        Err(_) => return false,
    };
    match raw.first().copied() {
        Some(FLAG_ED25519) => verify_ed25519(address, message, &raw[1..]),
        Some(FLAG_SECP256K1) => verify_secp256k1(address, message, &raw[1..]),
        Some(FLAG_SECP256R1) => verify_secp256r1(address, message, &raw[1..]),
        Some(FLAG_MULTISIG) | Some(FLAG_ZKLOGIN) => {
            tracing::warn!(
                flag = raw[0],
                "multisig/zkLogin signature presented but not yet supported by the gateway \
                 verifier (fails closed); see gateway audit F1"
            );
            false
        }
        _ => false,
    }
}

/// ed25519 (flag 0x00): body = `sig(64) || pubkey(32)`.
fn verify_ed25519(address: &str, message: &[u8], body: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if body.len() != 96 {
        return false;
    }
    let sig = match Signature::from_slice(&body[0..64]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk_bytes: [u8; 32] = match body[64..96].try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let digest = signing_digest(message);
    if vk.verify(&digest, &sig).is_err() {
        return false;
    }
    normalize_address(address) == derive_address(FLAG_ED25519, &pk_bytes)
}

/// secp256k1 (flag 0x01): body = `sig(64, compact r||s) || pubkey(33, SEC1-compressed)`.
/// Sui signs `SHA256(blake2b256(intent||msg))` with ECDSA-secp256k1. `k256`'s `Verifier::verify`
/// applies the SHA256 step internally, so we pass the blake2b digest and let k256 do the rest.
fn verify_secp256k1(address: &str, message: &[u8], body: &[u8]) -> bool {
    use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    if body.len() != 97 {
        return false;
    }
    let sig = match Signature::from_slice(&body[0..64]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk_bytes = &body[64..97];
    let vk = match VerifyingKey::from_sec1_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let digest = signing_digest(message);
    if vk.verify(&digest, &sig).is_err() {
        return false;
    }
    normalize_address(address) == derive_address(FLAG_SECP256K1, pk_bytes)
}

/// secp256r1 (flag 0x02): as secp256k1 but over the NIST P-256 curve. Same SHA256-over-blake2b
/// signing hash; `p256`'s `Verifier::verify` applies SHA256 internally.
fn verify_secp256r1(address: &str, message: &[u8], body: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    if body.len() != 97 {
        return false;
    }
    let sig = match Signature::from_slice(&body[0..64]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let pk_bytes = &body[64..97];
    let vk = match VerifyingKey::from_sec1_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let digest = signing_digest(message);
    if vk.verify(&digest, &sig).is_err() {
        return false;
    }
    normalize_address(address) == derive_address(FLAG_SECP256R1, pk_bytes)
}

/// Abstraction over on-chain lookups needed to authorise a request. Implemented by
/// [`crate::sui_rpc::SuiRpc`] in production and by a mock in tests. Kept as a generic trait
/// (not `dyn`) so async methods are allowed without `Box<dyn Future>` wrappers.
#[allow(async_fn_in_trait)]
pub trait ChainQuery {
    /// Does `address` own ≥1 NFT of `nft_type` (optionally for `gate_id`)?
    async fn owns_nft(
        &self,
        address: &str,
        nft_type: &str,
        gate_id: Option<&str>,
    ) -> anyhow::Result<bool>;

    /// Does `consume_digest` name a successful `access_gate::consume` transaction that emitted an
    /// `AccessConsumedEvent` for `address` (the sender) on `gate_id`? Digest-first and NOT bound to
    /// the challenge nonce — single-use is enforced by the redemption store keying on the digest,
    /// so an interrupted upload can resume with a fresh challenge while reusing the same consume.
    async fn consume_tx_valid(
        &self,
        consume_digest: &str,
        address: &str,
        gate_id: Option<&str>,
    ) -> anyhow::Result<bool>;
}

/// Reason a request was rejected by [`verify_access_request`].
#[derive(Debug, PartialEq, Eq)]
pub enum Denied {
    /// The proof token could not be decoded (not valid base64 JSON or missing required fields).
    BadProof,
    /// The signature does not recover the claimed address.
    BadSignature,
    /// The challenge nonce was not found, is expired, or has already been used.
    NonceInvalid,
    /// The address does not hold the required access NFT (ownership mode).
    NotOwner,
    /// No matching on-chain single-use consume event was found (single-use mode).
    ConsumeMissing,
    /// The consume has already been redeemed for an upload, or one is in progress (single-use).
    RedeemConflict,
    /// An on-chain query failed; the gateway returns 502 for this variant.
    ChainError,
}

impl Denied {
    /// A short, client-visible description of why access was denied.
    pub fn reason(&self) -> &'static str {
        match self {
            Denied::BadProof => "malformed access proof",
            Denied::BadSignature => "signature does not recover address",
            Denied::NonceInvalid => "challenge nonce invalid, expired, or already used",
            Denied::NotOwner => "address does not hold the required access NFT",
            Denied::ConsumeMissing => "no matching single-use consume for this address",
            Denied::RedeemConflict => {
                "this consume is already redeemed or an upload for it is in progress"
            }
            Denied::ChainError => "on-chain verification failed",
        }
    }
}

/// A successful verification: the recovered address, plus (single-use mode) the `consume_digest`
/// the dispatcher leases/commits so a use is only spent on a successful upload.
#[derive(Debug)]
pub struct Verified {
    pub address: String,
    pub redemption_key: Option<String>,
}

/// Authorise a request from its base64 proof token. Returns the verified address on success.
/// The nonce is consumed (single-use at the gateway) as part of a successful signature check,
/// so a replay presents an already-used nonce and is rejected.
pub async fn verify_access_request<C: ChainQuery>(
    cfg: &GatewayConfig,
    store: &NonceStore,
    token: &str,
    chain: &C,
) -> Result<Verified, Denied> {
    let proof = decode_access_proof(token).map_err(|_| Denied::BadProof)?;

    let message = personal_message_for_nonce(&proof.nonce);
    if !verify_personal_message_signature(&proof.address, &message, &proof.signature) {
        return Err(Denied::BadSignature);
    }

    // Canonicalise the address once the signature is proven, then use ONLY the normalised form for
    // on-chain comparisons and the returned value. The client emits the raw caller address; on-chain
    // owners are canonical (lower-case, 0x-prefixed, 64-hex), so comparing the raw string would
    // fail-closed for a non-canonical input (e.g. missing leading zeros). Owning canonicalisation
    // here — the security boundary — keeps the client wire format unchanged. (See conformance
    // vectors `addressNormalization`; matched by the Workers gateway.)
    let address = normalize_address(&proof.address);

    // Consume the nonce exactly once (fresh, unexpired, unused).
    if !store.take_if_valid(&proof.nonce).await {
        return Err(Denied::NonceInvalid);
    }

    if cfg.single_use {
        // A single-use client MUST first submit an on-chain consume and include its digest;
        // its absence signals a misconfigured/replaying client.
        let Some(digest) = proof.consume_digest.as_deref() else {
            return Err(Denied::ConsumeMissing);
        };
        let ok = chain
            .consume_tx_valid(digest, &address, cfg.gate_id.as_deref())
            .await
            .map_err(|_| Denied::ChainError)?;
        if !ok {
            return Err(Denied::ConsumeMissing);
        }
        // The consume is valid on-chain; the dispatcher leases/commits this digest so the use is
        // spent only on a successful upload (and a duplicate can't double-spend it).
        return Ok(Verified {
            address,
            redemption_key: Some(digest.to_string()),
        });
    }

    let ok = chain
        .owns_nft(&address, &cfg.nft_type, cfg.gate_id.as_deref())
        .await
        .map_err(|_| Denied::ChainError)?;
    if !ok {
        return Err(Denied::NotOwner);
    }
    Ok(Verified {
        address,
        redemption_key: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::AccessProof;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn build_token(
        sk: &SigningKey,
        address: &str,
        nonce: &str,
        consume_digest: Option<&str>,
    ) -> String {
        let message = personal_message_for_nonce(nonce);
        let digest = signing_digest(&message);
        let sig = sk.sign(&digest);
        let mut serialized = Vec::with_capacity(97);
        serialized.push(0x00);
        serialized.extend_from_slice(&sig.to_bytes());
        serialized.extend_from_slice(sk.verifying_key().as_bytes());
        let sig_b64 = BASE64_STANDARD.encode(serialized);
        let mut obj = json!({ "address": address, "nonce": nonce, "signature": sig_b64 });
        if let Some(d) = consume_digest {
            obj["consumeDigest"] = json!(d);
        }
        BASE64_STANDARD.encode(serde_json::to_vec(&obj).unwrap())
    }

    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let address = derive_address(FLAG_ED25519, sk.verifying_key().as_bytes());
        (sk, address)
    }

    #[test]
    fn signature_verifies_and_recovers_address() {
        let (sk, address) = keypair();
        let msg = personal_message_for_nonce("nonce-1");
        let proof: AccessProof =
            crate::proof::decode_access_proof(&build_token(&sk, &address, "nonce-1", None))
                .unwrap();
        assert!(verify_personal_message_signature(
            &address,
            &msg,
            &proof.signature
        ));
    }

    // ── secp256k1 (flag 0x01) ──────────────────────────────────────────────
    #[test]
    fn secp256k1_signature_verifies_and_recovers_address() {
        use k256::ecdsa::{signature::Signer, Signature, SigningKey as K1SigningKey};
        let sk = K1SigningKey::from_slice(&[9u8; 32]).unwrap();
        let pk = sk.verifying_key().to_encoded_point(true);
        let pk_bytes = pk.as_bytes(); // 33-byte compressed
        let address = derive_address(FLAG_SECP256K1, pk_bytes);

        let msg = personal_message_for_nonce("k1-nonce");
        let digest = signing_digest(&msg);
        // k256 Signer applies SHA256 internally, matching Sui's ECDSA hash: SHA256(blake2b).
        let sig: Signature = sk.sign(&digest);
        let mut serialized = vec![FLAG_SECP256K1];
        serialized.extend_from_slice(&sig.to_bytes());
        serialized.extend_from_slice(pk_bytes);
        let sig_b64 = BASE64_STANDARD.encode(serialized);

        assert!(verify_personal_message_signature(&address, &msg, &sig_b64));
        // wrong address rejected
        assert!(!verify_personal_message_signature("0xdead", &msg, &sig_b64));
        // tampered message rejected
        let other = personal_message_for_nonce("k1-other");
        assert!(!verify_personal_message_signature(
            &address, &other, &sig_b64
        ));
    }

    // ── secp256r1 (flag 0x02) ──────────────────────────────────────────────
    #[test]
    fn secp256r1_signature_verifies_and_recovers_address() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey as R1SigningKey};
        let sk = R1SigningKey::from_slice(&[11u8; 32]).unwrap();
        let pk = sk.verifying_key().to_encoded_point(true);
        let pk_bytes = pk.as_bytes();
        let address = derive_address(FLAG_SECP256R1, pk_bytes);

        let msg = personal_message_for_nonce("r1-nonce");
        let digest = signing_digest(&msg);
        // p256 Signer applies SHA256 internally, matching Sui's ECDSA hash: SHA256(blake2b).
        let sig: Signature = sk.sign(&digest);
        let mut serialized = vec![FLAG_SECP256R1];
        serialized.extend_from_slice(&sig.to_bytes());
        serialized.extend_from_slice(pk_bytes);
        let sig_b64 = BASE64_STANDARD.encode(serialized);

        assert!(verify_personal_message_signature(&address, &msg, &sig_b64));
        assert!(!verify_personal_message_signature("0xdead", &msg, &sig_b64));
    }

    #[test]
    fn multisig_and_zklogin_flags_fail_closed() {
        // flag 0x03 (multisig) / 0x05 (zkLogin) are recognised but not yet verified → false.
        let msg = personal_message_for_nonce("n");
        let mut ms = vec![FLAG_MULTISIG];
        ms.extend_from_slice(&[0u8; 96]);
        assert!(!verify_personal_message_signature(
            "0x1",
            &msg,
            &BASE64_STANDARD.encode(ms)
        ));
        let mut zk = vec![FLAG_ZKLOGIN];
        zk.extend_from_slice(&[0u8; 96]);
        assert!(!verify_personal_message_signature(
            "0x1",
            &msg,
            &BASE64_STANDARD.encode(zk)
        ));
    }

    // ── golden vector — mirrors nft-gate-client proof.test.ts + docs/challenge-response.md ──
    #[test]
    fn golden_vector_personal_message() {
        assert_eq!(
            personal_message_for_nonce("GOLDEN-NONCE-123"),
            b"nft-gate:access:GOLDEN-NONCE-123".to_vec()
        );
    }

    // ── cross-implementation conformance: the SAME fixtures the Workers gateway verifies
    // (gateway/conformance/vectors.json), so the two implementations cannot silently drift on
    // the wire format. Each `signatures[]` entry is a real Sui personal-message signature. ──
    #[test]
    fn conformance_shared_vectors() {
        let raw = include_str!("../../conformance/vectors.json");
        let v: serde_json::Value = serde_json::from_str(raw).unwrap();

        // personal-message derivation
        let pm = &v["personalMessage"];
        let nonce = pm["nonce"].as_str().unwrap();
        assert_eq!(
            personal_message_for_nonce(nonce),
            pm["messageUtf8"].as_str().unwrap().as_bytes().to_vec()
        );

        // proof decode
        let pd = &v["proofDecode"];
        let decoded = crate::proof::decode_access_proof(pd["token"].as_str().unwrap()).unwrap();
        assert_eq!(decoded.address, pd["expect"]["address"].as_str().unwrap());
        assert_eq!(decoded.nonce, pd["expect"]["nonce"].as_str().unwrap());
        assert_eq!(
            decoded.signature,
            pd["expect"]["signature"].as_str().unwrap()
        );

        // address normalization — the proof address is canonicalised before on-chain owner
        // comparison; both gateways must produce identical output for the same input.
        for case in v["addressNormalization"]["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let expected = case["expected"].as_str().unwrap();
            assert_eq!(
                normalize_address(input),
                expected,
                "address normalization diverged for input {input}"
            );
        }

        // per-scheme signature verification (ed25519 / secp256k1 / secp256r1)
        for sig in v["signatures"].as_array().unwrap() {
            let address = sig["address"].as_str().unwrap();
            let nonce = sig["nonce"].as_str().unwrap();
            let signature = sig["signature"].as_str().unwrap();
            let msg = personal_message_for_nonce(nonce);
            assert!(
                verify_personal_message_signature(address, &msg, signature),
                "scheme {} failed to verify",
                sig["scheme"].as_str().unwrap_or("?")
            );
            let p = crate::proof::decode_access_proof(sig["proofToken"].as_str().unwrap()).unwrap();
            assert_eq!(p.address, address);
        }
    }

    #[test]
    fn signature_rejected_for_wrong_address() {
        let (sk, _addr) = keypair();
        let msg = personal_message_for_nonce("nonce-1");
        let proof: AccessProof =
            crate::proof::decode_access_proof(&build_token(&sk, "0xdead", "nonce-1", None))
                .unwrap();
        assert!(!verify_personal_message_signature(
            "0xdead",
            &msg,
            &proof.signature
        ));
    }

    #[test]
    fn signature_rejected_when_tampered() {
        let (sk, address) = keypair();
        // sign nonce A but verify against nonce B's message
        let proof: AccessProof =
            crate::proof::decode_access_proof(&build_token(&sk, &address, "nonce-A", None))
                .unwrap();
        let other_msg = personal_message_for_nonce("nonce-B");
        assert!(!verify_personal_message_signature(
            &address,
            &other_msg,
            &proof.signature
        ));
    }

    struct MockChain {
        owns: bool,
        consumed: bool,
    }
    impl ChainQuery for MockChain {
        async fn owns_nft(&self, _a: &str, _t: &str, _g: Option<&str>) -> anyhow::Result<bool> {
            Ok(self.owns)
        }
        async fn consume_tx_valid(
            &self,
            _d: &str,
            _a: &str,
            _g: Option<&str>,
        ) -> anyhow::Result<bool> {
            Ok(self.consumed)
        }
    }

    fn cfg(single_use: bool) -> GatewayConfig {
        GatewayConfig {
            bind_addr: "0.0.0.0:8080".parse().unwrap(),
            upstream_url: "http://upstream".into(),
            sui_rpc_url: "http://rpc".into(),
            nft_type: "0xpkg::access_gate::AccessNFT".into(),
            gate_id: None,
            challenge_ttl_secs: 300,
            single_use,
            public_paths: vec!["/v1/tip-config".into()],
            rate_limit_per_min: 30,
            challenge_rate_limit_per_min: 30,
            max_body_bytes: 262144,
            redis_url: None,
            nonce_max_entries: 10_000,
            nonce_prune_interval_secs: 60,
            ownership_cache_ttl_ms: 0,
            redemption_lease_ttl_secs: 120,
            redemption_retention_secs: 2_592_000,
        }
    }

    #[tokio::test]
    async fn allows_owner_with_valid_proof() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("real-nonce").await;
        let token = build_token(&sk, &address, &nonce, None);
        let res = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
            },
        )
        .await;
        let v = res.unwrap();
        assert_eq!(v.address, address);
        assert_eq!(v.redemption_key, None); // ownership mode has no redemption key
    }

    #[tokio::test]
    async fn denies_non_owner() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n2").await;
        let token = build_token(&sk, &address, &nonce, None);
        let res = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: false,
                consumed: false,
            },
        )
        .await;
        assert_eq!(res.unwrap_err(), Denied::NotOwner);
    }

    #[tokio::test]
    async fn denies_replayed_nonce() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n3").await;
        let token = build_token(&sk, &address, &nonce, None);
        let ok = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
            },
        )
        .await;
        assert!(ok.is_ok());
        // second use of the same nonce is rejected
        let again = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
            },
        )
        .await;
        assert_eq!(again.unwrap_err(), Denied::NonceInvalid);
    }

    #[tokio::test]
    async fn denies_bad_signature() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n4").await;
        // sign a different nonce than the proof claims
        let mut token_proof: serde_json::Value = serde_json::from_slice(
            &BASE64_STANDARD
                .decode(build_token(&sk, &address, "OTHER", None))
                .unwrap(),
        )
        .unwrap();
        token_proof["nonce"] = json!(nonce); // claim n4 but signature is over OTHER
        let token = BASE64_STANDARD.encode(serde_json::to_vec(&token_proof).unwrap());
        let res = verify_access_request(
            &cfg(false),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
            },
        )
        .await;
        assert_eq!(res.unwrap_err(), Denied::BadSignature);
    }

    #[tokio::test]
    async fn single_use_requires_consume_event() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n5").await;
        let token = build_token(&sk, &address, &nonce, Some("0xdigest"));
        // owns but no consume -> denied
        let denied = verify_access_request(
            &cfg(true),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: false,
            },
        )
        .await;
        assert_eq!(denied.unwrap_err(), Denied::ConsumeMissing);

        let (nonce2, _) = store.issue_specific("n6").await;
        let token2 = build_token(&sk, &address, &nonce2, Some("0xdigest"));
        let ok = verify_access_request(
            &cfg(true),
            &store,
            &token2,
            &MockChain {
                owns: false,
                consumed: true,
            },
        )
        .await;
        let v = ok.unwrap();
        assert_eq!(v.address, address);
        // single-use returns the consume digest as the redemption key for the dispatcher to lease
        assert_eq!(v.redemption_key.as_deref(), Some("0xdigest"));
    }

    #[tokio::test]
    async fn single_use_denies_missing_consume_digest() {
        let (sk, address) = keypair();
        let store = NonceStore::in_memory(300, 10_000);
        let (nonce, _) = store.issue_specific("n7").await;
        let token = build_token(&sk, &address, &nonce, None); // no consumeDigest
        let res = verify_access_request(
            &cfg(true),
            &store,
            &token,
            &MockChain {
                owns: true,
                consumed: true,
            },
        )
        .await;
        assert_eq!(res.unwrap_err(), Denied::ConsumeMissing);
    }
}
