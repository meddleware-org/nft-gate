//! Access-proof wire format. MUST stay in sync with `@meddleware/nft-gate-client`'s `proof.ts`.
//!
//! # Wire format
//!
//! The proof token is `base64(UTF-8 JSON)` where the JSON object has the shape:
//!
//! ```text
//! { "address": "<0x-hex>", "nonce": "<hex>", "signature": "<base64>", "consumeDigest"?: "<tx-digest>" }
//! ```
//!
//! The optional `consumeDigest` field is camelCase in the JSON (JavaScript convention); this
//! module normalises it to `consume_digest` (snake_case) before deserializing into
//! [`AccessProof`] so serde's default field mapping works. Any other field-name mismatch between
//! the Rust struct and the JSON will be a silent `None` / deserialization error — keep the two in
//! sync when either side evolves.

use base64::prelude::*;
use serde::Deserialize;

/// Decoded access-proof submitted by the client in the `Authorization: Bearer` (or
/// `X-Access-Proof`) header.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessProof {
    /// The Sui address (0x-prefixed hex) that signed the challenge.
    pub address: String,
    /// The random nonce from `GET /v1/challenge`.
    pub nonce: String,
    /// Base64-encoded Sui personal-message signature (flag || sig || pubkey).
    pub signature: String,
    /// Optional transaction digest of the on-chain single-use consume (camelCase in JSON,
    /// normalised to snake_case before deserialization).
    #[serde(default)]
    pub consume_digest: Option<String>,
}

/// The exact bytes the wallet signs for a nonce. Mirror of the client's
/// `personalMessageForNonce`.
pub fn personal_message_for_nonce(nonce: &str) -> Vec<u8> {
    format!("nft-gate:access:{nonce}").into_bytes()
}

/// Longest accepted token, checked before decoding. Mirror of the client's `MAX_TOKEN_BYTES`.
pub const MAX_TOKEN_BYTES: usize = 4096;

/// Decode the base64(JSON) proof token. The JSON is `{ address, nonce, signature,
/// consumeDigest? }`; `consumeDigest` (camelCase from JS) is accepted via an alias.
///
/// # Errors
///
/// Returns an error if `token` is longer than [`MAX_TOKEN_BYTES`], is not valid base64, if the
/// decoded bytes are not valid UTF-8 JSON, if any required field (`address`, `nonce`,
/// `signature`) is missing, or if one of them is not ASCII (the client's ASCII contract; the
/// gateways only issue ASCII nonces).
pub fn decode_access_proof(token: &str) -> anyhow::Result<AccessProof> {
    if token.len() > MAX_TOKEN_BYTES {
        anyhow::bail!(
            "access proof token too large ({} > {MAX_TOKEN_BYTES})",
            token.len()
        );
    }
    let json = BASE64_STANDARD
        .decode(token.trim())
        .map_err(|e| anyhow::anyhow!("proof not base64: {e}"))?;
    // Accept the JS camelCase `consumeDigest` by normalising into serde's expected field.
    let mut value: serde_json::Value = serde_json::from_slice(&json)?;
    if let Some(obj) = value.as_object_mut() {
        if let Some(v) = obj.remove("consumeDigest") {
            obj.insert("consume_digest".to_string(), v);
        }
    }
    let proof: AccessProof = serde_json::from_value(value)?;
    if !(proof.address.is_ascii() && proof.nonce.is_ascii() && proof.signature.is_ascii()) {
        anyhow::bail!("non-ASCII field in access proof");
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_message_is_stable() {
        assert_eq!(personal_message_for_nonce("abc"), b"nft-gate:access:abc");
    }

    #[test]
    fn decodes_camelcase_consume_digest() {
        let json = r#"{"address":"0x1","nonce":"n","signature":"s","consumeDigest":"d"}"#;
        let token = BASE64_STANDARD.encode(json);
        let p = decode_access_proof(&token).unwrap();
        assert_eq!(p.address, "0x1");
        assert_eq!(p.consume_digest.as_deref(), Some("d"));
    }

    #[test]
    fn decodes_without_consume_digest() {
        let json = r#"{"address":"0x1","nonce":"n","signature":"s"}"#;
        let token = BASE64_STANDARD.encode(json);
        let p = decode_access_proof(&token).unwrap();
        assert!(p.consume_digest.is_none());
    }

    #[test]
    fn rejects_an_oversized_token_before_decoding() {
        let token = "A".repeat(MAX_TOKEN_BYTES + 1);
        let err = decode_access_proof(&token).unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn rejects_non_ascii_fields() {
        for json in [
            r#"{"address":"0x1","nonce":"nönce","signature":"s"}"#,
            "{\"address\":\"0x\u{e9}1\",\"nonce\":\"n\",\"signature\":\"s\"}",
        ] {
            let token = BASE64_STANDARD.encode(json);
            let err = decode_access_proof(&token).unwrap_err().to_string();
            assert!(err.contains("non-ASCII"), "{err}");
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(decode_access_proof("!!!not-base64!!!").is_err());
    }
}
