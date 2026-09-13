//! DSSE v1 envelopes (ADR-0002 §3; secure-systems-lab/dsse `protocol.md`, `envelope.md`).
//!
//! Everything here handles bytes that are **not yet authenticated**, so every error names a
//! field and never quotes the input.

use std::io::Read;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use super::{Document, FeedError, ENVELOPE_MAX_BYTES};

/// Most signatures one envelope may carry (ADR-0002 §3).
pub const MAX_SIGNATURES: usize = 8;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeJson {
    payload: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    signatures: Vec<SignatureJson>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureJson {
    /// An unauthenticated hint. DSSE: it "MUST NOT be used for security decisions", so it is
    /// read to satisfy the schema and then ignored. Every trusted key is tried instead.
    #[serde(default)]
    #[allow(dead_code)]
    keyid: String,
    sig: String,
}

/// A structurally valid envelope of the expected payload type. Not yet verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Envelope {
    /// The exact bytes that were signed and, once verified, are parsed.
    pub payload: Vec<u8>,
    pub signatures: Vec<Signature>,
    payload_type: &'static str,
}

impl Envelope {
    /// The DSSE pre-authentication encoding of this envelope's payload.
    pub fn signed_message(&self) -> Vec<u8> {
        pae(self.payload_type, &self.payload)
    }
}

/// Read at most [`ENVELOPE_MAX_BYTES`] from `reader`. The read stops at the cap plus one byte;
/// anything longer is refused without being consumed (ADR-0002 §3, FEED-08).
pub fn read_capped<R: Read>(reader: R) -> Result<Vec<u8>, FeedError> {
    let mut bytes = Vec::new();
    reader
        .take(ENVELOPE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FeedError::MalformedEnvelope("unreadable"))?;
    if bytes.len() > ENVELOPE_MAX_BYTES {
        return Err(FeedError::TooLarge);
    }
    Ok(bytes)
}

/// `PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, with `LEN` the
/// ASCII decimal byte length without leading zeros.
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(body);
    out
}

/// Parse an envelope that must carry `expected_type`. The payload is decoded, not parsed.
pub(crate) fn parse_envelope(
    bytes: &[u8],
    expected_type: &'static str,
    document: Document,
) -> Result<Envelope, FeedError> {
    if bytes.len() > ENVELOPE_MAX_BYTES {
        return Err(FeedError::TooLarge);
    }
    let json: EnvelopeJson =
        serde_json::from_slice(bytes).map_err(|_| FeedError::MalformedEnvelope("structure"))?;
    // Exact byte equality: no case folding, no parameters.
    if json.payload_type != expected_type {
        return Err(FeedError::WrongPayloadType(document));
    }
    if json.signatures.is_empty() || json.signatures.len() > MAX_SIGNATURES {
        return Err(FeedError::MalformedEnvelope("signature count"));
    }
    let payload = decode_canonical(&json.payload).ok_or(FeedError::MalformedEnvelope("payload"))?;
    let signatures = json
        .signatures
        .iter()
        .map(|s| {
            let bytes: [u8; 64] = decode_canonical(&s.sig)
                .and_then(|b| b.try_into().ok())
                .ok_or(FeedError::MalformedEnvelope("signature"))?;
            Ok(Signature::from_bytes(&bytes))
        })
        .collect::<Result<Vec<_>, FeedError>>()?;
    Ok(Envelope {
        payload,
        signatures,
        payload_type: expected_type,
    })
}

/// Standard-alphabet, padded base64 that re-encodes to exactly the input. Anything else,
/// including URL-safe, unpadded or non-zero trailing bits, is refused.
pub(crate) fn decode_canonical(text: &str) -> Option<Vec<u8>> {
    let bytes = STANDARD.decode(text).ok()?;
    (STANDARD.encode(&bytes) == text).then_some(bytes)
}

/// How many **distinct** keys from `keys` produced a strictly valid signature over `message`.
///
/// Strict verification rejects non-canonical and small-order signature components. A key
/// counts once however many of its signatures appear (ADR-0002 §2).
pub(crate) fn count_signers<'k>(
    message: &[u8],
    signatures: &[Signature],
    keys: impl IntoIterator<Item = &'k VerifyingKey>,
) -> usize {
    keys.into_iter()
        .filter(|key| {
            signatures
                .iter()
                .any(|sig| key.verify_strict(message, sig).is_ok())
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_the_dsse_definition() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ");
    }

    #[test]
    fn base64_must_be_canonical_standard_and_padded() {
        assert_eq!(decode_canonical("aGk="), Some(b"hi".to_vec()));
        assert_eq!(decode_canonical("aGk"), None); // unpadded
        assert_eq!(decode_canonical("aGl="), None); // non-zero trailing bits
        assert_eq!(decode_canonical("-_8="), None); // URL-safe alphabet
        assert_eq!(decode_canonical(" aGk="), None);
    }

    #[test]
    fn a_reader_is_never_consumed_past_the_cap() {
        struct Counting(usize);
        impl Read for Counting {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf.fill(b'a');
                self.0 += buf.len();
                Ok(buf.len())
            }
        }
        let mut endless = Counting(0);
        assert_eq!(read_capped(&mut endless), Err(FeedError::TooLarge));
        assert!(endless.0 <= ENVELOPE_MAX_BYTES + 1, "read {}", endless.0);

        let exact = vec![b'a'; ENVELOPE_MAX_BYTES];
        assert_eq!(
            read_capped(exact.as_slice()).unwrap().len(),
            ENVELOPE_MAX_BYTES
        );
    }
}
