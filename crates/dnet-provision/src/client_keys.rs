// SPDX-License-Identifier: GPL-3.0-or-later
//! Key material and parameters the *client* makes for a new endpoint (PR-13).
//!
//! Each side of a tunnel should hold its own private key and tell the other only the public half. For
//! AmneziaWG that means the client makes its keypair here, on the person's machine, and only the **public**
//! key goes into the server's bootstrap; the server makes its own and reports only its public key. The
//! client's private key never leaves this process except into the person's own sealed credential store.
//!
//! The obfuscation parameters are shared configuration (both ends must agree on them) rather than secrets
//! in the cryptographic sense, but they are what makes the handshake not look like the unobfuscated base
//! handshake, and a value everybody shares is a signature. So they are made fresh, from the operating
//! system's randomness, for every endpoint, within the bounds the profile feed uses (ADR-0002 §5.4).

use curve25519_dalek::montgomery::MontgomeryPoint;
use dnet_config::amneziawg::ObfuscationParams;
use dnet_core::transport_params::amneziawg_feed as awg;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("the operating system gave no randomness")]
    NoRandomness,
}

/// A client AmneziaWG keypair. The private half is wiped on drop and never printed.
pub struct ClientKeys {
    private_hex: Zeroizing<String>,
    public_hex: String,
}

impl std::fmt::Debug for ClientKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ClientKeys {{ private: <redacted>, public: {} }}",
            self.public_hex
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl ClientKeys {
    /// A fresh keypair from the operating system's randomness.
    pub fn generate() -> Result<Self, KeyError> {
        let mut private = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *private).map_err(|_| KeyError::NoRandomness)?;
        Ok(Self::from_private(*private))
    }

    /// The keypair for a given private key. The key is clamped as X25519 requires before the public half is
    /// derived; the private key is stored as given (the core clamps again when it uses it).
    pub fn from_private(private: [u8; 32]) -> Self {
        let public = MontgomeryPoint::mul_base_clamped(private).to_bytes();
        let private_hex = Zeroizing::new(hex(&private));
        Self {
            private_hex,
            public_hex: hex(&public),
        }
    }

    /// 64 lowercase hex digits, the form the core's control interface takes. This is the secret: it goes
    /// into the person's sealed credentials and nowhere else.
    pub fn private_hex(&self) -> &str {
        &self.private_hex
    }

    /// 64 lowercase hex digits. Public: goes to the server.
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }
}

/// A device's key pair for the session (ADR-0008): the same curve as [`ClientKeys`], written the way the primary
/// core takes it, as standard base64 of the 32 bytes. A key pair of its own: the AmneziaWG key is never reused
/// for another protocol. The private half is wiped on drop and never printed.
pub struct SessionKeys {
    private_b64: Zeroizing<String>,
    public_b64: String,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SessionKeys {{ private: <redacted>, public: {} }}",
            self.public_b64
        )
    }
}

impl SessionKeys {
    /// A fresh key pair from the operating system's randomness.
    pub fn generate() -> Result<Self, KeyError> {
        let mut private = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *private).map_err(|_| KeyError::NoRandomness)?;
        Ok(Self::from_private(*private))
    }

    /// The key pair for a given private key (clamped as X25519 requires before the public half is derived).
    pub fn from_private(private: [u8; 32]) -> Self {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let public = MontgomeryPoint::mul_base_clamped(private).to_bytes();
        Self {
            private_b64: Zeroizing::new(STANDARD.encode(private)),
            public_b64: STANDARD.encode(public),
        }
    }

    /// 44 characters. The secret: it goes into the person's sealed credentials and nowhere else.
    pub fn private_b64(&self) -> &str {
        &self.private_b64
    }

    /// 44 characters. Public: goes to the server.
    pub fn public_b64(&self) -> &str {
        &self.public_b64
    }
}

/// A uniform number in `low..=high`, from the operating system's randomness.
fn random_in(low: u32, high: u32) -> Result<u32, KeyError> {
    debug_assert!(low <= high);
    let span = u64::from(high - low) + 1;
    // Reject the top slice of the 64-bit range so every value in the span is equally likely.
    let limit = u64::MAX - (u64::MAX % span);
    loop {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).map_err(|_| KeyError::NoRandomness)?;
        let draw = u64::from_le_bytes(bytes);
        if draw < limit {
            return Ok(low + (draw % span) as u32);
        }
    }
}

/// Fresh obfuscation parameters, valid for the pinned core and inside the feed's bounds.
pub fn random_obfuscation() -> Result<ObfuscationParams, KeyError> {
    let jc = random_in(3, 10)?;
    let jmin = random_in(40, 100)?;
    let jmax = random_in(jmin + 30, 300)?;
    let s1 = random_in(15, 150)?;
    // `s1 + 56 == s2` would make the padded initiation and response the same size, which is a pattern.
    let s2 = loop {
        let candidate = random_in(15, 150)?;
        if candidate != s1 + awg::INIT_RESPONSE_SIZE_DIFFERENCE {
            break candidate;
        }
    };
    let mut headers = Vec::with_capacity(4);
    while headers.len() < 4 {
        let candidate = random_in(awg::HEADER_MIN, awg::HEADER_MAX)?;
        if !headers.contains(&candidate) {
            headers.push(candidate);
        }
    }
    let params = ObfuscationParams {
        jc,
        jmin,
        jmax,
        s1,
        s2,
        h1: headers[0],
        h2: headers[1],
        h3: headers[2],
        h4: headers[3],
    };
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 §6.1: Alice's private key and the public key it must give.
    const ALICE_PRIVATE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    /// RFC 7748 §6.1: Bob's.
    const BOB_PRIVATE: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

    fn bytes(text: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn the_public_key_matches_the_rfc_7748_known_answers() {
        for (private, public) in [(ALICE_PRIVATE, ALICE_PUBLIC), (BOB_PRIVATE, BOB_PUBLIC)] {
            let keys = ClientKeys::from_private(bytes(private));
            assert_eq!(keys.public_hex(), public);
            assert_eq!(keys.private_hex(), private);
        }
    }

    #[test]
    fn session_keys_are_the_same_curve_in_the_form_the_core_takes() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        // The RFC 7748 known answers, in standard base64 of the raw 32 bytes.
        let keys = SessionKeys::from_private(bytes(ALICE_PRIVATE));
        assert_eq!(keys.public_b64(), STANDARD.encode(bytes(ALICE_PUBLIC)));
        assert_eq!(keys.private_b64(), STANDARD.encode(bytes(ALICE_PRIVATE)));
        assert_eq!(keys.public_b64().len(), 44);
        // One person's two protocols never share a key.
        let (session, awg) = (
            SessionKeys::generate().unwrap(),
            ClientKeys::generate().unwrap(),
        );
        assert_ne!(
            STANDARD.decode(session.public_b64()).unwrap(),
            bytes(awg.public_hex()).to_vec()
        );
    }

    #[test]
    fn generated_session_keys_are_distinct_and_the_private_half_never_prints() {
        let (a, b) = (
            SessionKeys::generate().unwrap(),
            SessionKeys::generate().unwrap(),
        );
        assert_ne!(a.private_b64(), b.private_b64());
        assert_ne!(a.public_b64(), b.public_b64());
        for keys in [&a, &b] {
            let shown = format!("{keys:?}");
            assert!(!shown.contains(keys.private_b64()), "{shown}");
            assert!(shown.contains(keys.public_b64()));
        }
    }

    #[test]
    fn generated_keys_are_distinct_well_formed_and_the_private_half_never_prints() {
        let (a, b) = (
            ClientKeys::generate().unwrap(),
            ClientKeys::generate().unwrap(),
        );
        assert_ne!(a.private_hex(), b.private_hex());
        assert_ne!(a.public_hex(), b.public_hex());
        for keys in [&a, &b] {
            for half in [keys.private_hex(), keys.public_hex()] {
                assert_eq!(half.len(), 64);
                assert!(half
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
            }
            let shown = format!("{keys:?}");
            assert!(!shown.contains(keys.private_hex()), "{shown}");
            assert!(shown.contains(keys.public_hex()));
        }
    }

    #[test]
    fn a_numbers_range_is_inclusive_and_covers_both_ends() {
        let mut seen_low = false;
        let mut seen_high = false;
        for _ in 0..2000 {
            let n = random_in(5, 7).unwrap();
            assert!((5..=7).contains(&n));
            seen_low |= n == 5;
            seen_high |= n == 7;
        }
        assert!(seen_low && seen_high);
        assert_eq!(random_in(9, 9).unwrap(), 9);
    }

    #[test]
    fn every_set_of_obfuscation_parameters_is_valid_for_the_core_and_inside_the_feed_bounds() {
        // The padding rule (`s2 != s1 + 56`) is hit by chance about once in two hundred sets, so the count
        // is high enough that a missing check cannot go unseen.
        for _ in 0..5000 {
            let p = random_obfuscation().unwrap();
            assert_eq!(p.validate(), Ok(()), "{p:?}");
            assert!((awg::JC_MIN..=awg::JC_MAX).contains(&p.jc));
            assert!(p.jmin < p.jmax && p.jmax <= awg::JUNK_SIZE_MAX, "{p:?}");
            assert!(p.s1 <= awg::S1_MAX && p.s2 <= awg::S2_MAX, "{p:?}");
            assert_ne!(p.s1 + awg::INIT_RESPONSE_SIZE_DIFFERENCE, p.s2, "{p:?}");
            for h in [p.h1, p.h2, p.h3, p.h4] {
                assert!((awg::HEADER_MIN..=awg::HEADER_MAX).contains(&h), "{p:?}");
            }
            let mut headers = [p.h1, p.h2, p.h3, p.h4];
            headers.sort_unstable();
            assert!(headers.windows(2).all(|w| w[0] != w[1]), "{p:?}");
        }
    }

    #[test]
    fn two_endpoints_do_not_share_parameters() {
        let a = random_obfuscation().unwrap();
        let b = random_obfuscation().unwrap();
        assert_ne!(a, b);
    }
}
