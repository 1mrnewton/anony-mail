//! App Attest verification (docs/09, phase 2).
//!
//! Proves a request comes from a genuine, unmodified build of the official
//! iOS app on real hardware: the device's Secure Enclave key attests once
//! (certificate chain to Apple's App Attestation root CA), then refreshes its
//! client token with assertions whose counter must strictly increase.
//! Verification is fully local via the `appattest` crate — the server never
//! calls Apple. Everything is off unless `APP_ATTEST_TEAM_ID`/`_BUNDLE_ID`
//! are configured.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use appattest::assertion::Assertion;
use appattest::attestation::Attestation;
use base64::Engine as _;
use rand::RngExt as _;
use sha2::{Digest, Sha256};

/// Apple's App Attestation Root CA (P-384, valid 2020-03-18 → 2045-03-15),
/// from <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>.
/// Embedded so verification needs no network and no boot-time fetch;
/// `APP_ATTEST_ROOT_CA_PATH` overrides it (rotation, tests).
pub const APPLE_ROOT_CA_PEM: &[u8] = include_bytes!("apple_app_attest_root_ca.pem");

/// How long an issued challenge stays redeemable.
pub const CHALLENGE_TTL_SECONDS: u64 = 300;

/// Hard cap on outstanding challenges — they are free to request, so the map
/// must stay bounded even under a flood (the create-route rate limit is the
/// first line of defense).
const MAX_OUTSTANDING_CHALLENGES: usize = 100_000;

/// Upper bound on the base64 attestation blob (real ones are ~7.5 KB).
const MAX_ATTESTATION_B64_LEN: usize = 32 * 1024;

/// Upper bound on the base64 assertion blob (real ones are ~250 bytes; the
/// crate itself rejects anything decoding past 192 bytes).
const MAX_ASSERTION_B64_LEN: usize = 1024;

/// Single-use anti-replay challenges for `/api/client/attest` + `/assert`.
/// In-memory by design: this is a single-process deployment (same stance as
/// the rate limiters); replicas would need a shared table instead.
pub struct ChallengeStore {
    ttl: Duration,
    issued: Mutex<HashMap<String, Instant>>,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new(Duration::from_secs(CHALLENGE_TTL_SECONDS))
    }
}

impl ChallengeStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            issued: Mutex::new(HashMap::new()),
        }
    }

    /// Issue a fresh single-use challenge: 32 CSPRNG bytes, base64url.
    pub fn issue(&self) -> String {
        let bytes: [u8; 32] = rand::rng().random();
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

        let now = Instant::now();
        let mut issued = self.issued.lock().expect("challenge store poisoned");
        if issued.len() >= MAX_OUTSTANDING_CHALLENGES {
            issued.retain(|_, at| now.duration_since(*at) < self.ttl);
            // Still flooded after dropping expired ones: shed the older half
            // of the window. Legitimate in-flight attests simply retry with a
            // fresh challenge.
            if issued.len() >= MAX_OUTSTANDING_CHALLENGES {
                let half = self.ttl / 2;
                issued.retain(|_, at| now.duration_since(*at) < half);
            }
        }
        issued.insert(challenge.clone(), now);
        challenge
    }

    /// Redeem a challenge: true exactly once, and only within the TTL.
    pub fn consume(&self, challenge: &str) -> bool {
        let mut issued = self.issued.lock().expect("challenge store poisoned");
        issued
            .remove(challenge)
            .is_some_and(|at| at.elapsed() < self.ttl)
    }
}

/// Why an attestation or assertion was rejected. Rendered into the 400
/// response body — the detail helps app debugging and gives forgers nothing
/// (Apple's verification steps are public).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct AttestError(String);

/// Verify a one-time attestation object against `app_id`
/// (`TEAMID.bundle.id`) and the given root CA. Returns the device's 65-byte
/// uncompressed P-256 public key to store for later assertions.
///
/// The crate checks the full Apple recipe: certificate chain to the root,
/// nonce = SHA256(authData ‖ SHA256(challenge)) in the credential cert,
/// key id = SHA256(public key), RP ID = SHA256(app_id), counter 0, and the
/// App Attest AAGUID (production and development environments both accepted).
pub fn verify_attestation(
    app_id: &str,
    root_pem: &[u8],
    challenge: &str,
    key_id: &str,
    attestation_b64: &str,
) -> Result<Vec<u8>, AttestError> {
    if attestation_b64.len() > MAX_ATTESTATION_B64_LEN {
        return Err(AttestError("attestation too large".to_string()));
    }
    let cbor = Attestation::decode_base64(attestation_b64)
        .map_err(|e| AttestError(format!("attestation base64: {e}")))?;
    let attestation = Attestation::from_cbor_bytes(&cbor)
        .map_err(|e| AttestError(format!("attestation cbor: {e}")))?;
    let (public_key, _receipt) = attestation
        .verify(challenge, app_id, key_id, root_pem)
        .map_err(|e| AttestError(format!("attestation rejected: {e}")))?;
    Ok(public_key.to_vec())
}

/// Verify an assertion made with a previously attested key: ECDSA signature
/// over SHA256(authData ‖ SHA256(challenge)) with the stored public key,
/// RP ID matching `app_id`, and a counter strictly greater than
/// `previous_counter`. Returns the new counter to persist.
pub fn verify_assertion(
    app_id: &str,
    challenge: &str,
    assertion_b64: &str,
    public_key: &[u8],
    previous_counter: i64,
) -> Result<i64, AttestError> {
    if assertion_b64.len() > MAX_ASSERTION_B64_LEN {
        return Err(AttestError("assertion too large".to_string()));
    }
    let cbor = base64::engine::general_purpose::STANDARD
        .decode(assertion_b64)
        .map_err(|e| AttestError(format!("assertion base64: {e}")))?;

    let previous: u32 = previous_counter
        .try_into()
        .map_err(|_| AttestError("stored counter out of range".to_string()))?;

    // The counter the device claims, read straight from the CBOR. Trustable
    // only because `verify` below checks the signature over these exact
    // authenticator-data bytes.
    let new_counter = assertion_counter(&cbor)?;

    let client_data_hash: [u8; 32] = Sha256::digest(challenge.as_bytes()).into();
    Assertion::from_assertion(&cbor)
        .map_err(|e| AttestError(format!("assertion cbor: {e}")))?
        .verify(
            client_data_hash,
            challenge,
            app_id,
            public_key,
            previous,
            challenge,
        )
        .map_err(|e| AttestError(format!("assertion rejected: {e}")))?;

    Ok(i64::from(new_counter))
}

/// Extract the big-endian counter (bytes 33..37 of `authenticatorData`) from
/// assertion CBOR. The `appattest` crate verifies the counter advanced but
/// does not expose its value, which we must persist for replay protection.
fn assertion_counter(cbor: &[u8]) -> Result<u32, AttestError> {
    let mut decoder = minicbor::Decoder::new(cbor);
    let entries = decoder
        .map()
        .map_err(|_| AttestError("assertion is not a cbor map".to_string()))?
        .unwrap_or(0);
    for _ in 0..entries {
        let key = decoder
            .str()
            .map_err(|_| AttestError("assertion map key".to_string()))?;
        if key == "authenticatorData" {
            let auth_data = decoder
                .bytes()
                .map_err(|_| AttestError("authenticatorData bytes".to_string()))?;
            let counter_bytes: [u8; 4] = auth_data
                .get(33..37)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| AttestError("authenticatorData too short".to_string()))?;
            return Ok(u32::from_be_bytes(counter_bytes));
        }
        decoder
            .skip()
            .map_err(|_| AttestError("assertion map value".to_string()))?;
    }
    Err(AttestError(
        "assertion missing authenticatorData".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use appattest::testing::{TEST_ROOT_CA_CERT_PEM, build_test_assertion, build_test_attestation};
    use base64::engine::general_purpose::STANDARD as B64;

    const APP_ID: &str = "TESTTEAM12.com.example.app";

    #[test]
    fn challenges_are_single_use_and_unique() {
        let store = ChallengeStore::default();
        let c1 = store.issue();
        let c2 = store.issue();
        assert_ne!(c1, c2);
        assert!(store.consume(&c1), "first redemption");
        assert!(!store.consume(&c1), "second redemption must fail");
        assert!(!store.consume("never-issued"));
    }

    #[test]
    fn expired_challenges_do_not_redeem() {
        let store = ChallengeStore::new(Duration::ZERO);
        let c = store.issue();
        assert!(!store.consume(&c));
    }

    #[test]
    fn attestation_roundtrip_yields_stored_key() {
        let challenge = "test-challenge";
        let ta = build_test_attestation(challenge, APP_ID);
        let b64 = B64.encode(&ta.cbor);

        let public_key =
            verify_attestation(APP_ID, TEST_ROOT_CA_CERT_PEM, challenge, &ta.key_id, &b64)
                .expect("valid synthetic attestation");
        assert_eq!(public_key.len(), 65);

        // Wrong challenge, wrong app id, or the real Apple root must fail.
        assert!(
            verify_attestation(APP_ID, TEST_ROOT_CA_CERT_PEM, "other", &ta.key_id, &b64).is_err()
        );
        assert!(
            verify_attestation(
                "OTHERTEAM0.com.example.app",
                TEST_ROOT_CA_CERT_PEM,
                challenge,
                &ta.key_id,
                &b64
            )
            .is_err()
        );
        assert!(
            verify_attestation(APP_ID, APPLE_ROOT_CA_PEM, challenge, &ta.key_id, &b64).is_err()
        );
    }

    #[test]
    fn assertion_roundtrip_advances_counter_and_blocks_replay() {
        let challenge = "attest-challenge";
        let ta = build_test_attestation(challenge, APP_ID);
        let b64 = B64.encode(&ta.cbor);
        let public_key =
            verify_attestation(APP_ID, TEST_ROOT_CA_CERT_PEM, challenge, &ta.key_id, &b64).unwrap();

        let assert_challenge = "assert-challenge-1";
        let client_data_hash: [u8; 32] = Sha256::digest(assert_challenge.as_bytes()).into();
        let assertion = build_test_assertion(APP_ID, client_data_hash, 0, &ta.device_key);
        let assertion_b64 = B64.encode(&assertion);

        let new_counter =
            verify_assertion(APP_ID, assert_challenge, &assertion_b64, &public_key, 0)
                .expect("valid synthetic assertion");
        assert_eq!(new_counter, 1);

        // Replaying the same assertion against the advanced counter fails.
        assert!(
            verify_assertion(
                APP_ID,
                assert_challenge,
                &assertion_b64,
                &public_key,
                new_counter
            )
            .is_err()
        );

        // A different device key fails the signature check.
        let other = build_test_attestation("x", APP_ID);
        let forged = build_test_assertion(APP_ID, client_data_hash, 0, &other.device_key);
        assert!(
            verify_assertion(
                APP_ID,
                assert_challenge,
                &B64.encode(&forged),
                &public_key,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn garbage_inputs_are_rejected_not_panics() {
        assert!(verify_attestation(APP_ID, TEST_ROOT_CA_CERT_PEM, "c", "k", "!!!").is_err());
        assert!(verify_attestation(APP_ID, TEST_ROOT_CA_CERT_PEM, "c", "k", "aGVsbG8=").is_err());
        assert!(verify_assertion(APP_ID, "c", "!!!", &[4u8; 65], 0).is_err());
        assert!(verify_assertion(APP_ID, "c", "aGVsbG8=", &[4u8; 65], 0).is_err());
        let huge = "A".repeat(MAX_ATTESTATION_B64_LEN + 1);
        assert!(verify_attestation(APP_ID, TEST_ROOT_CA_CERT_PEM, "c", "k", &huge).is_err());
    }
}
