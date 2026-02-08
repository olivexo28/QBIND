//! Envelope signature verification (T225).
//!
//! This module provides multi-signature verification for upgrade envelopes
//! against a council keyset. It verifies that:
//!
//! 1. The envelope has at least M valid signatures (threshold check)
//! 2. Each signature is from a known council member
//! 3. Each signature is cryptographically valid (ML-DSA-44)
//!
//! # Example
//!
//! ```ignore
//! use qbind_gov::verify::{verify_envelope, VerificationResult};
//!
//! let envelope = UpgradeEnvelope::from_file("envelope.json")?;
//! let keyset = CouncilKeySet::from_file("council-keys.json")?;
//!
//! let result = verify_envelope(&envelope, &keyset)?;
//! if result.is_valid() {
//!     println!("Envelope is valid with {} signatures", result.valid_count);
//! }
//! ```

use qbind_crypto::ml_dsa44::MlDsa44Backend;

use crate::council::CouncilKeySet;
use crate::envelope::{CouncilSignature, EnvelopeError, UpgradeEnvelope};
use crate::hash::envelope_digest;

/// Result of verifying a single signature.
#[derive(Clone, Debug)]
pub struct SignatureVerification {
    /// Council member ID.
    pub member_id: String,
    /// Whether the signature is valid.
    pub valid: bool,
    /// Error message if verification failed.
    pub error: Option<String>,
}

/// Result of verifying all signatures on an envelope.
#[derive(Clone, Debug)]
pub struct VerificationResult {
    /// Number of valid signatures.
    pub valid_count: usize,
    /// Required threshold.
    pub threshold: usize,
    /// Individual signature verification results.
    pub signatures: Vec<SignatureVerification>,
    /// Envelope digest that was verified (hex).
    pub digest_hex: String,
}

impl VerificationResult {
    /// Returns true if the envelope meets the threshold requirement.
    pub fn is_valid(&self) -> bool {
        self.valid_count >= self.threshold
    }

    /// Returns the number of invalid signatures.
    pub fn invalid_count(&self) -> usize {
        self.signatures.len() - self.valid_count
    }

    /// Returns a list of valid member IDs.
    pub fn valid_members(&self) -> Vec<&str> {
        self.signatures
            .iter()
            .filter(|s| s.valid)
            .map(|s| s.member_id.as_str())
            .collect()
    }

    /// Returns a list of invalid signature results.
    pub fn invalid_signatures(&self) -> Vec<&SignatureVerification> {
        self.signatures.iter().filter(|s| !s.valid).collect()
    }
}

/// Verify all council signatures on an upgrade envelope.
///
/// This function:
/// 1. Computes the canonical envelope digest
/// 2. Verifies each signature against the council keyset
/// 3. Returns a detailed verification result
///
/// # Arguments
///
/// * `envelope` - The upgrade envelope to verify
/// * `keyset` - The council keyset containing public keys
///
/// # Returns
///
/// A `VerificationResult` with details about each signature.
pub fn verify_envelope(
    envelope: &UpgradeEnvelope,
    keyset: &CouncilKeySet,
) -> Result<VerificationResult, EnvelopeError> {
    // Compute envelope digest
    let digest = envelope_digest(envelope)?;
    let digest_hex = hex::encode(digest);

    // Build key lookup map
    let key_map = keyset.key_map()?;

    // Verify each signature
    let mut signatures = Vec::new();
    let mut valid_count = 0;

    for approval in &envelope.council_approvals {
        let verification = verify_single_signature(approval, &digest, &key_map);
        if verification.valid {
            valid_count += 1;
        }
        signatures.push(verification);
    }

    Ok(VerificationResult {
        valid_count,
        threshold: keyset.threshold(),
        signatures,
        digest_hex,
    })
}

/// Verify a single council signature.
fn verify_single_signature(
    approval: &CouncilSignature,
    digest: &[u8; 32],
    key_map: &std::collections::HashMap<String, Vec<u8>>,
) -> SignatureVerification {
    // Look up public key by member ID
    let pk_bytes = match key_map.get(&approval.member_id) {
        Some(pk) => pk,
        None => {
            return SignatureVerification {
                member_id: approval.member_id.clone(),
                valid: false,
                error: Some(format!("unknown council member: {}", approval.member_id)),
            };
        }
    };

    // Verify public key matches the one in the approval
    let approval_pk = match approval.public_key_bytes() {
        Ok(pk) => pk,
        Err(e) => {
            return SignatureVerification {
                member_id: approval.member_id.clone(),
                valid: false,
                error: Some(format!("invalid public key hex: {}", e)),
            };
        }
    };

    if pk_bytes != &approval_pk {
        return SignatureVerification {
            member_id: approval.member_id.clone(),
            valid: false,
            error: Some("public key mismatch with keyset".to_string()),
        };
    }

    // Decode signature
    let sig_bytes = match approval.signature_bytes() {
        Ok(sig) => sig,
        Err(e) => {
            return SignatureVerification {
                member_id: approval.member_id.clone(),
                valid: false,
                error: Some(format!("invalid signature hex: {}", e)),
            };
        }
    };

    // Verify signature using ML-DSA-44
    match MlDsa44Backend::verify(pk_bytes, digest, &sig_bytes) {
        Ok(()) => SignatureVerification {
            member_id: approval.member_id.clone(),
            valid: true,
            error: None,
        },
        Err(e) => SignatureVerification {
            member_id: approval.member_id.clone(),
            valid: false,
            error: Some(format!("signature verification failed: {:?}", e)),
        },
    }
}

/// Verify an envelope and check that the threshold is met.
///
/// This is a convenience function that returns an error if verification fails.
pub fn verify_envelope_threshold(
    envelope: &UpgradeEnvelope,
    keyset: &CouncilKeySet,
) -> Result<VerificationResult, EnvelopeError> {
    let result = verify_envelope(envelope, keyset)?;

    if !result.is_valid() {
        return Err(EnvelopeError::ThresholdNotMet {
            required: result.threshold,
            actual: result.valid_count,
        });
    }

    Ok(result)
}

/// Sign an envelope with a council member's private key.
///
/// This creates a new `CouncilSignature` that can be added to the envelope.
///
/// # Arguments
///
/// * `envelope` - The envelope to sign
/// * `member_id` - The council member's ID
/// * `public_key` - The member's public key (hex)
/// * `secret_key` - The member's secret key bytes
///
/// # Security Note
///
/// The secret key should be held in secure storage (HSM or encrypted file).
pub fn sign_envelope(
    envelope: &UpgradeEnvelope,
    member_id: &str,
    public_key_hex: &str,
    secret_key: &[u8],
) -> Result<CouncilSignature, EnvelopeError> {
    // Compute envelope digest
    let digest = envelope_digest(envelope)?;

    // Sign with ML-DSA-44
    let signature = MlDsa44Backend::sign(secret_key, &digest)
        .map_err(|e| EnvelopeError::InvalidSignature(format!("signing failed: {:?}", e)))?;

    // Get current timestamp
    let timestamp = chrono_timestamp();

    Ok(CouncilSignature {
        member_id: member_id.to_string(),
        public_key: public_key_hex.to_string(),
        signature: hex::encode(signature),
        timestamp,
    })
}

/// Generate an ISO 8601 timestamp for the current time.
fn chrono_timestamp() -> String {
    // Simple UTC timestamp without external chrono dependency
    // Format: 2026-02-08T12:00:00Z
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Simple formatting (not perfect but sufficient for this use case)
    let seconds_per_day = 86400;
    let seconds_per_hour = 3600;
    let seconds_per_minute = 60;

    let days_since_epoch = now / seconds_per_day;
    let remaining = now % seconds_per_day;
    let hours = remaining / seconds_per_hour;
    let remaining = remaining % seconds_per_hour;
    let minutes = remaining / seconds_per_minute;
    let seconds = remaining % seconds_per_minute;

    // Calculate year/month/day from days since epoch (1970-01-01)
    let (year, month, day) = days_to_ymd(days_since_epoch);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since Unix epoch to year/month/day.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Calculate year/month/day with proper leap year handling
    let mut year = 1970;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }

    (year, month, remaining_days + 1)
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::council::{CouncilKey, CouncilKeySet};
    use crate::envelope::{BinaryHashHex, UpgradeClass, UpgradeEnvelope};
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use std::collections::BTreeMap;

    fn test_envelope() -> UpgradeEnvelope {
        let mut binary_hashes = BTreeMap::new();
        binary_hashes.insert(
            "linux-x86_64".to_string(),
            BinaryHashHex::new("a".repeat(64)),
        );

        UpgradeEnvelope {
            envelope_version: "1.0".to_string(),
            envelope_id: "T225-001".to_string(),
            protocol_version: "0.1.0".to_string(),
            network_environment: "mainnet".to_string(),
            class: UpgradeClass::CHardFork,
            version: "0.1.0".to_string(),
            activation_height: 1000000,
            binary_hashes,
            notes: "Test upgrade".to_string(),
            council_approvals: vec![],
        }
    }

    #[test]
    fn test_sign_and_verify() {
        // Generate keypair
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        let pk_hex = hex::encode(&pk);

        // Create envelope and sign it
        let envelope = test_envelope();
        let signature = sign_envelope(&envelope, "council-1", &pk_hex, &sk).expect("sign");

        // Create keyset with this key
        let key = CouncilKey::new("council-1", pk_hex.clone());
        let keyset = CouncilKeySet::new(1, vec![key]);

        // Add signature to envelope
        let mut signed_envelope = envelope;
        signed_envelope.council_approvals.push(signature);

        // Verify
        let result = verify_envelope(&signed_envelope, &keyset).expect("verify");
        assert!(result.is_valid());
        assert_eq!(result.valid_count, 1);
    }

    #[test]
    fn test_threshold_verification() {
        // Generate 3 keypairs
        let (pk1, sk1) = MlDsa44Backend::generate_keypair().expect("keygen");
        let (pk2, sk2) = MlDsa44Backend::generate_keypair().expect("keygen");
        let (pk3, _sk3) = MlDsa44Backend::generate_keypair().expect("keygen");

        let pk1_hex = hex::encode(&pk1);
        let pk2_hex = hex::encode(&pk2);
        let pk3_hex = hex::encode(&pk3);

        // Create keyset with threshold 2
        let keys = vec![
            CouncilKey::new("c1", pk1_hex.clone()),
            CouncilKey::new("c2", pk2_hex.clone()),
            CouncilKey::new("c3", pk3_hex.clone()),
        ];
        let keyset = CouncilKeySet::new(2, keys);

        // Create envelope
        let envelope = test_envelope();

        // Sign with only 1 key - should not meet threshold
        let sig1 = sign_envelope(&envelope, "c1", &pk1_hex, &sk1).expect("sign");
        let mut envelope_1sig = envelope.clone();
        envelope_1sig.council_approvals.push(sig1.clone());

        let result = verify_envelope(&envelope_1sig, &keyset).expect("verify");
        assert!(!result.is_valid());
        assert_eq!(result.valid_count, 1);
        assert_eq!(result.threshold, 2);

        // Sign with 2 keys - should meet threshold
        let sig2 = sign_envelope(&envelope, "c2", &pk2_hex, &sk2).expect("sign");
        let mut envelope_2sig = envelope.clone();
        envelope_2sig.council_approvals.push(sig1);
        envelope_2sig.council_approvals.push(sig2);

        let result = verify_envelope(&envelope_2sig, &keyset).expect("verify");
        assert!(result.is_valid());
        assert_eq!(result.valid_count, 2);
    }

    #[test]
    fn test_invalid_signature_detection() {
        // Generate keypairs
        let (pk1, _sk1) = MlDsa44Backend::generate_keypair().expect("keygen");
        let (_pk2, sk2) = MlDsa44Backend::generate_keypair().expect("keygen");

        let pk1_hex = hex::encode(&pk1);

        // Create keyset
        let keys = vec![CouncilKey::new("c1", pk1_hex.clone())];
        let keyset = CouncilKeySet::new(1, keys);

        // Create envelope
        let envelope = test_envelope();

        // Sign with wrong secret key (sk2 doesn't match pk1)
        let bad_sig = sign_envelope(&envelope, "c1", &pk1_hex, &sk2).expect("sign");
        let mut envelope_bad = envelope.clone();
        envelope_bad.council_approvals.push(bad_sig);

        let result = verify_envelope(&envelope_bad, &keyset).expect("verify");
        assert!(!result.is_valid());
        assert_eq!(result.valid_count, 0);
        assert_eq!(result.invalid_count(), 1);
    }

    #[test]
    fn test_unknown_member_detection() {
        // Generate keypair
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        let pk_hex = hex::encode(&pk);

        // Create keyset without this member
        let keys = vec![CouncilKey::new("other", "aa".repeat(1312))];
        let keyset = CouncilKeySet::new(1, keys);

        // Create envelope and sign with unknown member
        let envelope = test_envelope();
        let sig = sign_envelope(&envelope, "unknown", &pk_hex, &sk).expect("sign");
        let mut signed_envelope = envelope;
        signed_envelope.council_approvals.push(sig);

        let result = verify_envelope(&signed_envelope, &keyset).expect("verify");
        assert!(!result.is_valid());
        assert_eq!(result.valid_count, 0);

        let invalid = &result.signatures[0];
        assert!(!invalid.valid);
        assert!(invalid.error.as_ref().unwrap().contains("unknown council member"));
    }

    #[test]
    fn test_chrono_timestamp() {
        let ts = chrono_timestamp();
        // Should be in format YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        assert_eq!(ts.len(), 20);
    }

    #[test]
    fn test_verification_result_helpers() {
        let result = VerificationResult {
            valid_count: 3,
            threshold: 5,
            signatures: vec![
                SignatureVerification {
                    member_id: "c1".to_string(),
                    valid: true,
                    error: None,
                },
                SignatureVerification {
                    member_id: "c2".to_string(),
                    valid: true,
                    error: None,
                },
                SignatureVerification {
                    member_id: "c3".to_string(),
                    valid: true,
                    error: None,
                },
                SignatureVerification {
                    member_id: "c4".to_string(),
                    valid: false,
                    error: Some("invalid".to_string()),
                },
            ],
            digest_hex: "abc".to_string(),
        };

        assert!(!result.is_valid()); // 3 < 5
        assert_eq!(result.invalid_count(), 1);
        assert_eq!(result.valid_members(), vec!["c1", "c2", "c3"]);
        assert_eq!(result.invalid_signatures().len(), 1);
    }
}