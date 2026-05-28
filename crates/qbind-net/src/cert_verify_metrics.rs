//! Cert-verify metrics sink trait (Run 044).
//!
//! This module defines a tiny observability-only callback surface that the
//! KEMTLS handshake engine calls at the *existing* PQC delegation-cert
//! verification success/failure boundaries inside
//! [`crate::handshake::parse_and_verify_client_cert`] (listener side) and
//! the cert-verification region of
//! [`crate::handshake::ClientHandshake::handle_server_accept`] (dialer
//! side).
//!
//! # Why a trait in `qbind-net` instead of importing `P2pMetrics`
//!
//! `P2pMetrics` lives in `qbind-node`. The crate layering forbids
//! `qbind-net → qbind-node`. So the smallest safe shape is a tiny trait
//! defined here that `qbind-node` implements for `P2pMetrics` and plumbs
//! through the handshake configs as an `Option<Arc<dyn ...>>`.
//!
//! # Behavioural guarantees
//!
//! - All methods default to a no-op, so test impls only override the
//!   ones they care about.
//! - The sink is *only* invoked at existing success/failure boundaries.
//! - The sink does **not** influence verification result. Verification
//!   logic returns the same `NetError` variants whether a sink is
//!   configured or not. A missing sink (`None`) is a zero-cost path.
//! - Counters are bumped *exactly once per cert verification event*:
//!   the success boundary bumps `inc_accepted` exactly once after all
//!   checks pass; each failure boundary bumps exactly one per-reason
//!   counter exactly once, before the error returns.
//! - The `qbind-node` `P2pMetrics` adapter then internally also bumps
//!   the aggregate `pqc_cert_verify_rejected_total` counter via the
//!   existing Run 037 contract (the per-reason `inc_*` setters bump
//!   the aggregate too).
//!
//! # Reason mapping (Run 044 + Run 045)
//!
//! | Failure boundary                                                  | Reason method                |
//! |-------------------------------------------------------------------|------------------------------|
//! | `NetworkDelegationCert::decode` fails                              | `inc_rejected_malformed`     |
//! | `trusted_client_roots.lookup` returns `None`                       | `inc_rejected_unknown_root`  |
//! | `verify_delegation_cert` returns `NetError::UnsupportedSuite(_)`   | `inc_rejected_wrong_suite`   |
//! | `verify_delegation_cert` returns `NetError::KeySchedule("signature verify error")` | `inc_rejected_bad_signature` |
//! | `verify_delegation_cert` returns `NetError::ClientCertInvalid("cert expired" \| "cert not yet valid" \| "cert invalid validity window")` (Run 045) | `inc_rejected_expired` |
//! | dialer-side `delegation_cert.validator_id != client_init.validator_id` | `inc_rejected_validator_mismatch` |
//! | leaf-cert fingerprint is on the active leaf-revocation list (Run 052) — `NetError::ClientCertInvalid("cert revoked")` | `inc_rejected_revoked` |
//!
//! Run 045: `inc_rejected_expired` is now wired at the live boundary —
//! [`crate::handshake::verify_delegation_cert`] enforces `not_before` /
//! `not_after` (inclusive on both ends) against the current wall-clock
//! (Unix seconds), AFTER signature verification, so a tampered
//! validity field surfaces as bad-signature rather than as expired.
//! Wall-clock here is strictly a transport-layer freshness check; it
//! is NOT a consensus time source. For deterministic tests, see
//! [`crate::handshake::verify_delegation_cert_at`].

use std::sync::Arc;

/// Observability-only sink for PQC delegation-cert verification events.
///
/// Implementations must be cheap and non-blocking; they are called on the
/// hot handshake path. All methods default to a no-op so impls only need
/// to override the ones they care about.
pub trait CertVerifyMetricsSink: Send + Sync {
    /// Called exactly once after a delegation cert has passed *all*
    /// verification checks at this boundary (parse, root lookup,
    /// signature, validator-id where applicable).
    fn inc_accepted(&self) {}

    /// Called exactly once when verification rejected the cert because
    /// the cert's `root_key_id` is not in the configured trust set.
    fn inc_rejected_unknown_root(&self) {}

    /// Called exactly once when verification rejected the cert because
    /// the cert's signature suite is not registered in the crypto
    /// provider.
    fn inc_rejected_wrong_suite(&self) {}

    /// Called exactly once when verification rejected the cert because
    /// signature verification under the configured root pk failed.
    fn inc_rejected_bad_signature(&self) {}

    /// Called exactly once (dialer side) when the cert's `validator_id`
    /// field did not match the expected `ClientInit.validator_id`.
    fn inc_rejected_validator_mismatch(&self) {}

    /// Called exactly once when the cert bytes failed to parse.
    fn inc_rejected_malformed(&self) {}

    /// Called exactly once when the cert is outside its validity window
    /// (Run 045): cert expired, not yet valid, or has an inverted
    /// (`not_before > not_after`) window. The handshake engine maps
    /// `NetError::ClientCertInvalid("cert expired" | "cert not yet valid" |
    /// "cert invalid validity window")` returned by
    /// [`crate::handshake::verify_delegation_cert`] onto this method.
    fn inc_rejected_expired(&self) {}

    /// Called exactly once (Run 052) when the cert otherwise verified
    /// (parse + root lookup + signature + validity window + (dialer)
    /// validator-id all passed) but its canonical leaf fingerprint
    /// is on the active leaf-cert revocation list configured on the
    /// handshake config (see
    /// [`crate::handshake::LeafCertRevocationList`]). The handshake
    /// engine returns `NetError::ClientCertInvalid("cert revoked")`
    /// for this case.
    fn inc_rejected_revoked(&self) {}
}

/// Convenience alias for an optional shared sink.
pub type CertVerifyMetricsSinkRef = Option<Arc<dyn CertVerifyMetricsSink>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Test-only sink that counts each invocation.
    #[derive(Default)]
    struct CountingSink {
        accepted: AtomicU64,
        unknown_root: AtomicU64,
        wrong_suite: AtomicU64,
        bad_signature: AtomicU64,
        validator_mismatch: AtomicU64,
        malformed: AtomicU64,
        expired: AtomicU64,
        revoked: AtomicU64,
    }

    impl CertVerifyMetricsSink for CountingSink {
        fn inc_accepted(&self) {
            self.accepted.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_rejected_unknown_root(&self) {
            self.unknown_root.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_rejected_wrong_suite(&self) {
            self.wrong_suite.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_rejected_bad_signature(&self) {
            self.bad_signature.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_rejected_validator_mismatch(&self) {
            self.validator_mismatch.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_rejected_malformed(&self) {
            self.malformed.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_rejected_expired(&self) {
            self.expired.fetch_add(1, Ordering::Relaxed);
        }
        fn inc_rejected_revoked(&self) {
            self.revoked.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn default_trait_methods_are_no_ops() {
        struct NoopSink;
        impl CertVerifyMetricsSink for NoopSink {}
        let s: Arc<dyn CertVerifyMetricsSink> = Arc::new(NoopSink);
        // Should not panic and should have no observable side-effects.
        s.inc_accepted();
        s.inc_rejected_unknown_root();
        s.inc_rejected_wrong_suite();
        s.inc_rejected_bad_signature();
        s.inc_rejected_validator_mismatch();
        s.inc_rejected_malformed();
        s.inc_rejected_expired();
        s.inc_rejected_revoked();
    }

    #[test]
    fn counting_sink_records_each_method() {
        let s = Arc::new(CountingSink::default());
        let dyn_sink: Arc<dyn CertVerifyMetricsSink> = s.clone();
        dyn_sink.inc_accepted();
        dyn_sink.inc_accepted();
        dyn_sink.inc_rejected_unknown_root();
        dyn_sink.inc_rejected_wrong_suite();
        dyn_sink.inc_rejected_bad_signature();
        dyn_sink.inc_rejected_validator_mismatch();
        dyn_sink.inc_rejected_malformed();
        dyn_sink.inc_rejected_expired();
        dyn_sink.inc_rejected_revoked();

        assert_eq!(s.accepted.load(Ordering::Relaxed), 2);
        assert_eq!(s.unknown_root.load(Ordering::Relaxed), 1);
        assert_eq!(s.wrong_suite.load(Ordering::Relaxed), 1);
        assert_eq!(s.bad_signature.load(Ordering::Relaxed), 1);
        assert_eq!(s.validator_mismatch.load(Ordering::Relaxed), 1);
        assert_eq!(s.malformed.load(Ordering::Relaxed), 1);
        assert_eq!(s.expired.load(Ordering::Relaxed), 1);
        assert_eq!(s.revoked.load(Ordering::Relaxed), 1);
    }
}
