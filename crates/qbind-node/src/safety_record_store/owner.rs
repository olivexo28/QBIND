//! Run 422 D7-D14 — the O1–O5 operations and the enforced single-writer
//! ownership / expected-revision fencing boundary (§ 13.4 / § 13.5).
//!
//! Every mutating operation takes the one shared serialization domain of the
//! attached [`SafetyBackend`] instance, re-reads the authoritative revision
//! under that lock, fences on the caller's expected revision, and only then
//! performs the checked, atomic, synchronous publication. Validation refusal,
//! write failure, uncertain publication, acknowledged durable success, and
//! in-memory effectiveness are returned as distinct outcomes.

use sha3::{Digest, Sha3_256};

use super::backend::{PublishOutcome, SafetyBackend};
use super::codec::{compute_evidence_lock_binding, decode_record, encode_record};
use super::error::SafetyStoreError;
use super::profile::PinnedSafetyContext;
use super::record::{
    DecodedRecord, EvidenceStatus, LockedRecord, SafetyRecord, SupportingEvidence, ValidatedRecord,
};
use super::validate::{validate_decoded, CommittedHistory};

const META_FORMAT_VERSION: u16 = 1;
const DOMAIN_META: &[u8] = b"QBIND-D7D14-SAFETY-META-v1";

/// Decoded initialization metadata (one per backend DB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyMeta {
    pub meta_format_version: u16,
    /// Digest binding the pinned context used at initialization.
    pub context_digest: [u8; 32],
    /// The authoritative current publication revision.
    pub current_revision: u64,
}

impl SafetyMeta {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 32 + 8);
        out.extend_from_slice(&self.meta_format_version.to_be_bytes());
        out.extend_from_slice(&self.context_digest);
        out.extend_from_slice(&self.current_revision.to_be_bytes());
        out
    }
    fn decode(buf: &[u8]) -> Result<Self, SafetyStoreError> {
        if buf.len() != 2 + 32 + 8 {
            return Err(SafetyStoreError::StructuralRefusal(
                "metadata length".into(),
            ));
        }
        let meta_format_version = u16::from_be_bytes([buf[0], buf[1]]);
        if meta_format_version != META_FORMAT_VERSION {
            return Err(SafetyStoreError::UnsupportedVersion(meta_format_version));
        }
        let mut context_digest = [0u8; 32];
        context_digest.copy_from_slice(&buf[2..34]);
        let mut rev = [0u8; 8];
        rev.copy_from_slice(&buf[34..42]);
        Ok(SafetyMeta {
            meta_format_version,
            context_digest,
            current_revision: u64::from_be_bytes(rev),
        })
    }
}

/// Compute a stable digest of the pinned context (identity fence for open).
pub fn context_digest(ctx: &PinnedSafetyContext) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_META);
    h.update(ctx.network_genesis_id);
    h.update(ctx.authority_context_ref);
    h.update(ctx.chain_id.to_be_bytes());
    h.update(ctx.epoch.to_be_bytes());
    h.update(ctx.qc_suite_id.to_be_bytes());
    h.update([ctx.timeout_suite_id]);
    h.update((ctx.s_sig as u64).to_be_bytes());
    h.update([ctx.require_height_equals_round as u8]);
    h.update((ctx.validators.len() as u64).to_be_bytes());
    for (id, p) in &ctx.validators {
        h.update(id.as_u64().to_be_bytes());
        h.update(p.to_be_bytes());
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// The owner of a safety-record store: one attached handle to a shared
/// [`SafetyBackend`] instance plus the pinned context.
#[derive(Debug, Clone)]
pub struct SafetyRecordOwner {
    backend: SafetyBackend,
    ctx: PinnedSafetyContext,
}

/// The result of O4/O5 publication, distinguishing every outcome class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishResult {
    /// Refused before any write (validation/eligibility/revision). Prior state intact.
    RefusedPreWrite(SafetyStoreError),
    /// The write errored; durable outcome ambiguous — predecessor NOT assumed stored.
    WriteFailedAmbiguous(String),
    /// The write durably succeeded but no success was delivered; a complete
    /// successor may survive. The caller must block dependent use until explicit
    /// recovery re-establishes state.
    UncertainDurable,
    /// Durable success acknowledged; the new restriction is now effective.
    DurableAcknowledged { new_revision: u64 },
}

impl SafetyRecordOwner {
    /// Attach an owner handle to an open backend instance. Every handle attached
    /// to the same backend shares its single serialization domain.
    pub fn attach(
        backend: SafetyBackend,
        ctx: PinnedSafetyContext,
    ) -> Result<Self, SafetyStoreError> {
        ctx.validate()?;
        Ok(SafetyRecordOwner { backend, ctx })
    }

    /// The pinned context.
    pub fn context(&self) -> &PinnedSafetyContext {
        &self.ctx
    }

    /// Whether the shared backend is currently in a recovery-required state
    /// (a prior ambiguous/uncertain publication under any handle has not yet
    /// been cleared by the required successful recovery operation).
    pub fn recovery_required(&self) -> bool {
        self.backend.recovery_required()
    }

    /// Load the established metadata + authoritative record bytes under the
    /// ownership boundary, enforcing the O2/`open` prerequisites that every
    /// public operation depends on: present-and-consistent metadata+record and a
    /// pinned-context digest that matches the stored one. Enforcing these here
    /// (rather than trusting callers to invoke `open` first) prevents a handle
    /// attached under a **foreign** pinned context from reading or publishing
    /// over a store initialized under a different context, and prevents O3/O4/O5
    /// from acting on missing/partial/foreign-context metadata.
    fn load_established(&self) -> Result<(SafetyMeta, Vec<u8>), SafetyStoreError> {
        let meta_bytes = self
            .backend
            .read_meta()?
            .ok_or_else(|| SafetyStoreError::MissingEstablishedState("no metadata".into()))?;
        let record_bytes = self
            .backend
            .read_record()?
            .ok_or_else(|| SafetyStoreError::StructuralRefusal("metadata without record".into()))?;
        let meta = SafetyMeta::decode(&meta_bytes)?;
        if meta.context_digest != context_digest(&self.ctx) {
            return Err(SafetyStoreError::SemanticRefusal(
                "stored context digest does not match this handle's pinned context".into(),
            ));
        }
        Ok((meta, record_bytes))
    }

    /// Source/test-only: overwrite the stored record bytes out-of-band to
    /// simulate a surviving divergent publication (used to exercise O5's
    /// byte-for-byte refusal). Never called by production. Gated behind
    /// `test-utils` so it is not a production-reachable escape.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn debug_overwrite_record_for_test(
        &self,
        record_bytes: &[u8],
    ) -> Result<(), SafetyStoreError> {
        let _guard = self.backend.lock_domain();
        self.backend.debug_overwrite_record(record_bytes)
    }

    // -----------------------------------------------------------------------
    // O1 — initialize
    // -----------------------------------------------------------------------

    /// **O1**: explicit first-use initialization. Requires the independent
    /// `first_use_intent` assertion and a genuinely unused backend (no metadata,
    /// no record). Refuses established / partial / malformed state. An empty
    /// directory alone does not authorize initialization. Writes initialization
    /// metadata and a `BootstrapNoLock` record atomically at revision 0.
    pub fn initialize(&self, first_use_intent: bool) -> Result<u64, SafetyStoreError> {
        if !first_use_intent {
            return Err(SafetyStoreError::MissingIndependentInput(
                "O1 requires an explicit first-use intent assertion".into(),
            ));
        }
        let guard = self.backend.lock_domain();
        let meta = self.backend.read_meta()?;
        let record = self.backend.read_record()?;
        match (meta.is_some(), record.is_some()) {
            (true, _) => {
                return Err(SafetyStoreError::AlreadyEstablished(
                    "metadata already present".into(),
                ))
            }
            (false, true) => {
                return Err(SafetyStoreError::StructuralRefusal(
                    "record present without metadata (partial/malformed safety state)".into(),
                ))
            }
            (false, false) => {}
        }

        let decoded = DecodedRecord {
            persistence_format_version: super::profile::SAFETY_PERSISTENCE_FORMAT_VERSION,
            network_genesis_id: self.ctx.network_genesis_id,
            publication_revision: 0,
            record: SafetyRecord::BootstrapNoLock {
                authority_context_ref: self.ctx.authority_context_ref,
                predecessor_ref: None,
            },
        };
        let encoded = encode_record(&decoded, &self.ctx)?;
        let meta = SafetyMeta {
            meta_format_version: META_FORMAT_VERSION,
            context_digest: context_digest(&self.ctx),
            current_revision: 0,
        };
        match self
            .backend
            .publish_atomic(&guard, &meta.encode(), &encoded)
        {
            PublishOutcome::DurableAcknowledged => Ok(0),
            PublishOutcome::PreWriteRefused(m) => Err(SafetyStoreError::WriteFailed(m)),
            PublishOutcome::WriteError(m) => Err(SafetyStoreError::WriteFailed(m)),
            PublishOutcome::UncertainDurable => Err(SafetyStoreError::UncertainPublication(
                "O1 metadata+bootstrap publish outcome uncertain".into(),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // O2 — open
    // -----------------------------------------------------------------------

    /// **O2**: open established state without auto-initialization, migration,
    /// repair, or any safety-state write. Requires consistent metadata + record
    /// and a matching pinned-context digest.
    pub fn open(&self) -> Result<SafetyMeta, SafetyStoreError> {
        let _guard = self.backend.lock_domain();
        let (meta, record_bytes) = self.load_established()?;
        // Structural decode to confirm the record is well-formed and revisions agree.
        let decoded = decode_record(&record_bytes, &self.ctx)?;
        if decoded.publication_revision != meta.current_revision {
            return Err(SafetyStoreError::SemanticRefusal(
                "record revision disagrees with metadata revision".into(),
            ));
        }
        Ok(meta)
    }

    // -----------------------------------------------------------------------
    // O3 — read / validate
    // -----------------------------------------------------------------------

    /// **O3**: read and validate without writing. Returns the validated record,
    /// its explicit (always `Unverified`) evidence status, and the retained
    /// original encoded publication bytes needed by O5.
    pub fn read_validate<H: CommittedHistory + ?Sized>(
        &self,
        history: Option<&H>,
    ) -> Result<ValidatedRecord, SafetyStoreError> {
        let _guard = self.backend.lock_domain();
        // Enforce the established-state + pinned-context prerequisites (do not
        // rely on the caller having invoked `open`). Reject missing/partial or
        // foreign-context metadata before validating the record.
        let (meta, record_bytes) = self.load_established()?;
        let decoded = decode_record(&record_bytes, &self.ctx)?;
        if decoded.publication_revision != meta.current_revision {
            return Err(SafetyStoreError::SemanticRefusal(
                "record revision disagrees with metadata revision".into(),
            ));
        }
        validate_decoded(decoded, record_bytes, &self.ctx, history)
    }

    // -----------------------------------------------------------------------
    // O4 — publish a new restriction
    // -----------------------------------------------------------------------

    /// **O4**: validate a candidate `Locked` transition, fence on the expected
    /// revision, use a checked revision increment, and publish atomically and
    /// synchronously. The new restriction becomes effective only after an
    /// acknowledged durable success.
    pub fn publish_locked<H: CommittedHistory + ?Sized>(
        &self,
        candidate: LockedRecord,
        expected_revision: u64,
        history: Option<&H>,
    ) -> PublishResult {
        let guard = self.backend.lock_domain();

        // A prior ambiguous/uncertain publication under any handle blocks further
        // dependent publication until the required successful recovery operation
        // (O5) clears it. Refuse before any read/write.
        if self.backend.recovery_required() {
            return PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(
                "a prior ambiguous/uncertain publication requires recovery before O4".into(),
            ));
        }

        // Re-read authoritative state under the ownership boundary, enforcing the
        // established-state + pinned-context prerequisites (foreign-context or
        // missing/partial metadata is refused before any write).
        let (meta, current_bytes) = match self.load_established() {
            Ok(pair) => pair,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        // Expected-revision fence.
        if meta.current_revision != expected_revision {
            return PublishResult::RefusedPreWrite(SafetyStoreError::StaleRevision {
                expected: expected_revision,
                stored: meta.current_revision,
            });
        }
        let current = match decode_record(&current_bytes, &self.ctx) {
            Ok(d) => d,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        // Transition eligibility: strictly-increasing lock view.
        if let SafetyRecord::Locked(cur) = &current.record {
            if candidate.lock_view <= cur.lock_view {
                return PublishResult::RefusedPreWrite(SafetyStoreError::TransitionIneligible(
                    format!(
                        "candidate lock_view {} not strictly greater than current {}",
                        candidate.lock_view, cur.lock_view
                    ),
                ));
            }
        }

        // Recompute the evidence binding so the stored record is self-consistent,
        // then validate the full candidate semantics before writing.
        let binding = match compute_evidence_lock_binding(
            &candidate.lock_block_id,
            candidate.lock_view,
            &candidate.evidence,
            &candidate.authority_context_ref,
        ) {
            Ok(b) => b,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let mut candidate = candidate;
        candidate.evidence_lock_binding = binding;

        // Checked revision increment.
        let new_revision = match meta.current_revision.checked_add(1) {
            Some(v) => v,
            None => {
                return PublishResult::RefusedPreWrite(SafetyStoreError::ArithmeticOverflow(
                    "publication revision exhausted".into(),
                ))
            }
        };

        let decoded = DecodedRecord {
            persistence_format_version: super::profile::SAFETY_PERSISTENCE_FORMAT_VERSION,
            network_genesis_id: self.ctx.network_genesis_id,
            publication_revision: new_revision,
            record: SafetyRecord::Locked(candidate),
        };
        // Full semantic validation of the candidate before any write.
        let encoded = match encode_record(&decoded, &self.ctx) {
            Ok(b) => b,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        if let Err(e) = validate_decoded(decoded.clone(), encoded.clone(), &self.ctx, history) {
            return PublishResult::RefusedPreWrite(e);
        }

        let new_meta = SafetyMeta {
            meta_format_version: META_FORMAT_VERSION,
            context_digest: meta.context_digest,
            current_revision: new_revision,
        };
        match self
            .backend
            .publish_atomic(&guard, &new_meta.encode(), &encoded)
        {
            PublishOutcome::DurableAcknowledged => {
                PublishResult::DurableAcknowledged { new_revision }
            }
            PublishOutcome::PreWriteRefused(m) => {
                PublishResult::RefusedPreWrite(SafetyStoreError::WriteFailed(m))
            }
            PublishOutcome::WriteError(m) => PublishResult::WriteFailedAmbiguous(m),
            PublishOutcome::UncertainDurable => PublishResult::UncertainDurable,
        }
    }

    // -----------------------------------------------------------------------
    // O5 — re-acknowledge
    // -----------------------------------------------------------------------

    /// **O5**: compare the retained original validated publication (`ENC_INPUT`)
    /// against a fresh read of the currently stored publication, **byte for
    /// byte**, under the owner/revision boundary. On complete equality,
    /// republish the original bytes verbatim and require a fresh durability
    /// acknowledgement. A stale O5 (stored state no longer equals the retained
    /// original) refuses without overwriting newer state.
    pub fn reacknowledge(&self, retained: &ValidatedRecord) -> PublishResult {
        let guard = self.backend.lock_domain();

        // O5 is the recovery operation; it is permitted to run while the shared
        // recovery requirement is set, and a successful fresh acknowledgement is
        // what clears it. Enforce the established-state + pinned-context
        // prerequisites first (foreign-context metadata is refused).
        let (meta, stored) = match self.load_established() {
            Ok(pair) => pair,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        // Complete byte-for-byte equality — NOT a digest, NOT a re-encode, NOT a
        // normalization. Divergence anywhere (even outside the binding digest's
        // coverage) refuses.
        if stored.as_slice() != retained.encoded.as_slice() {
            return PublishResult::RefusedPreWrite(SafetyStoreError::PublicationMismatch(
                "stored publication differs from retained original (byte-for-byte)".into(),
            ));
        }
        // The retained revision must also still be the authoritative revision.
        if retained.decoded.publication_revision != meta.current_revision {
            return PublishResult::RefusedPreWrite(SafetyStoreError::StaleRevision {
                expected: retained.decoded.publication_revision,
                stored: meta.current_revision,
            });
        }

        // Republish the ORIGINAL bytes verbatim; metadata revision is unchanged.
        match self
            .backend
            .publish_atomic(&guard, &meta.encode(), &retained.encoded)
        {
            PublishOutcome::DurableAcknowledged => {
                // The required successful recovery durability operation clears the
                // shared recovery requirement for every handle.
                self.backend.clear_recovery_requirement();
                PublishResult::DurableAcknowledged {
                    new_revision: meta.current_revision,
                }
            }
            PublishOutcome::PreWriteRefused(m) => {
                PublishResult::RefusedPreWrite(SafetyStoreError::WriteFailed(m))
            }
            PublishOutcome::WriteError(m) => PublishResult::WriteFailedAmbiguous(m),
            PublishOutcome::UncertainDurable => PublishResult::UncertainDurable,
        }
    }
}

/// Build a `BootstrapNoLock` validated record view (used by callers/tests that
/// need the explicit bootstrap variant with the always-`Unverified` status).
pub fn bootstrap_validated(
    ctx: &PinnedSafetyContext,
    revision: u64,
) -> Result<ValidatedRecord, SafetyStoreError> {
    let decoded = DecodedRecord {
        persistence_format_version: super::profile::SAFETY_PERSISTENCE_FORMAT_VERSION,
        network_genesis_id: ctx.network_genesis_id,
        publication_revision: revision,
        record: SafetyRecord::BootstrapNoLock {
            authority_context_ref: ctx.authority_context_ref,
            predecessor_ref: None,
        },
    };
    let encoded = encode_record(&decoded, ctx)?;
    Ok(ValidatedRecord {
        decoded,
        evidence_status: EvidenceStatus::Unverified,
        encoded,
    })
}

/// Helper to construct a QC-derived locked record for callers/tests, with the
/// binding digest computed consistently.
pub fn make_locked_qc(
    ctx: &PinnedSafetyContext,
    lock_block_id: [u8; 32],
    lock_view: u64,
    qc: super::record::WireQc,
    committed_anchor: Option<super::record::CommittedAnchor>,
) -> Result<LockedRecord, SafetyStoreError> {
    let evidence = SupportingEvidence::QcDerived(qc);
    let binding = compute_evidence_lock_binding(
        &lock_block_id,
        lock_view,
        &evidence,
        &ctx.authority_context_ref,
    )?;
    Ok(LockedRecord {
        lock_block_id,
        lock_view,
        evidence_lock_binding: binding,
        authority_context_ref: ctx.authority_context_ref,
        committed_anchor,
        predecessor_ref: None,
        evidence,
    })
}