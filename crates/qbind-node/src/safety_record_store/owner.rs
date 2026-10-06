//! Run 422 D7-D14 — the O1–O5 operations and the enforced single-writer
//! ownership / expected-revision fencing boundary (§ 13.4 / § 13.5).
//!
//! Every mutating operation takes the one shared serialization domain of the
//! attached [`SafetyBackend`] instance, re-reads the authoritative revision
//! under that lock, fences on the caller's expected revision, and only then
//! performs the checked, atomic, synchronous publication. Validation refusal,
//! write failure, uncertain publication, acknowledged durable success, and
//! in-memory effectiveness are returned as distinct outcomes.

use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use super::backend::{PublishOutcome, SafetyBackend};
use super::codec::{compute_evidence_lock_binding, decode_record, encode_record};
use super::error::SafetyStoreError;
use super::profile::{max_retained_generation_bytes, max_safety_record_bytes, PinnedSafetyContext};
use super::record::{
    size_of_timeout_msg, DecodedRecord, EvidenceStatus, LockedRecord, SafetyRecord,
    SupportingEvidence, ValidatedRecord,
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
///
/// The pinned [`PinnedSafetyContext`] (which owns a validator vector) is held
/// behind an [`Arc`] so that cloning an owner handle shares the single immutable
/// context allocation rather than copying the validator vector into an
/// unaccounted second buffer (§ 13.7B). Every clone observes the same backend
/// serialization domain and the same shared accountant; attaching or cloning a
/// handle therefore cannot mint an uncharged per-handle context copy.
#[derive(Debug, Clone)]
pub struct SafetyRecordOwner {
    backend: SafetyBackend,
    ctx: Arc<PinnedSafetyContext>,
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
        // Bind the shared aggregate accounting ceiling for this store's pinned
        // context (§ 13.7 / § 13.7B). The first handle establishes it; every
        // later handle on the same backend shares it and a divergent (foreign)
        // context ceiling is refused rather than silently widening the budget.
        // The validation re-encode scratch (one record-sized buffer) is included
        // in the aggregate so the complete-content comparison does not add an
        // uncharged record-sized buffer.
        let validation_scratch = max_safety_record_bytes(&ctx)?;
        backend.accounting().bind(&ctx, validation_scratch)?;
        Ok(SafetyRecordOwner {
            backend,
            ctx: Arc::new(ctx),
        })
    }

    /// The conservative retained-holder charge for a single O3-minted proof: the
    /// retained record-sized `encoded` buffer plus one decoded-generation bound
    /// (§ 13.7A / § 13.7B). Charged against the shared aggregate accountant for
    /// the lifetime of the returned proof.
    fn retained_holder_charge(&self) -> Result<u128, SafetyStoreError> {
        let rec = max_safety_record_bytes(&self.ctx)?;
        let gen = max_retained_generation_bytes(&self.ctx, size_of_timeout_msg())?;
        rec.checked_add(gen)
            .ok_or_else(|| SafetyStoreError::ArithmeticOverflow("retained holder charge".into()))
    }

    /// The pinned context.
    pub fn context(&self) -> &PinnedSafetyContext {
        self.ctx.as_ref()
    }

    /// Source/test-only: the shared backend handle, so accounting regressions can
    /// observe the real shared accountant (peak / current / cap) this owner's
    /// operations reserve against. Gated behind `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn backend_for_test(&self) -> &SafetyBackend {
        &self.backend
    }

    /// Source/test-only: the identity (allocation address) of this handle's shared
    /// pinned context. Two owner handles that share the one immutable
    /// `Arc<PinnedSafetyContext>` return the **same** pointer; a by-value context
    /// copy (the escape this closes) would return distinct pointers. Used by the
    /// owner-clone context-sharing regression. Gated behind `test-utils`.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn context_ptr_for_test(&self) -> *const PinnedSafetyContext {
        Arc::as_ptr(&self.ctx)
    }

    /// Whether the shared backend is currently in a recovery-required state
    /// (a prior ambiguous/uncertain publication under any handle has not yet
    /// been cleared by the required successful recovery operation).
    pub fn recovery_required(&self) -> bool {
        self.backend.recovery_required()
    }

    /// Load and establish the authoritative state under the ownership boundary,
    /// enforcing **every** prerequisite a dependent operation relies on (§ 13.4
    /// O2/O3 / § 13.5), rather than trusting callers to invoke `open` first:
    ///
    /// * metadata and record **presence** and valid **structure** (bounded decode);
    /// * **record revision equals metadata revision** (established here, not left
    ///   to each caller);
    /// * **pinned-context correspondence** (stored context digest matches this
    ///   handle's pinned context) — a foreign-context handle is refused.
    ///
    /// This is the single place the metadata↔record consistency is established;
    /// O3/O4/O5 consume the returned decoded predecessor and never re-derive a
    /// weaker check. Semantic association (P1–P4 / TA1–TA8) and committed-history
    /// membership remain the caller's explicit stage-3 step (O3), kept distinct
    /// from this structural establishment (O2).
    fn load_established(&self) -> Result<(SafetyMeta, Vec<u8>, DecodedRecord), SafetyStoreError> {
        let meta_bytes = self
            .backend
            .read_meta(super::backend::META_ENCODED_LEN)?
            .ok_or_else(|| SafetyStoreError::MissingEstablishedState("no metadata".into()))?;
        let record_bytes = self
            .backend
            .read_record(super::profile::max_safety_record_bytes(&self.ctx)?)?
            .ok_or_else(|| SafetyStoreError::StructuralRefusal("metadata without record".into()))?;
        let meta = SafetyMeta::decode(&meta_bytes)?;
        if meta.context_digest != context_digest(&self.ctx) {
            return Err(SafetyStoreError::SemanticRefusal(
                "stored context digest does not match this handle's pinned context".into(),
            ));
        }
        // Structural decode (bounds-checked) and metadata↔record revision
        // consistency are established here, once, for every dependent operation.
        let decoded = decode_record(&record_bytes, &self.ctx)?;
        if decoded.publication_revision != meta.current_revision {
            return Err(SafetyStoreError::SemanticRefusal(
                "record revision disagrees with metadata revision".into(),
            ));
        }
        Ok((meta, record_bytes, decoded))
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
        let meta = self.backend.read_meta(super::backend::META_ENCODED_LEN)?;
        let record = self
            .backend
            .read_record(super::profile::max_safety_record_bytes(&self.ctx)?)?;
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

        // Bounded namespace classification (§ 13.3A): distinguish a genuinely
        // unused safety namespace from established / partial / malformed / legacy
        // / unknown safety state. Any key in the component-owned `safetyrec:`
        // namespace other than the two recognized current-format keys causes the
        // contract-prescribed refusal — with NO migration, deletion, repair, or
        // initialization over it.
        if let Some(unknown_len) = self.backend.first_unrecognized_safety_key()? {
            return Err(SafetyStoreError::StructuralRefusal(format!(
                "unknown/legacy safety-namespace key present ({unknown_len} bytes); refusing O1 \
                 without migration or repair",
            )));
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
        // Reserve the bootstrap publication buffer against the shared aggregate
        // accountant BEFORE encoding it (§ 13.7: reservations precede the
        // protected allocation). The reservation releases on every exit (success,
        // refusal, error, uncertainty) via its drop at end of scope.
        let _pub_res = self
            .backend
            .accounting()
            .reserve(max_safety_record_bytes(&self.ctx)?)?;
        let encoded = encode_record(&decoded, &self.ctx)?;
        debug_assert!(
            encoded.capacity() as u128 <= _pub_res.charge(),
            "O1 bootstrap encoding exceeded its reserved charge"
        );
        let meta = SafetyMeta {
            meta_format_version: META_FORMAT_VERSION,
            context_digest: context_digest(&self.ctx),
            current_revision: 0,
        };
        match self
            .backend
            .publish_atomic(&guard, &meta.encode(), &encoded)
        {
            PublishOutcome::DurableAcknowledged => {
                // An acknowledged explicit O1 initialization establishes fresh
                // bootstrap effectiveness through its permitted path.
                self.backend.mark_effective();
                Ok(0)
            }
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
    /// (structure + revision) and a matching pinned-context digest. Opening does
    /// **not** make the surviving state effective: dependent O4 remains blocked
    /// until a successful O5 (or an acknowledged O1), so a reopen cannot bypass
    /// the recovery requirement.
    pub fn open(&self) -> Result<SafetyMeta, SafetyStoreError> {
        let _guard = self.backend.lock_domain();
        let (meta, _record_bytes, _decoded) = self.load_established()?;
        Ok(meta)
    }

    // -----------------------------------------------------------------------
    // O3 — read / validate
    // -----------------------------------------------------------------------

    /// **O3**: read and validate without writing. Returns the validated record,
    /// its explicit (always `Unverified`) evidence status, and the retained
    /// original encoded publication bytes needed by O5. Inspecting/validating
    /// surviving state here does **not** make it effective.
    pub fn read_validate<H: CommittedHistory + ?Sized>(
        &self,
        history: Option<&H>,
    ) -> Result<ValidatedRecord, SafetyStoreError> {
        let _guard = self.backend.lock_domain();
        // Reserve this proof's retained-holder charge (the retained `encoded`
        // buffer + its decoded generation) BEFORE `load_established` copies the
        // stored payload into a component-owned buffer, plus a transient
        // validation re-encode scratch (§ 13.7: reservations precede the
        // allocation/copy). The holder reservation is moved into the returned
        // proof and lives for its lifetime; the scratch releases at O3 return.
        let holder_res = self
            .backend
            .accounting()
            .reserve(self.retained_holder_charge()?)?;
        let _scratch_res = self
            .backend
            .accounting()
            .reserve(max_safety_record_bytes(&self.ctx)?)?;
        // Enforce the established-state + pinned-context + revision-consistency
        // prerequisites centrally (do not rely on the caller having invoked
        // `open`). Reject missing/partial, foreign-context, or revision-
        // inconsistent metadata before validating the record.
        let (_meta, record_bytes, decoded) = self.load_established()?;
        // Semantic/codec validation produces a proof WITHOUT an O5 capability;
        // O3 on this established backend then grants the backend-bound recovery
        // capability, stamped with THIS backend's ownership incarnation. Only a
        // successful O3 on an established backend mints an O5-usable token — the
        // public `validate_decoded` and the bootstrap builder never do.
        let validated = validate_decoded(decoded, record_bytes, &self.ctx, history)?;
        Ok(validated
            .with_holder(holder_res)
            .grant_recovery_capability(self.backend.incarnation()))
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

        // A fresh durability acknowledgement is required before dependent
        // publication: a newly opened established store (no inherited
        // acknowledgement knowledge) or a prior ambiguous/uncertain publication
        // blocks further O4 until a successful recovery operation (O5) — or an
        // acknowledged O1 — re-establishes effectiveness. Refuse before any
        // read/write. Reopening does not bypass this.
        if self.backend.recovery_required() {
            return PublishResult::RefusedPreWrite(SafetyStoreError::RecoveryRequired(
                "a fresh durability acknowledgement (O5/O1) is required before O4".into(),
            ));
        }

        // Reserve the O4 working-set peak against the shared aggregate accountant
        // BEFORE any O4 allocation/copy (§ 13.7 / § 13.7B). It bounds the
        // simultaneous coexistence of: the validated authoritative predecessor
        // (one decoded generation) and the admitted candidate (one decoded
        // generation) — two generations — plus the three record-sized buffers
        // that peak together across the operation (the predecessor read-back, the
        // candidate publication buffer, and the validation re-encode scratch).
        // A capacity refusal here is a pre-write refusal that leaves the
        // established evidence and any admitted retained holders untouched; the
        // reservation releases on every exit (refusal, error, uncertainty,
        // success) via its drop at end of scope.
        let gen = match max_retained_generation_bytes(&self.ctx, size_of_timeout_msg()) {
            Ok(v) => v,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let rec = match max_safety_record_bytes(&self.ctx) {
            Ok(v) => v,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        let o4_charge = gen
            .checked_mul(2)
            .and_then(|g| rec.checked_mul(3).and_then(|r| g.checked_add(r)));
        let o4_charge = match o4_charge {
            Some(v) => v,
            None => {
                return PublishResult::RefusedPreWrite(SafetyStoreError::ArithmeticOverflow(
                    "O4 working-set charge".into(),
                ))
            }
        };
        let _o4_res = match self.backend.accounting().reserve(o4_charge) {
            Ok(r) => r,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        // Re-read and establish authoritative state under the ownership boundary:
        // presence, structure, metadata↔record revision consistency, and
        // pinned-context correspondence are all enforced centrally.
        let (meta, _current_bytes, current) = match self.load_established() {
            Ok(triple) => triple,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };
        // Expected-revision fence.
        if meta.current_revision != expected_revision {
            return PublishResult::RefusedPreWrite(SafetyStoreError::StaleRevision {
                expected: expected_revision,
                stored: meta.current_revision,
            });
        }

        // Validate the authoritative PREDECESSOR itself (structural + semantic)
        // before relying on it as the eligibility base; O4 must not act on an
        // unvalidated predecessor. The candidate is validated separately below.
        if let Err(e) = validate_decoded(current.clone(), _current_bytes, &self.ctx, history) {
            return PublishResult::RefusedPreWrite(e);
        }

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

        // Structural admission of the candidate evidence BEFORE any component-owned
        // variable-size allocation or copy (§ 13.2A / § 13.7): the evidence-binding
        // `cert` scratch in `compute_evidence_lock_binding`, the candidate clone, and
        // `encode_record`'s buffer all follow. Refuse an over-bound count/length/width
        // (e.g. `S_sig=8` with a 9-byte signature) here, before allocating the binding
        // buffer — not after encoding.
        if let Err(e) = super::codec::admit_supporting_evidence(&candidate.evidence, &self.ctx) {
            return PublishResult::RefusedPreWrite(e);
        }

        // Recompute the evidence binding so the stored record is self-consistent,
        // then validate the full candidate semantics before writing.
        let binding = match compute_evidence_lock_binding(
            &candidate.lock_block_id,
            candidate.lock_view,
            &candidate.evidence,
            &candidate.authority_context_ref,
            &self.ctx,
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
                // An acknowledged O4 durable success keeps the shared state
                // effective for subsequent eligible transitions.
                self.backend.mark_effective();
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

        // Reserve the O5 stored read-back buffer against the shared aggregate
        // accountant BEFORE `load_established` copies the stored payload into a
        // component-owned buffer (§ 13.7: reservations precede the copy). The
        // retained operand is already charged by the holder reservation carried
        // in `retained`, so O5 does not add an uncharged fourth record-sized
        // buffer; this single read-back reservation plus the pre-charged retained
        // holder bound the O5 complete-content comparison. Releases on every exit
        // via drop at end of scope.
        let _o5_res = match self.backend.accounting().reserve(
            match max_safety_record_bytes(&self.ctx) {
                Ok(v) => v,
                Err(e) => return PublishResult::RefusedPreWrite(e),
            },
        ) {
            Ok(r) => r,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        // O5 is the recovery operation; it is permitted to run while the shared
        // recovery requirement is set, and a successful fresh acknowledgement is
        // what clears it. Enforce the established-state + pinned-context
        // prerequisites first (foreign-context metadata is refused).
        let (meta, stored, _stored_decoded) = match self.load_established() {
            Ok(triple) => triple,
            Err(e) => return PublishResult::RefusedPreWrite(e),
        };

        // The retained proof must have been sealed under THIS handle's pinned
        // context; a proof produced under a foreign context cannot authorize a
        // re-publication here.
        if retained.origin_context_digest() != &context_digest(&self.ctx) {
            return PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(
                "retained publication was validated under a different pinned context".into(),
            ));
        }

        // The retained proof must carry an O5 recovery capability bound to THIS
        // backend's ownership incarnation (§ 13.4 / § 13.5). Identical pinned
        // contexts are shared by different stores, so the context digest alone is
        // NOT backend identity. A token minted by O3 on a DIFFERENT backend
        // instance (another store, or a reopened incarnation of the same DB) is
        // refused even when context, revision, and publication bytes are
        // identical; a semantic/codec-only proof (public `validate_decoded`) or a
        // bootstrap-builder proof carries no capability and is refused here. Only
        // a fresh O3 on this exact backend incarnation yields an O5-usable token.
        match retained.recovery_backend_incarnation() {
            Some(inc) if inc == self.backend.incarnation() => {}
            _ => {
                return PublishResult::RefusedPreWrite(SafetyStoreError::SemanticRefusal(
                    "retained publication is not an O5 recovery capability for this backend \
                     incarnation (no cross-store / cross-reopen transfer of recovery authority)"
                        .into(),
                ))
            }
        }

        // Complete byte-for-byte equality — NOT a digest, NOT a re-encode, NOT a
        // normalization. Divergence anywhere (even outside the binding digest's
        // coverage) refuses.
        if stored.as_slice() != retained.encoded() {
            return PublishResult::RefusedPreWrite(SafetyStoreError::PublicationMismatch(
                "stored publication differs from retained original (byte-for-byte)".into(),
            ));
        }
        // The retained revision must also still be the authoritative revision.
        if retained.publication_revision() != meta.current_revision {
            return PublishResult::RefusedPreWrite(SafetyStoreError::StaleRevision {
                expected: retained.publication_revision(),
                stored: meta.current_revision,
            });
        }

        // Republish the ORIGINAL bytes verbatim; metadata revision is unchanged.
        match self
            .backend
            .publish_atomic(&guard, &meta.encode(), retained.encoded())
        {
            PublishOutcome::DurableAcknowledged => {
                // The required successful recovery durability operation marks the
                // shared state effective again for every handle.
                self.backend.mark_effective();
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
    Ok(ValidatedRecord::seal(
        decoded,
        EvidenceStatus::Unverified,
        encoded,
        context_digest(ctx),
    ))
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
    // Public builder: admit the evidence structure BEFORE the evidence-binding
    // allocation (same discipline as O4). An over-bound signature/count/width is
    // refused before `compute_evidence_lock_binding` owns any variable-size buffer.
    super::codec::admit_supporting_evidence(&evidence, ctx)?;
    let binding = compute_evidence_lock_binding(
        &lock_block_id,
        lock_view,
        &evidence,
        &ctx.authority_context_ref,
        ctx,
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