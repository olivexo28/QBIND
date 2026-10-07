//! Run 422 D7-D14 — fail-closed error taxonomy for the safety-record storage
//! component. Every variant is a **refusal**: no operation ever adopts, repairs,
//! resets, or migrates state, and no readable byte is treated as an acknowledged
//! write.

/// The component's fail-closed error type. Distinct refusal reasons are kept
/// separate so a caller can distinguish validation refusal, write failure,
/// uncertain publication outcome, and stale fencing (§ 13.4 / § 13.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyStoreError {
    /// The component policy is `Disabled` (default); the backend is refused.
    BackendDisabled,
    /// The pinned context is bound to MainNet; the backend is refused.
    MainNetRefused,
    /// A pinned profile parameter is invalid / self-inconsistent.
    ProfileInvalid(String),
    /// Checked arithmetic overflowed (size / revision); refuse, never wrap.
    ArithmeticOverflow(String),
    /// Structural decode failure (stage 1): bad version, magic, bounds, CRC,
    /// truncation, oversize, empty-signer certificate, or variant inconsistency.
    StructuralRefusal(String),
    /// Unsupported persistence-format version (no migration).
    UnsupportedVersion(u16),
    /// Oversize encoded record exceeding the checked serialized cap.
    Oversize { len: u128, max: u128 },
    /// A declared length/count exceeds its pinned bound (over-read guard).
    DeclaredBoundExceeded(String),
    /// Semantic / association refusal (stage 3): P1–P4 or TA1–TA8 failed, or a
    /// required independent input was not supplied.
    SemanticRefusal(String),
    /// A required independent input (pinned context / committed history) was not
    /// supplied, so the dependent predicate cannot be established.
    MissingIndependentInput(String),
    /// O1 refused: established / partial / malformed / legacy / unsupported state
    /// already present, or duplicate initialization.
    AlreadyEstablished(String),
    /// O2/O3 refused: expected established state is genuinely absent.
    MissingEstablishedState(String),
    /// Stale fencing refusal: the expected revision no longer matches the stored
    /// current revision (a newer publication exists).
    StaleRevision { expected: u64, stored: u64 },
    /// Transition ineligible (not strictly higher view, or evidence/context fail).
    TransitionIneligible(String),
    /// O5 content mismatch: the recovered publication differs byte-for-byte from
    /// the currently stored publication.
    PublicationMismatch(String),
    /// An allocation/admission charge would exceed a component cap, or a single
    /// decoded backing exceeded its pinned per-vector class maximum. The payload
    /// is a [`CapacityRefusalDetail`]: a free-form message, or typed, `Copy`
    /// per-vector bound data that the protected O4 preflight can construct
    /// **without** allocating an owned diagnostic `String` on the refusal path.
    CapacityRefusal(CapacityRefusalDetail),
    /// A storage write failed outright (before any uncertain barrier).
    WriteFailed(String),
    /// A storage write may or may not have become durable; the caller observed no
    /// acknowledgement. Dependent work stays blocked until O2/O3/O5 re-establish
    /// state. Never assume the predecessor remained stored.
    UncertainPublication(String),
    /// A read failed at the storage layer.
    ReadFailed(String),
    /// A prior ambiguous/uncertain publication left the shared serialization
    /// domain in a recovery-required state; dependent publication is refused for
    /// every handle until the required successful recovery operation clears it.
    RecoveryRequired(String),
}

impl std::fmt::Display for SafetyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendDisabled => write!(f, "safety store: backend disabled"),
            Self::MainNetRefused => write!(f, "safety store: MainNet refused"),
            Self::ProfileInvalid(s) => write!(f, "safety store: profile invalid: {s}"),
            Self::ArithmeticOverflow(s) => write!(f, "safety store: arithmetic overflow: {s}"),
            Self::StructuralRefusal(s) => write!(f, "safety store: structural refusal: {s}"),
            Self::UnsupportedVersion(v) => write!(f, "safety store: unsupported version {v}"),
            Self::Oversize { len, max } => {
                write!(f, "safety store: oversize record {len} > {max}")
            }
            Self::DeclaredBoundExceeded(s) => {
                write!(f, "safety store: declared bound exceeded: {s}")
            }
            Self::SemanticRefusal(s) => write!(f, "safety store: semantic refusal: {s}"),
            Self::MissingIndependentInput(s) => {
                write!(f, "safety store: missing independent input: {s}")
            }
            Self::AlreadyEstablished(s) => write!(f, "safety store: already established: {s}"),
            Self::MissingEstablishedState(s) => {
                write!(f, "safety store: missing established state: {s}")
            }
            Self::StaleRevision { expected, stored } => write!(
                f,
                "safety store: stale revision (expected {expected}, stored {stored})"
            ),
            Self::TransitionIneligible(s) => write!(f, "safety store: transition ineligible: {s}"),
            Self::PublicationMismatch(s) => write!(f, "safety store: publication mismatch: {s}"),
            Self::CapacityRefusal(d) => write!(f, "safety store: capacity refusal: {d}"),
            Self::WriteFailed(s) => write!(f, "safety store: write failed: {s}"),
            Self::UncertainPublication(s) => write!(f, "safety store: uncertain publication: {s}"),
            Self::ReadFailed(s) => write!(f, "safety store: read failed: {s}"),
            Self::RecoveryRequired(s) => write!(f, "safety store: recovery required: {s}"),
        }
    }
}

impl std::error::Error for SafetyStoreError {}

/// Typed, `Copy` identifier of a single per-vector decoded-backing capacity site
/// (§ 13.7A, D7-D14 allocation-free refusal correction). Carried by
/// [`CapacityRefusalDetail::PerVector`] so a per-vector capacity refusal is built
/// from stack-only `Copy` data — the array sites keep an inline index — and no
/// owned diagnostic `String` is allocated unless/until the refusal is actually
/// rendered through `Display`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapnormSiteKind {
    QcSignerBitmap,
    QcSignaturesDescriptor,
    QcSignatureBuffer(usize),
    RecordHighQcSigners,
    TcSigners,
    TcHighQcSigners,
    TcSignedTimeoutsDescriptor,
    TcSignedTimeoutSignature(usize),
    TcSignedTimeoutNestedHighQcSigners(usize),
}

impl std::fmt::Display for CapnormSiteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QcSignerBitmap => f.write_str("QC signer_bitmap"),
            Self::QcSignaturesDescriptor => f.write_str("QC signatures descriptor array"),
            Self::QcSignatureBuffer(i) => write!(f, "QC signature buffer [{i}]"),
            Self::RecordHighQcSigners => f.write_str("record-level high_qc.signers"),
            Self::TcSigners => f.write_str("tc.signers"),
            Self::TcHighQcSigners => f.write_str("tc.high_qc.signers"),
            Self::TcSignedTimeoutsDescriptor => f.write_str("tc.signed_timeouts descriptor array"),
            Self::TcSignedTimeoutSignature(i) => write!(f, "tc.signed_timeouts[{i}].signature"),
            Self::TcSignedTimeoutNestedHighQcSigners(i) => {
                write!(f, "tc.signed_timeouts[{i}].high_qc.signers")
            }
        }
    }
}

/// The payload of [`SafetyStoreError::CapacityRefusal`]. A capacity refusal is
/// either a free-form diagnostic `Message` (aggregate/admission refusals that are
/// not on the protected pre-reservation path) or a typed, **allocation-free**
/// `PerVector` per-vector bound violation.
///
/// The `PerVector` form carries only `Copy` data (`CapnormSiteKind` + three
/// `u128` bounds), so the O4 structural/capacity preflight — which runs BEFORE
/// the O4 operation reservation — constructs its refusal without allocating an
/// owned `String`; the equivalent diagnostic text is materialised only when the
/// error is rendered via `Display`. `Message` round-trips from `String`/`&str`
/// via `From`, so existing diagnostic sites are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityRefusalDetail {
    /// A free-form capacity/admission diagnostic (not on the protected
    /// pre-reservation refusal path).
    Message(String),
    /// A single decoded backing exceeded its pinned per-vector class maximum,
    /// identified by a `Copy` site and the numeric bounds — built without any
    /// heap allocation.
    PerVector {
        site: CapnormSiteKind,
        capacity: u128,
        profile_max: u128,
        slack: u128,
    },
}

impl std::fmt::Display for CapacityRefusalDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(s) => f.write_str(s),
            Self::PerVector {
                site,
                capacity,
                profile_max,
                slack,
            } => write!(
                f,
                "{site} capacity {capacity} exceeds profile maximum {profile_max} + \
                 CAPNORM_SLACK {slack} (per-vector capacity bound)"
            ),
        }
    }
}

impl From<String> for CapacityRefusalDetail {
    fn from(s: String) -> Self {
        Self::Message(s)
    }
}

impl From<&str> for CapacityRefusalDetail {
    fn from(s: &str) -> Self {
        Self::Message(s.to_string())
    }
}