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
    /// An allocation/admission charge would exceed a component cap.
    CapacityRefusal(String),
    /// A storage write failed outright (before any uncertain barrier).
    WriteFailed(String),
    /// A storage write may or may not have become durable; the caller observed no
    /// acknowledgement. Dependent work stays blocked until O2/O3/O5 re-establish
    /// state. Never assume the predecessor remained stored.
    UncertainPublication(String),
    /// A read failed at the storage layer.
    ReadFailed(String),
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
            Self::CapacityRefusal(s) => write!(f, "safety store: capacity refusal: {s}"),
            Self::WriteFailed(s) => write!(f, "safety store: write failed: {s}"),
            Self::UncertainPublication(s) => write!(f, "safety store: uncertain publication: {s}"),
            Self::ReadFailed(s) => write!(f, "safety store: read failed: {s}"),
        }
    }
}

impl std::error::Error for SafetyStoreError {}
