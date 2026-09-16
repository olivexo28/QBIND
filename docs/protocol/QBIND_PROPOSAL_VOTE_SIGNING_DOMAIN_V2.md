# QBIND Proposal/Vote Signing Domain v2

Run 422 D6 — versioned Proposal/Vote signing-domain isolation.

Status: **CODE + TEST only.** The v2 domain is implemented and tested. It is
**not** wired to any production authority: the production
`proposal_vote_authority` remains `None`, the genesis-authority startup refusal
is preserved, and there is no CLI flag, environment switch, or fallback that can
enable a v2-backed Proposal/Vote authority in a release binary. Authority
freshness/lifetime activation (D7) remains unresolved.

---

## 1. Problem

The legacy v1 Proposal/Vote preimage is

```
domain_prefix(runtime_chain_id, kind) || body
```

where `domain_prefix` (see `crates/qbind-types/src/domain.rs`) maps the runtime
`ChainId` to a short **textual scope** — `"DEV"`, `"TST"`, `"MAIN"`, or `"UNK"`
— and produces a tag `QBIND:<SCOPE>:PROPOSAL:v1` / `QBIND:<SCOPE>:VOTE:v1`.

Consequences at the v1 boundary:

* Every custom / unrecognised runtime chain id collapses to the **same**
  `"UNK"` scope, so two distinct networks that both use custom chain ids share
  an identical v1 domain prefix.
* v1 binds **nothing** about the accepted genesis identity or the accepted
  consensus-authority snapshot. Two networks that share a runtime `ChainId` but
  were bootstrapped from different genesis states are indistinguishable at the
  signing domain.

A shared prefix is not by itself a proof that a cross-chain replay succeeds —
the signed body embeds the wire `chain_id`, so replay also depends on the body
fields. But v1 offers no genesis/authority binding whatsoever, which is the gap
v2 closes.

## 2. Goal

Bind a Proposal/Vote signature unambiguously to:

1. an explicit **signing-format version**,
2. the **message family** (Proposal vs Vote),
3. the **full 64-bit runtime `ChainId`** (never truncated to the 32-bit wire
   field, never taken from an incoming message),
4. the **accepted canonical genesis identity** (32 bytes),
5. the **consensus authority commitment** (32 bytes) identifying the intended
   membership/key/suite snapshot,
6. **all currently signed, security-relevant message fields** (the exact v1
   body).

A valid signature for one domain must not authenticate the same message under a
different domain even when the key, validator index, message payload, and wire
`chain_id` are all unchanged.

## 3. Byte layout (v2 preimage)

Implemented by `ProposalVoteSigningDomainV2::{proposal_preimage, vote_preimage}`
in `crates/qbind-wire/src/pv_signing_domain.rs`.

```
offset  field                     width  encoding
------  ------------------------  -----  -------------------------------
0       domain_tag                17     ASCII "QBIND:PVDOMAIN:v2"
17      signing_format_version    1      u8, MUST be 2
18      message_family            1      u8, 1 = Proposal, 2 = Vote
19      runtime_chain_id          8      u64, big-endian (full ChainId)
27      expected_wire_chain_id    4      u32, big-endian
31      genesis_identity          32     raw bytes (accepted genesis hash)
63      authority_commitment      32     raw bytes (authority snapshot)
95      body_len                  8      u64, big-endian
103     body                      N      canonical_body() of the message
```

* All fixed fields have a fixed width and the single variable-length field
  (`body`) is length-prefixed, so the concatenation is unambiguous.
* Integers in the **domain header** are big-endian.
* `body` is `canonical_body()` — the **unchanged** little-endian v1 field
  encoding of the message. Reusing the identical body bytes means (a) the same
  security-relevant fields are bound and (b) the historical v1 golden vectors
  remain byte-identical (v1 = `domain_prefix || canonical_body()`).
* The fixed prefix before `body_len` (`domain_tag`..`authority_commitment`) is
  **95 bytes**; adding the 8-byte `body_len` gives the complete **103-byte** v2
  header. The 95-byte fixed prefix and the 103-byte header are distinct: only
  the header includes `body_len`.

### Golden vectors

Deterministic golden preimage vectors with independently specified expected
bytes are in
`crates/qbind-consensus/tests/run_422_d6_pv_domain_isolation_tests.rs`:

* `golden_vote_preimage_bytes` — full expected preimage for a fully fixed Vote
  (`runtime_chain_id = 0x0102030405060708`, `expected_wire_chain_id =
  0x0A0B0C0D`, `genesis_identity = 0x00..0x1f`, `authority_commitment =
  0x80..0x9f`). The vote body is the fixed **66-byte** v1 vote body
  (`1+4+8+8+8+1+32+2+2`), so `body_len = 66` (`00 00 00 00 00 00 00 42` as a
  big-endian u64) and the complete Vote preimage is `103 + 66 = 169` bytes.
* `golden_proposal_preimage_prefix_bytes` — asserts the **95-byte** fixed
  prefix (`domain_tag`..`authority_commitment`, i.e. the header without
  `body_len`) followed by the length-framed `canonical_body()` suffix for a
  Proposal. This prefix test alone does **not** independently specify the
  complete Proposal body.
* `cd_golden_proposal_full_independent_vector_with_qc_and_txs` — the complete
  independent Proposal-vector: a full second-encoder preimage (including a QC
  and two transactions) that specifies the entire Proposal body byte-for-byte.

These vectors are specified independently of the encoder (they do not compare
the encoder against itself).

## 4. Typed domain object

`ProposalVoteSigningDomainV2` is a validated, immutable value. Construction is
via `try_new(runtime_chain_id, expected_wire_chain_id, genesis_identity,
authority_commitment)`, which:

* rejects an **all-zero genesis identity** and an **all-zero authority
  commitment** — the constructor never defaults missing genesis/authority
  identity to zeros or to DevNet;
* stores the fields immutably; the only accessors are read-only
  (`runtime_chain_id()`, `expected_wire_chain_id()`, `genesis_identity()`,
  `authority_commitment()`, `format()`).

The constructor validates only its stated **structural** conditions
(non-zero genesis identity and authority commitment, plus explicit version
handling). A non-zero genesis identity or authority commitment — including any
arbitrary non-zero fixture hash used by tests — is **not** evidence of
provenance, current authorization, or freshness. It does not prove the hash
corresponds to an accepted genesis, a currently-authorized membership/key
snapshot, or a non-superseded activation. Establishing that binding is the
unresolved D7 authority-freshness/lifetime work plus the unresolved runtime
ChainId → wire chain_id mapping; until then production construction is
unavailable and the release binary constructs no `ProposalVoteAuthority`.

Format vs suite: `ProposalVoteSigningFormat` (currently only `V2`) is
**separate** from the cryptographic suite id. Selecting a suite never changes
the format and selecting a format never changes the suite.
`ProposalVoteSigningFormat::from_u8` rejects any unsupported version explicitly;
there is no fallback to another version.

## 5. Version selection rule

* The node selects its signing format from **trusted configuration / validated
  authority**, never from peer-negotiated or attacker-controlled message
  fields.
* The v2 boundary uses **only** the selected domain. It never tries v2 and then
  falls back to v1, never selects a weaker format from message fields, and
  never treats absent domain metadata as permission to use legacy verification.
* Verification failure is terminal: the verifier never retries with another
  domain, version, suite, or key after a failure.
* An unsupported signing version is rejected explicitly.

## 6. Verification entrypoints

`crates/qbind-consensus/src/proposal_vote_verify.rs` provides fail-closed
**public, message-bound** entrypoints:

* `verify_proposal_msg_with_domain(...)`
* `verify_vote_msg_with_domain(...)`

These take the message and the **trusted domain** and recompute the canonical v2
preimage **internally from the actual message** (a caller can never substitute a
stale or foreign preimage through the public interface). They enforce wire-chain
consistency **before** crypto and then run the **same** fail-closed verification
core used by the v1 `verify_proposal_msg` / `verify_vote_msg` (missing signature
→ reject, unknown validator → reject, wrong/unsupported suite → reject, backend
error → reject, signature mismatch → reject). The v1 and v2 entrypoints differ
only in which preimage bytes they authenticate; they share one crypto backend
and one hash primitive.

The raw-preimage helpers `verify_proposal_msg_with_preimage` /
`verify_vote_msg_with_preimage` are **private** (`fn`, not `pub fn`, and not
re-exported); they are an implementation detail of the public entrypoints above
and are not a caller-facing interface.

## 7. Node integration (fixture/test only)

`ProposalVoteAuthority` (in
`crates/qbind-node/src/binary_consensus_loop.rs`) carries a **mandatory**
`signing_domain: ProposalVoteSigningDomainV2` field (a plain field, **not**
`Option`):

* Inbound Proposal/Vote verification: the handler first checks the message wire
  `chain_id` against the domain's `expected_wire_chain_id` (rejecting a mismatch
  **before** crypto, via a typed counter, without rewriting the message), then
  authenticates using the domain's preimage.
* Outbound Proposal/Vote signing: signs the preimage produced by the **selected
  authority's** domain, and refuses (fail-closed, before signing) any message
  whose wire `chain_id` disagrees with the domain. Outbound code never derives a
  domain from the message it is about to sign.
* There is **no** missing-domain → legacy-v1 selection: the domain is always
  present on a `ProposalVoteAuthority`. When **no** authority is wired at all,
  the `Required` policy fails closed (it is never treated as legacy
  passthrough).

Admission order is preserved:

```
F6 authenticated sender binding
  → Proposal/Vote authority availability (Required + None ⇒ reject)
  → wire-chain / domain / suite / signature checks
  → delivery / restore deferral / reconfiguration observation / engine processing
```

**Production remains disabled.** `crates/qbind-node/src/main.rs` never
constructs a `ProposalVoteAuthority` (production `proposal_vote_authority`
stays `None`); only test fixtures construct a `ProposalVoteAuthority`. The
optional wrapper is the authority itself (`proposal_vote_authority:
Option<ProposalVoteAuthority>`), which production leaves `None`; the
`signing_domain` field inside an authority is mandatory and has no `Option`
wrapper, so a constructed authority always carries a domain. The
Timeout/NewView context is unchanged and cannot establish Proposal/Vote
authority (D5 policy preserved).

## 8. Compatibility

* **Wire bytes do not change.** The v2 domain changes only the *signed
  preimage* (the bytes handed to the existing signer/verifier). No wire struct,
  wire version field, transport, transaction, DAG, or Timeout/NewView signature
  format is modified.
* v1 preimage bytes and their regression vectors are preserved exactly
  (`signing_preimage_with_chain_id` still emits `domain_prefix ||
  canonical_body()`).
* A legacy v1 signature presented to the v2 verifier is rejected, and a v2
  signature presented to the v1 verifier is rejected (cases D and E in the test
  matrix).
* Downstream engine / QC verification that reconstructs the **legacy** preimage
  is unchanged and still legacy. Successful v2 boundary verification is **not**
  QC or engine validation. Any broader adoption of v2 by downstream consumers
  is a separate protocol change and is **not** performed here.

## 9. Runtime ChainId ↔ wire chain_id mapping (unresolved dependency)

Three distinct representations exist:

| identity                          | type    | source                              |
| --------------------------------- | ------- | ----------------------------------- |
| `GenesisConfig.chain_id`          | string  | genesis file                        |
| runtime `ChainId`                 | `u64`   | `qbind-types` primitive             |
| Proposal/Vote wire `chain_id`     | `u32`   | `qbind-wire` consensus messages     |

The repository does **not** contain a validated mapping from the 64-bit runtime
`ChainId` to the 32-bit wire `chain_id`. v2 therefore carries
`expected_wire_chain_id` as an **explicit** field supplied from trusted
configuration (fixtures/tests only); it is never derived by truncating the
runtime `ChainId` and never taken from an incoming message. Because a validated
production mapping is absent, a production v2 authority cannot be constructed
safely, which is one reason production activation stays unavailable. Resolving
this mapping is a prerequisite dependency recorded for later work.

### 9.1 Dormant standard-network wire alias mapping (Run 422 D7-C3A)

Run 422 D7-C3A introduces a **pure, dormant** helper in `qbind-types`
(`network_wire_alias.rs`) that assigns a compact 32-bit `NetworkWireAlias` to
each of the three standard environments and validates the standard
environment / runtime / wire correspondence. It does **not** resolve the
unresolved production dependency described above: it covers only the three
standard networks, is not wired into any preimage, message, authority or
activation path, and general 32-bit narrowing of arbitrary runtime `ChainId`s
can still collide.

Assigned dormant aliases (defined, not activated):

| Environment | Authoritative runtime source        | Wire alias   |
| ----------- | ----------------------------------- | ------------ |
| DevNet      | `NetworkEnvironment::chain_id()`    | `0x44455600` |
| TestNet     | `NetworkEnvironment::chain_id()`    | `0x54535400` |
| MainNet     | `NetworkEnvironment::chain_id()`    | `0x4D41494E` |

Each assigned alias is the low 32 bits of that environment's authoritative
64-bit runtime `ChainId`; the three standard low words are distinct, though
general narrowing of arbitrary runtime IDs to 32 bits can collide.

**Input contract of `resolve_network_wire_alias(environment, supplied_runtime)`:**

* The authoritative expected runtime is obtained **only** from
  `environment.chain_id()`; there is no parallel registry or fallback.
* The caller-supplied full 64-bit runtime `ChainId` must equal that expected
  runtime exactly (all 64 bits). A supplied ID sharing only the low 32 bits is
  rejected.
* On match it returns the alias for the environment; on any mismatch it returns
  `NetworkWireAliasMismatch { environment, expected_runtime, supplied_runtime }`.
* `NetworkWireAlias` is a raw, publicly constructible tag, **not** a validation
  certificate: a bare alias value does not prove the helper was called or that
  any correspondence was checked, and the helper grants no authorization.
* The helper never reads an incoming message, never truncates the runtime
  `ChainId` to derive the expected value, and performs no I/O.

Status markers: `STANDARD_WIRE_ALIAS_POLICY=DEFINED-NOT-ACTIVATED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`. The unresolved production
`ChainId` -> wire mapping in section 9 remains open.

### 9.2 Pinned genesis ⇄ standard network correspondence (Run 422 D7-C3B)

Run 422 D7-C3B binds the pinned genesis validation of C2 to the standard
network mapping of C3A, in the existing **non-authorizing** module
`crates/qbind-node/src/genesis_authority_record_correspondence.rs`. It reuses
the C2 construction path (`load_external_genesis` -> `verify_boot_time_genesis`
with the required independent pin -> `build_genesis_consensus_authority`, one
owned genesis read) and the C3A resolver; it introduces **no** new genesis
loader, parser, hash, environment table, numeric-ID registry, or authority
builder.

**Retained validation provenance.** `ExpectedGenesisIdentity` now also retains,
privately and immutably, the exact `NetworkEnvironmentPolicy` its successful
`load_pinned` construction validated under. The `load_pinned` signature and
validation behaviour are unchanged; there is no public unchecked constructor,
setter, deserialization route, or default that can fabricate this provenance.
The canonical genesis hash the pin is compared against already binds
`policy.scope()` (`"DEV"`/`"TST"`/`"MAIN"`), so the retained policy simply keeps
the environment scope attached to the already-validated identity.

**Input contract of
`ExpectedGenesisIdentity::check_network_correspondence(selected_environment, supplied_runtime)`:**

* It compares the retained validation policy against
  `pqc_boot_genesis::map_environment(selected_environment)` and rejects any
  mismatch with `GenesisNetworkCorrespondenceError::ValidationPolicyMismatch`
  (bounded enum metadata). This prevents relabelling an already-validated
  identity by choosing a different environment/runtime pair.
* It obtains the wire alias **only** through the existing
  `resolve_network_wire_alias(selected_environment, supplied_runtime)` (C3A),
  never from a caller-supplied raw alias. A full-width runtime mismatch is
  surfaced as `GenesisNetworkCorrespondenceError::RuntimeMismatch`, reusing the
  C3A `NetworkWireAliasMismatch` verbatim, without truncation or fallback.
* On success it returns a `GenesisNetworkCorrespondence<'a>` with **private**
  fields that **immutably borrows** the same validated identity, so the alias
  stays attached to the original validated genesis hash and authority
  commitment. It exposes only read-only inspection accessors.
* The numeric runtime `ChainId` is never inferred by parsing the genesis
  `chain_id` string, searching it for network names, truncating a number, or
  comparing it with a synthetic fixture label. The genesis string label is not a
  numeric network-ID registry.

**Trust limits.** A `GenesisNetworkCorrespondence` establishes **static
correspondence only**. It is not current authority, activation permission,
freshness, storage provenance, rollback resistance, or a signing capability, and
offers **no** conversion into `LocalAuthorizationState::Established`,
`CurrentAuthorizationOwner`, `AuthorizedProposalVoteSnapshot`,
`AuthorizationTicket`, `ProposalVoteSigningDomainV2`, or any signer / activated
verification context. It does not prove the operator obtained the correct
official genesis pin, and it never chooses an official genesis or asserts
uniqueness across forks — two distinct genesis files may each correspond under
the same standard environment when separately accepted under their own
independent pins. `GenesisConsensusAuthority.authorized_wire_chain_id` and the
existing fixture-label comparison are unchanged; production wire values remain
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`. The C3A resolver now has one
caller in this dormant library operation — that is not a startup or active
consensus integration.

## 9A. Dormant D6-compatible QuorumCertificate verification (Run 422 D7-C3D)

This bounded contract covers the pure, **dormant** boundary
`qbind_consensus::qc_verify_domain::verify_quorum_certificate_with_domain`,
which verifies the constituent `Vote` signatures and aggregate voting power of a
**wire** `QuorumCertificate` under an explicitly supplied v2 domain. It reuses
the D6 machinery and does **not** introduce a second QC verifier, a raw-preimage
public API, a duplicate D6 encoder, `vote_digest`, or a legacy retry.

**Signature.**

```text
verify_quorum_certificate_with_domain(
    qc: &qbind_wire::consensus::QuorumCertificate,   // fully untrusted
    domain: &ProposalVoteSigningDomainV2,            // trusted
    authorized_epoch: u64,                           // trusted
    validators: &ConsensusValidatorSet,              // trusted membership
    key_provider: &K: SuiteAwareValidatorKeyProvider,// trusted
    backend_registry: &B: ConsensusSigBackendRegistry,// trusted
) -> Result<VerifiedQuorumCertificate, QcDomainVerifyError>
```

**Trusted-input assumption.** The whole QC is untrusted (validated whether wire-
decoded or directly constructed). The `domain`, `authorized_epoch`,
`validators`, `key_provider`, and `backend_registry` are trusted and must
describe a coherent, stable context for the duration of the call. This boundary
does not solve concurrent provider mutation or persistent freshness. Success
establishes signature-and-quorum validity **relative to those inputs only** — it
does **not** establish official-genesis provenance, current authority, or
activation permission.

**Signer-index semantics.** Identical to D6: bitmap bit `i` reconstructs wire
`validator_index = i` and identifies `ValidatorId(i)`, subject to checked
representability and a trusted membership lookup. Membership-vector *position* is
never substituted for `ValidatorId`; ids are never reordered, renumbered,
truncated, or wrapped. A bitmap cannot repeat a bit, so signer ids are distinct
(index aliasing / incorrect association are tested rather than an invented
duplicate-bit encoding). For this bounded phase a membership containing an id the
u16 wire index cannot represent (`> u16::MAX`) is rejected.

**Size bounds (a complete structural preflight, all validated before any
signature-buffer clone and before any backend invocation).** Signature-count
representability and the bitmap bounds precede signer-vector construction;
`collect_signers` then materializes a temporary signer vector before the
popcount-correspondence, per-signature-size, and aggregate-size checks. The
per-signature and aggregate size checks therefore run *after* that temporary
vector exists — they precede only the signature-buffer clone and backend
invocation, not every allocation. The temporary vector is bounded by the
bitmap's capacity: before correspondence succeeds it may hold up to `65536`
entries (a full 8192-byte bitmap's popcount), and only after successful
correspondence is it bounded by `MAX_SIGNATURE_COUNT` (`65535`).

* **Signature-count representability.** The wire QC encodes `signatures.len()`
  as a `u16` (`sig_count`), so at most `MAX_SIGNATURE_COUNT` (`u16::MAX ==
  65535`) signatures are encodable. `signatures.len() > MAX_SIGNATURE_COUNT` is
  rejected (`SignatureCountNotRepresentable`) before any crypto, before the
  signer vector is constructed, without changing the wire format or encoder.
  Three distinct
  quantities: the maximum *validator index* is `65535` (valid); the number of
  *representable indices* is `65536` (`0..=65535`); the maximum *encodable
  signature count* is `65535`. A full 8192-byte bitmap has `65536` set bits — one
  more than the encodable count — so an 8192-byte bitmap alone does **not**
  enforce the count limit; the count is bounded explicitly.
* **Global bitmap length.** `signer_bitmap.len() <= MAX_BITMAP_LEN` (8192
  bytes). `8192 * 8 == 65536` bits, so the highest representable bit index is
  exactly `u16::MAX`; the cap bounds work and guarantees representable indices
  (`BitmapTooLong`).
* **Membership-relative bitmap span.** `signer_bitmap.len()` must not exceed the
  trusted membership's **identifier span** — the byte span required to represent
  bit indices `0..=max_id`, where `max_id` is the largest representable
  `ValidatorId` in the trusted set (`(max_id / 8) + 1` bytes; `0` for an empty
  set). This uses the *identifier span*, never `validators.len()`, so sparse and
  reordered memberships remain valid, and a bitmap shorter than the span is
  allowed. Any byte beyond that span — **including trailing zero padding** — is
  rejected (`BitmapBeyondMembershipSpan`). A set bit for a non-member id that
  falls *within* the span still rejects at the per-signer membership check
  (`UnknownSigner`). Because every `max_id <= u16::MAX`, the span is always
  `<= MAX_BITMAP_LEN`.
* `popcount(signer_bitmap) == signatures.len()`; `collect_signers` builds the
  temporary ascending-bit-order signer vector and this correspondence is checked
  against it. Signatures are associated with set bits in ascending-bit order.
* **Per-signature size.** Every signature length `<= MAX_SIGNATURE_LEN`
  (`u16::MAX`, the wire length bound), validated for *all* signatures before the
  crypto loop, so an oversized signature at any position (including after quorum
  would be reached) rejects (`MalformedSignature`) before any backend
  invocation.
* **Checked aggregate size.** The sum of all constituent signature byte lengths
  is accumulated with checked arithmetic (`checked_aggregate_signature_bytes`)
  and must not exceed the documented acceptance bound
  `MAX_AGGREGATE_SIGNATURE_BYTES` (`MAX_SIGNATURE_COUNT * MAX_SIGNATURE_LEN`).
  This is the structural worst case implied purely by the two wire field widths;
  it is the dormant verifier's own acceptance bound and is **deliberately
  distinct** from transport limits such as `qbind_wire::net::MAX_NET_MESSAGE_BYTES`
  (1 MiB). Establishing it does not change transport policy.

The only per-signer allocation is one clone of that signer's signature into the
reconstructed `Vote` (bounded by `MAX_SIGNATURE_LEN`), performed after the whole
preflight above. This is **not** a complete transport-level DoS audit.

**Failure ordering (fail-closed at the first failure).**

1. `qc.chain_id == domain.expected_wire_chain_id()` — else `WireChainMismatch`,
   before crypto.
2. `qc.epoch == authorized_epoch` — else `EpochMismatch`, before crypto.
3. Checked, representable, **positive** total voting power `W`
   (`ZeroTotalVotingPower` / `TotalVotingPowerOverflow` /
   `MembershipIdNotRepresentable`), and the membership identifier span used to
   bound the bitmap. The set's cached (saturating) total and `two_thirds_vp()`'s
   `2 * total` u64 arithmetic are **not** trusted blindly.
4. Complete structural preflight (`SignatureCountNotRepresentable`, then
   `BitmapTooLong`, `BitmapBeyondMembershipSpan`, `SignatureCountMismatch`,
   `SignerIndexNotRepresentable`, every per-signature `MalformedSignature`, and
   the checked `AggregateSignatureBytesTooLarge`) — all before the cryptographic
   loop and any signature clone.
5. Per set bit in ascending order: reconstruct the `Vote` from the QC's
   **actual** `version, chain_id, epoch, height, round, step, block_id, suite_id`
   plus the bit-derived index and its associated signature (no field is replaced
   with a trusted value to force a pass); verify via
   `verify_vote_msg_with_domain` (membership, missing signature, governed key,
   QC-suite-vs-governed-suite match, backend dispatch, and the cryptographic
   check over the recomputed v2 preimage). Accumulate the signer's voting power
   **once**, by `ValidatorId` lookup and checked arithmetic.
6. Quorum: `accumulated >= ceil(2W/3)`.

**Every declared signature is verified.** The function never returns success
upon merely reaching quorum with unchecked extra signatures; a valid quorum
followed by an invalid extra signature rejects.

**Quorum arithmetic.** The threshold is the existing mathematical `ceil(2W/3)`
computed with wide (`u128`) arithmetic — the **checked equivalent** of
`ConsensusValidatorSet::two_thirds_vp` that avoids its `2 * total` u64 overflow.
Because `ceil(2W/3) <= W <= u64::MAX`, the result always fits `u64`. Preserving
`ceil(2W/3)` is **compatibility behavior**, not a new proof of safety under
arbitrary weighted fault assumptions; it is deliberately not replaced with
`2f+1` or a different weighted threshold. Because `W` is validated positive and
non-overflowing and signer ids are distinct, the per-signer accumulation can
never exceed `W`; the later accumulation overflow (`VerifiedPowerOverflow`) is
therefore mathematically unreachable and retained only as an explicit checked
guard — the excluding precondition (total-power overflow rejection) is tested
instead of a fabricated case.

**Result ownership.** On success a `VerifiedQuorumCertificate` associates an
**owned clone** of the certificate, the distinct signer ids, the verified voting
power, the threshold, and the trusted verification context (expected wire chain,
authorized epoch, domain). It cannot silently refer to a later-mutated
certificate. All fields are private with read-only accessors; there is no public
constructor, no public mutable field, and no `Deserialize`. It provides **no**
conversion to a current-authorization owner, snapshot, ticket, signer,
activation state, or production verification capability, and its `Debug` is a
bounded summary that never dumps signature or key bytes.

**Typed failures.** `QcDomainVerifyError` distinguishes structural failures
(signature-count representability, global and membership-relative bitmap bounds,
bitmap/signature-count correspondence, per-signature and checked-aggregate
size), epoch/wire mismatch, invalid membership arithmetic, missing key, suite
mismatch, unsupported backend, malformed signature, invalid signature, backend
failure, and insufficient voting power. Outward diagnostics are bounded: no
variant embeds a certificate, signature array, or key bytes, and `BackendError`
carries only a truncated message produced by our own backends. There is no
panic, unchecked narrowing, saturating acceptance, default domain/epoch, unsigned
fallback, or cross-suite retry.

**Dormancy (updated by Run 422 D7-C3E).** The boundary is still **uncalled**
by production node startup, the engine's own QC formation/adoption, cache,
storage, and activation paths. Run 422 D7-C3E adds one conditional binary
caller — the inbound `Proposal` arm of the node handler (see §9B) — which is
only reachable under a bound current-authorization snapshot; genesis authority
activation stays DISABLED, so no release binary constructs that snapshot and the
caller is exercised by tests. The legacy `verify_quorum_certificate` (which
signs the `vote_digest` input) is unchanged and is **not** used as the D6 path
or a fallback.

## 9B. Conditional inbound admission of PRESENT embedded QCs (Run 422 D7-C3E)

Run 422 D7-C3E adds a **conditional inbound-admission gate** in the node's real
`handle_inbound_consensus_msg` `Proposal` arm. Under the `Required` verification
policy, when the admitted current-authorization snapshot is present **and** the
Proposal carries `Some(qc)`, the handler verifies the PRESENT embedded wire QC
with the §9A verifier (`verify_quorum_certificate_with_domain`) **before** any
inbound Proposal effect.

**Handler contract (ordering).** For a Required-policy Proposal carrying
`Some(qc)`:

1. Decode and existing F6 sender binding.
2. Existing current-authorization admission and signed-Proposal epoch check.
3. Existing outer Proposal verification under the admitted snapshot's verifier.
4. **Engine-context correspondence** (new): the engine's actual validator IDs
   and voting weights must match the bound verifier's membership (reusing the
   existing structural predicate; matching counts alone are insufficient;
   membership is compared by value, not by `Arc` pointer identity), and
   `engine.current_epoch()` must equal the snapshot's authorized epoch.
   Disagreement rejects before constituent-QC cryptography and downstream
   effects.
5. **Embedded-QC verification** (new): call the §9A verifier **once** for the
   present QC, with `domain`, `validators`, `key_provider`, and
   `backend_registry` drawn from the **same** admitted `snapshot.verifier()`
   used for outer verification, and `authorized_epoch` from that same admitted
   snapshot.
6. Confirm the existing authorization ticket.
7. Only then permit the existing downstream Proposal effects (restore-deferral
   accounting, delivery, reconfiguration observation, engine mutation including
   view advancement, and the immediate outbound handoff).

Placement is **before** the engine call because the reviewed engine's
`on_proposal_event` can advance `current_view` before later checks. A valid
outer Proposal signature never makes an invalid embedded QC acceptable. The
returned non-authorizing `VerifiedQuorumCertificate` stays associated with the
immutable Proposal through confirmation and the immediate handoff; there is no
"already verified" flag or certificate cache, and retention beyond the
synchronous handler call is out of scope. Bounded rejection counters distinguish
outer-signature acceptance, embedded-QC verified/rejected, and engine-context
mismatch; an outer-signature acceptance counter may increase even when the QC
subsequently rejects and is **not** relabelled as whole-Proposal acceptance.

**Trusted-input isolation.** Authorization is never derived from the QC, the
Proposal header, the engine's default epoch, a separately supplied
`pv_authority`, or Timeout context: a supplied authority B must not substitute
for admitted snapshot A. Signed fields are preserved exactly (no rewriting,
normalization, legacy retry, or unsigned fallback).

**Exact exclusions (unchanged by C3E).** This task verifies QCs that are
PRESENT. It does **not** change: `proposal.qc == None` behavior (absent QCs are
preserved, **not** counted as QC-verified and **not** a validated
genesis/bootstrap exception); `Some(empty_or_invalid_qc)`, which **rejects** and
is never converted to `None`; the test-only `LocalFixtureUnsigned` policy;
`main.rs` production authority wiring or genesis startup refusal; C3A
aliases / C3B provenance; C3D verification rules, D6 bytes, wire encodings, or
legacy verification; engine message/membership construction, vote aggregation,
or logical QC serialization; Timeout/NewView behavior; and storage / restore
protocol / durable freshness / anti-rollback. QC-to-parent/view/step semantics,
no-QC bootstrap authorization, persisted certificate evidence, locally formed QC
emission, full engine/QC adoption + retention, and other engine entrypoints
remain explicitly **unclosed**.

## 10. Non-goals (D7 and beyond)

This task establishes a scoped cryptographic boundary only. It does **not**
establish authority freshness, activation safety, complete consensus
validation, quorum/QC formation, or liveness. Specifically out of scope:

* epoch-transition authority activation / key rotation,
* restore/restart authority freshness or durable anti-rollback,
* authority replacement through peers or caches,
* QC / engine adoption of the v2 preimage,
* any production activation path.

A commitment embedded in a signature identifies the *intended* authority
snapshot; it does not prove that snapshot is current or authorized for a later
epoch. **D7 remains unresolved.**