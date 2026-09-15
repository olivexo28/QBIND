# QBIND Genesis Authority / Engine / QC Integration Audit

**Run:** 422 D7-C3C
**Status:** Source audit and integration design only. No production behavior
change. No new loader, registry, authority wrapper, verifier, or mapping helper
is introduced by this document.
**Scope:** How the completed C2 / C3A / C3B genesis-identity checks would be
consumed by the existing Proposal / Vote authority, engine, and QC paths that
the release binary actually runs.

```
D7C3C_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT=COMPLETE-FOR-INSPECTED-SCOPE
PRODUCTION_INTEGRATION=NOT-PERFORMED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

This document is **audit-scoped**. It does not move any readiness item to Green,
does not enable production authority, and does not perform Run 423, wallet,
presale, or bridge work. It separates, and never conflates, the following
independent categories:

* independently pinned genesis identity;
* standard runtime / wire correspondence;
* signature verification;
* quorum-certificate validation;
* current activation authorization;
* in-process freshness;
* persistent anti-rollback.

Success in one category does not establish any other. In particular, **C3B
network correspondence must never be presented as permission to activate.**

---

## 1. Scope, inspected revision, and source limitations

### 1.1 Branch and revision actually inspected

* **Working branch (actual):** `copilot/copilotcopilot-run-422-d7-c3b-again`
  (note the doubled `copilot` prefix; the task text names
  `copilot/copilot-run-422-d7-c3b-again`).
* **Inspected worktree HEAD:** `0b3eb4a19530f8ecf21b25212f92aa944473e154`
  (`update`).
* **HEAD parent (shallow boundary):**
  `02f7f1dce07b4df0dbcb0d1c1ecda7e6e453d8e3` (`update`), recorded in
  `.git/shallow`.

### 1.2 Ancestry limitation (reported accurately)

The clone is **shallow with depth 2** (`git rev-list --count HEAD` = 2;
`.git/shallow` pins `02f7f1d`). The **reviewed final revision named in the task,
`734a9425a15f8a5845b8bf0bdb4932b700d9cc22`, is not present** in this clone
(`git cat-file -t 734a9425…` → *could not get object info*). Therefore:

* Ancestry between HEAD and `734a9425…` **cannot be established** from local
  history.
* The worktree content corresponds to the completed D7-C2 / C3A / C3B work
  (module `genesis_authority_record_correspondence.rs` present with
  `load_pinned`, retained `validation_policy`, and `check_network_correspondence`
  — see §4.A). **Content correspondence does not establish ancestry** and is not
  claimed to.

All findings below are anchored to paths and symbols **as they exist at HEAD
`0b3eb4a`**. Every material finding cites `path:line`. Findings are **source
evidence** unless explicitly marked as executed behavior (§6).

### 1.3 Deliverable posture

No production edits or new Rust tests were required or made for this audit. The
only changes committed are this document and the concise C3C evidence entry in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.

---

## 2. Production call-path map (from `main.rs`)

The release binary’s consensus path is the **`BasicHotStuffEngine`** path wired
by `binary_consensus_loop.rs`. It is distinct from the older library
`Node<S>::apply_block` / `hotstuff_decide_and_maybe_record_vote` path (§4.C.5),
which `main.rs` does not reach.

| # | Boundary | Path:symbol | Reached from `main.rs`? |
|---|----------|-------------|-------------------------|
| 1 | Boot genesis verification (pin compare) | `main.rs` startup → `verify_boot_time_genesis` (qbind-ledger) | Yes (every startup) |
| 2 | Consensus security preflight | `crates/qbind-node/src/main.rs:5470` `build_consensus_security_preflight` | Yes |
| 3 | Proposal/Vote authority slot | `crates/qbind-node/src/main.rs:5549` `proposal_vote_authority: None` | Yes — **wired to `None`** |
| 4 | Validator set + key provider | `crates/qbind-node/src/peer_key_provider.rs` `build_validator_set_and_key_provider` (from `config.network.static_peer_consensus_keys`) | Yes |
| 5 | Engine construction | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:508` `BasicHotStuffEngine::new(local_id, validators)` | Yes |
| 6 | Inbound Proposal admission + verify + ingest | `crates/qbind-node/src/binary_consensus_loop.rs` inbound Proposal arm (≈`:4359`–`:4697`) | Yes |
| 7 | Inbound Vote admission + verify + ingest | `binary_consensus_loop.rs` inbound Vote arm (≈`:4833`–`:4929`) | Yes |
| 8 | Outbound forwarding | `binary_consensus_loop.rs` `forward_actions_to_facade` (≈`:4046`) | Yes |
| 9 | Leader step | `binary_consensus_loop.rs` `do_leader_tick` (≈`:3189`) | Yes |
| 10 | Late-peer cached re-emission | `binary_consensus_loop.rs` `maybe_reemit_on_late_peer_connect` (≈`:3324`) | Yes |
| 11 | Restore-catchup deferral | `binary_consensus_loop.rs` restore deferral (≈`:4632`) | Yes (restore mode) |
| 12 | Engine QC ingest (wire→logical) | `basic_hotstuff_engine.rs:1490`–`1493` / `:1567` `on_vote_event` | Yes |
| 13 | Embedded-QC crypto verify | `crates/qbind-consensus/src/lib.rs:705` `verify_quorum_certificate` / `:807` `verify_block_proposal` | **No** (dormant relative to binary path; §4.C) |
| 14 | Genesis correspondence module | `crates/qbind-node/src/genesis_authority_record_correspondence.rs` | **No** (test-only callers; §4.A) |

**Key structural fact:** the same verifier and the same admission owner are held
together in `AuthorizedProposalVoteSnapshot` (`binary_consensus_loop.rs:1176`),
but **no production code constructs that snapshot** — `main.rs:5549` supplies
`proposal_vote_authority: None`, so the inbound/outbound gates run in fail-closed
`Required` mode with no wired authority.

---

## 3. Trust-source and information-preservation tables

### 3.1 Trust source per boundary

| Boundary (path:symbol) | Trusted input | Untrusted input | Identity/membership/domain/epoch available | Retains | Production reachable |
|---|---|---|---|---|---|
| `genesis_authority_record_correspondence.rs:156` `load_pinned` | operator pin `GenesisHash`, env policy | genesis file bytes | chain_id, genesis_hash, authority commitment, validator_count, founding epoch 0, `validation_policy` | all of these (`:189`, `:221`) | No (test-only callers) |
| `genesis_authority_record_correspondence.rs` `check_network_correspondence` | retained `validation_policy`, selected env, supplied runtime `ChainId` | — | env policy vs runtime alias (via C3A) | immutable-borrow `GenesisNetworkCorrespondence` | No |
| `genesis_consensus_authority.rs` `build_genesis_consensus_authority` (→ `:439`) | boot-verified `GenesisConfig.validators[]` (suite, pk) | — | `Arc<ConsensusValidatorSet>`, key provider, genesis_hash, commitment, `authorized_epoch=0`, `authorized_wire_chain_id: None` | full authority | Boot-validation only; not fed to Proposal/Vote authority |
| `binary_consensus_loop.rs:1245` `try_bind` | owner candidate + verifier (shared `Arc`) | — | genesis hash, commitment, membership, key provider, chain label, wire chain id | `AuthorizedProposalVoteSnapshot` | No (test-only) |
| `binary_consensus_loop.rs` inbound Proposal verify → `proposal_vote_verify.rs:405` `verify_proposal_msg_with_domain` | bound domain, validator set, key provider | wire Proposal bytes | proposer index, wire chain id, v2 domain (runtime+wire+genesis+commitment+epoch) | pass/fail only | Yes |
| `basic_hotstuff_engine.rs:1567` `on_vote_event` → `hotstuff_state_engine.rs` `on_vote` → `vote_accumulator.rs` / `qc.rs:` `validate` | validator set membership + voting power | logical vote (id, view, block) | ValidatorIds, view, voting power | logical QC (ids only) | Yes |

### 3.2 Wire-QC → logical-QC information preservation (`basic_hotstuff_engine.rs:1493`)

`proposal.qc.as_ref().map(|wire_qc| QuorumCertificate::new(wire_qc.block_id, wire_qc.height, vec![]))`

| Wire QC field (`crates/qbind-wire/src/consensus.rs` QuorumCertificate) | Preserved into logical QC (`qc.rs` `QuorumCertificate<BlockIdT>`) |
|---|---|
| `block_id` | **Yes** (→ `block_id`) |
| `height` | **Yes** (→ `view`) |
| `signer_bitmap` | **No — discarded** |
| `signatures[]` | **No — discarded** |
| `suite_id` | **No — discarded** |
| `version` | **No — discarded** |
| `epoch` | **No — discarded** |
| `chain_id` | **No — discarded** |
| `round`, `step` | **No — discarded** |

The embedded QC is passed with an **empty signer list** (`vec![]`); its
cryptographic material is not carried and cannot be re-verified downstream
(`hotstuff_state_engine.rs` `on_qc` stores the logical QC as-is for locking /
commit).

---

## 4. Findings (existing containment + remaining risk)

### 4.A Genesis identity and authority ownership

* **Correspondence module is non-authorizing and unreached in production.**
  `ExpectedGenesisIdentity::load_pinned`
  (`genesis_authority_record_correspondence.rs:156`), the retained
  `validation_policy` field (`:122`, accessor `:221`), and
  `check_network_correspondence` (returning `GenesisNetworkCorrespondence`) have
  **no `main.rs` caller** — every caller is under `crates/qbind-node/tests/…`.
  This is exactly the C2/C3A/C3B design: read-only correspondence, never
  authorization.
* **A validated authority already exists, but is not fed to Proposal/Vote.**
  `build_genesis_consensus_authority` builds a single
  `GenesisConsensusAuthority` with `validators: Arc::new(...)`, a shared
  `Arc<dyn SuiteAwareValidatorKeyProvider>`, genesis hash, commitment,
  `authorized_epoch = GENESIS_STATIC_AUTHORITY_EPOCH (0)`, and
  **`authorized_wire_chain_id: None`** (`genesis_consensus_authority.rs:439`).
* **Ownership/encapsulation constraint (already enforced).**
  `AuthorizedProposalVoteSnapshot::try_bind` (`binary_consensus_loop.rs:1245`)
  requires the owner’s candidate and the verifier to share the **same** `Arc`
  allocations — `Arc::ptr_eq` on `validators` and on `key_provider` — plus
  structural membership equality, genesis-hash and commitment equality, a chain
  identity label match, and a wire-chain-id match. A freshly rebuilt-but-equal
  validator set fails `Arc::ptr_eq`. This is the correct anchor for “the same
  validated genesis stays associated through future construction”: future code
  must **clone the same `Arc`s** out of one authority, not rebuild them.
* **Two fixture conventions block real consumption today.**
  1. `snapshot_chain_identity_label` (`binary_consensus_loop.rs:1238`) is a
     synthetic `String` label; `try_bind` compares
     `candidate.chain_id != snapshot_chain_identity_label(domain.runtime_chain_id())`
     (`:1281`). Production would need the authority to carry a chain identity
     derived from validated provenance rather than a synthetic label.
  2. `authorized_wire_chain_id` is `None` in the production authority
     (`:439`); `try_bind` rejects any verifier whose domain expects a wire
     chain id (`:1295`). So **no production authority can bind any verifier**
     under the current construction — this is a deliberate closed door, not a
     latent activation.
* **Remaining risk / containment.** Because `main.rs:5549` wires
  `proposal_vote_authority: None`, inbound/outbound Proposal/Vote run fail-closed
  under `Required` with no authority. There is no path by which C3B
  correspondence becomes activation. What must change (future, not now):
  construct the snapshot by cloning the `Arc`s from one boot-validated
  `GenesisConsensusAuthority`, and resolve a real (non-synthetic) chain-identity
  label + an authorized wire chain id — **without** touching the C2/C3A/C3B
  checks and **without** introducing an “Established” production owner.

### 4.B Engine identity and membership

* **Engine and verifier membership share a validated source *type*, and can
  share an instance.** The engine gets `ConsensusValidatorSet` via
  `build_validator_set_and_key_provider` (`peer_key_provider.rs`) →
  `BasicHotStuffEngine::new` (`basic_hotstuff_engine.rs:508`). The timeout
  verification bridge (`timeout_verification_bridge.rs`) takes
  `Arc<ConsensusValidatorSet>` and `Arc<dyn SuiteAwareValidatorKeyProvider>` of
  the same types and performs fail-closed membership/suite cross-checks
  (local-in-set, key present, suite == ML-DSA-44 `SUPPORTED_TIMEOUT_SUITE_ID`).
  Today the engine set is built from CLI/config static peer keys, **not** from
  the genesis-validated authority; unifying them is an integration requirement,
  not an existing guarantee.
* **`chain_id: 1` is fixture-scoped, not a production wire constant.** The
  literal `chain_id: 1` appears only in `basic_hotstuff_engine.rs:1351`
  (proposal header), `:1370` (embedded QC), `:1405` (vote), and `:1531`
  (fixture), plus test fixtures in `proposal_vote_verify.rs`, `network.rs`,
  `driver.rs`. These are the engine’s own message constructors used by the
  self-driving/simulation harness. Production domain separation is carried by the
  64-bit runtime `ChainId` (`qbind-types/src/primitives.rs`) and the wire alias
  (`qbind-types/src/network_wire_alias.rs`), consumed by the v2 signing domain.
  **No global replacement of `chain_id: 1` is recommended**; the integration
  requirement is that emitted/accepted messages carry the runtime id and wire
  alias resolved from validated provenance and the authorized epoch.
* **Which bytes/signatures change if engine wire ids change.** The v2 signing
  preimage (`crates/qbind-wire/src/pv_signing_domain.rs`) binds the 64-bit
  `runtime_chain_id`, the 32-bit `expected_wire_chain_id`, the 32-byte genesis
  identity, and the authority commitment, then the message body (which itself
  contains the wire `chain_id` in `canonical_body`, `qbind-wire/src/consensus.rs`).
  Consequently, changing the engine’s wire `chain_id` changes **the signed
  preimage bytes and therefore every Proposal/Vote signature**, even if the
  serialized layout is byte-for-byte identical in shape. Verification also
  fail-closes earlier: `proposal_vote_verify.rs` rejects
  `expected_wire_chain_id() != header.chain_id` **before** any crypto
  (`WireChainMismatch`). Integration must therefore choose the wire id at
  immutable construction, once, from validated provenance.

### 4.C QC verification and proof preservation

The five concerns are explicitly distinct:

1. **Outer Proposal signature — PRESENT on binary path.**
   `binary_consensus_loop.rs` inbound Proposal arm calls
   `verify_proposal_msg_with_domain` (`proposal_vote_verify.rs:405`), fail-closed
   before engine ingest. The preimage covers the embedded-QC bytes (they are part
   of `canonical_body`), so the outer signature attests the QC bytes are
   untampered.
2. **Embedded-QC crypto verification — ABSENT on binary path.**
   `verify_quorum_certificate` (`qbind-consensus/src/lib.rs:705`) and its caller
   `verify_block_proposal` (`:807`, which checks `qc.block_id ==
   header.parent_block_id` then verifies each constituent signature and 2/3
   voting power) are **not reached from the binary path**. Their only non-test
   callers are the library functions `evaluate_proposal_for_vote` /
   `hotstuff_decide_and_maybe_record_vote` (`lib.rs:849`, `:906`), which are used
   by `Node<S>::apply_block` (`qbind-node/src/lib.rs:2577`) — a **separate**
   consensus/execution abstraction that `main.rs` does not construct (its
   `apply_block` callers are `execution_adapter.rs` tests/doc only). So this is
   not “never called anywhere,” but it **is** dormant relative to the release
   binary’s `BasicHotStuffEngine`.
3. **Logical vote counting / quorum formation — PRESENT.**
   `on_vote_event` (`basic_hotstuff_engine.rs:1567`) → `hotstuff_state_engine.rs`
   `on_vote` → `vote_accumulator.rs` `on_vote`/`maybe_qc_for` → `qc.rs` `validate`
   enforces membership, no-duplicate, and 2/3 voting-power. This is
   membership/power counting, **not** cryptographic certification.
4. **Constituent Vote signatures — PARTIAL.** The **outer** Vote signature is
   verified fail-closed (`verify_vote_msg_with_domain`, `proposal_vote_verify.rs`)
   before ingest. The **embedded QC’s** constituent vote signatures are **not**
   verified (see #2) and are discarded on conversion (#5).
5. **Wire↔logical QC conversion — PRESENT, information-losing.**
   `basic_hotstuff_engine.rs:1493` builds the logical QC with `vec![]` signers,
   discarding bitmap, signatures, suite, version, epoch, chain_id (see §3.2).

**Consequences, stated precisely.** A valid Proposal signature covering QC bytes
does **not** establish that the QC’s constituent signatures or quorum are valid.
A QC-formed counter does **not** by itself establish cryptographically verified
certification. **Existing upstream containment:** on the binary path the outer
Proposal/Vote signatures are verified fail-closed under
`ConsensusVerificationPolicy::Required` (`binary_consensus_loop.rs`), and — more
decisively — no production authority is wired (`main.rs:5549`), so Proposal/Vote
admission is closed regardless. No live exploit is inferred from the dormant
embedded-QC code.

### 4.D Admission and effect ordering

Ordering on the binary path (inbound Proposal arm, `binary_consensus_loop.rs`
≈`:4359`–`:4697`), each step fail-closed:

1. sender binding (`bind_sender`);
2. verifier selection — when a snapshot is wired, the verifier is
   `snap.verifier()`; `pv_authority` cannot substitute;
3. fresh admission `snap.owner().admit()` → ticket; epoch check
   `header.epoch == snap.authorized_epoch()`; no-snapshot + `Required` →
   `inbound_proposal_current_state_unavailable_total` (D7-A1);
4. wire-chain + crypto verify (D6/Run 420);
5. **re-confirm** ticket `snap.owner().confirm(&ticket)` immediately before
   effect (`inbound_proposal_authority_stale_before_effect_total` on failure);
6. restore-catchup deferral — the decoded proposal/ticket is **discarded** via
   early return (counter `restore_catchup_proposals_deferred`); **no queue is
   retained**; re-delivery re-runs the full pipeline;
7. reconfig observation recorded **after** auth checks, **before** engine call;
8. engine ingest `on_proposal_event`;
9. engine-produced Vote forwarded via `forward_actions_to_facade` with the same
   `current_auth`.

Outbound (`forward_actions_to_facade`, also from `do_leader_tick`) mirrors this:
per-action `admit` → epoch check → sign (fail-closed if signer context is `None`
under `Required`) → `confirm` before the facade effect. Cached late-peer
re-emission (`maybe_reemit_on_late_peer_connect` / `admit_cached_reemission`)
mints a `CachedReemissionProvenance` ticket at cache time in `do_leader_tick`,
then on re-emission performs a fresh `admit` + provenance `confirm` (issuer +
generation) + epoch check before signing and a final `confirm` before the facade.

**Credit for completed work (A1–A4, B1–B3):** sender binding, signature/suite
verification, D5 message-family split, D6 wire-chain consistency, engine
integration, and restore deferral are proven for their scoped behavior and are
**not reopened here**. The distinction between synchronous admission/immediate
handoff, queued/later socket delivery, serialized replacement, concurrent
invalidation (generation counter + `Arc::ptr_eq` issuer identity), and restart
freshness is preserved. **Unresolved:** persistent/durable current-authorization
state and **anti-rollback** — production can only construct `unavailable` owners
(`genesis_consensus_authority.rs:1125`); the `Established` local state exists only
under `cfg(test)` (`establish_for_fixture`).

### 4.E Existing mechanisms and duplication risk

| Future behavior | Existing implementation | Classification |
|---|---|---|
| Validator membership for engine + verifier | `ConsensusValidatorSet` shared as `Arc` (`genesis_consensus_authority.rs`, snapshot coherence `binary_consensus_loop.rs:1266`) | **Reusable unchanged** |
| Suite-aware key lookup | `GenesisConsensusKeyProvider : SuiteAwareValidatorKeyProvider` (`genesis_consensus_authority.rs`) | **Reusable unchanged** |
| Outer Proposal/Vote verification | `verify_proposal_msg_with_domain` / `verify_vote_msg_with_domain` (`proposal_vote_verify.rs`) | **Reusable unchanged** |
| Timeout/NewView verification | `timeout_verification_bridge.rs` + `verify_timeout_*` | **Reusable unchanged (separate boundary)** |
| Current-state freshness gate | `GenesisConsensusAuthority::authorize_current_state` / `authorize_configuration` | **Reusable with narrow extension** (persist an immutable observed snapshot; never mutate) |
| Bind owner↔verifier | `AuthorizedProposalVoteSnapshot::try_bind` (`binary_consensus_loop.rs:1245`) | **Reusable with narrow extension** (real chain label + authorized wire id) |
| Embedded-QC crypto verification on binary path | `verify_quorum_certificate` / `verify_block_proposal` (`lib.rs`) | **Not connected to this binary path** (wired only into `Node<S>::apply_block`) |
| Genesis-provenance-fed Proposal/Vote authority in production | — | **Missing** (`main.rs:5549` = `None`) |
| Runtime→wire chain-id mapping for a production authority | — | **Missing** (`authorized_wire_chain_id: None`) |
| Durable current-authorization state / anti-rollback | `Established` local state is `cfg(test)` only | **Fixture-only** (persistence missing) |

**Similarly-named ≠ duplicate.** `ProposalVoteAuthority` (Proposal/Vote signing
keys) vs `TimeoutVerificationContext` (Timeout/NewView) are different message
families split deliberately at D5. `GovernanceAuthority*` /
`PQCAuthorityMarkerAcceptance` / custody-attestation verifiers govern bundle
signing / marker attestation / custody aliveness — **orthogonal trust models**,
not consensus signing. Prefer the shared `ConsensusValidatorSet` + key provider
+ v2 signing domain over any parallel identity registry. Do **not** delete these
established APIs; caller evidence shows they serve distinct boundaries.

---

## 5. Integration contract and dependency order

All steps below can be implemented **while activation remains disabled**
(`main.rs:5549` stays `None` until the final, separately-authorized step) and
while `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR` stays UNCHANGED.

**Dependency order (each independently testable):**

1. **Resolve a real chain-identity label + authorized wire chain id from
   validated provenance** on the authority (owner of data:
   `GenesisConsensusAuthority`; consumers: `try_bind` `:1281`/`:1295`,
   `snapshot_chain_identity_label`). Trusted inputs: boot-verified genesis
   runtime `ChainId` + C3A wire alias. Fail-closed: mismatch/none → no bind.
   Wire/signature implication: none until a snapshot is actually wired.
   Prerequisite: the protocol decision in §5.1.
2. **Construct `AuthorizedProposalVoteSnapshot` by cloning the same `Arc`s** out
   of one boot-validated authority (owner: authority; consumer: `try_bind`).
   Fail-closed: any `Arc::ptr_eq` / membership / commitment mismatch → reject.
   Still not wired into `main` (kept behind the disabled flag).
3. **Unify engine membership with the authority membership** so
   `BasicHotStuffEngine::new` receives the authority’s `Arc<ConsensusValidatorSet>`
   (owner: authority; consumer: `basic_hotstuff_engine.rs:508`). Fail-closed:
   engine set must equal verifier set by `Arc` identity.
4. **Embedded-QC verification on the binary path** — invoke the existing
   `verify_quorum_certificate` (or an equivalent that consumes the *retained*
   wire QC) so a Proposal’s embedded QC has its constituent signatures and 2/3
   power verified, and stop discarding signer/signature/epoch on conversion
   (`basic_hotstuff_engine.rs:1493`). Owner: engine; consumer: state engine
   locking/commit. Fail-closed: invalid embedded QC → reject proposal.
5. **Wire the snapshot into `main`** (the only step that actually enables
   authority) — explicitly out of scope here and gated behind the disabled flag.

**Performance (concrete, no invented numbers):** membership, key provider,
chain-identity label, and authorized wire id are **immutable-construction**
checks (compute once per authority). Per-message checks that must remain
per-message: sender binding, wire-chain equality, outer signature, admit/epoch/
confirm. Avoid re-scanning the validator set per signer where a precomputed index
already exists (`ConsensusValidatorSet::index_of`), and avoid re-verifying the
same embedded QC more than once per proposal.

**Acceptance tests the contract must include** (distinguishing categories that
must never be conflated):

* correct-domain acceptance vs wrong-network/genesis rejection (v2 domain
  runtime id + genesis identity mismatch → `WireChainMismatch` / verify reject);
* valid outer Proposal signature **with an invalid embedded QC** → **reject**
  (guards §4.C #1 vs #2);
* actual verified quorum vs mere logical vote counting (a logical QC with 2/3
  ids but no valid signatures must not be treated as certified);
* membership / key / suite mismatch → fail-closed (`Arc::ptr_eq`, suite id);
* stale authorization vs current authorization (generation advanced between
  `admit` and `confirm` → `Stale`);
* preserved certificate evidence vs information-losing conversion (signers /
  signatures / epoch retained through wire→logical).

### 5.1 Precise open protocol decision (blocks step 1)

**Decision required:** what is the canonical **wire chain id** (and its binding
to the 64-bit runtime `ChainId`) that a genesis-validated production authority
must carry, and how is it derived — directly from the C3A wire alias, or from a
separately ratified value? Until this is fixed, `authorized_wire_chain_id`
cannot leave `None` without inventing a default, which this audit refuses to do.
The mapping must be defined so that `try_bind`’s wire-chain check (`:1295`) and
the v2 preimage’s `expected_wire_chain_id` agree by construction.

---

## 6. Single recommended next implementation task

**Task: Verify a Proposal’s embedded QC on the binary consensus path and stop
discarding its certificate evidence.**

* **Problem it solves.** Today the binary path verifies the outer Proposal
  signature but neither verifies the embedded QC’s constituent vote signatures
  nor retains them: `basic_hotstuff_engine.rs:1493` converts the wire QC to a
  logical QC with `vec![]` signers, and `verify_quorum_certificate`
  (`lib.rs:705`) is never reached from `BasicHotStuffEngine`. A syntactically
  valid Proposal can therefore carry an unverified/forged embedded QC.
* **Permitted files and functions.**
  `crates/qbind-consensus/src/basic_hotstuff_engine.rs` (embedded-QC ingest at
  `on_proposal_event` / the `:1490`–`:1506` conversion);
  `crates/qbind-consensus/src/qc.rs` (only to carry retained evidence if needed);
  read-only reuse of `crates/qbind-consensus/src/lib.rs`
  `verify_quorum_certificate` / `verify_block_proposal`; new tests under
  `crates/qbind-consensus/tests/`. **No** edits to `main.rs`,
  `binary_consensus_loop.rs` authority wiring, or the C2/C3A/C3B module.
* **Required behavior.** Before an embedded QC is accepted into engine state,
  verify its constituent signatures and 2/3 voting power against the engine’s
  validator set and key material, and preserve the signer set (and enough
  evidence to re-verify) through the conversion instead of `vec![]`. Reject the
  proposal fail-closed on any embedded-QC verification failure.
* **Non-goals.** Not enabling production Proposal/Vote authority; not wiring the
  snapshot; not changing wire `chain_id` behavior; not touching genesis
  correspondence, storage, or anti-rollback; not a global `chain_id: 1` change;
  not a whole-engine rewrite.
* **Acceptance tests.** (a) Proposal with a valid outer signature but an embedded
  QC whose signatures are invalid → rejected. (b) Proposal with a genuinely
  verified embedded QC (2/3 valid signatures) → accepted and signer evidence
  retained. (c) Embedded QC below 2/3 power → rejected. (d) Embedded QC referring
  to a mismatched block/parent → rejected. (e) Regression: outer-signature-only
  paths and existing engine sims unchanged.
* **Why it can proceed without enabling production authority.** It operates on
  the engine’s existing, already-reachable QC-ingest code and reuses an existing
  verifier; it does not construct or wire `ProposalVoteAuthority`, does not flip
  `main.rs:5549`, and leaves `authorized_wire_chain_id`, activation, and the §5.1
  wire-id decision untouched. It strictly narrows attacker capability rather than
  granting any new authority.

**Sequenced (not part of this next task):** §5 steps 1–3 (chain-identity + wire
id resolution, snapshot-by-shared-`Arc`, engine/verifier membership unification),
then the §5 step 5 activation wiring, then durable freshness / anti-rollback.
None of these is completed by the single task above, and the task alone does not
constitute activation.

---

## 7. Checks actually executed and tool limitations

* **Executed here:** repository inspection only — `git status`, `git log`,
  `git rev-parse HEAD`, `git rev-list --count HEAD` (=2), `cat .git/shallow`,
  `git cat-file -t 734a9425…` (object absent), and `rg`/`grep` source searches
  cited inline. No Rust build, test, or release rebuild was run (not required for
  a documentation-only audit).
* **No historical result is relabelled as newly executed.** The focused
  `cargo test` results in the D7 evidence file remain attributed to their
  original passes.
* **CodeQL / reviewer posture unchanged.** Prior CodeQL SKIPPED/INCOMPLETE and
  qualified reviewer outcomes stand as recorded; “no comments” from an
  unavailable reviewer and “0 alerts” alongside a skipped scan are **not**
  treated as successful analyses.

---

## 8. Status

```
D7C3C_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT=COMPLETE-FOR-INSPECTED-SCOPE
PRODUCTION_INTEGRATION=NOT-PERFORMED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

The audit is **COMPLETE-FOR-INSPECTED-SCOPE**. The only material inspection
limitation is the shallow clone (§1.2): the task’s named reviewed revision
`734a9425…` is not present, so ancestry could not be confirmed; all findings are
anchored to HEAD `0b3eb4a`, which carries the C2/C3A/C3B source. No readiness
item moves Green.