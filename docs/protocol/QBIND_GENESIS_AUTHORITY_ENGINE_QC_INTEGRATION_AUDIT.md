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

Inspected against the **actual supplied worktree**, not the SHAs the task text
recites:

* **Working branch (actual):** `copilot/copilotrun-422-d7-c3c`
  (`git branch --show-current`). The task text names the reviewed branch
  `copilot/run-422-d7-c3c`; the actual checkout carries the doubled `copilot`
  path segment.
* **Inspected worktree HEAD (actual):**
  `b7a38c6145d947499c0a4be8e2dbd6c87627f63a` (`update`) — the C3C-correction
  revision this session started from. Its parent
  `819f2b28ff05fc10f2b0b6c23af52808ac996cad` (`update`) first added this audit
  document and the C3C evidence entry; both are present locally.
* **Shallow boundary (actual):** `.git/shallow` now pins
  `819f2b28ff05fc10f2b0b6c23af52808ac996cad` (the parent of HEAD). The task's
  named **inspected source revision**
  `0b3eb4a19530f8ecf21b25212f92aa944473e154` is the parent of that boundary and
  is therefore **beyond the graft and absent** (`git cat-file -t 0b3eb4a…` →
  *could not get object info*); it is no longer a local object.
* **Reviewed final revision named by the task,
  `9cc94ab7dfacb2824de7aad76abd5573532a9f47`, is absent** from this clone
  (`git cat-file -t 9cc94ab7…` → *could not get object info*).
* The earlier-named `3a5ac02c06eb4a62368f6c922a911946b48b01df` and
  `734a9425a15f8a5845b8bf0bdb4932b700d9cc22` are likewise **absent**. Ancestry to
  any absent object is **not manufactured**.

### 1.2 Ancestry limitation (reported accurately)

The clone is **shallow with depth 2** (`git rev-list --count HEAD` = 2;
`.git/shallow` pins the boundary `819f2b2`, the parent of HEAD `b7a38c6`).
Therefore:

* The source tree is **unchanged between the shallow boundary `819f2b2` and HEAD
  `b7a38c6`** — the only differences are the two documentation files this run may
  touch (`git diff --stat 819f2b2 b7a38c6` = this audit + the D7 evidence file).
  So every source finding below is anchored to the worktree at HEAD.
* The task's named **inspected source revision `0b3eb4a`** is the parent of the
  shallow boundary and is **absent**, so a `git diff` against it can no longer be
  recomputed here. The prior C3C revision (at `819f2b2`, when `0b3eb4a` was still
  the pinned boundary) recorded `git diff --stat 0b3eb4a 819f2b2` as docs-only;
  that recorded fact is preserved but is **not** re-derived, and no ancestry to
  the now-absent `0b3eb4a` is manufactured.
* Ancestry to the task's **reviewed final revision `9cc94ab7…`** (and the
  earlier `3a5ac02…` / `734a9425…`) **cannot be established** from local history
  because those objects are absent. The worktree **content** corresponds to the
  completed D7-C2 / C3A / C3B work (module
  `genesis_authority_record_correspondence.rs` present with `load_pinned`,
  retained `validation_policy`, and `check_network_correspondence` — see §4.A),
  but **content correspondence does not establish ancestry** and is not claimed
  to.

All findings below are anchored to paths and symbols **as they exist in the
worktree at HEAD `b7a38c6` (source-identical to the shallow boundary
`819f2b2`)**. Every material finding cites `path:line`. Findings are **source
evidence** unless explicitly marked as executed behavior (§7).

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
| 1 | Boot genesis verification (external file + optional pin) | `main.rs:2382` `pqc_boot_genesis::run_boot_time_genesis_verification(&config)` | Yes, but **conditional**: for permitted non-MainNet configs without an external genesis it returns `BootGenesisOutcome::SkippedNoExternalGenesis` (`pqc_boot_genesis.rs:229`). Supplying `--genesis-path` provides only the external genesis **file** (`:225`, `:238`); the independent **expected-hash pin** is a separate input `config.expected_genesis_hash` (`:240`, `--expect-genesis-hash`). Verification (`verify_boot_time_genesis`, `qbind-ledger/src/genesis.rs:1797`) applies the environment policy from `map_environment`: MainNet **requires** both the path (`GenesisPathMissing`, `:227`) and the pin (`ExpectedCanonicalHashMissing`, `genesis.rs:1836`); DevNet/TestNet **permit an absent pin**, in which case the canonical-hash compare is **skipped** (`genesis.rs:1850`/`:1852`) — a supplied path alone does **not** establish an independent pin |
| 2 | Consensus security preflight | `crates/qbind-node/src/main.rs:5019` `run_p2p_consensus_security_preflight` (called `:7502`) | Yes |
| 3 | Proposal/Vote authority slot | `crates/qbind-node/src/main.rs:5549` `proposal_vote_authority: None` (field `:5016`) | Yes — **wired to `None`** |
| 4 | Timeout-bridge validator set + key provider | `crates/qbind-node/src/peer_key_provider.rs` `build_validator_set_and_key_provider` (from `config.network.static_peer_consensus_keys`) | Yes — feeds the **Timeout verification bridge only** (`try_build_timeout_verification_context`), **not** the engine's membership |
| 5 | Engine membership construction | `crates/qbind-node/src/binary_consensus_loop.rs:2308` `build_uniform_validator_set(cfg.num_validators)` (`:700`) → `BasicHotStuffEngine::new(cfg.local_validator_id, validators)` | Yes — engine set is a **uniform, power-1 set built from the validator count**, distinct from boundary 4 |
| 6 | Engine construction | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:508` `BasicHotStuffEngine::new(local_id, validators)` — takes `ConsensusValidatorSet` **by value** (not `Arc`) | Yes |
| 7 | Inbound Proposal admission + verify + ingest | `crates/qbind-node/src/binary_consensus_loop.rs` inbound Proposal arm (≈`:4359`–`:4697`) | Yes |
| 8 | Inbound Vote admission + verify + ingest | `binary_consensus_loop.rs` inbound Vote arm (≈`:4833`–`:4929`) | Yes |
| 9 | Outbound forwarding | `binary_consensus_loop.rs` `forward_actions_to_facade` (≈`:4046`) | Yes |
| 10 | Leader step | `binary_consensus_loop.rs` `do_leader_tick` (≈`:3189`) | Yes |
| 11 | Late-peer cached re-emission | `binary_consensus_loop.rs` `maybe_reemit_on_late_peer_connect` (≈`:3324`) | Yes |
| 12 | Restore-catchup deferral | `binary_consensus_loop.rs` restore deferral (≈`:4632`) | Yes (restore mode) |
| 13 | Engine QC ingest (wire→logical, embedded justify QC) | `basic_hotstuff_engine.rs:1490`–`1506` → `hotstuff_state_engine.rs:422` `register_block` | Yes (via `on_proposal_event`; **stored as `BlockNode.justify_qc`, not routed to `on_qc`** — §3.3) |
| 14 | Locally-formed QC → `on_qc` | `basic_hotstuff_engine.rs:1567` `on_vote_event` → `hotstuff_state_engine.rs:517` `on_vote` → `:560` `on_qc` | Yes (only for QCs formed from **received votes**, not embedded ones) |
| 15 | Embedded-QC crypto verify (legacy) | `crates/qbind-consensus/src/lib.rs:705` `verify_quorum_certificate` / `:807` `verify_block_proposal` | **No** (compiled but unreached from the binary path; §4.C) |
| 16 | Genesis correspondence module | `crates/qbind-node/src/genesis_authority_record_correspondence.rs` | **No** (test-only callers; §4.A) |

**Key structural fact:** the same verifier and the same admission owner are held
together in `AuthorizedProposalVoteSnapshot` (`binary_consensus_loop.rs:1176`),
but **no production code constructs that snapshot** — `main.rs:5549` supplies
`proposal_vote_authority: None`. The rejection paths that the task requires be
kept separate follow directly from the handler's own two match arms (inbound
Proposal arm, `binary_consensus_loop.rs` ≈`:4359`–`:4697`; inbound Vote arm
≈`:4833`–`:4929`).

Under `Required`, after successful F6 sender binding, the handler first selects
its **effective verifier**. A supplied authorization snapshot (`current_auth`)
selects its **bound** verifier (`snap.verifier()`, `:4423`); otherwise the
separately supplied Proposal/Vote authority (`pv_authority`) is considered.

| Condition | Result | Timing |
|---|---|---|
| No effective Proposal/Vote authority | Increment `inbound_proposal_verification_context_unavailable_total` or `inbound_vote_verification_context_unavailable_total`; reject | Before crypto |
| Effective verifier present, `current_auth` absent | Increment `inbound_proposal_current_state_unavailable_total` or `inbound_vote_current_state_unavailable_total`; reject | Before crypto |
| Bound snapshot present, `owner.admit()` rejects | Record the applicable admission failure; reject | Before crypto |
| Admission and verification succeed, `owner.confirm(ticket)` rejects | Increment the applicable `authority_stale_before_effect` counter; reject | After verification, before downstream effects |

A missing owner cannot confirm a ticket and **never reaches the confirmation
check**. A missing-owner admission failure must **not** be described as a
post-crypto `Stale` rejection: with `current_auth == None` the handler stops at
the current-state-unavailable arm (`:4492`), before any crypto and long before
`owner.confirm(ticket)`.

Current production supplies **no** Proposal/Vote authority and **no**
authorization snapshot (`main.rs:5549` = `None`); it matches the first row. Its
authority-absent path therefore rejects **before** cryptographic verification
(via `inbound_proposal_verification_context_unavailable_total` /
`inbound_vote_verification_context_unavailable_total`, `:4593`), and outbound
emission is suppressed.

Additionally, **compiled ≠ reachable**: several verification branches (the legacy
embedded-QC verifier at boundary 15, the D6 authority-bound Proposal/Vote
verifier) are compiled into the binary. **D6 signature verification is an
implemented conditional path** — it runs `verify_proposal_msg_with_domain` /
`verify_vote_msg_with_domain` (`:4522`) only inside the effective-verifier arm,
after admission succeeds. Because current production wires no authority/snapshot,
that arm is never entered, so D6 verification is **not exercised by current
production**; describe it as implemented-and-conditional, never as cryptographic
acceptance that current production actually performs.

---

## 3. Trust-source and information-preservation tables

### 3.1 Trust source per boundary

| Boundary (path:symbol) | Trusted input | Untrusted input | Identity/membership/domain/epoch available | Retains | Production reachable |
|---|---|---|---|---|---|
| `genesis_authority_record_correspondence.rs:156` `load_pinned` | operator pin `GenesisHash`, env policy | genesis file bytes | chain_id, genesis_hash, authority commitment, validator_count, founding epoch 0, `validation_policy` | all of these (`:189`, `:221`) | No (test-only callers) |
| `genesis_authority_record_correspondence.rs` `check_network_correspondence` | retained `validation_policy`, selected env, supplied runtime `ChainId` | — | env policy vs runtime alias (via C3A) | immutable-borrow `GenesisNetworkCorrespondence` | No |
| `genesis_consensus_authority.rs` `build_genesis_consensus_authority` (→ `:439`) | boot-verified `GenesisConfig.validators[]` (suite, pk) | — | `Arc<ConsensusValidatorSet>`, key provider, genesis_hash, commitment, `authorized_epoch=0`, `authorized_wire_chain_id: None` | full authority | Boot-validation only; not fed to Proposal/Vote authority |
| `binary_consensus_loop.rs:1245` `try_bind` | owner candidate + verifier (shared `Arc`) | — | genesis hash, commitment, membership, key provider, chain label, wire chain id | `AuthorizedProposalVoteSnapshot` | No (test-only) |
| `binary_consensus_loop.rs` inbound Proposal verify → `proposal_vote_verify.rs:405` `verify_proposal_msg_with_domain` | bound domain, validator set, key provider | wire Proposal bytes | proposer index, wire chain id, v2 domain (runtime+wire+genesis+commitment+epoch) | pass/fail only | **Implemented conditional path** — runs only inside the effective-verifier arm after admission (`:4522`); **not exercised by current production** (no authority/snapshot wired, `main.rs:5549`) |
| `basic_hotstuff_engine.rs:1567` `on_vote_event` → `hotstuff_state_engine.rs` `on_vote` → `vote_accumulator.rs` / `qc.rs:` `validate` | validator set membership + voting power | logical vote (id, view, block) | ValidatorIds, view, voting power | logical QC (ids only) | Yes |

### 3.2 Wire-QC → logical-QC information preservation (`basic_hotstuff_engine.rs:1490`)

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
cryptographic material is not carried and cannot be re-verified downstream. It is
stored on the block node as `BlockNode.justify_qc` by
`hotstuff_state_engine.rs:422` `register_block` and is consulted only by the
safety-to-vote rule (`is_safe_to_vote_on_block`, `hotstuff_state_engine.rs:877`,
a `justify_qc.view >= locked_qc.view` comparison). **It is not routed through
`on_qc`** (see §3.3), so no locking/commit decision is taken directly from an
embedded justify QC on ingest.

### 3.3 Three QC information flows, traced separately

The task requires these be kept distinct; they are different code paths with
different retained information:

1. **Embedded wire QC → logical justify QC → `register_block`.**
   `on_proposal_event` (`basic_hotstuff_engine.rs:1446`) converts
   `proposal.qc` at `:1490` to `QuorumCertificate::new(block_id, height, vec![])`
   and passes it to `state.register_block` (`:1506` →
   `hotstuff_state_engine.rs:422`). It is stored as `BlockNode.justify_qc`. Only
   `block_id` and `view` survive; **bitmap, signatures, suite, version, epoch,
   chain_id, round, step are absent** (§3.2). This justify QC is **not** given to
   `on_qc`; it only feeds the `justify_qc.view >= locked_qc.view` safety check.
2. **Received Votes → accumulator → locally formed QC → `on_qc`.**
   `on_vote_event` (`:1567`) → `state.on_vote` (`hotstuff_state_engine.rs:517`) →
   `votes.on_vote` / `votes.maybe_qc_for` (`vote_accumulator.rs`) → when a quorum
   forms, `on_qc` (`hotstuff_state_engine.rs:560`) updates `locked_qc`, attaches
   `own_qc` to the block, and runs the 3-chain commit
   (`try_commit_with_qc`). This QC is assembled from **locally counted vote ids**;
   the logical QC still carries **ids only, no signatures** — counting is not
   cryptographic certification.
3. **Logical QC → emitted wire QC.**
   `on_leader_step` (`basic_hotstuff_engine.rs:1284`, ≈`:1365`) maps the engine's logical
   `justify_qc` into a wire `QuorumCertificate` with
   **`signer_bitmap: vec![]`, `signatures: vec![]`** (`:1370`–`:1381`). So even a
   locally-formed QC is emitted on the wire **carrying no signer set and no
   signatures**; a downstream peer receiving it (flow 1) can never re-verify it.

**Where certificate information is discarded or absent:** at flow 1's `:1490`
conversion (all crypto fields dropped to `vec![]`), at flow 3's `:1370` emission
(bitmap/signatures emitted empty), and structurally in the logical `qc.rs`
`QuorumCertificate<BlockIdT>` type itself, whose only signer field is
`signers: Vec<ValidatorId>` (no signatures, suite, epoch, or domain). No point in
these three flows ever holds a re-verifiable embedded certificate.

### 3.4 State changes before a would-be QC-verification insertion point

Any future embedded-QC verification must be placed with awareness of state
already mutated on ingest. In `on_proposal_event`, **before** the `:1506`
`register_block` call:

* `proposal.header.epoch != self.current_epoch` is rejected (`:1452`);
* for a future view, **view is advanced** — `self.current_view = view` at
  `:1461`, and `proposed_in_view` / `voted_in_view` are reset — *before* the
  block or its justify QC is registered;
* leader-for-view and no-double-vote checks (`:1471`, `:1478`) run.

Consequently a future invalid-embedded-QC rejection inserted at or after
`register_block` would **not** by itself undo the already-applied view
advancement at `:1461`; a correct design must either reject before `:1461` or
specify explicitly which effects (view advance, block registration, self-vote,
lock/commit) it prevents. This audit does **not** assert that inserting a check
later automatically neutralizes the earlier view advance.

### 3.5 Serialization users of the logical QC type

The logical `QuorumCertificate<BlockIdT>` (`qc.rs:28`) derives
`serde::Serialize, serde::Deserialize` and is embedded as
`TimeoutMsg.high_qc` (`timeout.rs:78`, itself serde-derived `:72`) and used by
`driver.rs` and `remote_signer.rs` (`:414`). **Adding evidence fields (signer
bitmap, signatures, suite, epoch) to this shared type is therefore not
free**: it changes `TimeoutMsg` serialization and any snapshot/remote-signer
payloads that carry it. Evidence retention consequently has wire/serialization
compatibility implications and cannot be assumed layout-neutral; a future task
that needs retained evidence must decide whether to carry it in a separate type
rather than mutate the shared logical QC.

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

* **The engine set and the timeout-bridge set are different objects built from
  different sources.** The production engine membership is
  `build_uniform_validator_set(cfg.num_validators)`
  (`binary_consensus_loop.rs:2308` → `:700`): a **uniform, voting-power-1** set
  keyed only on the validator *count*, passed **by value** into
  `BasicHotStuffEngine::new(local_id, validators)`
  (`basic_hotstuff_engine.rs:508` — the parameter is `ConsensusValidatorSet`, not
  `Arc<ConsensusValidatorSet>`). Separately,
  `build_validator_set_and_key_provider` (`peer_key_provider.rs`, from
  `config.network.static_peer_consensus_keys`) supplies an
  `Arc<ConsensusValidatorSet>` + `Arc<dyn SuiteAwareValidatorKeyProvider>` **only
  to the Timeout verification bridge** (`try_build_timeout_verification_context`
  / `timeout_verification_bridge.rs`), which performs fail-closed
  membership/suite cross-checks (local-in-set, key present, suite == ML-DSA-44
  `SUPPORTED_TIMEOUT_SUITE_ID`). **Do not describe the timeout-bridge validator
  set as the engine's actual input** — the engine never receives it. Neither set
  is the genesis-validated authority set. Unifying all three is an integration
  requirement, not an existing guarantee, and is additionally constrained by the
  engine taking its set by value (it cannot today share an `Arc` instance with a
  verifier).
* **`chain_id: 1` message constructors are ordinary engine code, not test
  fixtures.** The literal `chain_id: 1` at `basic_hotstuff_engine.rs:1351`
  (proposal header), `:1370` (embedded QC), and `:1405` (leader vote) is inside
  the ordinary engine method `on_leader_step` (`:1284`); the fourth occurrence,
  `:1531` (the responding Vote), is inside the ordinary engine method
  `on_proposal_event` (`:1446`) — **not** a test-only fixture. All four are
  above the crate's `#[cfg(test)]` boundary (`:1921`). Only the `chain_id: 1`
  literals in `proposal_vote_verify.rs` (`:629`/`:661`/`:830`), `network.rs`
  (`:192`/`:210`), and `driver.rs` (`:752`/`:770`) are test-scoped (under
  `#[cfg(test)]`). Distinguish three layers: (a) **ordinary engine
  implementation** — `on_leader_step` / `on_proposal_event` construct these
  messages whenever the engine ticks; (b) **conditional reachability through the
  binary handler** — the binary loop's `do_leader_tick` and inbound arms drive
  the engine, so the constructors run in production; (c) **current Required /
  no-authority containment** — what is guarded is **signing and transmission**,
  not construction: the constructed Proposal/Vote carry `signature: vec![]` and
  are only signed/emitted through `forward_actions_to_facade`, which fail-closes
  under `Required` with no authority (`main.rs:5549` = `None`), so no
  `chain_id: 1` message is ever authenticated or placed on the wire today.
  Distinguish *"the constructor runs"* (true) from *"a `chain_id: 1` message is
  signed/transmitted"* (false under current startup). Production domain
  separation, when authority is eventually wired, is carried by the 64-bit
  runtime `ChainId` (`qbind-types/src/primitives.rs`) and wire alias
  (`qbind-types/src/network_wire_alias.rs`) in the v2 signing domain. **No global
  replacement of `chain_id: 1` is recommended**; the requirement is that
  signed/emitted messages carry the runtime id + wire alias resolved from
  validated provenance and the authorized epoch.
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
   `basic_hotstuff_engine.rs:1490` builds the logical QC with `vec![]` signers,
   discarding bitmap, signatures, suite, version, epoch, chain_id (see §3.2), and
   stores it via `register_block` (not `on_qc`, §3.3).

**Consequences, stated precisely.** A valid Proposal signature covering QC bytes
does **not** establish that the QC’s constituent signatures or quorum are valid.
A QC-formed counter does **not** by itself establish cryptographically verified
certification. **Existing upstream containment:** on the binary path the outer
Proposal/Vote signatures are verified fail-closed under
`ConsensusVerificationPolicy::Required` (`binary_consensus_loop.rs`), and — more
decisively — no production authority is wired (`main.rs:5549`), so Proposal/Vote
admission is closed regardless. No live exploit is inferred from the dormant
embedded-QC code.

#### 4.C.1 Verifier compatibility: legacy QC verifier vs the D6 signed input

The two verification paths bind **different signed inputs** and use **different
interfaces**; they are not interchangeable for D6-signed material.

**Legacy `verify_quorum_certificate` (`lib.rs:705`).** For each bitmap bit it
reconstructs a `Vote` from the QC header fields and computes
`vote_digest(&vote)` (`qbind-hash/src/consensus.rs:8`), then verifies it with
`crypto.signature_suite(vinfo.suite_id).verify(&vinfo.consensus_pk, &digest,
sig)`. Its interfaces are the legacy `ValidatorSet`/`ValidatorInfo`
(`lib.rs:169`, `:178`) and a `CryptoProvider`. The **signed input is
`vote_digest`** =
`sha3_256_tagged("QBIND:VOTE", chain_id(u32) ‖ height ‖ round ‖ step ‖ block_id ‖
validator_index ‖ suite_id)`. Note it **omits `version` and `epoch`** and
carries **no domain**: no runtime chain id (u64), no genesis identity, no
authority commitment, no signing-format version/family tag.

**D6 `verify_vote_msg_with_domain` (`proposal_vote_verify.rs:511`).** It first
rejects `domain.expected_wire_chain_id() != vote.chain_id`, then verifies the
signature over `domain.vote_preimage(vote)` using `ConsensusValidatorSet`, a
`SuiteAwareValidatorKeyProvider`, and a `ConsensusSigBackendRegistry`. The
**signed input is the D6 preimage** (`pv_signing_domain.rs:267`,
`build_preimage`) =
`PV_SIGNING_DOMAIN_V2_TAG ‖ v2 ‖ family=Vote ‖ runtime_chain_id(u64 BE) ‖
expected_wire_chain_id(u32 BE) ‖ genesis_identity(32) ‖ authority_commitment(32)
‖ len(body) ‖ vote.canonical_body()`, where `canonical_body`
(`consensus.rs:206`) = `version ‖ chain_id ‖ epoch ‖ height ‖ round ‖ step ‖
block_id ‖ validator_index ‖ suite_id`. The message is passed **un-pre-hashed**
to the suite backend (the backend hashes internally), unlike the legacy path
which verifies over a precomputed sha3-256 digest.

**Omitted fields / differing inputs / representation differences:**

* The legacy digest omits `version`, `epoch`, and the **entire D6 domain**
  (tag, format version, family, runtime chain id, genesis identity, authority
  commitment). A signature produced over the D6 preimage therefore **cannot**
  verify against the legacy digest, and vice versa — even for the same key and
  the same logical vote fields.
* Interfaces differ: legacy `ValidatorSet`/`ValidatorInfo` + `CryptoProvider`
  (with a caller-set `qc_threshold`) vs D6 `ConsensusValidatorSet` +
  `SuiteAwareValidatorKeyProvider` + `ConsensusSigBackendRegistry`.
* Suite/index representation differs: legacy derives the signer `vindex` from the
  **bitmap position** and reads `vinfo.suite_id`/`consensus_pk` from the legacy
  set; D6 reads `vote.validator_index` and resolves the suite/key through the
  key provider with explicit membership checks.

**Classification.** The legacy `verify_quorum_certificate` is **not reusable
unchanged for D6-signed Votes**: its structural checks are reusable, but its
signature verification is incompatible with the D6 signed input. Specifically:

* **Reusable structural checks** (independent of the signed bytes): the
  bitmap↔signature-count correspondence (`popcount(bitmap) ==
  signatures.len()`, else `BitmapLengthMismatch`), bit→index decoding, and
  voting-power accumulation with an overflow guard.
* **Incompatible signature verification**: the `vote_digest`-based per-signer
  check must be replaced by D6 domain-bound verification
  (`verify_vote_msg_with_domain`-style, over `domain.vote_preimage`) reusing the
  established membership/key/backend interfaces. A D6-compatible QC verifier must
  **reconstruct the exact Vote fields originally signed** and re-derive the D6
  preimage; it must **not** fall back to the legacy digest.

#### 4.C.2 Quorum rules and their sources (do not silently equate)

Three different "2/3"-shaped quantities appear and must not be conflated:

* **Legacy `qc_threshold`** — a caller-supplied `u64` field on the legacy
  `ValidatorSet` (`lib.rs:182`); `verify_quorum_certificate` requires
  `total_power >= vs.qc_threshold`. Its value is **whatever the caller set**; it
  is not computed and not guaranteed to be 2/3 of anything.
* **Engine `two_thirds_vp()`** — `ConsensusValidatorSet::two_thirds_vp()`
  (`validator_set.rs:491`) = `ceil(2 * total_voting_power / 3)`, used by the
  accumulator/`qc.rs:106` when forming a QC from received votes.
* **"2f+1"** — a count-based BFT bound that coincides with `two_thirds_vp()`
  **only** under equal voting power with `n = 3f+1`. For **arbitrary weighted
  memberships** these three are not equal.

The audit records these bounds and their sources without changing any protocol
rule. A future D6-compatible QC verifier must state which rule it enforces (it
should use the membership's actual voting-power threshold, `two_thirds_vp()`,
computed from the trusted `ConsensusValidatorSet`, **not** a caller-supplied
scalar or an assumed `2f+1`).



### 4.D Admission and effect ordering

Ordering on the binary path (inbound Proposal arm, `binary_consensus_loop.rs`
≈`:4359`–`:4697`), each step fail-closed:

1. sender binding (`bind_sender`);
2. effective-verifier selection — when a snapshot is wired, the verifier is the
   snapshot's **bound** `snap.verifier()`; otherwise `pv_authority` is considered
   but cannot substitute snapshot-bound membership/keys/suite/domain/epoch. With
   **no** effective verifier at all under `Required` →
   `inbound_proposal_verification_context_unavailable_total` /
   `inbound_vote_verification_context_unavailable_total` (before crypto);
3. current-state gate: with an effective verifier but `current_auth == None`
   under `Required` → `inbound_proposal_current_state_unavailable_total` /
   `inbound_vote_current_state_unavailable_total` (D7-A1, before crypto); with a
   bound snapshot, fresh admission `snap.owner().admit()` → ticket (an admission
   failure here is recorded before crypto); epoch check
   `header.epoch == snap.authorized_epoch()`;
4. wire-chain + crypto verify (D6/Run 420);
5. **re-confirm** ticket `snap.owner().confirm(&ticket)` immediately before
   effect (`inbound_proposal_authority_stale_before_effect_total` on failure — a
   `Stale` outcome reachable only after admission and verification already
   succeeded, never for a missing owner);
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
**not reopened here**. A4 demonstrates serialized synchronous handler ordering
under the existing immutable-borrow model. Issuer identity and generation checks
do not, by themselves, establish concurrent invalidation within a process,
cross-process invalidation, queued-work cancellation, restart freshness, or
durable anti-rollback. **Unresolved:** persistent/durable
current-authorization state and **anti-rollback** — production can only construct
`unavailable` owners (`genesis_consensus_authority.rs:1125`); the `Established`
local state exists only under `cfg(test)` (`establish_for_fixture`). Persisting an
observed snapshot alone does not establish durable anti-rollback (an
older-but-valid persisted state would still be accepted on open).

### 4.E Existing mechanisms and duplication risk

| Future behavior | Existing implementation | Classification |
|---|---|---|
| Validator membership for verifier boundaries | `ConsensusValidatorSet` shared as `Arc` for the timeout bridge (`peer_key_provider.rs`, coherence `binary_consensus_loop.rs:1266`) | **Reusable structurally** — but the **engine** takes `ConsensusValidatorSet` **by value** (`basic_hotstuff_engine.rs:508`) and today from `build_uniform_validator_set` (§4.B), so unifying engine + verifier membership needs work, not merely reuse |
| Suite-aware key lookup | `GenesisConsensusKeyProvider : SuiteAwareValidatorKeyProvider` (`genesis_consensus_authority.rs`) | **Reusable unchanged** |
| Outer Proposal/Vote verification | `verify_proposal_msg_with_domain` / `verify_vote_msg_with_domain` (`proposal_vote_verify.rs`) | **Reusable unchanged** |
| D6 message-bound Vote verification machinery (for a QC verifier) | `verify_vote_msg_with_domain` + `ProposalVoteSigningDomainV2::vote_preimage` + `ConsensusSigBackendRegistry` | **Reusable as the signature primitive** for a new D6-compatible QC boundary (§6) |
| Timeout/NewView verification | `timeout_verification_bridge.rs` + `verify_timeout_*` | **Reusable unchanged (separate boundary)** |
| Current-state freshness gate | `GenesisConsensusAuthority::authorize_current_state` / `authorize_configuration` | **Reusable only as a synchronous in-process gate.** Persisting an immutable observed snapshot is **not** sufficient to extend it: persisted observation alone establishes no current authorization and no rollback resistance, so it does not close the durable-freshness / anti-rollback gap |
| Bind owner↔verifier | `AuthorizedProposalVoteSnapshot::try_bind` (`binary_consensus_loop.rs:1245`) | **Reusable with narrow extension** (real chain label + authorized wire id) |
| QC **structural** checks (bitmap↔sig count, index decode, power sum) | `verify_quorum_certificate` (`lib.rs:705`) | **Structural ideas requiring checked adaptation** — the shapes (bitmap↔sig correspondence, bit→index decode, power accumulation) are a template only; indices must be bounded and computed with checked arithmetic, and the power sum must be overflow-guarded before reuse (§6) |
| QC **signature** verification for D6-signed Votes | `verify_quorum_certificate`'s `vote_digest` path (`lib.rs`) | **NOT reusable for D6 Votes** — incompatible signed input (§4.C.1); must use the D6 domain-bound preimage instead |
| Quorum threshold arithmetic | `ConsensusValidatorSet::two_thirds_vp()` (saturating accumulation; `2 * total` in u64) | **Structural idea requiring checked adaptation** — reuse only within proven arithmetic bounds (positive, consistent, representable total; no overflow in accumulation or `2 * total`), or use an explicitly checked equivalent preserving `ceil(2W/3)` (§6); do not reuse blindly for arbitrary inputs |
| Embedded-QC verification wired into `Node<S>::apply_block` | `verify_block_proposal` (`lib.rs:807`) | **Not connected to this binary path** (legacy `apply_block` abstraction only) |
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

**Preserved C3A/C3B contract (do not reopen).** Standard runtime/wire aliases are
**defined but not activated** (C3A); pinned genesis/network correspondence is
**implemented** (C3B, `check_network_correspondence`); production authority
consumption remains **unimplemented** (`main.rs:5549` = `None`). The alias
assignments are accepted as-is; this audit does **not** reopen them and does
**not** introduce another registry or a synthetic mapping (§5.1 records the
existing mapping policy and the later production-consumption requirements without
inventing a value).

All steps below can be implemented **while activation remains disabled**
(`main.rs:5549` stays `None`) and while `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR` stays
UNCHANGED. **Activation is intentionally last and gated.** It must remain gated by
**all** of the unresolved requirements — authority, freshness, compatibility,
engine/QC, and adversarial-evidence — and specifically must **not** precede the
lifecycle/restart (durable freshness / anti-rollback) protections. Persisting an
observed snapshot alone does **not** establish durable anti-rollback, so
activation may not be sequenced ahead of it.

**Dependency order (each independently testable; activation strictly last):**

1. **A dormant, pure D6-compatible QC verification boundary** (the single next
   task, §6) — reuse the D6 message-bound Vote verification machinery to verify a
   QC's constituent signatures against explicit trusted inputs, with no
   engine/binary wiring and no authority activation. Independent of steps 2–5;
   **not** blocked by the production runtime→wire mapping or provenance work
   below, which gate integration/activation only (§5.1).
2. **Resolve a real chain-identity label + authorized wire chain id from
   validated provenance** on the authority (owner of data:
   `GenesisConsensusAuthority`; consumers: `try_bind` `:1281`/`:1295`,
   `snapshot_chain_identity_label`). Trusted inputs: boot-verified genesis
   runtime `ChainId` + C3A wire alias. Fail-closed: mismatch/none → no bind. The
   runtime `ChainId` must come from validated provenance and preserve its
   association with the same authority snapshot — never from parsing the genesis
   string label or substituting another synthetic label (§5.1). This gates
   production integration, **not** the step-1 dormant verifier.
3. **Construct `AuthorizedProposalVoteSnapshot` by cloning the same `Arc`s** out
   of one boot-validated authority (owner: authority; consumer: `try_bind`).
   Fail-closed: any `Arc::ptr_eq` / membership / commitment mismatch → reject.
   Still not wired into `main`.
4. **Unify engine membership with the authority membership** so the engine
   consumes the authority's validated set rather than
   `build_uniform_validator_set` (consumer: `basic_hotstuff_engine.rs:508`, which
   currently takes the set **by value**). Fail-closed: engine set must match the
   verifier set. Then insert QC verification on the binary path using the step-1
   D6-compatible boundary (not the legacy `vote_digest` verifier), with the
   effect-ordering constraints of §3.4 respected.
5. **Durable current-authorization state + anti-rollback**, then finally **wire
   the snapshot into `main`** (the only step that enables authority). Both are
   out of scope here; activation may not occur until durable freshness /
   anti-rollback exist. **Do not** place snapshot-wiring before this step.

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
* membership / key / suite mismatch → fail-closed (suite id, `Arc` identity
  where applicable);
* stale authorization vs current authorization (generation advanced between
  `admit` and `confirm` → `Stale`);
* preserved certificate evidence vs information-losing conversion (signers /
  signatures / epoch retained, with the §3.5 serialization caveat in mind).

### 5.1 Existing mapping policy and later production-consumption requirements

C3A defines the dormant standard-network wire aliases. C3B checks correspondence
between a pinned genesis identity, its retained validation policy, the selected
environment, and the supplied full runtime `ChainId`. These decisions remain
accepted; this task does not reopen their alias assignments or introduce another
registry.

The next pure, dormant D6-compatible QC verifier can be implemented and tested
with explicit trusted domain, membership, key-provider, backend, and
authorized-epoch inputs. It does not require production authority construction or
activation.

Later production integration must obtain those inputs through validated
provenance and preserve their association with the same authority snapshot. It
must also satisfy the outstanding engine/QC compatibility, lifecycle, restart,
anti-rollback, and adversarial-validation requirements. These requirements block
production integration and activation, not implementation of the dormant
verifier.

The runtime `ChainId` must not be obtained by parsing the genesis string label or
substituting another synthetic label.

---

## 6. Single recommended next implementation task

**Withdrawn recommendation.** The prior recommendation — *"invoke the existing QC
verifier (`verify_quorum_certificate`) in the engine; prerequisites: none"* — is
**withdrawn**. It is unsafe as stated: `verify_quorum_certificate` verifies the
**legacy `vote_digest` signed input**, which is **incompatible with D6-signed
Votes** (§4.C.1); wiring it into the engine would either verify against the wrong
signed bytes or invite a legacy-fallback that a D6-signed certificate must never
be allowed. It also assumed engine/verifier membership sharing that does not hold
(engine set is by-value uniform, §4.B) and touched already-mutated ingest state
(view advancement, §3.4). Prerequisites are **not** "none".

**Replacement task: Add a dormant, pure D6-compatible QC verification boundary.**

Implement a standalone verification function/type that verifies a wire
`QuorumCertificate`'s constituent Votes using the **existing D6 message-bound
Vote verification machinery** (`verify_vote_msg_with_domain` /
`ProposalVoteSigningDomainV2::vote_preimage`) and the established
membership/key/backend interfaces (`ConsensusValidatorSet`,
`SuiteAwareValidatorKeyProvider`, `ConsensusSigBackendRegistry`). It is **dormant
and pure**: not wired into the engine, `binary_consensus_loop.rs`, `main.rs`, the
C2/C3A/C3B module, storage, or activation. **This audit defines the task; it must
not be implemented now.**

**Contract the future task must satisfy** (all inputs trusted, never inferred
from the untrusted QC):

* **Trusted inputs.** A caller-supplied trusted **domain**
  (`ProposalVoteSigningDomainV2`), **membership** (`ConsensusValidatorSet`),
  **key provider** (`SuiteAwareValidatorKeyProvider`), **backend registry**
  (`ConsensusSigBackendRegistry`), and **authorized epoch**. No domain,
  membership, epoch, or authority may be inferred from the untrusted QC itself.
* **Bound the bitmap before decoding.** Establish the bitmap length against the
  trusted membership size first; compute every signer index with **checked
  arithmetic** and establish representability **before any narrowing conversion**.
  Enforce `popcount(signer_bitmap) == signatures.len()`; reject out-of-range bits.
* **Bitmap-position / wire `validator_index` / `ValidatorId` correspondence.**
  Define the correspondence among bitmap position, the wire `validator_index`, and
  the membership `ValidatorId` **consistently with existing D6 verification**. Do
  **not** assume membership position and `ValidatorId` are interchangeable; derive
  each explicitly and check it against the trusted set.
* **No duplicate-bit fiction.** A set-based bitmap **cannot repeat the same bit**,
  so "duplicate bit" is not an encoding to defend against. Instead test **index
  aliasing** (distinct bits/positions resolving to the same signer, or a wire
  `validator_index` aliasing a different membership position) and **incorrect
  signature association**, rather than claiming an impossible duplicate-bit
  encoding.
* **Reconstruct the exact Vote fields originally signed.** For each signer,
  rebuild the `Vote` (`version, chain_id, epoch, height, round, step, block_id,
  validator_index, suite_id`) consistent with the QC and the trusted epoch, then
  verify over `domain.vote_preimage(vote)` — the exact D6 signed input — not over
  `vote_digest`. **Preserve the QC's actual signed fields**; never rewrite an
  inconsistent epoch or chain id to make verification pass.
* **Reject epoch / wire-chain inconsistencies before crypto.** Reject QC epoch and
  wire-chain inconsistencies **before** cryptographic verification, using the
  trusted authorized epoch and the domain's `expected_wire_chain_id`.
* **Arithmetic notes on the reused primitives.** Record that
  `ConsensusValidatorSet` construction uses **saturating accumulation** and
  `two_thirds_vp()` computes `2 * total` in `u64`; these operations **cannot be
  reused blindly** for arbitrary inputs (a saturated total or an overflowing
  `2 * total` silently misstates the threshold).
* **Validate the voting-power total.** Require a **positive, consistent,
  representable** voting-power total. Prevent overflow in the **total
  accumulation**, the **signer-power accumulation**, and the **threshold
  calculation**. Reuse the existing threshold **only within proven arithmetic
  bounds**, or use an **explicitly checked equivalent preserving `ceil(2W/3)`**.
* **Do not silently change quorum policy.** Compute the quorum threshold from the
  trusted set's actual voting power (`two_thirds_vp()` or the checked equivalent),
  not a caller scalar or an assumed `2f+1` (§4.C.2). Do **not** silently change
  the quorum policy or claim that this formula establishes safety under arbitrary
  weighted fault assumptions.
* **Suite consistency.** Require a consistent suite per the trusted
  membership/provider.
* **Malformed-certificate rejection.** Typed, fail-closed rejection for bad
  bitmap/index/signature shapes, suite mismatch, unknown signer, wire-chain
  mismatch, and insufficient quorum.
* **Evidence retained by the result.** Return evidence in a **separate,
  non-authorizing result type** that associates the verified certificate and
  signers with the trusted verification context — **without** mutating the shared
  logical `qc.rs` `QuorumCertificate` (whose serde/`TimeoutMsg` users make field
  additions non-neutral, §3.5).
* **Behavior on missing or inconsistent trusted inputs.** If any trusted input is
  absent or inconsistent (e.g. no domain, no membership, epoch mismatch), the
  boundary **fails closed** and performs no verification — it never defaults.
* **Compatibility with existing legacy callers.** The existing
  `verify_quorum_certificate` and `Node<S>::apply_block` legacy callers remain
  **unchanged and untouched**; the new boundary is additive. **No legacy
  signature retry/fallback may rescue a failed D6 verification.**

**Required future tests.**

* genuinely D6-signed QC accepted (real D6-signed positive controls, including a
  positive-and-representable voting-power total);
* index / representability limits (out-of-range bit, index at/over the narrowing
  boundary, bitmap length vs membership size);
* arithmetic limits (saturating total, overflowing `2 * total`, signer-power
  accumulation overflow at the threshold boundary);
* zero or otherwise invalid total voting power → reject;
* malformed signature associations (index aliasing, signature bound to the wrong
  signer, popcount mismatch, truncated signature);
* same-key **wrong-domain** and **wrong-epoch** negatives (correct signer key,
  wrong `ProposalVoteSigningDomainV2` / authorized epoch → reject);
* legacy vs D6 signature incompatibility (a `vote_digest`-signed QC → reject under
  the D6 boundary, and vice versa);
* insufficient quorum and membership/suite mismatch.

**Explicitly later, separate work (not this task):** binary/engine insertion,
certificate propagation, storage migration, and activation (§5 steps 2–5). If a
required production input remains unresolved (e.g. how a production authority
obtains its trusted domain and authorized wire chain id through validated
provenance — §5.1), that prerequisite gates **integration/activation only**; the
step-1 boundary simply remains dormant until callers can supply trusted inputs.

**Why it is safe to proceed now.** It adds a pure, dormant verification function
with trusted inputs and typed fail-closed outputs. It constructs no
`ProposalVoteAuthority`, does not flip `main.rs:5549`, changes no wire/QC/storage
behavior, and grants no authority — it only makes a correct D6-compatible QC
check available for later, safely-sequenced integration.

---

## 7. Checks actually executed and tool limitations

* **Executed here:** repository inspection only — `git status`, `git branch
  --show-current` (`copilot/copilotrun-422-d7-c3c`), `git rev-parse HEAD`
  (`b7a38c6`) and its parent (`819f2b2`), `git rev-list --count HEAD` (=2),
  `cat .git/shallow` (pins the boundary `819f2b2`), `git diff --stat 819f2b2
  b7a38c6` (docs-only), `git cat-file -t` for the task-named `9cc94ab7…`
  (reviewed final) and `0b3eb4a…` (inspected source) and the older `3a5ac02…` /
  `734a9425…` (**all absent**), plus
  the `grep`/`rg`/`view` source searches cited inline (`main.rs`,
  `binary_consensus_loop.rs`, `basic_hotstuff_engine.rs`,
  `hotstuff_state_engine.rs`, `lib.rs`, `qc.rs`, `proposal_vote_verify.rs`,
  `pv_signing_domain.rs`, `consensus.rs`, `validator_set.rs`, `vote_accumulator.rs`,
  `pqc_boot_genesis.rs`, `timeout.rs`). No Rust build, test, or release rebuild
  was run (not required for a documentation-only audit, and none of these two
  files changes any build input).
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

The audit is **COMPLETE-FOR-INSPECTED-SCOPE**: the corrected sections now cover
the required call-graph, verifier-compatibility, QC-flow, dependency-order, and
next-task paths and produce a coherent next-task contract (§6). The only material
inspection limitation is the shallow clone (§1.2): the task's named reviewed
final revision `9cc94ab7…`, its named inspected source revision `0b3eb4a…`, and
the older `3a5ac02…` / `734a9425…` are all absent, so ancestry could not be
confirmed; all findings are anchored to the worktree at HEAD `b7a38c6`,
source-identical to the shallow boundary `819f2b2`, which carries the C2/C3A/C3B
source. No readiness item moves Green. RS1/C4/C5 remain OPEN and public DevNet is
NO-GO.

---

## 9. Correction note (C3C revision)

This document supersedes the first C3C audit draft. The following were corrected
**in place** (not merely disclaimed):

* **Call graph (§2).** Preflight is `run_p2p_consensus_security_preflight`
  (`main.rs:5019`), not `build_consensus_security_preflight`. Engine membership is
  `build_uniform_validator_set(cfg.num_validators)` in
  `run_binary_consensus_loop_with_io` (`binary_consensus_loop.rs:2308`), passed
  **by value** to `BasicHotStuffEngine::new` (`ConsensusValidatorSet`, not
  `Arc`). `build_validator_set_and_key_provider` feeds the **Timeout bridge
  only** and is no longer described as the engine's input. Boot verification may
  return `SkippedNoExternalGenesis` (not "every startup"). The §2 rejection-path
  block is now a condition/result/timing table taken directly from the handler's
  two match arms; compiled-vs-reachable branches are distinguished and D6
  verification is described as an implemented conditional path.
* **`chain_id: 1` (§4.B).** Reclassified from "fixture-scoped" to
  **production-reachable message construction**, with the guard located at
  signing/transmission (fail-closed, no authority), not at construction.
* **Verifier compatibility (§4.C.1–2).** The legacy `verify_quorum_certificate` /
  `vote_digest` signed input is documented and shown **incompatible with
  D6-signed Votes**; reusable structural checks are separated from incompatible
  signature verification; the three quorum quantities (`qc_threshold`,
  `two_thirds_vp()`, `2f+1`) are no longer equated.
* **QC flow (§3.3–3.5).** The embedded justify QC is stored via `register_block`
  and is **not** routed through `on_qc`; the three flows are traced separately;
  view advancement before the insertion point is noted; serde/`TimeoutMsg` users
  of the logical QC are flagged before recommending field additions.
* **Dependency order (§5) and next task (§6).** The unsafe "invoke the existing
  QC verifier; prerequisites none" recommendation is **withdrawn** and replaced
  by a single dormant, pure **D6-compatible** QC verification boundary with a full
  input/evidence/failure contract and required negative tests. Activation remains
  last and gated behind lifecycle/restart (durable freshness / anti-rollback)
  protections; the accepted C3A/C3B alias contract is preserved and not reopened.
* **Git-fact reconciliation and source-reference fixes (this revision).** The
  branch / HEAD / shallow-boundary / object-availability report (§1.1–1.2, §7–8)
  is updated to the actual state: branch `copilot/copilotrun-422-d7-c3c`, HEAD
  `b7a38c6` on boundary `819f2b2`, with the task-named `9cc94ab7…` (reviewed
  final) and `0b3eb4a…` (inspected source) now **absent** and no ancestry
  manufactured. §4.B reclassifies `basic_hotstuff_engine.rs:1531` `chain_id: 1`
  as the ordinary `on_proposal_event` responding Vote (not a test fixture) and
  names the engine leader method `on_leader_step` (`:1284`), reserving
  `do_leader_tick` for the binary loop. §2 boundary 1 separates the external
  genesis **file** (`--genesis-path`) from the independent **expected-hash pin**
  (`--expect-genesis-hash` / `expected_genesis_hash`), which DevNet/TestNet may
  omit (hash compare skipped) and only MainNet forces.
* **Outstanding corrections applied in this pass (D7-C3C follow-up).** (1) The §2
  rejection-path bullets were replaced by the four-row condition/result/timing
  table (verification-context-unavailable vs current-state-unavailable vs
  admission failure vs post-verification `Stale`) for both Proposal and Vote, and
  the same distinction was applied to §3.1, §4.D, and the C3C evidence summary; a
  missing owner is no longer described as a post-crypto `Stale` rejection. (2)
  §5.1 was rewritten to "Existing mapping policy and later production-consumption
  requirements", dropping the "blocks step 1" heading and the "separately ratified
  value" alternative; §5's dependency list and §6's prerequisites now state that
  the production runtime→wire mapping/provenance gates integration/activation
  only, never the dormant verifier, and that the runtime `ChainId` must not be
  parsed from the genesis label. (3) §6 added explicit bitmap-bounding/checked-
  arithmetic/representability, position↔`validator_index`↔`ValidatorId`
  correspondence, index-aliasing (no duplicate-bit fiction), saturating/`2*total`
  arithmetic notes, positive-representable-total validation, quorum-policy
  preservation, epoch/wire-chain pre-crypto rejection with signed-field
  preservation, a separate non-authorizing evidence result, and no legacy
  fallback, plus the matching future tests; the reuse table and evidence summary
  now say "structural ideas requiring checked adaptation". (4) §4.D's
  concurrent-invalidation wording was replaced with the serialized-ordering scope
  statement, and the reuse-table row no longer suggests that persisting an
  immutable observed snapshot suffices to extend the current-state freshness gate.

## 10. Successor note (Run 422 D7-C3E)

The single recommended next task in §6 (verify PRESENT embedded QCs in the real
inbound Proposal handler, before downstream effects, using the existing C3D
`verify_quorum_certificate_with_domain`) was implemented in Run 422 D7-C3E. The
gate lives in `crates/qbind-node/src/binary_consensus_loop.rs`, before the
engine call (so it precedes any `on_proposal_event` view advancement), and draws
its trusted inputs (domain, membership, key provider, backend registry, and
authorized epoch) from the same admitted snapshot used for outer verification.
See `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md` §9B and the Run 422
D7-C3E section of `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`. This note is
additive; all historical findings above are preserved. The remaining scope
called out in §4 and §10-of-the-protocol-doc (absent-QC/bootstrap
authorization, full engine/QC adoption and retention, production lifecycle, and
durable anti-rollback) stays open.

## 11. Successor note (Run 422 D7-C3F)

Building on §10, Run 422 D7-C3F closes the **in-process retention** half of the
QC information flow traced in §3.2–§3.4: instead of discarding the verified
evidence after the §9B gate, the Required present-QC handoff now passes the
`VerifiedQuorumCertificate` into an explicit engine entrypoint
(`BasicHotStuffEngine::on_verified_proposal_event`) that retains the complete
evidence with the registered block's justification, under exact evidence↔QC
correspondence, wire-chain/epoch correspondence and a checked retained-evidence
byte budget — all enforced **before** engine mutation, fail-closed, with no legacy
fallback and no second constituent-signature verification. Retention uses a
separate non-serialized `Arc<VerifiedQuorumCertificate>` on `BlockNode`, so the
shared logical-QC serialization users in §3.5 are unchanged. Evidence is the
block's justification (certifying the parent), never `own_qc`, and its lifecycle
(replacement, unverified re-registration, eviction, restart) is routed through
single accounting choke points. See §9C of
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md` and the Run 422 D7-C3F
section of `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`. This note is additive;
all historical findings above are preserved. Absent-QC/bootstrap authorization,
outbound QC reconstruction/propagation, Timeout/NewView migration, persistent
evidence storage/recovery, production authority lifecycle/activation, durable
anti-rollback, and Run 423 remain open.

## 12. Successor note (Run 422 D7-C3F correction)

A bounded correction of §11 (not a new phase) fixed three defects in the C3F
retention path without changing the §11 information flow: (A) under **block-slot**
pressure the prior path could evict the just-registered candidate yet report success
and emit a vote — retention is now decided **before** mutation against both the byte
budget and block-slot capacity, the candidate is never evicted (only other
safe-to-evict blocks are), the discarded registration `Result` is removed, and
failure propagates as a typed `RetentionCapacityUnavailable`/`RetentionBudgetExceeded`
before view advancement, self-voting or outbound effects; (B) `retained_byte_size` is
now **checked/fallible** and charges the certificate struct value, signer-bitmap
capacity, outer signatures descriptor storage and each constituent
signature/signer capacity, rejecting unrepresentable totals instead of saturating
them; (C) the block's logical justification is **derived from the verified evidence**
(no caller-supplied or `None` justification), keeping evidence separate from `own_qc`
with its original certificate/domain/epoch metadata and introducing no new
parent/round/bootstrap rule. Each budget rejection is counted exactly once on both the
engine-preflight and direct-registration paths; consensus and block state are
unchanged on rejection. The 256 MiB default budget is retained. See §9C of
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md` and the Run 422 D7-C3F
CORRECTION subsection of `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`. This note
is additive; all historical findings and the retained D7 posture flags are preserved.

## 13. Successor note (Run 422 D7-C3F correction — candidate metadata + strengthened accounting)

A further bounded correction of §§11-12 (not a new phase) closes two residual gaps
without changing the information flow: (A) `register_block_with_verified_justification`
now derives the candidate’s state-dependent metadata (its height, from its parent) from
the **pre-eviction** engine state, before `reserve_block_slot_for_new` may evict a
safe-to-evict parent to make block-slot room — so admitting a candidate whose parent is
legitimately evicted no longer collapses the candidate height to zero; genuinely missing
parents still register at height zero, and no new parent/QC linkage or bootstrap rule is
introduced. (B) The allocation-charge accounting test is strengthened: an independent
expected-charge assertion (inside the `qc_verify_domain` module under `cfg(test)`, with
capacity > length for every component) verifies `retained_byte_size` equals the documented
component sum (struct value + bitmap capacity + outer signatures descriptor capacity +
each constituent signature-buffer capacity + signer-vector capacity), computed WITHOUT
calling `retained_byte_size`, so omission of any required component or substitution of
length for capacity is detected; the prior projected-total overflow test is preserved.
Regressions: `c3f_l_eviction_preserves_candidate_height_and_evidence` (eviction-required
admission at height 6 with a free-slot control) and
`c3f_b_expected_charge_sums_every_capacity_component`. This note is additive; all
historical findings and the retained D7 posture flags are preserved.

## 14. Successor note (Run 422 D7-D1 — production authority lifecycle contract)

Run 422 D7-D1 produces the single authoritative lifecycle contract for future
production Proposal/Vote signing authority at
`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`. It reuses the
mechanisms audited here (genesis verify + pin, the dormant
`build_genesis_consensus_authority`, the founding-epoch `authorize_configuration`
guard, the fail-closed `CurrentAuthorizationOwner` admission model, the C1
storage observation, the C2/C3A/C3B correspondence and alias mapping, the C3D
domain-bound QC verifier, the C3E present-QC gate, and the C3F in-process
retention) and records, as still **Missing**, both a durable rollback-resistant
current-authorization source and an independent freshness anchor. It recommends a
founding-authority-only first release, fixes no code, and keeps every retained D7
posture flag and the `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`
classification unchanged. Its single bounded next task, **as revised in the
D7-D1 review correction (§15)**, is a **source characterization of existing
signing-state persistence and recovery** through the real restart / restore
paths — keeping the harness `load_persisted_state` / `initialize_from_restart`
recovery distinct from the production `initialize_from_snapshot_baseline` snapshot
restore; the previously proposed generic freshness-anchor / epoch-witness
observation module is **withdrawn**. Activation remains disabled and no readiness
item moves. This note is additive.

## 15. Successor note (Run 422 D7-D1 review correction)

The D7-D1 review corrected the lifecycle contract in place. Summary for
cross-reference only (the authoritative text is in
`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`):

* **Three requirements separated** — activation authorization (A),
  current-authority freshness (B), and signing / consensus-state continuity (C)
  are distinct; an equal epoch comparison establishes none of them (epoch-0
  snapshot / sign / restore counterexample). Source-backed inventory:
  `voted_in_view` / `proposed_in_view` / `locked_qc` / `current_view` /
  `votes_by_view` are in-memory only; the `ConsensusStorage` trait persists
  committed block / QC / epoch and has no last-voted-view / locked-QC / vote-record
  method, so a committed-block checkpoint does not cover an uncommitted signing
  decision.
* **Provenance vs authentication** — a comparison classifies but cannot
  authenticate a caller-supplied value; the abstract anchor interface is gated on
  a stated authentication / binding / freshness / rollback-domain / failure
  contract; live-quorum / QC assumptions enumerated; anchor selection stays
  unresolved.
* **Lifecycle / ordering** — actual outbound order is admission/epoch → sign →
  confirm → facade handoff; a completed signature is distinct from a transmitted
  one; mid-handler same-owner replacement is not modeled; generation advance is
  in-process bookkeeping, not activation; "replacement fails → keep gen N" is
  corrected to fail-closed when superseded / revoked or when current authorization
  is unavailable.
* **Activation** — the trusted activation root / evidence (requirement A) is a
  recorded missing prerequisite; Profile A stays a proposed first-release profile
  (not an activation approval) with the full dependency list.
* **Source classifications** — `resolve_network_wire_alias` is defined in
  `qbind-types` and imported by the correspondence module; production preflight
  supplies `proposal_vote_authority: None`; S13 is conditionally reachable via
  C3E; S15 retains without a second constituent verification; Timeout / NewView
  credentials do not establish Proposal / Vote authority; governance replay
  persistence is not validator signing-state persistence or whole-DB rollback
  protection.
* **Next task withdrawn / replaced** — the generic freshness-anchor observation
  module is withdrawn; the replacement is a bounded source characterization of
  existing signing-state persistence / recovery. Activation remains disabled; no
  readiness item moves. This note is additive.

## 16. Successor note (Run 422 D7-D1 reconciliation pass)

This additive note records the D7-D1 reconciliation pass that fixed the remaining
**operative** contradictions in the lifecycle contract
(`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`) so its tables
and checklists agree with the §15 summary. For cross-reference only:

* **Recovery inventory corrected.** The contract §2.3.2 *Committed block / QC* row
  previously cited `get_last_committed` at `production_consensus_storage.rs:101`;
  that file contains **no** `get_last_committed`. The actual recovery reader is the
  harness `load_persisted_state` (`hotstuff_node_sim.rs:2049`), while the production
  binary restore uses `initialize_from_snapshot_baseline`
  (`binary_consensus_loop.rs:2390`) and reads neither `get_last_committed` nor any QC.
  The locked-QC row now describes a conservative reconstruction from committed /
  embedded QCs, not recovery of the exact latest pre-crash locked QC. The
  `ConsensusStorage` absence finding is scoped to that interface and the traced paths.

* **Activation / ordering rows fixed in place.** The §4.3 signing row no longer reads
  “none beyond activation” (durable requirement-C continuity is an unmet
  prerequisite); the activation row now also requires a trusted activation root (A)
  and requirement-C prerequisites, not correspondence + anchor alone; §5.4's outbound
  order is `admit` → epoch check → sign → `confirm` → facade handoff; §7 no longer
  claims anchor selection “unblocks activation.”

* **Rejection path and labels.** §4.1 records production `proposal_vote_authority:
  None` (`main.rs:5549`) failing closed under `Required`, not a present-authority /
  unavailable-owner case; the stale “dormant” S13 label was reconciled to
  conditionally reachable via the C3E gate (`binary_consensus_loop.rs:4736`).

* **Threat model.** T1 is scoped to governance-replay crash consistency (not validator
  signing-state continuity); “off-box” requirements were replaced by trusted state /
  evidence outside the attacker's rollback domain (protected local hardware or a remote
  witness, neither selected). The epoch-0 counterexample is intact.

Activation stays disabled; no code, test, or readiness item changes. This note is
additive.