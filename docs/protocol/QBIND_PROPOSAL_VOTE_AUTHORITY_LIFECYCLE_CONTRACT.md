# QBIND Proposal / Vote Authority Lifecycle Contract

**Run:** 422 D7-D1
**Status:** Source inspection and lifecycle contract only. No Rust, test,
configuration, storage-schema, wire-format, workflow, or activation change is
made or proposed for this phase. This document proposes a lifecycle; it does not
implement one and does not move any readiness item to Green.

```
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

This is the single authoritative lifecycle contract for future production
Proposal / Vote signing authority. It separates, and never conflates, **three
distinct security requirements** (§2.3) — **(A) activation authorization**, **(B)
current-authority freshness**, and **(C) signing / consensus-state continuity** —
together with their supporting inputs: independently pinned genesis identity;
standard runtime / wire correspondence; signature verification; and
quorum-certificate validation. Neither message correspondence nor a matching
epoch number establishes all three; success in one category never establishes
another. In particular an *equal* epoch comparison (§2.3.1) cannot establish
preservation of prior signing decisions (requirement C). Proposed conceptual
state names below are documentation only and are **not** instructions to add new
code types.

---

## 1. Inspected revision and source limitations

### 1.1 Branch, HEAD, and worktree (recorded, not manufactured)

Inspected against the **actual supplied worktree**, not the SHAs the task recites.

* **Working branch (actual):** `copilot/copilotcopilot-run-422-d7-d1`
  (`git branch --show-current`). The D7-D1 review task **reports** the branch as
  `copilot/copilotcopilot-run-422-d7-c3f`; the actual checkout is the `-d1`
  branch. The initial D7-D1 draft was recorded while the working label read
  `-c3f`; this review pass records the actual `-d1` branch and does not rename it.
* **Inspected worktree HEAD (actual):**
  `9ce29acbb88c5611064f155ec7566e02052c2720` (`update`) at this review pass; the
  prior D7-D1 draft recorded `38339d697797aa320ab372fdd5849ab0b45e595b`. Worktree
  clean before this documentation pass.
* **Reviewed revision named by the D7-D1 task**
  `ffa7b71cbdaa2d31badff519c346b40f00a9bc25`: **object absent** from this shallow
  clone; not in local ancestry and not referenced by any tracked file. Ancestry
  to an absent object is not manufactured; the correction is applied to the actual
  worktree content.
* **Accepted C3F final revision named by the task**
  `f97b49f72dc9af843d237f1758376096b58c08c1`: **object absent** from this clone
  (`git cat-file -t f97b49f7…` → *could not get object info*), even after
  `git fetch --unshallow` (840 commits recovered). It is not in local ancestry
  and is **not** referenced by any tracked file. Ancestry to an absent object is
  not manufactured.
* **Accepted tested code checkpoint named by the task**
  `5cedb9ca6b55cb4931d632730f7f390237978203`: **object absent** from this clone,
  but it **is** cited textually in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`
  (the C3F correction subsections) as the tested revision. Missing history is
  distinguished from missing implementation: the C3D verifier, the C3E present-QC
  gate, and the C3F retention path are all **present in this worktree** and were
  reported green at that tested revision.
* **Ancestry:** the clone was shallow (depth 2) and was unshallowed for this
  inspection; no missing object is invented and no absent SHA is presented as an
  ancestor.

### 1.2 Source references anchoring this contract (worktree HEAD)

| # | Symbol / mechanism | File |
|---|---|---|
| S1 | Boot genesis verify + optional independent hash pin | `crates/qbind-node/src/pqc_boot_genesis.rs` (`run_boot_time_genesis_verification`, `map_environment`); `crates/qbind-ledger/src/genesis.rs` (`verify_boot_time_genesis`) |
| S2 | Genesis-derived authority builder (dormant) | `crates/qbind-node/src/genesis_consensus_authority.rs` (`build_genesis_consensus_authority`, `GenesisConsensusAuthority`) |
| S3 | Founding-epoch lifetime guard | `genesis_consensus_authority.rs` (`GENESIS_STATIC_AUTHORITY_EPOCH`, `authorize_configuration`, `AuthorityLifetimeError`) |
| S4 | Current-authorization owner / ticket / snapshot | `genesis_consensus_authority.rs` (`CurrentAuthorizationOwner`, `AuthorizationTicket`, `admit`, `confirm`, `is_exhausted`); `binary_consensus_loop.rs` (`AuthorizedProposalVoteSnapshot`) |
| S5 | Inbound admission gate (Required policy) | `binary_consensus_loop.rs` (`ConsensusVerificationPolicy`, Proposal/Vote arms; `unavailable(...)` wiring) |
| S6 | Immediate outbound forwarding | `binary_consensus_loop.rs` (`forward_actions_to_facade`, `admit_outbound_action`, `confirm_outbound_before_effect`) |
| S7 | Cached late-peer re-emission | `binary_consensus_loop.rs` (`maybe_reemit_on_late_peer_connect`, `admit_cached_reemission`, `CachedReemissionProvenance`) |
| S8 | Restore-catchup deferral | `binary_consensus_loop.rs` (`should_defer_restore_proposal_for_catchup`; `restore_catchup_proposals_deferred`) |
| S9 | Read-only storage observation (C1) | `crates/qbind-node/src/consensus_storage_observation.rs` (`observe_consensus_storage`, `ConsensusStorageObservation`) |
| S10 | Genesis / record correspondence (C2) | `crates/qbind-node/src/genesis_authority_record_correspondence.rs` (`ExpectedGenesisIdentity::load_pinned`, `check_genesis_record_correspondence`) |
| S11 | Standard-network alias mapping (C3A) | `crates/qbind-types/src/network_wire_alias.rs` (`resolve_network_wire_alias`, **defined here**), imported by `genesis_authority_record_correspondence.rs` (C3B `check_network_correspondence`) |
| S12 | Pinned-genesis / network correspondence (C3B) | `genesis_authority_record_correspondence.rs` (`check_network_correspondence`, `GenesisNetworkCorrespondence`) |
| S13 | Domain-bound QC verifier (C3D; conditionally reachable via the C3E gate) | `crates/qbind-consensus/src/qc_verify_domain.rs` (`verify_quorum_certificate_with_domain`, `VerifiedQuorumCertificate`) |
| S14 | Present-QC admission gate (C3E) | `binary_consensus_loop.rs` (inbound Proposal arm; `inbound_proposal_embedded_qc_verified_total`) |
| S15 | Verified-evidence retention (C3F) | `crates/qbind-consensus/src/basic_hotstuff_engine.rs` (`on_verified_proposal_event`); `crates/qbind-consensus/src/hotstuff_state_engine.rs` (`register_block_with_verified_justification`, `verified_justification`) |
| S16 | Activation refusal (release binary) | `crates/qbind-node/src/main.rs` (`--consensus-authority-from-genesis` refused, `std::process::exit(1)`) |
| S17 | Existing anti-rollback machinery (same-disk) | `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` §8; Run 055 sequence file `pqc_trust_bundle_sequence.json`; `pqc_governance_production_durable_replay_rocksdb.rs` (disabled-by-default) |

---

## 2. Reuse audit

Traced the actual binary path from `main.rs` and classified each mechanism with
**distinct** labels that are **not** interchangeable: **production-reachable**;
**conditionally reachable** (compiled with a production caller that only fires
under specific runtime conditions, e.g. the C3E present-QC gate → S13);
**dormant** (compiled, no production caller); **disabled-by-default** (present but
off unless explicitly enabled, e.g. S17); **startup-refused** (S16 exits
non-zero); and **`cfg(test)`-only** (compiled only under test). Older run reports
were treated as leads, not proof.

### 2.1 Reuse table

| Requirement | Existing symbol / path | Actual guarantee | Limitation | Verdict |
|---|---|---|---|---|
| Independently pinned genesis identity | S1 `verify_boot_time_genesis(Some(pin))`; S10 `ExpectedGenesisIdentity::load_pinned` | Boot-time single-read verify of external genesis against an independent expected-hash pin; env policy from `map_environment` | Non-MainNet **permits an absent pin** (compare skipped); a supplied `--genesis-path` alone is a file, not a pin | **Reuse** (do not build a new genesis parser) |
| Genesis-derived validator set / keys / suites | S2 `build_genesis_consensus_authority` | Derives consensus validator set + per-validator ML-DSA-44 `(suite,pk)` provider from boot-verified `GenesisConfig.validators[]`, feeding the same `try_build_timeout_verification_context` main uses | **Dormant** — no production caller; release binary refuses the activating flag (S16) | **Reuse** (adapt as the single authority source) |
| Founding-epoch authority lifetime | S3 `authorize_configuration` | Fail-closed: authorizes **only** founding epoch 0 config (chain→genesis→count→commitment→epoch), else `AuthorityLifetimeError` | Founding epoch only; does **not** cover serialized epoch transitions | **Reuse** (adapt for multi-epoch profile) |
| Rollback-resistant *current* authorization | S4 `CurrentAuthorizationOwner` | In-process current-state model: `admit`→`confirm` with issuer binding (`ptr_eq`), monotonic `generation`, terminal `exhausted` latch | Production preflight supplies **`proposal_vote_authority: None`** (`main.rs:5549`) — no authority object at all — which is distinct from a *present-authority / missing-owner* case and a *present-authority / unavailable-owner* case; where an owner does exist, `Established` is `cfg(test)` only and the sole production constructor is `unavailable(...)`. Generation is **not durable** | **Missing** (production current-authorization source unavailable) |
| Inbound Proposal/Vote admission | S5 Required policy + `unavailable(...)` wiring | Under `Required` (production default), a present authority with `current_auth=None` rejects as current-state-unavailable **before crypto** | Rejects everything in production because current authorization is unavailable | **Reuse** (fail-closed gate is correct; needs a real current source) |
| Immediate outbound forwarding authorization | S6 `forward_actions_to_facade` | `admit`→epoch-check→sign via bound `snapshot.verifier()`→`confirm`→facade for BroadcastProposal/Vote/SendVoteTo; production wires `None` snapshot | Fail-closed only; no production authority to authorize a real send | **Reuse** |
| Cached re-emission authorization | S7 `admit_cached_reemission` | Fresh owner `admit`+`confirm` of an issuer+generation-bound `CachedReemissionProvenance` ticket before re-send | In-process only; no durability across restart | **Reuse** |
| Restore retransmission disposition | S8 restore-catchup deferral | Deferral path **discards** the decoded Proposal/ticket and re-runs admission fresh on re-delivery; Vote has no deferral path | Discards work; no completion of deferred effect | **Reuse** (its discard rule is the lifecycle rule for delayed work) |
| Persisted-epoch observation | S9 `observe_consensus_storage` | Read-only classification: NoStorageHandle / PresentNoCommittedEpoch / CommittedEpoch(u64); reuses schema + incomplete-transition + get_current_epoch | **Never converts to authorization**; persisted epoch is evidence only | **Reuse** (evidence input, not an authority) |
| Genesis ↔ record correspondence | S10 `check_genesis_record_correspondence` | Compares pinned expected identity vs untrusted claimed record vs C1 observation → all of co-origin / activation / current-auth **NOT-established** | Correspondence is **not** activation permission | **Reuse** (evidence input) |
| Runtime / wire-alias correspondence | S11 `resolve_network_wire_alias`; S12 `check_network_correspondence` | Standard-network aliases; retained validation policy vs `map_environment`; typed mismatches | Mapping policy only; not authorization | **Reuse** (do not build another alias registry) |
| Domain-bound QC verification | S13 `verify_quorum_certificate_with_domain` | Pure verifier: each signer via D6 v2 preimage, checked ceil(2W/3) in u128 → `VerifiedQuorumCertificate` | **Conditionally reachable**, not dormant: called by the inbound present-QC gate (C3E) at `binary_consensus_loop.rs:4736`, only when a bound snapshot **and** a present embedded QC exist; the result is non-authorizing | **Reuse** |
| Present-QC inbound gate | S14 inbound Proposal arm | Verifies a **present** embedded QC through S13 before engine effects; `proposal.qc == None` preserved exactly (neither verified, counted, nor inferred as bootstrap) | Only active when a bound snapshot **and** a present QC exist | **Reuse** |
| Verified-evidence retention | S15 `on_verified_proposal_event` / `register_block_with_verified_justification` | Retains the exact `Arc<VerifiedQuorumCertificate>` produced by the C3E gate at block registration under a byte budget, pre-mutation, with typed errors; performs **no second constituent-signature verification** | **In-process evidence ownership only** (`verified_justification` is non-serialized and discarded on restart); not persistence, not anti-rollback | **Reuse** |
| Durable replay / crash consistency | S17 `pqc_governance_production_durable_replay_rocksdb.rs` | **Governance**-replay restart persistence, atomic-write + partial-residue recovery, governance replay/equivocation rejection | **Test-only / disabled-by-default** (MainNet refused); its scope is **governance replay**, **not** validator Proposal/Vote signing-state persistence (§2.3.2) and **not** whole-database rollback protection; **no DB-wide monotonic counter / external anchor** → an older-but-valid DB is accepted on open | **Missing for anti-rollback** and **missing for signing-state continuity** (do not equate governance replay prevention with either) |
| Persistent anti-rollback anchor | S17 Run 055 sequence file; Trust-Anchor model §8 | Sequence anti-rollback for trust bundles, stored under `<data_dir>` | Stored in the **same rollbackable filesystem**; whole-DB / VM-snapshot restore defeats it | **Missing** (no independent freshness anchor) |

### 2.2 Duplication guardrails (explicit)

Do **not** introduce a duplicate registry, genesis parser, epoch source,
verifier, persistence mechanism, or authority wrapper: S1/S2/S3 supply genesis
and authority derivation; S9 supplies the epoch observation; S11/S12 supply the
alias mapping; S13 supplies QC verification; S15 supplies in-process retention.
Conversely, do **not** equate replay prevention (S17), crash consistency (S17),
or signed metadata with **rollback-resistant current authorization** (the
**Missing** rows: durable current source and independent freshness anchor).

### 2.3 Three distinct security requirements (never conflated)

Correct activation and safe operation require **three independent** properties.
None is established by message correspondence, and none by a matching or
"fresh-looking" epoch number:

* **(A) Activation authorization.** *Who or what policy authorizes this exact
  authority to operate?* A decision backed by a trusted root / evidence, not
  merely a validation that an identity is well-formed. Constructing an
  `Established` `CurrentAuthorizationOwner` (S4) is the **representation** of such
  a decision, **not** proof that the decision was legitimate. Today the only
  production owner constructor is `unavailable(...)` (S4; `Established` is
  `cfg(test)` only), so activation authorization is **absent** in a release build
  (§4).
* **(B) Current-authority freshness.** *Is that authorization still applicable to
  this network, epoch, membership, keys, and domain — now?* A statement about
  latestness against a rollback-capable environment (§5). A persisted committed
  epoch (S9) is **evidence**, never a freshness proof.
* **(C) Signing / consensus-state continuity.** *Has the validator retained the
  safety-relevant history needed to avoid incompatible actions after restart or
  rollback?* Distinct from (A) and (B): a correctly authorized, "fresh" authority
  can still double-sign if the record of its own prior signing decisions did not
  survive restart.

Neither correspondence nor a fresh epoch number establishes all three.

#### 2.3.1 Epoch equality does not establish (C) — explicit counterexample

Consider one validator plus an external witness, all reporting **epoch 0**:

1. A snapshot is taken **before** the validator signs a Vote.
2. The validator signs that Vote.
3. The earlier snapshot is restored.
4. Both snapshots and the external witness still report **epoch 0**.

An epoch comparison returns **equal** throughout. It cannot detect that a Vote
was signed between the snapshot and its restore, so it **cannot** establish
preservation of signing decisions or consensus safety state. A fresh or matching
epoch number is therefore not a substitute for requirement (C), and is not by
itself requirement (B).

#### 2.3.2 Safety-relevant signing state — source-backed inventory

Traced from the actual engine and storage. "Recovered" means a production
restart/restore path actually reads and restores the value; a `cfg(test)` fixture
is **not** production recovery.

| Safety-relevant state | Symbol / source | In-memory | Persisted | Recovered | Status |
|---|---|---|---|---|---|
| Current view | `current_view` (`basic_hotstuff_engine.rs:299`) | yes | no | reset to `committed_height + 1` (`:1146`, `initialize_from_restart`) | **not preserved** |
| Voted-in-view latch (anti double-vote) | `voted_in_view` (`:317`; checked `:1753`; set `:1824`; reset `:1012/1148/1220/2030`) | yes | no | reset to `false` on restart | **missing** |
| Proposed-in-view latch | `proposed_in_view` (`:314`) | yes | no | reset on restart | **missing** |
| Locked QC (locking rule) | `locked_qc` (`hotstuff_state_engine.rs:173`; getter `:293`) | yes | no (no `put_locked_qc`) | harness `load_persisted_state` reconstructs a *conservative* logical lock from the committed / embedded QC (`hotstuff_node_sim.rs:2095`–`:2135`) before `initialize_from_restart` — **not** recovery of the exact latest pre-crash locked QC; the production binary snapshot path (`initialize_from_snapshot_baseline`) restores none | **not durably preserved** |
| Per-view equivocation map | `votes_by_view` (`hotstuff_state_engine.rs:192`; cleared `:340`) | yes | no | not recovered | **missing** |
| Retained QC evidence (C3F) | `verified_justification` (`block_state.rs:74`) | yes | no (non-serialized `Arc`) | discarded on restart | **in-process only** |
| Committed block / QC | `put_block`/`put_qc` in `apply_epoch_transition_atomic` (`storage.rs:997`) | yes | yes | harness `load_persisted_state` reads `get_last_committed`→`get_block`→`get_qc` (`hotstuff_node_sim.rs:2049` / `:2066` / `:2085`) then `initialize_from_restart`; the **production binary** restore uses `initialize_from_snapshot_baseline` (`binary_consensus_loop.rs:2390`), reading **neither** `get_last_committed` **nor** any QC | **preserved (committed only); recovered on the harness path only** |
| Committed epoch | `put_current_epoch` (`storage.rs:1034`) | yes | yes | `get_current_epoch` via `observe_consensus_storage` (S9) | **preserved (committed only)** |

The `ConsensusStorage` trait (`storage.rs:142`) exposes `put_block` / `put_qc` /
`put_last_committed` / `put_current_epoch` / schema / epoch-transition-marker
methods **only**; there is **no** `put_last_voted_view`, `put_locked_qc`, or
vote-record method. `apply_epoch_transition_atomic` persists the **committed**
block, its QC, `last_committed`, and the target epoch — a **committed-block
checkpoint**. An earlier **uncommitted** signing decision (a Vote signed but not
yet committed, recorded only by the in-memory `voted_in_view` latch) is therefore
**not covered** by that checkpoint: on restart `voted_in_view` is `false` and
`current_view` is `committed_height + 1`, so the same view can be re-entered
without the prior signing decision being visible. This is why requirement (C) is
**not** satisfied by any persisted committed epoch, and why the §2.3.1
epoch-equality comparison cannot stand in for it. No new persistence format or
per-signature mechanism is prescribed in this documentation pass.

---

## 3. Supported lifecycle and effect boundary

Proposed baseline: **serialized authority transitions**. The current synchronous
handler's immutable ownership model (`CurrentAuthorizationOwner` held privately;
`admit`→`confirm` around each effect) remains intact. Concurrent mid-handler
replacement is treated as **unsupported** — a stated lifecycle constraint, **not**
a claim that concurrent invalidation has been implemented.

### 3.1 Lifecycle questions answered

* **Candidate validation.** A candidate authority is `build_genesis_consensus_authority`
  applied to a boot-verified, independently pinned `GenesisConfig` (S1+S2), and
  it must pass `authorize_configuration` for the founding epoch (S3).
* **Independent evidence that would authorize activation.** Correspondence
  between the pinned expected identity, the observed persisted epoch (S9), and
  the claimed record (S10/S12), and a durable, rollback-resistant proof that the
  observed epoch is *current now* (requirement B, the Missing rows), are each
  **necessary but not sufficient**: neither, nor both together, authorizes
  activation. Activation additionally requires an **independent trusted
  activation root / evidence** authorizing this exact authority (requirement A,
  §4.0) plus the requirement-C signing-state prerequisites. The complete set of
  activation prerequisites is the §3.3.1 checklist; correspondence plus freshness
  alone is explicitly **not** authorization to activate.
* **When an authority becomes current.** Only when a real current-authorization
  source constructs an `Established` `CurrentAuthorizationOwner`. Today the only
  production constructor is `unavailable(...)`, so no authority is ever current
  in a release build.
* **Exact point replacement becomes effective.** At the private generation
  advance inside the owner: an already-`admit`ted ticket whose `generation` no
  longer matches fails `confirm` as `Stale` **before** its effect. Effectiveness
  is defined at that in-process boundary, not at any external send.
* **Work admitted before that point.** A ticket admitted under the prior
  generation is rejected at `confirm`; the pending effect is **discarded**, never
  completed under stale authority. This matches the restore-catchup rule (S8),
  which discards the decoded Proposal and re-admits fresh.
* **Shutdown / restart / recovery / exhaustion.** Restart re-derives a candidate
  but yields an `unavailable(...)` owner until a real current source exists (no
  signing). Restart also does **not** restore the requirement-(C) signing state:
  `voted_in_view`/`proposed_in_view` reset and `current_view` becomes
  `committed_height + 1` (§2.3.2), so even were an owner available, signing-state
  continuity would remain unestablished. Exhaustion (`is_exhausted`) is a terminal
  latch: no admission or confirmation ever succeeds again, with no wraparound or
  reset.

### 3.2 Effect boundaries (must be distinguished; never conflated)

| Boundary | Mechanism | Cancellable after the fact? |
|---|---|---|
| Engine mutation | S15 block registration | No — once state mutates it is not "un-signed" |
| Signing (produce signature) | S4 `admit`→epoch-check→**sign** via bound verifier context | A produced signature may still be suppressed before transmission |
| Transmit signature (`confirm`→handoff) | S4 `confirm` gate, then facade handoff (S6) | Only *before* `confirm` returns; not after handoff |
| Facade handoff | S6 `forward_actions_to_facade` | No after handoff |
| Queued transmission | facade queue | No after enqueue |
| Actual socket delivery | transport | No |
| Remote processing | peer | No |

**Actual outbound order (traced).** For BroadcastProposal / BroadcastVote /
SendVoteTo the real sequence is **admission/epoch checks → signing → confirmation
→ facade handoff**: `admit_outbound_action` (and the cached-reemission admit),
then `sign_vote_for_broadcast` / proposal signing, then
`confirm_outbound_before_effect`, then `facade.broadcast_*`
(`binary_consensus_loop.rs` `forward_actions_to_facade` ~`:3505`–`:3613`; the
cached path near `:3571`–`:3596` signs *before* `confirm`). A **completed
signature** (bytes already produced) is therefore distinct from a **transmitted
signature**: `confirm` can suppress an already-computed signature before the
facade handoff, but once handed off the effect is not cancellable. Any different
future ordering (for example confirming *before* signing) is **proposed only** and
would carry the additional requirement of not producing signature bytes before the
current-authority check; it is not the current behavior.

**No effect that has already occurred is promised cancellation.** For delayed
work the transition rule is explicit: **discard and re-admit fresh** (the S8
disposition), never silently complete under a superseded authority.

### 3.3 Release-profile comparison

| Profile | Reuses | Remaining work |
|---|---|---|
| **A. Founding-authority-only first release** | S1–S3 (validate + founding-epoch guard), S4 fail-closed owner, S13–S15 verification/retention | The full dependency list in §3.3.1 (activation root, freshness, wiring, QC/Timeout compatibility, signing-state recovery + rollback safety, adversarial evidence) — **not** just an epoch-current proof |
| **B. Serialized epoch transitions** | All of A plus a serialized transition marker + committed-epoch source | Everything in A **plus** durable transition ordering, an epoch source beyond the same-disk DB, and per-transition anti-rollback |

**Recommendation:** pursue **Profile A first**. It has the smallest safety
surface, reuses the founding-epoch guard (S3) unchanged, and does not require
solving serialized multi-epoch durability before a first release. Profile A is
**not** "no restart safety": a fixed founding authority still needs the durable
anti-rollback proof of §5 before it can sign in production. Do **not** silently
broaden the founding-epoch guard to admit later epochs, and do **not** treat a
fixed authority as eliminating restart / rollback safety.

**Profile A is a *proposed first-release profile*, not an activation approval.**
Anchor selection (§5) alone does not unblock it. Its dependencies, each satisfied
on its own terms, are:

#### 3.3.1 Profile A dependency list

1. **Activation-authorization root / evidence** (requirement A, §2.3 / §4.0) —
   currently a **missing prerequisite** (S16 refuses activation).
2. **Bootstrap / absent-QC policy** (§4.2) — open.
3. **Trusted production identity and runtime / wire correspondence** (S1, S11/S12).
4. **Coherent authority, engine, verifier, and signer wiring** (S2 feeding
   `try_build_timeout_verification_context`; S13/S14/S15; S5/S6).
5. **Applicable QC formation / propagation and Timeout / NewView compatibility**
   (S13/S14; the Timeout bridge, §6.1) — open.
6. **Current-authority freshness** (requirement B, §2.3 / §5) — a durable,
   rollback-resistant proof, via an independent anchor (§5.2), that the observed
   epoch is current now; **missing** and distinct from item 7. A persisted
   committed epoch (S9) is evidence, never freshness.
7. **Signing-state recovery and rollback safety** (requirement C, §2.3.2; §5) —
   missing durable last-voted-view / locked-QC / anti-rollback; distinct from the
   item 6 freshness proof.
8. **Configured-authority release-binary adversarial evidence** —
   `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED` (S16).

A3 issuer identity / exhaustion (S4) and A4 serialized-handler ordering are
existing **scoped** results; this contract does not reopen them as wholly
unimplemented.

---

## 4. Bootstrap and activation authorization

These five steps are **independent**; each must be satisfied on its own terms:

1. **Validate an independently pinned genesis** — S1 (`verify_boot_time_genesis(Some(pin))`).
2. **Establish network / membership correspondence** — S11/S12.
3. **Authorize activation** — a *decision* backed by a trusted root / evidence,
   **not** the same thing as validating identity (1) or freshness (4). Currently
   **disabled** (S16 refuses the flag); the authorizing mechanism itself is a
   missing prerequisite (§4.0).
4. **Establish that an authority is current now** — Missing (needs a real current
   source + durable freshness (B) and signing-state continuity (C)).
5. **Permit a specific Proposal/Vote effect** — S5/S6 in the actual order
   `admit`→epoch-check→**sign**→`confirm`→facade handoff (§3.2).

### 4.0 Activation authorization root (requirement A) is a missing prerequisite

Step 3 is **not** satisfied by steps 1, 2, 4, or 5. Validating that an authority
is well-formed (S1/S2), that it corresponds to the network (S11/S12), and even
that it is fresh (§5) does **not** identify *who or what policy authorizes this
exact authority to begin signing*. No such trusted activation root / evidence
exists in the worktree today: the only production owner constructor is
`unavailable(...)`, and the release binary refuses
`--consensus-authority-from-genesis` with `std::process::exit(1)` (S16).
Constructing an `Established` owner would be the **representation** of an
authorization decision, not proof it was legitimate; the mechanism that would make
that decision (an operator policy / trust root / signed activation evidence bound
to the exact authority) is a **recorded missing prerequisite**, not something this
contract supplies. Anchor selection (§5) alone does **not** unblock activation. The
complete activation acceptance checklist is §3.3.1; requirement A is one item on
it and is **not** established by identity validation (1), correspondence (2), or
freshness (4).

### 4.1 Current absent-QC Proposal path (traced)

In the inbound Proposal arm, the present-QC gate (S14) runs only when
**both** a bound snapshot and `proposal.qc == Some(..)` exist. `proposal.qc == None`
is preserved exactly: it is **neither verified nor counted**, and is **never**
inferred as a validated bootstrap exception. In a production release the arm
never reaches the QC gate at all. Under the fail-closed `Required` policy, after a
successful F6 sender binding, the handler rejects **before any crypto** in one of
two **distinct** cases (reusing the audit condition/result/timing table in
`QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` §2):

* **No effective Proposal / Vote verification authority** — increment
  `inbound_proposal_verification_context_unavailable_total` or
  `inbound_vote_verification_context_unavailable_total`; reject before crypto.
* **Effective authority present but the current authorization snapshot is absent**
  — increment the corresponding
  `inbound_proposal_current_state_unavailable_total` /
  `inbound_vote_current_state_unavailable_total`; reject before crypto.

Current production wiring supplies **no** Proposal / Vote authority and **no**
authorization snapshot (`proposal_vote_authority: None`, `main.rs:5549`), so it
takes the **first** case. The second case is a **compiled production branch**, not
a `cfg(test)`-only construct; production wiring simply never reaches it because it
supplies no effective authority. What is restricted to `cfg(test)` is
**constructing an `Established` current authorization** (the present-authority
fixture) — the sole production owner constructor is `unavailable(...)` — not the
rejection branch itself. There is therefore no production absent-QC bootstrap
permission today, and none is fabricated here.

### 4.2 Requirements for any future bootstrap exception

If a bounded bootstrap exception is ever proposed, it must record: its **trusted
anchor** (independent of the DB and of peers); the exact **admitted epoch**; the
**permitted proposal fields**; its **replay / restart behavior**; and a
**termination condition** after which the exception can never re-open. Bootstrap
permission must **not** be inferred from an empty database, a missing epoch, an
engine default, an unsigned/empty QC, a genesis label, or a peer assertion. An
empty database may mean either first initialization **or** lost/restored state;
the trust model must distinguish them via appropriately authenticated trusted
state / evidence **outside the specified attacker rollback domain** (the §5
anchor — protected local hardware or a remote witness, neither mandated nor
selected here, and not necessarily an off-box service), because the local
filesystem alone cannot tell the two apart.
The present-QC path is not weakened and no QC is fabricated to solve bootstrap.

### 4.3 Per-transition record (conceptual; not new code types)

| Transition | Prior state | Trigger | Trusted inputs | Authorization condition | Required durability | Permitted effects | Fail-closed outcome |
|---|---|---|---|---|---|---|---|
| Candidate build | none | boot | pinned genesis (S1) | S3 founding-epoch guard passes | none (in-memory) | build owner `unavailable(...)` | refuse to activate (S16) |
| Activation | candidate + `unavailable` | operator + evidence | S9 epoch + S10/S12 correspondence + **durable freshness anchor** + **a trusted activation-authorization root (requirement A)** + **requirement-C signing / recovery prerequisites** | all correspond **and** anchor proves current **and** a trusted root authorizes this exact authority **and** signing-state continuity is established — correspondence + anchor alone are **insufficient** | anchor + committed epoch durably ordered | construct `Established` owner | remain `unavailable` (no signing) |
| Sign effect | `Established` owner | inbound/outbound action | admitted ticket (S4) | `confirm` matches generation, not exhausted | durable signing-state continuity (requirement C) is an **unmet** prerequisite — one-time activation durability does **not** establish ongoing signing-state continuity | sign + forward (S6) | `Stale`/`Exhausted`/`ForeignIssuer` reject |
| Replacement | `Established` gen N | new epoch | new correspondence + anchor advance | new candidate authorized + anchor strictly newer | durable epoch advance before signing | generation advance (in-process bookkeeping only) | reject the new candidate; gen N may keep signing **only** while independently established current and authorized — if superseded/revoked or if current authorization is unavailable, **fail closed** |

**Generation advancement is not activation.** The private `generation` counter on
`CurrentAuthorizationOwner` is **in-process invalidation bookkeeping**: it makes a
stale ticket fail `confirm`. It is **not** by itself authenticated activation, a
durable cutover, or a protocol-wide transition, and advancing it does not by
itself authorize the successor. A replacement that *fails* does not automatically
license continuing under the prior generation: the prior authority may sign only
while it remains independently established as current and authorized (requirements
A and B); if it is known superseded or revoked, or if current authorization
becomes unavailable, signing MUST fail closed rather than "keep generation N".
Activation durability (a one-time cutover) is separate from ongoing
signing / recovery safety (requirement C); "no durability beyond activation" is
**not** a sufficient lifecycle contract.

---

## 5. Durable freshness and rollback threat model

### 5.1 Threat classes (distinguished)

| # | Threat | Handled today | Requires additional trust |
|---|---|---|---|
| T1 | Ordinary restart / interrupted write | S17 atomic-write + partial-residue recovery (disabled default) — **governance-replay crash consistency only**; does **not** establish validator signing-state continuity (requirement C) | crash consistency ≠ signing-state continuity |
| T2 | Incomplete epoch transition / corrupted metadata | S9 detects incomplete transition (read-only) | activation ordering |
| T3 | Restoration of an older **valid** database | **No** | independent freshness anchor |
| T4 | Whole machine / VM snapshot restore (incl. local markers) | **No** | trusted state / evidence outside the attacker's rollback domain (protected local hardware **or** a remote witness — neither selected nor proven here) |
| T5 | Cloned / compromised signing keys | **No** | key custody / attestation (out of scope here) |
| T6 | Network partition / loss of freshness service | **No** | anchor availability model |

A signed checkpoint or monotonic number stored **only in the same rollbackable
database** (S17 Run 055 sequence file under `<data_dir>`) is **insufficient** to
prove latestness after whole-database restoration (T3/T4): the restore rolls the
counter back with the data.

### 5.2 Independent freshness-anchor options (assumptions)

| Option | Independence | Decentralization | Operational cost | Post-quantum note |
|---|---|---|---|---|
| On-chain height / QC from a live quorum | Strong if quorum is honest+live | High | Requires liveness | PQ if QC uses D6 v2 domain (S13) |
| External decentralized beacon / anchor chain | Strong | Medium–High | Integration + availability | Must avoid classical-signature dependence |
| Operator/cloud attestation service | **Weak** — becomes a new trusted authority | Low | Low | Often classical crypto; **rejected as silent dependency** |
| Peer-assisted "highest epoch received" | **Insufficient** — not proven current or independently trusted | — | — | — |

Do **not** silently introduce a classical signature/attestation dependency and
do **not** make a cloud/operator service a new trusted authority. Any
peer-assisted recovery must explain why its reference is **current and
independently trusted**; "highest epoch received" is explicitly insufficient.

### 5.2.1 What an anchor interface must state before it is permissible

A comparison can **classify** a supplied value (ahead / equal / behind); it
**cannot authenticate the value's origin**, and a caller-controlled "source label"
does not change that. An abstract anchor interface is permissible **only** after
its contract states:

* **What authenticates the witness** (not a self-declared source field).
* **Which network / genesis / authority and which validator instance** it
  concerns.
* **What safety-relevant state or history it binds** (requirements B and C),
  including whether it binds signing-state continuity or only an epoch number.
* **How freshness and replay resistance are established.**
* **Which state lies outside the attacker's rollback capability** (the rollback
  domain), described relative to that domain rather than by mandating one fixed
  transport. Protected local hardware state and a remote witness make **different**
  assumptions and are both admissible designs; an off-box service is **not** the
  only possible design.
* **Behavior on unavailable, conflicting, stale, or unverifiable evidence**
  (fail-closed unless independently established otherwise).

No classical-signature / attestation dependency may be introduced silently, and no
cloud / operator service may become a new trusted authority (§5.2 table).

**Live-quorum / QC anchor proposals** must additionally state their
**authentication**, **freshness**, **trusted-membership**, **cold-start**,
**all-validator-restart**, and **partition** assumptions. A valid QC verified via
S13 proves a quorum signed a block; it does **not** prove it is the **latest**
state, nor does it preserve any validator's prior signing decisions (requirement
C). It is therefore not, by itself, a freshness or continuity anchor.

### 5.3 Unresolved decision (recorded, not resolved)

The available evidence does **not** yet justify selecting a specific anchor.
Consequence, stated exactly: **production current authorization remains
unavailable** (`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`). This contract does
**not** claim durable anti-rollback has been established.

Anchor selection stays **explicitly unresolved**. No "durable freshness" claim may
rest on a caller-supplied scalar: a provenance / source label attached to such a
scalar classifies but does not authenticate it, so it cannot establish requirement
(B) or (C).

### 5.4 Required ordering

Durable state MUST be committed **before** authority activation, and activation
MUST precede any signing / external effect: `commit(epoch+anchor)` →
`activate(Established owner)` → `admit` → epoch check → **sign** → `confirm` →
facade handoff (the §3.2 order; `confirm` follows signing and can only suppress an
already-produced signature *before* handoff, never un-create it). **Crash
safety** (T1/T2, addressable by S17-class atomic writes) is distinct from
**protection against malicious rollback** (T3/T4, requiring the independent
anchor). The former does not imply the latter.

---

## 6. Production correspondence and remaining integration

The existing C3A/C3B mapping policy (S11/S12) is preserved. The remaining task
is **trusted production consumption**, not another wire-alias registry.

### 6.1 One coherent authority would supply

* **Genesis / network identity** — from boot-verified pinned `GenesisConfig` (S1).
* **Runtime ChainId and expected wire alias** — via `resolve_network_wire_alias`
  (S11); never parsed from the genesis label or truncated from an arbitrary
  runtime ID.
* **Membership, voting power, keys, suites, signing domain** — from
  `build_genesis_consensus_authority` (S2) feeding the same
  `try_build_timeout_verification_context` main uses. Note the direction of this
  relationship: genesis-derived membership / keys feed the **Timeout / NewView**
  verification bridge; that bridge does **not**, by itself, establish Proposal /
  Vote authority. Production makes this explicit — the legacy
  `--validator-consensus-key` path builds **only** the Timeout / NewView context
  and sets `proposal_vote_authority: None` (`main.rs:5545`–`5549`), so Timeout
  credentials must never be read as Proposal / Vote activation.
* **Authorized-epoch correspondence** — S3 founding-epoch guard + S9 observed
  epoch (correspondence and evidence only, **not** activation).
* **Activation authorization** — an independent trusted activation root /
  evidence authorizing this exact authority (requirement A, §4.0); a **missing
  prerequisite** today (S16 refuses the flag), never derived from the founding-
  epoch guard or the observed epoch.
* **Current-authority freshness** — the §5 durable, rollback-resistant anchor
  (requirement B), still unselected. The complete activation prerequisites are the
  §3.3.1 checklist.
* **Engine, verifier, signer, cache, recovery context** — S13 verifier, S15
  retention, S6/S7 forwarding/re-emission, S8 restore disposition.

Never parse numeric ChainId from the genesis label, never truncate arbitrary
runtime IDs, and never derive trusted values from incoming messages.

### 6.2 Remaining dependencies (tracked separately)

1. Absent-QC / bootstrap policy (§4.2) — **open**.
2. QC formation and propagation — **open**.
3. Timeout / NewView compatibility — **open**.
4. Production lifecycle (activation, §3/§4) — **open**.
5. Persistent freshness / anti-rollback anchor (§5) — **open**.
6. Configured-authority release-binary adversarial evidence — **not captured**
   (S16 refuses today).

Accepted C3F retention (S15) is scoped to **in-process evidence ownership**; it
does **not** close any dependency above.

---

## 7. First-release profile recommendation and dependency order

* **Recommended profile:** **A — founding-authority-only** (§3.3), because it
  minimizes the safety surface and reuses S3 unchanged.
* **Dependency order (must be satisfied in sequence):**
  1. **Implementation and isolated (non-production) validation — produces the
     required evidence.** Wire the coherent authority / engine / verifier / signer
     path (S2 feeding `try_build_timeout_verification_context`; S13/S14/S15;
     S5/S6), exercise founding-epoch activation in isolation, and **capture the
     configured-authority release-binary adversarial evidence**. These steps
     *produce* the evidence the checklist later requires; none of them is
     production activation, and none authorizes a test bypass or a new activation
     flag.
  2. Durable ordering commit-before-activate-before-sign (§5.4).
  3. **Production activation is permitted only after the complete §3.3.1
     activation acceptance checklist is satisfied** — activation-authorization
     root (requirement A), current-authority freshness (requirement B) via an
     independent anchor (§5.2), signing-state continuity (requirement C), bootstrap
     / absent-QC policy (§4.2), coherent wiring, applicable QC / Timeout / NewView
     compatibility, and the release-binary evidence captured in step 1. Founding-
     epoch activation wiring then replaces the S16 refusal. Anchor selection alone
     does **not** unblock activation, and activation is never its own
     prerequisite.
  4. (Profile B only) serialized epoch-transition marker + committed-epoch source.

---

## 8. Acceptance scenarios (for later implementation)

1. **Fail-closed default preserved.** With no anchor configured, a release binary
   still constructs only `unavailable(...)` and refuses to sign; S16 refusal holds.
2. **Older-DB restore rejected.** After restoring an older valid DB (T3), a node
   with the anchor refuses to activate an epoch older than the anchor's current
   value (typed rollback refusal); without the anchor it stays `unavailable`.
3. **VM-snapshot restore rejected.** A whole-VM snapshot including local markers
   (T4) does not activate; a trusted anchor outside the rollback domain (protected local hardware or a remote witness — not selected here) detects staleness.
4. **Empty-DB ambiguity.** First-init vs lost-state is resolved only by
   appropriately authenticated trusted state / evidence outside the specified
   attacker rollback domain (§5 — not necessarily an off-box service or any one
   fixed anchor); an empty DB alone never grants bootstrap.
5. **Replacement between completed operations (not mid-handler).** The existing
   synchronous handler holds the owner by an immutable borrow, so **no same-owner
   replacement occurs halfway through a single handler's borrow**; replacement is
   modeled only **between** completed operations. A ticket admitted under
   generation N and re-checked after a subsequent generation advance fails
   `confirm`; the pending effect is discarded (the S8 disposition), not completed.
   A produced-but-not-yet-transmitted signature is likewise suppressed at
   `confirm` (§3.2). This scenario does **not** assert or require mid-handler
   replacement.
6. **Present-QC unchanged / absent-QC unchanged.** A present embedded QC is still
   verified through S13/S14; `proposal.qc == None` remains neither verified,
   counted, nor treated as bootstrap.

---

## 9. Single bounded next implementation task

**Objective.** Produce a **source characterization of existing signing-state
persistence and recovery** for the same-epoch restart / restore case, using the
paths that already exist — **before** proposing any new abstraction. Concretely,
document, through the real entrypoints, exactly what the restart / restore path
reads and restores versus what it drops for a validator that signed a Vote in the
current (e.g. founding, epoch 0) view but did not commit it, and classify the
result as *evidence of missing protection* vs *evidence that protection exists*.
This turns §2.3.2's inventory into a bounded, testable characterization without
inventing a new module, storage key, or anchor transport, and without enabling
activation.

* **Actual entrypoints / paths to characterize:**
  * `basic_hotstuff_engine.rs` `initialize_from_restart` (`:1138`) and the
    production `initialize_from_snapshot_baseline` restore path used by
    `binary_consensus_loop.rs`, including `current_view = committed_height + 1`
    (`:1146`) and the reset of `voted_in_view` / `proposed_in_view`.
  * `storage.rs` `apply_epoch_transition_atomic` (`:997`), `get_last_committed`
    (`:879`), `get_current_epoch` (`:936`), and the absence of any
    `put_last_voted_view` / `put_locked_qc` / vote-record method on the
    `ConsensusStorage` trait (`:142`).
  * S9 `observe_consensus_storage` (`consensus_storage_observation.rs`) as the
    existing read-only, non-authorizing observation surface.
* **Reusable mechanisms:** S9 observation states; the D7-C module conventions
  (`cfg(test)` fixtures, typed non-authorizing result types, no production
  wiring). No new production module is required to *characterize* current behavior.
* **Prerequisites (state explicitly; do not fabricate):** the traced paths — the
  `ConsensusStorage` trait (`storage.rs:142`), `apply_epoch_transition_atomic`, the
  harness `load_persisted_state` / `initialize_from_restart`, and the production
  `initialize_from_snapshot_baseline` — expose **no** durable writer / reader /
  recovery path for last-voted-view, locked-QC, or per-vote signing decisions
  (§2.3.2). This is a finding about **those inspected interfaces and paths**, not a
  proven repository-wide absence; the characterization task's job is to determine
  what the actual paths establish. A characterization task must **not**
  create such a path in a fixture and then present the result as production
  recovery. If the task is later extended to *add* protection, that durable
  writer / reader / recovery path is a **prerequisite**, not an assumption.
* **Test scenarios (characterization, `cfg(test)`) — three distinct cases, each
  naming its entrypoint and persisted data; keep harness recovery
  (`load_persisted_state` / `initialize_from_restart`) distinct from the production
  binary snapshot path (`initialize_from_snapshot_baseline`), and keep
  `CommittedEpoch(0)` distinct from `PresentNoCommittedEpoch`:**
  1. **Ordinary restart after an uncommitted signing decision.** Sign a Vote in view
     V at epoch 0 (not committed), then restart. The decision is recorded only by the
     in-memory `voted_in_view` latch, which no writer persists; after the restart
     entrypoint `voted_in_view` is `false` and `current_view` is `committed_height +
     1`. Characterize what the entrypoint reads versus drops.
  2. **Restoration of a snapshot captured BEFORE that signing decision.** Snapshot
     before the Vote is signed; sign the Vote; restore the earlier snapshot. The
     production restore uses `StateSnapshotMeta` + `initialize_from_snapshot_baseline`,
     which carries only height / block hash and restores no QC or vote history, so the
     signed-then-rolled-back Vote leaves no trace.
  3. **Existing committed-state recovery (control).** On the harness path a
     *committed* block **is** restored via `load_persisted_state`
     (`get_last_committed`→`get_block`→`get_qc`→`initialize_from_restart`); assert
     `observe_consensus_storage` reports `CommittedEpoch(0)` (distinct from
     `PresentNoCommittedEpoch`) and never converts to authorization.

  Scenarios 1–2 show that neither restart nor snapshot restore covers an uncommitted
  signing decision; scenario 3 bounds what committed-state recovery restores. A reset
  latch or a repeated engine action is **not**, by itself, proof that two conflicting
  signatures were created or transmitted; any later behavioral claim must name the
  boundary actually exercised.
* **Exclusions:** no new module, storage schema, wire format, or anchor transport;
  **no `freshness_anchor_observation.rs`**; no activation or readiness promotion;
  no Run 423 work. **Isolated test-fixture signing is permitted for
  characterization** — scenarios 1 and 2 sign a Vote in a `cfg(test)` fixture to
  exercise the uncommitted-signing-decision case; **production signing enablement
  and authority activation remain prohibited.** The task is **not**
  implementation-ready as
  *protection* while its security semantics (requirement-C durability) remain
  unspecified — it is bounded to **characterization** of existing paths, and it
  distinguishes evidence of missing protection from evidence that protection
  exists.

## Run 422 D7-D2 inventory / next-step note (characterization only)

Per §§2.3 and 9, Run 422 D7-D2 characterized (test + source inspection, no
production change) what the existing recovery entrypoints preserve across restart
and pre-decision snapshot restore. Inventory observation: none of
`BasicHotStuffEngine::initialize_from_restart`,
`initialize_from_snapshot_baseline`, or `NodeHotstuffHarness::load_persisted_state`
consumes a persisted per-view vote or anti-equivocation record. The harness reader
path (`load_persisted_state` → `initialize_from_restart`) reconstructs committed
state plus a conservative lock derived from committed/embedded QCs only; the
production binary snapshot initializer `initialize_from_snapshot_baseline`
reconstructs committed height + an opaque anchor from the two `StateSnapshotMeta`
fields it consumes (`block_hash`, `height`) and reconstructs **no** QC lock
(`locked_qc()` stays `None`). The in-process double-vote latch therefore does not
survive restart or restore, so signing-state continuity remains NOT-established.
Evidence: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D2 section) and
`crates/qbind-node/tests/run_422_d7d2_signing_state_recovery_tests.rs`. Next step
(not authorized here): characterize the actual binary snapshot-restore call path
over a real RocksDB artifact before considering any durable protection.
## Run 422 D7-D3 successor note (binary snapshot-restore characterization only)

The D7-D2 next step above is now covered by characterization only. Run 422 D7-D3
exercised the actual binary snapshot-restore call path over a real RocksDB
checkpoint through the **unmodified `qbind-node` release executable**
(sha256 `060fb0f0…`): create checkpoint via `StateSnapshotter::create_snapshot`,
launch the binary with `--restore-from-snapshot`, observe the ordered startup
stages (restore → Run 093 storage open → Run 097 epoch parity → LocalMesh loop),
deliberately terminate or fail closed, then independently reopen the RocksDB
stores. It confirmed, at the executable level, that only the `RestoreBaseline`
(`snapshot_height` + `snapshot_block_id`) reaches
`initialize_from_snapshot_baseline`, that the consensus store distinguishes
epoch-absence from explicit `0`, and that an epoch-parity conflict fails closed
(nonzero exit, existing epoch preserved) with account-state restoration having
already occurred before rejection. No signing/locking evidence is restored,
reconstructed, or observable through these paths. No production change; signing-
state continuity remains NOT-established; `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`. Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D3 section) and
`crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`.

### Run 422 D7-D3 correction (process observation + successor distinction)

The D7-D3 evidence was corrected for process-observation and evidence-boundary
honesty. The ordered startup observation now runs THROUGH an existing
post-baseline observation — `[binary-consensus] B5: applied restore baseline:
snapshot_height=… starting_view=…`, emitted after
`engine.initialize_from_snapshot_baseline(...)` executes — so engine-initializer
CONSUMPTION of the `RestoreBaseline` is executable-observed, whereas the earlier
`[binary] B5: …enabled` and `[binary] LocalMesh mode: starting consensus loop`
lines establish only baseline construction and entry into the LocalMesh startup
dispatch. That no per-view vote latch / anti-equivocation record travels the
recovery interface remains a source-traced finding; signing-state continuity
stays NOT-established. No production change; no readiness promotion.

The recommended successor MUST distinguish two paths over a partially-restored
directory and must not conflate them: a restart **WITH** `--restore-from-snapshot`
reaches the B3 `TargetStateNotEmpty` guard (that guard belongs to *requested*
restoration), whereas an **ordinary restart WITHOUT** the restore request has
`apply_snapshot_restore_if_requested` return `Ok(None)` and never reaches that
guard — so its outcome is not predetermined by `TargetStateNotEmpty`. Neither
scenario is implemented in this correction. Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D3 correction
subsection).

## Run 422 D7-D4 successor note (partial-restore restart characterization only)

The D7-D3 next step is now extended by characterization only. Run 422 D7-D4
records, against the same release executable, what the binary does on the two
starts that follow a partially completed restore (restored `state_vm_v0` +
preserved conflicting consensus epoch 42): the WITH-flag repeat is refused by the
requested-restoration `TargetStateNotEmpty` guard (natural exit 1; no state,
epoch, or audit-marker mutation), while the WITHOUT-flag ordinary start returns
`Ok(None)` (no `TargetStateNotEmpty` guard, no Run 097 epoch comparison) and
proceeds to the consensus-loop-start boundary with `restore_baseline=false` over
the mixed destination — an observed limitation requiring assessment, not safe
recovery, and not repaired here. This changes no lifecycle-contract clause and
authorizes nothing: no proposal/vote authority is derived, activated, or
continued by either start. Signing-state continuity remains NOT-established and
C4/C5 stay open. Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D4 section).

## Run 422 D7-D5 successor note (pre-materialization epoch-conflict rejection)

Run 422 D7-D5 adds a production correction (code + test): a requested snapshot
restore whose declared canonical epoch conflicts with the destination consensus
storage's committed epoch is rejected BEFORE account-state materialization,
snapshot-byte copy, restore-marker write, or baseline construction, preserving
the pre-existing committed epoch. The reusable non-writing compatibility decision
(`evaluate_restore_epoch_compatibility`) is shared by the early check and the
Run 097 persistence path; the early check writes nothing. The check binds to the
same validated `StateSnapshotMeta` that materializes the restore and reuses one
canonical consensus-storage handle across check, materialization, and
persistence. This authorizes nothing: no proposal/vote authority is derived,
activated, or continued; matching, missing, or successfully restored epochs are
not authorization, signing continuity, or activation evidence. Signing-state
continuity remains NOT-established and C4/C5 stay open; durable anti-rollback and
cross-database atomicity remain NOT-established, and ordinary startup over a
legacy partial directory is outside this correction's scope. Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D5 section).

## Run 422 D7-D5 corrective note (CLI precheck bypass + cached-epoch decisions)

The D7-D5 successor note above is corrected. A requested restore combined with any
CLI storage-exit mode is now REFUSED before the early storage open and before any
account-state materialization or restore-marker write (all predicates covered,
including the Run 077 peer-candidate path-only and enabled-only partial shapes);
CLI modes without a restore are unchanged. The epoch-compatibility decision is now
taken from a fresh LIVE read of the committed epoch through the canonical storage
handle rather than the cached startup observation, so a same-handle write cannot
leave a stale decision to authorize a conflicting overwrite, and a live-read
failure stays an error rather than epoch absence. Authority lifecycle posture is
unchanged. Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D5 corrective pass).

## Run 422 D7-D7 successor reference (restore completion contract)

The authoritative contract for containing interrupted snapshot restores is now
`docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md` (status
`D7D7_RESTORE_COMPLETION_CONTRACT=DEFINED-NOT-IMPLEMENTED`). It defines a durable
restore-transaction record (INTENT/COMPLETE), serialized by a chosen
destination lock (kernel advisory `flock` on `<data_dir>/restore.lock`), so that
ordinary startup refuses a tracked, interrupted restore (`INTENT`) while proceeding
over untracked/ordinary destinations, and admits only a COMPLETE restore covering
account-state installation, the required audit record, and required epoch
persistence. As authored at D7-D7 it was documentation-only and established no
operational protection. **Run 422 D7-D8 update:** the restore-admission and
startup-containment scope of that contract is now implemented and tested in the
tree (bounded RTR reader, advisory destination lock, ordinary-startup guard,
profile-independent required-state admission, and synced-storage completion
barrier), with release-binary acceptance evidence; see the "Run 422 D7-D8
implementation status" block in that contract. Matching, missing, or completed
restores are still not authorization, signing continuity, or activation
evidence, and power-loss durability / durable anti-rollback remain
NOT-established. Authority lifecycle posture is unchanged and
C4/C5 stay open. Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D7 and D7-D8 sections).

## Run 422 D7-D9 successor reference (signing-state continuity contract)

Requirement (C) — signing / consensus-state continuity — is now elaborated by
the single authoritative peer contract
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`
(status `D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED`). This
lifecycle contract remains the authority over requirements (A) activation and
(B) current-authority freshness; the D7-D9 contract does not reopen (A)/(B) and a
signing record alone establishes neither.

Operative reconciliation (current implementation vs proposed requirement — the
D7-D9 protocol is NOT relabelled as existing behavior):

* **Current behavior (traced):** the immediate outbound signing path
  (`binary_consensus_loop.rs::forward_actions_to_facade`, L4101) runs
  `admit_outbound_action` (L3852) → `sign_proposal_for_broadcast` /
  `sign_vote_for_broadcast` (L3646/L3733) → `confirm_outbound_before_effect`
  (L3913) → facade. A **second** caller family, cached re-emission
  (`maybe_reemit_on_late_peer_connect`, L3379), reaches the **same** signing
  helpers through its **own** `admit_cached_reemission` → sign → confirm cycle and
  does **not** pass through `forward_actions_to_facade`. Confirmation runs AFTER a
  completed signature and can only suppress the network effect; it cannot un-sign.
  No signing decision is persisted; `voted_in_view` / `proposed_in_view` latches
  are in-memory and lost on restart.
* **Current storage inventory (corrected):** `ConsensusStorage`
  (`storage.rs` L142) exposes `put_current_epoch_synced` (L224) and
  `flush_epoch_durable` (L242); the obsolete claim that it exposes no synced
  operation is not repeated. Those epoch operations persist a coarse epoch value
  only and do NOT persist any signing decision.
* **Proposed requirement (D7-D9, not implemented):** a durable, fail-closed
  reservation of the exact authorized decision committed BEFORE `signer.sign_*`
  is invoked (durable-before-sign, INV-1), with the linearization point at the
  acknowledged reservation. Durable anti-rollback anchor selection stays
  UNRESOLVED and consensus-lock recovery stays an unmet prerequisite.

Authority lifecycle posture is unchanged; C4/C5 stay open; no activation or
readiness promotion. Evidence:
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (Run 422 D7-D9 section).

## Run 422 public DevNet Proposal/Vote signing-profile decision proposal

**DRAFT / OWNER DECISION PENDING / NOT IMPLEMENTED**

**Approval fields:** decision `PENDING`; approver `PENDING`; date `PENDING`;
authorization evidence `PENDING`. This appendix records a recommendation for
review. It does not approve an operating profile, trust root, resource limit,
production integration, or activation.

### 1. Decision scope and repository evidence

This proposal was prepared at required starting commit
`ff8eea048355535373299d582dd1776e49f63257`, root tree
`5a0fb3e2410c2104272e44ca65ce9ec2e660495d`. The commit and tree objects are
available and the commit is an ancestor of the inspected worktree. This appendix
does not convert any historical test result into evidence for this proposal.
The current integrated assessment is
`docs/devnet/QBIND_PUBLIC_DEVNET_CRITICAL_PATH.md`; the detailed component
evidence and its producing revisions remain in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.

The current public-DevNet posture remains **NO-GO**, activation **DISABLED**,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, C4/C5 and RS1 **OPEN**, candidate
limits **UNAPPROVED**, and §13.6 whole-lifecycle **INCOMPLETE**. The production
binary has no configured Proposal/Vote authority, current-authorization owner,
or signing journal; Required verification fails closed when those prerequisites
are absent. `binary_consensus_loop.rs` contains guarded Proposal/Vote signing
and `signing_reservation_journal.rs` contains `reserve_for_sign`, but their
existence is not production lifecycle wiring. The safety-record store defaults
disabled. No policy conclusion follows from those local components.

Reuse is bounded and intentionally not reopened: the local D10 signing
reservation result is `D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`;
D7D14 remains `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED` and
`D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`; QC/TC verification, retention,
ownership and O1–O5 results retain their producing revisions and accepted
subsets. These do not supply A, B, C, a production caller, or full restart
recovery. In particular, never attach a historical run to this proposal's
starting commit or describe historical evidence as newly executed validation.
Native-program authority, transaction ingress, key-identity admission, M4 and
M6 remain separate obligations.

**Profile A remains the smallest justified *scope*, not a selected trust
model.** Restricting the first release to a pinned founding authority and
founding epoch avoids adding epoch-transition and successor-authority paths.
It does not eliminate the need for authorized first use, present freshness,
per-validator signing-history continuity, lock recovery, or copied-key
exclusivity. A fixed authority can still be rolled back, duplicated, or used
to produce incompatible signatures. Profile A is therefore still the
smallest candidate to evaluate, but no available repository evidence justifies
enabling it.

### 2. Operating and adversary model

**Authorization principal is deliberately unassigned.** The project owner must
name the person, governance body, or documented process authorized to establish
the founding authority and must designate how that decision is authenticated.
No owner infrastructure, staffing, key custody, validator distribution,
hardware, or willingness to trust a third party is inferred here. Owner
approval of this document would be a policy decision only; it would not itself
be a cryptographic activation credential or freshness/durability evidence.

The activation decision and any later evidence must bind, without aliases or
caller-selected substitutions, at least:

* QBIND network/environment and exact runtime chain ID / wire signing domain;
* independently pinned genesis hash and the genesis founding-authority record;
* exact membership/voting-power commitment, validator ID, and validator key
  identity (key material or a canonical digest), key suite and role;
* Profile A identifier and founding epoch; and
* for continuity evidence, this validator's ordered signing-history head and
  the exact safety restriction/history state being advanced.

The authority that authenticates these pins, how operators distribute and
verify them, and how changes are announced remain **deployment facts required
from the owner**. A genesis file, matching epoch, membership copied from that
file, a historical QC, local checksum, source label, or caller Boolean is not
an independent pin or activation authorization.

**Threat boundary.** Consider both an honest validator with fault-prone storage
and an attacker able to copy, restore, replay, corrupt, or suppress the node's
data directory, database, journal, snapshots, VM image, or network messages.
The attacker may restore an older but internally valid copy, erase recent
records, replay old evidence, or make local evidence unavailable. A cloned
host may run concurrently with the original while both have the same key and
database image. An attacker may also compromise an unrestricted signing key.
The chosen trust model must state which authenticated state remains outside
each attacker's rollback domain; state copied or rewound with the node is not
outside it.

| Case | What this proposal assumes or requires; current conclusion |
|---|---|
| Ordinary process crash / interrupted write | Honest storage may preserve acknowledged durable writes only under explicitly validated filesystem/device assumptions. Atomic write, fsync, recovery and local D10 evidence do not imply resistance to a restored older copy. Any ambiguous write blocks dependent signing until reconciled. |
| Disk loss or missing/corrupt history | Treat as lost state, not first use. Fail closed unless an independently authenticated source establishes both authorized activation and the exact current history/safety state. The repository has no such selected source. |
| Old valid database restore | Treat every local marker, checksum, revision and journal head in that restored database as rollbackable. Local consistency cannot establish latestness. |
| Whole-VM restore | Assume database, journal, local counters, clock, and software-visible markers can all revert together. A fresh nonce or local clock is not anti-rollback. Require evidence outside this VM rollback domain or refuse. |
| Cloned host / copied key | A local mutex, file lock or D10 owner coordinates supported local handles; it does not fence another host. Concurrent use is excluded only if the owner approves and an independently justified mechanism enforces exclusive use. No such mechanism is demonstrated. |
| Honest validator storage | The local-journal candidate may assume honest operation honors acknowledged durability barriers, but only after its filesystem/device assumptions and failure model are demonstrated. This is not a claim about all hardware. |
| Compromised unrestricted signing key | No proposed storage or witness arrangement prevents arbitrary signatures from an attacker who already possesses an unrestricted key. A compromise requires refusal, incident handling, and an authorized replacement identity; signatures made during compromise cannot be undone. |
| Partition / cold start / simultaneous restart | No node may infer latestness from peers it can reach, local epoch equality, or absence of records. If current evidence is unavailable, conflicting, stale, or cannot establish a trusted first-use state, refuse. All-validator restart must not bootstrap solely from each other using unauthenticated or stale state. |
| Backup / reset / identity replacement / retirement | Backups are recovery inputs, never freshness authority; restoring one requires external reconciliation. Reset does not erase signing obligations or authorize reuse. Identity replacement requires explicit authenticated retirement/revocation and a distinct key identity; do not silently reuse the old key or reset its history namespace. Retirement must preserve the old history and pending/uncertain reservations. |

### 3. Keep the requirements and their consumers distinct

| Requirement | Evidence a future selected policy must provide | Trust root / consumer | Required failure behavior |
|---|---|---|---|
| **A. Activation authorization** | An authenticated authorization for first use of this exact network, genesis, membership, validator/key, suite, domain and Profile A. It must state whether authority is one-time, revocable and replaceable. | Owner-designated activation authority and its independently pinned verification root; consumed before creating any usable Proposal/Vote authorization. Identity validation alone is not permission. | Missing, invalid, ambiguous, replayed, wrong-identity or wrong-domain authorization keeps the authority unavailable; no signing or bootstrap exception. |
| **B. Current-authority freshness** | Authenticated evidence that the A-authorized authority and its freshness/history head remain applicable now, with replay resistance and a stated rollback domain. A counter must be bound to the exact identity and committed history, not merely an epoch. | An independently justified fresh-state root or witness arrangement, separate from the rollbackable DB; consumed at cold start and before each dependent signing transition as its contract requires. | Stale, conflicting, unavailable or unverifiable evidence blocks activation/signing. No fallback to a local epoch, peer maximum, source label or old QC. |
| **C. Signing-history continuity** | Authenticated, monotonic per-validator history covering every reservation that may have produced a signature, resulting publication/retained result, and safety restriction relevant to future Proposal/Vote actions. It must detect lost/rolled-back state and define exclusive use. | A root outside the specified rollback domain with identity-bound update/compare semantics; consumed before the signer and before result publication. D10 remains the local reservation mechanism, not this independent root. | Keep every uncertain reservation potentially signed; refuse conflicting or new signing until exact state is reconciled. Never erase uncertainty because a commit later occurred. |
| **Lock/safety-record recovery** | The actual durable safety restriction required by the engine (including lock and QC/TC-derived restrictions) must be recovered and bound to the decision before signing. | Independently authenticated durable safety record plus the engine decision consumer; D7 O1–O5/QC/TC work is reusable only in its accepted scope. | Missing, uncertain or stale lock evidence means no Proposal/Vote signing. A logical QC/TC restriction recovered from evidence remains unverified unless independently verified; recovery does not authenticate or make it current. |
| **Copied-key/concurrent host** | Evidence of approved custody and enforced single-use/exclusive writer behavior across all permitted hosts, or an explicit threat-model exclusion. | Owner-approved key-custody boundary and a mechanism that actually fences copies; a local mutex is insufficient. | If concurrency cannot be excluded or safely fenced, no signing. A compromised unrestricted key remains outside prevention capability. |
| **Bootstrap / absent QC** | Explicit authenticated permission for the exact initial proposal fields and a termination/replay rule; evidence must distinguish genuine first use from lost or rolled-back state. | The same independently established A/B root, not an empty DB, genesis label, unsigned QC, or peer assertion. | Absent QC is not a bootstrap credential. Refuse until policy authorizes it; preserve existing present-QC verification unchanged. |

No single row subsumes another. In particular, a valid QC only proves the
verified quorum statement it contains; it is not proof of latestness or of an
individual validator's uncommitted signing history. Identity correspondence,
matching epoch, checksum, source label and caller Boolean establish none of A,
B and C by themselves.

### 4. Candidate comparison (none silently adopted)

| Candidate | What it could cover, if its assumptions were proven | Trust, freshness and retention requirements | Failure, feasibility and trade-offs |
|---|---|---|---|
| **Protected local state outside the rollback domain** | Potentially B and C for one validator; A only if it also verifies a separately authorized activation credential. It does not itself recover the engine lock. | Identify the actual device, API, firmware/update chain, access control, state capacity, identity binding, monotonic/compare-and-advance semantics, authenticated readback, rollback/copy resistance and PQ dependencies. A hardware counter alone is not a history commitment. A counter must commit to the ordered record/history head; attestation is not accepted unless its actual verification roots and cryptography satisfy QBIND's PQ requirements. Per-host copied keys still require an exclusivity story. | Lowest network dependence and potentially low per-operation latency, but hardware availability, quality, firmware, administration, portability, recovery and concurrent-clone behavior are unknown. Device loss/unavailability must refuse. No suitable device or assurance is established in the repository; no external device specification is selected. |
| **Authenticated witness arrangement using the existing validator/quorum trust model** | Could provide a current shared head and possibly per-validator C if witnesses retain and authenticate the full per-validator history, not just chain epoch or QC. It may help B; A still requires an authorized founding decision. It does not automatically recover a validator's lock. | Authenticate membership against independent network/genesis pins; use the approved QBIND quorum rule and domain-bound signatures; retain each validator's ordered commitments, pending reservations, safety restrictions, and update responses across restart. Specify quorum intersection, Byzantine bound, state durability outside each witness rollback domain, freshness challenge/version semantics, replay rejection, exclusive updates, cold-start and simultaneous/all-validator restart behavior. A QC alone is insufficient. | Decentralized in principle and avoids a single operator, but adds network round trips, quorum availability and protocol burden. A partition or no quorum must refuse. If the same consensus validators must first activate/sign to create the witness QC that authorizes their activation/signing, the design is circular. It is not resolved by describing the witness as a quorum; it needs an independently valid bootstrap/current-state rule. No retained-state witness service or demonstrated interface is known here. |
| **Decentralized external anchor** | Could publish an authenticated latest head for B and per-validator history commitments for C; cannot by itself authorize A or reconstruct lock state. | Name the actual protocol, independent genesis/membership pins, finality and reorganization bound, data-availability/retention, query freshness, replay-resistant inclusion/current-head proof, authenticated update rules, write authority, and PQ security assumptions. The anchor must commit to full validator history and exact authority identity, not only an epoch. | May avoid a single QBIND operator and support independent reads, but adds latency, throughput/cost, availability and integration dependencies. No chain, external network, or classical signature is implicitly selected. No technically reviewed anchor with these properties is available in this repository evidence. |
| **Continued refusal** | Prevents authorized production Proposal/Vote effects while A/B/C and lock recovery are unresolved; it does not prove the missing properties or protect an out-of-band use of a compromised key. | Existing fail-closed Required policy and disabled activation are the current boundary; no new trust root or state is asserted. | No signing availability or added signing-path cost; operationally unavailable consensus for this profile, with no added witness service, decentralization trade-off or new state growth. This is the only candidate justified by presently available evidence. |

For a witness-based design, witnesses must each authenticate the exact
membership and keep durable history outside the relevant validator's rollback
domain. A fresh quorum response is useful only if the quorum is itself authorized,
has retained the latest head through cold start/all-restart, and cannot produce
two accepted conflicting advances under the chosen intersection/fault
assumptions. If every witness can restore an old copy, a quorum can sign stale
state. If the validator quorum is the only source of permission to activate the
same validators, the circular dependency remains unresolved. The repository
demonstrates QC verification, not this witness service or any of these
operational properties.

An external anchor or protected device cannot be credited with post-quantum
assurance based on its label. Its actual authentication/signature algorithms,
root distribution, hardware or consensus dependency, update/firmware trust,
rollback boundary and adversarial behavior require primary evidence and owner
approval before it can be reconsidered. No cloud/operator service, external
chain, classical signature, remote signing root or trusted third party is
introduced by this proposal.

### 5. Conditional evidence and effect ordering for future review

This section defines what a later selected mechanism must be able to represent;
it does not define a new wire format, storage schema, interface, or mechanism.
The absence of trustworthy evidence remains a refusal.

A future evidence record must bind a canonical authority identity:
`(network/environment, chain ID, genesis hash, founding-authority commitment,
membership commitment, validator ID, key identity, suite, signing domain,
Profile A, epoch)`. Its ordered history commitment must bind at least:
`(authority identity, prior history commitment, monotonic sequence, canonical
Proposal/Vote position and kind, exact signing-preimage/payload binding,
decision-time safety restriction identity and view, supporting-evidence
identity/status, reservation disposition, and any signed/retained-result
commitment)`. It must distinguish verified from merely logical/recovered
supporting evidence. This list is a logical completeness requirement, not a
claim that the existing D10 `BindingDigest` contains or recovers those fields.

**First use is not inferred from absence.** First use is permitted only when A
authenticates the exact founding authority and an independently trusted B/C
source establishes a never-initialized state for that exact identity, with
freshness and replay protection. An empty, missing, corrupt, reset, replaced or
restored local database is indistinguishable from lost history without that
independent evidence and therefore refuses. A fresh nonce only prevents replay
if its challenge source and current response are independently authenticated;
it does not defeat whole-VM rollback by itself.

**Conditional order and acknowledgements.** A future implementation must compose
the existing mechanisms in this order and satisfy every acknowledgement before
the next external effect:

1. Authenticate A and independently pinned identity; establish B currentness;
   recover the durable safety record and restriction. No `Established`
   authorization or engine effect before all checks pass.
2. Capture and durably publish the exact decision-time safety restriction
   through the selected safety-record owner. Require the durability/publication
   acknowledgement before proceeding; an uncertain publication blocks.
3. Use the existing D10 admission and reserve the exact signing position and
   binding. Require its durable reservation acknowledgement before any
   independent history update or signer invocation. A recovered `Reserved`
   remains **potentially signed**.
4. Advance the independently retained C history head with a compare against
   the exact prior head and the exact reservation/history commitment. Require
   authenticated acknowledgement before calling the signer. A monotonic
   counter that does not retain this commitment is insufficient.
5. Invoke the signer only after those acknowledgements. Persist/publish the
   exact signed result through the existing D10 path and require its
   acknowledgement before network/facade publication. Publication is never
   authorized merely because a signature was produced.

If a C update succeeds but its acknowledgement or local record is lost, the
new C head may already state that the reservation could have produced a
signature. Do not retry with a different position/binding, roll back C, or
assume the update failed. Read and authenticate the exact current head and
reconcile the same operation; if the result cannot be established, retain
uncertainty and refuse. If the local D10 reservation survives but C update is
uncertain, do not sign until C is reconciled. If C advances but the D10 record
is missing, treat the exact reservation as potentially signed and refuse any
conflicting action. If signing completes but result persistence/publication
acknowledgement is lost, reconcile the exact retained result; never sign again
for an uncertain reservation. An authenticated C head alone does not recreate
missing signature bytes.

Exact retained-result reuse is permitted only where existing D10 rules establish
the same canonical signing position and exact binding, the retained bytes are
identical, no new signer invocation occurs, current A/B authorization is still
valid, the latest effective safety restriction allows the exact candidate, and
all local and independent history acknowledgements are reconciled. Reuse is not
a shortcut around currentness or recovery.

Do not prune a pending reservation, recovered `Reserved`, ambiguous result, or
unresolved publication merely because a later block/epoch checkpoint committed.
Any future compaction must prove that a separately authenticated checkpoint
covers the complete ordered reservation/signature history, all pending or
uncertain outcomes, retained-result obligations, and safety restrictions; it
must preserve the ability to refuse conflicting actions. No compaction rule or
history cap is approved here.

QC/TC recovery follows the existing recovery contract: preserve the safety
restriction required by the selected rule, bind it to the actual decision, and
refuse dependent signing until durably recovered. A QC/TC-derived logical
restriction is not silently promoted to an independently authenticated,
latest, or verified record. Verified-QC evidence remains distinct from
recovered logical lock state; do not reverify by pretending retained evidence
survived process death or discard a restriction because its proof is unavailable.

Backup restore must reconcile the full history with the selected independent
source before any signing. Reset cannot clear the external head or pending
reservations. Replacement/retirement must authenticate revocation and preserve
the old identity's history; the successor receives a distinct identity/history
namespace only after owner-authorized lifecycle evidence. No operator procedure
or reset contract is amended by this proposal. Existing operator requirements
remain in `docs/release/public-devnet/ops/RESET_POLICY.md` §§2–8, including
its distinction between a data reset and the offline authority-state-reset
ceremony.

### 6. Performance, resource behavior, and future acceptance

Under the **recommended current refusal**, Proposal/Vote effect paths perform
zero signing-history writes and zero witness/network round trips: they refuse
before a signer or publication effect. This is intentional unavailability, not
a throughput claim.

For a later owner-selected candidate, symbolic work per fresh signing effect is
at least: `W_safety` durable safety-record publications required by the
decision; `W_reserve` acknowledged D10 reservation; `W_history` independent
history-head advance; and `W_result` acknowledged D10 result recording before
publication. Any independent freshness read is `R_current` and any challenge or
readback adds `R_reconcile`; a remote witness necessarily adds the round trips
its selected protocol requires. The ordering is serialized per validator
identity, and a cross-host design additionally needs a real exclusive-update
primitive. No batching, numerical cap, TPS, latency or memory figure is
proposed.

Retained history grows with every reservation and result not safely compacted:
`O(number of retained signing positions and unresolved outcomes)`. Compaction
preconditions are those in §5 and may not discard pending or uncertain entries.
Serialization and ownership boundaries must cover activation, safety decision,
reservation, independent history advance, signing, result recording and
publication across every leader, inbound, re-emission and restart path.
Capacity exhaustion, malformed state, allocation/storage failure, unavailable
witness, partition, stale/conflicting response or lost acknowledgement all
refuse the dependent effect. Exact retry is allowed only after reconciliation
under D10 and the selected history rules.

The following are **required future tests, not executed evidence**:

| Scenario | Required assertion |
|---|---|
| Authorized genuine first use | Exact A, pinned identity and never-initialized B/C evidence permit only the stated founding authority and permitted initial effect. |
| Unauthorized/replayed activation | Missing, invalid, wrong-identity or replayed A refuses without signer or publication effect. |
| Wrong identity/domain | Wrong network, genesis, membership, validator, key, suite, role or signing domain refuses. |
| Restart after reservation | A surviving reservation remains potentially signed; no conflicting retry or signature occurs. |
| Sign then crash before publication | Exact result is recovered/reconciled or the reservation remains uncertain; no second sign. |
| Independent update survives, acknowledgement lost | Reconcile the exact head; do not roll back, substitute an operation, or sign while uncertain. |
| Older valid DB / whole-VM restore | Independent current-history evidence detects the old copy; absent independent evidence, refuse. |
| Conflicting or stale witness evidence | Conflicting heads, replayed response, stale membership or unverifiable proof refuses without selecting a convenient source. |
| Partition, cold start, all-validator restart | No peer-only or stale-QC bootstrap; refuse unless the approved independent evidence establishes current authorized state. |
| Cloned host/concurrent use | Enforce the expressly approved concurrency boundary or demonstrate refusal; local lock alone must not pass. |
| Missing/corrupt local history | Distinguish neither first use nor safe restore by absence; refuse until authenticated recovery completes. |
| QC/TC-derived restrictions | Preserve and bind the restriction; distinguish logical/unverified recovery from independently verified current evidence. |
| Capacity exhaustion / safe retry | Fail before effect; retain uncertain reservations; allow only exact D10-approved result reuse after reconciliation. |
| Backup, reset, retirement and identity replacement | Restoring/resetting cannot erase history; retired identity cannot be accidentally reused or silently reactivate. |

The future gate sequence is separate: **design approval** selects or rejects
assumptions; **implementation acceptance** proves implementation against an
approved contract; **release-binary evidence** proves the deployed path and
build; **public activation** is a further explicit operational decision.
Passing or approving any one does not imply the next passed. This appendix
records no evidence for any of these gates.

### 7. Owner decision summary

**Recommendation:** retain Profile A (founding-authority-only) as the smallest
scope for future evaluation, but choose **continued refusal** now: leave
activation disabled and Proposal/Vote signing unavailable until a concrete,
independently justified activation root, rollback domain, fresh history source,
and lock-recovery path are named and shown to meet A/B/C. This is a
recommendation, not an approved selection.

**New trust assumptions the owner would have to accept to enable any candidate:**
an authenticated principal authorized to establish the exact founding
authority; independently pinned network/genesis/membership/key/domain values;
an identified rollback boundary and state outside it; and a defined durability,
freshness, replay and exclusive-use guarantee for every selected mechanism.
None is supplied by this proposal or inferred from existing QBIND components.

**Operational consequences and principal failure modes:** under the present
recommendation there is no configured Proposal/Vote consensus availability.
A future selected mechanism would add durable serialization and, for witness
options, network availability/latency; unavailable or uncertain state would
stop signing. Old backups, cloned hosts, lost acknowledgements, corrupt history,
compromised keys and all-validator restart can require prolonged refusal and
explicit identity retirement/recovery. Resettable/no-value status does not
reduce these safety requirements.

**Owner decision questions (maximum three):**
1. Who is authorized to authenticate first activation, and how will the exact
   network/genesis/membership/validator/key/domain pins be independently
   distributed and checked?
2. What actual trusted state and operational rollback domain are available for
   current-authority freshness and per-validator history continuity, including
   cloned-host, cold-start, partition and all-validator-restart behavior?
3. Given the evidence and deployment facts, should Profile A remain disabled
   under continued refusal, or should a specific candidate proceed to a
   feasibility review without implying activation?

**Unresolved prerequisite preventing responsible enablement:** the owner has
not identified a concrete A/B/C trust root and state source that survives the
stated rollback domain while preserving per-validator history and safe lock
recovery. The smallest discriminating input is an owner-provided deployment
statement naming the actual available mechanism, its authenticated roots,
what state it retains outside which rollback domain, and whether it fences
copied-key concurrent use; if none exists, continued refusal remains the
justified outcome. A hardware counter, a valid QC or owner approval alone does
not answer this.

**Exactly one bounded next task after the decision — candidate feasibility
characterization:** after the owner records the decision and, only if a
candidate is named, characterize that candidate's trust roots, rollback
boundary, retained history, freshness/update/readback semantics, exclusive
use, lost-ack behavior, cold-start/partition recovery and PQ dependencies
against this appendix. Paths: this lifecycle contract; the continuity and
recovery contracts; `docs/devnet/QBIND_PUBLIC_DEVNET_CRITICAL_PATH.md`; and a
new owner-authorized evidence entry in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.
Prerequisites: written owner decision, exact mechanism/documentation supplied
by the owner, and no implication that a proposed capability exists. Acceptance:
each A/B/C/lock requirement is mapped to authenticated evidence, trust root,
consumer, rollback boundary and fail-closed behavior; all unavailable facts
remain explicit; recommendation is either technically supported or continued
refusal. Exclusions: code, tests/builds, new service or trust root, resource
caps, production wiring, activation, release-binary claims, deployment and
readiness changes.

**Decision remains PENDING.** Approval fields remain PENDING; no approver,
signature, date or authorization token is asserted.

## RUN 422 separately protected consensus signer assessment

`docs/devnet/QBIND_RUN_422_SEPARATE_SIGNER_FEASIBILITY.md` evaluates fixed founding-authority membership and one separately protected, stateful PQ consensus signer per validator. Profile A remains a candidate only: no activation root, currentness source, operator, rollback boundary, signer deployment, or production profile is selected. The assessment finds no live remote consensus signer and leaves activation disabled, public DevNet NO-GO, and whole-lifecycle acceptance INCOMPLETE. This cross-reference does not alter this contract's DRAFT / NOT APPROVED / NOT IMPLEMENTED status or authorize implementation, activation, F1/F2 closure, or release approval.

## RUN 422 — selected initial DevNet authority-role clarification

`docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md` records founder-authorized bootstrap as the selected **design direction** for one exact initial DevNet configuration. This resolves only the prior role-selection question for initial DevNet activation. The lifecycle contract's earlier “owner not selected” and activation-root questions remain accurate as historical statements about the source/revision they describe; the selected role does not supply a credential, independently distributed trust root, approval record, currentness source, continuity, recovery, or activation mechanism.

This clarification does not approve Profile A or change this contract's `DRAFT / NOT APPROVED / NOT IMPLEMENTED` status. Activation remains disabled; §13.6 whole-lifecycle acceptance remains `INCOMPLETE`; durable anti-rollback remains `NOT-ESTABLISHED`; public DevNet remains `NO-GO`; C4/C5 and RS1 remain open. TestNet and MainNet retain separate identities, credentials, and records; joint authority before MainNet is only a planned direction, with participants, threshold, and transition mechanism unselected.