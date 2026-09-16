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
Proposal / Vote signing authority. It separates, and never conflates:
independently pinned genesis identity; standard runtime / wire correspondence;
signature verification; quorum-certificate validation; **current activation
authorization**; in-process freshness; and **persistent anti-rollback**. Success
in one category never establishes another. Proposed conceptual state names below
are documentation only and are **not** instructions to add new code types.

---

## 1. Inspected revision and source limitations

### 1.1 Branch, HEAD, and worktree (recorded, not manufactured)

Inspected against the **actual supplied worktree**, not the SHAs the task recites.

* **Working branch (actual):** `copilot/copilotcopilot-run-422-d7-c3f`
  (`git branch --show-current`). The task's **Reported branch**
  `copilot/copilot-run-422-d7-c3f` differs by the doubled `copilot` path
  segment; the checkout carries the doubled form.
* **Inspected worktree HEAD (actual):**
  `38339d697797aa320ab372fdd5849ab0b45e595b` (`update`). Worktree clean before
  this documentation pass.
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
| S11 | Standard-network alias mapping (C3A) | `genesis_authority_record_correspondence.rs` (`resolve_network_wire_alias`) |
| S12 | Pinned-genesis / network correspondence (C3B) | `genesis_authority_record_correspondence.rs` (`check_network_correspondence`, `GenesisNetworkCorrespondence`) |
| S13 | Domain-bound QC verifier (C3D, dormant) | `crates/qbind-consensus/src/qc_verify_domain.rs` (`verify_quorum_certificate_with_domain`, `VerifiedQuorumCertificate`) |
| S14 | Present-QC admission gate (C3E) | `binary_consensus_loop.rs` (inbound Proposal arm; `inbound_proposal_embedded_qc_verified_total`) |
| S15 | Verified-evidence retention (C3F) | `crates/qbind-consensus/src/basic_hotstuff_engine.rs` (`on_verified_proposal_event`); `crates/qbind-consensus/src/hotstuff_state_engine.rs` (`register_block_with_verified_justification`, `verified_justification`) |
| S16 | Activation refusal (release binary) | `crates/qbind-node/src/main.rs` (`--consensus-authority-from-genesis` refused, `std::process::exit(1)`) |
| S17 | Existing anti-rollback machinery (same-disk) | `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` §8; Run 055 sequence file `pqc_trust_bundle_sequence.json`; `pqc_governance_production_durable_replay_rocksdb.rs` (disabled-by-default) |

---

## 2. Reuse audit

Traced the actual binary path from `main.rs` and classified each mechanism as
**production-reachable**, **dormant** (compiled, no production caller),
**test-only** (`cfg(test)` / disabled default), or **unavailable** (refused at
startup). Older run reports were treated as leads, not proof.

### 2.1 Reuse table

| Requirement | Existing symbol / path | Actual guarantee | Limitation | Verdict |
|---|---|---|---|---|
| Independently pinned genesis identity | S1 `verify_boot_time_genesis(Some(pin))`; S10 `ExpectedGenesisIdentity::load_pinned` | Boot-time single-read verify of external genesis against an independent expected-hash pin; env policy from `map_environment` | Non-MainNet **permits an absent pin** (compare skipped); a supplied `--genesis-path` alone is a file, not a pin | **Reuse** (do not build a new genesis parser) |
| Genesis-derived validator set / keys / suites | S2 `build_genesis_consensus_authority` | Derives consensus validator set + per-validator ML-DSA-44 `(suite,pk)` provider from boot-verified `GenesisConfig.validators[]`, feeding the same `try_build_timeout_verification_context` main uses | **Dormant** — no production caller; release binary refuses the activating flag (S16) | **Reuse** (adapt as the single authority source) |
| Founding-epoch authority lifetime | S3 `authorize_configuration` | Fail-closed: authorizes **only** founding epoch 0 config (chain→genesis→count→commitment→epoch), else `AuthorityLifetimeError` | Founding epoch only; does **not** cover serialized epoch transitions | **Reuse** (adapt for multi-epoch profile) |
| Rollback-resistant *current* authorization | S4 `CurrentAuthorizationOwner` | In-process current-state model: `admit`→`confirm` with issuer binding (`ptr_eq`), monotonic `generation`, terminal `exhausted` latch | **`Established` current state is `cfg(test)` only**; the sole production constructor is `unavailable(...)` → always fail-closed. Generation is **not durable** | **Missing** (production current-authorization source unavailable) |
| Inbound Proposal/Vote admission | S5 Required policy + `unavailable(...)` wiring | Under `Required` (production default), a present authority with `current_auth=None` rejects as current-state-unavailable **before crypto** | Rejects everything in production because current authorization is unavailable | **Reuse** (fail-closed gate is correct; needs a real current source) |
| Immediate outbound forwarding authorization | S6 `forward_actions_to_facade` | `admit`→epoch-check→sign via bound `snapshot.verifier()`→`confirm`→facade for BroadcastProposal/Vote/SendVoteTo; production wires `None` snapshot | Fail-closed only; no production authority to authorize a real send | **Reuse** |
| Cached re-emission authorization | S7 `admit_cached_reemission` | Fresh owner `admit`+`confirm` of an issuer+generation-bound `CachedReemissionProvenance` ticket before re-send | In-process only; no durability across restart | **Reuse** |
| Restore retransmission disposition | S8 restore-catchup deferral | Deferral path **discards** the decoded Proposal/ticket and re-runs admission fresh on re-delivery; Vote has no deferral path | Discards work; no completion of deferred effect | **Reuse** (its discard rule is the lifecycle rule for delayed work) |
| Persisted-epoch observation | S9 `observe_consensus_storage` | Read-only classification: NoStorageHandle / PresentNoCommittedEpoch / CommittedEpoch(u64); reuses schema + incomplete-transition + get_current_epoch | **Never converts to authorization**; persisted epoch is evidence only | **Reuse** (evidence input, not an authority) |
| Genesis ↔ record correspondence | S10 `check_genesis_record_correspondence` | Compares pinned expected identity vs untrusted claimed record vs C1 observation → all of co-origin / activation / current-auth **NOT-established** | Correspondence is **not** activation permission | **Reuse** (evidence input) |
| Runtime / wire-alias correspondence | S11 `resolve_network_wire_alias`; S12 `check_network_correspondence` | Standard-network aliases; retained validation policy vs `map_environment`; typed mismatches | Mapping policy only; not authorization | **Reuse** (do not build another alias registry) |
| Domain-bound QC verification | S13 `verify_quorum_certificate_with_domain` | Pure verifier: each signer via D6 v2 preimage, checked ceil(2W/3) in u128 → `VerifiedQuorumCertificate` | **Dormant** — non-authorizing result; no production caller besides S14/S15 | **Reuse** |
| Present-QC inbound gate | S14 inbound Proposal arm | Verifies a **present** embedded QC through S13 before engine effects; `proposal.qc == None` preserved exactly (neither verified, counted, nor inferred as bootstrap) | Only active when a bound snapshot **and** a present QC exist | **Reuse** |
| Verified-evidence retention | S15 `on_verified_proposal_event` / `register_block_with_verified_justification` | Retains the exact `Arc<VerifiedQuorumCertificate>` at block registration under a byte budget, pre-mutation, with typed errors | **In-process evidence ownership only**; not persistence, not anti-rollback | **Reuse** |
| Durable replay / crash consistency | S17 `pqc_governance_production_durable_replay_rocksdb.rs` | Restart persistence, atomic-write + partial-residue recovery, replay/equivocation rejection | **Test-only / disabled default** (MainNet refused); **no DB-wide monotonic counter / external anchor** → an older-but-valid DB is accepted on open | **Missing for anti-rollback** (do not equate replay prevention with rollback resistance) |
| Persistent anti-rollback anchor | S17 Run 055 sequence file; Trust-Anchor model §8 | Sequence anti-rollback for trust bundles, stored under `<data_dir>` | Stored in the **same rollbackable filesystem**; whole-DB / VM-snapshot restore defeats it | **Missing** (no independent freshness anchor) |

### 2.2 Duplication guardrails (explicit)

Do **not** introduce a duplicate registry, genesis parser, epoch source,
verifier, persistence mechanism, or authority wrapper: S1/S2/S3 supply genesis
and authority derivation; S9 supplies the epoch observation; S11/S12 supply the
alias mapping; S13 supplies QC verification; S15 supplies in-process retention.
Conversely, do **not** equate replay prevention (S17), crash consistency (S17),
or signed metadata with **rollback-resistant current authorization** (the
**Missing** rows: durable current source and independent freshness anchor).

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
  the claimed record (S10/S12) — **plus** a durable, rollback-resistant proof
  that the observed epoch is *current now* (the Missing rows). Correspondence
  alone is explicitly **not** activation.
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
  signing). Exhaustion (`is_exhausted`) is a terminal latch: no admission or
  confirmation ever succeeds again, with no wraparound or reset.

### 3.2 Effect boundaries (must be distinguished; never conflated)

| Boundary | Mechanism | Cancellable after the fact? |
|---|---|---|
| Engine mutation | S15 block registration | No — once state mutates it is not "un-signed" |
| Signing | S4 `confirm` then sign via bound verifier context | Only *before* `confirm` returns |
| Facade handoff | S6 `forward_actions_to_facade` | No after handoff |
| Queued transmission | facade queue | No after enqueue |
| Actual socket delivery | transport | No |
| Remote processing | peer | No |

**No effect that has already occurred is promised cancellation.** For delayed
work the transition rule is explicit: **discard and re-admit fresh** (the S8
disposition), never silently complete under a superseded authority.

### 3.3 Release-profile comparison

| Profile | Reuses | Remaining work |
|---|---|---|
| **A. Founding-authority-only first release** | S1–S3 (validate + founding-epoch guard), S4 fail-closed owner, S13–S15 verification/retention | A durable, rollback-resistant proof that the founding epoch is *current* (Missing rows); release-binary adversarial evidence (S16 refusal today) |
| **B. Serialized epoch transitions** | All of A plus a serialized transition marker + committed-epoch source | Everything in A **plus** durable transition ordering, an epoch source beyond the same-disk DB, and per-transition anti-rollback |

**Recommendation:** pursue **Profile A first**. It has the smallest safety
surface, reuses the founding-epoch guard (S3) unchanged, and does not require
solving serialized multi-epoch durability before a first release. Profile A is
**not** "no restart safety": a fixed founding authority still needs the durable
anti-rollback proof of §5 before it can sign in production. Do **not** silently
broaden the founding-epoch guard to admit later epochs, and do **not** treat a
fixed authority as eliminating restart / rollback safety.

A3 issuer identity / exhaustion (S4) and A4 serialized-handler ordering are
existing **scoped** results; this contract does not reopen them as wholly
unimplemented.

---

## 4. Bootstrap and activation authorization

These five steps are **independent**; each must be satisfied on its own terms:

1. **Validate an independently pinned genesis** — S1 (`verify_boot_time_genesis(Some(pin))`).
2. **Establish network / membership correspondence** — S11/S12.
3. **Authorize activation** — currently **disabled** (S16 refuses the flag).
4. **Establish that an authority is current now** — Missing (needs a real
   current source + durable freshness).
5. **Permit a specific Proposal/Vote effect** — S5/S6 `admit`→`confirm`.

### 4.1 Current absent-QC Proposal path (traced)

In the inbound Proposal arm, the present-QC gate (S14) runs only when
**both** a bound snapshot and `proposal.qc == Some(..)` exist. `proposal.qc == None`
is preserved exactly: it is **neither verified nor counted**, and is **never**
inferred as a validated bootstrap exception. In a production release the arm
never reaches the QC gate at all, because the present authority has an
`unavailable(...)` current state and is rejected as current-state-unavailable
before any crypto. There is therefore no production absent-QC bootstrap
permission today, and none is fabricated here.

### 4.2 Requirements for any future bootstrap exception

If a bounded bootstrap exception is ever proposed, it must record: its **trusted
anchor** (independent of the DB and of peers); the exact **admitted epoch**; the
**permitted proposal fields**; its **replay / restart behavior**; and a
**termination condition** after which the exception can never re-open. Bootstrap
permission must **not** be inferred from an empty database, a missing epoch, an
engine default, an unsigned/empty QC, a genesis label, or a peer assertion. An
empty database may mean either first initialization **or** lost/restored state;
the trust model must distinguish them via an **external** first-boot witness
(the §5 anchor), because the local filesystem alone cannot tell the two apart.
The present-QC path is not weakened and no QC is fabricated to solve bootstrap.

### 4.3 Per-transition record (conceptual; not new code types)

| Transition | Prior state | Trigger | Trusted inputs | Authorization condition | Required durability | Permitted effects | Fail-closed outcome |
|---|---|---|---|---|---|---|---|
| Candidate build | none | boot | pinned genesis (S1) | S3 founding-epoch guard passes | none (in-memory) | build owner `unavailable(...)` | refuse to activate (S16) |
| Activation | candidate + `unavailable` | operator + evidence | S9 epoch + S10/S12 correspondence + **durable freshness anchor** | all correspond **and** anchor proves current | anchor + committed epoch durably ordered | construct `Established` owner | remain `unavailable` (no signing) |
| Sign effect | `Established` owner | inbound/outbound action | admitted ticket (S4) | `confirm` matches generation, not exhausted | none beyond activation | sign + forward (S6) | `Stale`/`Exhausted`/`ForeignIssuer` reject |
| Replacement | `Established` gen N | new epoch | new correspondence + anchor advance | new candidate authorized + anchor strictly newer | durable epoch advance before signing | generation advance | reject; keep gen N |

---

## 5. Durable freshness and rollback threat model

### 5.1 Threat classes (distinguished)

| # | Threat | Handled today | Requires additional trust |
|---|---|---|---|
| T1 | Ordinary restart / interrupted write | S17 atomic-write + partial-residue recovery (disabled default) | — |
| T2 | Incomplete epoch transition / corrupted metadata | S9 detects incomplete transition (read-only) | activation ordering |
| T3 | Restoration of an older **valid** database | **No** | independent freshness anchor |
| T4 | Whole machine / VM snapshot restore (incl. local markers) | **No** | off-box anchor |
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

### 5.3 Unresolved decision (recorded, not resolved)

The available evidence does **not** yet justify selecting a specific anchor.
Consequence, stated exactly: **production current authorization remains
unavailable** (`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`). This contract does
**not** claim durable anti-rollback has been established.

### 5.4 Required ordering

Durable state MUST be committed **before** authority activation, and activation
MUST precede any signing / external effect: `commit(epoch+anchor)` →
`activate(Established owner)` → `admit`/`confirm` → sign → forward. **Crash
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
  `try_build_timeout_verification_context` main uses.
* **Authorized epoch and activation provenance** — S3 founding-epoch guard + S9
  observed epoch + §5 durable anchor.
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
  1. Independent freshness anchor selection (§5.2) — unblocks activation.
  2. Durable ordering commit-before-activate-before-sign (§5.4).
  3. Founding-epoch activation wiring replacing the S16 refusal (behind evidence).
  4. Release-binary adversarial evidence capture.
  5. (Profile B only) serialized epoch-transition marker + committed-epoch source.

---

## 8. Acceptance scenarios (for later implementation)

1. **Fail-closed default preserved.** With no anchor configured, a release binary
   still constructs only `unavailable(...)` and refuses to sign; S16 refusal holds.
2. **Older-DB restore rejected.** After restoring an older valid DB (T3), a node
   with the anchor refuses to activate an epoch older than the anchor's current
   value (typed rollback refusal); without the anchor it stays `unavailable`.
3. **VM-snapshot restore rejected.** A whole-VM snapshot including local markers
   (T4) does not activate; the off-box anchor detects staleness.
4. **Empty-DB ambiguity.** First-init vs lost-state is resolved only by the
   external witness; an empty DB alone never grants bootstrap.
5. **Stale mid-handler replacement.** A ticket admitted under generation N fails
   `confirm` after a generation advance; the pending effect is discarded, not
   completed.
6. **Present-QC unchanged / absent-QC unchanged.** A present embedded QC is still
   verified through S13/S14; `proposal.qc == None` remains neither verified,
   counted, nor treated as bootstrap.

---

## 9. Single bounded next implementation task

**Objective.** Introduce a **read-only durable freshness-anchor observation**
(non-authorizing) that records an externally sourced current-epoch witness and
compares it to the S9 observed persisted epoch, emitting a typed
`FreshnessAnchorObservation` (e.g. `AnchorAhead` / `AnchorEqual` /
`AnchorBehind(persisted)` / `AnchorUnavailable`). It must **never** activate an
authority and must **never** be derived from peers or from the same rollbackable
DB. This is the smallest step that turns §5's unresolved anchor decision into an
inspectable, testable evidence surface without enabling activation.

* **Existing mechanisms to reuse:** S9 `observe_consensus_storage` (persisted
  epoch, read-only); S10/S12 correspondence pattern (untrusted-input vs pinned
  evidence, non-authorizing result types); the D7-C module conventions
  (`cfg(test)` fixtures, typed errors, no production wiring).
* **Prerequisites:** none beyond the worktree; documentation-defined anchor
  interface only. Do **not** select the concrete anchor transport yet (that is
  the §5 decision) — the module consumes an abstract, caller-supplied witness.
* **Files likely affected:** a new
  `crates/qbind-node/src/freshness_anchor_observation.rs` module + `pub mod` in
  `crates/qbind-node/src/lib.rs`; a new
  `crates/qbind-node/tests/run_422_d7d2_freshness_anchor_observation_tests.rs`;
  an evidence subsection in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.
* **Tests:** anchor-ahead / equal / behind / unavailable classification; that the
  result never converts to authorization; that a peer-sourced or same-DB value is
  rejected as an anchor input; parity with S9 observation states.
* **Exclusions:** no activation, no signing, no storage-schema or wire change, no
  concrete anchor transport, no Run 423 work, no readiness promotion. Do not
  generate a speculative sequence of many new modules or promise a run count.
