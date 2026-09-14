# QBIND DevNet Evidence — Run 422 D7

Genesis-static consensus-authority freshness / lifetime (code + test).

```
RESULT=PARTIAL-GENESIS-STATIC-AUTHORITY-LIFETIME-CODE-TEST
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
D6_STATUS=VERSIONED-PROPOSAL-VOTE-BOUNDARY-CODE-TEST-POSITIVE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PROPOSAL_VOTE_AUTHORITY_FROM_LEGACY_CLI=DISALLOWED
LEGACY_TIMEOUT_CONTEXT=EXISTING-POLICY-PRESERVED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

This is a **CODE + TEST** evidence record. It contains no public deployment,
external-network, or standalone release-binary adversarial evidence. Security
(CodeQL) analysis status is reported separately and is not converted into a
zero-alert conclusion.

## Run 422 D7 corrective (this pass) — scope and withdrawn claims

An earlier revision of this record labelled D7 as a POSITIVE genesis-static
lifetime closure. That claim is **withdrawn**. The originally committed tests
are limited **configuration / snapshot** tests: they exercise identity
equality of an immutable authority snapshot against a caller-supplied
`ObservedConsensusConfiguration`, plus non-mixing of two unchanged snapshots.
They do **not** demonstrate a production lifecycle, live Proposal/Vote
freshness enforcement, deterministic concurrent invalidation reaching an
external effect, or durable anti-rollback. D7 therefore remains **PARTIAL**.

This pass tightens the trust boundary (task section 2) only:

* `GenesisConsensusAuthority.authorized_epoch` is now a **private**,
  construction-enforced field (no public field / setter), so the "always
  founding epoch 0" invariant is enforced by encapsulation rather than a
  comment or source-string test.
* A new `LocalAuthorizationState` (`MissingStorage` /
  `StorageWithoutCommittedEpoch` / `Established`) makes the node's
  **independently held** current state explicit, and
  `authorize_current_state` rejects the two unavailable cases fail-closed —
  the founding epoch 0 is **never** inferred from missing storage, an
  uncommitted epoch, or an engine default.
* `config_identity()` is documented as a self-description that is **not**
  independent freshness evidence: an authority comparing itself to its own
  `config_identity()` proves nothing.

Still **NOT** delivered in this pass (explicit gaps, tracked as remaining D7
work): live inbound/outbound Proposal & Vote / BroadcastVote / SendVoteTo /
cached re-emission / deferred-work freshness enforcement in
`binary_consensus_loop.rs`; deterministic concurrent-invalidation tests that
prevent a stale authorization from reaching an external effect; storage /
recovery readers over temporary databases with matching/missing/corrupt/
stale/future/inconsistent state; real-PQC behavioral proofs for both message
families; and full anchor-document reconciliation. Production
`proposal_vote_authority` stays `None` and genesis activation stays DISABLED.
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED` is retained: no durable independent
trust anchor is introduced, so whole-database rollback remains undetectable.

## Run 422 D7-A — Independent current authorization + inbound enforcement (this phase)

This phase (branch
`copilot/copilotcopilotrun-422-proposal-vote-authority-fres`, tested at
`90af004cee80e39833b8592a8b384c8227e22c16`, on a fresh shallow clone whose
shallow boundary is `819ef7b`; the continuation SHA
`fd3aec143343189b778eb69c49b0c2ab04bbadd7` is not materialized in the shallow
clone) implements the section-2/3/4/5 boundary the previous corrective pass
left open. It does **not** close D7. Production activation stays DISABLED.

### Authority-model correction (section 3)

The prior public path `LocalAuthorizationState::Established(auth.config_identity())`
let an authority present its **own** stale self-description as "current state",
which `authorize_current_state` then compared for equality — a self-proof. This
phase separates the candidate snapshot from the **owner** of current
authorization:

* New `CurrentAuthorizationOwner` privately holds the current
  `LocalAuthorizationState` and a monotonic in-process `generation: u64`
  alongside the candidate `Arc<GenesisConsensusAuthority>`. The current state
  is **not** a public field and cannot be replaced by a caller after
  validation. The only production-reachable constructor is
  `CurrentAuthorizationOwner::unavailable(candidate, reason)` — production can
  therefore never present an `Established` current authorization.
* `admit()` obtains authorization by calling
  `candidate.authorize_current_state(&self.current)` on the **independently
  held** state and returns a generation-bound `AuthorizationTicket`; it is not
  a caller-declared `Established` wrapper.
* `confirm(&ticket)` re-checks the ticket generation against the owner's
  current generation and returns `StaleAuthorizationError` if the owner was
  replaced between admit and the effect.
* Establishing a concrete current state is `#[cfg(test)]`-only
  (`establish_for_fixture` / `replace_for_fixture` /
  `GenesisConsensusAuthority::for_current_authorization_fixture`). No public
  production constructor treats caller-supplied fields as validated current
  authority.
* `GenesisConsensusAuthority.authorized_epoch` remains a **private**
  construction-enforced field with an `authorized_epoch()` accessor (the
  section-7 "private authorized_epoch" discrepancy is correct as stated).

### Inbound enforcement (section 4)

`handle_inbound_consensus_msg` takes a new
`current_auth: Option<&CurrentAuthorizationOwner>`. In the real Proposal and
Vote handler arms, when both `pv_authority` and `current_auth` are present:

1. Existing **F6 sender-binding** runs first (unchanged).
2. **Freshness admit** (`owner.admit()`) runs inside the verification arm
   **before** domain/crypto admission; an unavailable/superseded current state
   rejects fail-closed and increments the family's
   `*_current_state_unavailable_total` / `*_authority_superseded_total`
   counter, before any signature work.
3. Existing D6 domain + wire-chain + crypto verification runs (unchanged).
4. **Ticket confirm** runs after verification and **before** restore deferral,
   reconfiguration observation, engine/aggregation/QC mutation, or any
   resulting outbound action; a generation mismatch increments
   `*_authority_stale_before_effect_total` and drops the operation.

Ordering guarantee: a replacement that occurs after admit but before the
effect is caught by `confirm()`; the check is not reused across invalidation.
This is an **in-process** generation guard only — it is **not** durable
anti-rollback and **not** A→B→A signature-replay prevention across restarts
(`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED` retained). When `current_auth` is
`None` (production and all pre-existing tests) behavior is byte-for-byte
unchanged, so the Required default, D6 wire/preimage bytes, genesis refusal,
and legacy Timeout/NewView policy are all preserved. Timeout/NewView authority
remains separate: a valid Timeout context cannot supply Proposal/Vote
authorization (proven below).

### Behavioral tests (section 5) — 13 in-crate tests, all passing

In `binary_consensus_loop.rs` module `tests::run420::run422_d7a`, using the
real F6 gate, matching authenticated origin, real ML-DSA PQC signatures, and
recording facades. For **both** Proposal and Vote:

* `d7a_{proposal,vote}_matching_current_state_verify_accepted` — verification
  succeeds; verification acceptance is distinguished from downstream engine
  acceptance.
* `d7a_{proposal,vote}_unavailable_current_state_rejects_before_crypto` —
  fail-closed despite a present authority; rejection precedes crypto.
* `d7a_proposal_superseded_by_b_rejects_including_cloned_handle` /
  `d7a_vote_superseded_by_b_rejects` — authority A superseded by state B;
  A rejects, including a retained/cloned candidate handle (`Arc::ptr_eq`).
* `d7a_{proposal,vote}_same_epoch_replacement_rejects` — stale A rejects after
  same-epoch replacement.
* `d7a_{proposal,vote}_f6_mismatch_precedes_freshness` — F6 mismatch rejects
  before freshness lookup and crypto.
* `d7a_timeout_context_cannot_supply_pv_authorization` — a valid Timeout
  context cannot authorize Proposal/Vote.
* `d7a_ticket_confirm_fails_after_replacement` — deterministic admit→replace→
  confirm interleaving (explicit state ordering, no sleeps) demonstrates the
  stale-before-effect guard.
* `d7a_active_restore_mode_negative_and_positive_control` — ACTIVE restore-mode
  Proposal negative plus an admitted positive control.

### This-phase validation (correcting section-7 discrepancies)

Executed in this environment at the tested SHA (not historical):

* New behavioral tests: `cargo test -p qbind-node --lib run422_d7a` ⇒ **13
  passed**.
* `binary_consensus_loop::tests::run420` (D5/D6 + D7-A) ⇒ **66 passed**;
  `genesis_consensus_authority::tests` ⇒ **14 passed**.
* Integration: `run_422_d7_authority_lifetime_tests` ⇒ **14 passed** (the
  corrective count is 14, superseding the original 12);
  `run_422_genesis_consensus_authority_tests` ⇒ **15**;
  `run_418_authenticated_peer_consensus_sender_binding_tests` ⇒ **18**;
  `run_418_newview_demux_chain_integration_tests` ⇒ **3**;
  `run_420_production_policy_reachability_tests` ⇒ **3**;
  `run_422_d4_startup_ordering_tests` ⇒ **5**;
  `run_422_startup_refusal_tests` ⇒ **4**.
* Production `cargo check -p qbind-node` ⇒ clean; release
  `cargo build -p qbind-node --release --bin qbind-node` ⇒ built.
* Focused `cargo clippy -p qbind-node --lib` ⇒ no new lints attributable to the
  D7-A additions (pre-existing crate-wide warnings only).
* Security review-tool / CodeQL: **not run in this environment for this phase**
  (no CodeQL runner invoked here); this is recorded as skipped/incomplete
  rather than converted into a zero-alert conclusion.
* The known unrelated broad-test compilation failure is **not** treated as a
  successful check.

### Remaining D7 obligations after this phase (still open)

Independent outbound Proposal/Vote signing, directed-Vote (`SendVoteTo`),
cached re-emission, deferred-work re-admission, storage/recovery matrices,
durable anti-rollback / persistent authority checkpoints, production
chain-ID mapping, downstream QC migration, governance transitions, genesis
activation, and any Run 423 work. Inbound enforcement does **not** close these.

## Continuation context (recorded honestly)

The original Run 422 D7 pass stopped because the previous Copilot runner ran
out of disk space. This pass resumed on a fresh clone of the task branch
`copilot/run-422-proposal-vote-authority-freshness-lifetime` at the accepted
baseline `b94dcf8102961802c55f25e33b4b515d03e8a091`.

* Environment inspection at start: branch as above; `HEAD` = the baseline;
  `git status` clean; `df -h .` ~85 GiB free on a 145 GiB volume; inode use
  ~6%. **No uncommitted prior work survived** to preserve (clean tree at the
  baseline) — the interrupted pass had committed nothing beyond the baseline.
* No blanket `git clean` was used. No source, evidence, task instructions,
  or `.git` data was deleted. Only Cargo build output under `target/`
  (regenerable) accumulated during validation; disk was re-measured between
  stages and never dropped below ~75 GiB free, so no reclamation was needed.
* Implementation checkpoints were committed and pushed **before** the
  expensive release build and security analysis, so another runner failure
  cannot lose completed work.
* Tested implementation commits: `0edf7ed` (guard + tests) and `d4ec8f2`
  (rustfmt of the new LF test file). This documentation lands in a later
  commit; the final documentation SHA is recorded in the final report rather
  than self-referentially inside this file.

## What D7 resolves

The Run 422 containment review left four genesis-authority defects (D4–D7).
D4/D5 (startup ordering + context separation) and D6 (versioned
Proposal/Vote signing-domain isolation) are complete. D7 is the last:

> **D7 — Genesis-static lifetime.** An immutable authority *provider* does
> not, by itself, prove continued authorization across epoch / membership /
> restore transitions.

D7 adds an additive, fail-closed **genesis-static authority lifetime /
freshness guard**. The genesis validator set is the founding epoch-0
membership (`qbind_consensus::validator_set` documents "the genesis epoch
(epoch 0)"; the HotStuff engine and the binary path start at
`current_epoch = 0`; an absent persisted epoch key is treated as epoch 0). A
genesis-static authority is therefore valid for **exactly** epoch 0 with the
committed membership and keys. Because this run implements **no** key
rotation, revocation, or membership transition (task section 10), any
observed epoch other than the founding epoch — or any changed chain /
genesis / commitment / membership — has **no authorized transition** and is
rejected fail-closed. This is a real stale-key guard, not an operational
note.

## What changed

All changes are inside one existing module plus one new test file. No
production wiring, CLI surface, or runtime behavior changed.

| File | Change |
| --- | --- |
| `crates/qbind-node/src/genesis_consensus_authority.rs` | **additive** (CRLF line endings preserved): `const GENESIS_STATIC_AUTHORITY_EPOCH = 0`; **private** construction-enforced field `GenesisConsensusAuthority.authorized_epoch`; `ObservedConsensusConfiguration` (+`::new`); `AuthorityLifetimeError` (+`Display`/`Error`); section-2 corrective `LocalAuthorizationState` / `CurrentStateUnavailableReason` / `FreshnessError` (+`Display`/`Error`); methods `authorized_epoch()`, `config_identity()` (documented as self-description, not freshness), the fail-closed `authorize_configuration(&observed)`, and the independent-current-state `authorize_current_state(&current)`. |
| `crates/qbind-node/tests/run_422_d7_authority_lifetime_tests.rs` | **additive** (CRLF preserved): now **14** tests — the original 12 limited configuration/snapshot tests (task section 12.E) plus 2 section-2 corrective tests (`unavailable_current_state_is_rejected_and_epoch_zero_never_inferred`, `established_current_state_fresh_authorizes_superseded_rejected`), using the real ML-DSA-44 backend and real genesis parsing through the shared production activation boundary. |

### The guard

`GenesisConsensusAuthority::authorize_configuration(&observed)` returns
`Ok(())` **only** when `observed` is the exact founding configuration at the
founding epoch. Otherwise it returns a bounded `AuthorityLifetimeError`,
ordered coarse-to-fine so the first, most fundamental divergence is named:

1. `ChainIdChanged` — a different chain id.
2. `GenesisHashChanged` — a restart / restore / replay onto a different
   canonical genesis identity.
3. `MembershipCountChanged` — a resized validator set.
4. `AuthorityCommitmentChanged` — a changed validator set / suite / key
   (same count, different commitment), or a tampered membership commitment.
5. `EpochTransitionUnauthorized` — any epoch other than the founding epoch;
   no authorized transition exists, so the stale genesis keys must not sign.

Every path is total and non-panicking; diagnostics carry only fingerprints,
counts, and epochs — never key bytes.

The observed epoch is caller-supplied from a **validated** source. D7
introduces **no** synthetic epoch and does **not** consume `current_epoch`
for trust-bundle activation: the fail-closed `CurrentEpochUnavailable`
boundary is untouched (task section 10). C4/C5 remain OPEN; no peer-driven
trust apply/propagation, session eviction, or governance mutation is enabled.

## Test evidence (section 12.E)

`run_422_d7_authority_lifetime_tests.rs` — **12** tests, all passing:

* **Snapshot immutability vs source-file change** — activate from a temp
  genesis file, overwrite the file with a different genesis; the in-memory
  hash / commitment / keys are unchanged and the guard still authorizes only
  the original founding identity; a freshly reloaded authority differs and
  is refused.
* **Parallel non-mixing** — 8 threads × 500 iterations over two distinct
  authorities; each authorizes only its own identity, never the other's, and
  no provider serves the other authority's keys/suites.
* **Restart/restore identity mismatch fails closed** — different canonical
  genesis hash and same-network tampered commitment both reject.
* **Changed configuration/epoch fails closed** — changed validator-set
  commitment, changed membership count, and epoch advance (1, 2, 7,
  `u64::MAX`) all reject with no fallback.
* **Malformed/extreme input cannot panic** — empty chain id, all-`0x00` /
  all-`0xFF` hashes, `usize::MAX` count, `u64::MAX` epoch, control chars ⇒
  `Err`, never a panic.
* **Fixture bypass unreachable** — exactly one struct-literal builder, no
  bypass constructor, and `main.rs` refuses the activation route.

Regressions green in this environment: qbind-node module unit (14), run_422
genesis/startup-refusal/D4 (15 + 4 + 5), D6 in-module (10), full
`qbind-node --lib` (**1478**). The affected release build compiled; the
release binary still refuses `--consensus-authority-from-genesis` with exit
code **1** before any P2P/consensus service. Exact commands, counts, and
exit codes are in
`docs/devnet/run_422_d7_authority_lifetime/commands.txt` and
`.../test_results.txt`.

Two initial D7-test assertions were over-strict and were corrected in the
**test only**; no production logic was changed to make a test pass, and no
existing harness expectation was edited to hide a regression.

## Boundaries and blockers preserved (unchanged by D7)

* Production `proposal_vote_authority` stays `None`; the genesis-authority
  startup refusal is preserved **verbatim** (message wording unchanged; the
  release binary exits 1). No CLI flag / env switch / fallback enables a
  genesis-static authority in a release binary.
* The legacy `--validator-consensus-key` CLI route is unchanged.
* `LocalFixtureUnsigned` stays test-only and is not referenced by the
  genesis-authority module.
* The runtime `ChainId` (u64) ↔ wire `chain_id` (u32) mapping and the D6
  downstream engine/QC reconstruction limitations are unchanged; D7 makes no
  QC/engine/consensus-safety claim.

## Preserved posture

F3/F4/F8 not fully activated in production; F1/F2/F5/F7 unresolved; F6
partial; RS1 and C4/C5 **OPEN**; M4/M6/S5/S7 Yellow; Public DevNet
**NO-GO**. No live seed file; no TestNet/MainNet readiness claim; no
readiness item moved Green. Configured-authority standalone release-binary
adversarial evidence remains **NOT-YET-CAPTURED** and is deferred to Run 423.