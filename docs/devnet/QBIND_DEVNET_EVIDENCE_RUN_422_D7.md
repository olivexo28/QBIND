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

## Run 422 D7-A — RUN 422 review correction: scoped-positive inbound verdict WITHDRAWN (current status)

The D7-A subsections above and below ("… this phase", authority-model /
inbound-enforcement / behavioral-tests / this-phase-validation) are the
**historical** record of the reviewed implementation at `90af004…` and are
retained unchanged for provenance. This section records the **current** status
after the RUN 422 D7-A review and supersedes the earlier "scoped-positive
inbound" framing. It appends no contradictory claim to the historical
sections; it states the corrected verdict separately.

### Provenance / deviations (this pass, no invented ancestry)

* Actual working branch: `copilot/copilotcopilotcopilotrun-422-proposal-vote-authori`
  — **not** the expected `copilot/copilotcopilotrun-422-proposal-vote-authority-fres`.
* Actual `HEAD`: `92cbbe89cd1c3c9511dd1b8e03f95957710b1568` (`92cbbe8`); its
  parent `bb28b3c` is the shallow graft boundary, so no deeper local ancestry
  exists.
* The reviewed implementation SHA `90af004…` and documentation SHA `158d8f…`
  are **not** ancestors of `HEAD`. They were fetched only for comparison and
  differ from the worktree solely by line endings (the worktree carries CRLF;
  `90af004`'s `binary_consensus_loop.rs` is LF). After CR normalization the
  worktree source is byte-identical to the reviewed revision. No ancestry
  between the reviewed SHAs and `HEAD` is asserted.

### Verdict: PARTIAL — scoped-positive inbound claim withdrawn, not re-granted

The reviewed findings are confirmed against the actual code and remain **OPEN**;
`D7A_INBOUND_VERDICT=PARTIAL`. Specific failing requirements:

1. **Missing-current-owner bypass (task §1) — OPEN.** In
   `handle_inbound_consensus_msg` the Proposal arm
   (`crates/qbind-node/src/binary_consensus_loop.rs` ~L3419) and Vote arm
   (~L3659) gate the freshness admit behind `if let Some(owner) = current_auth`.
   When a `ProposalVoteAuthority` is present but `current_auth` is `None`, the
   admit is skipped and the message proceeds to crypto/delivery. There is no
   `Required + present authority + current_auth=None` fail-closed rejection and
   no missing-owner test distinct from `unavailable`. (Production is unaffected
   because it passes both `pv_authority=None` and `current_auth=None`, so the
   `None` arm still applies the `Required` fail-closed default; the fail-open is
   in the intended D7-A inbound contract at the test boundary.)
2. **Admission not bound to the authority actually used (task §2) — OPEN.**
   `CurrentAuthorizationOwner::admit()` calls `authorize_current_state()` on its
   stored `GenesisConsensusAuthority`, while the handler verifies signatures
   with an independently supplied `ProposalVoteAuthority`; nothing binds the
   admitted snapshot to the verification snapshot. The positive fixtures are
   incoherent: `candidate_a()` =
   `for_current_authorization_fixture(chain="qbind-d7a-fixture", genesis=[0x11;32],
   count=4, commitment=[0xAA;32])` with a synthesized **empty** key provider,
   whereas the `ProposalVoteAuthority` under test (`make_ctx`) carries a
   separate real ML-DSA-44 provider/domain — so `admit()` proves only
   self-consistency of an unrelated authority. There are no owner-A/verifier-B
   negatives, no signed-epoch-vs-admitted-epoch check, and the admitted
   identity does not cover signing domain / membership / keys / suite policy.
3. **Ticket identity & handler ordering (task §3) — OPEN.**
   `AuthorizationTicket` carries only `generation: u64`; it is not bound to an
   issuing owner identity or authorized snapshot, so a foreign-owner ticket at
   an equal generation is not rejected, and generation advance uses
   `saturating_add` (saturates rather than failing closed at exhaustion). The
   only ordering evidence is the standalone `admit→replace→confirm` unit test;
   there is no deterministic real-handler/facade ordering proof across
   replacement and no documented synchronization model.
4. **Behavioral acceptance coverage (task §4) — INCOMPLETE.** Missing:
   missing-owner (distinct from unavailable), mismatched owner/verifier,
   wrong-signed-epoch-before-effect, and coherent **bound** positive fixtures.

### Corrections not implemented this pass (existing work preserved)

Sections 1–4 are deeply coupled: a correct §1 fix requires the §2 binding so the
mandatory owner authorizes the exact verification snapshot; both require
replacing the incoherent fixtures and rewiring the handler signature and the
~8 D5/D6 `handle_inbound_consensus_msg` call sites that pass
`pv_authority=Some, current_auth=None`. This is a cross-module redesign that
could not be completed **and** fully validated (release build, integration
matrix, broad regressions) within this session without risk of leaving the
tree in a worse state, so **existing work is preserved unchanged** and no
partial/destabilizing code change was landed. No production activation route,
new flag/env override, QC migration, chain-ID mapping, durable checkpoint, or
Run 423 work was added.

### Validation actually run this pass (no invented results)

* `cargo check -p qbind-node --lib` (dev profile, default features) at `HEAD`
  `92cbbe8` ⇒ **clean, exit 0** (Finished in 5m49s). Confirms the reviewed
  worktree compiles as-is.
* No code changes were made, so no test/build deltas were produced; the
  historical test counts in the sections above are from `90af004` and are
  **not** re-attested here.
* Release build, focused Clippy, D6 crypto/handler, Run 418/420, Run 422
  startup/refusal/D4, and the integration D7-A tests were **not re-run** this
  pass (no code change to validate; deferred).
* **CodeQL / security review-tool: not run in this session.** The historical
  D7-A record states "not run for this phase"; any separate final-message claim
  of a database-size skip plus review completion is not corroborated here. With
  no code change in this pass there is nothing new to scan; the discrepancy is
  left to be resolved by running the actual tool against the actual revision
  rather than asserting either outcome.

### Preserved boundaries (task §6, unchanged) and retained D7 status

Required default; production `proposal_vote_authority=None`; production current
authorization available only through the unavailable-only constructor;
mandatory D6 domain/bytes; genesis-authority startup refusal (release binary
exits 1 on `--consensus-authority-from-genesis`); legacy Timeout/NewView
policy — all preserved.

```
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
D7A_INBOUND_VERDICT=PARTIAL (scoped-positive WITHDRAWN; §1–§4 OPEN)
```

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

## Run 422 D7-A1 — Required-policy MISSING-OWNER rejection implemented (code + test)

This sub-phase closes review finding **#1** (missing-current-owner bypass)
only. It does **not** close D7, D7-A, or findings #2–#4, which remain
**OPEN** (see the sections above). Tested at branch
`copilot/run-422-d7-a1-implement-required-policy-missing-ow`.

### Exact missing-owner behavior implemented

In `handle_inbound_consensus_msg` (`crates/qbind-node/src/binary_consensus_loop.rs`),
both the inbound Proposal and Vote arms previously gated the current-
authorization admission behind `if let Some(owner) = current_auth`, so a
present `ProposalVoteAuthority` with `current_auth == None` silently skipped
the freshness admission and proceeded to crypto. That `if let` is now a full
`match current_auth { Some(owner) => admit…, None => … }`: under a policy that
`requires_context()` (i.e. `Required`) the `None` arm records the family's
current-state-unavailable counter
(`inbound_proposal_current_state_unavailable_total` /
`inbound_vote_current_state_unavailable_total`) exactly once and returns
fail-closed — **before** the D6 domain/crypto verification, delivery, restore
deferral, reconfig observation, engine/aggregation/QC mutation, and any
outbound action. F6 sender-binding still runs first; the pre-existing
missing-PV-authority rejection (the `pv_authority == None` arm) and the
`Some(owner)` unavailable/superseded handling are unchanged. No owner is
synthesized from the candidate authority; no flag, env switch, default owner,
or fallback was introduced. The test-only `LocalFixtureUnsigned` passthrough
is preserved (its `requires_context()` is `false`, so the `None` arm does not
reject). Production is unaffected: `main` wires both `proposal_vote_authority`
and the current-authorization owner as `None`, so the pre-existing
`pv_authority == None` fail-closed default still applies.

### Both-family tests (through the real handler)

Added to `mod run422_d7a`, driving the real `handle_inbound_consensus_msg`
with a real F6 binding gate, matching authenticated origin, real ML-DSA-44
signatures, and `Required` policy:

* `d7a1_proposal_missing_owner_rejects_before_crypto` and
  `d7a1_vote_missing_owner_rejects_before_crypto`: present PV authority +
  `current_auth == None`. Observations: F6 admitted once
  (`gate.metrics().accepted() == 1`); the family current-state-unavailable
  counter increments exactly once; superseded and stale-before-effect stay 0;
  signature verification is not invoked — asserted by a **direct backend-call
  counter** (`CountingSigVerifier` wrapping the real ML-DSA-44 backend,
  incremented inside `verify_vote`/`verify_proposal`), reset before the handler
  call and asserted to be **zero**; the latency-observation counter
  (`proposal_vote_crypto_verify_latency_observations_total == 0`) is retained
  only as supplementary evidence — with no verify acceptance/rejection; a
  recording outbound facade asserts **zero** outbound actions; no delivery,
  engine acceptance, restore deferral, reconfig observation (empty detector
  header cache), or view mutation. Each test **separately** verifies the same
  signed message with `verify_{proposal,vote}_msg_with_domain` under the exact
  D6 domain and asserts it is `Ok`, so the handler rejection is attributable
  solely to the missing current authorization. Paired positive controls
  (`d7a1_{proposal,vote}_backend_call_counter_positive_control`) drive a
  coherently bound snapshot and assert the same backend-call counter is `>= 1`,
  proving the counter is wired to the real verify path (this corrects the
  earlier D7-A1 claim that the latency observation was "equivalent direct
  instrumentation").
* `d7a1_proposal_f6_mismatch_precedes_missing_owner` and
  `d7a1_vote_f6_mismatch_precedes_missing_owner`: same present-authority /
  `current_auth == None` setup but with a claimed-proposer/voter that
  disagrees with the authenticated origin. Observations: F6 rejects first
  (`inbound_sender_binding_rejected_total == 1`, `accepted() == 0`); the
  missing-owner decision is never reached (current-state-unavailable == 0, no
  crypto observation).

The existing distinctions are retained: missing PV authority
(`d7a_timeout_context_cannot_supply_pv_authorization`), missing owner (the new
`d7a1_*` tests), and present-but-unavailable owner
(`d7a_{proposal,vote}_unavailable_current_state_rejects_before_crypto`).

### Fixture migration (only)

Some Required-positive D5/D6 handler wrappers
(`deliver_proposal_pol`, `deliver_vote_pol`, `deliver_proposal_combined`,
`deliver_vote_combined`, `deliver_proposal_combined_restore`) intentionally
passed `current_auth == None` with a present PV authority; the strengthened
contract now rejects that input. Each wrapper was migrated to provide an
explicit established test owner (`migration_established_current_auth`, built
through the existing `cfg(test)` `for_current_authorization_fixture` +
`establish_for_fixture` interfaces) whenever `pv.is_some() &&
policy.requires_context()`. The owner is behaviorally transparent — `admit()`
returns a ticket and the pre-effect `confirm()` succeeds — so every original
cryptographic and behavioral assertion is preserved unchanged. This is fixture
migration only: no test was switched to `LocalFixtureUnsigned`, no assertion
was weakened, and no production bypass was added. It does **not** prove the
still-open owner/verifier-binding (#2) or ticket-identity (#3) findings.

### Validation results (tested SHA `175839819abc54e5500f31d907ce457cf2827b8a`)

* `cargo test -p qbind-node --lib d7a` ⇒ 17 passed, 0 failed (incl. the 4 new
  `d7a1_*` tests).
* `cargo test -p qbind-node --lib binary_consensus_loop` ⇒ 133 passed, 0 failed.
* `cargo test -p qbind-node --lib` ⇒ 1495 passed, 0 failed.
* `cargo test -p qbind-node --test run_422_d7_authority_lifetime_tests --test
  run_422_genesis_consensus_authority_tests --test run_422_startup_refusal_tests
  --test run_422_d4_startup_ordering_tests --test
  run_420_production_policy_reachability_tests --test
  run_418_authenticated_peer_consensus_sender_binding_tests` ⇒ 18/3/5/14/15/4
  passed, 0 failed.
* `cargo check -p qbind-node` (dev profile, default features) ⇒ clean, exit 0.
* `cargo clippy -p qbind-node --lib` ⇒ exit 0 (87 pre-existing warnings, none
  in the changed lines).
* `cargo build -p qbind-node --release --bin qbind-node` ⇒ Finished, exit 0.
* `cargo clippy -p qbind-node --tests` ⇒ exit 101 due to a **known unrelated**
  pre-existing failure in the `m16_epoch_transition_hardening_tests` binary
  (missing `RocksDbConsensusStorage::set_inject_write_failure` /
  `clear_epoch_transition_marker`); this is not touched by this change and
  compiles/fails identically on the base tree.
* **Security tools (`parallel_validation` at SHA above):** Code Review
  completed, reviewed 2 files, **no review comments**. CodeQL (`rust`)
  reported **0 alerts** but **analysis was skipped because the database size
  is too large** — recorded exactly; this skipped scan is NOT converted into
  a zero-alert / clean conclusion.

### Remaining inbound findings still OPEN

Findings #2 (owner→verifier binding / incoherent positive fixtures), #3
(ticket identity + generation exhaustion via `saturating_add`), and #4
(handler-ordering / bound positive coverage) are **unchanged and OPEN**. This
sub-phase rejects an absent owner; it does not bind the admitted snapshot to
the verification snapshot, does not give the ticket an issuer identity, and
establishes no durable anti-rollback.

```
D7A_INBOUND_VERDICT=PARTIAL (finding #1 missing-owner CLOSED; #2–#4 OPEN)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```
## Run 422 D7-A2 — Current authorization BOUND to the actual verification snapshot (code + test)

This sub-phase resolves review finding **#2** (owner authorizes its own stored
authority while cryptographic verification consumes a separately-supplied
`ProposalVoteAuthority`, so an owner for identity A could admit verification
performed under an unrelated authority B) for the tested **inbound** boundary
only. It preserves the D7-A1 missing-owner rejection and does **not** reopen the
`None` bypass. Findings **#3** (ticket issuer identity / generation exhaustion)
and **#4** (handler-ordering / replacement) remain **OPEN** and are not claimed
closed. Tested at branch
`copilot/copilotrun-422-d7-a2-bind-current-authorization`.

### Provenance / deviations (no invented ancestry)

* The task preamble names an expected branch
  `copilot/run-422-d7-a1-implement-required-policy-missing-ow` and a reviewed
  tip `fd8b349f989ce41d23cf02f06a58ae436a81aef0`. Neither is present in this
  environment: the actual working branch is
  `copilot/copilotrun-422-d7-a2-bind-current-authorization`, and the clone is a
  shallow 2-commit history (`e4cb391` squashed import + `e8bef80` "update",
  which already contains the committed D7-A1 missing-owner work). `fd8b349` is
  not an ancestor of the local HEAD and cannot be inspected here. The existing
  D7-A1 work in the worktree was preserved and extended, not rewritten.

### Binding design (section 2)

A new fail-closed, coherence-validated type
`AuthorizedProposalVoteSnapshot` (`crates/qbind-node/src/binary_consensus_loop.rs`)
bundles the current-authorization owner with the **exact** verifier the handler
consumes (`verifier: Arc<ProposalVoteAuthority>`). Its constructor
`try_bind(owner, verifier)` validates, fail-closed, that the owner's genesis
authority identity actually corresponds to the verifier:

* genesis identity == the verifier's mandatory D6 signing-domain
  `genesis_identity()`;
* authority commitment == the domain's `authority_commitment()`;
* the **actual** validator membership is shared — both `Arc::ptr_eq` on the
  `ConsensusValidatorSet` **and** structural equality of ids + voting weights
  (a shared pointer alone is not accepted as proof — task section 2);
* the **actual** suite-aware key provider is the same shared `Arc` instance
  (matching a count or an independently-asserted label is insufficient);
* the owner's chain-identity label corresponds to the domain's
  `runtime_chain_id()` via a trusted, test-identified fixture label
  (`snapshot_chain_identity_label`; **no** production runtime→wire chain-id
  mapping is introduced).

Coherence is validated at construction. Provenance and local binding stay
separate guarantees: `try_bind` proves the local objects match, while
`CurrentAuthorizationOwner::admit()` independently proves the node's current
authorization state still equals that founding identity — both must pass. The
epoch the snapshot authorizes is the genesis-static founding epoch
(`authorized_epoch()` = `GENESIS_STATIC_AUTHORITY_EPOCH` = 0).

The handler `handle_inbound_consensus_msg` now takes
`current_auth: Option<&AuthorizedProposalVoteSnapshot>`. In both the Proposal
and Vote arms, when a snapshot is present the handler derives
`effective_pv = snapshot.verifier()` and performs D6 crypto through **that**
verifier, **ignoring** any separately-supplied `pv_authority` — a substituted
context can no longer change the verification inputs after admission. When no
snapshot is present it falls back to the supplied `pv_authority` (so the
`Required` + `None` D7-A1 rejection and the test-only `LocalFixtureUnsigned`
passthrough are unchanged). No production route constructs a
`ProposalVoteAuthority` or an `Established` owner, so production current
authorization stays unavailable and no arbitrary-fields production authorization
factory was added (the new snapshot-building constructor
`GenesisConsensusAuthority::for_verification_snapshot_fixture` is `#[cfg(test)]`).

### Epoch / handler behavior (section 3)

For both families the ordering is: F6 sender-binding → present-authority gate →
current-authorization admission (`admit()`) → **signed-epoch check** → D6
wire-chain + signature verification → pre-effect `confirm()` → delivery. The
epoch check compares the message's signed epoch (`BlockHeader.epoch` /
`Vote.epoch`) against `snapshot.authorized_epoch()` **before** any crypto or
downstream effect; a mismatch increments
`inbound_{proposal,vote}_epoch_unauthorized_total` and returns fail-closed. The
missing-authority, missing-owner, and unavailable/superseded rejections are all
preserved and continue to reject before delivery, restore deferral, reconfig
observation, engine/aggregation/QC mutation, and outbound actions. D6 signing
bytes, the domain version, and QC verification are unchanged; no production
chain-ID mapping was added.

### Incoherent positive fixtures replaced (section 4)

The D7-A1 migration owner (`for_current_authorization_fixture` with independent
constants and an empty key provider) was accepted only as a temporary fixture
while finding #2 stayed open. It is replaced by coherent fixtures
(`coherent_authority_for` / `coherent_snapshot_for` / `migration_bound_snapshot`
and the `snapshot_{matching,superseded,unavailable}` helpers) whose owner
authorization, membership, keys, suite and signing domain **describe the actual
verifier**: the owner's candidate authority shares the verifier's real
`ConsensusValidatorSet` and `SuiteAwareValidatorKeyProvider` and re-derives its
genesis / commitment / chain identity from the verifier's D6 domain. Existing
`Required` policies and the original cryptographic assertions are retained; no
test was downgraded to `LocalFixtureUnsigned` and no assertion was weakened.

### Behavioral tests (section 5) — both families, through the real handler

Added to `mod run422_d7a`, all passing:

* Coherently bound current authority ⇒ valid signature verifies:
  `d7a_{proposal,vote}_matching_current_state_verify_accepted` (retained,
  now driven by a coherent snapshot).
* Owner A paired with verifier B ⇒ rejection:
  `d7a2_bind_rejects_owner_a_verifier_b_while_b_is_valid` asserts `try_bind`
  fails closed for the incoherent (A-owner, B-verifier) pair, and
  **independently** shows B is a valid verifier when coherently bound (a
  B-signed proposal verifies through the handler under a B snapshot) — so the
  negative is attributable to binding, not to B being invalid.
* Same validator count but different keys ⇒ rejection:
  `d7a2_bind_rejects_same_count_different_keys` (identical ids/weights but a
  different membership instance ⇒ `MembershipMismatch`; and, isolating the key
  provider by sharing B's exact membership while pairing A's key provider ⇒
  `KeyProviderNotShared`).
* Different genesis / commitment / chain ⇒ rejection:
  `d7a2_bind_rejects_isolated_genesis_commitment_chain` (each field varied
  alone rejects with its specific reason).
* Substitution prevention through the handler:
  `d7a2_{proposal,vote}_admitted_verifier_ignores_supplied_pv` — with the
  admitted snapshot bound to A and a **separately-supplied** `pv_authority` = B,
  an A-signed message is accepted (proving A was used and B ignored; the A-signed
  message is independently shown **invalid under B**), and a B-signed message
  (independently shown **valid under B**) is rejected.
* Correctly re-signed message carrying an unauthorized epoch ⇒ rejection before
  effects: `d7a2_{proposal,vote}_unauthorized_epoch_rejected_before_effects`
  (epoch-1 message, signature independently asserted valid under the D6 domain;
  `inbound_*_epoch_unauthorized_total == 1`; direct backend-call counter `0`;
  zero latency observation, delivery, engine acceptance, outbound action, and
  view mutation).
* Missing owner and explicitly unavailable owner remain rejected: the retained
  `d7a1_*` missing-owner tests and
  `d7a_{proposal,vote}_unavailable_current_state_rejects_before_crypto`.
* F6 mismatch precedes authorization lookup:
  `d7a1_{proposal,vote}_f6_mismatch_precedes_missing_owner` and
  `d7a_{proposal,vote}_f6_mismatch_precedes_freshness`.

For every mismatch case the message's signature validity under B (or under the
D6 domain) is independently established with `verify_{proposal,vote}_msg_with_domain`,
so the negative is attributable to authorization binding. ACTIVE restore-mode
negative + admitted positive controls and the verification-vs-engine/QC
acceptance distinction are retained.

### Direct backend-call instrumentation (section 6)

`CountingSigVerifier` wraps the real ML-DSA-44 backend, increments a shared
`AtomicU64` **inside** `verify_vote` / `verify_proposal`, and delegates to the
real backend (`counting_pv` builds a `ProposalVoteAuthority` using it). The
positive controls
(`d7a1_{proposal,vote}_backend_call_counter_positive_control`) demonstrate the
counter increments on a real verification; the missing-owner and
unauthorized-epoch negatives reset the counter before the handler call and
assert **zero** backend calls, and pass a recording outbound facade
(`D7ActionRecorder`) asserting **zero** outbound actions. The earlier D7-A1
comment/evidence describing the latency counter as "equivalent direct
instrumentation" is corrected (here and in the D7-A1 section above): the latency
observation is supplementary, and a direct backend-call counter is now the
primary evidence.

### Validation results (tested SHA `2aefdee5575677e312abffcad98b9ca536f0664e`)

* `cargo test -p qbind-node --lib run422_d7a` ⇒ 26 passed, 0 failed (19 retained
  + 7 new `d7a2_*` plus the 2 backend-counter positive controls).
* `cargo test -p qbind-node --lib binary_consensus_loop` ⇒ 142 passed, 0 failed.
* `cargo test -p qbind-node --lib genesis_consensus_authority` ⇒ 14 passed, 0 failed.
* `cargo test -p qbind-node --test run_422_genesis_consensus_authority_tests
  --test run_422_d7_authority_lifetime_tests --test run_422_startup_refusal_tests
  --test run_420_production_policy_reachability_tests
  --test run_418_authenticated_peer_consensus_sender_binding_tests
  --test run_418_newview_demux_chain_integration_tests` ⇒ 15/…/4/3/18/3 passed,
  0 failed.
* `cargo test -p qbind-consensus` ⇒ all passed, 0 failed (D6 proposal/vote
  verify matrix included).
* `cargo check -p qbind-node` (dev profile, default features) ⇒ clean, exit 0.
* `cargo clippy -p qbind-node --lib` ⇒ exit 0 (pre-existing warnings only, none
  in the changed lines).
* `cargo build -p qbind-node --release` ⇒ Finished, exit 0 (`release` profile,
  optimized target(s) in 5m 25s).
* **Security tools (`parallel_validation`):** Code Review ⇒ completed, reviewed 3
  files, no review comments (the underlying model-backed reviewer reported an
  environment/model-registry error, so this is not a substitute for manual
  review). CodeQL (`rust`) ⇒ **Analysis SKIPPED because the database size is too
  large** — 0 alerts reported, but this is an INCOMPLETE analysis and is NOT
  converted into a clean/passing conclusion. CodeQL coverage for this change
  remains outstanding.
* Known unrelated broad-Clippy/`--tests` failures (e.g.
  `m16_epoch_transition_hardening_tests` missing storage helpers) are kept
  separate and are not touched by this change.

### Finding dispositions and remaining obligations

Finding **#2** may be marked **closed for the tested inbound boundary only**:
admission now authorizes the exact snapshot the handler cryptographically
consumes, and a separately-supplied context cannot substitute different inputs.
Findings **#3** (ticket issuer identity + generation exhaustion via
`saturating_add`) and **#4** (handler-ordering / replacement) remain
**OPEN**. This phase establishes no durable anti-rollback and no production
lifecycle.

```
D7A_INBOUND_VERDICT=PARTIAL (findings #1 missing-owner + #2 snapshot-binding CLOSED for tested inbound boundary; #3–#4 OPEN)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

## Run 422 D7-A2 (continued) — complete domain binding (wire-chain-id) + immediate-handoff authority

This continuation of D7-A2 closes the remaining half of finding **#2** and
corrects the immediate inbound action handoff. It is code + test only, stays
fixture-only for established authorization, and does **not** add production
chain-ID mapping, new activation routes, or any change to D6 signing bytes.
Implemented at branch `copilot/copilotcopilotrun-422-d7-a2-bind-current-authoriza`,
**implementation SHA** `d7387dcecb55ba6d7050158c5d70492301f6334e`; the **final
documentation SHA** for that pass was `a7af8db` (the later evidence commit — the
release build recorded there does not attest this changed A3 production source).

### Gap identified (section 2)

The prior D7-A2 `try_bind` bound genesis identity, authority commitment,
membership (ptr + structural), key provider (shared `Arc`) and the runtime-chain
label, but it did **not** bind the D6 v2 domain's `expected_wire_chain_id`. An
owner authorized for domain A could therefore authorize a verifier B that shares
the same membership, key provider, runtime chain, genesis and commitment and
differs **only** in `expected_wire_chain_id` — an incomplete cover of the
selected v2 domain.

### Binding completion (section 2)

* `GenesisConsensusAuthority` now **independently holds** the authorized wire
  chain id as `authorized_wire_chain_id: Option<u32>` with accessor
  `authorized_wire_chain_id()`. Production constructors set it to `None` (there
  is no runtime→wire chain-id mapping, so production stays unbindable and
  honest); only the `#[cfg(test)]` `for_verification_snapshot_fixture` sets
  `Some(_)`, fixed at owner construction.
* `AuthorizedProposalVoteSnapshot::try_bind` adds a fail-closed check after the
  chain-identity check: the owner's `authorized_wire_chain_id()` must be `Some`
  and equal the verifier domain's `expected_wire_chain_id()`, else it returns the
  new `SnapshotCoherenceError::WireChainIdMismatch`. The authorized wire id is
  never read from the verifier during binding (no manufactured approval by
  copying B's domain into the owner's expected identity); a `None` owner value
  rejects.

### Immediate-handoff correction (section 3)

The Proposal handler verifies using `effective_pv` (the bound snapshot verifier
when a snapshot is present), but on an engine-produced action it previously
called `forward_actions_to_facade(..., pv_authority, ...)` — the separately
supplied authority. That immediate path could switch from admitted A to
unrelated B. It now forwards with the **bound** `effective_pv` so the outbound
effect uses the same authority that admitted and verified the message; it never
falls back to the supplied B or the Timeout signer. QC verification, general
outbound, cached/directed/deferred freshness paths are unchanged (explicitly out
of scope).

### New behavioral tests (section 5) — in `mod run422_d7a`, all passing

* `d7a2_bind_rejects_owner_a_verifier_b_differ_only_in_wire_chain_id` — owner A
  vs verifier B identical in membership, key provider, runtime chain, genesis and
  commitment, differing only in `expected_wire_chain_id`; `try_bind` fails closed
  with `WireChainIdMismatch`.
* `d7a2_wire_domain_proposal_ml_dsa_controls` and
  `d7a2_wire_domain_vote_ml_dsa_controls` — real ML-DSA-44 controls: a B-domain
  message is valid under coherently-authorized B, while A cannot authorize it;
  the matching-A positive control is retained.
* `d7a2_immediate_handoff_uses_bound_authority_not_supplied_b` — real handler with
  coherent snapshot A and separately-supplied authority B, a recording facade
  (`HandoffFacade`) and directly-instrumented A/B signers. Positive control: the
  inbound A proposal is engine-accepted and the immediate action path is reached
  (one forwarded action). Assertions: B's signer is **never invoked**, and the
  emitted vote verifies under the selected domain A.

### Validation results (implementation SHA `d7387dcecb55ba6d7050158c5d70492301f6334e`; final doc SHA `a7af8db`)

* `cargo test -p qbind-node --lib run422_d7a` ⇒ 30 passed, 0 failed, exit 0.
* `cargo test -p qbind-node --lib binary_consensus_loop` ⇒ 146 passed, 0 failed,
  exit 0.
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` ⇒
  34 passed, 0 failed, exit 0 (D6 crypto matrix).
* `cargo test -p qbind-node --test run_422_d7_authority_lifetime_tests
  --test run_422_genesis_consensus_authority_tests` ⇒ the two source targets carry
  **14** and **15** tests respectively (combined 14 + 15 = 29), 0 failed, exit 0.
  (The earlier "15 passed" figure recorded only the second target and undercounted
  the 14-test lifetime target; the count is reconciled from actual per-target
  execution records, not inferred from source line counts.)
* `cargo check -p qbind-node --lib` ⇒ clean, exit 0.
* `cargo clippy -p qbind-node --lib` ⇒ exit 0 (pre-existing warnings only; none in
  the changed lines).
* `cargo build --release -p qbind-node` ⇒ Finished, exit 0 (`release` profile,
  optimized target(s) in 5m 39s).
* Known unrelated `--tests` compile failures (e.g.
  `m16_epoch_transition_hardening_tests` missing `RocksDbConsensusStorage`
  helpers) are pre-existing and untouched by this change.
* **Security tools (`parallel_validation`):** Code Review ⇒ reviewed 3 files, no
  comments, but the model-backed reviewer reported a model-registry environment
  error (`claude-sonnet-4.6 not found in registry`), so this is NOT a substitute
  for manual review. CodeQL (`rust`) ⇒ **Analysis SKIPPED because the database
  size is too large** — 0 alerts, but this is an INCOMPLETE analysis and is NOT
  converted into a passing conclusion; CodeQL coverage for this change remains
  outstanding.

### Finding dispositions

Finding **#2** is now **fully bound for the tested inbound boundary**: the
authorized identity covers the complete selected v2 domain including
`expected_wire_chain_id`, and the immediate handoff uses the bound authority.
Findings **#3** (ticket issuer identity / generation exhaustion) and **#4**
(replacement-ordering) remain explicitly **OPEN**. No durable anti-rollback and
no production lifecycle are established. Run 423 remains deferred.

```
D7A_INBOUND_VERDICT=PARTIAL
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

## Run 422 D7-A3 — issuer-bound authorization tickets + fail-closed generation exhaustion (code + test)

This bounded phase closes the **ticket-issuer identity** and **generation-exhaustion**
halves of finding **#3**. It is source + `cfg(test)` only and does **not** reopen
D7-A1/A2. Real-handler replacement-ordering (finding #4) stays explicitly **OPEN**.

### Issuer binding (section 3)

`AuthorizationTicket` is now opaque and bound to its issuing owner via an
opaque **allocation-backed identity** (`Arc<OwnerIdentity>`, a zero-sized marker):

- Each `CurrentAuthorizationOwner` constructor (`unavailable`,
  `establish_for_fixture`) allocates one fresh `Arc<OwnerIdentity>`; `admit`
  clones it into the ticket and `confirm` compares allocations with
  `Arc::ptr_eq` (never a raw address, reusable numeric id, or wrapping global
  counter).
- A **different** owner rejects the ticket (`ConfirmError::ForeignIssuer`) even
  with byte-for-byte identical configuration and equal generation; an
  **unavailable** owner also rejects a foreign ticket.
- The identity is **stable across moves** of the owner value (the heap
  allocation is unchanged), so moving the owner does not invalidate its
  legitimate ticket.
- **Snapshot binding invariant (documented):** an owner's `candidate` authority
  is immutable and its private `current` state changes only via a replacement
  that advances `generation`; therefore *(issuer allocation, generation)*
  uniquely pins the admitted snapshot — issuer binding plus the ticket
  generation is sufficient to bind the snapshot, and complete D6 domain binding
  (incl. authorized wire-chain id) is preserved by `try_bind`.
- **Clone semantics:** `CurrentAuthorizationOwner` intentionally does not derive
  `Clone`, so a second handle to the same logical owner cannot be forged; every
  constructed owner is a separately maintained owner with a distinct identity.

### Generation exhaustion (section 4)

`replace_for_fixture` uses a **checked** advance instead of `saturating_add`. If
generation+1 cannot be represented, the owner latches a terminal exhausted state
(generation left at `u64::MAX`, no wraparound / reset / panic / silent reuse):

- `admit` fails closed with `FreshnessError::AuthorizationExhausted`;
- `confirm` rejects **every** outstanding ticket with `ConfirmError::Exhausted`,
  including a ticket issued at the maximum generation (whose generation still
  equals the owner's);
- later replacement attempts cannot restore authorization.

The exhaustion-injection helper (`set_generation_for_exhaustion_fixture`) is
`cfg(test)`-only; production retains **unavailable-only** current-authorization
construction. `confirm` returns a bounded, non-secret `ConfirmError`
(`ForeignIssuer` / `Stale` / `Exhausted`).

**Exhaustion counters (accurate scope).** The new
`inbound_{proposal,vote}_authorization_exhausted_total` counters are incremented
by **admission-error handling** only: `record_{proposal,vote}_current_auth_reject`
maps `FreshnessError::AuthorizationExhausted` (returned by `admit` on an
exhausted owner) into them. The real inbound handler's **confirmation**
(`confirm`) failure path still routes through the existing
stale-before-effect counter; a `ConfirmError::Exhausted` returned by `confirm`
is **not** separately dispatched through the real handler in this phase and is
**not** claimed as demonstrated there. No existing rejection is weakened.

### Tests (section 5)

New deterministic unit tests in
`genesis_consensus_authority::tests::d7a3_ticket_issuer_and_exhaustion` (10,
passing): same-owner admit+confirm; foreign owner with identical config +
generation; foreign unavailable owner; owner move preserves ticket; identical-
config replacement invalidates earlier ticket; near-maximum advance;
exhaustion permanently rejects admit+confirm incl. the last max-generation
ticket; repeated post-exhaustion attempts; distinct per-owner identities; and
the shared-candidate regression below. The retained separate-candidate, move,
stale-ticket and exhaustion tests are unchanged, as are the retained
`mod run422_d7a` (30) and D7 lifetime (14) controls.

**Shared-candidate regression — `shared_candidate_owners_have_distinct_issuer_identities`.**
The pre-existing foreign-owner tests call `owner_matching()` separately, which
allocates a *different* candidate `Arc` per owner, so they cannot by themselves
distinguish issuer identity from candidate identity. This added test isolates
the two: it creates **exactly one** candidate `Arc`, constructs two independent
owners from `Arc::clone`s of that same candidate with byte-for-byte identical
observed configuration and equal generations, and explicitly asserts
`Arc::ptr_eq(owner_a.candidate(), owner_b.candidate())` (both owners share the
single candidate allocation). It then obtains a ticket from each owner, proves
each owner confirms **its own** ticket, and proves each **rejects the other's**
ticket with `ConfirmError::ForeignIssuer`. Exact claim: *issuer identity is the
per-owner opaque allocation, independent of a shared candidate allocation and of
equal generation numbers.*

### Provenance / SHAs (no invented ancestry)

This A3 completion runs in a shallow single-branch clone of
`copilot/run-422-d7-a3-complete-validation`; the earlier reviewed tip
`db69457b687f8ca9d9edb9b1f671ae041e592d82` cited in the task is not present in
this branch's local ancestry (only two commits are reachable). The recorded
SHAs are therefore taken from this branch:

* **A3 starting / implementation SHA** (issuer binding + exhaustion source and
  `d7a3_ticket_issuer_and_exhaustion` module as reviewed):
  `06dbfb68970f7f0e7a08c4841cb1ee576c8c4087`.
* **Tested implementation SHA** (adds the shared-candidate regression test; all
  validation below executed against this source):
  `56416d64717f2e7d19f4656fbcbe77b3a72b7407`.
* **Final documentation SHA**: recorded in the final report of this pass (the
  commit that lands this evidence update), not back-dated here.

### Validation results (tested SHA `56416d64717f2e7d19f4656fbcbe77b3a72b7407`)

All commands were run in this environment against the tested SHA above, dev
profile with default features unless noted. Sequential builds; normal commits
were checkpointed before the expensive release build. Subset relationships are
identified rather than summed.

| # | Command | Profile / features | Target(s) & count | Result | Exit |
|---|---------|--------------------|-------------------|--------|------|
| 1 | `cargo test -p qbind-node --lib genesis_consensus_authority::tests::d7a3_ticket_issuer_and_exhaustion` | dev / default | 10 tests (incl. new shared-candidate) | 10 passed, 0 failed | 0 |
| 2 | `cargo test -p qbind-node --lib genesis_consensus_authority` | dev / default | 24 tests (⊇ the 10 in #1) | 24 passed, 0 failed | 0 |
| 3 | `cargo test -p qbind-node --lib run422_d7a` | dev / default | 30 tests (⊂ #4) | 30 passed, 0 failed | 0 |
| 4 | `cargo test -p qbind-node --lib binary_consensus_loop` | dev / default | 146 tests (⊇ the 30 in #3) | 146 passed, 0 failed | 0 |
| 5 | `cargo test -p qbind-node --test run_422_d7_authority_lifetime_tests` | dev / default | 14 tests | 14 passed, 0 failed | 0 |
| 6 | `cargo test -p qbind-node --test run_422_genesis_consensus_authority_tests` | dev / default | 15 tests | 15 passed, 0 failed | 0 |
| 7 | `cargo test -p qbind-consensus` (D6 crypto matrix) | dev / default | full crate suite, D6 proposal/vote verify matrix included | all passed, 0 failed | 0 |
| 8 | `cargo check -p qbind-node` | dev / default | — | Finished (4m 11s) | 0 |
| 9 | `cargo clippy -p qbind-node --lib` | dev / default | — | Finished; 87 pre-existing lib warnings, **none in the changed lines** | 0 |
| 10 | `cargo build -p qbind-node --release` | release / default | — | Finished (5m 22s) | 0 |

Subset notes: #1 ⊂ #2 (the d7a3 module is part of the `genesis_consensus_authority`
lib tests); #3 ⊂ #4 (`run422_d7a` is a submodule of `binary_consensus_loop`).
Counts from a superset are therefore **not** added to its subset. Targets #5 and
#6 are distinct source files carrying **14** and **15** tests respectively; they
are reported separately (combined 14 + 15 = 29), never inferred from source line
counts.

Known unrelated broad-`--tests` compilation failures (e.g.
`m16_epoch_transition_hardening_tests` missing storage helpers) are pre-existing,
untouched by this change, and kept separate from the targeted runs above.

**Security tools.** CodeQL (`rust`): recorded **SKIPPED / INCOMPLETE** — the
database size prevents analysis in this environment; this is **not** a passed
scan and **not** a zero-alert security conclusion, and CodeQL coverage for this
change remains outstanding. Code review tool: any model-backed reviewer
backend/registry error is recorded separately and is **not** treated as a
successful review result or a substitute for manual review.

### Finding dispositions
**closed at the owner/ticket boundary (code + test)**. Finding **#4**
(real-handler replacement-ordering under the current single-threaded borrowing
model) remains explicitly **OPEN** — these tests establish owner/ticket
behavior and are **not** a proof of concurrent invalidation inside the real
handler. No shared mutable concurrency was introduced. Run 423 remains deferred.

```
D7A3_TICKET_ISSUER_BINDING=CLOSED-CODE-TEST
D7A3_GENERATION_EXHAUSTION=CLOSED-CODE-TEST
D7A_REPLACEMENT_ORDERING_REAL_HANDLER=OPEN
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

## Run 422 D7-A4 — real-handler authorization-to-effect ordering under the existing ownership model (test + docs)

This bounded phase addresses finding **#4** for the existing **synchronous**
inbound Proposal/Vote handler. It is **test + documentation only**: no
production behavior or build source changed (`crates/qbind-node/src/
binary_consensus_loop.rs` production paths and `genesis_consensus_authority.rs`
production paths are untouched; the only edit is additive `#[cfg(test)]`
coverage inside `mod run422_d7a`). The completed D7-A1/A2/A3 boundaries are
preserved and not reopened. No concurrency was introduced to manufacture an
otherwise-impossible interleaving.

### Provenance / deviations (no invented ancestry)
* Branch: `copilot/run-422-d7-a4`.
* This clone is a shallow single-branch clone (`.git/shallow` present); the
  reviewed branch `copilot/run-422-d7-a3-complete-validation` and the SHAs
  `f08079856a9214a6108436a01b8f5d8bf14e0c82` (reviewed final) and
  `56416d64717f2e7d19f4656fbcbe77b3a72b7407` (prior tested) are **not present**
  as local objects (`git cat-file -t` fails). No ancestry was invented; A4 work
  was performed on the supplied task branch. Disk: ~85 GB free.
* Implementation (tests) SHA: `eab2a838a12be96d8e7de242bad7ed3da3e3370e`.
* Final documentation SHA: recorded by the commit that lands this section
  (branch tip; see the PR commit list).

### Ownership / serialization model and its assumptions (source-backed)
* The handler borrows the current authorization **immutably**:
  `current_auth: Option<&AuthorizedProposalVoteSnapshot>`
  (`binary_consensus_loop.rs:3552`). The snapshot holds its
  `CurrentAuthorizationOwner` by value with **no interior mutability** (no
  `Cell`/`RefCell`/`Mutex`/`Arc<Mutex>` around the owner or its `current`
  state; `AuthorizedProposalVoteSnapshot` at `:1176`).
* The handler is **fully synchronous** — no `async`/`await` and no other
  suspension point exists between admission and effect. The backend crypto
  callbacks (`verify_proposal_msg_with_domain` / `verify_vote_msg_with_domain`)
  receive only immutable borrows of the snapshot-bound verifier
  (`effective_pv`, `:3669` / `:3992`) and cannot re-enter to replace
  `current_auth`.
* Consequence (the serialization argument): within **one** handler call,
  admission (`owner().admit()`), signature verification, confirmation
  (`owner().confirm(&ticket)`, `:3854` / `:4150`) and the synchronous effect
  all observe the **same** authorization generation. Refined (Run 422 D7-B1):
  the admission→verify→confirmation→effect **ordering** is **source-backed**
  (borrow model + statement order) rather than directly instrumented in A4;
  the A4 tests observe the boundary outcomes (reject-before-crypto / reach
  verification+confirmation), not an injected probe between confirm and effect.
  Replacing the current
  state requires **exclusive `&mut` access** to the owner, which is only
  reachable at a call site **outside** the handler (`owner_mut()` at `:1325`
  driving `replace_for_fixture` at `genesis_consensus_authority.rs:1255`,
  both `#[cfg(test)]`).
* Assumption/limitation: this is a **SERIALIZED-HANDLER** argument for the
  existing single-threaded borrowing model. It does **not** establish
  concurrent invalidation, and it does not assume a concurrency redesign. A
  redesign is neither a prerequisite nor an authorized deliverable here.

### Exact synchronous effect boundary (defined precisely)
The "synchronous effect" asserted by these tests is, within the handler call:
the **engine mutation** (`engine.on_proposal_event` / `engine.on_vote_event`),
the **delivery counters** (`inbound_proposals_delivered` /
`inbound_votes_delivered`, `*_engine_accepted`), the **restore deferral**
counter, and any **immediate outbound handoff** to the in-process
`ConsensusNetworkFacade` reached during the call. It explicitly does **NOT**
include later network delivery over a real socket, nor cancellation of work
already queued before entry. A facade call or queue insertion inside the call
is the boundary; it is **not** proof of downstream transmission. `engine
.current_view()` before/after is used as a **partial** source-backed no-effect
witness — refined (Run 422 D7-B1): unchanged `current_view` alone is **not** a
complete engine-state non-mutation witness (a mutation could leave the view
scalar unchanged), so the non-mutation claim rests on the source-backed
single-borrow / no-suspension serialization argument, with `current_view`
as corroborating rather than dispositive evidence.

### New behavioral evidence (section 5) — 6 A4 tests in `mod run422_d7a`, all passing
Coherent bound snapshots, `Required` policy, real F6 admission
(`pv_binding_gate`) and real ML-DSA-44 verification (`counting_pv` wrapping the
real `MlDsa44Backend`) are used throughout. `CountingSigVerifier` provides a
direct backend-call counter; `D7ActionRecorder` records emitted outbound
actions. Replacement between/before calls uses the real `owner_mut()
.replace_for_fixture` (exclusive `&mut` at a call site outside the handler),
never a mid-call hook and never shared mutable authorization; no sleeps.

| Test (`run422_d7a::…`) | Claim | Kind |
| --- | --- | --- |
| `d7a4_proposal_replacement_between_completed_calls_obtains_fresh_authorization` | Call 1 (matching) reaches verification + confirmation and the real backend; after an exclusive `&mut` replacement between calls, call 2 obtains **fresh** authorization and rejects the superseded candidate before crypto (backend counter unchanged, latency observations 0, no engine effect). | observed + source-backed |
| `d7a4_vote_replacement_between_completed_calls_obtains_fresh_authorization` | Same serialized-ordering claim on the Vote arm. | observed + source-backed |
| `d7a4_proposal_replacement_before_entry_rejects_before_crypto` | Replacement to a superseding configuration **before** entry ⇒ reject before crypto and before any downstream effect (backend 0, facade 0, view unchanged). | observed + source-backed |
| `d7a4_vote_replacement_before_entry_rejects_before_crypto` | Same, Vote arm. | observed + source-backed |
| `d7a4_proposal_exhausted_authorization_rejects_before_crypto` | Terminally **exhausted** authorization rejects with the exhausted admission reason (`inbound_proposal_authorization_exhausted_total==1`), distinct from unavailable/superseded, before crypto and effect. | observed + source-backed |
| `d7a4_vote_exhausted_authorization_rejects_before_crypto` | Same, Vote arm. | observed + source-backed |

Retained (unchanged) controls that A4 relies on and preserves: matching-state
verify-accepted, unavailable/superseded/missing-owner (finding #1) rejections,
`d7a_ticket_confirm_fails_after_replacement` (admit→replace→confirm state
machine), `d7a_active_restore_mode_negative_and_positive_control` (valid control
reaches actual deferral; invalid cannot change deferral/delivery/reconfig), and
`d7a2_immediate_handoff_uses_bound_authority_not_supplied_b` (engine-produced
action invokes only the bound signer and records the emitted Vote).

### Observed vs source-backed vs still-unproven
* **Observed** (through the real handler + real ML-DSA-44): fresh authorization
  is re-derived on each entry; a superseded/exhausted current state rejects
  **before** the real signature backend is invoked and before any engine/facade
  effect; matching state reaches verification and confirmation.
* **Source-backed**: the immutable-borrow + no-interior-mutability +
  no-suspension-point argument that serializes admission→verify→confirm→effect
  within one call and forces replacement to an exclusive external `&mut` site.
* **Still unproven / out of scope (retained OPEN)**: concurrent invalidation
  inside a single call; queued-work cancellation; persistent/durable freshness
  across restart; production current-authorization lifecycle (production
  `current_auth` remains **unavailable-only**). No claim is made that every
  downstream stage was reached merely because a message verified.

### This-phase validation (exact commands, counts, exit codes)
Profile: `test`/`dev` (unoptimized + debuginfo), default features. Tested
implementation SHA `eab2a838a12be96d8e7de242bad7ed3da3e3370e`.
* `cargo test -p qbind-node --lib run422_d7a::d7a4` → ok, **6 passed**, 0 failed
  (exit 0).
* `cargo test -p qbind-node --lib run422_d7a` → ok, **36 passed**, 0 failed
  (exit 0) — the 30 retained D7-A1/A2/A3 in-crate tests plus the 6 new A4 tests
  (overlapping subset: the 6 `d7a4_*` are a strict subset of the 36).
* `cargo test -p qbind-node --lib d7a3_ticket_issuer_and_exhaustion` → ok,
  **10 passed**, 0 failed (exit 0).
* `cargo test -p qbind-node --test run_422_d7_authority_lifetime_tests` → ok,
  **14 passed**, 0 failed (exit 0).
* `cargo test -p qbind-node --test run_422_genesis_consensus_authority_tests`
  → ok, **15 passed**; `--test run_422_startup_refusal_tests` → ok,
  **4 passed** (exit 0).
* `cargo check -p qbind-node --lib` → Finished, exit 0.
* `cargo clippy -p qbind-node --lib` → 0 errors (pre-existing warnings only),
  exit 0. `cargo clippy -p qbind-node --lib --tests` surfaces **5 pre-existing
  E0599 errors in the unrelated integration test
  `crates/qbind-node/tests/m16_epoch_transition_hardening_tests.rs`**
  (`set_inject_write_failure` / `clear_epoch_transition_marker`, a
  feature-gated fault-injection API); these are **not** introduced by this pass
  and do not touch the A4 change (lib-only).
* Release `qbind-node` build: **not re-run** this pass. This is a test/docs-only
  change with no production behavior/build source delta, so the previous
  release-build result is **preserved at its actual prior tested SHA** rather
  than relabeled. `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`
  is retained.

### CodeQL reconciliation (kept separate, no history overwrite)
Two distinct reasons must not be conflated: (a) the **historical** production-
analysis CodeQL **database-size** skips recorded in earlier D7 passes remain as
they were — not overwritten and not claimed as a successful scan; and (b) this
completion pass is **test/docs scope** (no production source delta), so its
CodeQL security-scan disposition is a **scope skip**, which is **incomplete
analysis**, not a passing scan. Neither is reported as success.

### Finding dispositions and remaining obligations
Finding **#4** is established **only** as a scoped **SERIALIZED-HANDLER**
positive: under the existing single-threaded immutable-borrow model, the real
handler re-derives fresh authorization on each entry and rejects a
superseded/exhausted current state before crypto and before any synchronous
effect. No claim of concurrent invalidation, queued-work cancellation,
persistent freshness, or production-lifecycle completion is made. Preserved
boundaries (task §6): production Proposal/Vote authority unavailable;
unavailable-only production current authorization; genesis startup refusal;
`Required` default; F6-before-authorization ordering; complete D6 domain
binding and unchanged signing bytes; Timeout/NewView separation; issuer-bound
tickets and terminal exhaustion; bound authority at the immediate handoff. Run
423 remains deferred; no storage/recovery, durable anti-rollback, persistent
checkpoints, production chain-ID mapping, QC migration, general outbound
freshness lifecycle, or governance activation was implemented.

```
D7A4_SERIALIZED_HANDLER_ORDERING=CLOSED-CODE-TEST (scoped positive)
D7A4_CONCURRENT_INVALIDATION=NOT-CLAIMED
D7A4_QUEUED_WORK_CANCELLATION=NOT-CLAIMED
D7A4_PERSISTENT_FRESHNESS=NOT-ESTABLISHED
D7A_INBOUND_VERDICT=PARTIAL
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

## Run 422 D7-B1 — current authorization at the immediate OUTBOUND action-forwarding boundary (code + test)

Tested implementation + final documentation SHA: `ab69af25a70341cb2bf2fe3f2c0cc7c93e669b1d` (branch `copilot/run-422-d7-b1`; prior D7-A4 tested SHA `eab2a838a12be96d8e7de242bad7ed3da3e3370e`, reviewed A4 final `3627f1b36d8149a5d80c48d6bf9b8609791d3e55` — both are pre-clone ancestry, not present as local objects in this shallow single-branch checkout; no ancestry was invented).

### Exact forwarding scope and call-site changes (section 3)
The single guarded boundary is `forward_actions_to_facade` (`crates/qbind-node/src/binary_consensus_loop.rs:3613`). Its signature now threads an explicit, coherently-bound current-authorization snapshot **before** the test-only passthrough authority:

* new parameter `current_auth: Option<&AuthorizedProposalVoteSnapshot>` (the enforced snapshot) precedes the retained `pv_authority: Option<&ProposalVoteAuthority>` (consulted **only** on the `LocalFixtureUnsigned` no-snapshot passthrough) and `verification_policy`.
* two helpers were added: `admit_outbound_action` (`:3505`) returning `OutboundAuthAdmission::{Admitted{signer_ctx,ticket}, Rejected}`, and `confirm_outbound_before_effect` (`:3566`).
* outbound reject→counter mapping helpers `record_outbound_proposal_current_auth_reject` (`:5404`) and `record_outbound_vote_current_auth_reject` (`:5430`) map each `FreshnessError` to the correct per-action counter.

Call sites updated:

* `do_leader_tick` (`:3011`) gained a `current_auth` parameter (placed before `signer_ctx`) and forwards it; both production run-loop call sites (`:2679`, `:2824`) pass `None` — production wires **no** snapshot, so under `Required` leader-emitted actions reject fail-closed exactly as before (no behavioral regression, no new production capability).
* the real inbound Proposal handler’s immediate action handoff (`:4255`) now passes its **already-bound** `current_auth` (plus `pv_authority`) through the strengthened interface instead of the previously-computed `effective_pv`, so the inbound-admitted snapshot is the same object that guards the outbound handoff.

New per-action counters on `BinaryConsensusLoopInboundStats` (`:1749`–`:1757`), with documented semantics (a rejected action is **never** counted as sent): `outbound_{proposal,vote}_current_state_unavailable_total`, `_authority_superseded_total`, `_epoch_unauthorized_total`, `_authorization_exhausted_total`, `_authority_stale_before_effect_total`.

### Per-action authorization / signing / confirmation / effect sequence (section 3)
For each of `BroadcastProposal`, `BroadcastVote` and `SendVoteTo`, under `Required`:

1. **Admit** through `current_auth.owner().admit()` **before any signing**. Missing snapshot (`None` under `Required`) → `*_current_state_unavailable_total`; `Unavailable` → `*_current_state_unavailable_total`; `Superseded` → `*_authority_superseded_total`; `Exhausted` → `*_authorization_exhausted_total`. All reject before crypto.
2. **Epoch check**: the action message’s own `epoch` must equal `current_auth.authorized_epoch()` (founding epoch 0). A mismatch → `*_epoch_unauthorized_total`, rejected **before signing**; the message is **never** rewritten to pass.
3. **Sign** through the snapshot’s **bound verifier** (`snap.verifier()`) — never a separately-supplied authority or Timeout context. The retained D6 wire-chain checks, v2 signing-domain bytes, signer checks and fail-closed signing errors inside `sign_{proposal,vote}_for_broadcast` run here (`*_wire_chain_mismatch` / `*_signing_failure` preserved).
4. **Confirm** the issuer/generation-bound ticket via `owner().confirm(&ticket)` **immediately before** the facade call. Confirmation failure (owner replaced / generation advanced / foreign / exhausted between admit and effect) → `*_authority_stale_before_effect_total`, effect **suppressed**, signed message discarded and not counted as sent.
5. **Effect**: only on confirmation success does the facade method fire (`broadcast_proposal` / `broadcast_vote` / `send_vote_to`) and the sent counter increment.

### Behavioral tests (section 5) — `mod run422_d7b`, 24 tests, all passing
Located inside `mod run422_d7a` at `:15541` (reusing the D7-A coherent snapshot / exhaustion / replacement fixtures and the 4-validator ML-DSA-44 crypto fixture). Each drives the **actual** `forward_actions_to_facade` with a recording facade (`OutboundRecorder`, capturing proposals / broadcast-votes / directed-votes **separately**) and a directly-instrumented `RecordingSigner` that counts `sign_proposal` / `sign_vote` and **delegates to the real ML-DSA-44 `LocalKeySigner`**. All three variants are exercised **independently** — a rejected Proposal never stands in for the Vote or SendVoteTo branches.

Test-to-claim matrix (each row present for **all three** variants: Proposal / BroadcastVote / SendVoteTo):

| Scenario | Test (per variant) | Asserted |
| --- | --- | --- |
| matching current authorization signs + reaches the correct facade method | `d7b_{proposal,vote,send_vote_to}_matching_*` | signer invoked exactly once; correct sent counter = 1; **positive control** — emitted message verifies under the SELECTED domain and FAILS under a FOREIGN domain (proves the real signing path is connected) |
| missing current snapshot | `d7b_*_missing_snapshot_rejects_before_signing` | `*_current_state_unavailable_total=1`; zero signer calls; zero facade calls; legacy `*_verification_context_unavailable_total=0` (rejection now occurs at the stronger D7-B1 layer) |
| unavailable authorization | `d7b_*_unavailable_rejects_before_signing` | `*_current_state_unavailable_total=1`; no signing/effect |
| superseded authorization | `d7b_*_superseded_rejects_before_signing` | `*_authority_superseded_total=1`; no signing/effect |
| exhausted authorization | `d7b_*_exhausted_rejects_before_signing` | `*_authorization_exhausted_total=1`; no signing/effect |
| unauthorized message epoch (epoch=1) | `d7b_*_unauthorized_epoch_rejects_before_signing` | `*_epoch_unauthorized_total=1`; no signing/effect |
| separately supplied authority B cannot replace admitted A | `d7b_*_supplied_authority_b_cannot_replace_admitted_a` | A signs (its counter=1); B never invoked (B counter=0); emitted message verifies under A’s domain, not B’s |
| replacement after a completed authorized call | `d7b_*_replacement_after_completed_call_rejects_next` | call 1 sends; after `replace_current_with_b` the next call rejects with `*_authority_superseded_total=1` before signing; signer count unchanged; no further effect |

Directed-Vote specificity: the `send_vote_to` tests assert the `directed_votes` capture (recipient `ValidatorId(3)`) and that `broadcast_votes` stays empty (and vice-versa for the broadcast tests), so the wrong method can never satisfy the assertion. Every rejection asserts sent counters are unchanged. A4’s synchronous borrowing model is preserved: replacement is a deterministic between-call `&mut` operation (`replace_current_with_b`), with no unsafe code or test-only mutable aliasing manufacturing concurrent mutation.

### Migrated Required-positive tests (section 4)
* `run422_d5d_outbound_forwarding_suppressed_without_pv_authority`: now drives the strengthened interface with `None, None`; asserts the D7-B1 unavailable counters (`outbound_proposal_current_state_unavailable_total=1`, `outbound_vote_current_state_unavailable_total=2`) and that the older D5 `*_verification_context_unavailable_total` counters are `0` (rejection moved earlier — a strengthening, not a weakening). No assertion was weakened; no switch to `LocalFixtureUnsigned`.
* `run422_d6_outbound_vote_wire_chain_refusal_through_forward_actions` (both sub-cases): now build a coherently-bound `coherent_snapshot_for(&pv)` and pass `Some(&snap), None`, so the D6 wire-chain refusal and correct-wire control are exercised **through** the bound snapshot (admission + founding-epoch check pass; base messages carry epoch 0). Selected/foreign/legacy-domain signature controls and the wire-chain-mismatch / signing-error coverage are retained.

The explicit test-only unsigned policy (`LocalFixtureUnsigned`) remains reachable **only** without a wired snapshot and is **not** exposed through any production configuration route.

### Upstream engine / cache effects OUTSIDE this guard (documented, not silently expanded)
This phase enforces authorization only on actions **already supplied** to `forward_actions_to_facade`. It does **not** establish authorization before upstream engine action generation (`engine.on_proposal_event` / leader-tick action production), leader-cache updates (the `reemit_*` single-shot caches), or reconfiguration/peer-transition observation. Those earlier effects (engine state advance, action enqueue, last-known-peer set updates) occur before this boundary and are **not** guarded by it.

### Remaining cached / deferred / later-delivery freshness gaps (retained OPEN)
* **Cached re-emission** (B9/B10 `maybe_reemit_on_late_peer_connect`, which calls `sign_*_for_broadcast` directly): **OPEN** — not threaded through the D7-B1 snapshot in this phase.
* **Deferred-work re-admission**: **OPEN**.
* **Later network delivery** over a real socket: **OPEN** — a facade call is the boundary, not proof of transmission (no socket delivery is claimed from facade observations).
* Every other `sign_*_for_broadcast` helper caller beyond the two guarded production call sites: inventoried and kept explicitly **OPEN** (this task was not expanded to all signing-helper callers).

### A4 wording refinement (section 8)
The A4 report text is refined in place: (a) the admission→verify→confirmation→effect **ordering** is **source-backed** (borrow model + statement order) and is **not** claimed as directly instrumented in A4; (b) unchanged `engine.current_view()` alone is **not** a complete engine-state non-mutation witness — it is corroborating, not dispositive, with the non-mutation claim resting on the single-borrow / no-suspension serialization argument. The valid scoped serialized-handler result (`D7A4_SERIALIZED_HANDLER_ORDERING=CLOSED-CODE-TEST`) is preserved. No claim of cancellation of previously-queued work or actual socket delivery is made.

### Validation results (tested SHA `ab69af25a70341cb2bf2fe3f2c0cc7c93e669b1d`)
Profile: `test`/`dev` (unoptimized + debuginfo) for tests/check/clippy; `release` (optimized) for the node build. Default features. Sequential builds; normal task-branch commits checkpointed before the expensive release build. Overlapping subsets identified inline.

* `cargo test -p qbind-node --lib run422_d7b` → ok, **24 passed**, 0 failed, 1524 filtered out (exit 0). *(strict subset of the run422 run below.)*
* `cargo test -p qbind-node --lib run422` → ok, **82 passed**, 0 failed, 1466 filtered out (exit 0) — the 58 retained D7-A/A3/D5/D6 in-crate tests plus the 24 new D7-B1 tests.
* `cargo test -p qbind-node --lib binary_consensus_loop` → ok, **176 passed**, 0 failed, 1372 filtered out (exit 0) — full module, no regressions. *(superset of the two runs above.)*
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests` → ok, **3 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_d7_authority_lifetime_tests` → ok, **14 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_genesis_consensus_authority_tests` → ok, **15 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` → ok, **4 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_d4_startup_ordering_tests` → ok, **5 passed** (exit 0).
* `cargo check -p qbind-node --lib` → Finished, exit 0.
* `cargo clippy -p qbind-node --lib` → 0 errors; the two new multi-arg fns carry `#[allow(clippy::too_many_arguments)]` per the file’s existing convention (7 prior uses); only pre-existing warnings remain, exit 0.
* Release `qbind-node` build: `cargo build -p qbind-node --release` → Finished in 5m 28s, exit 0 — this run **does** cover production-source changes (the forwarding boundary), so the release build was re-run and passed. `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED` is retained: the release build proves compilation, **not** adversarial release-binary current-authorization activation (production still wires no snapshot).

### Security-tool disposition (accurate, no incomplete-analysis-as-pass)
CodeQL: this pass **does** touch production consensus source, so CodeQL is **not** a scope skip; it is run via `parallel_validation` with `codeql.isTrivial=false`. Observed outcome this run: **"Analysis was skipped because the database size is too large"** — recorded as **incomplete analysis, NOT a passing scan**. Historical production-analysis CodeQL database-size skips from earlier D7 passes remain as recorded and are not overwritten. Code Review: completed with **no review comments**, but the reviewer backend also emitted a **model-registry error** (`model claude-sonnet-4.6 not found in registry`); the clean result is therefore reported with that **reviewer-backend error noted**, not treated as an unqualified independent pass.

### Scoped verdict and preserved posture
The only new positive verdict names the **immediate outbound forwarding boundary** (`forward_actions_to_facade`) and nothing downstream. Preserved (task §6): production Proposal/Vote authority unavailable; unavailable-only production current authorization; genesis startup refusal; `Required` default; F6-before-inbound-authorization ordering; complete D6 domain binding and unchanged signing bytes; Timeout/NewView separation; issuer-bound tickets and terminal exhaustion; all completed D7-A1–A4 guarantees. No production activation, trusted-epoch fabrication, storage/recovery lifecycle, persistent checkpoints, durable anti-rollback, production chain-ID mapping, QC migration, concurrency redesign, or Run 423 work was implemented.

```
D7B1_OUTBOUND_FORWARDING_BOUNDARY=CLOSED-CODE-TEST (scoped positive; immediate forward_actions_to_facade only)
D7B1_CACHED_REEMISSION_FRESHNESS=OPEN
D7B1_DEFERRED_WORK_READMISSION_FRESHNESS=OPEN
D7B1_LATER_SOCKET_DELIVERY=NOT-CLAIMED
D7A4_SERIALIZED_HANDLER_ORDERING=CLOSED-CODE-TEST (scoped positive)
D7A4_CONCURRENT_INVALIDATION=NOT-CLAIMED
D7A4_QUEUED_WORK_CANCELLATION=NOT-CLAIMED
D7A4_PERSISTENT_FRESHNESS=NOT-ESTABLISHED
D7A_INBOUND_VERDICT=PARTIAL
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

## Run 422 D7-B2 — authorize cached Proposal/Vote late-peer re-emission (code + test)

### B1 revision separation (task §1)
The reviewed D7-B1 branch `copilot/run-422-d7-b1` was verified in the actual
source. Two SHAs are kept **distinct**, not described as one revision:

* **B1 tested SHA** `eba8e0d827a3bd16c53fd08ad635bdfde7c9363f` — the revision at
  which the D7-B1 outbound-forwarding tests were run.
* **B1 final CRLF/documentation SHA** `9b8acf7` — a trailing-newline-only
  change over `eba8e0d` touching exactly two files
  (`crates/qbind-node/src/binary_consensus_loop.rs` and this evidence doc); no
  logic difference from the tested SHA.

`eba8e0d` was absent from the shallow task checkout and was fetched on demand
(`git fetch --depth=50 origin <sha>`); no ancestry was fabricated and no older
implementation was substituted. HEAD at the start of D7-B2 = `9b8acf7`.

### Exact cache trust boundary (task §2–§4)
The strengthened boundary is the **cached** late-peer re-emission path
`maybe_reemit_on_late_peer_connect` (`crates/qbind-node/src/binary_consensus_loop.rs`),
which the B1 pass had explicitly left **OPEN**
(`D7B1_CACHED_REEMISSION_FRESHNESS=OPEN`). It now enforces current
authorization **before** the cached bodies are signed or forwarded, for both the
**B9 cached Proposal** and the **B10 paired cached Vote**. B1's immediate
`forward_actions_to_facade` boundary and the A1–A4 guarantees are unchanged.

Cache-provenance binding (the core of §3):

* `CachedReemissionProvenance` (`:3067`) binds each eligible cached message to
  its **originating** authorized snapshot via an `AuthorizationTicket` minted by
  the originating owner's `CurrentAuthorizationOwner::admit()` at the trusted
  cache-creation boundary (`CachedReemissionProvenance::capture`, `:3086`),
  reusing the existing opaque issuer-identity + generation ticket mechanism. It
  also records the snapshot's `authorized_epoch` at capture for a defence-in-depth
  cross-check.
* Provenance is captured **only** at cache creation inside `do_leader_tick` —
  the caches are now typed `CachedLeaderProposal` / `CachedLeaderVote`
  (`:3101`, `:3111`) carrying the immutable message, its view, and the
  provenance together, so a cache entry can never be separated from the
  authorization that created it. The re-emission path **never** mints fresh
  provenance for an already-cached entry.
* At re-emission, `admit_cached_reemission` (`:3934`) takes a **fresh**
  `admit()` from the snapshot's owner (proves current authorization is available
  now) **and** re-validates the cached ticket via the same owner's `confirm()`.
  A different owner (foreign issuer — a new owner with identical configuration),
  an advanced generation (same-owner replacement, including replacement back to
  an identical configuration), or a terminally exhausted owner is refused. Fresh
  authorization is therefore necessary but **not** sufficient: cached work
  created under owner A can never acquire authorization merely because owner B is
  current at replay. Missing provenance fails closed under `Required`.
* This binding is explicitly **in-process** (issuer allocation + generation live
  for the life of the owner value); no persistent or restart anti-rollback is
  claimed (`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED` retained).

Enforcement order per eligible cached message (§4), before the facade call:
require a coherent `AuthorizedProposalVoteSnapshot` → fresh `admit()` from its
owner → validate the cache's originating provenance against that owner/snapshot
→ enforce the message's authorized epoch → sign **only** through the snapshot's
bound `verifier()` (preserving the D6 wire-chain checks, canonical v2 bytes, and
existing signer/error checks) → `confirm_outbound_before_effect` immediately
before the facade call. Any rejection suppresses that message's effect. A
separately-supplied `pv_authority` is consulted **only** under the test-only
`LocalFixtureUnsigned` policy when no snapshot is wired; it can never substitute
for a wired snapshot, and message epoch/chain/domain are never rewritten to
pass. Production wires `None` (fail-closed under `Required`); no
established-owner factory, new flag, environment override, or unsigned fallback
was added. The synchronous immutable-borrow model is unchanged (no unsafe,
interior mutability, sleeps, or test-only aliasing to manufacture mid-call
mutation).

### Counter semantics (task §5)
Fresh-admission failures at re-emission (unavailable / superseded / exhausted /
epoch) reuse the existing B1 `outbound_proposal_*` / `outbound_vote_*` reject
counters. Two cache-specific counter families were added (`:1759`–):
`outbound_{proposal,vote}_reemit_missing_provenance_total` and
`outbound_{proposal,vote}_reemit_provenance_rejected_total`. Authorization
failures and facade failures are documented separately (the facade-error paths
`eprintln!` and return without incrementing a re-emit counter).

**Partial-outcome accounting is preserved and accurate:** the Proposal and Vote
run **independent** admission/sign/confirm cycles. If the Proposal was
successfully handed to the facade but the paired Vote is subsequently rejected,
`outbound_proposal_late_peer_reemits` stays `1`, `outbound_vote_late_peer_reemits`
stays `0`, the Vote's per-reason rejection counter is `1`, and the completed
Proposal handoff is **not** undone. The per-view single-shot latch (set when the
Proposal is sent) is **not** weakened to retry a denied Vote through repeated
Proposal broadcasts. Genuine new-peer detection, current-view / local-leader
requirements, committed/obsolete-cache rejection, Proposal/Vote pairing, and the
reconnect-churn bound are all preserved.

### Behavioral tests (task §6) — `mod run422_d7b2`, 15 in-crate tests, all passing
Located inside `mod run420` (reusing `coherent_snapshot_for` / `make_ctx_v2` /
`d6_control_domain` / the 4-validator ML-DSA-44 crypto fixture). Every test
drives the **actual** `maybe_reemit_on_late_peer_connect` across a genuine
new-peer transition and eligible leader/current-view engine state, with a
`RecordingFacade` distinguishing broadcast Proposal / broadcast Vote / directed
(`send_vote_to`) Vote calls, and cached bodies signed on the positive path
through the snapshot's bound verifier delegating to the **real ML-DSA-44**
backend (signing invocations recorded via the `outbound_*_signing_success`
counters and corroborated by verifying emitted signatures).

* Positive both-families: `d7b2_valid_cache_current_auth_emits_both_families`
  — correct Proposal + Vote emitted; signatures **valid** under the selected v2
  domain and **rejected** under a foreign v2 domain and the legacy v1 boundary.
* Proposal-first negatives (nothing forwarded): missing snapshot under Required,
  unavailable state, superseded state, terminal exhaustion, missing cache
  provenance, cache from owner A offered to owner B (identical configuration /
  shared candidate, distinct issuer identity), same-owner generation replacement
  (including replacement back to the original configuration), unauthorized
  Proposal epoch, and a separately-supplied authority that cannot substitute.
* Cached **Vote branch exercised independently** with an **admissible Proposal
  control** so the Proposal is emitted and the Vote branch is genuinely reached,
  then only the Vote fails — missing Vote provenance, Vote cache from owner A
  offered to owner B, and unauthorized Vote epoch — each asserting the actual
  partial outcome (`assert_proposal_only_partial`).
* Guards retained: no-peer-transition suppression despite valid auth, and the
  single-shot latch not weakened to retry a denied Vote across churn ticks.

Inconsistent-wire-metadata coverage is retained by the pre-existing
`run422_d6_late_peer_reemit_refused_on_inconsistent_wire` (updated to the new
cache structs; now also asserts authorization **passed** and the refusal is the
wire-chain check). Selected-domain acceptance and foreign-domain/legacy
rejection controls are retained; no Required-positive test selects
`LocalFixtureUnsigned`. Three pre-existing reemit tests were migrated to the new
cache structs + signature (D5-G suppression, D6-8 selected-domain signing, D6-9
inconsistent-wire) and pass.

### Validation results (task §7) — tested SHA `475e4114dc52acd52c6c0322f00d01105913943c`
Profile: `test`/`dev` (unoptimized + debuginfo) for tests/check/clippy;
`release` (optimized) for the node build. Default features. Sequential builds;
substantive work checkpointed before the expensive release build; disk monitored
(`df` ≈ 48–52% used throughout). Overlapping subsets identified inline.

* `cargo test -p qbind-node --lib run422_d7b2` → ok, **15 passed**, 0 failed,
  1548 filtered out (exit 0). *(strict subset of the run422 run below.)*
* `cargo test -p qbind-node --lib run422` → ok, **97 passed**, 0 failed, 1466
  filtered out (exit 0) — the retained D7-A/A3/A4/B1/D5/D6 in-crate tests plus
  the 15 new D7-B2 tests. *(superset of the run422_d7b2 run.)*
* `cargo test -p qbind-node --lib binary_consensus_loop` → ok, **191 passed**,
  0 failed, 1372 filtered out (exit 0) — full module incl. B9/B10 reemit
  regressions and the migrated D5-G/D6-8/D6-9 tests, no regressions.
  *(superset of the two runs above.)*
* `cargo test -p qbind-consensus --lib` → ok, **182 passed** (exit 0).
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
  → ok, **34 passed** (exit 0) — D6 domain-isolation matrix.
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests`
  → ok, **3 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` → ok,
  **4 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_d4_startup_ordering_tests` → ok,
  **5 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_d7_authority_lifetime_tests` → ok,
  **14 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_genesis_consensus_authority_tests`
  → ok, **15 passed** (exit 0).
* `cargo check -p qbind-node` → Finished, exit 0.
* `cargo clippy -p qbind-node --lib` → 0 errors; **no new warnings in the
  changed regions** (the two new multi-arg fns carry
  `#[allow(clippy::too_many_arguments)]` per the file's existing convention);
  only pre-existing baseline warnings remain, exit 0.
* Release `qbind-node` build: `cargo build -p qbind-node --release` → Finished
  in 7m 18s, exit 0. `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`
  retained: the release build proves compilation, **not** adversarial
  release-binary current-authorization activation (production still wires no
  snapshot).

### Security-tool disposition (accurate, no incomplete-analysis-as-pass)
This pass touches production consensus source, so CodeQL is **not** a scope skip
and is run via `parallel_validation` with `codeql.isTrivial=false`. Any
database-size skip observed is recorded as **SKIPPED/INCOMPLETE**, not a passing
scan. A reviewer-backend error is not treated as a successful review. Outcomes
are recorded exactly as returned.

### Scoped verdict and preserved posture
The only new positive verdict names the **cached late-peer re-emission
boundary** (`maybe_reemit_on_late_peer_connect`) and nothing downstream.
Explicitly retained as **unproved by this phase**: deferred-work re-admission,
later socket delivery, upstream engine / leader-step / reconfiguration effects,
production lifecycle, and persistent (restart) freshness. No production
activation, trusted-epoch fabrication, storage/recovery lifecycle, durable
anti-rollback, production chain-ID mapping, QC migration, authority activation,
or Run 423 work was implemented.

```
D7B2_CACHED_REEMISSION_BOUNDARY=CLOSED-CODE-TEST (scoped positive; maybe_reemit_on_late_peer_connect only)
D7B2_CACHE_PROVENANCE_BINDING=IN-PROCESS-ONLY
D7B1_OUTBOUND_FORWARDING_BOUNDARY=CLOSED-CODE-TEST (scoped positive; immediate forward_actions_to_facade only)
D7B1_DEFERRED_WORK_READMISSION_FRESHNESS=OPEN
D7B1_LATER_SOCKET_DELIVERY=NOT-CLAIMED
D7B2_UPSTREAM_ENGINE_LEADER_RECONFIG_EFFECTS=NOT-CLAIMED
D7B2_PERSISTENT_FRESHNESS=NOT-ESTABLISHED
D7A_INBOUND_VERDICT=PARTIAL
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```