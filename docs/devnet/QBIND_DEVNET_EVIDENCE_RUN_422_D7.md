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

Tested implementation SHA: `ab69af25a70341cb2bf2fe3f2c0cc7c93e669b1d`; reviewed B1 final CRLF/documentation tip: `eba8e0d827a3bd16c53fd08ad635bdfde7c9363f` (branch `copilot/run-422-d7-b1`; prior D7-A4 tested SHA `eab2a838a12be96d8e7de242bad7ed3da3e3370e`, reviewed A4 final `3627f1b36d8149a5d80c48d6bf9b8609791d3e55`). `9b8acf7` is the D7-B2 starting/import revision and is **not** B1's final revision; no claim is made that B1 tests ran at `9b8acf7`. All of `ab69af2`, `eba8e0d`, `eab2a83`, `3627f1b` are pre-clone ancestry, **not present as local objects** in this shallow single-branch checkout, so their recorded results are preserved as reported and not re-verified here; no ancestry was invented.

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

### B1 revision separation (task §1, §6 — corrected)
Three D7-B1 / D7-B2 revisions are kept **distinct** and are no longer conflated.
The earlier draft of this section mislabelled `eba8e0d…` as the "B1 tested SHA"
and `9b8acf7` as the "B1 final CRLF/documentation SHA"; that is corrected here:

* **B1 tested implementation SHA** `ab69af25a70341cb2bf2fe3f2c0cc7c93e669b1d` —
  the revision reported as the one at which the D7-B1 outbound-forwarding tests
  were run (see the D7-B1 section, which records the same SHA).
* **Reviewed B1 final CRLF/documentation tip** `eba8e0d827a3bd16c53fd08ad635bdfde7c9363f`
  — the trailing-newline / documentation tip of the reviewed B1 branch.
* **B2 starting / import revision** `9b8acf7` — this is B2's starting (import)
  revision. It is **not** B1's final revision, and no claim is made that the B1
  tests were executed at `9b8acf7`.

Shallow-checkout limitation (task §1, §6): this task's working tree is a
**shallow single-branch clone** of `copilot/copilotrun-422-d7-b2` (`git
rev-parse --is-shallow-repository` ⇒ `true`; `git rev-list --count HEAD` ⇒ `2`).
Only `a3d64fe` (HEAD) and `9b8acf7` are present as local objects. The revisions
`ab69af2`, `eba8e0d`, `475e411…` (reported B2 tested SHA) and `36c49520e8bfeb22be75c7c5a20b6f5558361999` (corrected; see typo note below)
(reported B2 final documentation SHA) are **absent** from this checkout
(`git cat-file -t` ⇒ "could not get object info") and could not be fetched in
this environment. Their SHAs are recorded **as reported**, not re-verified
against local objects; no ancestry was invented or substituted. HEAD at the
start of this corrective continuation = `a3d64fe`; B2's import revision =
`9b8acf7`.

Historical-identifier correction (task §6): an earlier revision of this
record wrote the previously reviewed B2 documentation revision as the
truncated, mistyped `36c5249…`. The correct object name is
`36c49520e8bfeb22be75c7c5a20b6f5558361999`. **Object availability is reported
separately from this supplied historical identifier:** like the other pre-clone
B1/B2 revisions above, `36c49520e8bfeb22be75c7c5a20b6f5558361999` is **absent**
from this shallow single-branch checkout (`git cat-file -t
36c49520e8bfeb22be75c7c5a20b6f5558361999` ⇒ "could not get object info"), so
its contents were not inspected and **no tested SHA is inferred from the
commit’s contents**. The identifier is recorded as the reviewed B2
documentation revision exactly as supplied; correcting the typo does not assert
that any test was executed at that object in this environment.

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

### Behavioral tests (task §6) — `mod run422_d7b2`, **24** in-crate tests, all passing
(15 tests from the prior pass, described immediately below; **9 added by the
corrective continuation**, described in the following subsection. All 24 pass —
see the corrective-continuation validation results.)
Located inside `mod run420` (reusing `coherent_snapshot_for` / `make_ctx_v2` /
`d6_control_domain` / the 4-validator ML-DSA-44 crypto fixture). Every test
drives the **actual** `maybe_reemit_on_late_peer_connect` across a genuine
new-peer transition and eligible leader/current-view engine state, with a
`RecordingFacade` distinguishing broadcast Proposal / broadcast Vote / directed
(`send_vote_to`) Vote calls, and cached bodies signed on the positive path
through the snapshot's bound verifier delegating to the **real ML-DSA-44**
backend (successful signing corroborated by the `outbound_*_signing_success`
counters **and** by verifying emitted signatures; direct signer-entry invocation
counting — including zero-invocation on rejection — is added by the corrective
continuation described below).

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

### Direct signer-invocation observation and reachable cases (corrective continuation, task §2–§4)
The prior 15 tests corroborated signing via the `outbound_*_signing_success`
counters and signature verification. That is **necessary but not sufficient**:
`outbound_*_signing_success == 0` does **not** by itself prove the signer was
never invoked (a signer call returning an error would also leave that counter at
0). The corrective continuation adds a `ValidatorSigner` wrapper
(`RecordingSigner`) that **counts `sign_proposal` / `sign_vote` at method entry**
and delegates normal signing to the real ML-DSA-44 backend, with **separate
per-authority counters** (`SignerCounters`). Misleading comments that treated
`signing_success == 0` as proof of non-invocation were removed from the module
doc and from `assert_proposal_only_partial`. The 9 added tests:

* `d7b2_recording_signer_positive_control_directly_counts_both_invocations` —
  **positive control** proving the entry-counters are wired to the actual cached
  re-emission path: a successful both-families re-emission drives the recording
  signer and the proposal/vote entry counts are each `1`.
* `d7b2_recording_signer_rejected_proposal_directly_shows_zero_invocations` and
  `d7b2_recording_signer_rejected_vote_directly_shows_zero_vote_invocations` —
  **negative** tests that directly assert **zero** entry invocations for the
  rejected message (not merely `signing_success == 0`). Signing-success,
  rejection, and facade counters are kept as separate observations.
* `d7b2_do_leader_tick_creates_caches_then_real_reemission_uses_them` (task §3) —
  a **Required-policy** positive test driving `do_leader_tick` → the resulting
  typed `CachedLeaderProposal`/`CachedLeaderVote` caches → the actual
  `maybe_reemit_on_late_peer_connect`. It asserts the real cache writer created
  both entries with originating authorization, the cached bodies correspond to
  the leader-generated actions, re-emission reuses those entries **without**
  replacing/refreshing provenance, emitted signatures verify under the selected
  domain, and **initial forwarding vs later re-emission are distinguished** via
  separate facade captures / explicit deltas.
* `d7b2_do_leader_tick_without_current_auth_then_replay_stays_rejected` (task §3)
  — cache creation **without** current authorization (captured provenance is
  `None`) followed by replay under otherwise-valid authorization; the unproven
  entry remains rejected and replay does **not** manufacture provenance.
* `d7b2_case_a_cached_vote_generation_invalidation_across_a_b_a` (task §4.A) — a
  Vote from generation *g* is retained, the same owner's generation is advanced,
  and an admissible **current-generation Proposal** drives execution into the
  cached Vote: Proposal handoff succeeds, stale Vote provenance is rejected, the
  Vote signer is **not** invoked (direct zero-count), and no Vote is emitted. A
  real **A→B→A** configuration sequence is exercised between completed calls;
  fresh admission after returning to A succeeds while the old cache stays invalid.
* `d7b2_case_b_cached_vote_wire_chain_rejection_partial_outcome` (task §4.B) — an
  admissible Proposal plus a Vote with **inconsistent wire-chain metadata**
  reaches the Vote branch under valid current authorization/provenance; asserts
  the Vote **wire-mismatch** reason, **zero** Vote signer invocations (the wire
  check precedes `sign_vote`), and an accurate Proposal-only partial outcome.
  This is distinct from the pre-existing Proposal-first wire test.
* `d7b2_case_c_bound_a_signs_supplied_b_never_invoked` (task §4.C) — a valid
  **bound** snapshot A and a distinct **separately-supplied** authority B are
  present simultaneously with separately-instrumented signers; cached Proposal
  and Vote emit successfully, **A signs**, **B is never invoked**, and emitted
  signatures **verify under A's domain** and **fail under B's foreign domain and
  legacy v1**.
* `d7b2_case_d_shared_candidate_arc_still_isolates_by_issuer` (task §4.D) — the
  claimed shared-candidate case is constructed from **clones of the exact same
  candidate `Arc`** (asserted via `Arc::ptr_eq` on the candidate handles), and
  foreign cached authorization still fails. Separately-allocated,
  structurally-equal candidates are **not** described as a shared candidate.

The independent Vote missing-provenance, foreign-issuer, and unauthorized-epoch
tests are preserved. Shared-owner admission may reject at the Proposal before
Vote processing under the immutable synchronous model; that coverage is
attributed accurately and no mid-call mutation is manufactured to force an
unreachable Vote case.

**Coverage mapping (direct measurement vs source-supported ordering vs
untested).** *Directly measured* this pass: signer entry-invocation counts
(present and zero), real cache creation via `do_leader_tick`, provenance
preservation across re-emission, selected-domain signature acceptance and
foreign-domain / legacy-v1 rejection, wire-chain Vote rejection, A-signs /
B-never-invoked authority selection, and `Arc::ptr_eq` shared-candidate
isolation. *Source-supported ordering* (asserted by outcome, not by intra-call
tracing): the admit→provenance→epoch→sign→confirm→facade sequence within a
single synchronous call. *Untested / outside this phase:* deferred-work
re-admission, later socket delivery, upstream engine / leader-step effects,
production lifecycle activation, and persistent (restart) freshness. Counts of
overlapping test subsets are **not** summed.

### Validation results — prior D7-B2 pass (reported tested SHA `475e4114dc52acd52c6c0322f00d01105913943c`)
**Shallow-checkout caveat (task §1, §6):** `475e411…` is **absent** from this
shallow single-branch checkout and could not be re-verified. The counts in this
subsection are **preserved as recorded by the prior pass** at that reported SHA;
they predate the 9 tests added by the corrective continuation (see the next
subsection for the re-executed results at the actual working HEAD). They are
**not** relabelled as newly executed.

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

### Validation results — corrective continuation (this pass)
Branch `copilot/copilotrun-422-d7-b2` (note: the task specification names the
branch `copilot/run-422-d7-b2`; the actual checked-out branch name carries the
extra `copilot` segment — reported, not renamed). Working HEAD before this pass
= `a3d64fe`; only `a3d64fe` and the B2 import revision `9b8acf7` are present as
local objects (shallow clone). This is a **test-and-evidence-only** change to
`crates/qbind-node/src/binary_consensus_loop.rs` (added the `RecordingSigner`
invocation-recording wrapper, per-authority `SignerCounters`, a
`do_leader_tick`→cache→re-emission positive test, a no-authorization-then-replay
test, and Cases A/B/C/D) plus this evidence doc; **no production logic changed**,
so no new defect was exposed and the prior pass's release build is preserved at
its recorded SHA rather than re-executed.

Profile: `test`/`dev` (unoptimized + debuginfo). Default features. Disk
monitored (`df /` ≈ 47% used throughout, 78 G free). Overlapping subsets marked
inline; counts are **not** summed across overlapping runs.

* `cargo test -p qbind-node --lib run422_d7b2` → ok, **24 passed**, 0 failed,
  1548 filtered out (exit 0) — 15 retained + 9 new D7-B2 tests. *(strict subset
  of the run422 run below.)*
* `cargo test -p qbind-node --lib run422` → ok, **106 passed**, 0 failed, 1466
  filtered out (exit 0). *(superset of the run422_d7b2 run.)*
* `cargo test -p qbind-node --lib run422_d7b::` → ok, **24 passed**, 0 failed,
  1548 filtered out (exit 0) — D7-B1 in-crate module. *(subset of run422.)*
* `cargo test -p qbind-node --lib binary_consensus_loop` → ok, **200 passed**,
  0 failed, 1372 filtered out (exit 0) — full module incl. B9/B10 reemit
  regressions and binary-consensus-loop tests; no regressions. *(superset of the
  runs above.)*
* `cargo test -p qbind-consensus --lib` → ok, **182 passed** (exit 0).
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
  → ok, **34 passed** (exit 0) — D6 domain-isolation matrix.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` → ok,
  **4 passed** (exit 0) — Run 422 startup-refusal.
* `cargo test -p qbind-node --test run_422_d7_authority_lifetime_tests` → ok,
  **14 passed** (exit 0).
* `cargo test -p qbind-node --test run_422_genesis_consensus_authority_tests`
  → ok, **15 passed** (exit 0).
* `cargo check -p qbind-node` → Finished (dev), exit 0.
* `cargo clippy -p qbind-node --lib` → Finished (dev), **exit 0**; **85
  pre-existing baseline warnings**, no errors and **no new warnings introduced in
  the changed test regions**.
* Release `qbind-node` build: **not re-executed this pass** (test/docs-only
  change). The prior pass's `cargo build -p qbind-node --release` result is
  preserved at its recorded SHA; `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE
  =NOT-YET-CAPTURED` is retained.

### Security-tool disposition — corrective continuation
Recorded exactly as observed this pass; neither a CodeQL skip nor a reviewer
backend error is treated as a successful scan/review:

* CodeQL (`rust`, via `parallel_validation`, `codeql.isTrivial=false` because the
  touched file `binary_consensus_loop.rs` contains production consensus source
  even though the diff is test/comment-only): **observed outcome — "Analysis was
  skipped because the database size is too large" (0 alerts reported)**. This is
  recorded as **SKIPPED / INCOMPLETE, NOT a passing scan**; CodeQL coverage for
  this change remains **outstanding**.
* Code Review (via `parallel_validation`): the run returned a nominal
  "completed, reviewed 2 files, no review comments" **together with an explicit
  environment note that the code-review tool is NOT available in this
  environment** (`autofind` binary not found). It is therefore recorded as
  **UNAVAILABLE / UNVERIFIED**, not an independent clean review.

### Prior-pass security-tool disposition (retained, reported as returned)

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

## Run 422 D7-B3 — restore-catchup deferral disposition and fresh authorization on Proposal re-delivery (test + evidence)

Additive continuation. **No production logic changed** in this phase: the
inbound handler already re-runs the full admission/verification sequence on
every received envelope, so D7-B3 adds behavioral tests and this evidence
correction rather than a new mechanism.

### Actual branch / SHAs (task §1, §7)
* **Actual working branch:** `copilot/restore-deferral-disposition-fresh-authorization`
  (the supplied task branch; the message's `copilot/copilotrun-422-d7-b2` name and
  its revisions `8afb2915c0c4c463609098f1d1fcf1874513685e` /
  `53a534077b962013e986cbca6dbda689dbb2023f` are the *reviewed* B2 branch, not
  this checkout).
* **Starting HEAD (this phase):** `bb767166a705e3f217bfb6d8791feb3fce05fd76`.
* **Shallow-checkout limitation:** `git rev-parse --is-shallow-repository` ⇒
  `true`; `git rev-list --count HEAD` ⇒ `2` (only `bb76716` and its parent
  `a3d64fe` are present as local objects). The reviewed B2 revisions
  `8afb2915c0c4c463609098f1d1fcf1874513685e`,
  `53a534077b962013e986cbca6dbda689dbb2023f`, and the corrected historical
  documentation revision `36c49520e8bfeb22be75c7c5a20b6f5558361999` are **absent**
  from this checkout (`git cat-file -t` ⇒ "could not get object info") and could
  not be fetched here. Their SHAs are recorded **as supplied**; no ancestry or
  historical test execution is fabricated.
* Final SHA for this phase is the tip recorded by the commit that adds these
  tests and this section.

### Deferred-input disposition map (task §2)
Traced from `InboundConsensusEnvelope` reception through
`handle_inbound_consensus_msg` (`crates/qbind-node/src/binary_consensus_loop.rs`),
Proposal arm:

| Question | Finding (source) |
| --- | --- |
| Is the decoded Proposal discarded on deferral? | **Yes.** The active-restore branch increments `restore_catchup_proposals_deferred` and `return`s; the local `proposal`, its decoded bytes, the `AuthorizationTicket`, and the "verified" result are owned by the handler frame and dropped at scope end. |
| Do any Proposal bytes / ticket / snapshot / "already verified" result escape into retained work? | **No.** Nothing is stored, queued, or handed to another owner on the deferral path — no field, collection, or channel captures them. |
| Does a later retry require a newly received envelope? | **Yes.** There is no replay source; the only way the frame is processed again is a fresh `InboundConsensusEnvelope` re-entering the same handler. |
| Is there a nearby queue holding raw unverified input or previously authorized work? | **Not on this path.** The restore-catchup machinery (`RestoreCatchupModeState`, `handle_restore_catchup_response`) applies *authenticated response blocks*, not deferred inbound Proposals; it is a separate surface with its own obligations and is **not** expanded here. |
| Does Vote have an analogous deferral path? | **No.** The single `should_defer_restore_proposal_for_catchup` call site is the Proposal arm; the Vote arm has admission but no restore deferral. No Vote deferral was invented. |

**"Deferral" therefore means discard + await retransmission, not retained
work.** Because the frame is discarded, a re-delivered network message is fresh
untrusted input and is re-checked in full: F6 sender binding →
`owner().admit()` (current bound-snapshot admission) → signed-epoch check →
domain/wire/signature verification → pre-effect `confirm()` → the single
permitted synchronous effect. No cached verdict is consulted.

### Behavioral tests (task §4) — module `run422_d7b3` (11 tests)
All drive the real `handle_inbound_consensus_msg` under `Required` policy with
real encoded Proposals, coherent snapshots, real ML-DSA-44, a genuine F6
gate/origin, an active restore baseline (`snapshot_height=5`, engine restored so
`committed_height()==Some(5)`), the invocation-counting `CountingSigVerifier`
backend, and the recording `D7ActionRecorder` facade. Deferring frames are shaped
at height 7 (> committed+1) to reach the actual deferral branch. Cases H and I
are **sequential** real-handler tests over a single engine and (for I) a single
current-authorization owner: H advances the receiver's committed prefix between
completed calls, and I terminally exhausts the same owner between completed
calls, before re-delivering the identical encoded bytes.

| Case | Test | Demonstrated |
| --- | --- | --- |
| A. Initial deferral | `d7b3_a_initial_deferral_reached_after_admit_and_verify` | admit+epoch pass, real verify (backend calls == 1), `restore_catchup_proposals_deferred==1` attributed as the sole effect; `inbound_proposals_delivered==0`, engine-accepted 0, empty reconfig detector, facade 0. |
| B. Fresh verify on identical re-delivery | `d7b3_b_identical_redelivery_verifies_again` | same encoded Proposal + same valid snapshot delivered twice; backend-call delta is +1 each time (2 total), `deferred==2`; prior deferral supplies no reusable verdict. |
| C. Changed authorization before re-delivery | `d7b3_c_unavailable_current_auth_on_redelivery_rejects_before_effect`, `d7b3_c_superseded_current_auth_on_redelivery_rejects_before_effect`, `d7b3_c_omitted_snapshot_on_redelivery_rejects_before_effect` | after a completed deferral, making current authorization unavailable / superseded / omitted rejects the re-delivery on current state (no further backend call, no further deferral, no delivery, facade 0). |
| D. Foreign current domain | `d7b3_d_foreign_current_domain_rejects_original_signature` | the d5-domain-signed Proposal is verify-accepted under a d5-domain verifier and verify-**rejected** under a coherent d6-domain snapshot (same keys); rejection is a signature failure, **not** a wire-chain mismatch. |
| E. Valid new owner | `d7b3_e_valid_new_owner_independently_admits_and_verifies` | a distinct current-authorization owner with the same valid configuration independently admits + verifies the re-delivery (backend delta +1, `deferred==2`); the earlier owner's ticket is not reused and a new owner is not itself grounds to reject. |
| F. F6 ordering | `d7b3_f_f6_mismatch_precedes_authorization_on_redelivery` | on re-delivery a mismatched authenticated sender is rejected by F6 before any current-auth lookup or crypto (no backend call, no current-state counter, no deferral, facade 0). |
| G. Deferral branch control (distinct frames) | `d7b3_g_progress_stops_deferral_and_delivers_without_claiming_engine_success` | **Branch-control (predicate-outcome) test only:** two DIFFERENT signed frames on separate engines — a height-7 frame that DOES defer and a height-6 frame (committed+1, parent == committed block) that does NOT; the non-deferring frame is verify-accepted and `inbound_proposals_delivered==1`; engine acceptance is asserted only as a separate downstream outcome (`engine_accepted <= delivered`) — **no engine/QC success is claimed** from verifier success. This establishes distinct predicate outcomes; it is **not** progress-then-retransmission of the same deferred message (that is case H). |
| H. Receiver progress between deliveries (sequential retransmission) | `d7b3_h_receiver_progress_between_deliveries_delivers_same_message` | **Newly demonstrated sequential behavior.** One coherent snapshot, one engine, one signed height-7 Proposal (parent `[0xAB;32]`). Delivery 1 ⇒ admitted, real-verified (backend calls==1), `deferred==1`, not delivered. Between calls the receiver committed prefix is advanced to height 6 anchored at `[0xAB;32]` via the established `initialize_from_snapshot_baseline` startup helper — **fixture-driven receiver progress, NOT authenticated catch-up transport / QC validation / durable recovery** — while restore mode stays ACTIVE and the engine is NOT replaced. Delivery 2 re-delivers the identical encoded bytes: F6 admits again (accepted==2), backend delta exactly +1 (calls==2, no reused verdict), `verify_accepted==2`, `deferred` unchanged (still 1), `inbound_proposals_delivered==1`; engine/QC checked separately (`engine_accepted <= delivered`), facade 0. |
| I. Terminal exhaustion before retransmission | `d7b3_i_terminal_exhaustion_between_deliveries_rejects_retransmission` | A valid height-7 Proposal is admitted, verified, and deferred. Between calls the SAME current-authorization owner is driven into the terminal exhausted latch through the cfg(test) checked-overflow path (`set_generation_for_exhaustion_fixture(u64::MAX)` then a `replace_for_fixture` whose `generation+1` overflows — the latch is actually exercised, asserted via `is_exhausted`, not merely positioned). Candidate/verifier/bytes/sender unchanged. Re-delivery of the identical Proposal: F6 admits (accepted==2) but current admission fails as exhausted — dedicated admission-time counter `inbound_proposal_authorization_exhausted_total==1` (NOT the confirm-time `stale_before_effect` path), with the exhaustion reason independently established via the owner API. No further backend call (calls unchanged), no further verify-accept/deferral/delivery/engine-accept/facade action; owner remains terminally exhausted (`generation==u64::MAX`, no wraparound). |

Backend/signer invocation claims are DIRECT observations of the shared atomic;
multi-call claims use before/after deltas. No mid-call mutation, sleeps,
concurrent aliases, or persistent epoch source were introduced.

### Validation (task §6)

**Corrective continuation (cases H, I).** This phase adds the two sequential
real-handler tests (H: receiver progress between deliveries; I: terminal
exhaustion before retransmission), clarifies the case-G branch-control naming,
and updates this evidence. It was validated at code checkpoint
`e79e267c2d1a74afdfcf14cb98a72f3cddc5a6bd` on the actual working branch
`copilot/copilotrestore-deferral-disposition-fresh-authoriz` (the environment's
supplied branch; the message's reviewed branch
`copilot/restore-deferral-disposition-fresh-authorization` and the reviewed B3
revisions `a1852788a4e4171a3185832aa7444f9346482d49` /
`9f8d2bacb2bafaae74db24ccc09554412a39ef20` are **absent** from this shallow
single-branch checkout — `git cat-file -t` ⇒ "could not get object info" — and
could not be fetched; recorded as supplied, no ancestry fabricated).

**B3 provenance correction (task §7).** `bb767166a705e3f217bfb6d8791feb3fce05fd76`
is the *earlier baseline*, **not** the shallow boundary. The immediate
pre-implementation import that precedes the B3 tests
(`e79e267c2d1a74afdfcf14cb98a72f3cddc5a6bd`) is
`4c7e86d107e7c0677d18c6c6f13eb1b70a29d818`; in the reviewed ancestry the order is
`bb767166` (baseline) → `4c7e86d1` (import/update) → `e79e267` (tests) →
`62407fe` (evidence) → `1a75d30` (tool outcomes). In *this* checkout the local
shallow boundary is `4c7e86d1` (recorded in `.git/shallow`); the earlier `bb767166`
and the later `e79e267`/`62407fe`/`1a75d30` are pre-clone ancestry and are **not
present as local objects** here (historical local-object limitation preserved
separately, unchanged). Commands re-executed in the D7-B3 phase environment (profile: `test`/`dev`,
default features, qbind-node; disk `df` ≈ 44% used throughout):

* `cargo test -p qbind-node --lib run422_d7b3` ⇒ **11 passed**, 0 failed, 1572
  filtered out (exit 0) — the 9 prior cases plus new H and I. *(strict subset of
  the run422 and binary_consensus_loop runs below.)*
* `cargo test -p qbind-node --lib run422` ⇒ **117 passed**, 0 failed, 1466
  filtered out (exit 0) — retained D7-A/A3/B1/B2/D5/D6 in-crate tests plus the
  now-11 D7-B3 tests. *(superset of the run422_d7b3 run.)*
* `cargo test -p qbind-node --lib binary_consensus_loop` ⇒ **211 passed**, 0
  failed, 1372 filtered out (exit 0) — full module incl. restore-catchup, D6
  domain-isolation, and D5/D7-A/B1/B2 regressions, no regressions. *(superset of
  the two runs above.)*
* `cargo test -p qbind-node --lib d7a3_ticket_issuer_and_exhaustion` ⇒ **10
  passed**, 0 failed, 1573 filtered out (exit 0) — the owner ticket-issuer /
  exhaustion unit coverage that case I builds on, unchanged.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` ⇒ **4 passed**,
  0 failed (exit 0).
* `cargo check -p qbind-node` ⇒ Finished, exit 0.
* `cargo clippy -p qbind-node --lib` ⇒ Finished, exit 0 (85 pre-existing
  warnings, none in the new `run422_d7b3` code).
* CRLF-aware whitespace check on the changed source file
  (`crates/qbind-node/src/binary_consensus_loop.rs`): file remains uniformly
  CRLF (19120/19120 lines CR-terminated, no lone CR, no mixed endings) and the
  added test lines carry the same CRLF convention; no trailing-whitespace
  introduced. Original line endings preserved.

**Prior 9-test D7-B3 pass (preserved as recorded).** The earlier D7-B3 pass
reported `cargo test -p qbind-node --lib run422_d7b3` ⇒ **9 passed** (and the
associated run422 ⇒ 115, binary_consensus_loop ⇒ 209 counts). Those counts are
retained as historical results at their originally reported revision and are
**superseded** by the re-executed 11/117/211 counts above; they are not
relabelled as newly executed.

Because only tests + documentation changed, earlier release-build evidence is
retained at its original recorded revision and NOT re-captured
(`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`).

### Security-tool outcomes (task §6)
Both tools were attempted for this corrective continuation and neither produced a
completed scan/review:
* **CodeQL** — SKIPPED under the per-tool trivial-change declaration
  (test-and-documentation-only change; no production code path altered). A skip
  is **not** a passing scan; status remains **SKIPPED/INCOMPLETE**.
* **Code review** — the reviewer backend was **UNAVAILABLE** in this environment
  (the `autofind` binary was not found on any searched path), so it returned "no
  comments" without executing. This is recorded as **UNAVAILABLE/UNVERIFIED** and
  is **not** treated as a completed clean review.

### Verdict — scoped strictly to the restore-deferral / re-delivery boundary
The positive result names ONLY the demonstrated boundary: at the inbound
restore-catchup deferral path, deferral discards the decoded Proposal and a
re-delivered Proposal receives fresh F6 + current-authorization admission +
cryptographic verification (never a reused verdict). Duplicate-processing safety,
persistent freshness, durable anti-rollback, later socket delivery, upstream
engine/leader effects, and production lifecycle are **not** claimed.

```
D7B3_RESTORE_DEFERRAL_DISPOSITION=DISCARD-AND-AWAIT-RETRANSMISSION
D7B3_REDELIVERY_FRESH_AUTHORIZATION=CLOSED-CODE-TEST (scoped positive; inbound restore-deferral boundary only)
D7B3_SEQUENTIAL_PROGRESS_RETRANSMISSION=CLOSED-CODE-TEST (case H; identical message re-delivered after fixture-driven receiver progress; delivery ≠ engine/QC success)
D7B3_TERMINAL_EXHAUSTION_RETRANSMISSION=CLOSED-CODE-TEST (case I; cfg(test) checked-overflow exhausted latch; admission-time exhaustion counter)
D7B3_VOTE_RESTORE_DEFERRAL=NONE (no analogous path; not invented)
D7B3_DUPLICATE_PROCESSING_SAFETY=NOT-CLAIMED
D7B3_LATER_SOCKET_DELIVERY=NOT-CLAIMED
D7B3_UPSTREAM_ENGINE_LEADER_RECONFIG_EFFECTS=NOT-CLAIMED
D7A_INBOUND_VERDICT=PARTIAL
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```
## Run 422 D7-C1 — read-only consensus-storage observations and recovery evidence

This section is additive. It records a **bounded, read-only observation
boundary** over the existing consensus storage and the real-storage / recovery
evidence for it. It introduces no production activation, no authorization owner,
no genesis-authority activation, and no durable anti-rollback claim. A readable
persisted epoch is **storage evidence only** and is explicitly **not** proof of
current Proposal/Vote authority.

### Actual branch / SHAs (task §1, §7)
* **Actual working branch:** `copilot/copilotcopilotrestore-deferral-disposition-fresh-a`
  (the environment's supplied branch). The task message's stated branch
  `copilot/copilotrestore-deferral-disposition-fresh-authoriz` differs from this
  checkout's actual branch name; reported here without renaming and without
  manufacturing ancestry.
* **Starting HEAD (this phase):** `909e245079bd93bc9212755fce79a6c7c5cd880a`.
* **Tested SHA (implementation checkpoint):** `52a6b72f55b6583c3fcd156d6411293ffaf449e2`
  (the commit that adds `crates/qbind-node/src/consensus_storage_observation.rs`
  and `crates/qbind-node/tests/run_422_d7c1_storage_observation_tests.rs`).
* **Final SHA:** the tip recorded by the commit carrying this evidence section.
* **Shallow-checkout limitation:** `git rev-parse --is-shallow-repository` ⇒
  `true`; `.git/shallow` boundary is `4c7e86d107e7c0677d18c6c6f13eb1b70a29d818`.
  The task's stated final revision `1a75d30a35e02e99a31762afbe66444b546e290a`, the
  reviewed B3 tested implementation `e79e267c2d1a74afdfcf14cb98a72f3cddc5a6bd`, the
  earlier baseline `bb767166a705e3f217bfb6d8791feb3fce05fd76`, and the evidence
  revision `62407fe53745647b9113cf28135d85ff4bf0ee35` are pre-clone ancestry and
  are **not present as local objects** here (`git cat-file -t` ⇒ "could not get
  object info"); recorded as supplied, no ancestry fabricated.

### Source map (task §3)
Interfaces inspected and reused (read-only helpers marked ✓ read-only):

| Symbol | File | Role established from source |
| --- | --- | --- |
| `ConsensusStorage::get_current_epoch` | `crates/qbind-node/src/storage.rs:200,936` | ✓ read-only. Returns `Result<Option<u64>>`; `None` (no key) is distinct from `Some(0)`; decode uses `unwrap_checksummed_meta` (strict), so malformed/short/bad-checksum epoch → `Codec`/`Corruption`, **never** `None`. |
| `ensure_compatible_schema` | `crates/qbind-node/src/storage.rs:1414` | ✓ read-only. Missing schema key ⇒ legacy-v0 compatible; `v ≤ 1` compatible; `v > 1` ⇒ `IncompatibleSchema`. No upgrade/rewrite. |
| `ConsensusStorage::get_schema_version` | `crates/qbind-node/src/storage.rs:225,978` | ✓ read-only. Wrong length ⇒ `Codec`. |
| `ConsensusStorage::check_for_incomplete_epoch_transition` | `crates/qbind-node/src/storage.rs:277,1087` | ✓ read-only (a `get`, no delete). Marker present ⇒ `Some(marker)`; undecodable marker ⇒ `Corruption`. |
| `ConsensusStorage::verify_epoch_consistency_on_startup` | `crates/qbind-node/src/storage.rs:285,1117` | ✓ read-only. Composes the marker check into `IncompleteEpochTransition`. |
| `RocksDbConsensusStorage::open` | `crates/qbind-node/src/storage.rs:682` | **Writes**: `create_if_missing(true)` — can create a database. Opening/initializing is **not** the reader's job; the reader never calls it. |
| `put_*` / `apply_epoch_transition_atomic` / `write_epoch_transition_marker` / `clear_epoch_transition_marker` | `storage.rs:912,997,1065,1174` | **Write/mutation** paths; the reader calls **none** of them. |
| `ConsensusStorageState`, `OpenedProductionConsensusStorage`, `open_production_consensus_storage`, `persist_restored_snapshot_epoch` | `crates/qbind-node/src/production_consensus_storage.rs:89,302,391,504` | `OpenedProductionConsensusStorage.state` is a **startup observation**, not a continuously refreshed value; `persist_restored_snapshot_epoch` is the restore-**write** API used only for test fixtures. |
| `LocalAuthorizationState`, `CurrentAuthorizationOwner`, `authorize_current_state` | `crates/qbind-node/src/genesis_consensus_authority.rs:685,1069,871` | Authorization surface. The C1 observation is **deliberately not convertible** into any of these; production owner construction remains unavailable-only. |

Storage binds an epoch value, a schema version, and an in-progress transition
marker. It does **not** bind chain/genesis identity, validator membership, keys,
suite, signing domain, authority commitment, or activation authorization. The
several reads (schema, marker, epoch) have **no atomicity guarantee** across
calls.

### Implementation (task §4)
New module `crates/qbind-node/src/consensus_storage_observation.rs` (exported from
`lib.rs`), sole entry point:

```
observe_consensus_storage<S: ConsensusStorage + ?Sized>(handle: Option<&S>)
    -> Result<ConsensusStorageObservation, ConsensusStorageObservationError>
```

* Consumes an **existing optional** storage reference; never opens or creates
  storage.
* Reads the actual storage on **every** invocation (no cached startup summary).
* Reuses the existing decoders/validation (`ensure_compatible_schema`,
  `check_for_incomplete_epoch_transition`, `get_current_epoch`) — **no parallel
  epoch parser**, legacy compatibility unchanged.
* Calls **no** `put`/`delete`/`clear`/apply-transition/restore-write method.
* Returns the observed epoch only as `ConsensusStorageObservation` (evidence);
  there is **no** conversion to `LocalAuthorizationState::Established`,
  `CurrentAuthorizationOwner`, `AuthorizedProposalVoteSnapshot`, or any ticket.

### Observation / error matrix
| Input state | Result |
| --- | --- |
| `None` handle | `ConsensusStorageObservation::NoStorageHandle` (nothing opened/created) |
| Storage present, no epoch key | `PresentNoCommittedEpoch` (never `Some(0)`) |
| Explicit epoch `n` (incl. `0`) | `CommittedEpoch(n)` (evidence only) |
| Schema `> 1` | `Err(IncompatibleSchema{stored,current})` |
| Malformed schema / epoch / marker bytes | `Err(MalformedMetadata{surface,source})` — never "no epoch" |
| Incomplete-transition marker present | `Err(IncompleteEpochTransition{target,previous})`; marker not cleared, epoch unchanged |
| Injected I/O read failure | `Err(ReadFailed{surface,source})` — never "no epoch" |

### Tests (task §5) — `run_422_d7c1_storage_observation_tests` (20) + module units (5)
Real-storage vs injected attribution:

| Case | Test(s) | Backing |
| --- | --- | --- |
| A No handle | `d7c1_a_*` | logic (asserts no dir/db created) |
| B Present-no-epoch (+reopen) | `d7c1_b_*` | **real RocksDB** temp db |
| C Explicit epoch 0 (+reopen) | `d7c1_c_*` | **real RocksDB** temp db |
| D Later epoch vs stale startup summary (+reopen control) | `d7c1_d_*` | **real RocksDB** via `open_production_consensus_storage` |
| E Schema supported/legacy/unsupported/malformed | `d7c1_e_*` (3) | **real RocksDB** (malformed via raw key overwrite of a closed db) |
| F Malformed epoch encoding / corrupted checksum | `d7c1_f_*` (2) | **real RocksDB** (raw key overwrite) |
| G Marker present / malformed marker | `d7c1_g_*` (2) | **real RocksDB** |
| H Read failure | `d7c1_h_*` (2) | **INJECTED** `FaultInjectingStorage` (labelled; not a real disk failure) |
| I Snapshot-epoch parity None/0/idempotent/conflict | `d7c1_i_*` (4) | **real RocksDB** via `persist_restored_snapshot_epoch` (restore writes separate from the read-only observation) |
| Read-only guarantee | `d7c1_reader_performs_no_writes_*` (3) | `WriteCountingStorage` write-call instrumentation (0 writes across present/committed/marker cases) |

Read-only assertions compare **logical** stored values / marker state and use
write-call instrumentation; no reliance on physical RocksDB file timestamps or
compaction output. All database fixtures are temporary (`tempfile::TempDir`);
no live data directory is touched.

### Read-only guarantees & synchronization assumption (task §4, §6)
* **Read-only:** the reader invokes only `get_schema_version` (via
  `ensure_compatible_schema`), `check_for_incomplete_epoch_transition`, and
  `get_current_epoch`. Instrumentation confirms zero write/mutation calls.
* **Synchronization assumption:** the multiple reads are **not** an atomic
  snapshot. The observation is meaningful only while relevant writers are
  serialized or quiescent (e.g. startup probe / exclusive-lock holder). No claim
  of atomic snapshot, concurrent consistency, or freshness-through-later-effect
  is made; no concurrency redesign is introduced. Case D is a **serialized**
  test and is **not** described as concurrent-invalidation protection.

### Trust limits — missing authority bindings (task §6)
The evidence establishes only what the supplied local database reports under the
stated read model. It does **not** establish that: the database belongs to the
expected chain/genesis; its epoch is bound to the candidate's membership, keys,
suite, signing domain, or activation authorization; an old-but-valid database was
not restored; a whole-data-dir clone/rollback/replacement is detectable; a
startup observation stays current while consensus runs; or that checksums
authenticate storage against an adversary. Persisted epoch zero does **not** close
D7. A current-authorization lifecycle still requires additional validated bindings
and a defined rollback trust model, not manufactured here.

### Validation (task §7)
Environment: profile `test`/`dev` and `release`; package `qbind-node`; default
features unless noted; run sequentially; disk `df` monitored (≈ 44%→52% used,
never exhausted). Tested SHA `52a6b72f55b6583c3fcd156d6411293ffaf449e2`.

* `cargo test -p qbind-node --lib consensus_storage_observation` ⇒ **5 passed**,
  0 failed, 1583 filtered out (exit 0). *(strict subset of the full `--lib` run.)*
* `cargo test -p qbind-node --test run_422_d7c1_storage_observation_tests -- --test-threads=1`
  ⇒ **20 passed**, 0 failed (exit 0).
* `cargo test -p qbind-node --test run_093_production_consensus_storage_lifecycle_tests` ⇒ **12 passed** (exit 0).
* `cargo test -p qbind-node --test run_097_snapshot_epoch_parity_tests` ⇒ **7 passed** (exit 0).
* `cargo test -p qbind-node --test epoch_persistence_tests` ⇒ **13 passed** (exit 0).
* `cargo test -p qbind-node --test storage_corruption_tests` ⇒ **14 passed** (exit 0).
* `cargo test -p qbind-node --features test-utils --test m16_epoch_transition_hardening_tests` ⇒ **14 passed** (exit 0).
  **Feature selection recorded:** this target requires the `test-utils` feature
  (it calls the cfg-gated `set_inject_write_failure` / `clear_epoch_transition_marker`);
  this is a **pre-existing** requirement of the target, unrelated to D7-C1. The
  normal production build was checked separately (below).
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` ⇒ **4 passed** (exit 0) — genesis startup refusal preserved.
* `cargo test -p qbind-node --lib` ⇒ **1588 passed**, 0 failed, 0 ignored (exit 0)
  — full binary_consensus_loop library tests incl. A/B1/B2/B3 modules preserved
  (previously 1583; the +5 are the new observation unit tests). *(superset of the
  `consensus_storage_observation` run.)*
* `cargo check -p qbind-node` (default features, production build) ⇒ Finished, exit 0.
* `cargo clippy -p qbind-node --lib --test run_422_d7c1_storage_observation_tests`
  ⇒ Finished, exit 0; **no** warnings in the new module or test target (85
  pre-existing lib warnings unrelated to D7-C1 remain).
* `cargo build --release -p qbind-node --bin qbind-node` ⇒ Finished (release
  profile), exit 0.
* **CRLF-aware whitespace:** the two new files
  (`consensus_storage_observation.rs`, `run_422_d7c1_storage_observation_tests.rs`)
  and `lib.rs` are uniformly **LF** (0 CR bytes), matching the crate's existing
  Rust-source convention; no trailing whitespace introduced. Each edited file's
  existing line-ending convention preserved.
* **Secret/privacy scan:** secret scan over the changed files ⇒ no secrets
  detected. No credentials/tokens introduced.

### Security-tool outcomes (task §7)
Both tools were attempted for this phase and neither produced a completed
scan/review:
* **CodeQL** — attempted via the parallel validation path (per-tool triviality:
  **non-trivial**, new production module). It returned **SKIPPED** with reason
  "database size is too large" (0 alerts reported). A database-size skip is
  **not** a passing/clean scan; status is **SKIPPED/INCOMPLETE**.
* **Code review** — the reviewer backend was **UNAVAILABLE** in this environment
  (the `autofind` binary was not found on any searched path), so it returned "no
  comments" without executing. Recorded as **UNAVAILABLE/UNVERIFIED**; **not** a
  completed clean review.

### Verdict (task §8) — scoped strictly to the read-only storage-observation boundary
The positive result names ONLY the demonstrated boundary: a read-only observation
that distinguishes absent handle, present-no-committed-epoch, explicit epoch
(including 0), incompatible schema, malformed metadata/corruption, incomplete
epoch transition, and injected read failure — over real temporary RocksDB
databases (plus one labelled injected I/O case) — while performing no writes and
converting to no authorization. Chain/genesis binding, membership/key/suite/
signing-domain binding, restore-of-old-db detection, whole-dir rollback
detection, cross-run freshness, and adversarial authentication are **not**
claimed.

```
D7C1_STORAGE_OBSERVATION=CODE-TEST-POSITIVE
PERSISTED_EPOCH_IS_AUTHORIZATION=FALSE
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

### Remaining steps before storage evidence could support current authorization
1. Bind the observed epoch to the expected chain/genesis identity and to the
   candidate's validator membership, keys, suite, and signing domain.
2. Bind it to an activation-authorization commitment (not an engine default, CLI
   value, or `config_identity()`).
3. Define and implement a durable anti-rollback / restore-of-old-db trust model
   (detecting whole-data-dir clone/rollback/replacement).
4. Establish a freshness model that remains valid while consensus runs (the C1
   observation is a serialized/quiescent snapshot only).
5. Capture configured-authority release-binary adversarial evidence (Run 423+),
   which remains `NOT-YET-CAPTURED`. No readiness item moves Green.

### D7-C1 correction — storage-reported incomplete transition (RUN 422 D7-C1 metadata fix)

This subsection is additive and corrects one defect in `classify_read_error`
introduced with the module above. Historical results at their original revisions
are preserved unchanged; only the items below are updated.

**Defect.** In `crates/qbind-node/src/consensus_storage_observation.rs`,
`classify_read_error` mapped a direct
`StorageError::IncompleteEpochTransition { epoch, .. }` to
`ConsensusStorageObservationError::IncompleteEpochTransition { target_epoch: epoch,
previous_epoch: epoch }`. The source error establishes only its own reported
`epoch` and `details`; it does **not** establish a previous/target transition
pair. Reporting both fields as the same value **fabricated** transition metadata.
The `Ok(Some(marker))` path (which has genuine `previous_epoch` / `target_epoch`
fields) was and remains correct.

**Correction.** A distinct bounded variant
`ConsensusStorageObservationError::StorageReportedIncompleteEpochTransition {
surface: &'static str, source: StorageError }` was added. The direct-error
fallback now maps to it, preserving the failing read surface and the original
`StorageError` verbatim (its reported epoch and details). No previous epoch is
inferred; the reported epoch is not treated as a proven target; the details
string is not parsed into authority metadata; no replacement values are
manufactured. `Display` renders the surface and the wrapped error and does **not**
emit any `previous=` / `target=` claim. The marker-derived
`IncompleteEpochTransition { target, previous }` variant, its `Display`, and its
behavior are unchanged. Both paths remain errors and neither produces
`NoStorageHandle`, `PresentNoCommittedEpoch`, `CommittedEpoch`, or any
authorization capability.

**Observation / error matrix (added row).**

| Input state | Result |
| --- | --- |
| A consulted read returns `StorageError::IncompleteEpochTransition` directly | `Err(StorageReportedIncompleteEpochTransition{surface,source})` — original epoch/details preserved, **no** fabricated previous/target pair |

**Regression coverage (case J, added to `run_422_d7c1_storage_observation_tests`).**
An explicitly-labelled injected backend (`StorageReportedIncompleteBackend`)
returns a direct `StorageError::IncompleteEpochTransition { epoch: 9, details:
"backend reported incomplete transition; no previous epoch recorded" }` from each
consulted read, with per-read call counters. The error supplies **no** previous
epoch, so the original fabrication (`previous_epoch == target_epoch == 9`) would
be detected. Injected-backend evidence is kept distinct from the real RocksDB
evidence (case G).

| Test | Failing read | Surface asserted | No-continuation assertion |
| --- | --- | --- | --- |
| `d7c1_j_storage_reported_incomplete_from_schema_read` | `get_schema_version` | `schema version` | marker/epoch reads = 0 |
| `d7c1_j_storage_reported_incomplete_from_marker_read` | `check_for_incomplete_epoch_transition` | `epoch transition marker` | epoch reads = 0 |
| `d7c1_j_storage_reported_incomplete_from_epoch_read` | `get_current_epoch` | `current epoch` | schema=1, marker=1, epoch=1 |

Each case asserts: the distinct `StorageReportedIncompleteEpochTransition`
category (and explicitly **not** the marker-derived `IncompleteEpochTransition`
variant); the correct failing surface; preservation of the original epoch (`9`)
and details; that neither the `Display` diagnostic nor the `Debug` metadata
exposes a fabricated `previous=`/`target=` (or `previous_epoch`/`target_epoch`)
pair; no continuation to subsequent reads after the failure; and no write /
mutation call (the backend panics on any write). The real RocksDB marker test
`d7c1_g_incomplete_transition_marker_rejected_without_mutation` is retained
unchanged and still proves that a genuine `previous=6, target=7` marker reports
those exact values, leaves the marker intact, and leaves the stored epoch (`6`)
unchanged.

**Validation (this correction).** Tested SHA
`3b573bd945c44f8f615298076b73966d8fcea339`; package `qbind-node`; default
features unless noted; `test`/`dev` and `release` profiles; run sequentially.

* `cargo test -p qbind-node --lib consensus_storage_observation` ⇒ **5 passed**,
  0 failed, 1583 filtered out (exit 0).
* `cargo test -p qbind-node --test run_422_d7c1_storage_observation_tests --
  --test-threads=1` ⇒ **23 passed**, 0 failed (exit 0) — previously 20; the +3
  are case J.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` ⇒ **4 passed**
  (exit 0) — genesis startup refusal preserved.
* `cargo check -p qbind-node` (default features, production build) ⇒ Finished,
  exit 0.
* `cargo clippy -p qbind-node --lib --test run_422_d7c1_storage_observation_tests`
  ⇒ Finished, exit 0; **no** warnings in the changed module or test target
  (pre-existing lib warnings unrelated to this correction remain).
* `cargo build --release -p qbind-node --bin qbind-node` ⇒ Finished (release
  profile), exit 0. A release build is compilation evidence only, **not**
  configured-authority runtime evidence.
* **CRLF-aware whitespace:** `consensus_storage_observation.rs` and
  `run_422_d7c1_storage_observation_tests.rs` retain their existing **CRLF**
  line endings; the added lines match that convention and introduce no genuine
  trailing whitespace.
* **Secret scan:** the two changed source files were scanned ⇒ no secrets
  detected.

**Security-tool outcomes (this correction).** This change edits production-source
error handling and is **not** docs-only; it is therefore declared non-trivial for
CodeQL. Both tools were attempted via the parallel-validation path:
* **CodeQL** (rust) returned **SKIPPED** with reason "database size is too large"
  (0 alerts). A database-size skip is **not** a clean/passing scan; status is
  **SKIPPED/INCOMPLETE**.
* **Code review** reported "no review comments" but the reviewer backend was
  **UNAVAILABLE** in this environment (the `autofind` binary was not found on any
  searched path). Recorded as **UNAVAILABLE/UNVERIFIED**, not a completed clean
  review.

**Trust limits.** Unchanged from the D7-C1 section above. This correction only
removes a fabricated previous/target pair from one error path; it establishes no
new authority binding, no durable anti-rollback, and no conversion of observation
into authorization. Persisted epoch remains authorization-FALSE.

Status flags retained (unchanged):

```
D7C1_STORAGE_OBSERVATION=CODE-TEST-POSITIVE
PERSISTED_EPOCH_IS_AUTHORIZATION=FALSE
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

## Run 422 D7-C2 — independently pinned genesis / authority-record correspondence (test + evidence)

This section is additive and strictly scoped to a new, read-only, **non-authorizing**
correspondence boundary. It preserves all historical evidence above unchanged and
introduces no protocol migration, no replacement commitment, and no change to any
production authority wiring, storage schema, startup refusal, or D6 signing bytes.

### Actual branch / SHAs (task §1, §7)

* **Actual branch (environment-supplied):** `copilot/olivexo28fix-incomplete-transition-error-metadata`.
  The task message named the review branch `copilot/fix-incomplete-transition-error-metadata`;
  the branch actually checked out in this environment is the one above and is
  reported verbatim rather than renamed.
* **Starting HEAD (this environment):** `78af0f21cdd893c7f41deb36be0adca8c2e5de1b`.
* **Implementation checkpoint (tested SHA, recorded before validation):**
  `0ddd2b5b90b54df4771164145c1bb776f612734c`.
* **Availability of the reviewed SHAs:** the clone is a shallow, single-branch clone
  with two reachable commits (`78af0f2`, `9f37fbd`). The reviewed final revision
  `a12b33990ffb52196f1e89f87224dd962344cb0f` and the reviewed C1 checkpoint
  `3b573bd945c44f8f615298076b73966d8fcea339` are **not present** as objects in this
  clone (`git cat-file -t` fails for both). No ancestry to them is manufactured; the
  work is layered on the actual environment HEAD above.
* Normal task-branch commits only; no PR, amend, rebase, force-push, or history
  rewrite. `task/warning.txt` and unrelated task files are untouched.

### Trust model (stated explicitly)

The new module implements a bounded comparison between (a) an **independently
pinned, validated** genesis-derived expected identity, (b) a **separately
supplied, explicitly untrusted** authority-record description, and (c) a D7-C1
storage observation. A successful result establishes correspondence of the
fields actually compared **only**. It does **not** authenticate a persisted
authority record, prove the record and the epoch came from the same database,
establish current authority, or prevent rollback. A matching record plus
`CommittedEpoch(0)` never becomes `LocalAuthorizationState::Established`, a
`CurrentAuthorizationOwner`, an `AuthorizedProposalVoteSnapshot`, an
`AuthorizationTicket`, or a signing capability. The result type exposes no
conversion into any of those.

### Source investigation (task §3)

| Source | Role in D7-C2 |
| --- | --- |
| `consensus_storage_observation.rs` (`observe_consensus_storage`, `ConsensusStorageObservation`, `ConsensusStorageObservationError`) | The C1 observation consumed as the third input. Its `NoStorageHandle` / `PresentNoCommittedEpoch` / `CommittedEpoch(e)` / error results are each mapped to a **distinct** outcome; never coerced to zero or to success. |
| `genesis_consensus_authority.rs` (`build_genesis_consensus_authority`, `GenesisConsensusAuthority` public fields, `MAX_GENESIS_CONSENSUS_VALIDATORS`, `GENESIS_STATIC_AUTHORITY_EPOCH`, `compute_authority_commitment`) | Reused to derive the expected membership, per-validator `(suite, pk)` provider, chain id, canonical hash binding, authority commitment, and founding epoch from the validated snapshot. The public fields are read only *after* the checked build; the type name alone is never treated as evidence. |
| `pqc_boot_genesis.rs` (`load_external_genesis`) + `qbind_ledger::verify_boot_time_genesis` | The single owned read + boot-time validation + canonical hashing used by the checked expected-identity constructor, run **against the required pin**. `compute_print_genesis_hash` (which reopens the file without authority validation) is deliberately not used. |
| `production_consensus_storage.rs` / `storage.rs` (`RocksDbConsensusStorage`, `ConsensusStorage`, `put_current_epoch`, `EpochTransitionMarker`, `StorageError`) | Used only in tests to create **real temporary RocksDB** observations; no production reader/writer is added. |
| existing D6 signing-domain (`ProposalVoteSigningDomainV2` in `binary_consensus_loop.rs`) | Preserved unchanged. D7-C2 introduces no replacement commitment and no signing-domain change. |

### Field-by-field source attribution (task §2, §4, §5)

| Field | Independently established by pinned genesis validation | Merely claimed by the untrusted record | Observed from storage (C1) | Unavailable in the current production path |
| --- | :---: | :---: | :---: | :---: |
| chain id label | ✔ (expected) | ✔ (claimed) | | |
| canonical genesis hash | ✔ (against the required pin) | ✔ (claimed) | | |
| authority commitment | ✔ (derived) | ✔ (claimed) | | |
| validator membership / genesis index | ✔ (derived) | ✔ (claimed) | | |
| per-validator suite / complete key bytes / voting power | ✔ (derived; equal power) | ✔ (claimed) | | |
| founding epoch (0) | ✔ (constant) | ✔ (claimed epoch) | | |
| committed epoch | | | ✔ (evidence only) | |
| wire-domain (`authorized_wire_chain_id`) mapping | | | | ✔ (production `None`) |
| activation authorization / current freshness | | | | ✔ |

The record's own commitment is **never** trusted as a substitute for comparing
the full membership contents: case D alters a validator while leaving the claimed
commitment unchanged and is still rejected by the per-member comparison.

### Implementation (task §4, §5, §7)

New module `crates/qbind-node/src/genesis_authority_record_correspondence.rs`
(exported from `lib.rs`); new focused test target
`crates/qbind-node/tests/run_422_d7c2_genesis_record_correspondence_tests.rs`.
No shared-helper extraction was required — the existing `load_external_genesis`
+ `verify_boot_time_genesis` + `build_genesis_consensus_authority` trio already
provides a single-read, single-snapshot construction.

* `ExpectedGenesisIdentity` — immutable, **private** field (`authority:
  GenesisConsensusAuthority`), no unchecked public constructor or setter. The only
  constructor `load_pinned(genesis_path, env_policy, expected_genesis_hash)`:
  requires the pin; reads the genesis file **once** into an owned snapshot; runs
  the existing boot-time validation + canonical hashing against the pin
  (`verify_boot_time_genesis(_, _, Some(pin))`, fail-closed on mismatch); derives
  membership + key material from that **same** snapshot; copies immutable values in.
  The pin is never sourced from the record and never silently calculated-and-accepted
  from the file. Accessors expose chain id, genesis hash, commitment, count, and
  founding epoch only.
* `ClaimedAuthorityRecord` / `ClaimedValidatorRecord` — an explicitly untrusted,
  bounded, **in-memory** description. No new database key, storage schema, file
  format, CLI argument, or production reader/writer.
* `check_genesis_record_correspondence(expected, Option<&record>, storage_result)`
  compares, in coarse-to-fine order: record presence → chain label → canonical
  genesis identity → authority commitment → membership count + hard bound →
  per-validator (canonical index / ML-DSA-44 key size / supported suite / duplicate
  key / expected suite / complete key bytes / equal voting power) → claimed epoch vs
  founding epoch → C1 observation (error / absent handle / absent epoch stay
  explicit) → claimed epoch vs C1 observed committed epoch. Deterministic member
  ordering is enforced by requiring each declared index to equal its canonical
  position; malformed / duplicate / missing / extra entries and unsupported suites
  are rejected without silent repair.
* `GenesisRecordCorrespondence` — the correspondence-only success value. It is
  structurally separate from every authorization API and always reports
  `storage_record_coorigin_established() == false`,
  `activation_authorization_established() == false`, and
  `current_authorization_available() == false`.

Missing record, absent storage handle, absent committed epoch, epoch mismatches,
non-founding epoch, and every C1 observation error remain **distinct explicit**
outcomes. A missing epoch is never turned into zero. C1 errors are propagated
verbatim (preserving the corrected D7-C1 storage-reported / marker-derived
distinction); no transition metadata is fabricated.

### Behavioral tests (task §6) — `run_422_d7c2_genesis_record_correspondence_tests` (23) + module units (2)

Real genesis loader/validator with temporary genesis files and valid ML-DSA-44
public keys from `qbind_crypto::ml_dsa44::MlDsa44Backend`; C1 exercised against
**real temporary RocksDB** databases wherever a database observation is claimed.
**The authority records in these tests are supplied in-memory fixtures, NOT
records read from RocksDB.**

| Case | Tests |
| --- | --- |
| A. Matching pinned genesis + coherent record + explicit persisted epoch 0 → correspondence succeeds, no authorization capability, no writes | `d7c2_a_matching_record_explicit_epoch_zero_corresponds_without_authorization` |
| B. Wrong pin / replacement genesis contents reject at checked construction | `d7c2_b_wrong_pin_rejects_expected_construction`, `d7c2_b_replacement_genesis_contents_reject_against_frozen_pin` |
| C. Wrong chain label / genesis hash / authority commitment reject independently | `d7c2_c_wrong_chain_label_rejects`, `d7c2_c_wrong_genesis_hash_rejects`, `d7c2_c_wrong_authority_commitment_rejects` |
| D. Same count but changed key / suite / weight reject (claimed commitment left unchanged) | `d7c2_d_changed_validator_key_rejects_despite_unchanged_commitment`, `d7c2_d_changed_validator_suite_rejects`, `d7c2_d_changed_validator_weight_rejects` |
| E. Missing / extra / duplicate / noncanonical membership reject without repair | `d7c2_e_missing_entry_rejects_as_count_mismatch`, `d7c2_e_extra_entry_rejects_as_count_mismatch`, `d7c2_e_duplicate_key_rejects_without_repair`, `d7c2_e_noncanonical_index_rejects_without_repair` |
| F. Missing record; absent handle; db without epoch (never 0); record/storage epoch mismatch; non-founding epoch | `d7c2_f_missing_record_is_explicit`, `d7c2_f_absent_storage_handle_is_explicit`, `d7c2_f_database_without_committed_epoch_never_becomes_zero`, `d7c2_f_record_storage_epoch_mismatch_rejects`, `d7c2_f_non_founding_claimed_epoch_rejects` |
| G. C1 malformed metadata / incomplete transition / read failure stay errors | `d7c2_g_injected_malformed_metadata_stays_error` (injected, labelled), `d7c2_g_injected_read_failure_stays_error` (injected, labelled), `d7c2_g_real_incomplete_transition_marker_stays_error` (real RocksDB marker) |
| H. Record from unrelated genesis B cannot redefine expectations pinned to A (A frozen) | `d7c2_h_unrelated_genesis_b_cannot_redefine_pinned_a` |
| I. Separate / reopened db reporting the same epoch supplies no provenance | `d7c2_i_separate_database_same_epoch_supplies_no_provenance` |

Module units (`#[cfg(test)] mod tests`):
`missing_record_diagnostic_is_bounded_and_self_describing`,
`correspondence_reports_non_authorizing_invariants`. The former checks only the
`MissingRecord` diagnostic's bounded `Display`; missing-record behavior *through
the real checker* is exercised in the integration target
(`d7c2_f_missing_record_is_explicit`). The A/I tests assert no writes and no
activation effect; I asserts a successful database reopen with the same epoch is
not treated as authentication or anti-rollback evidence.

### Validation (task §8) — sequential

Tested SHA `0ddd2b5b90b54df4771164145c1bb776f612734c`; package `qbind-node`;
default features; `test`/`dev` profile unless noted; run sequentially. Disk before
the release build: 77 GiB free on `/`.

* `cargo test -p qbind-node --test run_422_d7c2_genesis_record_correspondence_tests -- --test-threads=1`
  ⇒ **23 passed**, 0 failed (exit 0).
* `cargo test -p qbind-node --lib genesis_authority_record_correspondence -- --test-threads=1`
  ⇒ **2 passed**, 0 failed, 1588 filtered out (exit 0).
* `cargo test -p qbind-node --lib consensus_storage_observation -- --test-threads=1`
  ⇒ **5 passed**, 0 failed, 1585 filtered out (exit 0) — C1 unit tests.
* `cargo test -p qbind-node --test run_422_d7c1_storage_observation_tests -- --test-threads=1`
  ⇒ **23 passed**, 0 failed (exit 0) — full C1 integration target.
* `cargo test -p qbind-node --test run_422_genesis_consensus_authority_tests -- --test-threads=1`
  ⇒ **15 passed**, 0 failed (exit 0).
* `cargo test -p qbind-node --test run_422_d7_authority_lifetime_tests -- --test-threads=1`
  ⇒ **14 passed**, 0 failed (exit 0).
* `cargo test -p qbind-node --test run_422_startup_refusal_tests -- --test-threads=1`
  ⇒ **4 passed**, 0 failed (exit 0) — genesis startup refusal preserved.
* `cargo check -p qbind-node` (default features, production build) ⇒ Finished, exit 0.
* `cargo clippy -p qbind-node --lib --test run_422_d7c2_genesis_record_correspondence_tests`
  ⇒ Finished, exit 0; **no** warnings attributed to the new module or the new test
  target (85 pre-existing lib warnings unrelated to D7-C2 remain).
* `cargo build --release -p qbind-node --bin qbind-node` ⇒ Finished (release
  profile) in 6m 53s, exit 0. A release build is compilation evidence only, **not**
  configured-authority runtime evidence (`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE`
  stays `NOT-YET-CAPTURED`).

Overlapping subsets distinguished: the two lib subsets
(`genesis_authority_record_correspondence` = 2, `consensus_storage_observation` = 5)
are filtered slices of the full `qbind-node` lib **test inventory** (1590 total —
the prior filtered results `2 passed + 1588 filtered` and `5 passed + 1585
filtered` each imply 1590; the earlier "1588 total" sentence was stale). Test
inventory is distinct from execution: the two subset commands above were run, but
the **full** 1590-test library suite was **not** rerun in C2. The D7-C2
integration target (23) is distinct from the D7-C1 integration target (23).

* **CRLF-aware whitespace:** the new module and test file were authored with **CRLF**
  line endings to match the neighboring D7 sources
  (`consensus_storage_observation.rs`, `genesis_consensus_authority.rs`); `lib.rs`
  retains its existing **LF** endings and only added CRLF-free lines. No genuine
  trailing whitespace introduced.
* **Secret scan:** the changed source files were scanned ⇒ no secrets detected.

### Security-tool outcomes (task §8)

This change introduces production-source validation logic and is **not** docs-only;
it is declared non-trivial for CodeQL. Both tools were attempted via the parallel-validation path:
* **CodeQL** (rust) returned **SKIPPED** with reason "Analysis was skipped because the
  database size is too large" (0 alerts). A database-size skip is **not** a
  clean/passing scan; status is **SKIPPED/INCOMPLETE**.
* **Code review** reported "No review comments found" but the reviewer backend was
  **UNAVAILABLE** in this environment (the `autofind` model `claude-sonnet-4.6` was
  not found in the registry). Recorded as **UNAVAILABLE/UNVERIFIED**, not a
  completed clean review.

### Trust limits and remaining dependencies (task §5, §8)

* Storage/record **co-origin is not established**: a matching hash/commitment and a
  successful epoch read do not prove the record and the database share an origin;
  case I demonstrates a separate/reopened database with the same epoch carries no
  chain/genesis provenance by itself.
* **Activation authorization is not established** and **current authorization is
  unavailable**: the production runtime→wire chain-id mapping is `None`, no
  `ProposalVoteAuthority` / `Established` current state is produced, and the result
  is not convertible into any owner, snapshot, ticket, or signing capability.
* No durable anti-rollback is established; a successful RocksDB reopen is not
  authentication or anti-rollback evidence.
* Unchanged: authority commitment, D6 signing bytes, storage schema, restore
  behavior, `CurrentEpochUnavailable`, genesis startup refusal, production owner
  availability. `GENESIS_AUTHORITY_ACTIVATION` stays `DISABLED`.

### Verdict (task §9) — scoped strictly to the correspondence boundary

```
D7C2_GENESIS_RECORD_CORRESPONDENCE=CODE-TEST-POSITIVE
D7C2_STORAGE_RECORD_COORIGIN=NOT-ESTABLISHED
D7C2_ACTIVATION_AUTHORIZATION=NOT-ESTABLISHED
D7C2_CURRENT_AUTHORIZATION=UNAVAILABLE
D7C1_STORAGE_OBSERVATION=CODE-TEST-POSITIVE
PERSISTED_EPOCH_IS_AUTHORIZATION=FALSE
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

### D7-C2 correction — bounded chain-label mismatch error (RUN 422 D7-C2 error-handling fix)

This correction is additive and strictly scoped to the chain-label error path of
`check_genesis_record_correspondence`. It preserves all historical evidence above
and every other comparison (pin, membership/key/suite/weight, epoch, C1-error
propagation, separate-database) unchanged. It changes production-source error
handling and is therefore **not** docs-only.

* **Defect.** `RecordCorrespondenceError::ChainIdMismatch` previously stored the
  complete claimed chain label as a `String`; the checker cloned `record.chain_id`
  into it and `Display` printed it. An oversized untrusted label thus caused an
  extra allocation and an unbounded diagnostic (via `Display` and derived
  `Debug`), contradicting the bounded-error claim. The identity comparison itself
  was already correct and is unchanged in outcome.
* **Bounded representation.** The variant now carries only two `usize` byte
  lengths (`expected_len`, `claimed_len`); the untrusted label is never cloned,
  formatted, hashed, or otherwise copied into the error. The checker rejects a
  length-incompatible claimed label **before** any per-byte comparison (byte
  lengths are compared first, short-circuiting), using the independently
  validated expected label's byte length as the applicable bound; only an
  equal-length label is then compared byte-for-byte, and an ordinary same-length
  mismatch is still rejected (`expected_len == claimed_len`). No full-input
  fingerprint of the claimed label is computed before the length rejection, and
  no truncation/normalization can turn a mismatch into a match. Neither `Display`
  nor derived `Debug` can reproduce an unbounded label. Raw label contents are
  omitted from the error entirely (no excerpt is retained).
* **Tests.** The D7-C2 integration target now has **24** tests (was 23):
  * `d7c2_c_oversized_claimed_label_rejects_with_bounded_diagnostics` — a 1 MiB
    claimed label built before the checker is invoked; asserts rejection, bounded
    `ChainIdMismatch { expected_len, claimed_len = 1 MiB }` metadata, and bounded
    `Display`/`Debug` under explicit ≤ 256-byte limits that never contain the
    label run. (The fixture's own allocation is separate from checker behavior;
    zero allocation is not claimed merely from a short diagnostic — boundedness is
    established from the error representation and the length-first rejection.)
  * `d7c2_c_wrong_chain_label_rejects` — retained as the same-length positive
    mismatch (16-byte claimed vs 16-byte expected), now also asserting the equal
    bounded byte lengths, proving ordinary mismatches still reject.
  * `d7c2_a_matching_record_explicit_epoch_zero_corresponds_without_authorization`
    — retained matching-label positive control (full correspondence checks,
    non-authorizing result, no writes).
  The module unit test was renamed
  `missing_record_diagnostic_is_bounded_and_self_describing`.
* **Tested SHA.** `708d2c30cb0845843cb99d99f5e29175a4355004`.
* **Validation (sequential, package `qbind-node`, default features).**
  * `cargo test -p qbind-node --lib genesis_authority_record_correspondence`
    ⇒ **2 passed**, 0 failed, 1588 filtered out (exit 0). *(Inventory: 1590 total
    library tests; the full suite was not rerun.)*
  * `cargo test -p qbind-node --test run_422_d7c2_genesis_record_correspondence_tests -- --test-threads=1`
    ⇒ **24 passed**, 0 failed (exit 0).
  * `cargo test -p qbind-node --test run_422_d7c1_storage_observation_tests -- --test-threads=1`
    ⇒ **23 passed**, 0 failed (exit 0).
  * `cargo test -p qbind-node --test run_422_startup_refusal_tests`
    ⇒ **4 passed**, 0 failed (exit 0).
  * `cargo check -p qbind-node` ⇒ Finished, exit 0.
  * `cargo clippy -p qbind-node --lib --test run_422_d7c2_genesis_record_correspondence_tests`
    ⇒ Finished, exit 0; no warnings attributed to the corrected module or test.
  * `cargo build --release -p qbind-node --bin qbind-node` ⇒ Finished (release
    profile), exit 0 — compilation evidence only.
  * Genuine trailing whitespace check + secret scan of the changed files ⇒ clean;
    CRLF line endings preserved on the two code files and this document.
* **Documentation corrections in this pass.** (A) The stale "1588 total" library
  inventory sentence was corrected to **1590 total**, distinguishing inventory
  from execution. (B) The `ExpectedGenesisIdentity::load_pinned` doc comments that
  attributed construction to `load_verify_and_build_genesis_authority` were
  corrected to the actual single-read trace `load_external_genesis` →
  `verify_boot_time_genesis(_, _, Some(pin))` → `build_genesis_consensus_authority`
  (the module docs already described this trio; only the source comments were
  stale). (C) The missing-record unit test's nonexistent
  dangling-reference/helper explanation was removed and the test renamed; the unit
  test checks only the `MissingRecord` diagnostic, while missing-record behavior
  through the checker is exercised by `d7c2_f_missing_record_is_explicit`.
  (D) Release-binary evidence is **not** the only outstanding dependency: storage/
  record provenance, activation authorization, production wire-domain mapping,
  durable anti-rollback, and running-consensus freshness all remain unresolved
  (see "Trust limits and remaining dependencies" above).
* **Security-tool outcomes.** Attempted via the parallel-validation path.
  Recorded honestly: a CodeQL database-size skip is **SKIPPED/INCOMPLETE**, not a
  clean pass; an unavailable code-review backend is **UNAVAILABLE/UNVERIFIED**.
* **Scope claim.** This is limited to the corrected chain-label path. It does
  **not** claim a complete allocation/DoS audit of all genesis loaders and error
  types. All retained verdict markers above are unchanged.

---

## Run 422 D7-C3A — dormant standard-network runtime/wire alias mapping (coverage + evidence)

### Actual state (task §1)

* **Actual branch.** `copilot/copilotrun-422-d7-c3a` (the reference name in the
  task, `copilot/run-422-d7-c3a`, differs by the `copilot` path segment; the
  work is on the branch above).
* **Starting HEAD.** `b1643fea29d2a66d929d49ed126e9c1a44f0bdc3` (parent
  `6dd9b7a5d9cdb819427126929b2c10e7bdc9b3e3`, the task baseline).
* **Worktree status at start.** Clean (`git status --porcelain` empty).
* **Reference-object availability.** Baseline `6dd9b7a` is present (it is the
  parent commit). The reviewed implementation SHA
  `899099a3770f686f35b67280b82f68f59e0fde66` is **not available** in this shallow
  single-branch clone (`git cat-file -t 899099a` ⇒ *not a valid object name*);
  the current work is instead carried on `b1643fe` and preserved here.
* **Preservation.** Normal task-branch commits only; no `main` change, no history
  rewrite, no PR opened by this task.

### Preserved implementation (task §2, §7)

* `crates/qbind-types/src/network_wire_alias.rs` is retained. `resolve_network_wire_alias`
  keeps its **full 64-bit** runtime-ID comparison (`supplied_runtime != environment.chain_id()`),
  and the three assigned dormant aliases are unchanged: DevNet `0x44455600`,
  TestNet `0x54535400`, MainNet `0x4D41494E`.
* `NetworkEnvironment::chain_id()` remains the **sole** expected-runtime source;
  no parallel registry or fallback was added.
* No production logic redesign was made; the only source change is an added
  doc-comment on `NetworkWireAlias` clarifying it is a **raw, publicly
  constructible tag, not a validation certificate** (a bare alias does not prove
  the helper was called and grants no authorization). No API was added or removed.
* **No new production callers.** `grep` across `crates/**` finds the helper/alias
  symbols only in the module itself, the `lib.rs` re-export, and the C3A test
  target — confirming the mapping stays dormant.

### Extended test matrix (task §3) — target `run_422_d7c3a_network_wire_alias_tests`

Note: assigned aliases are the low 32 bits of each environment's authoritative
64-bit runtime `ChainId` (high word `0x51424E44`, "QBND").

* **A — full 3×3 environment/runtime matrix** (`matrix_a_full_3x3_environment_runtime_pairs`):
  the three diagonal pairs resolve to the exact assigned alias; all six
  off-diagonal standard pairs reject, each asserting `environment`,
  `expected_runtime` (== `env.chain_id()`) and `supplied_runtime`. **9 cases.**
* **B — boundary/extreme runtime IDs under every environment**
  (`matrix_b_boundary_runtime_ids_reject_under_every_environment`): `ChainId(0)`,
  `ChainId(u32::MAX as u64)`, `ChainId(u64::MAX)`, and the representative
  `0x0000_0000_DEAD_BEEF` already covered elsewhere; each rejected under all three
  environments with exact metadata. **12 cases.**
* **C — high-bit-flip low-word-collision matrix**
  (`matrix_c_high_bit_flips_share_low_word_but_reject`): per network, a zeroed
  high word, an all-ones high word, and every single high-bit flip (bits 32..=63)
  — 34 unsupported full IDs per network. Each asserts (1) the low word matches
  the expected runtime's low word, (2) the full ID differs, (3) resolution
  rejects. Deterministic; no randomness. **102 cases.**
* **D — aliases pairwise distinct**
  (`matrix_d_assigned_aliases_are_pairwise_distinct`): the three assigned aliases
  (and their `as_u32()`) are pairwise unequal. **3 comparisons.**
* **E — extreme supplied values, bounded rendering, exact metadata**
  (`matrix_e_extreme_mismatch_errors_are_bounded_and_preserve_metadata`): under
  each environment, `ChainId(0)`, `ChainId(u64::MAX)`, `ChainId(u32::MAX as u64)`,
  `ChainId(0xFFFF_FFFF_0000_0000)` reject; the error equals the exact
  `NetworkWireAliasMismatch { environment, expected_runtime, supplied_runtime }`;
  `Display` and `Debug` each stay within an explicit **256-byte** bound while
  still naming the environment. **12 cases.**
* **Positive controls retained.** The eight pre-existing functions
  (alias constants + `as_u32`, three matching resolves, the
  `expected_runtime_is_network_environment_chain_id` loop, single mismatch,
  arbitrary-runtime rejection per environment, and the Display-context check) are
  kept unchanged.

**Coverage vs function count (task §3).** The target has **13 test functions**
(8 preserved + 5 new matrix functions). The five new functions exercise
**≈ 138 parametrized cases** (A 9 + B 12 + C 102 + D 3 + E 12); test-case
coverage is therefore reported separately from the function count.

### Validation (task §4) — sequential, checkpoint SHA `fcdc7ca20f78ec9aa9389bcc354c5c8e9292e260`

* `cargo test -p qbind-types` (default features, dev/test profile) ⇒ **all
  passed**, exit 0. C3A target: **13 passed**, 0 failed; other qbind-types
  targets (lib 7, primitives 6, governance 6+2, keyset 3, roles 3, suite 2,
  validator 4) all pass; 2 doc-tests ignored.
* `cargo clippy -p qbind-types --lib --test run_422_d7c3a_network_wire_alias_tests -- -D warnings`
  ⇒ Finished, exit 0; no warnings on the qbind-types library or the C3A target.
* `cargo check -p qbind-node` (**default production features**) ⇒ Finished, exit 0.
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
  ⇒ **34 passed**, 0 failed, exit 0 (D6 isolation preserved).
* Line endings preserved: all four changed files remain **CRLF**; secret scan of
  changed files clean.

### Security-tool and CI reconciliation (task §6)

* **Original "CodeQL 0 alerts" / successful-review claim.** The supporting output
  for the reviewed commit `899099a` **cannot be recovered** in this sandbox: that
  SHA is absent from the shallow clone and no SARIF/scan artifact is committed in
  the tree. Recorded as **UNVERIFIED**; no successful scan or skip reason is
  invented for it.
* **Agent-local CodeQL (this task's changes).** Tool/language: **CodeQL, `rust`**.
  Scope: the agent-local database for the changed revision `fcdc7ca`. Status:
  **SKIPPED / INCOMPLETE** — "Analysis was skipped because the database size is
  too large." The "0 alerts" figure is reported **only inside that skip context**
  and is **not** whole-project coverage.
* **Agent-local code review (this task's changes).** Completed over the 3 changed
  files with **no review comments**; a backend note reported a model-registry
  warning, so treat the review as best-effort rather than exhaustive.
* **GitHub Actions (separate from agent-local tools).** On the pushed checkpoint
  `fcdc7ca`, three release/package workflows show `conclusion=failure` with
  **0 executed jobs** (startup/config-level failure):
  `public-devnet-release-signing-attestation.yml`,
  `public-devnet-package-integrity.yml`, and
  `public-devnet-release-artifact-manifest.yml`. These release/package workflows
  were already failing on the reviewed commit and baseline; this task edits no
  workflow, production, or packaged file, so there is **no evidence** the
  failures were caused by C3A. Recorded as observed pre-existing status.

### Documentation (task §5)

* Mapping + input contract documented in the existing protocol document
  `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md`, new **§9.1**
  ("Dormant standard-network wire alias mapping (Run 422 D7-C3A)"), reusing the
  section-9 runtime-`ChainId` ↔ wire mapping discussion rather than adding a new
  file. The unresolved production mapping in §9 is explicitly left open.
* Source raw-tag distinction added to `network_wire_alias.rs`.
* This C3A evidence section appended here.

### Explicit statements (task §5)

* The wire-alias **assignments are defined but dormant**
  (`STANDARD_WIRE_ALIAS_POLICY=DEFINED-NOT-ACTIVATED`).
* The helper validates **only** the standard environment/runtime/wire
  correspondence; it is not authorization.
* A raw `NetworkWireAlias` value **does not prove the helper was called**.
* **Genesis acceptance, signing custody and current authorization remain
  separate** and unaffected.
* Standard **low words are distinct**, while **general 32-bit narrowing can
  collide** (matrix C exercises the collision-shaped inputs and confirms full-ID
  rejection).
* Changing a wire field value **changes the signed bytes even when the encoding
  layout is unchanged** (consistent with the D6/v2 preimage; C3A adds no
  encoding).
* **Genesis/runtime binding and downstream engine/QC compatibility remain
  unresolved.**

### Boundaries preserved (task §7) and verdict (task §8)

* Unchanged: engine wire-ID construction, message encodings, D6 preimages, golden
  vectors, genesis validation, snapshot binding, authority constructors,
  CLI/configuration, activation guards. Changed files vs baseline: only
  `network_wire_alias.rs` (doc-comment), its `lib.rs` re-export (from prior C3A
  commit), the C3A test target, and the v2 protocol doc.
* Retained markers: `STANDARD_WIRE_ALIAS_POLICY=DEFINED-NOT-ACTIVATED`,
  `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
  `GENESIS_AUTHORITY_ACTIVATION=DISABLED`.
* D7 remains **partial**; durable anti-rollback is **not** established;
  configured-authority release-binary evidence remains **absent**; RS1/C4/C5
  remain **open**; public DevNet remains **NO-GO**. No production integration and
  no Run 423 work performed.

---

## Run 422 D7-C3B — pinned genesis validation bound to the standard network mapping (test + evidence)

### Actual branch / SHAs (task §1, §7)

* **Actual working branch:** `copilot/copilot-run-422-d7-c3b` (single-branch
  shallow clone).
* **Starting revision (this task's HEAD before edits):**
  `c37f059` — already carrying the D7-C1/C2/C3A dormant modules and the retained
  authority snapshot in `ExpectedGenesisIdentity`.
* **Reference checkpoints named in the task** (`fcdc7ca2…` tested checkpoint,
  `f1c3dc4f…` final reference for the reviewed C3A branch
  `copilot/copilotrun-422-d7-c3a`) are **not present** in this shallow clone
  (`git cat-file` reports them missing) and are not ancestors reachable here.
  Ancestry beyond the two local commits (`c37f059`, `b1643fe`) is unavailable;
  content correspondence was used to verify the C2/C3A implementations are
  present, **not** commit ancestry.
* **Changed paths vs the starting revision `c37f059`:**
  * `crates/qbind-node/src/genesis_authority_record_correspondence.rs`
    (retained validation policy + `check_network_correspondence` +
    `GenesisNetworkCorrespondence` + `GenesisNetworkCorrespondenceError`);
  * `crates/qbind-node/tests/run_422_d7c3b_genesis_network_correspondence_tests.rs`
    (new C3B integration target);
  * this evidence doc and
    `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md` §9.2.

### Trust model (stated explicitly, task §2)

The trust source is the caller's independently accepted genesis pin and selected
environment. The code enforces consistency with those inputs; it cannot prove
the operator obtained the correct official pin. A successful correspondence is
**static correspondence only** — not current authority, activation permission,
freshness, storage provenance, rollback resistance, or a signing capability.

### Source investigation / reuse findings (task §3)

Scoped reuse check (not a whole-repository duplication audit) confirmed the
existing interfaces are sufficient; the only gap was that
`ExpectedGenesisIdentity` retained the validated authority snapshot but **not**
the environment policy used to validate it, and there was no operation binding
that identity to the C3A resolver.

* Reused unchanged: `ExpectedGenesisIdentity::load_pinned` (C2 path:
  `load_external_genesis` → `verify_boot_time_genesis(Some(pin))` →
  `build_genesis_consensus_authority`, one owned read),
  `pqc_boot_genesis::map_environment`, `resolve_network_wire_alias` (C3A),
  `NetworkEnvironment::chain_id`.
* **No** new genesis loader, parser, hash implementation, environment conversion
  table, numeric-ID registry, or authority builder was introduced.

### Implementation (task §4)

* **A — retained provenance.** `ExpectedGenesisIdentity` gains a private,
  immutable `validation_policy: NetworkEnvironmentPolicy`, set only by the
  successful `load_pinned` from its `env_policy` argument. `load_pinned`'s
  signature and validation behaviour are unchanged; the single owned genesis
  read is preserved (no reload/reparse). No public unchecked constructor,
  setter, deserialization route, or default exists.
* **B — correspondence operation.**
  `ExpectedGenesisIdentity::check_network_correspondence(selected_environment, supplied_runtime)`
  (1) compares the retained policy to `map_environment(selected_environment)`,
  (2) rejects a mismatch explicitly, (3) calls
  `resolve_network_wire_alias(selected_environment, supplied_runtime)`, and
  (4) returns a private-field, immutable `GenesisNetworkCorrespondence<'_>` that
  **immutably borrows** the same identity only when both checks pass. The alias
  is obtained solely through C3A; no raw wire alias is accepted. Read-only
  accessors expose the environment, runtime ID, alias, retained policy, and the
  underlying validated genesis hash / authority commitment.
* **C — fail-closed errors.** `GenesisNetworkCorrespondenceError` distinguishes
  `ValidationPolicyMismatch { validated_policy, selected_environment,
  selected_policy }` from `RuntimeMismatch(NetworkWireAliasMismatch)` (the reused
  C3A error). `Display`/`Debug` carry only bounded enum + numeric-ID metadata;
  no genesis labels, file contents, paths, or key material are copied or printed.
* **D — trust boundary preserved.** No conversion into
  `LocalAuthorizationState::Established`, `CurrentAuthorizationOwner`,
  `AuthorizedProposalVoteSnapshot`, `AuthorizationTicket`,
  `ProposalVoteSigningDomainV2`, or any signer / verification context.
  `GenesisConsensusAuthority.authorized_wire_chain_id`, snapshot binding, and the
  fixture-label comparison are untouched.

### Behavioral tests (task §5) — `run_422_d7c3b_genesis_network_correspondence_tests` (9 functions)

Uses the real loader, boot validation, canonical hashing, and valid ML-DSA-44
consensus-key fixtures; TestNet/MainNet fixtures carry a full authority block and
environment-token chain labels so their strict validators pass unrelaxed.
Parameterized cases are grouped inside single `#[test]` functions and are not
double-counted.

| Case | Function | Coverage |
| ---- | -------- | -------- |
| A | `d7c3b_a_matching_controls_resolve_exact_alias_attached_to_identity` | DevNet/TestNet/MainNet load pinned, resolve with matching env + full runtime ID, assert exact C3A alias, and verify the result refers to the original validated genesis hash + authority commitment. |
| B | `d7c3b_b_env_provenance_mismatch_rejects_all_six_pairs` | Full 3×3 matrix; all six mismatched pairs reject with typed `ValidationPolicyMismatch` metadata even when the supplied runtime ID is correct for the newly selected environment. |
| C | `d7c3b_c_full_width_runtime_mismatch_rejects_via_c3a` | Matching policy/env; other standard runtime IDs and invalid values (including a different high word with the correct low 32 bits, plus `0` and `u64::MAX`) reject via C3A `RuntimeMismatch` — no truncation/fallback. |
| D | `d7c3b_d_wrong_pin_rejects_construction`, `d7c3b_d_replacement_genesis_rejects_against_frozen_pin`, `d7c3b_d_loaded_identity_survives_source_removal_and_correspondence_needs_no_reread` | Wrong pin rejects construction; replacing A with B while retaining pin A rejects; a loaded identity survives removal of its source file and correspondence succeeds from the retained identity with no reread. |
| E | `d7c3b_e_canonical_hash_pin_is_environment_isolated` | One fixture that validates under **both** DevNet and TestNet (required `"testnet"` chain-id token + full authority block, production validators unrelaxed): its frozen DevNet and TestNet canonical pins differ; each pin loads only under its own environment; and supplying the frozen DevNet pin under TestNet is rejected by the **canonical-hash comparison itself** — the typed `BootGenesisVerificationError::CanonicalHashMismatch { env: Testnet, expected: devnet_pin, actual: testnet_pin }` from `verify_boot_time_genesis`, and the same mismatch through `ExpectedGenesisIdentity::load_pinned`'s existing `GenesisRevalidationFailed` interface. This is a canonical-hash pin isolation, **not** a label-policy rejection. |
| F | `d7c3b_f_two_distinct_genesis_files_each_correspond_under_same_env` | Two distinct genesis files, separately pinned, each correspond under DevNet with the same alias but distinct genesis hashes — the helper chooses no official genesis and asserts no cross-fork uniqueness. |
| G | `d7c3b_g_bounded_diagnostics_for_both_mismatch_variants` | Exact metadata and bounded (≤256-byte) `Display`/`Debug` for both mismatch variants, including a `u64::MAX` runtime ID; no genesis label leaks. |

### Source-inspection vs behavioural measurement (task §5.D)

Case D's behavioural tests measure that the retained identity is *used* after its
source file is replaced or removed — they cannot, by themselves, prove only one
read ever occurred. The single-owned-read guarantee is a **source** property of
`load_pinned` (one `load_external_genesis`, then validation and authority
derivation from that same owned snapshot), which the correspondence operation
never re-enters.

### Validation (task §6) — sequential, tested SHA `2c882e8` (+ uncommitted docs)

All commands from repo root, default profile unless noted; recorded exit code 0:

* `cargo test -p qbind-node --test run_422_d7c3b_genesis_network_correspondence_tests` → `9 passed; 0 failed`.
* `cargo test -p qbind-node --test run_422_d7c2_genesis_record_correspondence_tests` → `24 passed; 0 failed` (C2 unchanged).
* `cargo test -p qbind-node --lib genesis_authority_record_correspondence` → `2 passed; 0 failed`.
* `cargo test -p qbind-types --test run_422_d7c3a_network_wire_alias_tests` → `13 passed; 0 failed`.
* `cargo test -p qbind-node --test run_422_genesis_consensus_authority_tests` → `15 passed; 0 failed`.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` → `4 passed; 0 failed`.
* `cargo check -p qbind-node` → `Finished` (exit 0).
* Focused Clippy: `cargo clippy -p qbind-node --lib` and
  `cargo clippy -p qbind-node --test run_422_d7c3b_genesis_network_correspondence_tests`
  produce **no new warnings** attributable to the changed library or the new
  test; the changed file `genesis_authority_record_correspondence.rs` yields zero
  Clippy diagnostics. All emitted warnings originate from pre-existing, unrelated
  files (`pqc_governance_*`, `snapshot_restore.rs`, `three_node_chaos_net_tests.rs`)
  and are inherited, not introduced. A broad `--tests` gate was avoided.
* `cargo build --release -p qbind-node --bin qbind-node` → compilation evidence
  only (see marker below); it is **not** configured-authority release-binary
  evidence.

**D6 `run_422_d6_pv_domain_isolation_tests` target — correction (task §1).** The
earlier C3B evidence above stated this target was *"not present in this shallow
clone"* and that it *"could not be executed here."* **That statement was wrong:
the earlier search examined the wrong crate** (it looked under
`crates/qbind-node/tests/`). The regression target actually lives under
**`crates/qbind-consensus/tests/run_422_d6_pv_domain_isolation_tests.rs`** and is
present in this checkout. Distinguishing the two facts:

* *Previous omission:* the earlier C3B pass never executed the D6 target (it
  searched the wrong crate and reported absence). That earlier claim is corrected
  here; it is not re-asserted.
* *Newly performed validation (this correction):* executed from the repository
  root against the actual working tree —
  * Command: `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
  * Revision: `02f7f1d` (this task's working HEAD; see the correction subsection
    below for branch/SHA context).
  * Exit code: **0**.
  * Result: **`34 passed; 0 failed; 0 ignored`** (34 test functions).

### Boundaries preserved (task §6)

Diff and caller inspection confirm no startup, engine, handler, cache, signing,
verification, CLI, or storage behaviour was integrated; Required and genesis
startup refusal remain intact (`run_422_startup_refusal_tests` green); engine
wire values, D6 preimages/encodings/golden vectors, and existing authority
boundaries are unchanged. The C3A resolver now has exactly **one** caller — this
dormant library operation — which is not a startup or active-consensus
integration.

### Security-tool outcomes (task §7)

Attempted against the actual revision via `parallel_validation`; outcomes
recorded on their own axis (no readiness item moves Green):

* **Code review:** completed, reviewed 4 files, **no review comments**. The
  environment additionally reported a reviewer model-availability error
  (`claude-sonnet-4.6 not found in registry`), so this is treated as
  *completed-with-tool-degradation*, not an unconditional pass.
* **CodeQL security scan (rust):** **skipped — database size too large.** The
  accompanying "0 alerts" is a **skip, not a passing scan**; no CodeQL coverage
  of this change was obtained here.

### Verdict (task §8) — scoped strictly to the pinned-genesis network-correspondence boundary

```
D7C3B_PINNED_GENESIS_NETWORK_CORRESPONDENCE=CODE-TEST-POSITIVE
GENESIS_NETWORK_CORRESPONDENCE_IS_CURRENT_AUTHORIZATION=FALSE
STANDARD_WIRE_ALIAS_POLICY=DEFINED-NOT-ACTIVATED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

The canonical genesis hash already includes the environment scope; C3B retains
and checks the policy used to validate that hash; the genesis string label is not
a numeric network-ID registry; correspondence does not establish official-pin
authenticity, live authority, or rollback resistance; and engine/QC and
production authority integration remain unresolved. No readiness item moves
Green.

### Run 422 D7-C3B correction — D6 execution + canonical-hash case E (test/doc only)

This subsection records a limited, test-and-documentation-only correction to the
C3B evidence above. It does **not** redesign C3B or change any production
behaviour. Earlier C3B results remain recorded above at their original tested
revision; only the two items below are corrected.

**Actual branch / SHA context (task §1, §4).**

* **Actual working branch:** `copilot/copilot-run-422-d7-c3b-again` (single-branch
  shallow clone). The task text names the *reviewed* branch
  `copilot/copilot-run-422-d7-c3b`; the correction was performed on the
  `-again` working branch noted here.
* **Local commits available:** `02f7f1d` (working HEAD) and `c37f059` only.
  Ancestry beyond these two is unavailable in the shallow clone.
* **Starting revision (before this correction's edits):** `02f7f1d`.
* **`continue-from` reference `d8956c6075dcae51152411c29219223ee43b21b8` and the
  previous tested checkpoint `2c882e869dfb86175e982f9010e0ad2587626235`** named in
  the task are **absent** from this shallow clone (`git cat-file` reports them
  missing) and are not reachable ancestors here. Their absence does not imply the
  source files are missing — the C3B test target, the D6 target, and this evidence
  doc are all present in the working tree.
* **Final revision:** recorded on the completed correction commit for this branch
  (the commit that carries the two changed paths below).

**Correction 1 — D6 regression target executed.** The earlier C3B claim that
`run_422_d6_pv_domain_isolation_tests` was *absent* was wrong because the search
examined the wrong crate (`qbind-node` instead of `qbind-consensus`). The target
exists at `crates/qbind-consensus/tests/run_422_d6_pv_domain_isolation_tests.rs`.
Newly executed here:

* Command: `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
* Revision: `02f7f1d`; exit code **0**; **34 passed; 0 failed; 0 ignored**.

The distinction between the *previously omitted execution* and this *newly
performed validation* is preserved; no replacement test was created and no
historical execution is asserted.

**Correction 2 — case E now demonstrates canonical-hash pin isolation.** The C3B
integration test `d7c3b_e_*` was rewritten (test file + its comments only) as
`d7c3b_e_canonical_hash_pin_is_environment_isolated`. It uses **one** genesis
fixture that satisfies the existing validators under **both** DevNet and TestNet
(required lowercase `"testnet"` chain-id token + full authority block; production
validators unrelaxed). For that same unchanged fixture it:

* computes and freezes the DevNet and TestNet canonical pins and asserts they
  differ;
* loads it successfully under DevNet with the DevNet pin and under TestNet with
  the TestNet pin via `ExpectedGenesisIdentity::load_pinned`;
* calls `verify_boot_time_genesis(Testnet, cfg, Some(devnet_pin))` and asserts the
  typed `BootGenesisVerificationError::CanonicalHashMismatch { env: Testnet,
  expected: devnet_pin, actual: testnet_pin }` (environment + expected/actual
  hashes checked exactly);
* asserts `ExpectedGenesisIdentity::load_pinned(path, Testnet, devnet_pin)` also
  rejects the mismatched pin through its existing `GenesisRevalidationFailed`
  interface (detail carries the canonical-hash mismatch).

The earlier case-E claim (that a scope-differing canonical hash *or* a stricter
validator rejects the cross-policy pin) is superseded: the corrected case proves
the rejection comes from the **canonical-hash comparison itself**, not from a
label-policy rejection. No public error type was changed to make the test
convenient; the other C3B assertions and fail-closed behaviour are retained.

**Focused verification (task §3).** From repo root, exit code 0 unless noted:

* `cargo test -p qbind-node --test run_422_d7c3b_genesis_network_correspondence_tests`
  → **9 passed; 0 failed** (includes the corrected case E).
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
  → **34 passed; 0 failed**.
* `cargo clippy -p qbind-node --test run_422_d7c3b_genesis_network_correspondence_tests`
  → finished with **no warnings attributable to the changed test**; all emitted
  warnings originate from pre-existing, unrelated library files and are inherited,
  not introduced.
* Formatting/whitespace checked on the changed test file only (no package-wide
  `cargo fmt` and no line-ending changes): the file retains its existing CRLF line
  endings, and the correction adds no trailing whitespace, tabs, or lines beyond
  the file's established width.

**Changed paths (this correction).**

* `crates/qbind-node/tests/run_422_d7c3b_genesis_network_correspondence_tests.rs`
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`

**Unchanged posture (task §4).** No production integration, activation, wire, QC,
storage, or historical-archive change. CodeQL SKIPPED/INCOMPLETE and the qualified
review records for earlier D7 passes remain as recorded and are not relabelled as
successful scans. D7 remains **partial**; production authority **unavailable**;
genesis activation **DISABLED**; durable anti-rollback **NOT established**; public
DevNet **NO-GO**.
## Run 422 D7-C3C — Authority / Engine / QC integration audit (documentation only)

This entry records a **bounded source audit and integration-design** pass. It
performed **no production integration, no activation, and no wire/QC/storage
change**. The full analysis lives in
`docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md`; it is not
duplicated here.

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

**Inspected revision (actual).** Branch `copilot/copilotrun-422-d7-c3c` (the task
names the reviewed branch `copilot/run-422-d7-c3c`; the checkout carries the
doubled `copilot` segment), worktree HEAD
`b7a38c6145d947499c0a4be8e2dbd6c87627f63a`, whose parent
`819f2b28ff05fc10f2b0b6c23af52808ac996cad` first added this audit + C3C entry.
The clone is shallow (depth 2); `.git/shallow` now pins the boundary
`819f2b28ff05fc10f2b0b6c23af52808ac996cad`, so its parent —
`0b3eb4a19530f8ecf21b25212f92aa944473e154`, the task's named inspected source
revision — is beyond the graft and **absent**. The task's named reviewed final
revision `9cc94ab7dfacb2824de7aad76abd5573532a9f47` (and the older
`3a5ac02c06eb4a62368f6c922a911946b48b01df` /
`734a9425a15f8a5845b8bf0bdb4932b700d9cc22`) are likewise **absent**, so ancestry
could not be confirmed; content correspondence to the C2/C3A/C3B source is not
claimed as ancestry.

**Correction (this C3C revision).** The first C3C draft is superseded in place;
the audit's §9 records the corrections. Key fixes:

* Preflight is `run_p2p_consensus_security_preflight` (`main.rs:5019`), **not**
  `build_consensus_security_preflight`.
* Engine membership is `build_uniform_validator_set(cfg.num_validators)`
  (`binary_consensus_loop.rs:2308` → `:700`), a uniform power-1 set passed **by
  value** into `BasicHotStuffEngine::new` (`ConsensusValidatorSet`, not `Arc`).
  `build_validator_set_and_key_provider` feeds the **Timeout bridge only**, not
  the engine.
* Boot verification distinguishes the external genesis **file**
  (`--genesis-path`) from the independent **expected-hash pin**
  (`--expect-genesis-hash` / `config.expected_genesis_hash`,
  `pqc_boot_genesis.rs:240`); it can return `SkippedNoExternalGenesis` (`:229`)
  for permitted non-MainNet configs, and DevNet/TestNet may omit the pin
  (canonical-hash compare skipped, `qbind-ledger/src/genesis.rs:1850`/`:1852`) —
  a path alone does not establish independent pinning; only MainNet forces the
  pin (`:1836`).
* `chain_id: 1` message construction is **ordinary engine code, not a test
  fixture**: `basic_hotstuff_engine.rs:1351/1370/1405` are in `on_leader_step`
  and `:1531` is in `on_proposal_event` (both above the `#[cfg(test)]` boundary
  `:1921`); the binary loop's `do_leader_tick` drives them in production. The
  guard is at signing/transmission (fail-closed, no authority), not at
  construction.

**Principal findings (source-anchored, HEAD `b7a38c6` ≡ boundary `819f2b2`).**

* Production wires no Proposal/Vote authority: `main.rs:5549`
  `proposal_vote_authority: None`; inbound/outbound Proposal/Vote run fail-closed
  under `Required`. The handler's two match arms give a precise rejection ladder:
  **no effective verifier** (no snapshot and no `pv_authority`) →
  `inbound_proposal_verification_context_unavailable_total` /
  `inbound_vote_verification_context_unavailable_total` before crypto; **effective
  verifier present but `current_auth` absent** →
  `inbound_proposal_current_state_unavailable_total` /
  `inbound_vote_current_state_unavailable_total` before crypto; **bound snapshot,
  `owner.admit()` rejects** → the applicable admission failure before crypto; and
  only **after** admission and verification succeed can `owner.confirm(ticket)`
  fail with the `authority_stale_before_effect` counter. A missing owner never
  reaches the confirmation check, so it must **not** be described as a post-crypto
  `Stale` rejection. Current production (no authority, no snapshot) rejects on the
  first rung, before cryptographic verification; D6 signature verification is an
  implemented conditional path, not acceptance exercised by current production.
  C3B correspondence (`genesis_authority_record_correspondence.rs` `load_pinned` /
  `check_network_correspondence`) has **test-only callers** and never becomes
  authorization.
* A boot-validated `GenesisConsensusAuthority` exists but is not fed to the
  Proposal/Vote snapshot; it carries `authorized_wire_chain_id: None`
  (`genesis_consensus_authority.rs:439`) and `try_bind`
  (`binary_consensus_loop.rs:1245`) rejects any verifier lacking an authorized
  wire id (`:1295`) — a deliberate closed door.
* Outer Proposal/Vote signatures are verified on the binary path
  (`proposal_vote_verify.rs:405`), but the **embedded QC's constituent signatures
  are not verified** there. The embedded justify QC is converted with `vec![]`
  signers (`basic_hotstuff_engine.rs:1490`) and stored via `register_block` — it
  is **not** routed through `on_qc` (which handles only locally-formed QCs).
  The legacy `verify_quorum_certificate` (`lib.rs:705`) is reached only via the
  separate `Node<S>::apply_block` abstraction.
* **Verifier incompatibility:** `verify_quorum_certificate` verifies the legacy
  `vote_digest` signed input (`qbind-hash/src/consensus.rs:8`), which omits
  `version`/`epoch` and the entire D6 domain; it is **not reusable unchanged for
  D6-signed Votes** (whose signed input is `ProposalVoteSigningDomainV2::
  vote_preimage`). Its structural checks (bitmap↔sig count, index decode, power
  sum) are **structural ideas requiring checked adaptation**, not drop-in reuse:
  indices must be bounded and computed with checked arithmetic before any
  narrowing, and the power sum must be overflow-guarded; its signature
  verification is not reusable. Quorum rules (`qc_threshold` scalar vs
  `two_thirds_vp()` vs `2f+1`) are not equated, and `ConsensusValidatorSet`'s
  saturating accumulation / `two_thirds_vp()`'s `2 * total` in `u64` cannot be
  reused blindly for arbitrary inputs.

**Reused implementations (no duplication introduced):** `ConsensusValidatorSet`
+ `SuiteAwareValidatorKeyProvider`, `verify_proposal_msg_with_domain` /
`verify_vote_msg_with_domain` (the D6 machinery), the timeout verification
bridge, and `try_bind` coherence. The legacy `verify_quorum_certificate` and the
`two_thirds_vp()` threshold arithmetic are **structural ideas requiring checked
adaptation** — reusable as templates for a checked implementation, **not** their
signature path and **not** blind reuse of the saturating/`2 * total` arithmetic.

**Recommended next code task (exactly one, revised).** The prior "invoke the
existing QC verifier; prerequisites none" recommendation is **withdrawn** as
unsafe (it would verify the legacy `vote_digest` input, incompatible with
D6-signed Votes). Instead: add a **dormant, pure D6-compatible QC verification
boundary** that verifies a QC's constituent Votes via the existing D6
message-bound Vote machinery and the established membership/key/backend
interfaces, with trusted domain/membership/key-provider/backend/epoch inputs. It
must bound the bitmap before decoding and compute indices with checked arithmetic
(representability before any narrowing); define bitmap-position / wire
`validator_index` / `ValidatorId` correspondence consistently with D6 (position
and `ValidatorId` not interchangeable); test index aliasing and incorrect
signature association instead of an impossible duplicate-bit encoding; validate a
positive, consistent, representable voting-power total with overflow prevention in
total, signer-power, and threshold arithmetic (reuse `two_thirds_vp()` only within
proven bounds or a checked `ceil(2W/3)` equivalent, without silently changing
quorum policy); reject epoch/wire-chain inconsistencies before crypto while
preserving the QC's actual signed fields; return evidence in a separate,
non-authorizing result type; keep legacy callers unchanged with no
legacy-signature fallback; and fail closed on missing/inconsistent trusted
inputs. Full contract and required negative tests (index/representability limits,
arithmetic limits, zero/invalid total power, malformed signature associations,
wrong domain/epoch, insufficient quorum, and real D6-signed positive controls) in
the audit §6. Not wired into engine/binary/main; activation stays last and gated
behind durable freshness / anti-rollback. The production runtime→wire mapping and
provenance work gates integration/activation only, **not** this dormant verifier.

**Checks executed / tool limitations.** Git and `rg`/`grep` source inspection
only (recorded in the audit §7); no build, test, or release rebuild was run for
this documentation-only pass. Historical `cargo test` results above are not
relabelled as newly executed. Prior CodeQL SKIPPED/INCOMPLETE and qualified
reviewer outcomes remain as recorded and are not converted into successful
analyses.

## Run 422 D7-C3D — pure, dormant D6-compatible QuorumCertificate verification (code + test)

This entry records the **authorized code task** recommended by C3C: a pure,
dormant, D6-compatible QC verification boundary, with focused tests and evidence.
It performs **no** production integration, activation, or wire/QC/storage change.

```
D7C3D_D6_QC_VERIFICATION=CODE-TEST-POSITIVE
D7C3D_BINARY_ENGINE_INTEGRATION=NOT-PERFORMED
D7C3D_VERIFIED_QC_IS_CURRENT_AUTHORIZATION=FALSE
D7A_INBOUND_VERDICT=PARTIAL
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

### Actual branch / SHAs (task §1, §9)

* Branch (actual): `copilot/copilotcopilotrun-422-d7-c3c-again`. The task names
  the reviewed branch `copilot/copilotrun-422-d7-c3c-again`; the checkout carries
  an extra doubled `copilot` segment. Reported, not corrected (no history
  rewrite).
* Starting HEAD: `9c616577c209864aeb866d0f6b6db6fc5285fa33` (`update`).
* Tested implementation SHA (checkpoint before lengthy validation):
  `2ec4437f8fb24e78d9082b8d3373194193f483d7`.
* The accepted C3C audit revision `03ed9104663f9d17074fe5ddb3fe3fb96c387070` and
  the task's named reviewed branch tip are **absent** from this shallow clone
  (`.git/shallow` grafts at `f124ec10aac4167319c6244e333f6e04345d7eae`), so
  ancestry to the named C3C revision could not be confirmed. The present source
  (the D6 verifier, wire QC/Vote, validator set, key/backend registries, and the
  C3C audit doc) was verified directly in the worktree; missing historical
  objects do not imply missing implementation and no ancestry was manufactured.
* Disk/inodes at start: root fs 42% used, 6% inodes — ample headroom for
  sequential builds; no duplicate target directories were created.

### Reused implementations and the distinct gap filled (task §3, §8)

Reused unchanged: `verify_vote_msg_with_domain` (the D6 message-bound Vote
verifier, so the signed input is exactly `ProposalVoteSigningDomainV2::
vote_preimage`), `ProposalVoteSigningDomainV2`, `ConsensusValidatorSet`,
`SuiteAwareValidatorKeyProvider`, `ConsensusSigBackendRegistry` /
`SimpleBackendRegistry`, and the real ML-DSA-44 test infrastructure
(`MlDsa44Backend`).

No equivalent domain-aware QC verifier existed. The legacy
`verify_quorum_certificate` (`lib.rs:705`) verifies the legacy `vote_digest`
signed input (which omits `version`/`epoch` and the entire D6 domain) through a
different `CryptoProvider` interface; it is **not reusable unchanged** for
D6-signed Votes and is left untouched (no legacy fallback). Its structural ideas
(bitmap↔sig count, index decode, power sum) were adapted with checked
arithmetic, not blindly copied.

### New behavior (task §4, §5)

New module `crates/qbind-consensus/src/qc_verify_domain.rs` exposes
`verify_quorum_certificate_with_domain(qc, domain, authorized_epoch, validators,
key_provider, backend_registry) -> Result<VerifiedQuorumCertificate,
QcDomainVerifyError>`. `lib.rs` adds the narrow `pub mod qc_verify_domain;` and
re-exports the function, result type, error type, and the `MAX_BITMAP_LEN` /
`MAX_SIGNATURE_LEN` bounds. Full contract (API, trusted-input assumptions, index
semantics, size bounds, quorum arithmetic, failure ordering, result ownership,
typed failures, dormancy) is documented in
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md` §9A and is not duplicated
here.

Mandatory borrowed inputs make absence unrepresentable: no optional default
domain/epoch, no second authority registry, and no production authority
constructor were added to represent missing-input tests.

### Index mapping, bounds, arithmetic, ordering, ownership (task §5, §9.5)

* **Index mapping:** bitmap bit `i` → wire `validator_index = i` →
  `ValidatorId(i)`, matching D6's `ValidatorId::new(vote.validator_index as
  u64)`. Vector position is never used. Signatures associate with set bits in
  ascending-bit order.
* **Bounds:** `signer_bitmap.len() <= MAX_BITMAP_LEN` (8192; `8192*8 == 65536`
  bits so the top index is exactly `u16::MAX`); `popcount == signatures.len()`;
  each signature `<= MAX_SIGNATURE_LEN` (`u16::MAX`). Sizes are validated before
  the single per-signer signature clone and before crypto. A membership id
  `> u16::MAX` is rejected (`MembershipIdNotRepresentable`).
* **Arithmetic:** total `W` recomputed with `checked_add` (reject
  `TotalVotingPowerOverflow`), required positive (reject `ZeroTotalVotingPower`);
  threshold `ceil(2W/3)` computed in `u128` (checked equivalent of
  `two_thirds_vp()`, no `2*W` u64 wrap); per-signer power accumulated once with
  `checked_add`. The accumulation overflow is mathematically excluded by the
  validated total precondition and is tested via that precondition rather than a
  fabricated case.
* **Failure ordering:** WireChainMismatch → EpochMismatch → membership
  arithmetic → bitmap/structural → per-signer (membership/missing-sig/key/suite/
  backend/malformed/invalid) → InsufficientVotingPower. The first two and the
  epoch check occur before any crypto; verified by direct backend-call counts.
* **Result ownership:** `VerifiedQuorumCertificate` owns a clone of the QC plus
  signer ids, verified power, threshold, and trusted context (expected wire
  chain, authorized epoch, domain). Private fields, read-only accessors, no
  public constructor, no public mutable field, no `Deserialize`, bounded `Debug`.
  It offers no conversion to any authorization owner/snapshot/ticket/signer/
  activation state/production verification capability.

### Behavioral tests (task §6) — `run_422_d7c3d_qc_domain_verification_tests` (35)

Real ML-DSA-44 positives/negatives; a `CountingVerifier` adapter delegates to the
real backend and asserts backend-invocation counts where "before crypto" is
claimed. Each negative crypto case has a matching same-key positive control and
changes only the boundary under test. Coverage maps to the task §6 matrix:

1. Valid quorum returns associated signer ids, power, threshold, certificate,
   and context (`c3d_1_*`, 2 tests).
2. Nonuniform powers: accept at exact threshold, reject below
   (`c3d_2_nonuniform_accept_at_threshold_reject_below`).
3. Sparse/reordered membership proving lookup by `ValidatorId` not position
   (`c3d_3_sparse_reordered_membership_lookup_by_validator_id`).
4. Correct-key wrong-domain negatives varying runtime id, genesis identity, and
   authority commitment independently, each with a same-key control
   (`c3d_4_*`, 3 tests).
5. Wire-chain mismatch and a genuinely-signed wrong-epoch QC rejected before
   crypto (backend calls == 0), the epoch case with an authorized-epoch control
   (`c3d_5_*`, 2 tests).
6. Legacy `vote_digest` signatures rejected as `InvalidSignature` by the D6
   boundary, with a D6 positive control — signed-input incompatibility without
   attributing an unrelated suite/key failure
   (`c3d_6_legacy_vote_digest_signatures_rejected_by_d6`).
7. Empty / popcount-mismatched (both directions) / overlong bitmaps, max-length
   all-zero bitmap accepted structurally, unknown ids, index representability,
   signature reordering, incorrect association (`c3d_7_*`, 9 tests).
8. Empty/truncated/overlong signatures, header-field tampering, and a valid
   quorum plus an invalid extra signature (backend calls == 5, proving all
   signatures verified past quorum) (`c3d_8_*`, 5 tests).
9. Missing key, governed-suite mismatch, unsupported backend, and a
   registered-but-faulting backend as distinct outcomes (`c3d_9_*`, 4 tests).
10. Zero total power, overflowed total (excluding the later accumulation
    overflow), and safe threshold near/above the u64 half-limit without
    wraparound (`c3d_10_*`, 4 tests).
11. No partial verified result on failure and bounded Display/Debug diagnostics
    (`c3d_11_*`, 3 tests).

### Validation (task §7) — sequential, tested SHA `2ec4437`

Recorded commands, all exit 0; subset counts are not summed as independent
totals:

* `cargo test -p qbind-consensus --test run_422_d7c3d_qc_domain_verification_tests`
  → 35 passed.
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
  → 34 passed (existing D6 isolation target, unchanged).
* `cargo test -p qbind-consensus` (full) → all targets pass (e.g. lib 182;
  D7-C3D 35; D6 34; plus every other target 0 failed).
* `cargo test -p qbind-wire` → all pass, 0 failed.
* `cargo check -p qbind-node` (default production features) → Finished, exit 0.
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests
  --test run_422_startup_refusal_tests` → 3 + 4 passed.
* `cargo clippy -p qbind-consensus --lib --test
  run_422_d7c3d_qc_domain_verification_tests` → zero warnings attributable to the
  new files; the 8 pre-existing lib warnings (e.g. slashing `large size
  difference`, map-keys iteration) are in unrelated modules and untouched.
* `rustfmt --check --edition 2021` on the two new files and the lib.rs edit →
  clean. Formatting/whitespace limited to changed files; original CRLF doc line
  endings preserved; no package-wide `cargo fmt` was run (a pre-existing
  `basic_hotstuff_engine.rs` fmt diff is left untouched).
* `cargo build --release -p qbind-node --bin qbind-node` (once, after the
  implementation was stable) → Finished `release` profile (exit 0, 7m06s). This is **compilation
  evidence only**, not configured-authority adversarial runtime evidence.

The known unrelated broad `qbind-node --tests` feature-gating failure was
avoided (only the two named node targets were built); no storage tests or APIs
were modified.

### Security-tool outcomes (task §7)

`parallel_validation` was run on the changed set. **Code Review:** reviewed 5
files, **0 review comments** — but the review model was reported unavailable in
this environment (`model claude-sonnet-4.6 not found in registry`), so the empty
result is **not** a clean reviewer pass. **CodeQL (rust):** **0 alerts**, but the
analysis was **skipped — database size too large**. Per task §7 a database-size
skip and a "0 alerts" accompanying a skip are **not** a passed security analysis;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO` is retained. These are the
actual tool limitations, not converted into successful analyses.

### No production integration or activation (task §8)

`verify_quorum_certificate_with_domain` has **no** non-test callers: it is not
referenced by the engine, node startup, handlers, cache, storage, or activation
paths (only the new test target uses it). Production
`proposal_vote_authority=None`, the genesis startup refusal, D6 signing bytes,
Timeout/NewView separation, and `CurrentEpochUnavailable` behavior are unchanged;
existing wire encodings, D6 preimages, shared logical QC fields, legacy verifier
behavior, validator-set semantics, engine membership, node configuration, and
authority constructors are untouched.

### Remaining limitations / retained verdicts (task §9)

Verified signature-and-quorum validity relative to trusted inputs is **not**
current authorization: it does not establish official-genesis provenance,
authority currency/freshness, or activation permission, and does not solve
concurrent provider mutation or persistent freshness. This is not a complete
transport-level DoS audit. Engine insertion, certificate propagation,
parent/justify safety, lock/commit behavior, lifecycle activation, durable
anti-rollback, and Run 423 remain separate work. Retained verdicts:
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. Prior C3A/C3B/C3C decisions and
historical evidence are preserved and not relabelled as newly executed.

## Run 422 D7-C3D — structural-preflight correction (this pass, code + test)

This subsection records the corrective continuation to the dormant
`verify_quorum_certificate_with_domain` boundary. It hardens the structural
preflight only. No wire format, encoder, engine, handler, startup, cache,
storage, authority-lifecycle, legacy-verifier, or production-integration change
was made. D6 signing bytes and the existing validator-set / `ceil(2W/3)` quorum
semantics are preserved. The boundary remains dormant (no non-test callers).

### Actual branch / SHAs (correction pass)

* Branch (actual): `copilot/copilotcopilotrun-422-d7-c3c-again-again`. Reported,
  not corrected (no rename / history rewrite).
* Starting HEAD at this pass: `95d863243e96cb189d9ae7dc28b05d1e155a93c8`.
* The task-named reviewed revision `3d228cd41d345f3f79133001a2c5c93478c22373`
  and reported tested revision `2ec4437f8fb24e78d9082b8d3373194193f483d7` are
  **absent** from this shallow clone; recorded as missing historical objects,
  not missing source. Present source was verified directly in the worktree; no
  ancestry was invented.
* Code checkpoint committed before lengthy validation:
  `50aeba3fd6413ced471bd97950a95b1d1f595f0b`.
* Disk at start: root fs 42% used — ample headroom.

### The three structural-preflight corrections

**A. Signature-count representability.** The wire QC encodes `signatures.len()`
as `u16`, so the maximum *encodable* signature count is `65535`. The verifier now
rejects `signatures.len() > MAX_SIGNATURE_COUNT` (`= u16::MAX as usize = 65535`)
with typed `SignatureCountNotRepresentable { count, max }` **before** any crypto
or signer-result allocation. Three quantities are kept distinct: maximum valid
validator **index** `65535`; number of representable indices `65536`; maximum
encodable QC signature **count** `65535`. The 8192-byte bitmap alone does not
enforce the count limit (8192·8 = 65536 possible bits). The wire format and
encoder are unchanged; oversized counts are rejected, not accommodated.

**B. Complete structural size checks before cryptographic verification.** All
structural size validation now precedes the crypto loop and any signature-buffer
clone: signature count (A), global bitmap bound (`MAX_BITMAP_LEN`),
membership-relative bitmap bound (C), bitmap/signature-count correspondence via
popcount, **every** individual signature's size (`MAX_SIGNATURE_LEN`), and a
checked aggregate-size bound. A late oversized signature therefore rejects with
`MalformedSignature` **before ANY backend invocation** — proven by a
zero-backend-call test paired with a same-backend positive control. The
verifier's own aggregate acceptance bound is
`MAX_AGGREGATE_SIGNATURE_BYTES = MAX_SIGNATURE_COUNT * MAX_SIGNATURE_LEN`,
computed with `checked_add` folding (`checked_aggregate_signature_bytes`) and
reported via `AggregateSignatureBytesTooLarge { aggregate, max }`. This bound is
deliberately **distinct** from the transport `MAX_NET_MESSAGE_BYTES` (1 MiB) and
is not a claim of a complete DoS audit or any transport-policy change. The
existing rule that every structurally valid declared signature must verify —
even after quorum is reached — is preserved.

**C. Membership-relative bitmap bound.** Bitmap length is now bounded by both the
global representable range and the trusted membership's maximum representable
`ValidatorId` (the identifier *span*, `(max_id / 8) + 1` bytes; `0` for empty
membership), never `validators.len()`, so sparse and reordered memberships stay
valid. Bytes beyond the trusted span — **including zero padding** — reject with
`BitmapBeyondMembershipSpan { len, allowed }`. Set bits for unknown members
within the span continue to reject (`UnknownSigner`). The mapping
`bit i → wire validator_index i → ValidatorId(i)` is unchanged; no validator is
renumbered or truncated and vector position is never assumed to equal
`ValidatorId`. Narrowing conversions are guarded by checked arithmetic / the
established span bound.

### Tests (correction pass) — `run_422_d7c3d_qc_domain_verification_tests` (46)

Test function count rose from **35** (historical C3D entry above) to **46**
newly executed here. Retained: valid-crypto, arithmetic, suite, domain, epoch,
and invalid-extra-signature coverage. The former
`c3d_7_max_len_bitmap_all_zero_is_within_bounds` assertion (which accepted a
full-length all-zero bitmap regardless of membership) was **replaced** because
its acceptance policy was incomplete under the new membership-relative bound.
Added / strengthened:

* Signature count `65536` rejects with `SignatureCountNotRepresentable` and
  **zero** backend calls (modest fixture; no 65536 keypairs generated).
* A genuine real-ML-DSA-44 positive QC whose sole signer is `ValidatorId(65535)`
  with the highest bitmap bit set and the matching reconstructed `Vote` index,
  over a sparse one-validator membership (not an all-zero bitmap).
* Membership-relative bitmap length: exact valid span (all-zero within bounds),
  zero padding beyond the span (rejected), unknown set bit within the span
  (rejected), plus retained sparse / reordered positive controls.
* Valid signatures followed by an oversized signature: **zero** backend calls
  (via a counting backend), paired with a successful same-backend control.
* Checked aggregate-size arithmetic and its acceptance/rejection boundaries via
  the pure `checked_aggregate_signature_bytes` helper (no multi-gigabyte
  allocations), plus real-entrypoint oversized-signature rejection.
* An independently constructed ordinary D6 `Vote`→QC positive control over the
  actual signed header fields (not derived through the verifier's reconstruction
  helper).
* Legacy/D6 three-way incompatibility: legacy signatures verify over legacy
  input, fail under D6; D6 signatures fail over legacy input. Each test states
  which entrypoint it exercises (`verify_vote_msg_with_domain` vs the legacy
  path).

Direct backend invocation counters back all pre-crypto zero-call claims; real
ML-DSA-44 backs cryptographic acceptance/replay controls; structural/fault test
doubles are clearly identified. No all-zero bitmap is described as proof of
highest-index cryptographic acceptance.

### Validation (correction pass) — sequential, checkpoint `50aeba3`

* Focused C3D target: `46 passed; 0 failed`.
* D6 isolation (`proposal_vote_verify` D6 tests) in `qbind-consensus`: `34 passed`.
* Full `qbind-consensus` suite: `803 passed; 0 failed`. `qbind-wire`: `88 passed`.
* Focused Clippy on changed targets: clean (pre-existing lib warnings in
  unrelated modules `adversarial_multi_sim.rs`, `basic_hotstuff_engine.rs`,
  `slashing/mod.rs` are untouched and not introduced here).
* `rustfmt --check` on the two changed Rust files: clean; CRLF line endings
  preserved (verified per-file); no repository-wide formatting performed.
* Additional node-target and release-build validation results are recorded with
  their literal outcomes in the final report accompanying this commit.

### Docs reconciled

Module doc "Size bounds", protocol §9A (Size bounds / Failure ordering / Typed
failures), and this C3D evidence were reconciled with the implemented preflight
order and exact limits (`MAX_SIGNATURE_COUNT = 65535`,
`MAX_AGGREGATE_SIGNATURE_BYTES`, membership-relative bitmap span). Historical
35-function count and prior execution are kept separate from the newly executed
46-function count.

### Retained posture (correction pass)

A positive verdict covers only the corrected dormant QC-verification boundary.
No readiness item moves Green; no engine adoption, activation, or Run 423 work.
Retained verdicts are unchanged:
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`.

## Run 422 D7-C3D — arithmetic-test & evidence correction (this pass, test + comments + docs)

This subsection records a narrow follow-up to the structural-preflight correction
above. It corrects one ineffective test assertion and reconciles the
allocation-order wording and provenance. **No production logic, exports, wire
format, engine, handler, storage, authority, or activation change was made.** The
dormant `verify_quorum_certificate_with_domain` boundary is unchanged and still
has no non-test callers.

### Actual state (this pass)

* Branch (actual, in this shallow clone): `copilot/copilotcopilotcopilotrun-422-d7-c3c-again-again`.
  Recorded as-is; not renamed, not rewritten.
* HEAD at start of this pass: `d3087542ce6aa3d32a6eaad8a94497e4924c43d0`
  (subject `update`); its only available parent / shallow boundary is
  `95d863243e96cb189d9ae7dc28b05d1e155a93c8`. `git rev-list --count HEAD == 2`;
  `.git/shallow` pins `95d8632`.
* The task-reported reviewed revision `df9f742f316c5610d1caa5ca7b6350a701c86bae`
  and reported code checkpoint `50aeba3fd6413ced471bd97950a95b1d1f595f0b` are
  **not present as objects** in this shallow clone (`git cat-file -t` fails for
  both). Recorded as missing historical objects, not missing source; no ancestry
  was manufactured. Present source was verified directly in the worktree.

### Correction dispositions

**1. Arithmetic test (`c3d_14_checked_aggregate_signature_bytes_boundaries`) —
CORRECTED.** The former input `[usize::MAX, usize::MAX]` never reached the
checked-add overflow path: the *first* element (`usize::MAX`) already exceeds
`MAX_AGGREGATE_SIGNATURE_BYTES`, so `checked_aggregate_signature_bytes` rejects it
on the first addition via the `> MAX` branch (with `aggregate == usize::MAX`),
returning before the second element is ever added. It exercised immediate bound
rejection, not addition overflow. The test now uses `[1usize, usize::MAX]`: the
first addition `0 + 1 == 1` succeeds and remains within the acceptance bound, and
the *second* checked addition `1 + usize::MAX` overflows the `usize` accumulator,
returning the existing bounded `AggregateSignatureBytesTooLarge { aggregate:
usize::MAX, max: MAX_AGGREGATE_SIGNATURE_BYTES }`. A separate retained case
`[usize::MAX]` is now explicitly described as **immediate bound rejection** (not
overflow). The exact-bound (`[MAX_AGGREGATE_SIGNATURE_BYTES] ⇒ Ok`) and over-bound
(`[MAX_AGGREGATE_SIGNATURE_BYTES, 1] ⇒ AggregateSignatureBytesTooLarge`) cases are
retained unchanged. No production arithmetic or acceptance policy was altered.

**2. Allocation-order descriptions — RECONCILED (comments/docs only).** The
implemented order is: signature-count representability and the bitmap bounds
(global length, membership-relative span) precede signer-vector construction;
`collect_signers` then materializes a **temporary** signer vector; only after that
do the popcount-correspondence, per-signature-size (`MAX_SIGNATURE_LEN`), and
checked aggregate-size checks run. Those per-signature and aggregate checks
therefore precede only the signature-buffer clone and backend invocation — **not
every allocation**. The blanket claim that every structural check precedes any
signer-result allocation is removed from the module doc "Size bounds" heading,
protocol §9A, and this evidence. The temporary vector is bounded by the bitmap's
capacity: before correspondence succeeds it can hold up to `65536` entries (a full
8192-byte bitmap's popcount, one more than `MAX_SIGNATURE_COUNT`), and only after
successful correspondence is it bounded by `MAX_SIGNATURE_COUNT` (`65535`).
Production behavior was **not** changed to match any overstated description; the
signature-count-representability check specifically does still precede the signer
vector and remains accurately described as such.

### Provenance & evidence reconciliation

* The actual starting-to-final diff (`95d8632` → `d3087542`) spans **FIVE** files:
  `crates/qbind-consensus/src/lib.rs`,
  `crates/qbind-consensus/src/qc_verify_domain.rs`, the C3D test file
  `crates/qbind-consensus/tests/run_422_d7c3d_qc_domain_verification_tests.rs`, and
  the two Markdown records
  (`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md`, this evidence file)
  — `git diff --stat` confirms 5 files. The `lib.rs` **export** changes
  (`pub mod qc_verify_domain` + the re-export list) occurred at the reported code
  checkpoint `50aeba3`; they do **not** predate this correction line and are not
  described as pre-existing.
* The subsequent Rust-file changes at the reviewed revision `df9f742` were
  **formatting / newline-only**, with **no behavioral change** (recorded from the
  task-supplied provenance; those two revisions are not locally recoverable in
  this shallow clone, so this is a supplied report rather than an independently
  re-derived diff).

### Validation (this pass) — independently executed here

* `cargo test -p qbind-consensus --test run_422_d7c3d_qc_domain_verification_tests`
  ⇒ **46 passed; 0 failed; 0 ignored** (finished ~1.3s).
* Focused Clippy on the changed test target
  (`cargo clippy -p qbind-consensus --test run_422_d7c3d_qc_domain_verification_tests`)
  ⇒ no warnings referencing the changed test target. The 8 emitted warnings are
  pre-existing `qbind-consensus` **lib** warnings in unrelated modules
  (`adversarial_multi_sim.rs`, `basic_hotstuff_engine.rs`, `slashing/mod.rs`,
  the `needless_return`/hardened-evidence sites); they are untouched and not
  introduced here.
* Formatting / whitespace, restricted to edited files: CRLF line endings
  preserved on all three edited source/doc files (verified per file); no trailing
  whitespace introduced in edited hunks. `rustfmt --check` on the two Rust files
  reports only a pre-existing end-of-file blank-line normalization artifact at
  lines outside the edited regions (a CRLF-vs-rustfmt artifact), not a change from
  this pass.

### Not re-executed this pass (supplied vs. recovered)

Per scope, **no** release rebuild or broad regression rerun was performed for this
test/comment/documentation correction. The node-check (`cargo check -p qbind-node`),
Run 420 production-policy reachability / startup-refusal, release-build, and
security-tool (CodeQL / review-tool) outcomes are **preserved at their actual
prior reported checkpoints** as recorded elsewhere in this document; they are
**supplied prior results**, not independently recovered execution logs from this
pass, and are not relabelled as newly executed. Reported literally: the
security-tool / CodeQL results carried forward remain **SKIPPED / INCOMPLETE**
(database-size skips / not-run in this environment) — a skip, unavailable backend,
or model error is recorded as such and is **not** a successful scan or review.

### Legacy / D6 control attribution

The three-way legacy/D6 controls exercise (a) **raw ML-DSA-44 verification over
each signed input** (legacy signatures verify over legacy bytes and fail under the
D6 v2 preimage; D6 signatures fail over legacy bytes), and (b) the **D6 QC
entrypoint** (`verify_vote_msg_with_domain` via the domain QC verifier). The
**legacy public QC verifier was not exercised**; no test implies otherwise.

### Retained posture (this pass)

The positive verdict covers **only** the dormant QC-verification boundary. No
readiness item moves Green. Retained verdicts are unchanged: `D7_STATUS=PARTIAL`;
production authority remains **unavailable**; `GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. No engine adoption, activation,
readiness promotion, or Run 423 work.

## Run 422 D7-C3E — verify PRESENT embedded QCs before inbound Proposal effects (code + test)

**Objective.** In the real `handle_inbound_consensus_msg` `Proposal` arm, under
the `Required` policy, verify every PRESENT embedded wire QuorumCertificate using
the existing C3D `verify_quorum_certificate_with_domain` **before** the Proposal
reaches restore-deferral accounting, delivery accounting, reconfiguration
observation, engine mutation (including view advancement), or the immediate
outbound handoff. A valid outer Proposal signature must not make an invalid
embedded QC acceptable. This is a conditional inbound-admission improvement using
the existing authorized snapshot; it does **not** establish production authority
construction, activation, complete engine/QC adoption, or public DevNet
readiness.

### Provenance correction (C3D)

Recorded from git in this worktree, correcting prior evidence:

* `d3087542ce6aa3d32a6eaad8a94497e4924c43d0` was the C3D **starting/import**
  revision (present locally), **not** the final corrected revision.
* `15557323248946e25fe71a8e4a1b931fbb9383d4` contains the C3D
  test/comment/protocol correction (object **absent** in this shallow clone).
* `bec1fbda9c350b8cf4b31e5358db2bef1f02ffd3` contains the final C3D evidence
  update (object **absent** in this shallow clone); that continuation changed
  four files.
* Missing historical objects do not imply missing implementations, and no
  executed-test SHA is inferred solely from source correspondence.

**Actual supplied branch (inspected, not manufactured):**
`copilot/copilotcopilotcopilotcopilotrun-422-d7-c3c-again-a` (the working branch
differs from the problem statement's reported
`copilot/copilotcopilotcopilotrun-422-d7-c3c-again-again`; reported as a
deviation without fabricating ancestry). The C3D continuation is present locally
as the pre-C3E HEAD (four changed files: `qc_verify_domain.rs`, the
`run_422_d7c3d` tests, this evidence doc, and the signing-domain protocol doc);
its parent is the starting revision `d3087542`.

### What changed (from git, not an assumed count)

Changed files in this C3E pass:

* `crates/qbind-node/src/binary_consensus_loop.rs` — production gate + counters +
  the `run422_d7c3e` real-handler test module (the only expected production
  change).
* `crates/qbind-consensus/src/qc_verify_domain.rs` — **dormancy comment only**
  (it now has one conditional binary caller; no C3D production-logic change).
* `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md` — new §9B conditional
  handler contract + exact exclusions; §9A dormancy note updated.
* `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` — additive
  §10 successor note (historical C3C findings preserved).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — this section.

No `main.rs`, C3A/C3B, C3D-rule/D6-byte/wire-encoding, engine-construction,
Timeout/NewView, or storage/restore changes. No package-integrity anchor artifact
changed, so no manifest refresh is required.

### Production gate (insertion order)

Inserted in the `ConsensusNetMsg::Proposal` arm **after** the existing outer
Proposal verification and **before** the D7-A freshness-ticket confirmation and
all downstream effects. Preserved ordering for a Required Proposal carrying
`Some(qc)`:

a. Decode + existing F6 sender binding.
b. Existing current-authorization admission + signed-Proposal epoch check.
c. Existing outer Proposal verification under the admitted snapshot's verifier.
d. **Engine-context correspondence** (new): reuse `validator_membership_matches`
   to require the engine's actual validator IDs **and** voting weights to match
   the bound verifier's membership (by value, not `Arc` identity; matching counts
   alone insufficient) and require `engine.current_epoch() ==
   snap.authorized_epoch()`. Mismatch increments
   `inbound_proposal_engine_context_mismatch_total` and returns before QC crypto.
e. **Embedded-QC verification** (new): call
   `verify_quorum_certificate_with_domain` **once** for the present QC; success
   increments `inbound_proposal_embedded_qc_verified_total` and retains the
   non-authorizing `VerifiedQuorumCertificate` with the immutable Proposal;
   failure increments `inbound_proposal_embedded_qc_rejected_total` and returns.
f. Existing authorization-ticket confirmation.
g. Only then the existing downstream Proposal effects.

Engine membership is never resized, replaced, renumbered, or mutated to force a
match. No new QC verifier, signing encoder, key registry, authority factory, or
runtime/wire mapping was added; there is no "already verified" flag or
certificate cache, and retention beyond the synchronous handler call is out of
scope.

### Trusted-input provenance

`domain` (`verifier.signing_domain`), `validators`, `key_provider`, and
`backend_registry` are all taken from the SAME admitted `snap.verifier()` used
for the outer verification; `authorized_epoch` is taken from
`snap.authorized_epoch()` (the `GENESIS_STATIC_AUTHORITY_EPOCH`). Authorization is
never derived from the QC, the Proposal header, the engine's default epoch, a
separately-supplied `pv_authority` B, or Timeout context.

### Bounded counters

Added to `BinaryConsensusLoopInboundStats`:
`inbound_proposal_embedded_qc_verified_total`,
`inbound_proposal_embedded_qc_rejected_total`,
`inbound_proposal_engine_context_mismatch_total`. Existing counters keep their
meanings: the pre-existing outer-signature acceptance counter may increase even
when the embedded QC subsequently rejects; it is **not** relabelled as
whole-Proposal acceptance. "Before QC crypto" is instrumented as zero constituent
Vote backend calls via a dedicated counting verifier that separates Proposal vs.
Vote backend calls.

### Real-handler tests (`mod run422_d7c3e`, 22 tests, all passing)

Nested inside `run422_d7a`, reusing the D7-A/run420 fixtures: the actual
encoded-envelope handler under `Required` policy, a real F6 gate + authenticated
origin, coherent snapshots, real ML-DSA-44, independently counted Proposal/Vote
backend calls (`C3eCountingVerifier`), and a recording facade. Each invalid-QC
case attaches the QC **before** signing the outer Proposal so rejection can never
be attributed to a stale outer signature.

* **A — positive control:** `c3e_a_valid_qc_delivers_distinct_from_engine_accept`
  (valid outer + genuine D6-signed quorum passes the gate and reaches delivery)
  and `c3e_a_valid_qc_reaches_engine_acceptance_and_outbound` (reaches genuine
  engine acceptance with appropriate leader/epoch/state; delivery, engine
  acceptance, and outbound distinguished).
* **B — invalid constituent signature:**
  `c3e_b_valid_quorum_plus_invalid_extra_signature_rejects` (valid quorum + an
  invalid extra signature → QC rejection, no downstream effects).
* **C — insufficient quorum / encodable malformed:**
  `c3e_c_insufficient_quorum_rejects`, `c3e_c_some_empty_qc_rejects_not_routed_as_absent`
  (`Some(empty_qc)` rejects and is not routed as absent),
  `c3e_c_bitmap_signature_count_mismatch_rejects_before_crypto`. Pure-C3D tests
  retain the limits that cannot be encoded into a handler input.
* **D — domain and epoch isolation:**
  `c3e_d_foreign_domain_qc_rejects_current_domain_succeeds`,
  `c3e_d_qc_wire_chain_mismatch_rejects_before_vote_crypto`,
  `c3e_d_qc_epoch_mismatch_rejects_before_vote_crypto` (mismatches reject before
  constituent Vote verification; the outer Proposal remains valid).
* **E — engine/verifier mismatch:**
  `c3e_e_same_size_different_ids_rejects_before_qc_crypto`,
  `c3e_e_same_ids_different_weights_rejects_before_qc_crypto`,
  `c3e_e_engine_epoch_mismatch_rejects_before_qc_crypto`, and the positive control
  `c3e_e_by_value_matching_membership_positive_control` (structurally matching
  by-value membership passes).
* **F — bound context:** `c3e_f_a_valid_qc_succeeds_supplied_b_never_used`
  (admitted A + separately supplied authority B still uses A; B instrumented and
  proven unused) and `c3e_f_b_only_valid_qc_fails_under_a`.
* **G — ordering:** `c3e_g_f6_rejection_prevents_qc_verification`,
  `c3e_g_unavailable_authorization_prevents_qc_verification`,
  `c3e_g_invalid_outer_signature_prevents_qc_verification` (each prevents QC
  verification; existing reason/counter semantics preserved).
* **H — active restore:** `c3e_h_invalid_qc_rejects_before_deferral` (invalid QC
  rejects before deferral) and `c3e_h_valid_qc_reaches_deferral_branch` (matching
  valid-QC control reaches the existing deferral branch; discard-and-retransmission
  preserved).
* **I — state protection:** `c3e_i_future_view_invalid_qc_no_state_change`
  asserts unchanged engine view / lock / high-QC / block / commit state via
  existing APIs, no reconfiguration observation, no delivery or deferral, and zero
  facade actions for a future-view Proposal with an invalid QC (the C3D verifier
  short-circuits on the first invalid constituent signature, so the Vote-backend
  count is `>= 1`, not the full quorum size).
* **J — absent-QC compatibility:**
  `c3e_j_absent_qc_behavior_preserved_and_uncounted` (preserved `None` behavior,
  not counted as successful QC verification).

Command / result:

```
cargo test -p qbind-node --lib run422_d7c3e
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 1590 filtered out
```

### Validation

See the "Validation (D7-C3E)" subsection below for exact commands, profiles,
counts, and exit codes.

#### Validation (D7-C3E) — exact commands, counts, exit codes (exit 0 unless noted)

All commands run in this worktree; profiles as shown; disk monitored (peaked ~50%
of 145G, ~73G free).

* `cargo test -p qbind-node --lib` (dev) → **1612 passed; 0 failed** (includes
  `run422_d7c3e` and retained D5/D6/D7 coverage).
* `cargo test -p qbind-node --lib run422_d7c3e` (dev) → **22 passed; 0 failed**
  (1590 filtered out).
* `cargo test -p qbind-consensus --test run_422_d7c3d_qc_domain_verification_tests`
  (dev) → **46 passed; 0 failed** (C3D target).
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
  (dev) → **34 passed; 0 failed** (D6 isolation target).
* Run 418 regressions:
  `run_418_authenticated_peer_consensus_sender_binding_tests` → **18 passed**;
  `run_418_newview_demux_chain_integration_tests` → **3 passed**.
* Run 420 production-policy reachability
  (`run_420_production_policy_reachability_tests`) → **3 passed**.
* Run 422: `run_422_startup_refusal_tests` → **4 passed**;
  `run_422_d4_startup_ordering_tests` → **5 passed**;
  `run_422_d7_authority_lifetime_tests` → **14 passed**;
  `run_422_genesis_consensus_authority_tests` → **15 passed**.
* Restore targets: `b3_snapshot_restore_tests` → **10 passed**;
  `b5_restore_aware_consensus_start_tests` → **4 passed**;
  `run_124_snapshot_restore_authority_marker_tests` → **7 passed**;
  `run_140_snapshot_restore_v2_authority_marker_tests` → **13 passed**.
* `cargo check -p qbind-node` (default production features, dev) → **Finished, exit
  0**.
* `cargo clippy -p qbind-consensus -p qbind-node --lib` → **Finished, no errors**;
  all reported warnings are **pre-existing** and outside the C3E-edited line
  ranges (verified by line-range filtering the C3E gate, counters, imports, test
  module, and the `qc_verify_domain.rs` doc-comment block — zero warnings there).
* `cargo fmt -p qbind-node -p qbind-consensus -- --check` → reports diffs, but this
  is a **pre-existing, repo-wide** condition: unedited files such as
  `crates/qbind-consensus/src/basic_hotstuff_engine.rs` (LF, not touched here) also
  fail, and the diffs span the entire files rather than the C3E-edited regions. No
  reformatting of unrelated code was performed.
* `cargo build --release -p qbind-node --bin qbind-node` → **Finished release
  profile, exit 0**; binary at `target/release/qbind-node` (compilation evidence
  only — no production authority activation, and the release binary still refuses
  `--consensus-authority-from-genesis`).

Line endings preserved on every edited file (CRLF on the three docs and on
`binary_consensus_loop.rs`/`qc_verify_domain.rs`; verified `LFonly=0`). No
package-integrity anchor artifact changed, so no manifest refresh was required.

**Security tooling (reported literally).** `parallel_validation` was run; both
outcomes are recorded exactly as returned and are **incomplete / unverified**:

* **CodeQL (rust):** surface read "Found 0 alerts", but "Analysis was skipped
  because the database size is too large." A skipped analysis is **not** a passing
  scan; 0 alerts here means **not analyzed**, not clean.
* **Code review:** surface read "No review comments found" over 5 files, but the
  tool also reported it "is not available in this environment" with a
  model-registry error (`model claude-sonnet-4.6 not found in registry`). An
  unavailable reviewer is **not** a passing review; "no comments" here means **not
  reviewed**.

Neither result establishes a clean security posture. A skip, unavailable reviewer,
or model-registry error is recorded as incomplete/unverified regardless of any
"0 alerts"/"no comments" surface. `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`
is retained.

### Verdict and retained posture

`D7C3E_PRESENT_EMBEDDED_QC_ADMISSION=CODE-TEST-POSITIVE` — the real Required-policy
handler rejects invalid PRESENT embedded QCs before restore-deferral, delivery,
reconfiguration observation, engine mutation/view advancement, and outbound
handoff.

Explicitly **not** closed: absent-QC / no-QC bootstrap authorization, full
engine/QC adoption and retention, production lifecycle, and durable anti-rollback.
Retained markers unchanged: `D7_STATUS=PARTIAL-CODE-TEST /
PRODUCTION-LIFECYCLE-UNAVAILABLE`; `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. No readiness promotion,
production activation, PR, or Run 423 work.

## Run 422 D7-C3E — present-QC rejection completion + state-protection evidence (this pass, test + docs)

**Continuation, not a redesign.** This pass adds the missing present-QC
authorization-ordering rejection cases, Timeout non-substitution controls, and a
strengthened direct block-state protection test to the existing `run422_d7c3e`
module. The C3E production gate, C3D rules, D6 signing bytes, quorum policy, wire
IDs, and authority constructors are unchanged; the only edited file is
`crates/qbind-node/src/binary_consensus_loop.rs` (test code + test comments) plus
this evidence section. No `main.rs`, engine-API, protocol-byte, or package-integrity
anchor change; no manifest refresh required.

### Inspected state (recorded, not manufactured)

* **Working branch (inspected):** `copilot/copilotcopilotcopilotcopilotcopilotrun-422-d7-c3c`.
  This differs from the problem statement's reported branch
  `copilot/copilotcopilotcopilotcopilotrun-422-d7-c3c-again-a`; reported as a
  deviation without fabricating ancestry.
* **Starting HEAD (pre-C3E-continuation):** `1391c88` (`update`), parent `bee45c9`.
* **Reviewed revision `722a093dee50841006e737bfe573ceed1a67ee03`:** object **absent**
  in this shallow clone (`git cat-file -t` fails). Missing history is distinguished
  from missing implementation: the C3E gate and the prior `run422_d7c3e` module
  (22 tests) were **present** in the worktree and executed green before this pass.
* Existing helpers were reused rather than duplicated: the D7-A snapshot builders
  (`snapshot_superseded`), `coherent_snapshot_for` / `coherent_authority_for`, the
  checked-overflow exhaustion latch (`set_generation_for_exhaustion_fixture` +
  `replace_for_fixture`), the `C3eCountingVerifier` / `counting_registry`
  instrumentation, `D7ActionRecorder`, and the F6 `pv_binding_gate`. The existing
  UNAVAILABLE case (`c3e_g_unavailable_authorization_prevents_qc_verification`) is
  reused and **not** re-implemented.

### New present-QC authorization-ordering cases (section 2)

Each delivers a correctly encoded, correctly OUTER-signed Proposal carrying a
genuine D6-signed quorum (`valid_quorum`) through the real
`handle_inbound_consensus_msg` `Proposal` arm under `Required`, with matching F6
identity and coherent fixtures. Each asserts the **exact existing** rejection
counter, **zero** outer/constituent verification where admission must stop first
(instrumented `C3eCountingVerifier` proposal/vote counts and the crypto-latency
observation counter all `0`), **unchanged** QC-gate counters
(`inbound_proposal_embedded_qc_verified_total` /
`inbound_proposal_embedded_qc_rejected_total` = 0,
`inbound_proposal_engine_context_mismatch_total` = 0), and **no** delivery,
deferral, reconfiguration observation, engine mutation, or facade effect:

* **No P/V authority AND no current snapshot** →
  `c3e_k_no_authority_no_snapshot_rejects_before_verification`: F6 admits, then
  `inbound_proposal_verification_context_unavailable_total == 1`.
* **Present P/V authority but missing current snapshot** →
  `c3e_k_present_authority_missing_snapshot_rejects_before_verification`:
  `inbound_proposal_current_state_unavailable_total == 1`; the present authority's
  instrumented backend proves zero outer/QC verification.
* **Unavailable current authorization** → reused existing
  `c3e_g_unavailable_authorization_prevents_qc_verification` (not duplicated).
* **Superseded current authorization** →
  `c3e_k_superseded_current_authorization_prevents_qc_verification`:
  `inbound_proposal_authority_superseded_total == 1`.
* **Terminally exhausted current authorization** →
  `c3e_k_exhausted_current_authorization_prevents_qc_verification`: drives the
  **checked-overflow terminal latch** (generation positioned at `u64::MAX`, then one
  `replace_for_fixture` whose `generation + 1` cannot be represented sets
  `exhausted = true`) — asserted via `admit()` returning
  `FreshnessError::AuthorizationExhausted` — not a bare generation set to MAX;
  `inbound_proposal_authorization_exhausted_total == 1`.

The **authorized control** demonstrating the same message can reach outer and QC
verification is the retained `c3e_a_*` / `c3e_f_a_*` positive controls (control
backend counts are kept in separate authorities from the rejection measurements).

### Timeout non-substitution controls (section 3)

`counting_timeout_ctx` builds a valid, populated `TimeoutVerificationContext`
(shared fixture membership/keys, an **instrumented** backend registry, and a live
`LocalKeySigner` — `signer.is_some()`). Repeating the two missing-context
present-QC cases with this context wired proves it supplies neither the missing
Proposal/Vote authorization nor any QC verification:

* **Missing authority + valid Timeout context** →
  `c3e_l_timeout_context_does_not_supply_missing_authority`: still
  `inbound_proposal_verification_context_unavailable_total == 1`; the Timeout
  context's instrumented backend recorded **0** proposal and **0** vote
  verifications.
* **Missing snapshot + valid Timeout context** →
  `c3e_l_timeout_context_does_not_supply_missing_snapshot`: still
  `inbound_proposal_current_state_unavailable_total == 1`; **both** the Timeout
  context's backend and the present authority's backend recorded **0**/**0**.

No alternate authority mechanism is introduced; existing fixtures are reused and
the type-level Timeout↔P/V separation (no `From` conversion) is unchanged.

### Strengthened state protection (section 4)

The state-protection pair is now an **isolated control**: the invalid-QC case
(`c3e_i_future_view_invalid_qc_no_state_change`) and its valid-QC control
(`c3e_i_valid_qc_control_reaches_engine_and_registers_block`) are built by a single
shared setup (`c3e_state_fixture`) so the two deliveries share an **identical**
environment — the same membership, epoch, and initial view; the same bound
authority + admitted domain; an instrumented backend (with per-case-isolated
counters); an available local signer; a recording facade; and the same Proposal
header/payload. Both deliver from **proposer 2**, which is asserted to equal
`engine.leader_for_view(6)`, and each outer Proposal is **re-signed after** its QC
is attached, so both outer signatures are valid under the admitted domain. The
**only** thing that varies between the two cases is the embedded QC's signing
domain/signatures — correcting the earlier "matching control" gap where the
invalid case used a non-leader proposer (1) while its control used proposer 2.

Both cases run against a **coherent nonempty-state fixture**
(`initialize_from_snapshot_baseline(anchor, 4)` — committed height 4, one anchored
block, resume at view 5), so they demonstrate preservation/transition of
**existing** state, not merely the absence/presence of a new commit. State is
compared before vs. after directly through the engine/state APIs: `current_view()`,
`locked_height()`, `locked_qc()` (the engine derives `TimeoutMsg.high_qc` from its
locked QC — there is no separate high-QC store), `committed_height()`,
`committed_block()`, `commit_log()`, and the block store via
`state().block_count()`, `state().blocks_iter()`, and `state().get_block(...)`.

The "block contents unchanged" claim is now backed by a **field-level** comparison,
not just an id-set: a test-local projection reads each pre-existing `BlockNode`'s
`id`, `view`, `parent_id`, `height`, `justify_qc`, and `own_qc` (QC fields compared
structurally via `QuorumCertificate`'s derived `PartialEq`; no production getter or
engine behavior is added) into an id→fields map, and asserts every pre-existing
entry is identical before and after. The **candidate block** the Proposal would
register is derived exactly as the engine derives it (`derive_block_id_from_header`,
reproduced test-locally) and asserted **absent before and after** the rejection, and
**absent before / present after** the valid control.

For the invalid case (height 6, valid outer signature, foreign-domain embedded QC)
the delivery reaches **outer acceptance** (`inbound_proposal_verify_accepted == 1`)
and **constituent QC verification** (instrumented backend recorded ≥1 vote) and then
**rejects** the QC (`inbound_proposal_embedded_qc_rejected_total == 1`); every state
observation, the full block-content projection, both anchor and candidate presence,
and the id-set are unchanged, with no reconfiguration observation, delivery,
deferral, engine acceptance, or facade action. `inbound_proposals_engine_accepted ==
0` is **not** treated as standalone proof the engine was never entered — it is
asserted as corroboration alongside the direct state observations and inspected call
ordering. The valid control reaches engine acceptance, advances to view 6, verifies
the QC, and registers exactly one new block (`block_count` +1, one new id in
`blocks_iter` equal to the derived candidate, pre-existing entries preserved
field-for-field) and produces the expected single facade action, proving the fixture
is genuinely capable of the transition the invalid case suppresses. The fixture is
described honestly as an in-memory seeded baseline — not authenticated catch-up,
persistent recovery, or durable freshness.


### State-protection control isolation (this correction pass)

This sub-pass corrects the state-protection pair only (tests + comments in
`binary_consensus_loop.rs` and this C3E subsection); no production, authorization,
history, activation, or Run 423 change.

* **Actual working branch (inspected):** `copilot/copilot-run-422-d7-c3c`. This
  differs from the problem statement's reported branch
  `copilot/copilotcopilotcopilotcopilotcopilotrun-422-d7-c3c`; reported as a
  deviation without fabricating ancestry.
* **Starting HEAD:** `9f812c4` (`update`).
* **Reviewed revision `1a33547a0f639ea3a5f8eac063b9ccee97d3faed`:** object **absent**
  in this shallow clone (`git cat-file -t` fails). Missing history is distinguished
  from missing implementation: the `run422_d7c3e` module (29 tests) and the C3E gate
  were **present** in the worktree and executed green before and after this pass.
* **What changed:** both `c3e_i_*` cases now share a single `c3e_state_fixture`
  (identical membership/epoch/view, bound authority + admitted domain, instrumented
  backend with per-case-isolated counters, available local signer, recording facade,
  Proposal header/payload); both deliver from **proposer 2** with a matching
  authenticated origin, asserting the proposer equals `engine.leader_for_view(6)`;
  each outer Proposal is re-signed after its QC is attached; and the only variation
  is the embedded QC's signing domain/signatures. Block-state evidence was
  strengthened from an id-set check to a field-level `BlockNode` projection (`id`,
  `view`, `parent_id`, `height`, `justify_qc`, `own_qc`, QC compared structurally)
  plus explicit candidate-block presence assertions (absent before/after rejection;
  absent before / present after the valid control) using a test-local reproduction of
  the engine's block-id derivation. No production getter or engine behavior was added.
  The test count is unchanged at **29** (existing cases strengthened, none added).

### Validation (this pass) — exact commands, counts, exit codes

Test-and-documentation-only change (no production logic touched); per policy a
release build is **not** repeated — its historical attribution above is retained.

* `cargo test -p qbind-node --lib run422_d7c3e` (dev) → **29 passed; 0 failed; 0
  ignored; 1590 filtered out**, exit 0. (Was 22 at the prior pass; +7:
  `c3e_i_valid_qc_control_reaches_engine_and_registers_block`, four `c3e_k_*`, two
  `c3e_l_*`. This correction pass strengthened the two `c3e_i_*` cases without
  changing the count.)
* `cargo test -p qbind-node --lib binary_consensus_loop` (dev) → **240 passed; 0
  failed; 0 ignored; 1379 filtered out**, exit 0. The `run422_d7c3e` set (29) is a
  strict subset of this suite (240).
* `cargo clippy -p qbind-node --lib` (dev) → **Finished, exit 0**; all reported
  warnings are pre-existing and outside the C3E-edited ranges (e.g.
  `cert_bound_node_id` dead-code in `p2p_node_builder.rs`); none reference the
  `run422_d7c3e` module.
* CRLF-aware whitespace / changed-region formatting: every edited file remains CRLF
  (`binary_consensus_loop.rs` and this doc; verified no LF-only lines); no
  added line carries trailing whitespace before the CR; unrelated formatting and
  line endings were left untouched.

### Security tooling (reported literally)

`parallel_validation` outcomes are recorded exactly as returned:

* **CodeQL (rust):** recorded literally. A skipped or size-limited analysis is
  **incomplete** — "0 alerts" from a skip means **not analyzed**, not clean.
* **Code review:** recorded literally. An unavailable reviewer / model-registry
  error is **not** a successful review — "no comments" then means **not reviewed**.

Neither establishes a clean security posture.

### Retained posture (unchanged)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. Absent-QC / bootstrap
authorization, full engine/QC evidence retention, production lifecycle, and durable
anti-rollback remain open. No readiness promotion, production activation, or Run 423
work.
## Run 422 D7-C3F — retain verified embedded-QC evidence at engine block registration (code + test)

**Continuation, not a redesign.** This pass consumes the `VerifiedQuorumCertificate`
that the existing C3E gate already produces for a PRESENT embedded QC and passes it,
under the SAME admitted snapshot, into an explicit engine ingestion path that retains
the complete verified evidence with the proposed block's justification. No second
verifier, validator registry, signing domain, or block-ID algorithm is introduced;
the C3D verifier and C3E admission protections are preserved unchanged.

### Inspected state (recorded, not manufactured)

* **Working branch (inspected):** `copilot/copilot-run-422-d7-c3c-again`. The problem
  statement's reported branch is `copilot/copilot-run-422-d7-c3c`; recorded as a
  deviation without fabricating ancestry.
* **Starting HEAD:** `860d1ed` (`update`). **Production checkpoint:** `935c662`.
  **Tests checkpoint:** `c7f5819`.
* **Accepted C3E revision `ffb82a5dc322e9bc2a04ccfd6b18af440b4c4078`:** object **absent**
  in this shallow clone. Missing history is distinguished from missing implementation:
  the C3D verifier (`qc_verify_domain.rs`) and the C3E gate + `run422_d7c3e` module were
  **present** in the worktree and executed green before this pass.

### Reuse map (no new verifier / registry / domain / block-ID)

* `VerifiedQuorumCertificate` + `verify_quorum_certificate_with_domain` (C3D) — the ONLY
  source of verified evidence; retained as-is.
* The C3E Proposal-handler gate and its retained `_retained_verified_qc` result — now
  consumed instead of discarded.
* `BasicHotStuffEngine::on_proposal_event` — refactored into a thin wrapper over a shared
  private `ingest_proposal`; the legacy proposal-processing logic is reused, not copied.
* `BlockNode`, `HotStuffStateEngine::register_block`, block replacement/eviction — reused
  for evidence ownership, replacement and reclamation via a single insert choke point.
* Logical `QuorumCertificate` serde type and Timeout/NewView serialization — **unchanged**;
  evidence is stored in a separate, non-serialized `Arc<VerifiedQuorumCertificate>` handle.
* Existing C3E test helpers (`counting_registry`/`C3eCountingVerifier`, `D7ActionRecorder`,
  `coherent_snapshot_for`, `c3e_state_fixture`, `c3e_candidate_block_id`, `deliver`,
  `valid_quorum`, `build_signed_qc`, `proposal_with_qc`) — reused, not re-implemented.

### What changed (production)

* `crates/qbind-consensus/src/block_state.rs`: `BlockNode` gains a non-serialized
  `verified_justification: Option<Arc<VerifiedQuorumCertificate>>` plus a
  `with_verified_justification` builder. `BlockNode::new` sets it `None`, so restart/
  baseline/legacy nodes never manufacture verified evidence.
* `crates/qbind-consensus/src/qc_verify_domain.rs`: `VerifiedQuorumCertificate::retained_byte_size()`
  (fixed overhead + signature buffers + bitmap + signer-id list, saturating) for checked
  byte accounting.
* `crates/qbind-consensus/src/hotstuff_state_engine.rs`: a dedicated retained-evidence byte
  budget (`DEFAULT_MAX_RETAINED_EVIDENCE_BYTES = 256 MiB`, configurable via
  `set_max_retained_evidence_bytes`), running `retained_evidence_bytes`, a
  `rejected_evidence_over_budget` counter, a pure `can_retain_evidence` pre-check, a single
  `insert_block_node` accounting choke point (reclaims same-id evidence, adds new), a
  `remove_block_and_reclaim` used by eviction, and
  `register_block_with_verified_justification(...) -> Result<(), EvidenceRetentionError>`.
  The retention budget is a **separate** engine-level bound, NOT `ConsensusLimitsConfig`
  (which is `Copy` with exhaustive struct-literals in out-of-scope tests); block-count
  limits alone are not described as a byte bound.
* `crates/qbind-consensus/src/basic_hotstuff_engine.rs`: `VerifiedProposalIngestError`
  (`MissingEmbeddedQc`, `EvidenceCertificateMismatch`, `WireChainMismatch`, `EpochMismatch`,
  `RetentionBudgetExceeded`) and `on_verified_proposal_event(from, proposal, evidence)`. Before
  any engine mutation it: requires a present QC; checks `evidence.certificate() == qc` (WireQC
  derives `Eq` ⇒ all wire fields, bitmap and signature bytes); checks proposal↔evidence wire-chain
  and epoch correspondence; and pre-checks the retention budget for the exact derived block id.
  It never rewrites a Proposal or QC and performs **no** second constituent-signature verification.
* `crates/qbind-node/src/binary_consensus_loop.rs`: the Required, present-QC handoff now calls
  `engine.on_verified_proposal_event(...)` with the evidence returned by ITS OWN C3E verification;
  `Ok` increments `inbound_proposal_verified_qc_handoff_total`; any typed `Err` increments
  `inbound_proposal_verified_qc_handoff_rejected_total`, logs, and returns **fail-closed with no
  legacy fallback**. Absent-QC and the test-only `LocalFixtureUnsigned` passthrough keep the legacy
  `on_proposal_event` entrypoint (no retained evidence). Handler-delivery accounting is kept
  distinct from engine acceptance.

### Ownership, lifecycle and resource bounds

* Evidence is stored ONLY as the block's `verified_justification` (justifies the parent), never in
  `own_qc`; a retained certificate therefore never becomes a certificate for the child block itself.
* Block replacement, legacy re-registration and eviction all route through the insert/remove choke
  points: an unverified replacement drops any earlier verified designation and reclaims its bytes; a
  removed block releases its evidence; retained bytes never grow unbounded.
* A new retention that cannot be accommodated is rejected BEFORE engine mutation
  (`RetentionBudgetExceeded` / `EvidenceRetentionError::BudgetExceeded`), with the failure counted
  at the engine boundary (`rejected_evidence_over_budget`, and the loop's
  `inbound_proposal_verified_qc_handoff_rejected_total`).

### Behavioral tests (module `run422_d7a::run422_d7c3e::c3f`, 8 tests)

Real D6/PQC verification, reusing accepted C3E fixtures:

* **A** `c3f_a_real_handler_retains_exact_verified_evidence` — real handler positive: after the
  handler returns, the registered child block retains the exact certificate, signatures, bitmap,
  domain, epoch, signer identities `[0,1,2]`, voting power `3` and threshold `3`; the certified
  block id (`[9;32]`) differs from the child candidate.
* **B** `c3f_b_evidence_for_a_rejected_against_proposal_carrying_b` — evidence for QC A cannot
  accompany a Proposal carrying QC B (same logical block/view, different genuine quorum) →
  `EvidenceCertificateMismatch` before any engine mutation.
* **C** `c3f_c_retained_evidence_independent_of_caller_wire_input` — mutating/dropping the caller's
  wire input does not alter retained evidence.
* **D** `c3f_d_engine_retention_adds_no_second_qc_verification` — direct backend counts: one up-front
  constituent-vote pass (`votes == 3`); engine ingestion adds `0`.
* **E** `c3f_e_invalid_qc_retains_no_evidence_positive_control_does` — invalid (foreign-domain) QC:
  no handoff, no view advance, no block, no retained evidence, no facade action; matching positive
  control retains.
* **F** `c3f_f_replacement_and_removal_lifecycle` — real state-engine replacement (unverified replacement
  does not inherit; bytes reclaimed) and eviction (evidence released; bytes reclaimed).
* **G** `c3f_g_resource_limits_checked_accounting` — exact-capacity accept (`retained == max`),
  over-capacity reject (typed `BudgetExceeded`, block absent, `retained == 0`,
  `rejected_evidence_over_budget == 1`), replacement accounting (no double-count), and real-handler
  over-budget rejection (`handoff_rejected == 1`, no view advance, no retained evidence).
* **H** `c3f_h_absent_qc_and_typed_contract_errors` — absent-QC compatibility preserved (no handoff,
  no retention) plus typed `MissingEmbeddedQc` / `WireChainMismatch` / `EpochMismatch`.

### Validation — exact commands, profiles, exit codes (exit 0 unless noted)

Tested SHA `c7f5819`; final SHA recorded at the closing checkpoint of this pass.

* `cargo test -p qbind-node --lib run422_d7a::run422_d7c3e::c3f` → **8 passed** (dev).
* `cargo test -p qbind-node --lib binary_consensus_loop` → **248 passed** (includes `run422_d7c3e`).
* `cargo test -p qbind-consensus --lib` → **182 passed**.
* `cargo test -p qbind-consensus --test run_422_d7c3d_qc_domain_verification_tests` → **46 passed** (C3D).
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` → **34 passed** (D6).
* Block-state/engine: `consensus_state_tests` **8**, `consensus_state_memory_limits_tests` **7**,
  `commit_log_memory_limits_tests` **6** (1 ignored), `hotstuff_state_tests` **15**,
  `hotstuff_state_commit_tests` **7**, `basic_hotstuff_engine_sims_tests` **6** — all passed.
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests` → **3 passed**.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` → **4 passed** (startup refusal preserved).
* `cargo check -p qbind-node` (default production features) → **exit 0**.
* `cargo clippy -p qbind-consensus --lib` and `-p qbind-node --lib` → no new warnings in the C3F-edited
  regions (pre-existing repo warnings unchanged; e.g. `is_safe_to_vote_at_height` match-like-matches is
  pre-existing and untouched).
* `rustfmt --check` on the changed consensus files: the C3F-authored lines are conformant; the repo is
  broadly non-`rustfmt`-clean pre-existing (dozens of unrelated files flagged), so no repo-wide
  reformat was performed (unrelated formatting left untouched).
* Release build: `cargo build -p qbind-node --release` — recorded at the closing checkpoint.

### Security tooling (reported literally)

`parallel_validation` was run (production-source changes; declared **non-trivial** for CodeQL). Outcomes
recorded exactly as returned:

* **CodeQL (rust): INCOMPLETE / UNVERIFIED.** Returned literally: "Analysis was skipped because the
  database size is too large. Found 0 alerts." A skipped analysis means **not analyzed** — the "0 alerts"
  is **not** a clean result and does not establish CodeQL coverage for this change.
* **Code review: UNVERIFIED.** The tool reported "Reviewed 9 file(s). No review comments found," but also
  emitted a model-registry error (`model claude-sonnet-4.6 not found in registry`) and noted the reviewer
  "is not available in this environment." An unavailable reviewer is **not** a successful review; "no
  comments" here means **not reviewed**.
* **secret_scanning:** run on the changed source and doc files — no secrets detected.

Neither CodeQL nor the reviewer establishes a clean security posture for this change; both are recorded as
incomplete/unverified rather than converted into a pass.

### Retained posture (unchanged)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. Retaining an inbound embedded QC does not close the full
engine/QC pipeline: absent-QC/bootstrap authorization, outbound QC reconstruction/propagation,
Timeout/NewView certificate migration, persistent evidence storage/recovery, production authority
lifecycle/activation, durable anti-rollback and Run 423 remain separate, open obligations.
## Run 422 D7-C3F — CORRECTION: retention postconditions, resource accounting and evidence association (code + test)

**Bounded correction of the C3F pass above — not a new phase.** This subsection records
newly-run commands and measured guarantees for three defects found in the C3F retention
path. The C3D/C3E work and the original C3F handoff/ownership tests are preserved.

### Inspected state (recorded, not manufactured)

* **Working branch (inspected):** `copilot/copilotcopilot-run-422-d7-c3c-again`.
* **Starting HEAD:** `066d8c9` (`update`) — worktree clean, shallow clone (depth 2).
* **Reviewed revision `20b9e052c6109e095159bbb6c7df2be564e5cb58`:** object **absent** in this
  shallow clone (missing history, distinguished from missing implementation — the C3D
  verifier, the C3E gate and the C3F retention path were all present and executed green
  before this correction).

### Defects reproduced (then fixed; kept as regressions)

* **A — retention postcondition violated under block-slot pressure.**
  `register_block_with_verified_justification` inserted the candidate and then called
  `evict_blocks_if_needed()`, which could evict the just-registered candidate while still
  returning success; the engine path (`ingest_proposal`) discarded the registration
  `Result` via `let _ =`, so a vote could be emitted with the block/evidence no longer
  stored. Now: admission is decided **before** mutation (byte budget + block-slot), the
  candidate is **never** evicted to make room (only other safe-to-evict blocks are), the
  discarded `Result` is removed, and any failure propagates as a typed
  `VerifiedProposalIngestError::RetentionCapacityUnavailable` / `RetentionBudgetExceeded`
  before view advancement, block-tree changes, self-voting or outbound effects.
* **B — resource accounting.** `retained_byte_size` used a fixed 128-byte constant plus
  `len()` (not `capacity()`) of the signature buffers/bitmap/signer list, omitted the
  `VerifiedQuorumCertificate` struct value and the outer `Vec<Vec<u8>>` descriptor storage,
  and used `saturating_add`, so an overflowing projected total could saturate into an
  admissible value. Now `retained_byte_size(&self) -> Result<u64, RetainedByteSizeError>`
  charges: the struct value (`size_of`, covering inline `Vec` descriptors), the signer-bitmap
  capacity, the outer signatures descriptor storage (`capacity * size_of::<Vec<u8>>()`), each
  constituent signature-buffer capacity, and the signer-vector capacity, using only checked
  conversion/add/mul; an unrepresentable total rejects explicitly. Allocator/process-wide
  overhead and externally retained `Arc` handles are documented as outside the model.
  `can_retain_evidence` uses `checked_add` so projected-total overflow is inadmissible.
* **C — evidence association at the storage boundary.** The public
  `register_block_with_verified_justification` accepted a caller-supplied
  `justify_qc: Option<...>` and the direct path accepted `None` or a mismatching value. The
  parameter is removed; the logical justification is now **derived from the verified
  evidence** (block id = `certificate().block_id`, view = `certificate().height`, signers =
  `evidence.signers()`). Evidence stays separate from `own_qc` and retains its original
  certificate/domain/epoch metadata; no new parent/round/bootstrap rule is introduced.

### What changed (production, this correction)

* `qc_verify_domain.rs`: `retained_byte_size` is now checked/fallible with the accounting
  model above; `RetainedByteSizeError` + checked helpers added; re-exported from `lib.rs`.
* `block_state.rs`: `BlockNode` stores a per-node `verified_justification_charge: u64` (0 when
  no evidence); `with_verified_justification(evidence, charge)` sets both, validated
  independently of `retained_byte_size` on both sides of an assertion.
* `hotstuff_state_engine.rs`: `EvidenceRetentionError` gains `SlotCapacityUnavailable` and
  `UnrepresentableCharge`; new `can_admit_block_slot` (pure) and `reserve_block_slot_for_new`
  (atomic; evicts only OTHER safe blocks, rejects up front on deficit, never touches the
  candidate); `register_block_with_verified_justification` drops `justify_qc`, derives it from
  evidence, and admits byte + slot before any insert with no post-insert eviction of the
  candidate.
* `basic_hotstuff_engine.rs`: `VerifiedProposalIngestError` gains
  `RetentionCapacityUnavailable` and `RetentionChargeUnrepresentable`;
  `on_verified_proposal_event` pre-checks checked-charge, byte budget and block-slot capacity
  before `ingest_proposal`; `ingest_proposal` propagates the registration failure (no vote,
  no panic, no rollback). New `BasicHotStuffEngine::with_state_limits` builds the engine with
  custom `ConsensusLimitsConfig` so block-slot pressure is exercisable through the full path.
* `binary_consensus_loop.rs`: C3F tests updated to the corrected API; three new regressions
  added; the real-handler positive strengthened to exact backend counts.

### Rejection counting (each path counts once)

The engine preflight calls `note_rejected_evidence_over_budget()` before returning
`RetentionBudgetExceeded` and does not call `ingest_proposal`; the direct registration path
increments its own `rejected_evidence_over_budget` exactly once. Block-slot rejection is
counted by the loop as `inbound_proposal_verified_qc_handoff_rejected_total`. Diagnostic
counters may change on rejection; consensus and block state do not.

### Behavioral tests (module `run422_d7a::run422_d7c3e::c3f`, now 11 tests)

The 8 original tests A–H are preserved (A strengthened to assert EXACTLY `proposals()==1`
and `votes()==3`, proving no duplicate QC verification — the previous `votes() >= 3` could
not). Three new regressions:

* **I** `c3f_i_block_slot_pressure_rejects_without_candidate_retention` — protected committed
  anchor + `max_pending_blocks==1` + ample byte budget: the real handler rejects with
  `handoff_rejected_total==1`, no view advance, no engine acceptance, candidate never stored,
  anchor never evicted, no facade action; a `max_pending_blocks==2` control retains the
  candidate and its exact evidence.
* **J** `c3f_j_checked_accounting_rejects_overflow_and_charges_owned_allocations` — the charge
  strictly exceeds `size_of::<VerifiedQuorumCertificate>()` (owned allocations counted); with
  the maximum budget and a nonzero retained charge, `can_retain_evidence(_, u64::MAX)` is
  rejected (checked, not saturated); exact-limit and one-over boundaries via pure arithmetic.
* **K** `c3f_k_logical_justification_is_derived_from_verified_evidence` — the stored
  `justify_qc` is derived from the evidence (block id/view/signers), certifies the parent not
  the child, and `own_qc` stays `None`.

### Validation — newly-run commands this correction (dev profile, exit 0 unless noted)

Starting SHA `066d8c9`; final SHA recorded at the closing checkpoint.

* `cargo test -p qbind-node --lib run422_d7a::run422_d7c3e::c3f` → **11 passed**.
* `cargo test -p qbind-node --lib run422_d7c3e` → **40 passed**.
* `cargo test -p qbind-node --lib binary_consensus_loop` → **251 passed**.
* `cargo test -p qbind-consensus --lib` → **182 passed**.
* `cargo test -p qbind-consensus --test run_422_d7c3d_qc_domain_verification_tests` → **46 passed** (C3D).
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` → **34 passed** (D6).
* `cargo test -p qbind-consensus --test consensus_memory_limits_tests` → **19 passed**;
  `--test consensus_state_memory_limits_tests` → **7 passed**;
  `--test commit_log_memory_limits_tests` → **6 passed** (1 ignored).
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests` → **3 passed**.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` → **4 passed** (startup refusal preserved).
* `cargo check -p qbind-node` (default production features) → **exit 0**.
* `cargo clippy -p qbind-consensus --lib` → the changed regions produce **no** warnings; all
  reported warnings are pre-existing and in unrelated files/lines (e.g. `basic_hotstuff_engine.rs:2077`
  match-like-matches in `is_safe_to_vote`, and `slashing/mod.rs`, `adversarial_multi_sim.rs`).
* `rustfmt`: changed-region formatting only. The two touched CRLF-committed files
  (`qc_verify_domain.rs`, `binary_consensus_loop.rs`) were left with their original CRLF line
  endings (a repo-wide `rustfmt` run would rewrite them entirely to LF and is not performed).
* Release build: `cargo build --release -p qbind-node` — outcome recorded at the closing checkpoint.

### Security tooling (recorded literally)

Outcomes of `parallel_validation` / `secret_scanning` for this correction are recorded exactly
as returned at the closing checkpoint; a skipped CodeQL analysis or an unavailable reviewer is
recorded as **incomplete/unverified**, never converted into a pass.

### Retained posture (unchanged by this correction)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. This correction fixes retention
postconditions, accounting and evidence association only; absent-QC/bootstrap authorization,
outbound QC reconstruction, Timeout/NewView migration, persistent storage/recovery, production
authority lifecycle/activation, durable anti-rollback and Run 423 remain separate, open obligations.
## Run 422 D7-C3F — CORRECTION (continuation): preserve candidate metadata during eviction + independent allocation accounting (code + test)

**Bounded continuation of the C3F correction above — not a new phase.** This subsection
closes the eviction-order height regression and the incomplete allocation-accounting test
identified in the reviewed C3F correction, and finalizes this correction's provenance. All
prior C3D/C3E/C3F work and tests are preserved; `task/warning.txt` and unrelated task files
are untouched.

### Inspected state (recorded, not manufactured)

* **Working branch (inspected):** `copilot/copilot-run-422-d7-c3f`.
* **Starting HEAD:** `5a327ed` (`update`) — worktree clean, shallow single-branch clone.
* **Reviewed branch named in the task** (`copilot/copilotcopilot-run-422-d7-c3c-again`) and
  **reviewed tip `f88e6fc67bc18649815c73c1aa79c5a2025cc420`:** object **absent** from this
  shallow clone (missing history, distinguished from missing implementation — the C3D
  verifier, C3E gate and C3F retention path were all present and executed green here).
* **Tested code checkpoint (recorded before validation):**
  `5cedb9ca6b55cb4931d632730f7f390237978203`.

### Correction A — candidate metadata survives capacity reservation

`register_block_with_verified_justification` computed the candidate's `height` from
`self.blocks.get(parent)` **after** calling `reserve_block_slot_for_new`, which can evict a
safe-to-evict parent to make block-slot room. Evicting the known parent made the later
lookup fall back to height zero, so a candidate whose parent was at height 5 registered at
height 0 instead of 6. **Fix (smallest):** the state-dependent metadata (`height`) is now
derived from the **pre-eviction** state — computed before `reserve_block_slot_for_new`.
Genuinely missing parents still register at height 0; no new parent/QC linkage, bootstrap
policy or consensus redesign is introduced. All prior guarantees are preserved (capacity
rejection precedes mutation; the candidate is never evicted to fake retention success;
protected blocks stay protected; evidence association, byte accounting, replacement and
reclamation are unchanged; no vote/outbound action follows a retention rejection).

### Correction B — independently verify the allocation charge

The prior `c3f_j` assertion only proved the charge exceeds
`size_of::<VerifiedQuorumCertificate>()`, not that every required component is included. A
new in-module test (under `cfg(test)` in `qc_verify_domain.rs`, so it can inspect private
allocation capacities) starts from **genuinely verified** evidence, grows each heap
component's allocation **capacity** above its length without changing certificate contents,
and asserts `retained_byte_size` equals the documented component sum — struct value +
bitmap capacity + outer signatures-vector descriptor capacity + each constituent
signature-buffer capacity + signer-vector capacity — computed WITHOUT calling
`retained_byte_size`. Because capacity > length for every component, the test detects both
the omission of any required component and the substitution of length for capacity. The
useful projected-total overflow test is preserved. No production mutation API or unchecked
evidence constructor is exposed.

### What changed (this continuation)

* `hotstuff_state_engine.rs`: in `register_block_with_verified_justification`, the `height`
  computation is moved ahead of `reserve_block_slot_for_new` (pre-eviction derivation);
  logic otherwise unchanged.
* `qc_verify_domain.rs`: new `#[cfg(test)] mod c3f_expected_charge_tests` with the
  independent expected-charge assertion (real ML-DSA-44 evidence; capacity-inflation helper
  that preserves contents).
* `binary_consensus_loop.rs`: new regression
  `c3f_l_eviction_preserves_candidate_height_and_evidence` added to module
  `run422_d7a::run422_d7c3e::c3f` (the protected-anchor rejection test `c3f_i` is retained).
* `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2.md` (§9C) and
  `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` (§13): narrow
  descriptions of the pre-eviction metadata derivation and strengthened accounting.

### Behavioral tests (module `run422_d7a::run422_d7c3e::c3f`, now 12 tests)

* **L** `c3f_l_eviction_preserves_candidate_height_and_evidence` — real handler/engine path:
  protected committed anchor A (height 4) + unprotected child P (height 5) fill both slots
  (`max_pending_blocks==2`) with ample byte budget; admitting candidate C (parent P) evicts
  P and registers C at **height 6, not 0**, with exactly one eviction, the protected anchor
  preserved, the exact verified evidence retained, the derived logical justification
  (certificate parent block id/height/signers) correct, and
  `retained_evidence_bytes == charge(retained)`. An otherwise-identical free-slot control
  (`max_pending_blocks==3`) registers the SAME height 6 with no eviction and P retained.

### Allocation-accounting test (`qc_verify_domain`, +1 test)

* `c3f_b_expected_charge_sums_every_capacity_component` — independent expected-charge model
  as above; asserts equality with `retained_byte_size`, that dropping any single component
  changes the total (omission detected), and that a length-substituted model is strictly
  smaller and unequal (capacity, not length).

### Validation — newly-run commands this continuation (dev profile unless noted, exit 0)

Tested checkpoint SHA `5cedb9ca6b55cb4931d632730f7f390237978203`; final SHA recorded at the
closing checkpoint of this pass.

* `cargo test -p qbind-node --lib run422_d7a::run422_d7c3e::c3f` → **12 passed**.
* `cargo test -p qbind-node --lib run422_d7c3e` → **41 passed** (overlaps the C3F subset).
* `cargo test -p qbind-node --lib binary_consensus_loop` → **252 passed** (overlaps the two above).
* `cargo test -p qbind-consensus --lib` → **183 passed** (includes the new accounting test; +1 vs 182).
* `cargo test -p qbind-consensus --test run_422_d7c3d_qc_domain_verification_tests` → **46 passed** (C3D).
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` → **34 passed** (D6).
* `cargo test -p qbind-consensus --test consensus_memory_limits_tests` → **19 passed**;
  `--test consensus_state_memory_limits_tests` → **7 passed**;
  `--test commit_log_memory_limits_tests` → **6 passed** (1 ignored).
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests` → **3 passed**.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` → **4 passed** (startup refusal preserved).
* `cargo check -p qbind-node` (default production features) → **exit 0**.
* `cargo clippy -p qbind-consensus --lib` and `-p qbind-node --lib` → **no new warnings** in the
  changed regions; all reported warnings are pre-existing and in unrelated files/lines
  (`basic_hotstuff_engine.rs:2075`, `slashing/mod.rs`, `adversarial_multi_sim.rs`, etc.).
* `rustfmt --check` on `hotstuff_state_engine.rs` (LF file): the changed region is conformant;
  the only reported diff is a pre-existing end-of-file newline at `:1359`. The CRLF-committed
  files (`qc_verify_domain.rs`, `binary_consensus_loop.rs`) keep their CRLF endings and their
  changed regions have no trailing whitespace; no repo-wide reformat is performed.
* Release build: `cargo build --release -p qbind-node --bin qbind-node` → **Finished (exit 0)**,
  tested revision `5cedb9ca6b55cb4931d632730f7f390237978203`.

### Security tooling (recorded literally)

`secret_scanning` and `parallel_validation` (Code Review + CodeQL) outcomes for this
continuation are recorded exactly as returned at the closing checkpoint (below). A skipped
CodeQL analysis or an unavailable/errored reviewer is recorded as incomplete/unverified,
never converted into a pass or into "0 alerts".

* **`secret_scanning`** (changed files) → **no secrets detected**.
* **Code Review** → returned "reviewed 6 file(s), no review comments", but the run also
  reported a **backend error** ("Code review tool is not available in this environment …
  model claude-sonnet-4.6 not found in registry"). Per the record-literally rule, the empty
  result **after a backend error is treated as incomplete/unverified — NOT a clean review**.
* **CodeQL Security Scan** → reported "0 alerts" but with "Analysis was **skipped** because
  the database size is too large." Per the record-literally rule this is a **SKIPPED /
  not-run analysis — NOT 0-alerts-verified**. CodeQL was declared non-trivial (production
  consensus source changed) but could not execute here; a full CodeQL pass over the
  production-source correction remains **not captured**.

### Retained posture (unchanged by this continuation)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. This continuation fixes the eviction-order
height regression and strengthens allocation accounting only; absent-QC/bootstrap
authorization, outbound QC reconstruction, Timeout/NewView migration, persistent
storage/recovery, production authority lifecycle/activation, durable anti-rollback and Run 423
remain separate, open obligations. No production activation or readiness promotion is performed.

## Run 422 D7-D1 — Production authority lifecycle contract and reuse audit (documentation only)

**Documentation and source inspection only.** No Rust, test, configuration,
storage-schema, wire-format, workflow, or activation change. All prior D7 work,
`task/warning.txt`, and unrelated files are preserved.

### Inspected state (recorded, not manufactured)

* **Working branch (actual):** `copilot/copilotcopilot-run-422-d7-c3f`; the task's
  reported branch `copilot/copilot-run-422-d7-c3f` differs by the doubled
  `copilot` segment.
* **Worktree HEAD (actual):** `38339d697797aa320ab372fdd5849ab0b45e595b` (`update`),
  worktree clean before this pass.
* **Accepted C3F final revision `f97b49f72dc9af843d237f1758376096b58c08c1`:** object
  **absent** from this clone even after `git fetch --unshallow` (840 commits);
  not in local ancestry and not referenced by any tracked file. Ancestry to an
  absent object is not manufactured.
* **Accepted tested checkpoint `5cedb9ca6b55cb4931d632730f7f390237978203`:** object
  **absent** locally, but cited textually in the C3F correction subsections above
  as the tested revision. Missing history is distinguished from missing
  implementation: the C3D verifier, the C3E present-QC gate, and the C3F
  retention path are all present in this worktree.

### What D7-D1 produced

* New single authoritative contract
  `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`: inspected
  revision + source references (S1–S17); a reuse table
  (requirement -> symbol/path -> guarantee -> limitation -> reuse/adapt/missing);
  the proposed serialized-transition lifecycle and effect-boundary table; the
  durable-freshness / rollback threat model (T1–T6) with unresolved anchor
  decision; a first-release **Profile A (founding-authority-only)**
  recommendation; the dependency order; acceptance scenarios; and exactly one
  bounded next task.
* A short **successor reference** appended to
  `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` (§14).

### Reuse findings (summary)

* **Reuse (do not duplicate):** genesis verify + pin (S1), genesis authority
  builder (S2, dormant), founding-epoch guard (S3), fail-closed admission/owner
  (S4/S5), outbound + cached re-emission + restore-disposition (S6/S7/S8),
  storage observation (S9), genesis/network correspondence + alias mapping
  (S10/S11/S12), QC verifier (S13, dormant), present-QC gate (S14), verified
  retention (S15).
* **Missing (not satisfied by reuse):** a **durable, rollback-resistant current
  authorization** source (the production `CurrentAuthorizationOwner` constructor
  is `unavailable(...)`; `Established` is `cfg(test)` only) and an **independent
  freshness anchor** (S17 replay backend and the Run 055 sequence file are
  same-disk / disabled and have no anti-rollback). Replay prevention and crash
  consistency are **not** equated with rollback-resistant current authorization.

### Recommended lifecycle profile and next task

* **Profile A (founding-authority-only)** first; do not broaden the founding-epoch
  guard or treat fixed authority as removing restart/rollback safety.
* **Bounded next task (revised in the D7-D1 review correction below):** a
  **source characterization of existing signing-state persistence and recovery**
  for the same-epoch restart / restore case, through the real paths, keeping the
  **harness** recovery (`load_persisted_state` reading `get_last_committed` /
  `get_block` / `get_qc` then `initialize_from_restart`, `hotstuff_node_sim.rs:2049`)
  distinct from the **production binary** snapshot restore
  (`initialize_from_snapshot_baseline`, `binary_consensus_loop.rs:2390`, which reads
  neither `get_last_committed` nor any QC), plus `apply_epoch_transition_atomic`,
  `get_current_epoch`, and S9 `observe_consensus_storage` — characterizing what is
  restored vs dropped for an uncommitted Vote at epoch 0. The previously proposed generic
  **freshness-anchor / epoch-witness observation module is withdrawn** (a
  comparison classifies but cannot authenticate a caller-supplied value). Files,
  tests, prerequisites, and exclusions are enumerated in the corrected contract
  §9.

### Validation (documentation-only)

Source-reference, link/path, diff-scope, secret, and line-ending checks performed
below. No Cargo test/check/release rebuild is required for this phase; earlier
execution results are retained at their actual tested revisions. Available
review/security-tool outcomes are recorded literally in the final report.

### Retained posture (unchanged by D7-D1)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. This phase proposes a lifecycle
and audits reuse only; it does not activate authority, promote readiness, or
perform Run 423 work.

## Run 422 D7-D1 — review correction (this pass, documentation only)

This pass applied the D7-D1 review corrections to
`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` in place and
appended this reconciliation note; prior evidence above is preserved unchanged.

### Inspected state (recorded, not manufactured)

* **Working branch (actual):** `copilot/copilotcopilot-run-422-d7-d1`. The review
  task reports the branch as `copilot/copilotcopilot-run-422-d7-c3f`; the actual
  checkout is the `-d1` branch (deviation recorded, branch not renamed).
* **Worktree HEAD (actual) at this pass:** `9ce29ac` (`update`); the prior D7-D1
  section above recorded `38339d6`.
* **Reviewed revision named by the task** `ffa7b71cbdaa2d31badff519c346b40f00a9bc25`:
  **object absent** from this shallow clone; not in local ancestry and not
  referenced by any tracked file. Corrections were applied to the actual worktree.

### Corrections applied

* **A — three requirements separated.** Activation authorization (A),
  current-authority freshness (B), and signing / consensus-state continuity (C)
  are now distinct; an *equal* epoch comparison establishes none of them
  (epoch-0 snapshot → sign → restore counterexample). A source-backed inventory
  (contract §2.3.2) shows `voted_in_view` (`basic_hotstuff_engine.rs:317`),
  `proposed_in_view` (`:314`), `current_view` (`:299`, reset to
  `committed_height + 1` at `:1146`), `locked_qc` (`hotstuff_state_engine.rs:173`),
  and `votes_by_view` (`:192`) are **in-memory only**; the `ConsensusStorage`
  trait (`storage.rs:142`) persists committed block / QC / epoch and has **no**
  `put_last_voted_view` / `put_locked_qc` / vote-record method, so a
  committed-block checkpoint (`apply_epoch_transition_atomic`, `:997`) does not
  cover an uncommitted signing decision.
* **B — provenance vs authentication.** Withdrew the claim that an abstract
  caller-supplied epoch witness can reject peer / same-DB values by provenance; a
  comparison classifies but cannot authenticate. Added the anchor-interface
  preconditions and the live-quorum / QC assumption list; anchor selection stays
  explicitly unresolved (contract §5.2.1 / §5.3).
* **C — lifecycle / ordering.** Corrected the outbound order to admission/epoch →
  **sign** → **confirm** → facade handoff (`forward_actions_to_facade`, cached
  path signs before `confirm`); distinguished a completed signature from a
  transmitted one; removed the mid-handler same-owner replacement requirement;
  corrected "replacement fails → keep gen N" to fail-closed when superseded /
  revoked or when current authorization is unavailable; recorded that generation
  advance is in-process bookkeeping, not activation (contract §3–§4).
* **D — activation permission.** Recorded the trusted activation root / evidence
  (requirement A) as a **missing prerequisite**; kept Profile A as a proposed
  first-release profile (not an activation approval) with its full dependency list
  (contract §3.3.1 / §4.0).
* **E — source classifications.** `resolve_network_wire_alias` is defined in
  `qbind-types` (`network_wire_alias.rs`) and imported by the correspondence
  module; production preflight supplies `proposal_vote_authority: None`
  (`main.rs:5549`); S13 is **conditionally reachable** via the C3E gate
  (`binary_consensus_loop.rs:4736`), not dormant; S15 retains without a second
  constituent verification; Timeout / NewView credentials do not establish
  Proposal / Vote authority; governance replay persistence is not validator
  signing-state persistence or whole-DB rollback protection.
* **Next task replaced.** The generic freshness-anchor observation module is
  withdrawn from all three documents; the replacement is a bounded source
  characterization of existing signing-state persistence / recovery (contract §9).

### Validation

Source-reference, link / path, diff-scope, secret, and CRLF line-ending checks
performed. No Cargo test / check / release rebuild is required or authorized by
this documentation-only pass. Posture flags unchanged (below).

### Retained posture (unchanged by the D7-D1 review correction)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`;
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. No activation, readiness
promotion, or Run 423 work.

## Run 422 D7-D1 — reconciliation pass (this pass, documentation only)

This pass reconciles the operative contract rows/checklists with the D7-D1 review
summaries above. The prior review-correction section recorded corrections A–E, but
several **operative** rows still carried the pre-correction wording (an appended
qualification does not fix an incorrect table row). Superseded operative claims are
identified below; earlier text is preserved.

* **Inspected state (recorded, not manufactured):** working branch (actual)
  `copilot/copilotcopilotcopilot-run-422-d7-d1`; worktree HEAD `7a995f6` (`update`),
  clean before this pass. The reviewed object
  `d2bd379eb8a1854d8a225b55d6f5ab3cd92815ff` is **absent** from this shallow (depth-2)
  clone — not in local ancestry, not referenced by any tracked file; corrections were
  applied to the actual worktree content, and no ancestry to an absent object is
  manufactured.

* **Correction A (activation / signing / ordering) — operative rows fixed in place:**
  contract §4.3 *Sign effect* row's Required-durability cell no longer reads
  “none beyond activation”; it now states durable signing-state continuity
  (requirement C) is an **unmet** prerequisite. The §4.3 *Activation* row's
  authorization condition no longer relies on correspondence + anchor alone; it now
  also requires a trusted activation-authorization root (A) and requirement-C
  prerequisites. §5.4's ordering was corrected to `admit` → epoch check → **sign** →
  `confirm` → facade handoff (matching §3.2; confirmation after signing cannot
  un-create a signature). §7's dependency-order item 1 no longer asserts anchor
  selection “unblocks activation”; it references the single §3.3.1 dependency list.

* **Correction B (persistence / recovery inventory) — corrected citations:** the
  §2.3.2 *Committed block / QC* row previously cited `get_last_committed`
  (`production_consensus_storage.rs:101`), which is **wrong** — that file contains no
  `get_last_committed`; line 101 is an enum doc-comment. The actual recovery reader is
  the harness `load_persisted_state` (`hotstuff_node_sim.rs:2049` → `:2066` → `:2085`
  → `initialize_from_restart`); the production binary restore uses
  `initialize_from_snapshot_baseline` (`binary_consensus_loop.rs:2390`), reading
  neither `get_last_committed` nor any QC. The *Locked QC* row now states the harness
  reconstructs a conservative logical lock from committed / embedded QCs (not recovery
  of the exact latest pre-crash locked QC). The `ConsensusStorage` absence finding is
  scoped to that interface and the traced paths, **not** a repository-wide absence.

* **Correction C (production rejection path):** contract §4.1 no longer describes
  production as a *present* authority with an `unavailable(...)` owner; production
  preflight supplies `proposal_vote_authority: None` (`main.rs:5549`), so under
  `Required` the inbound arm fails closed as verification-context / current-state-
  unavailable before crypto (the present-authority / unavailable-owner arm is
  `cfg(test)`-only). S13's stale “dormant” label in the §1.2 source inventory was
  reconciled to conditionally reachable via the C3E gate
  (`binary_consensus_loop.rs:4736`); production authority remains unavailable.

* **Correction D (threat model):** the T1 row no longer reads a blanket “handled” —
  S17's atomic-write / partial-residue recovery is **governance-replay crash
  consistency only** and does not establish validator signing-state continuity. The
  T4 row and acceptance scenario 3 replace the unconditional “off-box anchor” with
  trusted state / evidence **outside the attacker's rollback domain** (protected local
  hardware or a remote witness — neither selected nor proven). The epoch-0 snapshot /
  sign / restore counterexample (§2.3.1) is intact.

* **Single next task reconciled:** contract §9 retains a bounded signing-state
  persistence / recovery **characterization** (no pre-decided repository-wide absence)
  requiring three distinct scenarios — (1) ordinary restart after an uncommitted
  signing decision, (2) restoration of a snapshot captured **before** that decision,
  and (3) existing committed-state recovery as a control — each naming its entrypoint
  and persisted data, keeping harness recovery distinct from the production snapshot
  path and `CommittedEpoch(0)` distinct from `PresentNoCommittedEpoch`. Not implemented
  in this pass.

* **Checks performed:** exactly the three authorized Markdown files changed; CRLF
  line endings preserved; no genuine trailing whitespace; source references
  re-verified against this checkout (`main.rs:5549`, `hotstuff_node_sim.rs:2049`,
  `binary_consensus_loop.rs:2390` / `:4736`, `production_consensus_storage.rs`
  contains no `get_last_committed`). No Cargo test / check / Clippy / release build
  run or authorized for this documentation-only pass; prior executions retained at
  their actual revisions. `task/warning.txt` and unrelated files untouched; no PR,
  branch rename, force-push, rebase, or history rewrite.

### Retained posture (unchanged by this reconciliation pass)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`; `GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. No readiness promotion or Run 423
work.

## Run 422 D7-D1 — five-correction contract reconciliation (this pass, documentation only)

This additive pass corrects the five remaining contract inconsistencies (A–E)
identified for RUN 422 D7-D1 in
`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`, and reconciles
this evidence summary with the corrected text. Prior evidence above is preserved
unchanged; several operative summaries in the earlier reconciliation notes are
**superseded** where identified below. No Rust, test, configuration, schema,
wire-format, workflow, authority, or activation change; `task/warning.txt` and
unrelated files untouched.

### Inspected state (recorded, not manufactured)

* **Working branch (actual):** `copilot/copilot-run-422-d7-d1`
  (`git branch --show-current`). The task **reports** the branch as
  `copilot/copilotcopilotcopilot-run-422-d7-d1`; the actual checkout differs and
  is not renamed.
* **Worktree HEAD (actual) at this pass:** `689454237696a6d56cb66037a19748cf7d19fd66`
  (`update`); worktree clean before this pass.
* **Reviewed revision named by the task** `11bc2279a605d48c04bfda552a098eb7890cd0c4`:
  **object absent** from this shallow clone (`git cat-file -t 11bc2279…` → could
  not get object info); not in local ancestry and not referenced by any tracked
  file. Corrections were applied to the actual worktree; no ancestry to an absent
  object is manufactured.

### Corrections applied (A–E)

* **A — one complete activation checklist.** §3.1's independent-evidence bullet no
  longer treats correspondence plus freshness as sufficient authorization to
  activate; it now references the independent trusted activation root / evidence
  (requirement A, §4.0) and the complete §3.3.1 prerequisite checklist. §3.3.1 now
  lists **current-authority freshness (requirement B)** as its own item, distinct
  from **signing-state recovery / rollback safety (requirement C)**; the
  release-binary-evidence item renumbered accordingly. §6.1 splits the former
  “authorized epoch and activation provenance” bullet into **authorized-epoch
  correspondence**, **activation authorization** (requirement A, missing), and
  **current-authority freshness** (requirement B). §4.0 now points to §3.3.1 as the
  single acceptance checklist. §3.3.1 is the one complete activation acceptance
  checklist and the other sections reference it.
* **B — circular dependency removed.** §7's dependency order no longer requires the
  complete checklist (including configured-authority release-binary evidence)
  *before* the wiring / capture that produces that evidence. Implementation and
  isolated (non-production) validation now **produce** the evidence (step 1);
  production activation is permitted **only after** the complete §3.3.1 checklist
  is satisfied (step 3). Activation is never described as its own prerequisite. No
  test bypass, new activation flag, or production activation is authorized; Profile
  A remains a proposed founding-authority-only profile.
* **C — exact rejection categories and compilation status.** §4.1 replaces the
  combined “verification-context / current-state-unavailable” description with the
  two distinct pre-crypto cases and their exact counters
  (`inbound_{proposal,vote}_verification_context_unavailable_total` when no
  effective authority; `inbound_{proposal,vote}_current_state_unavailable_total`
  when authority is present but the snapshot is absent), reusing the audit
  condition/result/timing table (`QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md`
  §2). Current production wiring (`proposal_vote_authority: None`, `main.rs:5549`)
  takes the **first** case. The current-state-unavailable branch is now recorded as
  a **compiled production branch** — not `cfg(test)`-only — that production wiring
  simply never reaches; only **constructing an `Established` current authorization**
  is `cfg(test)`-restricted. This **supersedes** the prior reconciliation note's
  “verification-context / current-state-unavailable … (the present-authority /
  unavailable-owner arm is `cfg(test)`-only)” wording.
* **D — consistent rollback-domain requirement.** §4.2 (“external first-boot
  witness”) and §8 scenario 4 (“only by the external witness”) now require
  appropriately authenticated trusted state / evidence **outside the specified
  attacker rollback domain**, without mandating an off-box service or selecting any
  one concrete anchor (protected local hardware or a remote witness, neither
  mandated nor selected). The empty-database ambiguity requirement is preserved, and
  the epoch-0 external-witness counterexample (§2.3.1) is left intact.
* **E — characterization fixture signing permitted.** §9's exclusions no longer
  exclude all “signing”; they now state that **isolated test-fixture signing is
  permitted for characterization** while **production signing enablement and
  authority activation remain prohibited**. The three characterization scenarios
  (ordinary restart; snapshot restored before the decision; committed-state
  recovery control) and their distinctions are preserved; the tests are not
  implemented in this pass.

### Checks performed

Exactly the three authorized Markdown files changed; CRLF line endings preserved
(each file retains its single no-trailing-newline final line); no genuine trailing
whitespace introduced; earlier accepted corrections (C1–C3F and the prior D7-D1
passes) left intact; no production activation or readiness promotion implied.
Semantic agreement re-read across the §3.3.1 checklist, the §7 dependency order,
the §4.3 transition rows, the §8 scenarios, and §9. No Cargo test / check / Clippy
/ release build was run or is required for this documentation-only correction;
historical execution results are retained at their actual revisions. No PR opened;
no branch rename, force-push, rebase, or history rewrite.

### Retained posture (unchanged by this pass)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`; `GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. No readiness promotion or Run 423
work.

## Run 422 D7-D2 — signing-state continuity characterization across restart and snapshot restore (test + evidence)

This phase is a **bounded characterization** of what the *existing* consensus
recovery entrypoints preserve, reconstruct, or lose after an *uncommitted*
signing decision. It adds source-backed observations and focused behavioral
tests only. It implements no new protection, no production behavior change, no
public getter, no persistence mechanism, and authorizes no production signing or
authority activation. Isolated test-fixture signing with the existing real
ML-DSA-44 backend is used for characterization only.

### Provenance and object limitations

* Actual branch inspected in this clone: `copilot/copilotcopilotcopilot-run-422-d7-d2`.
  Deviation reported, not manufactured: the task and the earlier D7-D2 write-up
  name the branch `copilot/copilotcopilot-run-422-d7-d2` (two `copilot` segments);
  the checked-out branch carries three (`copilotcopilotcopilot`). No branch rename
  was performed to reconcile this — the working branch is reported as-is.
* Reviewed final revision `d685e29746e8b52b9e354335478a4d7018d0b981` and the
  previously reported tested checkpoint
  `5aa2f9dd62e72e16a2c6d6e382a1b5683ba94f0d` are **not present** in this clone
  (`git cat-file -t` fails for both; `.git/shallow` present). Missing historical
  objects do not imply missing implementation: the D7-D2 test target and this
  documentation section are present in-tree and were re-inspected directly.
* Accepted D7-D1 baseline: `70d665277f987ee43013e41de55c409b21ae2331`. This object
  is likewise **not present** in the shallow clone. The D7-D1 documentation content
  is present in-tree (the five accepted corrections and the D7-D1 sections above are
  intact); content correspondence is therefore reported separately from ancestry,
  which cannot be verified from this shallow clone. No accepted C3F implementation
  or D1 documentation review was reopened.
* Starting SHA of this correction pass (D2-findings correction): `1c29ae6` (branch
  HEAD at checkout). New test checkpoint recorded for this pass: `d7002e4`
  (the corrected test target + evidence). Validation below was run at this tree.
* Supplied task branch used with normal commits + push only. No PR, no main
  changes, no branch rename, no force-push, rebase, or history rewrite.
  `task/warning.txt` and unrelated files untouched.

### Changed paths / diffstat

* `crates/qbind-node/tests/run_422_d7d2_signing_state_recovery_tests.rs`
  (dedicated integration target; corrected in this pass to sign the engine's
  actual emitted decisions, use comparable baselines and same-process controls,
  state initializer-only snapshot scope, and distinguish C1-versus-harness epoch
  behavior — corrections A–D).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (this section, corrected in
  place plus one appended correction note).
* `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` (inventory /
  next-step note only).
* `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` (short
  successor note only).

No production source file was modified. Production behavior is unchanged.

### Selected test location (explained)

Every reused recovery path is **public**
(`BasicHotStuffEngine::{initialize_from_restart, initialize_from_snapshot_baseline,
on_proposal_event, leader_for_view, current_view, committed_height, locked_qc}`,
`NodeHotstuffHarness::load_persisted_state`, `observe_consensus_storage`, the
`ConsensusStorage` put/get API, and the D6 `verify_vote_msg_with_domain`
verifier over the real `MlDsa44Backend`). A single dedicated integration target
(the one sanctioned by the task) therefore exercises the real entrypoints
directly, keeps the change isolated from the large production consensus-loop
module, and needs no `cfg(test)` accessor or private-state exposure. The minimal
validator/key fixture in the new file is built only from public constructors and
is explicitly labelled test fixture setup; it is not a production route.

### Source / recovery path matrix (source inspection)

| Entrypoint | Reachability | Persisted inputs it consumes | Reconstructs | Does NOT reconstruct |
| --- | --- | --- | --- | --- |
| `BasicHotStuffEngine::initialize_from_restart` (`basic_hotstuff_engine.rs:1134`) | called by the harness/async-runner reader `load_persisted_state`; test. NOT shown production-binary-reachable here solely because the harness calls it — the production binary snapshot path is `main.rs` restore → `open_production_consensus_storage` → B5 `initialize_from_snapshot_baseline`, which does not route through this entrypoint | `(committed_block_id, committed_height, locked_qc)` passed by its caller | committed baseline; `current_view = committed_height + 1`; latch reset; optional lock from the supplied QC | any uncommitted vote; per-view vote latch state; block tree above committed |
| `HotStuffStateEngine::initialize_from_restart` (`hotstuff_state_engine.rs:1190`) | via the above | committed block/height + optional locked QC | committed prefix + lock | vote accumulator; tree above committed |
| `BasicHotStuffEngine::initialize_from_snapshot_baseline` (`basic_hotstuff_engine.rs:1201`) | binary B5 (`binary_consensus_loop.rs:2389`); test | ONLY `block_hash` + `height` — the two `StateSnapshotMeta` fields this initializer reads (the full meta also carries `created_at_unix_ms`, `chain_id`, `epoch`, `authority_state`, `authority_state_v2`, none of which this initializer consumes) | committed height; synthetic anchor block; `current_view = height + 1` | locked QC; QC/vote history; any intervening signing decision; and it does NOT reconstruct any QC lock |
| `NodeHotstuffHarness::load_persisted_state` (`hotstuff_node_sim.rs:2035`) | harness / async-runner startup only (this is the harness/async-runner reader, distinct from the production binary snapshot path) | `get_last_committed`, `get_block`, `get_qc`, embedded block QC, `get_current_epoch` | committed block+height; **lock reconstructed from the committed/stored QC** (higher-view of block-level vs embedded); epoch via `get_current_epoch()?.unwrap_or(0)` — a MISSING epoch is defaulted to 0 by this reader (restore branch taken only when `> 0`) | latest uncommitted vote; latest pre-crash lock; C3F retained evidence |
| `observe_consensus_storage` (`consensus_storage_observation.rs:295`) | read-only observation (C1) | schema, incomplete-transition marker, `meta:current_epoch` | `NoStorageHandle` / `PresentNoCommittedEpoch` / `CommittedEpoch(n)` | the C1 observer never coerces a missing epoch to zero (this is distinct from the harness reader's `unwrap_or(0)` fallback above); never authorizes |
| `open_production_consensus_storage` / `persist_restored_snapshot_epoch` (`production_consensus_storage.rs:391/504`) | binary main (`main.rs:2470/4726`) | data-dir consensus RocksDB; snapshot epoch | epoch parity between restored state and consensus storage | any vote/lock/signing state |
| `ConsensusStorage::apply_epoch_transition_atomic` (`storage.rs`; RocksDB `997`, in-memory `1318`) | epoch transition | reconfig block/QC, last-committed, new epoch | atomic committed-epoch transition | uncommitted signing decisions |

Distinctions recorded: the lock produced by `load_persisted_state` /
`initialize_from_restart` is a lock **reconstructed from committed/embedded QCs**,
not the latest *pre-crash* lock; and committed-state recovery is distinct from
preservation of an uncommitted signing decision. No relevant existing
implementation persists a per-view vote or an anti-equivocation record consumed by
any of these entrypoints; that absence is reported as a gap, not invented inside a
fixture.

### Scenario-to-test mapping, persisted inputs, and observed outcomes

All five tests pass at the tested checkpoint.

**A — ordinary restart after an uncommitted signing decision**
(`d7d2_a_uncommitted_vote_lost_and_latch_reset_permits_conflicting_vote_after_restart`).
Fixture: 4-validator set, real ML-DSA-44 keys, explicit epoch 0, view 1, an
explicitly-declared v2 fixture signing domain whose `expected_wire_chain_id = 1`
matches the wire `chain_id = 1` the engine stamps on every emitted `Vote`.
Comparable baseline (correction B): BOTH the pre-decision engine and the
restarted engine are initialized from the SAME explicit inputs
(`initialize_from_restart([0x00;32], 0, None)` — committed id, committed height 0,
explicitly-absent lock/QC); baseline state is asserted BEFORE and AFTER
initialization (`committed_height None → Some(0)`, `current_view = 1`,
`locked_qc = None`, `current_epoch = 0`), not merely the resulting view.
Exercised: a valid leader proposal for block X → `on_proposal_event` returns
`BroadcastVote` (the engine **decision**; the emitted vote is unsigned, carries
`validator_index = 0` = the LOCAL validator, and the placeholder
`suite_id = DEFAULT_CONSENSUS_SUITE_ID = 0`). Same-process control: a conflicting
proposal for block Y at the same view is refused by the engine's per-view vote
latch (`voted_in_view`). Completed-signature boundary (correction A): a
test-local signing adapter — mirroring the production preparation
`sign_vote_for_broadcast` — consumes the ACTUAL emitted `Vote`, applies the
documented suite selection (overwriting ONLY the placeholder `suite_id` with the
configured real suite, exactly as `vote.suite_id = signer.suite_id()` does),
computes the mandatory v2 preimage over the emitted domain, and assigns completed
signature bytes from the LOCAL validator's key. All other emitted fields (version,
validator index, wire chain, epoch, height, round, step, block id) are asserted
unchanged; the real D6 verifier independently accepts the completed signature over
the engine's decision. Restart: a fresh engine initialized from the SAME baseline;
observed `committed_height = 0`, `current_view = 1`, `locked_qc = None`,
`current_epoch = 0`. After restart the reset latch admits the previously-refused
conflicting proposal for Y → the engine emits a second vote decision at the same
view for a different block id. Both emitted decisions are signed by the same
local validator over the same key/domain/epoch/voting position but DIFFERENT
signed message bodies (asserted: the two v2 preimages differ, not merely the
signature bytes), and both pass D6 verification. Boundary: this is
engine-decision-level equivocation plus signer-level conflicting-signature
capability; the facade handoff and network transmission were **not** exercised,
this correction establishes no production authorization or transmission, and no
persisted anti-equivocation record is consumed by the recovery entrypoint.

**B — replay the same pre-decision snapshot baseline inputs**
(`d7d2_b_snapshot_baseline_before_decision_omits_intervening_vote`). Scope stated
accurately (correction C): this test replays the SAME declared pre-decision
initializer inputs into a fresh engine and exercises
`initialize_from_snapshot_baseline` ONLY. It does **not** exercise snapshot
creation, serialization, filesystem restoration, RocksDB recovery, or the full
binary startup path. `StateSnapshotMeta`
(`crates/qbind-ledger/src/state_snapshot.rs:91`) actually carries a COMPLETE
structure — `height`, `block_hash`, `created_at_unix_ms`, `chain_id`,
`epoch: Option<u64>`, `authority_state: Option<..>`, `authority_state_v2:
Option<..>`; the engine initializer consumes ONLY TWO of these (`block_hash` reused
as an opaque parent id, and `height`). The epoch/chain/authority metadata is not
recovered by this initializer and is **not** recovered Proposal/Vote signing
history or current authorization. A live engine is restored to a pre-decision
baseline (height 5) and makes an uncommitted decision at view 6; a same-process
conflicting proposal at view 6 is refused by the per-view latch (correction B
control); a **fresh** engine instance then replays the same inputs (fields are not
reset on the live engine). Baseline state is asserted BEFORE and AFTER init on both
engines (`committed_height None → Some(5)`, `current_view = 6`, `locked_qc = None`,
`current_epoch = 0`). Observed on the fresh instance: a conflicting proposal at
view 6 is admitted and voted for a different block id. Both engine epochs are
asserted explicitly at 0 — an unchanged epoch does **not** establish preservation
of the intervening decision; the decision is simply absent from the replayed
baseline. Completed signatures follow the same correction-A adapter over the actual
emitted decisions (documented suite selection, local-validator key, preserved
fields, differing preimages).

**C — existing committed-state recovery control**
(`d7d2_c_load_persisted_state_recovers_committed_baseline_present_no_committed_epoch`,
`d7d2_c_committed_epoch_zero_observed_distinctly_as_fixture_setup`,
`d7d2_c_fresh_node_recovers_nothing`). The real harness/async-runner reader
`NodeHotstuffHarness::load_persisted_state` is exercised (not reproduced) against an
`InMemoryConsensusStorage` seeded with a committed block at height 7 and an
**unverified storage/reconstruction QC fixture** (empty `signatures` — no
constituent signatures). Its successful loading establishes reader/reconstruction
behavior only, NOT authenticated quorum evidence or recovery safety. Observed: the
reader returns the committed block id; the engine reconstructs
`committed_height = Some(7)`, `current_view = 8`, and a lock **reconstructed from
the stored/embedded QC** (`locked_qc().view == 7`) — this is a lock reconstructed
from the committed/stored QC, kept explicitly separate from recovery of the exact
latest pre-crash lock. C1-versus-harness epoch behavior (correction D) is asserted
distinctly: the `observe_consensus_storage` (C1) observation is checked BEFORE and
AFTER the harness read; with no epoch seeded it is `PresentNoCommittedEpoch` both
times (the reader is read-only w.r.t. the epoch key, so storage remains missing);
separately, the harness reader's own fallback
(`storage.get_current_epoch()?.unwrap_or(0)`) defaults that MISSING epoch to 0 in
the resulting engine (`engine().current_epoch() == 0`). These are recorded as two
distinct behaviors — the C1 observer never coerces the missing epoch to zero, while
the harness reader does; this does NOT claim the entire recovery path never
defaults a missing epoch to zero. With an explicit `put_current_epoch(0)`
(labelled fixture setup) the observation is `CommittedEpoch(0)` (distinct from the
absent-epoch case, and still present after the read), with the resulting engine
epoch 0 sourced from the seeded committed epoch rather than the missing-epoch
fallback. The fresh-node control recovers nothing. Stated boundary: this control
recovers committed state only; it establishes recovery of neither the latest
uncommitted vote, nor the exact latest pre-crash lock, nor C3F retained
verified-justification evidence.

### Evidence strength and controls (task §5)

For each scenario the boundaries are kept separate: engine decision/action
(`on_proposal_event` → `BroadcastVote`); signer invocation and **completed
signature bytes** (real `MlDsa44Backend::sign` + `verify_vote_msg_with_domain`);
facade handoff and network transmission — the last two are **not** exercised. The
cleared latch, repeated action and reset view are reported as recovery-entrypoint
observations, not as proof of transmitted conflicting signatures. The
conflicting-signature capability in Scenario A is established at the signer/backend
level under fixture-declared authority assumptions (fixture-established membership
and keys), with the transmission boundary explicitly unexercised. Test-derived
findings (green characterization tests) are kept separate from source-inspection
findings (the path matrix); neither is presented as production capability.

### Validation results

Commands (default features, debug/test profile; no release rebuild — none is
required for test/documentation-only changes), re-run at the corrected checkpoint:

* `cargo test -p qbind-node --test run_422_d7d2_signing_state_recovery_tests` → `ok. 5 passed; 0 failed`.
* `cargo test -p qbind-node --test hotstuff_restart_semantics_tests` → `ok. 14 passed; 0 failed`.
* `cargo test -p qbind-node --test persistence_integration_tests` → `ok. 6 passed; 0 failed`.
* `cargo test -p qbind-node --test run_422_d7c1_storage_observation_tests` → `ok. 23 passed; 0 failed`.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` → `ok. 4 passed; 0 failed` (real binary, startup refusal preserved).
* `cargo clippy -p qbind-node --test run_422_d7d2_signing_state_recovery_tests` → exit 0; no warning is attributable to the edited target (only pre-existing `qbind-node` lib warnings, unrelated and unchanged).

All exit codes `0`. No repository-wide formatter was run; CRLF line endings of the
edited Markdown and Rust files are preserved. Unrelated broad-target failures, if
any, are out of scope and were not modified to green this report. Automated
tooling outcomes are recorded literally: the Code Review pass returned no review
comments but its model backend reported an error (`model claude-sonnet-4.6 not
found in registry`), and the CodeQL Security Scan was **skipped** (changes declared
trivial: test + documentation only). Neither a skip nor a backend error
establishes a successful security review; `SECURITY_POSTURE` is unchanged.

### Scoped verdict

`D7D2_SIGNING_STATE_RECOVERY_CHARACTERIZATION=COMPLETE-FOR-TESTED-SCOPE`

The three required scenarios (A ordinary restart, B snapshot restored before the
decision, C committed-state recovery control) have adequate source-backed and
behavioral evidence within the stated boundaries. Signing-state **continuity** is
reported **separately** and is **NOT** established: the tested recovery entrypoints
carry no channel for an uncommitted vote or a per-view anti-equivocation record, so
the in-process double-vote guard does not survive restart or pre-decision snapshot
restore. A green characterization test here confirms *missing* protection; it is
not translated into any safety claim.

Retained posture (unchanged by this pass):

* `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`
* `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`
* `GENESIS_AUTHORITY_ACTIVATION=DISABLED`
* `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`
* `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`
* `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`

### One recommended next task (not implemented here)

Add a bounded characterization of the **actual binary snapshot-restore call path**
(`main.rs` restore → `open_production_consensus_storage` →
`persist_restored_snapshot_epoch` → B5 `initialize_from_snapshot_baseline`) over a
real RocksDB artifact using the existing supported snapshot/checkpoint procedure
(closing storage handles before any filesystem-copy fixture), to observe the same
uncommitted-decision boundary end-to-end rather than at the initializer level.
This remains characterization only; it authorizes no durability fix, freshness
anchor, or activation.

### Clean-worktree / push status

Worktree clean after each reported checkpoint; changes pushed to the supplied task
branch via normal commits only. No PR was opened; no branch rename, force-push,
rebase, or history rewrite.

### D2-review correction note (this pass)

The four D2 review findings were corrected in place above; the original scenario
structure and accepted D1/C3F results are preserved. Concisely: (A) scenarios A and
B now sign the engine's ACTUAL emitted `Vote` — via a test-local adapter mirroring
the production `sign_vote_for_broadcast` suite selection, using the LOCAL
validator's key and the emitted wire chain (1)/epoch/position, asserting only
`suite_id` and `signature` changed and that both completed signatures cover
different signed message BODIES — replacing the earlier reconstruction helper that
re-signed a separate vote under the leader's identity with wire chain 0/step 1;
(B) the pre-decision and restarted/replayed engines now use the SAME explicit
baseline inputs with before/after state assertions, and both scenarios carry a
same-process conflicting-decision control with explicitly-asserted engine epochs;
(C) scenario B is described as initializer-only replay (`initialize_from_snapshot_baseline`,
consuming only `block_hash` + `height`) and the `StateSnapshotMeta` claim is
corrected to its complete field set; (D) the C1 observer's explicit-absence
behavior is distinguished from the harness reader's `get_current_epoch().unwrap_or(0)`
fallback, the stored QC is labelled an unverified fixture, the reconstructed lock is
kept separate from the exact latest pre-crash lock, and the source matrix no longer
labels `initialize_from_restart` production-binary-reachable solely because the
harness calls it. No production source changed.
## Run 422 D7-D3 — real snapshot artifact and binary restore characterization (test + evidence)

This phase is a **bounded characterization** of the *existing* snapshot/restore
mechanisms exercised end-to-end, including through the **unmodified `qbind-node`
release executable**. It adds one focused integration target plus this evidence
section. It implements no durable signing protection, no anti-rollback, no
production behavior change, no public getter, no CLI flag, no storage
key/schema change, and authorizes no production signing or authority
activation. Genesis-authority activation stays DISABLED.

### Provenance and object limitations

* Actual branch inspected in this clone: `copilot/copilotcopilotcopilotcopilot-run-422-d7-d2`
  (four `copilot` segments). The task's reported D7-D2 branch was
  `copilot/copilotcopilotcopilot-run-422-d7-d2` (three segments). No branch
  rename was performed; the working branch is reported as-is.
* Accepted D7-D2 reference commits `9e66680deda49b67962d1e6f7ea665fc305d10ec`
  (final) and `d7002e4736fd756ea3e3e334655ce96b357dcd92` (tested checkpoint)
  are **not present** in this shallow clone (`git cat-file -t` fails for both;
  `git rev-parse --is-shallow-repository` = `true`). Missing historical objects
  do not imply missing implementation: the D7-D2 target, the B3/B5/Run 097
  targets, and the production restore/storage sources named by the task are all
  present in-tree and were re-inspected directly. Content correspondence is
  reported separately from ancestry, which cannot be verified from this shallow
  clone.
* Starting HEAD at checkout: `7675df8388b32aea64fb5f917154491db8f23176`.
  Capacity at start: `/dev/root` 145G total, 85G avail (42% used), inodes 6%
  used.
* Supplied task branch used with normal commits + push only. No PR, no main
  changes, no branch rename, no force-push, rebase, or history rewrite.
  `task/warning.txt` and unrelated files untouched.

### Source / reuse map (exact missing coverage identified)

| Mechanism (reused, not reimplemented) | Location |
| --- | --- |
| Real RocksDB checkpoint via `StateSnapshotter::create_snapshot` | `crates/qbind-ledger/src/execution.rs` (impl for `RocksDbAccountState`) |
| `StateSnapshotMeta` (`height`/`block_hash`/`chain_id`/`epoch`) + `with_epoch` | `crates/qbind-ledger/src/state_snapshot.rs` |
| `restore_from_snapshot` / `apply_snapshot_restore_if_requested` | `crates/qbind-node/src/snapshot_restore.rs` |
| Startup ordering: restore → storage open → epoch persist → loop | `crates/qbind-node/src/main.rs` (restore ~L2463, Run 093 open ~L4684, Run 097 persist ~L4726) |
| `open_production_consensus_storage` / `persist_restored_snapshot_epoch` | `crates/qbind-node/src/production_consensus_storage.rs` |
| `observe_consensus_storage` (C1 read-only epoch observation) | `crates/qbind-node/src/consensus_storage_observation.rs` |
| `RestoreBaseline` / `initialize_from_snapshot_baseline` wiring | `crates/qbind-node/src/binary_consensus_loop.rs`, `crates/qbind-consensus/src/basic_hotstuff_engine.rs` |
| Deadline-based child-process runner (kill+reap+drain-join, timeout = hard fail) | pattern from `crates/qbind-node/tests/run_422_d4_startup_ordering_tests.rs` |
| Real-checkpoint fixture build + reopen-and-observe | pattern from `b3_snapshot_restore_tests.rs`, `run_097_snapshot_epoch_parity_tests.rs` |

**Exact missing coverage before D7-D3:** the B3/B5/Run 097 targets call library
entrypoints in-process; they never launch a child `qbind-node` process, never
observe the ordered production startup stages of a real restore invocation, and
never independently reopen the restored RocksDB stores after a real process
exit. D7-D3 adds precisely that child-process / release-binary layer while
reusing every underlying mechanism above. No new parser, snapshot
implementation, epoch observer, signing adapter, or authorization mechanism was
introduced.

### Changed paths

* `crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
  (new dedicated integration target; 4 tests). Contains a test-support
  process runner and a `QBIND_D7D3_NODE_BIN` executable-selection override
  used to point the identical child-process cases at an explicitly selected
  release executable. Both live entirely in the test file, outside production
  code.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (this section).
* `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`
  (successor note only).
* `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md`
  (successor note only).

No production source file was modified. Production behavior is unchanged.

### Scenario matrix with exact exercised entrypoints and evidence boundary

| Case | Entrypoint exercised | Evidence level | Result |
| --- | --- | --- | --- |
| **A** canonical real checkpoint + point-in-time control | `StateSnapshotter::create_snapshot` → mutate source via `put_account_state` → `restore_from_snapshot` → reopen | **library / in-process** | PASS — restored artifact holds checkpoint value 4242; mutated source holds later value 9999; source artifact intact |
| **B1** binary restore, snapshot epoch **absent** | child `qbind-node --restore-from-snapshot` (LocalMesh DevNet) → deliberate terminate at loop → independent reopen of `state_vm_v0` + `consensus` | **child-process / release-binary** + independent reopen | PASS — account 4242 restored; consensus observed `PresentNoCommittedEpoch` (explicit absence) |
| **B2** binary restore, snapshot epoch **Some(0)** | same as B1, snapshot meta `epoch=Some(0)` | **child-process / release-binary** + independent reopen | PASS — account 4242 restored; consensus observed `CommittedEpoch(0)`; distinction absence≠0 asserted |
| **C** epoch-conflict fail-closed control | child `qbind-node` onto fresh `state_vm_v0` + separately seeded `consensus` committed epoch 42, snapshot epoch 7 | **child-process / release-binary** + independent reopen | PASS — nonzero exit, Run 097 `RestoreEpochInconsistent` FATAL, loop NOT reached, existing epoch 42 preserved; `state_vm_v0` account restored *before* rejection (reported, not hidden) |
| **D** signing-state evidence boundary | typed `StateSnapshotMeta::from_json` + scoped content inspection of THIS fixture's `meta.json` / restore audit marker / single account lookup / restore baseline | **fixture / structural + source-traced** | PASS — signing-state continuity **NOT-established**; the keyword checks are scoped content observations of this fixture, not a universal absence or schema claim (corrected — see D7-D3 correction subsection) |

### Artifact and metadata provenance

* Checkpoint is produced by RocksDB's checkpoint API through
  `StateSnapshotter::create_snapshot` (a `state/` checkpoint plus `meta.json`),
  **not** a copy of an open database directory.
* `StateSnapshotMeta` height, block hash (`[height as u8; 32]`), and epoch are
  **fixture declarations**, not authenticated consensus evidence, and are
  labelled as such in the target.
* DevNet chain id observed end-to-end: `0x51424e4444455600`.
  Copied checkpoint size per case: `bytes_copied=8572`.

### Process commands, executable hash and outcomes (exact release executable)

Release build (as required):

```
cargo build --release -p qbind-node --bin qbind-node   # Finished release in 7m35s
sha256sum target/release/qbind-node
060fb0f00685f267307bf302728f539a4dfdce7bd73ea452cd488a20abfe475d  target/release/qbind-node
```

The representative valid-restoration cases (B1/B2) and the epoch-conflict
control (C) were executed against **that exact release executable** by pointing
the target at it:

```
QBIND_D7D3_NODE_BIN="$PWD/target/release/qbind-node" \
  cargo test -p qbind-node \
  --test run_422_d7d3_binary_snapshot_restore_characterization_tests \
  -- --test-threads=1
# test result: ok. 4 passed; 0 failed
```

Observed ordered stderr from the release executable (transcribed via the
target's `QBIND_D7D3_DUMP_STDERR` echo; publish-safe, no secrets):

**B1 (epoch absent):**
```
[restore] complete: height=111 chain_id=0x51424e4444455600 bytes_copied=8572 target=.../state_vm_v0
[restore] OK: restored from snapshot height=111 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=111, starting_view=112)
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=.../consensus
[binary] Run 097: no snapshot epoch persistence performed (snapshot_epoch=None, storage_state=present-no-committed-epoch).
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
```
Then deliberately terminated (SIGKILL) after the loop marker; reaped; independent
reopen → account 4242, consensus `PresentNoCommittedEpoch`.

**B2 (epoch Some(0)):**
```
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=.../consensus
[restore] Run 097 persisted snapshot canonical epoch=0 into .../consensus
[binary] Run 097: snapshot canonical epoch=0 persisted into <data_dir>/consensus meta:current_epoch.
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
```
Then deliberately terminated; reaped; independent reopen → account 4242,
consensus `CommittedEpoch(0)`. Distinction absence (`None`) ≠ explicit zero
(`Some(0)`) asserted.

**C (epoch conflict, fail-closed):**
```
[restore] OK: restored from snapshot height=333 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=333, starting_view=334)
[binary] Run 093 consensus storage: state=committed-epoch epoch=42 path=.../consensus
[binary] FATAL: Run 097 snapshot epoch parity failed: ... existing meta:current_epoch=42 but snapshot meta.json declares epoch=7. Refusing to silently overwrite. ...
```
Natural nonzero exit (`std::process::exit(1)`); loop marker never emitted;
independent reopen → consensus epoch **still 42** (preserved). The restored
`state_vm_v0` account (7,4242) **is** materialized because account-state
restoration precedes the epoch-parity rejection; the data directory is
therefore **not** wholly unchanged. This earlier effect is asserted explicitly,
not hidden.

### Process vs library vs fixture distinctions (explicit)

* **Child-process (release binary):** cases B1, B2, C — the restoration
  invocation, the ordered startup-stage observation, the fail-closed exit, and
  the deliberate termination of the running loop. Post-process storage reads
  are **independent in-process reopens** after the child was reaped.
* **Library / in-process:** case A (checkpoint + point-in-time control) and the
  `restore_from_snapshot` calls used only to inspect artifacts in case D.
* **Fixture declaration:** `StateSnapshotMeta` height/block-hash/epoch values.
  These are inputs, not authenticated consensus evidence.

### Signing-state evidence boundary (case D, precise)

* **What the checkpoint contains:** a RocksDB account-state checkpoint (the
  single known account) plus `meta.json`. No signing/vote/lock material.
* **What `meta.json` declares:** parsed with the existing typed
  `StateSnapshotMeta::from_json` parser. The schema is NOT merely
  `height`/`block_hash`/`chain_id`/`epoch`: it also carries `created_at_unix_ms`
  and the optional Run 117/140 `authority_state` / `authority_state_v2`
  carriers, which are **absent (omitted) in THIS fixture** (built with no
  authority marker) — recorded as an absence in this fixture, not a schema-wide
  guarantee. The `signature`/`signed_vote`/`vote`/`locked_qc`/`signing`/`secret`
  keyword check is a scoped observation of THIS fixture's serialized content,
  not a universal absence claim.
* **What is materialized in account storage:** account state only.
* **What is written/observed in the separate consensus store:** only
  `meta:current_epoch` (absent, or the explicit value persisted by Run 097).
* **What the binary passes to the engine initializer:** only the
  `RestoreBaseline` (`snapshot_height` + `snapshot_block_id`) via
  `initialize_from_snapshot_baseline`. That the initializer actually RAN at
  runtime is now observed at the executable level via the post-baseline
  `[binary-consensus] B5: applied restore baseline: snapshot_height=… starting_view=…`
  observation (see the D7-D3 correction subsection); the earlier `[binary] B5:
  …enabled` and `[binary] LocalMesh mode: starting consensus loop` lines only
  establish baseline construction and entry into the LocalMesh startup dispatch.
  That NO per-view vote latch or anti-equivocation record travels this path is a
  source-traced finding (consistent with D7-D2), not a runtime inventory.
* **Signing/locking evidence restored / reconstructed / absent / unobservable:**
  **absent** through every restore path exercised here. Account-state rollback
  is **not** proof of conflicting signatures, and epoch equality is **not**
  proof of signing-state continuity. The production binary performs **no**
  signature demonstration during restore; D7-D2's fixture signing demonstration
  is a separate activity and is **not** repeated here as if the binary
  performed it.

### Validation results (dev profile unless noted; sequential)

* `run_422_d7d3_binary_snapshot_restore_characterization_tests` — 4 passed
  (dev binary and, via `QBIND_D7D3_NODE_BIN`, the exact release executable).
* `run_422_d7d2_signing_state_recovery_tests` — 5 passed.
* `b3_snapshot_restore_tests` — 10 passed.
* `b5_restore_aware_consensus_start_tests` — 4 passed.
* `run_422_d7c1_storage_observation_tests` — 23 passed.
* `run_422_startup_refusal_tests` — 4 passed.
* Run 097 coverage located and reused: `run_097_snapshot_epoch_parity_tests`
  — 7 passed (creation parity, restore parity, old-snapshot compatibility,
  fail-closed inconsistency, activation isolation). D7-D3 adds the
  release-binary layer above these library-level cases rather than duplicating
  them.
* Focused Clippy: `cargo clippy -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests`
  — clean for the new target (the ~85 pre-existing `qbind-node` lib warnings are
  unrelated and unchanged).
* Release build: `cargo build --release -p qbind-node --bin qbind-node` — Finished.

### Security tooling (recorded literally)

* Secret scan of the new target: **no secrets detected**.
* CodeQL / reviewer backend outcomes are recorded literally in the final report
  for this pass. A skipped CodeQL or reviewer backend error is treated as
  incomplete/unverified regardless of any accompanying "0 alerts"/"no comments".

### Scoped verdict

`D7D3_BINARY_SNAPSHOT_RESTORE_CHARACTERIZATION=COMPLETE-FOR-TESTED-SCOPE`

The required executable/artifact observations were actually obtained: the
unmodified release executable (sha256 `060fb0f0…`) performed the restore, the
ordered startup stages were observed, the process was deliberately terminated
or failed closed, and the RocksDB stores were independently reopened after the
process exited.

### Retained posture (unchanged by D7-D3)

* `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`
* `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`
* `GENESIS_AUTHORITY_ACTIVATION=DISABLED`
* `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`
* `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`
  (D7-D3 is *restore-path* release-binary evidence, not configured-authority
  release-binary evidence, and not Run 423.)
* `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`

Signing-state continuity remains NOT-established. No readiness promotion.

### One recommended next task (justified by findings) — corrected distinction

Case C established that the restore path materializes `state_vm_v0` **before**
the Run 097 epoch-parity rejection, leaving a restored account store on disk
after a fail-closed exit. A bounded successor should characterize a restart
over that partially-restored directory (occupied `state_vm_v0` + preserved
conflicting `consensus` epoch), and it MUST distinguish two DIFFERENT paths
rather than conflating them:

* **Restart WITH `--restore-from-snapshot`** (fast-sync requested again). Only
  this path runs the B3 validate→materialize pipeline, and only this path
  reaches the `TargetStateNotEmpty` guard (`snapshot_restore.rs` step 4), which
  refuses because `state_vm_v0` is now non-empty. The guard belongs to
  *requested* restoration.
* **Ordinary restart WITHOUT `--restore-from-snapshot`.**
  `apply_snapshot_restore_if_requested` returns `Ok(None)` when restoration is
  not requested (fast-sync disabled), so the `TargetStateNotEmpty` guard NEVER
  fires on this path. The ordinary-startup outcome over the partially-restored
  directory is therefore NOT predetermined by that guard and must be
  characterized on its own.

Do NOT claim `TargetStateNotEmpty` protects both paths, and do NOT predetermine
the ordinary-startup outcome. Neither successor scenario is added in this
correction, and no cleanup, rollback, or anti-rollback mechanism is introduced
(all remain out of scope).

### Clean-worktree / push status

Normal task-branch commits + push only. No PR, no main changes, no branch
rename, no force-push/rebase/history rewrite. `task/warning.txt` and unrelated
task files untouched.

## Run 422 D7-D3 correction — process observation and evidence boundaries (test + evidence)

This bounded correction preserves the useful real-checkpoint, account-restoration
and epoch-parity evidence already implemented and fixes the process-observation
and evidence-boundary overclaims identified in review. It changes **only** the
D7-D3 test target and documentation; no production source was touched, no getter,
CLI flag, storage/schema, authorization wiring, recovery redesign, cleanup, or
activation was added. Genesis-authority activation stays DISABLED.

### Provenance and object availability (this correction pass)

* Actual branch inspected/used: `copilot/copilotcopilotcopilotcopilotcopilot-run-422-d7-d2`
  (five `copilot` segments). Supplied task branch used with normal commits +
  push only — no PR, main change, branch rename, force-push, rebase, or history
  rewrite. `task/warning.txt` and unrelated files untouched. Worktree was clean
  at checkout; shallow single-branch clone (`git rev-parse --is-shallow-repository`
  = `true`).
* Starting HEAD at checkout: `4ecb3fb5a062d3649bc67c9d52a333a9041f129a`.
* Capacity at start: `/dev/root` 145G total, ~85G avail (42% used); inodes ~6% used.
* Reviewed D7-D3 reference objects are **not present** in this shallow clone
  (`git cat-file -t` fails for both): final revision
  `2068f5d4e18edabf2e6e645130592ddfe949e4ca` and test checkpoint
  `ccb4d755e476fbf85982847886fab4c9f3c1da5a`. The historical checkpoint
  `ccb4d755…` is thus recorded **as supplied, object-unavailable** (not
  verifiable from this clone). Missing reference objects do not imply missing
  implementation: the D7-D3 target and all named production sources are present
  in-tree and were re-inspected directly; content correspondence is reported
  separately from ancestry, which cannot be verified here.
* The prior pass's release binary (`060fb0f0…`) is not present in this fresh
  clone (`target/` absent), so the source-corresponding release executable was
  rebuilt for this pass (hash below).

### Changed files (this correction)

* `crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
  (corrections A/B/C + 3 new runner-control tests; now 7 tests).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (this subsection + in-place
  corrections to the case-D matrix row, the engine-initializer boundary bullet,
  the `meta.json` schema bullet, and the successor distinction).
* `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`,
  `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md`
  (successor-note corrections only).

No production source file was modified; production behavior is unchanged.

### Disposition of corrections

* **Correction A (startup dispatch vs engine initialization): applied.** The
  misleading "loop reached" anchor description was renamed to say it marks only
  ENTRY into the LocalMesh startup dispatch (`run_local_mesh_node`), before the
  config is built and before `spawn_binary_consensus_loop` runs. An EXISTING
  post-baseline observation was adopted as the honest anchor:
  `[binary-consensus] B5: applied restore baseline: snapshot_height=… starting_view=… (engine committed_height=…)`,
  emitted by `run_binary_consensus_loop_with_io` AFTER
  `engine.initialize_from_snapshot_baseline(...)` executes. No production
  instrumentation was added, no pre-initialization message / sleep / task-spawn
  was substituted for evidence that initialization completed. Cases B1/B2 now
  assert marker ORDER (not mere presence) —
  `restore OK → B5 construct → Run 093 storage open → Run 097 epoch → LocalMesh
  entry → baseline applied` — and assert the fixture height/starting-view the
  diagnostics expose (111→112, 222→223).
* **Correction B (reliable process outcomes): applied.** The runner now
  preserves the full `ExitStatus` (signals via `ExitStatusExt`, never collapsed
  to an integer); rejects an already-exited positive child even when its
  markers were captured (liveness checked first); resolves the
  liveness/terminate race by classifying on the ACTUAL post-kill status (a
  natural exit code is reported as an unexpected exit, not deliberate
  termination); handles kill/wait errors explicitly on the normal path; keeps
  `Drop` best-effort with no second panic during unwinding; drains and joins
  captured streams before final diagnostics; and refuses to support a
  "forbidden later marker absent" assertion on truncated capture (case C
  asserts `stderr_dropped_bytes()==0` first). Three focused runner-control tests
  use a small test-only `sh -c` child (kept separate from qbind-node protocol
  evidence; per-`Command` `env_remove` only, no process-global env mutation):
  marker-then-unsuccessful-exit ⇒ rejected (exit code 7 preserved);
  marker-then-alive ⇒ deliberate termination identified (signal); missing-marker
  ⇒ bounded-deadline failure. Case C now requires the exact natural exit code 1
  (not merely nonzero), asserts the epoch-conflict-SPECIFIC diagnostic
  (`existing meta:current_epoch=42 but snapshot meta.json declares epoch=7`), and
  preserves the loop-dispatch-absent / epoch-42-preserved / account-restored
  assertions, additionally asserting the baseline-applied observation is absent
  (initializer never ran).
* **Correction C (structural/provenance claims): applied.** Case D now parses
  `meta.json` with the EXISTING typed `StateSnapshotMeta::from_json` (no second
  parser), records that the schema carries more than height/hash/chain/epoch
  (`created_at_unix_ms` + optional `authority_state`/`authority_state_v2`
  carriers, absent in this fixture), reframes the keyword denylists as scoped
  CONTENT observations of THIS fixture (not a universal absence or schema
  claim), separates the single observed account value and the single-key
  `meta:current_epoch` reads from the source-traced recovery-interface finding,
  and preserves the NOT-established signing-state-continuity conclusion. The
  executable-provenance runner line is explicitly labelled `byte_len … (no
  sha256 emitted here)`; the authoritative SHA-256 is captured out-of-band by
  `sha256sum` and recorded below (the runner does not emit a content hash).

### Exact observed startup boundary vs source-only inference

* **Executable-observed (release binary):** account-state restoration; the
  ordered restore/storage/epoch markers; entry into the LocalMesh startup
  dispatch; and — new in this correction — that
  `initialize_from_snapshot_baseline` actually ran, via the post-baseline
  `[binary-consensus] B5: applied restore baseline …` observation. Consensus
  storage epoch handling is executable-observed plus independent post-process
  reopen.
* **Source-traced (not runtime-observed by this test):** that only
  `snapshot_height`/`snapshot_block_id` travel the `RestoreBaseline`, and that
  no per-view vote latch or anti-equivocation record travels the recovery
  interface (Run 422 D7-D2). Signing-state continuity remains NOT-established.

### Positive/negative process outcomes and runner-control results

* B1 (epoch absent): observed-then-deliberately-terminated (SIGKILL after the
  baseline-applied marker); independent reopen ⇒ account `(7,4242)`, consensus
  `PresentNoCommittedEpoch`.
* B2 (epoch `Some(0)`): observed-then-deliberately-terminated; independent
  reopen ⇒ account `(7,4242)`, consensus `CommittedEpoch(0)`; absence ≠ 0.
* C (epoch conflict): natural exit code **1**; epoch-conflict-specific FATAL
  (42 vs 7); loop-dispatch + baseline-applied markers absent (untruncated
  capture); consensus epoch **42 preserved**; `state_vm_v0` account restored
  before rejection.
* Runner controls: reject-on-unsuccessful-exit (code 7 preserved) PASS;
  identify-deliberate-termination (signal) PASS; missing-marker deadline failure
  PASS.

### Commands, test counts, profiles, release-executable hash

Release build (source-corresponding, rebuilt this pass):

```
cargo build --release -p qbind-node --bin qbind-node   # Finished release in 7m12s
sha256sum target/release/qbind-node
70671e40871c9a8010b3ddbff5dc489ce4cb28aeb807460ccaf0d06f36cce923  target/release/qbind-node
# byte_len = 16953520
```

This exact release executable was built from the checked-out source tree at this
correction's HEAD via the required command above; B1/B2/C were repeated against
it (a successful build alone was treated as insufficient):

```
QBIND_D7D3_NODE_BIN="$PWD/target/release/qbind-node"   cargo test -p qbind-node   --test run_422_d7d3_binary_snapshot_restore_characterization_tests -- --test-threads=1
# test result: ok. 7 passed; 0 failed
```

Retained-log excerpts (below) were obtained by selecting the release executable
AND enabling the stderr-dump option:

```
QBIND_D7D3_NODE_BIN="$PWD/target/release/qbind-node" QBIND_D7D3_DUMP_STDERR=1   cargo test -p qbind-node   --test run_422_d7d3_binary_snapshot_restore_characterization_tests   -- --test-threads=1 --nocapture
```

Newly observed post-baseline lines from the release executable (publish-safe):

```
[d7d3][B1-epoch-absent] [binary-consensus] B5: applied restore baseline: snapshot_height=111 starting_view=112 (engine committed_height=Some(111))
[d7d3][B2-epoch-zero]   [binary-consensus] B5: applied restore baseline: snapshot_height=222 starting_view=223 (engine committed_height=Some(222))
```

Validation targets (dev profile unless noted; `--test-threads=1`):

* `run_422_d7d3_binary_snapshot_restore_characterization_tests` — **7 passed**
  (dev binary and, via `QBIND_D7D3_NODE_BIN`, the exact release executable
  `70671e40…`). Includes the 3 runner-control cases.
* `b3_snapshot_restore_tests` — 10 passed.
* `b5_restore_aware_consensus_start_tests` — 4 passed.
* `run_422_d7c1_storage_observation_tests` — 23 passed.
* `run_422_startup_refusal_tests` — 4 passed.
* `run_097_snapshot_epoch_parity_tests` — 7 passed (Run 097 epoch-parity reuse).
* `run_422_d7d2_signing_state_recovery_tests` — 5 passed.
* Focused Clippy: `cargo clippy -p qbind-node --test
  run_422_d7d3_binary_snapshot_restore_characterization_tests` — **clean for the
  changed target** (zero warnings referencing the target file; the ~85
  pre-existing `qbind-node` lib warnings are unrelated and unchanged).
* No repository-wide formatting or unrelated warning fixes; file-specific CRLF
  line endings and no-final-newline EOF conventions preserved.

### Security tooling (recorded literally)

* Secret scan of the changed target: no secrets detected.
* Secret scan (`secret_scanning`) over all four changed files: **no secrets
  detected**.
* `parallel_validation` was run for THIS correction pass with the following
  LITERAL outcomes (recorded here, not deferred to the final chat report):
  * **CodeQL Security Scan: SKIPPED = INCOMPLETE ANALYSIS.** Returned literally
    "Skipped: all changes are trivial." (changes were declared trivial for
    CodeQL — test-only Rust file plus Markdown docs, no production source). A
    skipped run does **not** establish CodeQL coverage and is **not** a
    0-alerts-verified pass.
  * **Code Review: INCOMPLETE / UNVERIFIED.** The backend emitted a
    model-registry error (`model claude-sonnet-4.6 not found in registry` /
    "Code review tool is not available in this environment") while reporting
    "No review comments found." An unavailable/errored reviewer is **not** a
    successful review; "no comments" alongside a backend error does **not**
    become a pass.
* Neither CodeQL nor the reviewer establishes a clean security posture for this
  change; both are recorded as incomplete/unverified per the run rules.

### Scoped verdict (corrected)

`D7D3_BINARY_SNAPSHOT_RESTORE_CHARACTERIZATION=COMPLETE-FOR-TESTED-SCOPE`, with
the evidence boundary stated honestly: account restoration and consensus-storage/
epoch handling are executable-observed (plus independent reopen); baseline
construction/dispatch is observed at the actual markers; engine-initializer
CONSUMPTION is now executable-observed via the post-baseline
`[binary-consensus] B5: applied restore baseline …` line; and the
recovery-interface signing-state finding remains **source-traced, not runtime
observed**, so signing-state continuity stays **NOT-established**. Retained
unchanged: `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. No readiness promotion and no
Run 423 work. Prior execution results at their actual revisions are retained and
not relabelled as newly executed.

## Run 422 D7-D3 correction (process-runner reliability, this pass) — B1/B2/B3 (test + evidence)

This bounded pass completes the **process-runner reliability** corrections on the
D7-D3 target. It refines the earlier "Correction B" (which still classified any
terminating signal as deliberate and silently dropped capture failures) and makes
the runner controls deterministic. It preserves the accepted A/C findings above
and the real-checkpoint / account-restoration / epoch-parity evidence. It changes
**only** the D7-D3 test target and documentation; no production source, getter,
CLI flag, storage/schema, authorization, activation, or recovery redesign was
touched. Genesis-authority activation stays DISABLED.

### Provenance and object availability (this pass)

* Actual branch inspected/used: `copilot/copilotcopilotcopilotcopilotcopilotcopilot-run-422`
  (six `copilot` segments — differs from the reported
  `copilot/copilotcopilotcopilotcopilotcopilot-run-422-d7-d2`). Supplied task
  branch used unchanged with normal commits + push only — no PR, main change,
  branch rename, force-push, rebase, or history rewrite. `task/warning.txt` and
  unrelated files untouched. Worktree clean at checkout; shallow single-branch
  clone (`git rev-parse --is-shallow-repository` = `true`).
* Starting HEAD at checkout: `b21814a7e3935488dd81f0014ff30e42ecdfa97e`.
* Capacity at start: `/dev/root` 145G total, ~85G avail (42% used).
* Reviewed revision `278a87ebf9c524cf1af286641197272a4400845a` is **not present**
  in this shallow clone (`git cat-file -t` fails). Missing reference objects do
  not imply missing implementation: the D7-D3 target and named production sources
  are present in-tree and were re-inspected directly; content correspondence is
  reported separately from ancestry, which cannot be verified here.
* Implementation checkpoint (corrected test committed BEFORE validation):
  `8751e8bf4d05c2d8f27b46d542a36ce580dbf24b`.

### Changed files (this pass)

* `crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
  (B1/B2/B3 corrections; now **12 tests**: A/B/C/D + 3 runner-control + 5
  constructed classification/capture controls).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (this subsection).
* `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md`
  (successor-note refinement of the runner description to match B1/B2/B3 only).
  `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` was left
  unchanged (its successor note is accurate and does not overstate the runner).

No production source file was modified; production behavior is unchanged.

### Disposition of B1/B2/B3

* **B1 (classify deliberate termination correctly): applied.**
  `observe_then_terminate` now preserves BOTH the termination-request result
  (`kill()` outcome) and the full `ExitStatus`, and classifies via a pure,
  unit-testable `classify_termination(kill_succeeded, status, expected_signal)`
  helper. A deliberate termination is accepted **only** when the requested kill
  succeeded AND the observed terminating signal equals the expected SIGKILL
  (`EXPECTED_TERMINATION_SIGNAL=9`). A natural exit ⇒
  `ExitedBeforeDeliberateTermination` (real status preserved); a different
  terminating signal or a failed kill request ⇒ `UnexpectedTermination` (never a
  positive). Liveness is still checked first; wait errors are handled explicitly
  and cleanup is **not** marked complete when reaping failed (`Drop` retries).
  `Drop` stays best-effort and cannot raise a second panic during unwinding
  (poison-tolerant `lock_recover`; no `.expect` locks in the cleanup path).
  Constructed-status coverage (`classify_termination_decision_table`, using
  `ExitStatus::from_raw`): (a) SIGKILL+kill-ok ⇒ `DeliberatelyTerminated`;
  (b) SIGABRT(6)+kill-ok ⇒ `UnexpectedSignal` (rejected); (c) SIGKILL+kill-failed
  ⇒ `KillRequestFailed` (never accepted); (d) exit code 7 ⇒ `NaturalExit{Some(7)}`
  regardless of kill result. These constructed tests are clearly separated from
  real-child observations and qbind-node evidence.
* **B2 (propagate capture failures): applied.** `drain_into` now records a
  terminal per-stream `read_outcome` (`Some(Ok)` on EOF, `Some(Err(bounded
  desc))` on a non-`Interrupted` read error — no silent break).
  `join_drain_threads` records capture-thread join failures (panics) instead of
  discarding them. A new `CaptureOutcome` (`Complete` / `Truncated` /
  `ReadFailed` / `ThreadPanicked` / `StillDraining`) is computed by the pure
  `classify_capture`; only `Complete` (`is_complete()`) may support an absence
  assertion. Positive results now CARRY the capture outcome
  (`ObservedThenTerminated{…, capture}` / `Deadline{…, capture}`);
  `expect_observed_then_terminated` asserts `capture.is_complete()`. Case C's
  missing-marker absence assertions now require `capture.is_complete()` (not the
  weaker `stderr_dropped_bytes()==0`). Deterministic controls:
  `capture_read_error_is_propagated_not_silently_dropped` (reader yields bytes
  then an I/O error ⇒ `ReadFailed`, cannot support absence);
  `capture_thread_join_failure_is_recorded` (panicking `JoinHandle` ⇒
  `join().is_err()`; `ThreadPanicked` cannot support absence);
  `capture_truncation_cannot_support_absence` (reader overflows the ring cap then
  EOF ⇒ `Truncated`, cannot support absence despite a clean EOF).
* **B3 (deterministic, bounded child controls): applied.** All runner controls
  use SINGLE-PROCESS waiting children so no descendant survives holding the
  pipes: the alive controls `exec sleep` after the marker (`printf … 1>&2; exec
  sleep 30` and `exec sleep 30`), so a kill closes the captured pipes at once and
  drain-thread joins do not block on a surviving sleep. The exit-7 control now
  establishes the child's COMPLETED exit through a bounded PROCESS-STATUS wait
  (`establish_exit`, repeated `try_wait`, NOT a fixed sleep) before exercising the
  already-exited observation path, removing the kill-vs-exit race. Marker content
  and exit-code assertions are preserved. Both the deliberate-termination and the
  missing-marker deadline controls assert cleanup returns within a generous outer
  bound (`RUNNER_CONTROL_CLEANUP_OUTER_BOUND=15s`, far below the 30s descendant
  sleep) — a result returned only after a 30s sleep would fail these. No
  process-global environment mutation (per-`Command` `env_remove` only).

### Runner-control and constructed-control outcomes (exact)

* `runner_control_rejects_marker_then_unsuccessful_exit` — PASS. `establish_exit`
  returns code 7; `observe_then_terminate` ⇒ `ExitedBeforeDeliberateTermination`
  with code 7 preserved and the marker captured (rejected despite the marker).
* `runner_control_identifies_deliberate_termination_of_live_marked_child` — PASS.
  ⇒ `ObservedThenTerminated{term_signal=9, capture=Complete}`; cleanup elapsed
  well under the 15s outer bound (no surviving-sleep block).
* `runner_control_missing_marker_deadline_is_failure` — PASS. ⇒ `Deadline{capture=
  Complete}`, marker genuinely absent; deadline+cleanup under the 15s outer bound.
* `classify_termination_decision_table` — PASS (B1 decision table above).
* `capture_read_error_is_propagated_not_silently_dropped` — PASS (`ReadFailed`).
* `capture_thread_join_failure_is_recorded` — PASS (`ThreadPanicked`).
* `capture_truncation_cannot_support_absence` — PASS (`Truncated`).
* `complete_capture_is_the_only_absence_supporting_outcome` — PASS (`Complete`).

### Commands, counts, profiles, release-executable hash (this pass)

Release build (source-corresponding, rebuilt this pass because the previously
reported executable `70671e40…` is not present in this fresh clone and its hash /
source correspondence could not be established here):

```
cargo build --release -p qbind-node --bin qbind-node   # Finished release in 6m41s
sha256sum target/release/qbind-node
e62a6e5ef576b2afb403b3b4c048cdb0b75db364c3339151fd95c16724f44165  target/release/qbind-node
# byte_len = 16953504
```

The rebuilt hash **differs** from the previously reported `70671e40…`; per the run
rules no reproducibility or non-reproducibility is inferred from the differing
hash. This executable was built from the checked-out source at this pass's HEAD;
compilation alone was not treated as executable-level validation.

D7-D3 target (dev profile) and repeated against the exact release executable via
`QBIND_D7D3_NODE_BIN` (cases B1/B2/C execute against that binary):

```
cargo test -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests
# test result: ok. 12 passed; 0 failed

QBIND_D7D3_NODE_BIN="$PWD/target/release/qbind-node" \
  cargo test -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests
# test result: ok. 12 passed; 0 failed   (B1 epoch-absent, B2 epoch-zero, C epoch-conflict against e62a6e5e…)
```

Real-binary B1/B2/C results against `e62a6e5e…`:

* B1 (epoch absent): observed-then-deliberately-SIGKILL-terminated at
  `M_BASELINE_APPLIED`, complete capture; independent reopen ⇒ account `(7,4242)`,
  consensus `PresentNoCommittedEpoch`.
* B2 (epoch `Some(0)`): observed-then-deliberately-SIGKILL-terminated, complete
  capture; independent reopen ⇒ account `(7,4242)`, consensus `CommittedEpoch(0)`;
  absence ≠ explicit 0.
* C (epoch conflict): natural exit code **1** (signal `None`); epoch-conflict-
  specific FATAL (existing 42 vs snapshot 7); loop-dispatch + baseline-applied
  markers absent under **complete** capture; consensus epoch **42 preserved**;
  `state_vm_v0` account restored before the fail-closed rejection.

Scope of retesting: the changes are confined to this single test target (no shared
helper outside it), so previous regression results at their actual revisions are
retained unchanged and not re-run/relabelled.

* Focused Clippy: `cargo clippy -p qbind-node --no-deps --test
  run_422_d7d3_binary_snapshot_restore_characterization_tests -- -D warnings` —
  **clean for the changed target** (zero findings referencing the target file
  after fixing one `clippy::io_other_error` in the new test code). The pre-existing
  `qbind-node` lib and `qbind-consensus` clippy findings are unrelated to this
  change and were not touched.
* Formatting/whitespace checked in the changed file only: no real trailing
  whitespace introduced (0 lines with space/tab before the CR); CRLF line endings
  and the no-final-newline EOF convention preserved. The file follows a
  pre-existing house style with single-line `assert!` messages wider than the
  default rustfmt `max_width`; default-rustfmt line-wrap diffs (pre-existing and
  in the additions alike) were **not** applied to avoid reformatting unrelated
  lines and introducing a mixed style.

### Security tooling (recorded literally, this pass)

* Secret scan (`secret_scanning`) of the changed files: **no secrets detected**.
* `parallel_validation` (CodeQL + Code Review) LITERAL outcomes for this pass:
  * **CodeQL Security Scan: SKIPPED = INCOMPLETE ANALYSIS.** Returned literally
    "Skipped: all changes are trivial." (declared trivial for CodeQL — a single
    Rust integration TEST file plus Markdown docs, no production source). A
    skipped run does **not** establish CodeQL coverage and is **not** a
    0-alerts-verified pass.
  * **Code Review: INCOMPLETE / UNVERIFIED.** The tool reported "No review
    comments found" but ALSO emitted a backend error: "Code review tool is not
    available in this environment: … model `claude-sonnet-4.6` not found in
    registry" (`capi-prod-claude-sonnet-4.6` creation failure). An
    unavailable/errored reviewer is **not** a successful review; "no comments"
    alongside a backend error does **not** become a pass.
* Neither CodeQL nor the reviewer establishes a clean security posture for this
  change; both are recorded as incomplete/unverified per the run rules.

### Scoped verdict (this pass)

`D7D3_PROCESS_RUNNER_RELIABILITY=COMPLETE-FOR-TESTED-SCOPE`: unexpected
exits/signals can no longer pass as deliberate termination (B1); capture
read/join failures cannot support successful observations or missing-marker
claims (B2); runner controls are deterministic and cleanup does not wait on
surviving sleep descendants (B3); and the corrected real-binary B1/B2/C cases pass
against `e62a6e5e…`. Retained unchanged: `D7_STATUS=PARTIAL-CODE-TEST /
PRODUCTION-LIFECYCLE-UNAVAILABLE`, `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. Signing-state continuity remains
NOT-established. No readiness promotion and no Run 423 successor restart
investigation was started.

## Run 422 D7-D4 — restart after a partially completed restore (test + evidence)

This phase is a **bounded characterization** of what the *existing* binary does
on the two subsequent starts that follow the D3 case-C partial restore (a
restored `state_vm_v0` alongside a preserved conflicting consensus epoch). It
adds three `d7d4_*` cases to the existing D3 integration target plus this
evidence section. It implements **no** recovery repair, rollback protection,
authority activation, production-source/CLI/config/schema/storage-format/
signing/wire change, cleanup command, or new persistence mechanism.
Genesis-authority activation stays DISABLED. A successful characterization
records existing behavior; it does **not** establish safe recovery, state
coherence, signing continuity, or production readiness.

### Provenance and object limitations

* **Actual branch** inspected in this clone:
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilot` (seven `copilot`
  segments). The task's **reported** branch was
  `copilot/copilotcopilotcopilotcopilotcopilotcopilot-run-422`. No branch rename
  was performed; the working branch is reported as-is.
* **Actual starting HEAD** at checkout:
  `358a69052a73d906dbe29c722f741579b9b5e19a`. **Tested implementation
  checkpoint** (committed before recording validation):
  `7208e043415b3b184235e20d0f178b7553fa7252`. The task's **reported** final
  `dba99d62691bc33e888706a75cba6d4cbf49ed4a` and checkpoint
  `8751e8bf4d05c2d8f27b46d542a36ce580dbf24b` are **not present** in this shallow
  clone (`git cat-file -t` fails for both). The clone is shallow with a single
  grafted boundary at `b21814a7e3935488dd81f0014ff30e42ecdfa97e` (`.git/shallow`).
  Missing historical objects do **not** imply missing implementation: the D3
  target and every reused production source named by the task are present in-tree
  and were re-inspected directly. Content correspondence is reported separately
  from ancestry, which cannot be verified from this shallow clone.
* Capacity at start: `/dev/root` 145G total, 85G avail (42% used) — ample.
* Supplied task branch used with normal commits + push only. No PR, no main
  changes, no branch rename, no force-push, rebase, or history rewrite.
  `task/warning.txt` and unrelated files untouched. File-specific CRLF line
  endings of the D3 target and this doc are preserved.

### Source trace: WITH vs WITHOUT the restore flag (distinct paths)

Both starts share the same early dispatch
(`crates/qbind-node/src/main.rs` ~L2463) but diverge on whether restoration is
requested:

* **WITH `--restore-from-snapshot` (requested restoration).**
  `apply_snapshot_restore_if_requested_inner` (fast-sync enabled) runs the
  materialization pipeline. Because no `--genesis-path` is supplied and no local
  `pqc_authority_state.json` marker exists on the partial destination, it takes
  the legacy no-context branch → `restore_from_snapshot` →
  `materialize_validated_snapshot`
  (`crates/qbind-node/src/snapshot_restore.rs`). There the `target_state_dir`
  (`<data_dir>/state_vm_v0`) already exists and is **non-empty** (it was
  materialized by the case-C restore), so the empty-check returns
  `RestoreError::TargetStateNotEmpty` **before** any byte copy or
  `write_restore_marker`. `main.rs` prints `[restore] ERROR: <Display>` and
  `std::process::exit(1)`. The `TargetStateNotEmpty` guard belongs to this
  requested-restoration path only.
* **WITHOUT the flag (ordinary startup).**
  `apply_snapshot_restore_if_requested` sees fast-sync disabled and returns
  `Ok(None)`. `main.rs` prints the normal-startup line, builds **no**
  `RestoreBaseline`, and **skips** the Run 097 epoch block entirely (it is
  guarded by `if let Some(outcome)`). The `TargetStateNotEmpty` guard does
  **not** run and no snapshot-epoch comparison is performed. Startup then opens
  the canonical consensus storage (which already holds epoch 42), dispatches into
  `run_local_mesh_node`, and enters `run_binary_consensus_loop_with_io` with
  `restore_baseline=None`, so `initialize_from_snapshot_baseline` is **not**
  invoked (no `[binary-consensus] B5: applied restore baseline` line). The honest
  last-observed boundary is the existing `[binary-consensus] Starting consensus
  loop:` line (exposing `restore_baseline=false`), reached while the child is
  still alive.

The `[binary] LocalMesh mode: starting consensus loop` line is a **dispatch
marker only**; engine baseline application is a distinct, later step and is
**not** claimed for the WITHOUT-flag path (there is no baseline to apply).

### How each partial destination was produced (independently, through the real binary)

Each continuation calls the extracted test-local helper
`reproduce_case_c_partial_restore`, which reproduces D3 case C end-to-end through
the **unmodified release executable** for its **own** independent tempdirs:

1. Build a real RocksDB account-state store (account `0xCD..`, value 4242) and a
   real checkpoint via `StateSnapshotter::create_snapshot`, meta declaring
   height 333, **epoch 7**.
2. Seed **only** `<data_dir>/consensus` with committed **epoch 42** (RocksDB
   handle dropped before launch).
3. Launch `qbind-node --restore-from-snapshot` (LocalMesh DevNet).
4. Require natural **exit 1**, complete capture, the Run 097 epoch-parity FATAL
   with the exact `existing meta:current_epoch=42 but snapshot meta.json declares
   epoch=7` diagnostic, and `restore → B5 → storage-open → epoch-FATAL` order.
5. After the child is reaped, independently reopen both stores: restored account
   `AccountState::new(7, 4242)` and consensus `CommittedEpoch(42)`.
6. Record the restore audit-marker (`RESTORED_FROM_SNAPSHOT.json`) written by
   this first invocation.

The helper preserves every original case-C assertion; `d7d3_c` now calls it. The
continuations never share a destination and never hand-fabricate the partial
directory. All RocksDB handles are closed before every child launch; stored
logical values are read only after reaping (a selected-value match is **not**
claimed to be directory byte-identity).

### Scenario table (observed against the release executable)

| Case | Args (beyond `--env devnet --network-mode local-mesh --data-dir <partial>`) | Observed exit / termination | Capture | Last observed startup boundary | Before → after stored values |
| --- | --- | --- | --- | --- | --- |
| **A** WITH-flag retry | `--restore-from-snapshot <snap-epoch7>` | **natural exit 1** (no signal) | complete | `[restore] ERROR: … target state directory is not empty:` (`TargetStateNotEmpty`); **no** storage-open, loop, or baseline | account 7/4242 → 7/4242; `CommittedEpoch(42)` → `CommittedEpoch(42)`; audit marker byte-identical (not appended/replaced) |
| **B** WITHOUT-flag restart | *(none — flag omitted)* | observed-while-alive → deliberate SIGKILL(9) | complete | `[binary-consensus] Starting consensus loop:` with `restore_baseline=false` (proceeded past `[restore] no …; normal startup.` → storage-open `state=committed-epoch epoch=42` → LocalMesh dispatch) | account 7/4242 → 7/4242; `CommittedEpoch(42)` → `CommittedEpoch(42)` (unchanged at loop-start); audit marker byte-identical (ordinary start writes none) |
| **C** fresh control | *(none — flag omitted, fresh empty data dir)* | observed-while-alive → deliberate SIGKILL(9) | complete | `[binary-consensus] Starting consensus loop:` with `restore_baseline=false` (storage-open `state=present-no-committed-epoch`) | consensus `PresentNoCommittedEpoch` (never `CommittedEpoch(42)`) — distinct from the partial destination |

### Evidence-boundary separation (explicit)

* **Executable observations:** the exit codes, terminating signal (SIGKILL 9),
  ordered stderr markers, and `restore_baseline=false` field are all from the
  real child `qbind-node` process; timeouts are hard failures and only an
  observed-while-alive → deliberate-SIGKILL outcome with complete capture counts
  as a positive (`observe_then_terminate` / `expect_observed_then_terminated`).
* **Independent database reads:** account value and consensus observation are
  read by reopening the RocksDB stores in-process **after** the child is reaped,
  via the existing `RocksDbAccountState` reader and
  `observe_consensus_storage` (C1). These are single-key/single-account reads,
  not a full-store inventory or a directory byte-identity claim.
* **Fixture declarations:** snapshot height 333 / block hash / epoch 7 are
  `StateSnapshotMeta` inputs, not authenticated consensus evidence.
* **Source-only conclusions:** the WITH/WITHOUT branch divergence, the
  `TargetStateNotEmpty` location before any copy/marker write, and the absence of
  a Run 097 comparison on the WITHOUT-flag path are source-traced (cited above),
  distinct from the executable observations.

### Newly characterized recovery limitation

Ordinary startup (case B) **proceeds** over the mixed account/epoch destination:
restored `state_vm_v0` (account 7/4242) coexists with preserved consensus
`CommittedEpoch(42)`, and the binary starts the consensus loop from a fresh
(`restore_baseline=false`) engine without any snapshot-epoch comparison. This is
recorded as an **observed limitation requiring assessment before production
activation** — it is **not** coherent or safe recovery, and it is **not**
repaired in this task. The last observed boundary is the consensus-loop-start
line; **no** engine recovery of the mixed state is inferred from startup
dispatch.

### Validation (recorded literally)

Dev profile unless noted; the child-process cases additionally executed against
the explicitly selected release executable via `QBIND_D7D3_NODE_BIN`.

* **Full D3+D4 integration target — dev binary:**
  `cargo test -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests -- --test-threads=1`
  → **15 passed; 0 failed** (12 D3/runner-control + 3 new D4 = 15; retained
  runner controls intact).
* **Full D3+D4 integration target — explicitly selected release executable:**
  `QBIND_D7D3_NODE_BIN="$PWD/target/release/qbind-node" cargo test -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests -- --test-threads=1`
  → **15 passed; 0 failed**. The three D4 cases were also run in isolation with
  `QBIND_D7D3_DUMP_STDERR=1` to transcribe the exact child stderr shown above.
* **Focused Clippy (changed test target):**
  `cargo clippy -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests`
  → the changed test target compiles with **no warnings attributable to it**.
  With `-D warnings` the command fails on **pre-existing** `clippy::needless_return`
  lints in the `qbind-consensus` **library** (`basic_hotstuff_engine.rs`), a
  dependency this test-only change does not touch and does not modify — recorded
  literally, not converted into a pass or a regression.
* **Focused regressions:** `cargo test -p qbind-node --test b3_snapshot_restore_tests`
  → **10 passed**; `cargo test -p qbind-node --test run_097_snapshot_epoch_parity_tests`
  → **7 passed**. (Newly executed subsets are reported separately; not summed
  with overlapping historical D3 counts.)
* **File-specific whitespace / line endings:** the changed target retains **CRLF**
  line endings throughout (2061/2061 lines CRLF; final `}` without trailing
  newline, matching the pre-existing file), no trailing whitespace, no tabs.
  `git diff --numstat` = `391 insertions, 4 deletions` (the moved case-C body
  matched as unchanged context — no whole-file line-ending churn).

### Executable identity

| Field | Value |
| --- | --- |
| Path | `target/release/qbind-node` |
| SHA-256 | `575215409d09a2b8500a48d04d1ef6026da45d76d04e05c9c24574998d6df54c` |
| Byte length | `16953520` |
| Build / source revision | `358a69052a73d906dbe29c722f741579b9b5e19a` (starting HEAD) |
| Profile | `release` |
| Build command | `cargo build --release -p qbind-node --bin qbind-node` |

A different hash on a future rebuild is an observation, not proof of either
reproducibility or a regression.

### Security tooling (recorded literally)

Reported literally: no CodeQL result is asserted in this section. A skipped
CodeQL run is incomplete analysis, and an unavailable or errored reviewer is not
a completed review; “0 alerts” or “no comments” accompanying such outcomes are
**not** converted into passes. The changes are **test + documentation only**
(no production source, CLI, schema, storage-format, signing, or wire change).

### Scoped verdict

`D7D4_PARTIAL_RESTORE_RESTART_CHARACTERIZATION=COMPLETE-FOR-TESTED-SCOPE`

Both continuations and the control have concrete, asserted outcomes against the
identified release executable (SHA-256 `57521540…`): (A) the WITH-flag retry is
refused with the `TargetStateNotEmpty` diagnostic at natural exit 1, leaving the
account value, consensus epoch 42, and restore audit marker unchanged; (B) the
WITHOUT-flag restart proceeds to the consensus-loop-start boundary with
`restore_baseline=false` over the mixed destination (observed limitation), epoch
42 unchanged at loop-start; (C) the fresh control reaches the same boundary but
shows `PresentNoCommittedEpoch`, distinguishing partial-destination behavior from
normal startup. No deadline or runner failure was used to complete any scenario.

### Retained posture (unchanged by D7-D4)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. Signing-state continuity
remains **NOT-established**; C4/C5 stay open. No readiness promotion and no
Run 423 successor work was started. The one material contradiction surfaced —
ordinary startup proceeding over a mixed account/epoch destination — is recorded
above as a recovery limitation for separate follow-up assessment, not repaired
here.

### Clean-worktree / push status

Changes limited to the four authorized paths, committed to the task branch and
pushed via the progress tool (test checkpoint committed **before** validation
results were recorded). No PR, no main changes, no branch rename, no force-push,
rebase, or history rewrite. Worktree clean after the documentation commit.

## Run 422 D7-D5 — reject restore epoch conflicts before account-state materialization (code + test + evidence)

D7-D3/D4 demonstrated a partial-destination defect: with a snapshot declaring
canonical epoch 7 restored over a destination whose consensus storage already
committed epoch 42, the *pre-fix* binary materialized `state_vm_v0`, copied the
snapshot account-state bytes, and wrote the restore audit marker, and only THEN
did the Run 097 check reject the epoch conflict — leaving a partially restored
destination. Ordinary startup (no restore flag) could subsequently reach the
consensus loop over that partial destination. D7-D5 is the bounded correction
that prevents creation of that partial destination.

### Old vs corrected effect ordering

Old (pre-fix) ordering for a conflicting restore:

1. `apply_snapshot_restore_if_requested` validates + materializes `state_vm_v0`
   (copies account-state bytes) and writes `RESTORED_FROM_SNAPSHOT.json`.
2. `[binary] B5:` restore baseline constructed.
3. `open_production_consensus_storage` opens `<data_dir>/consensus`.
4. `persist_restored_snapshot_epoch` detects `Some(7)` vs committed `Some(42)`
   and fails closed (`RestoreEpochInconsistent`) — AFTER materialization.

Result: exit 1, but `state_vm_v0` + restore marker already on disk.

Corrected (D7-D5) ordering for a conflicting restore:

1. `open_production_consensus_storage` opens `<data_dir>/consensus` EARLY (only
   when a restore is requested and no CLI storage-exit mode is active); logs the
   `[binary] Run 093 consensus storage:` summary.
2. `[restore] requested:` — the restore pipeline validates the snapshot and the
   authority marker, then runs the D7-D5 pre-materialization epoch precheck on
   the SAME validated `StateSnapshotMeta`.
3. The precheck calls `evaluate_restore_epoch_compatibility(&opened, meta.epoch)`.
   On `Some(7)` vs committed `Some(42)` it returns `RestoreEpochInconsistent`;
   `main.rs` prints `[restore] FATAL: refused by Run 422 D7-D5 consensus
   epoch-conflict check …`, the restore returns
   `RestoreError::ConsensusEpochConflict`, `main.rs` prints `[restore] ERROR: …`
   and `std::process::exit(1)` — BEFORE any `state_vm_v0` creation, account-byte
   copy, restore-marker write, or baseline construction.

Result: exit 1, `state_vm_v0` and the restore audit marker ABSENT, committed
consensus epoch 42 preserved. No partial destination is created.

### Reused compatibility policy and exact check/write separation

The Run 097 helper `persist_restored_snapshot_epoch` previously combined the
epoch comparison and the write. D7-D5 factors the non-writing decision into
`evaluate_restore_epoch_compatibility(opened, snapshot_epoch) ->
Result<RestoreEpochPlan, ProductionConsensusStorageError>` in
`crates/qbind-node/src/production_consensus_storage.rs`. It is the single source
of truth for the compatibility matrix and NEVER writes:

| Snapshot epoch | Existing committed epoch | `RestoreEpochPlan` / result       |
| -------------- | ------------------------ | --------------------------------- |
| None           | any                      | `NoEpochToPersist` (no write)     |
| Some(n)        | none committed           | `PersistAfterMaterialization{n}`  |
| Some(n)        | Some(n)                  | `AlreadyConsistent{n}` (no write) |
| Some(n)        | Some(m), m ≠ n           | `Err(RestoreEpochInconsistent)`   |
| any            | no storage handle        | `NoStorageHandle` (no write)      |

`persist_restored_snapshot_epoch` now calls `evaluate_restore_epoch_compatibility`
and acts on the plan — only `PersistAfterMaterialization` writes — so the early
check and the later persistence path cannot drift. The early check writes
nothing (in particular it never persists the snapshot epoch when storage has no
committed epoch). Failed validation or materialization never becomes an
instruction to persist. Epoch persistence is retained AFTER successful
account-state materialization.

### Validated-metadata ownership and canonical-storage handle lifetime

The early check consumes the SAME validated `StateSnapshotMeta` used to
materialize the restore and to perform later epoch handling: the precheck is a
closure threaded into the restore pipeline via
`apply_snapshot_restore_if_requested_with_context_and_epoch_precheck` /
`SnapshotEpochPrecheckFn`, invoked AFTER `validate_snapshot_for_restore` and the
authority-marker check and BEFORE `materialize_validated_snapshot`. `main.rs`
does not parse `meta.json` separately; no unchecked "validated snapshot"
constructor was introduced. Both production restore branches (authority-context
and no-context) receive the check through the shared inner seam.

A single `OpenedProductionConsensusStorage` handle spans the early check,
materialization, and the later Run 097 persistence: it is opened once
(`pre_opened_consensus_storage`), borrowed by the precheck closure (borrow ends
before the move), then moved into `consensus_storage_lifecycle` and reused at the
Run 093 site — avoiding a second `open_production_consensus_storage` on the same
path (which would fail on the RocksDB lock). Ordinary (non-restore) startups open
at the Run 093 site exactly as before.

### Early storage-opening effects and error precedence

`open_production_consensus_storage` is NOT read-only: it can create the
`<data_dir>/consensus` directory and open/create RocksDB, and it runs the
established schema and incomplete-transition checks. The D7-D5 negative guarantee
is specifically about account-state materialization, restore-marker writes, and
preservation of the existing committed epoch — not byte-identical storage
directories. Read/open failures remain failures (fail-closed) and are never
reinterpreted as epoch absence; "no committed epoch" means a successful read of
an uncommitted surface, not a failed read or an unavailable handle.

Because storage now opens before the requested restore, three CLI early-exit
modes that themselves open `<data_dir>/consensus`
(`--p2p-trust-bundle-reload-check`, the Run 077 hook, and the trust-bundle
reload-apply path) are explicitly EXCLUDED from the early open via
`cli_storage_exit_mode_active`, preventing a double-open lock failure. Those
modes never reach the consensus loop, so D7-D5 does not apply to them and their
behavior is unchanged.

Deliberate diagnostic-precedence changes (documented and tested):

* Startup marker order for a compatible requested restore now begins with the
  `[binary] Run 093 consensus storage:` open (early), then `[restore] OK:`,
  `[binary] B5:`, the Run 097 persistence line (when applicable), the LocalMesh
  loop-start, and the baseline-application line.
* Over a directory holding BOTH a non-empty `state_vm_v0` AND a conflicting
  committed epoch, the epoch-conflict refusal now precedes the
  `TargetStateNotEmpty` occupied-target refusal (the epoch check runs before
  `materialize_validated_snapshot`). The authority-marker check still precedes
  the epoch check. The new check only ADDS refusals; no existing refusal was
  turned into permission to restore.

### Conflict rejection, compatible controls, and failure controls (tests)

Migrated / added in
`crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`:

* `d7d3_c_binary_epoch_conflict_rejected_before_materialization` (migrated D3
  case C): real snapshot epoch 7, seeded consensus epoch 42, `state_vm_v0` and
  restore marker absent. The corrected release-selectable binary refuses with the
  D7-D5 pre-materialization diagnostic at natural exit 1; complete capture is
  required before absent-marker assertions; no `M_RESTORE_OK` / `M_B5` /
  `M_LOOP_REACHED` / `M_BASELINE_APPLIED` / `M_EPOCH_PERSIST`; `M_STORAGE_OPEN`
  precedes the refusal; `state_vm_v0` and the restore marker remain absent
  (checked via `Path::exists()` BEFORE any account accessor); an independent
  reopen shows committed epoch 42 preserved. The rejected request is REPEATED
  over the same destination and must reject again on epoch conflict (not a
  manufactured occupied-target failure), leaving no restored account state.
* `d7d5_c_preexisting_restore_marker_preserved_on_rejection`: with a pre-placed
  `RESTORED_FROM_SNAPSHOT.json` (permitted because the epoch check precedes the
  occupied-target check and never touches the marker), the refused restore leaves
  the marker byte-for-byte unchanged.
* `d7d5_b_compatible_present_epochs_reach_baseline`: real-binary compatible
  controls for `Some(n)/None` (persist n) and `Some(n)/Some(n)` (matching epoch
  NOT overwritten; no `M_EPOCH_PERSIST`), both reaching baseline application with
  the expected committed epoch. Complements `d7d3_b` (None/None and Some(0)/None).
* Unit tests in `production_consensus_storage.rs` (`d7d5_evaluate_matrix_*`,
  `d7d5_persist_and_evaluate_agree_*`) prove the full matrix and that invoking
  the compatibility check alone never persists an epoch into storage with no
  committed epoch, and that check and writer agree.

Existing writer-behavior tests (Run 097) and the deterministic restore-failure
paths are retained; snapshot-invalid, wrong-chain, authority-marker, and
occupied-target refusals remain covered by their existing suites (b3, Run 124,
Run 140) and were re-run green. Storage-open/read, incompatible-schema, and
incomplete-transition fail-closed behavior remains covered by Run 093.

### Migration of historical D3/D4 tests

The corrected binary no longer produces the old case-C partial destination, so
the D3 conflict case now asserts the pre-materialization refusal (above). D7-D4
coverage of behavior over a directory left by older behavior uses a clearly
labeled legacy-layout fixture, `build_legacy_partial_restore_destination`, built
via real library materialization (`restore_from_snapshot`, which performs no
consensus epoch check) over a seeded conflicting consensus epoch — an
imported/pre-fix on-disk layout, NOT a failure produced by the corrected
executable:

* `d7d4_a_repeat_with_restore_flag_over_legacy_partial_rejects_epoch_conflict`:
  the corrected binary WITH the flag over the legacy partial directory now
  refuses with the D7-D5 epoch-conflict refusal (epoch check precedes the
  occupied-target check), leaving account value, consensus epoch 42, and the
  restore marker untouched. (The `TargetStateNotEmpty` occupied-target refusal
  itself remains covered by `b3_snapshot_restore_tests`.)
* `d7d4_b_restart_without_restore_flag_over_legacy_partial_proceeds`: ordinary
  startup (no flag) still proceeds to the consensus loop over the mixed
  account/epoch legacy directory — OUTSIDE this correction's protection (D7-D5
  guards only the requested-restore path). This remains an observed limitation,
  recorded and not repaired here.

Historical D3/D4 execution claims remain at their original SHAs; current tests
distinguish newly prevented partial-state creation from behavior over an
already-existing legacy partial directory.

### D4 record reconciliation

The final accepted D4 revision is `bf5a692a1524537e876197a05e1cf35371b892d0`
(tested checkpoint `7208e043415b3b184235e20d0f178b7553fa7252`). That historical
D4 report recorded a CodeQL scope skip (database-size/backend) and reviewer
unavailability; those outcomes are attributed to that historical report and are
NOT claimed as newly executed here. The present D7-D5 pass records its own tool
outcomes literally below.

### Remaining crash-consistency and legacy-directory limitations

D7-D5 prevents creation of the demonstrated partial destination for a requested
restore with conflicting present epochs. It does NOT repair existing partial
directories, make restoration atomic across the account and consensus databases,
or establish durable anti-rollback. A crash or I/O failure DURING a compatible
restore remains a separate recovery problem: the post-materialization Run 097
persistence/error boundary is retained and is not made infallible by the early
check. Ordinary startup over a legacy partial directory remains outside this
correction's protection. Missing epochs, matching epochs, and successful
restoration are not authorization, signing continuity, or activation evidence.
The assumptions are serialized startup and exclusive directory access; no
protection against concurrent hostile filesystem replacement is claimed.

### Retained posture (unchanged by D7-D5)

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. Required defaults,
unavailable production Proposal/Vote authority, genesis activation refusal,
existing `CurrentEpochUnavailable` behavior, D6 signing bytes, and
Timeout/NewView separation are preserved. No readiness promotion, authority
activation, or Run 423 work.

### Exact release-binary evidence and literal tool outcomes (this pass)

Actual checkout (D7-D5 pass):

* Branch: `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc`
  (trailing `c`; differs from the D7-D4 report's
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilot`). Not renamed.
* Shallow single-branch clone: `.git/shallow` grafts at
  `358a69052a73d906dbe29c722f741579b9b5e19a`; only two commits are locally
  reachable. The accepted D7-D4 references
  (`bf5a692a1524537e876197a05e1cf35371b892d0` final,
  `7208e043415b3b184235e20d0f178b7553fa7252` checkpoint) are NOT present as
  objects in this clone (`git cat-file` fails). Per repository instruction,
  missing historical objects do not imply missing implementation — every named
  production source and test target is present and was inspected.
* Worktree clean before edits; disk capacity ample.

Release build and integration run:

```text
# cargo build --release -p qbind-node --bin qbind-node   (profile: release)
# executable: target/release/qbind-node
# sha256   = eaa42a5bcee4d9ab654cdaf1e56baca5270a28bacce17a74518336d51779163a
# byte_len = 16957384
# build/source revision = 7f7db1c20a0c12f33c0be00ce7797ecc3b977a0d (this branch HEAD at build time)

# QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
#   cargo test -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests
# test result: ok. 17 passed; 0 failed   (release binary; incl. d7d3_c pre-materialization
#                                          rejection, d7d5_b compatible controls, d7d5_c marker
#                                          preservation, d7d4_a/b legacy-layout fixtures)

# Dev-profile run of the same target (CARGO_BIN_EXE_qbind-node):
# test result: ok. 17 passed; 0 failed

# cargo test -p qbind-node --lib production_consensus_storage
# test result: ok. 19 passed; 0 failed   (incl. d7d5_evaluate_matrix_* + d7d5_persist_and_evaluate_agree_*)

# cargo test -p qbind-node --test run_097_snapshot_epoch_parity_tests       => ok. 7 passed
# cargo test -p qbind-node --test b3_snapshot_restore_tests                 => ok. 10 passed
# cargo test -p qbind-node --test b5_restore_aware_consensus_start_tests    => ok. 4 passed
# cargo test -p qbind-node --test run_093_production_consensus_storage_lifecycle_tests => ok. 12 passed
# cargo test -p qbind-node --test run_124_snapshot_restore_authority_marker_tests      => ok. 7 passed
# cargo test -p qbind-node --test run_140_snapshot_restore_v2_authority_marker_tests   => ok. 13 passed
# cargo test -p qbind-node --test run_422_d4_startup_ordering_tests         => ok. 5 passed
# cargo test -p qbind-node --test run_422_startup_refusal_tests             => ok. 4 passed
# cargo check -p qbind-node                                                 => Finished (default features)
```

Literal tool outcomes / limitations:

* `rustfmt --check` on the three changed source files reports diffs, but the
  same diffs are PRE-EXISTING on the base revision (`HEAD~2`):
  `main.rs`, `production_consensus_storage.rs`, and `snapshot_restore.rs` are
  hand-formatted (and the two `*_consensus_storage.rs`/`snapshot_restore.rs`
  sources are CRLF with no trailing newline), so rustfmt is not the governing
  formatter. Changed code matches the surrounding hand-formatted convention
  (e.g. single-line `opened.handle.as_ref().unwrap().put_current_epoch(n)`
  chains as used by existing tests). Unrelated lines were NOT reformatted, and
  file-specific line endings were preserved.
* `cargo clippy -p qbind-node --lib`: the only lint touching the new code is the
  pre-existing `clippy::result_large_err` on functions returning
  `Result<_, RestoreError>` (the large `RestoreError::SnapshotInvalid` variant,
  ≈456 bytes, already triggers this across ~16 sites file-wide). The new small
  `ConsensusEpochConflict` variant does not become the largest variant; boxing
  the enum would be an out-of-scope crate-wide refactor. No new clippy category
  was introduced by the D7-D5 code.
* CodeQL (this pass, literal): **"Analysis was skipped because the database size
  is too large."** Production source changes were declared non-trivial. Per the
  task's reporting rule this is **incomplete/unverified security coverage**, NOT a
  clean result — the reported "0 alerts" does not constitute a completed scan of
  the changed Rust code.
* Code Review (this pass, literal): the reviewer returned **no review comments**,
  but its backend also logged a model-registry error
  (`model claude-sonnet-4.6 not found in registry`), so the "no comments" outcome
  should be read as reviewer-unavailable rather than an affirmatively clean
  review. Both outcomes are recorded verbatim rather than interpreted as passing.

### Scoped verdict and worktree/push status

`D7D5_RESTORE_EPOCH_CONFLICT_BEFORE_MATERIALIZATION=CODE-AND-RELEASE-TEST-POSITIVE`

Justification: the corrected production path rejects a conflicting requested
restore BEFORE `state_vm_v0` creation, account-byte copy, restore-marker write,
and baseline construction while preserving the committed epoch, and this is
demonstrated against a freshly built release executable
(`sha256 eaa42a5b…`, 16957384 bytes) via `QBIND_D7D3_NODE_BIN` (17/17), plus the
compatible controls, marker-preservation, and legacy-layout characterization.
All retained D7 posture lines are unchanged (see above). This verdict is scoped
strictly to pre-materialization epoch-conflict rejection; it does NOT promote
readiness, does not repair pre-existing partial directories, does not make
restore atomic across databases, and does not establish durable anti-rollback.

Changes are limited to the six authorized paths (`main.rs`,
`production_consensus_storage.rs`, `snapshot_restore.rs`, the D7-D3 test target,
and the three docs), committed to the task branch and pushed via the progress
tool with an unambiguous implementation checkpoint recorded BEFORE validation
outcomes. `task/warning.txt` and unrelated files are untouched. No PR, no main
changes, no branch rename, no force-push, no rebase, no history rewrite.

## Run 422 D7-D5 corrective pass — close CLI precheck bypass and cached-epoch decisions (code + test + evidence)

The immediately preceding D7-D5 subsection ("reject restore epoch conflicts
before account-state materialization") landed the factored, non-writing
`evaluate_restore_epoch_compatibility` decision and the pre-materialization
epoch precheck, and closed its verdict as
`CODE-AND-RELEASE-TEST-POSITIVE`. This corrective pass **supersedes that prior
unrestricted D5 completion claim**: review of the actual checkout found two
still-open defects (A, B) and one missing direct test (C). The verdict is only
re-asserted after all three are closed with the evidence below.

### Finding A — CLI modes bypassed the pre-materialization check (closed)

Previously, `cli_storage_exit_mode_active` (any of
`--p2p-trust-bundle-reload-check`, the Run 077 peer-candidate hook, the
trust-bundle reload-apply path, or reload-apply enabled) merely SKIPPED the
early storage open when a restore was also requested, producing
`epoch_precheck=None` while the restore pipeline still ran — copying
account-state and writing the restore marker before the CLI command executed or
rejected its arguments. The absence of later consensus startup did not prevent
those effects. The operative claim that "these modes never reach the consensus
loop, so D7-D5 does not apply to them" has been REMOVED from `main.rs`.

`main.rs` now REFUSES a requested restore combined with any
`cli_storage_exit_mode_active` mode BEFORE the early storage open, before
account-state materialization, and before any restore-marker write, with an
unmistakable diagnostic that names the offending mode(s)
(`[binary] FATAL: refused by Run 422 D7-D5: --restore-from-snapshot is
unsupported in combination with the CLI validation/apply exit mode(s): ...`)
and `std::process::exit(1)`. Every predicate is covered, including its
partial-configuration shapes: the Run 077 hook is active for a peer-candidate
path WITHOUT the enabled flag or the enabled flag WITHOUT a path
(`run077_hook_active(path, enabled) = path.is_some() || enabled`), and the
reload-apply predicate is active for a path without the enabled flag or vice
versa. A flag destined to be rejected later therefore can no longer first
disable the epoch check and permit restoration. CLI modes WITHOUT a restore
request retain their existing behavior (the guard only fires when
`restore_requested` is also true), and normal compatible restores are
unchanged.

Release-binary coverage (in
`run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`), each using a
valid real snapshot declaring epoch 7 against a destination whose consensus
storage already holds committed epoch 42:

* `d7d5a_restore_with_reload_check_mode_refused_before_effects` — predicate
  `p2p_trust_bundle_reload_check.is_some()`.
* `d7d5a_restore_with_peer_candidate_check_path_only_refused_before_effects` —
  Run 077 hook, path-only partial shape.
* `d7d5a_restore_with_peer_candidate_enabled_only_refused_before_effects` —
  Run 077 hook, enabled-only partial shape.
* `d7d5a_restore_with_reload_apply_path_mode_refused_before_effects` —
  `p2p_trust_bundle_reload_apply_path.is_some()`.
* `d7d5a_restore_with_reload_apply_enabled_mode_refused_before_effects` —
  `p2p_trust_bundle_reload_apply_enabled`.

Each asserts: the specific combination refusal itself (not a later missing-file
or command-configuration error), natural failure exit 1 (no signal), complete
stderr capture, ABSENCE of the early storage-open log / epoch-conflict refusal /
`TargetStateNotEmpty` / restore-OK / B5 / loop / baseline / epoch-persist
markers, `state_vm_v0` and the restore marker ABSENT (checked via
`Path::exists()` before any accessor), and an independent reopen confirming the
committed epoch 42 is preserved.
`d7d5a_restore_without_cli_exit_mode_is_permitted_control` is the deliberate-
command-contract control: a restore with NO CLI exit-mode flag reaches the
normal restore path and persists epoch 7. The CLI-only regressions
(`run_069_pqc_trust_bundle_reload_check_tests`,
`run_077_binary_peer_candidate_check_tests`,
`run_070_pqc_trust_bundle_reload_apply_tests`) confirm those commands WITHOUT
restoration remain supported as before.

### Finding B — decisions now read the live storage value (closed)

`evaluate_restore_epoch_compatibility` previously matched
`OpenedProductionConsensusStorage.state`, the cached startup observation. A
write through the same live handle after open (including this binary's own Run
097 persistence) makes that field stale, so the later persistence path could
consume a stale "matching"/"absent" decision and overwrite a now-conflicting
epoch. The function now performs a FRESH read of `meta:current_epoch` through
the canonical live handle
(`ConsensusStorage::get_current_epoch`) at the moment of decision; `opened.state`
is retained only as a startup observation for logging. Both the early precheck
and `persist_restored_snapshot_epoch` consume this same live-backed decision, so
re-evaluation means a real re-read, not a re-read of the cached field. Semantics
are preserved: snapshot `None` never becomes zero and writes nothing; explicit
`Some(0)` stays distinct from absence; a genuinely missing committed epoch
persists only after successful materialization; matching present epochs are not
overwritten; conflicting present epochs reject; a live-read failure surfaces as
`ProductionConsensusStorageError::EpochProbeFailed` and NEVER as epoch absence
or a successful plan. Because live reads are now performed inside the decision,
`main.rs`'s precheck error handling and comments were updated: errors other than
`RestoreEpochInconsistent` (notably `EpochProbeFailed`) are no longer
unreachable and are treated as a fail-closed read-error refusal before
materialization.

Same-object regressions (unit tests in `production_consensus_storage.rs`, using
real temporary storage and mutating through the SAME
`OpenedProductionConsensusStorage` WITHOUT closing/reopening between the
mutation and the decision):

* `d7d5b_live_write_after_open_forces_conflict_not_cached_persist` — open with
  no epoch, write 42 through the live handle, evaluate snapshot 7: both
  evaluator and writer reject; 42 preserved.
* `d7d5b_cached_matching_value_does_not_authorize_after_live_update` — open with
  epoch 7, update the live handle to 42, evaluate snapshot 7: the cached
  "matching" 7 does not authorize; rejects on the live 42.
* `d7d5b_second_persist_through_same_object_rejects_on_live_value` — open with
  no epoch, persist 7, then attempt to persist 9 through the same object:
  rejects and preserves 7.
* `d7d5b_repeat_persist_same_epoch_through_same_object_is_idempotent` —
  repeating persistence of 7 through the same object is an idempotent no-op.
* `d7d5b_live_read_error_surfaces_as_probe_failed_not_absence` — a corrupted
  on-disk `meta:current_epoch` (raw-put corruption mirroring the D7-C1 pattern,
  no public production corruption API added) surfaces as `EpochProbeFailed`,
  never absence or a plan, with the cached `state` deliberately set to a value
  that would otherwise authorize.

The existing positive/no-write semantic-matrix controls
(`d7d5_evaluate_matrix_*`, `d7d5_persist_and_evaluate_agree_*`, and the Run 097
writer tests) are retained. These fixture mutations exercise stale-observation
handling only; they do NOT authorize production epoch rollback and do NOT
establish durable anti-rollback.

### Finding C — no premature persistence after a materialization refusal (closed)

`d7d5c_occupied_target_refused_after_precheck_permits` (release-binary) exercises
the NEW production precheck path (not a library entrypoint that passes no
precheck): a valid real snapshot with epoch `Some(7)`; the destination consensus
storage opens successfully with NO committed epoch (so the epoch compatibility
check PERMITS the attempt — `PersistAfterMaterialization`); `state_vm_v0` is
already occupied with a known sentinel account (id `0xAB..`, value
`AccountState::new(99, 123456)`); and no CLI exclusion mode is selected. The
subsequent occupied-target check refuses materialization.

Before → after observations: consensus `PresentNoCommittedEpoch` → still
`PresentNoCommittedEpoch` (no snapshot-epoch persistence); sentinel account
`(99, 123456)` → unchanged; restore audit marker absent → still absent. The test
requires natural failure exit 1 (no signal) with the specific
`restore-from-snapshot target state directory is not empty:`
(`TargetStateNotEmpty`) diagnostic, absence of the epoch-conflict refusal
(proving the precheck permitted) and of any restore-OK / baseline / epoch-persist
marker, complete capture, and `M_STORAGE_OPEN` preceding the refusal. The
compatible empty-target control demonstrating successful materialization then
persistence of epoch 7 is reused from
`d7d5_b_compatible_present_epochs_reach_baseline` (case `Some(7)/None`). No
production hook was added and the occupied-target guard was not weakened.

### Actual checkout (this corrective pass)

* Branch: `copilot/run-422-close-cli-precheck-bypass` (the actual working
  branch). This differs from the problem statement's reported branch
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc`; not renamed.
* HEAD at start of this pass: `412b0cd24484f7fb82215b3c8eb4b717704e66a8`
  (parent / starting revision of the pass:
  `2e28c2645d55149ba4eaaa269b38426e273aa455`, present locally).
* Shallow single-branch clone (`.git/shallow` grafts at
  `2e28c2645d55149ba4eaaa269b38426e273aa455`); only two commits are locally
  reachable. The problem statement's referenced revisions
  `0d6ac9e512655a23388719d558d0014233aa55dd` (final) and
  `7f7db1c20a0c12f33c0be00ce7797ecc3b977a0d` (release build/test) are NOT present
  as objects in this clone (`git cat-file` fails). Per repository instruction,
  missing history does not imply missing implementation: every named production
  source and test target is present and was inspected.
* Worktree clean before edits; disk capacity ample (~85 GiB free). Changed files
  preserved their file-specific line endings
  (`production_consensus_storage.rs` and the D7-D3 test target are CRLF;
  `main.rs` is LF); `task/warning.txt` and unrelated files untouched.

### Changed files (this corrective pass)

Exactly THREE files carry code/test changes plus the documentation set:

* `crates/qbind-node/src/main.rs` — correction A refusal + correction B precheck
  error-handling/comment updates.
* `crates/qbind-node/src/production_consensus_storage.rs` — correction B live
  read in `evaluate_restore_epoch_compatibility` + same-object/live-read unit
  tests.
* `crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
  — correction A predicate/control tests + correction C occupied-target test.
* Docs: this file, plus
  `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` and
  `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`.

`crates/qbind-node/src/snapshot_restore.rs` was NOT modified in this corrective
pass: its precheck contract (authority-marker check → epoch precheck →
occupied-target materialization) already propagates errors correctly and needed
no change.

### Release-binary evidence and validation outcomes (this corrective pass)

```text
# cargo build --release -p qbind-node --bin qbind-node   (profile: release)
# executable: target/release/qbind-node
# sha256   = cbb8a7bfeef4f36dfeb17e4910d3bcece6a8db6535df3bac1998b1c7b2a68816
# byte_len = 16952728
# source/build revision = a7564d6eb3ebf6bffd4a3031873132ba71a603dc
#   (implementation checkpoint committed BEFORE these validation outcomes; the
#    later documentation/formatting changes in this section are recorded separately
#    and do not alter the tested binary)

# QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node #   cargo test -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests
# test result: ok. 24 passed; 0 failed   (release binary; incl. d7d5a_* CLI-combo refusals +
#                                          control, d7d5c occupied-target, d7d3_c, d7d4_a/b/c,
#                                          d7d5_b/c, runner/capture controls)

# cargo test -p qbind-node --lib production_consensus_storage
# test result: ok. 24 passed; 0 failed   (incl. d7d5b_* same-object live-read/stale-observation
#                                          + retained d7d5_evaluate_matrix_* / persist controls)

# cargo test -p qbind-node --test run_097_snapshot_epoch_parity_tests       => ok. 7 passed
# cargo test -p qbind-node --test b3_snapshot_restore_tests                 => ok. 10 passed
# cargo test -p qbind-node --test b5_restore_aware_consensus_start_tests    => ok. 4 passed
# cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests     => ok. 12 passed
# cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests       => ok. 12 passed
# cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests     => ok. 13 passed
# cargo test -p qbind-node --test run_422_startup_refusal_tests             => ok. 4 passed
# cargo test -p qbind-node --test run_422_d4_startup_ordering_tests         => ok. 5 passed
# cargo check -p qbind-node                                                 => Finished (default features)
```

Literal tool outcomes / limitations (this corrective pass):

* `cargo fmt -p qbind-node -- --check`: the three changed files are NOT in the
  reported diff (pre-existing diffs are confined to unrelated `build.rs` /
  `examples/*` files, which were left untouched). Changed code matches the
  surrounding hand-formatted convention. File-specific line endings preserved;
  no trailing-whitespace was introduced in the changed hunks.
* `cargo clippy -p qbind-node --tests`: no new clippy category is introduced by
  the corrective-pass code (the pre-existing `clippy::result_large_err` on
  `Result<_, RestoreError>` is unchanged and not aggravated; no new large error
  variant was added).
* CodeQL / Code Review (`parallel_validation`): recorded LITERALLY below in the
  final report — a skipped or backend-errored security tool is incomplete
  analysis, not a passing "0 alerts"/"no comments" result.

### Reconciliation

* The prior D5 subsection's
  `D7D5_RESTORE_EPOCH_CONFLICT_BEFORE_MATERIALIZATION=CODE-AND-RELEASE-TEST-POSITIVE`
  claim was UNRESTRICTED with respect to CLI-mode combinations and cached-epoch
  decisions; it is **superseded** by this corrective pass, which re-establishes
  the verdict only after findings A, B, and C are closed with the evidence above.
* The newly explicit restore/CLI incompatibility (A) and the live-read-versus-
  cached-startup-observation distinction (B) are documented above; the
  post-precheck materialization-refusal test (C) is recorded above.
* Historical execution remains attributed to its actual SHAs; missing objects in
  this shallow clone do not retract prior work.
* D4 attribution correction: the historical D4 report's CodeQL outcome was a
  trivial-scope skip, NOT a newly verified database-size result. This corrective
  pass does not inherit or re-assert that as a completed scan.
* Actual changed-file count for this corrective pass: THREE code/test files plus
  three documentation files (enumerated above).

### Verdict (this corrective pass)

`D7D5_RESTORE_EPOCH_CONFLICT_BEFORE_MATERIALIZATION=CODE-AND-RELEASE-TEST-POSITIVE`
— re-asserted only now that A (restore/CLI-combination refused before any
effect), B (decisions read the live committed epoch; read failures stay errors),
and C (occupied-target refusal after a permitting precheck persists nothing) are
each closed with concrete implementation and release-binary/unit-test evidence.

All retained D7 posture lines are UNCHANGED:
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. Existing partial-directory
handling, cross-database crash consistency, signing-state continuity, and durable
anti-rollback remain unresolved. No readiness promotion and no Run 423 work.

### Literal security-tool outcomes (this corrective pass)

Reported verbatim; a skipped or backend-errored tool is INCOMPLETE analysis, not a
passing result:

* CodeQL Security Scan (rust): "Analysis was skipped because the database size is
  too large." — 0 alerts is therefore a SKIP, not a verified clean scan. This is
  the genuine database-size skip; it is distinct from the historical D4 CodeQL
  outcome, which was a trivial-scope skip and must not be re-attributed as a
  verified database-size result.
* Code Review: reviewed 6 file(s), no review comments; however the tool also
  reported a backend limitation ("Code review tool is not available in this
  environment: ... model claude-sonnet-4.6 not found in registry"). The
  no-comments result is therefore NOT evidence of a completed model review.
## Run 422 D7-D5 correction — matching-epoch CLI-combination refusal control (test + evidence only)

This is a coverage-only correction. No production behavior changed; only the two
files below were edited. It closes the one acceptance control the prior D7-D5
corrective pass left missing: a real-binary regression showing that the
restore + excluded-CLI-mode refusal fires even when the snapshot and destination
committed epochs MATCH (i.e. independently of any epoch conflict).

### Provenance and object availability (actual checkout)

* Actual working branch: `copilot/run-422-complete-compatible-epoch-cli-refusal-cont`.
* Starting SHA (this session): `49c3554`.
* Reviewed-branch / final-revision / tested-checkpoint SHAs cited in the task
  (`copilot/run-422-close-cli-precheck-bypass`, `b1ff541…`, `a7564d6…`) are NOT
  present in this shallow single-branch clone: `git cat-file -t b1ff541…` and
  `git cat-file -t a7564d6…` both return "could not get object info". Missing
  historical objects do not establish missing implementation; the reviewed
  restore/CLI-combination guard and its five predicate cases are present in the
  worktree and pass here (below).
* Final SHA is the task-branch commit recorded by the push accompanying this
  entry.

### Change (two files only, no production change)

* `crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
  — the existing refusal helper `assert_restore_plus_cli_mode_refused_before_effects`
  was minimally parameterized with a `dest_committed_epoch: u64` argument (used
  when seeding the destination consensus store and in the post-reap
  `CommittedEpoch(dest_committed_epoch)` observation). The five pre-existing
  predicate cases are UNCHANGED in meaning — each now passes `42` explicitly and
  still seeds/asserts `CommittedEpoch(42)`. One case was added:
  `d7d5a_restore_with_cli_mode_and_matching_epoch_refused_before_effects`
  (snapshot `Some(7)`, destination `CommittedEpoch(7)`, existing
  `--p2p-trust-bundle-reload-apply-enabled` predicate). The
  restore-without-CLI positive control (`d7d5a_restore_without_cli_exit_mode_is_permitted_control`)
  and the B/C regressions are unchanged. No new runner, fixture framework,
  parser, or production accessor was introduced.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — this entry.

### New matching-epoch case — concrete observations

Valid real snapshot declaring epoch 7; destination seeded to `CommittedEpoch(7)`
(matching), with NO `state_vm_v0` directory and NO restore marker; storage
handles closed before the child launched. Via the existing child-process runner,
capture checks, markers, and `QBIND_D7D3_NODE_BIN` selector, the case asserts:

* Natural exit code 1, `status.signal()` is `None` (no terminating signal).
* stderr carries `M_D7D5_CLI_COMBO_REJECT` (the specific D7-D5 restore+CLI-mode
  combination refusal).
* stderr capture is complete before any absence assertion is relied on.
* NONE of `M_STORAGE_OPEN`, `M_D7D5_REJECT` (epoch-conflict), `M_TARGET_NOT_EMPTY`
  (occupied-target), `M_RESTORE_OK`, `M_B5` (baseline construction), `M_LOOP_REACHED`
  (consensus-loop entry), `M_BASELINE_APPLIED`, or `M_EPOCH_PERSIST` appears.
* `state_vm_v0` remains ABSENT (filesystem check performed before any account
  accessor, so no database is created).
* The restore marker remains ABSENT.
* Independent post-reap reopen observes `CommittedEpoch(7)` (the matching
  pre-existing epoch preserved). No whole-directory byte-identity claim is made.

This differs from the retained no-CLI positive control (which is a compatible
restore that reaches baseline and persists epoch 7): the positive control was NOT
the requested matching-epoch COMBINATION rejection. The five conflicting-epoch
cases (destination `CommittedEpoch(42)`) are retained unchanged.

### Validation and executable provenance (this execution)

Test implementation checkpoint was committed before these outcomes were recorded.

Release executable — the historically recorded binary
(`sha256 cbb8a7bf…`, `16952728` bytes, source `a7564d6`) is NOT available in this
clone and its source checkpoint object is absent, so it could not be reused. The
current release binary was rebuilt and its ACTUAL identity recorded (the rebuilt
hash is NOT assumed to match the historical evidence):

```
# cargo build --release -p qbind-node --bin qbind-node        (profile: release)   => Finished in 5m59s
# executable  = target/release/qbind-node
# source rev  = a6ac1fbee840f9f5696801676794cda2994fa001 (task-branch checkpoint; test-only edit, main.rs unchanged)
# sha256      = 0299f445fe7c9d5668366496122ba9ac0eacb69373427fc22bf3595e3fae700c
# byte_len    = 16952776
#   (rebuilt hash/length differ from the historical cbb8a7bf…/16952728 record; NOT assumed equal)

# QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
#   cargo test -p qbind-node --release --test run_422_d7d3_binary_snapshot_restore_characterization_tests d7d5a_
# test result: ok. 7 passed; 0 failed; 18 filtered out
#   (includes the new d7d5a_restore_with_cli_mode_and_matching_epoch_refused_before_effects,
#    the five conflicting-epoch predicate cases, and the no-CLI positive control)

# QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
#   cargo test -p qbind-node --release --test run_422_d7d3_binary_snapshot_restore_characterization_tests
# test result: ok. 25 passed; 0 failed; 0 ignored   (was 24 before this +1 case; superset of the focused d7d5a_* run)
```

The focused `d7d5a_*` run (7) is a subset of the full target run (25). The full
count increased by exactly one (24 → 25) from the added matching-epoch case.

Focused Clippy (`cargo clippy -p qbind-node --release --test
run_422_d7d3_binary_snapshot_restore_characterization_tests`): the changed target
compiles with the SAME single pre-existing `clippy::needless_borrows_for_generic_args`
warning at line ~1228 (outside the changed hunks); the parameterized helper and
new case add no new Clippy warning. Changed-region formatting matches the file's
established wider hand-formatted convention (the whole file already diverges from
default rustfmt); no repository-wide formatting was run. The evidence doc's CRLF
line endings were preserved.

### Literal security-tool outcomes (this correction)

Recorded verbatim below in the final report; a skipped CodeQL analysis or an
errored/unavailable reviewer is NOT a successful security review and no historical
outcome is upgraded here.

### Scoped disposition

The matching-epoch CLI-combination case passes against the identified (rebuilt)
release executable and the retained D3/D4/D5 target cases pass, so the scoped D5
verdict is recorded:

`D7D5_RESTORE_EPOCH_CONFLICT_BEFORE_MATERIALIZATION=CODE-AND-RELEASE-TEST-POSITIVE`

All retained posture lines are UNCHANGED:
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. Partial-directory handling,
cross-database crash consistency, signing-state continuity, and durable
anti-rollback remain unresolved. No activation, readiness promotion, new recovery
mechanism, or Run 423 work. No protocol/lifecycle/audit/contradiction-ledger edit
was needed for this coverage-only correction.

### Literal security-tool outcomes (this correction, verbatim)

Recorded literally; a skipped CodeQL analysis or an errored/unavailable reviewer
is NOT a successful security review:

* CodeQL Security Scan (`parallel_validation`): "Skipped: all changes are
  trivial." — the changes are test-file + documentation only, declared trivial
  for CodeQL. This is a SKIP, not a completed clean scan.
* Code Review (`parallel_validation`): reported "Reviewed 2 file(s). No review
  comments found." but ALSO reported a backend error — "Code review tool is not
  available in this environment: ... model claude-sonnet-4.6 not found in
  registry." The no-comments result is therefore NOT evidence of a completed
  model review.

## Run 422 D7-D6 — Late restore FAILURE (marker-open) and restart characterization (test + evidence only)

This section characterizes a deterministic **late** restore failure produced by
the corrected release executable itself — a compatible restore that copies
account state and then fails to OPEN its audit marker — and the two subsequent
restart paths over the resulting directory. It **does not** implement recovery
protection. It is an ordinary local I/O-failure characterization, **not** a
power-loss simulation, malicious-rollback test, or durability proof. Only two
files were edited:
`crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
and this evidence document. No production source, CLI flag, environment bypass,
fault-injection hook, parser, storage schema, recovery journal, automatic
cleanup, or second process runner was added.

### Provenance and object availability (actual checkout)

* Actual working branch: `copilot/run-422-d7-d6`.
* Starting `HEAD` for this task: `36f179469753e85b24a51cc2b116e3f959e549fd`.
* Tested checkpoint (test-implementation commit exercised by validation): the
  first D7-D6 commit on this branch (`Add D7-D6 late-restore marker-open failure
  characterization tests`), with the release executable rebuilt from it.
* Referenced-object limitation: the D7-D5 acceptance provenance named in the task
  — accepted branch `copilot/run-422-complete-compatible-epoch-cli-refusal-cont`,
  accepted revision `df0f6aac31c669285c9cc167d39d64f5c834805f`, and source
  checkpoint `a6ac1fbee840f9f5696801676794cda2994fa001` — are **not resolvable
  as git objects** in this shallow, single-branch clone (`git cat-file -t` →
  "could not get object info" for both). No branch was renamed and no ancestry
  was manufactured. Missing objects do **not** establish missing implementation:
  the accepted D5 behavior is present in this worktree (the D5 pre-materialization
  epoch-conflict precheck and restore+CLI-combination refusal in
  `crates/qbind-node/src/main.rs`, live epoch reads in
  `production_consensus_storage.rs`, and the `d7d5_*` positive/negative controls
  in the test file), and is exercised green by the retained cases below.

### Source-backed operation ordering (not modified here)

Read from `crates/qbind-node/src/snapshot_restore.rs`
(`materialize_validated_snapshot`, `write_restore_marker`) and
`crates/qbind-node/src/main.rs` (restore path):

1. For a requested restore on the normal-startup path, `main.rs` opens the
   canonical `<data_dir>/consensus` storage EARLY
   (`open_production_consensus_storage`, logged `[binary] Run 093 consensus
   storage: ...`), performs a LIVE committed-epoch read, and runs the D5
   pre-materialization epoch-compatibility precheck.
2. When the precheck PERMITS (compatible snapshot),
   `materialize_validated_snapshot`:
   1. computes `<data_dir>/state_vm_v0`, and (when absent) creates it and
      **copies** the snapshot account state into it (`copy_dir_recursive`), THEN
   2. calls `write_restore_marker`, which OPENS `RESTORE_MARKER_FILENAME`
      (`RESTORED_FROM_SNAPSHOT.json`) with
      `OpenOptions::create(true).append(true).open(path)` to append one JSON
      audit line.
3. The Run 097 snapshot-epoch persistence runs only AFTER a successful restore
   outcome (`if let Some(outcome)` in `main.rs`); a restore `Err` prints
   `[restore] ERROR: <e>` and `std::process::exit(1)`.

Because the audit-marker open (2b) happens **after** the account-state copy (2a)
and **before** the Run 097 epoch persistence (3), obstructing only the marker
path yields a copy-succeeded / marker-failed / epoch-not-persisted destination.

### Exact fixture construction and failure mechanism

One reusable test-local helper, `produce_and_verify_marker_obstructed_failure`,
constructs and verifies the failed destination; cases A/B/C each invoke it
independently with their **own** temporary directories. The fixture:

* Real supported RocksDB checkpoint via `build_real_snapshot`, snapshot epoch
  `Some(7)`, known account (`ACCOUNT_ID` = `AccountState::new(7, 4242)`).
* Destination `<data_dir>/consensus` opened once as an empty RocksDB so it
  reports `PresentNoCommittedEpoch`, **explicitly observed** with
  `observe_consensus_storage` before launch.
* Account-state destination `<data_dir>/state_vm_v0` initially **absent**.
* No excluded CLI mode (a plain `--restore-from-snapshot` LocalMesh DevNet start).
* At the existing `RESTORE_MARKER_FILENAME` path a **directory** is created,
  holding a small sentinel file (`obstruction_sentinel.bin`) with fixed bytes
  (`OBSTRUCTION_SENTINEL_BYTES`).
* All RocksDB handles are dropped before the child launches.

Failure mechanism: opening a **directory** as an appendable file fails with
`EISDIR`. A directory (not a permission bit) is used deliberately so the
obstruction survives a test runner executing as **root**, which a permission-only
obstruction would not. This obstruction is produced/consumed by the corrected
executable itself; it does **not** reuse the legacy partial-directory fixture.

### Case A — late marker-open failure (child-process / release-binary)

Child args: `--env devnet --network-mode local-mesh --data-dir <D> \
--restore-from-snapshot <snap>`. Termination classification: **natural exit code
1, no terminating signal** (bounded `wait_natural_exit`, complete capture).
Observed boundary (verbatim, paths abbreviated):

```
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=<D>/consensus
[restore] requested: snapshot_dir=<snap> data_dir=<D> expected_chain_id=0x51424e4444455600
[restore] ERROR: restore-from-snapshot IO error: cannot open marker file <D>/RESTORED_FROM_SNAPSHOT.json: Is a directory (os error 21)
[restore] qbind-node refuses to start because the requested snapshot restore could not be honestly applied. ...
```

Asserted: the specific marker-open I/O failure naming the obstructed marker path
(`cannot open marker file <D>/RESTORED_FROM_SNAPSHOT.json` + EISDIR); storage-open
observed BEFORE the failure (`M_STORAGE_OPEN` precedes the marker failure); NO
CLI-combination or epoch-conflict refusal; and ABSENCE of any restore-success,
baseline, consensus-loop-entry, or epoch-persistence observation. The marker is
**not** called "absent": the obstruction exists, but no successful audit record
was written.

Independent database reads (after reap, fresh reopen): restored account =
`AccountState::new(7, 4242)` (copied before the marker open failed); consensus =
`PresentNoCommittedEpoch` (no epoch persisted). Obstruction observations: the
marker path remains a **directory**; its sentinel bytes are byte-unchanged.

### Case B — ordinary restart WITHOUT the restore flag (child-process)

Independently reproduces A, then starts the SAME failed destination with NO
restore flag (`--env devnet --network-mode local-mesh --data-dir <D>`), without
deleting or repairing anything. Termination classification: observed while ALIVE
at the existing `[binary-consensus] Starting consensus loop:` line, then
**deliberately SIGKILL-terminated** through the validated runner
(`observe_then_terminate` + `expect_observed_then_terminated`, complete capture,
successful reap). A LocalMesh dispatch line alone was **not** accepted. Observed
boundary (verbatim):

```
[restore] no --restore-from-snapshot requested; normal startup.
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=<D>/consensus
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=nonce-only
[binary-consensus] Starting consensus loop: ... restore_baseline=false ...
```

Ordinary startup therefore PROCEEDS to the consensus loop with
`restore_baseline=false`; the obstructing marker directory is irrelevant (no
marker write is attempted). Independent reads afterward: account unchanged
(`7/4242`); consensus still `PresentNoCommittedEpoch`; marker path still a
directory; sentinel bytes unchanged. This is an OBSERVED limitation — reaching
the loop is **not** whole-directory identity, signing-state continuity, or safe
recovery.

### Case C — repeated restore WITH the flag (child-process / release-binary)

Independently reproduces A, then retries the ORIGINAL restore request over the
unchanged destination. Termination classification: **natural exit code 1, no
signal**, complete capture. Observed boundary (verbatim):

```
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=<D>/consensus
[restore] ERROR: restore-from-snapshot target state directory is not empty: <D>/state_vm_v0 (refusing to overwrite; remove or move it before restoring)
```

As the source predicts: the epoch precheck PERMITS (still no committed epoch),
then `materialize_validated_snapshot` refuses with `TargetStateNotEmpty` because
`state_vm_v0` is now non-empty from case A's copy — BEFORE reaching
`write_restore_marker`, so the marker-open failure does **not** recur. Storage
opened before the refusal (`M_STORAGE_OPEN` precedes `TargetStateNotEmpty`); no
restore success, baseline, or epoch persistence. Independent reads afterward:
account unchanged (`7/4242`); consensus still `PresentNoCommittedEpoch`; marker
path still a directory; sentinel bytes unchanged.

### Positive control (retained, executed)

The existing `Some(7)/None` compatible-restore control
(`d7d5_b_compatible_present_epochs_reach_baseline`) — WITHOUT the obstruction —
reaches baseline application and persists epoch 7 (`CommittedEpoch(7)`). It is
retained and passes in the full-target run below; its fixture and assertions are
not duplicated.

### Evidence-level separation

* **Release-executable observations**: the ordered stderr markers, exit codes,
  and termination classifications above (cases A/B/C) come from launching the
  unmodified release binary.
* **Independent database reads**: every account value and consensus observation
  is a fresh in-process reopen AFTER the child was reaped
  (`observe_restored_data_dir` / `observe_consensus_storage`); a selected-value
  match is not a byte-identity claim over the directory.
* **Source-only findings**: the operation ordering (copy → marker-open → Run 097)
  is read from `snapshot_restore.rs` / `main.rs`; no production line was changed.

### Validation and release-executable identity (this execution)

The test-implementation checkpoint was committed BEFORE recording these outcomes.

```
# Release executable rebuilt from the task branch (production source UNCHANGED):
# cargo build --release -p qbind-node                        (profile: release) => Finished in 7m19s
# executable  = target/release/qbind-node
# source rev  = 36f179469753e85b24a51cc2b116e3f959e549fd  (HEAD; test + docs-only edit, main.rs unchanged)
# sha256      = dc00c48bbb3a3735bcc383a3e921f50437ed2c7fcc04c9a6d08c21345fecd6e0
# byte_len    = 16953040
#   (a first link of the same source produced 41c7b0e8…/16952680; `cargo test --release`
#    relinked the SAME path to dc00c48b…/16953040, which is the binary actually exercised.
#    Both differ from the historical 0299f445…/16952776 record — hashes are NOT assumed
#    reproducible, exactly as the task cautions.)

# Focused D7-D6 cases against the identified release executable:
# QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
#   cargo test -p qbind-node --release --test run_422_d7d3_binary_snapshot_restore_characterization_tests d7d6_
# test result: ok. 3 passed; 0 failed; 0 ignored; 25 filtered out

# Complete existing D3/D4/D5 + new D6 target against the same executable:
# QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
#   cargo test -p qbind-node --release --test run_422_d7d3_binary_snapshot_restore_characterization_tests
# test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
#   (was 25 before this +3 D7-D6 cases; the 28 is a strict superset of the focused d7d6_ run)

# Focused Clippy (qbind-node tests): the only lint pointing at this test file is a
# pre-existing `needless_borrows_for_generic_args` at the existing d7d5_b line 1228
# (rust-1.98.0 toolchain strictness), NOT in the new D7-D6 region, which is lint-clean.
# `-D warnings` fails on unrelated pre-existing qbind-ledger lib lints; left unfixed
# (out of scope for this test/docs-only change).
# Changed-region whitespace: no trailing whitespace in the added lines; file-specific
# CRLF line endings preserved (no repository-wide reformatting).
```

Runner discipline: bounded deadlines and complete capture throughout; no
fixed-sleep race, no process-global environment mutation of the parent, no leaked
child (kill+reap+drain-join on every path, including `Drop`), and no unexpected
signal supports a passing result.

### Literal security-tool outcomes (this correction, verbatim)

Recorded literally; a skipped CodeQL analysis or an errored/unavailable reviewer
is NOT a successful security review and no historical outcome is upgraded here.

* CodeQL Security Scan (`parallel_validation`): "Skipped: all changes are
  trivial." — the changes are test-file + documentation only, declared trivial
  for CodeQL. This is a SKIP, **not** a completed clean scan.
* Code Review (`parallel_validation`): reported "Code review completed. Reviewed
  2 file(s). No review comments found." but ALSO reported a backend error —
  "Code review tool is not available in this environment: ... model
  claude-sonnet-4.6 not found in registry." The no-comments result is therefore
  **not** evidence of a completed model review.

### Scoped verdict and preserved posture

The three required scenarios (A late marker-open failure; B ordinary restart
without the flag; C repeated restore with the flag) and the retained positive
control are concretely established against the identified release executable, so:

`D7D6_LATE_RESTORE_FAILURE_RESTART_CHARACTERIZATION=COMPLETE-FOR-TESTED-SCOPE`

This means the characterization is complete; the recovery risk is **not**
repaired. The accepted D5 verdict is intact — a later I/O failure does not
invalidate D5's scoped pre-materialization epoch-conflict protection:
`D7D5_RESTORE_EPOCH_CONFLICT_BEFORE_MATERIALIZATION=CODE-AND-RELEASE-TEST-POSITIVE`
is unchanged. All retained posture lines are UNCHANGED:
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. No authority activation,
signing enablement, readiness promotion, Run 423 work, cleanup/repair mechanism,
or cross-database atomicity claim is made here.

### Unresolved risk and one concrete containment requirement (for a later task)

Observed risk: a compatible restore can copy account state and then fail to write
its audit marker, and BOTH subsequent restarts leave the destination in a state
that is neither cleanly restored nor cleanly refused — the WITHOUT-flag restart
silently proceeds to the consensus loop over a marker-less restored `state_vm_v0`
(no successful audit record), and the WITH-flag retry is permanently blocked by
`TargetStateNotEmpty`. Concrete containment requirement for a subsequent
implementation task (NOT implemented here): make the requested-restore path
**atomic with respect to its audit marker** — the restored `state_vm_v0` must not
be observable to a later startup as a completed restore unless the corresponding
`RESTORED_FROM_SNAPSHOT.json` audit record was successfully written (e.g. write
the marker before/with the state under a single commit point, or refuse and
surface a partially-materialized `state_vm_v0` on the next startup rather than
proceeding as `restore_baseline=false`). This addresses the root cause; it is out
of scope for this characterization.

## Run 422 D7-D7 — Restore Completion and Fail-Closed Startup Contract (documentation only)

This section records the documentation-only D7-D7 phase, which produces and then
**corrects** (per the review disposition PARTIAL on the reviewed draft) the new
authoritative contract
`docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md`. It implements
**no** production code, tests, storage schema, journal, CLI flag, recovery
command, cleanup, or activation change. Defining the contract does **not**
establish operational protection.

### Provenance and object availability (actual checkout)

* This D7-D7 review-correction pass (corrections A–C below) ran on actual branch
  `copilot/copilotrun-422-d7-d7-again`, starting HEAD
  `79dd28eaf01924d13008e8b0c013a2924fac00ec`, clean worktree. The reviewed revision
  `bc0bc2541f53492d19aae1a6c7848381e2c1ac36` is **not resolvable as a git object**
  here (`git cat-file -t` → "could not get object info"); worktree content
  corresponds to the reviewed contract but no ancestry is manufactured. Edits stay
  on this branch (no PR, rename, force-push, or history rewrite).
* Earlier draft pass working branch: `copilot/run-422-d7-d7-again`.
* Prior on-branch commits before this correction pass: `a3d82382` (parent
  `1babc12216f29bf02a44742a56996acb8d691a3f`) — the reviewed draft. The
  review-named draft revision `b8333f33b422e273f439983e269d577637655b8f` is **not
  resolvable as a git object** in this checkout (`git cat-file -t` → "could not get
  object info"); missing objects do not establish missing source and no ancestry
  is manufactured. This correction pass edits the four authorized documents in
  place on the same branch (no PR, rename, force-push, or history rewrite).
* Shallow single-branch clone. The D7-D6
  provenance named in the task — accepted branch `copilot/run-422-d7-d6`,
  accepted revision `9d9723e09b65381bba5f784d0cd10b1d2455c6ea`, and D6 test
  checkpoint `0099517183bfe842e0a8c04ddd179c44c285934a` — are **not resolvable as
  git objects** here (`git cat-file -t` → "could not get object info" for both).
  `36f179469753e85b24a51cc2b116e3f959e549fd` remains separately identified as the
  previously reported base / build-source reference; it is NOT relabeled as the
  test-implementation checkpoint. No branch renamed, no ancestry manufactured.
  Missing objects do not establish missing implementation: the D5/D6 behavior the
  contract builds on is present in this worktree and cited by file and line in the
  contract.

### What the contract establishes (summary; full text in the protocol doc)

* The central requirement: ordinary startup must not admit a tracked, interrupted
  restore as completed; completion must cover account-state installation, the
  required audit record, and the required epoch persistence.
* The source-backed failure window: account-state copy
  (`snapshot_restore.rs:652`) precedes the un-synced audit-marker append
  (`snapshot_restore.rs:746`), which precedes Run 097
  `persist_restored_snapshot_epoch` → `put_current_epoch` (`storage.rs:912`, plain
  `self.db.put`, RocksDB default async write). Obstructing the marker (D6
  `d7d6_*`) leaves account state copied, marker failed, epoch unpersisted, and an
  ordinary no-flag restart proceeds with `restore_baseline=false` without
  inspecting the destination.
* The protocol: one durable restore-transaction record (RTR) with `INTENT` /
  `COMPLETE` states, bound to `destination_id`, `snapshot_meta_digest`,
  `attempt_nonce`, and `expected_epoch` (`Option`, preserving missing-vs-zero),
  written durably before the first destination mutation and upgraded to
  `COMPLETE` only after all required effects are durable. Startup consults the RTR
  before using `state_vm_v0` or starting services and refuses interrupted
  (`INTENT`), corrupt, mismatched, foreign, or missing-state `COMPLETE`
  destinations, while **proceeding** over untracked (ordinary/legacy) destinations
  whether empty or non-empty — an ordinary node writes `state_vm_v0` normally and
  never creates an RTR, so RTR-absence is the ordinary lifecycle, not an
  interrupted restore.
* Trust model stated separately for ordinary I/O error, process termination,
  host/power failure, and malicious directory rollback; a complete ordered
  durability sequence (preparatory effects vs the first protected mutation, all
  epoch outcomes) with explicit synced-write / atomic-publish
  (temp+fsync+rename+dir-fsync) barriers; one chosen destination lock — a
  kernel-managed advisory `flock(LOCK_EX|LOCK_NB)` on `<data_dir>/restore.lock`
  held for the process lifetime and auto-released on death (the consensus RocksDB
  LOCK covers only `<data_dir>/consensus`); an explicit first-profile legacy policy
  that **admits** untracked destinations as ordinary (no operator adoption step,
  no refusal of legitimate fresh nodes); an association/comparison-input table
  naming each compared value, its source, the trusted source, and the phase; and
  D5 restore/CLI incompatibility, live-read epoch semantics, authority-marker
  checks, and fail-closed defaults preserved, with a bypass-entrypoint inventory.
* A single bounded successor implementation task (RTR + ordinary-startup guard +
  destination lock) naming `snapshot_restore.rs`, `main.rs`,
  `production_consensus_storage.rs`, and a **required `storage.rs` interface
  change** (a synced epoch effect the current `ConsensusStorage` API does not
  expose) as the smallest file set, with no new enablement flag, and with
  automatic repair, anti-rollback, and signing continuity kept separate.

### Corrections applied to the reviewed draft (A–F)

* **A (initialization / restart).** The draft refused any untracked non-empty
  `state_vm_v0`, which would have refused a legitimate fresh node that merely wrote
  account data (the VM-v0 runtime opens `state_vm_v0` via
  `vm_v0_runtime.rs:70`). Corrected to one coherent lifecycle: RTR-absence is the
  ordinary lifecycle and startup proceeds; only a lingering `INTENT` marks an
  interrupted restore. Added a fresh-start → ordinary-writes → restart transition
  table alongside the successful and interrupted restore paths; the minimal
  missing mechanism is exactly the `INTENT`/`COMPLETE` RTR.
* **B (durability ordering).** Added a complete ordered sequence distinguishing
  permitted preparatory effects (lock/dir create, consensus-storage open) from the
  first protected mutation (the account copy), with synchronization for copied
  files, installed directories, the audit file, and new paths, and all epoch
  outcomes (`None` no-coercion, required write, already-matching barrier, conflict
  refuse). Recorded that the current `ConsensusStorage` API exposes no synced-write
  and that a `storage.rs` interface change is required.
* **C (association / comparison inputs).** Added a table naming each compared
  value, its source, the trusted source, and the phase; noted ordinary restart
  supplies no new snapshot/nonce (no self-comparison); bound `authority_state` and
  `authority_state_v2` into the digest and limited the identity claim (not
  authentication/freshness/authorization); defined version, bounded record, nonce,
  and invalid-record refusal; and specified refusal when a `COMPLETE`'s state is
  missing.
* **D/E (retries / ownership).** Removed the idempotent-success route: a requested
  restore over an occupied `COMPLETE` destination is refused; a historical
  `COMPLETE` never re-applies an old baseline/epoch. Chose one lock mechanism
  (kernel advisory `flock` on `<data_dir>/restore.lock`) with acquisition,
  coverage, lifetime, competing-process, process-death, identity, and participating
  entrypoints defined, plus read-only/test limits. Updated future tests.
* **F (readiness / successor / evidence).** Withdrew the "implementation-ready"
  claim; separated resolved protocol choices from remaining implementation and
  durability-evidence obligations; provided one corrected successor task including
  the `storage.rs` interface change and no new enablement flag; and kept the
  security-tool reporting honest (a CodeQL Markdown-only skip is not a passed scan;
  a reviewer backend/model-registry error is not a successful review).

### D7-D7 review-correction pass (three material fixes, applied in place)

A subsequent review kept the disposition **PARTIAL** and named three remaining
contract inconsistencies. Each is corrected in the operative text of
`docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md`, not merely appended:

* **Correction A — eligibility before intent.** The prior §5.9 published `INTENT`
  (step 2) and only refused a non-empty target during the copy (step 3), so a
  rejected restore over an ordinary populated directory could leave a persistent,
  startup-refusing `INTENT`. §5.9 step 1 now performs, before any RTR write, the
  ordered checks lock-held → existing-RTR inspection → snapshot validation + D5
  gates (precedence preserved) → a **non-writing** destination-eligibility
  (occupied-target) check that factors the existing
  `snapshot_restore.rs:627-638` occupancy read; only then is `INTENT` published.
  §4.3 lists the eligibility check ahead of intent, and §10's safety boundary
  states occupied-target refusal precedes any `INTENT`. §7 adds the occupied-target
  acceptance test (ordinary non-empty destination, no RTR, sentinel unchanged, RTR
  stays absent, ordinary startup still proceeds).
* **Correction B — observable crash decisions.** The §6 "during `COMPLETE` write /
  sync" row ("`INTENT` or torn `COMPLETE`" / "refuse unless `COMPLETE` fully
  durable") is replaced by decisions on the **observable final record** under the
  atomic temp→`fsync`→`rename`→dir-`fsync` model: valid final `INTENT` ⇒ refuse;
  valid published `COMPLETE` ⇒ apply the completion/destination/required-state
  checks; temporary artifacts are never promoted; malformed/corrupt/unreadable
  final record ⇒ separate fail-closed refusal; no final record during interrupted
  initial intent ⇒ absent-record policy. §5.9 separates writer synchronization
  obligations from what a restarting reader can observe, and specifies any
  restart-admission durability barrier directly instead of an unknowable claim about
  the previous process's `fsync` acknowledgment. Process-kill tests characterize
  observed interruption only, not power-loss durability.
* **Correction C — active-attempt binding vs ordinary restart.** §4.5, §4.8, §6, and
  §10 no longer require ordinary (no-flag) admission to match a freshly supplied
  snapshot identity or attempt nonce (neither exists on that path). During an active
  restore attempt the `INTENT`/`COMPLETE` bind to the validated snapshot metadata
  (both authority fields) and the attempt nonce that attempt holds, and wrong-nonce/
  wrong-snapshot comparisons occur only there. On ordinary restart, admission
  validates the record format, checks the recorded `destination_id` against the
  actual destination, and requires `state_vm_v0` present and the startup checks;
  historical digest/nonce are provenance, and the epoch/baseline are never rewritten
  from the historical record. Future "wrong nonce" tests must name an active-attempt
  comparison, not invent an expected nonce for ordinary restart.

### Reuse findings (non-restore mechanisms not conflated)

The M16 `EpochTransitionMarker` / `EpochTransitionBatch` (`storage.rs:350`,
`:361`, `check_for_incomplete_epoch_transition:1087`) is a consensus epoch-boundary
mechanism inside the `<data_dir>/consensus` RocksDB WriteBatch, NOT a restore
transaction; the contract uses its start/clear-marker pattern only as a design
reference and does not reuse it for restore completion. The D7-C1 read-only
`observe_consensus_storage` is reused as the startup epoch-state reader (evidence,
not authority). Governance replay records are not treated as restore transactions.

### Contradiction-ledger reconciliation

`docs/whitepaper/contradiction.md` C4 is `OPEN — partial` (B3 VM-v0 restore, B5
restore-aware start among its partial items). This documentation-only phase does
not change C4's status and requires no ledger rewrite; the ledger already reflects
C4/C5 open and the restore path as partial, consistent with
`DEFINED-NOT-IMPLEMENTED`. Reconciliation is required only when the successor task
establishes an actual boundary.

### Changed documents (this phase)

1. `docs/protocol/QBIND_SNAPSHOT_RESTORE_COMPLETION_CONTRACT.md` (authoritative;
   corrected in place per corrections A–F).
2. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — this section.
3. `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` — concise
   successor reference only.
4. `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` — concise
   successor reference only.

### Checks and tool limitations (documentation phase)

* Source-reference check: every code citation in the corrected contract
  (`snapshot_restore.rs:613/638/652/669/715/746`, `main.rs` ~L2511/2553/2660/4920,
  `production_consensus_storage.rs:535/619`, `storage.rs:142/188/350/361/912/1087`,
  `consensus_storage_observation.rs`, `vm_v0_runtime.rs:70`,
  `state_snapshot.rs:169/187`, and the D3–D6 test names) was read in this checkout
  before citing.
* Cross-section consistency: the contract, this evidence section, and the two
  successor references state the same protocol, complete durability ordering,
  admit-untracked legacy policy, chosen `flock` lock, and the separation of
  resolved protocol choices from remaining implementation/evidence obligations.
* Diff scope: only the four documents above are changed; no production source,
  test, schema, or CLI change.
* Link check: internal doc paths reference existing files.
* Whitespace / line endings: the new contract and all edited docs use CRLF
  (matching the existing protocol/evidence files); no repository-wide reformatting;
  no trailing whitespace added in changed regions.
* Secret scan: documentation only; no secrets, credentials, or tokens introduced.
* No Cargo rebuild or test execution performed or required for this phase.
* Security-tool reporting (kept honest): this correction pass changes Markdown
  only, so CodeQL is a **scope skip**, which is **not** a passed scan, and any
  model-backed reviewer "no comments" is **not** an independent pass if the
  reviewer backend reported an environment/model-registry error. Earlier D7 passes'
  recorded CodeQL database-size skips and qualified reviewer outcomes stand as
  recorded and are not overwritten.

### Retained posture

`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. C4/C5 remain open. Scoped
status: `D7D7_RESTORE_COMPLETION_CONTRACT=DEFINED-NOT-IMPLEMENTED`.

## Run 422 D7-D8 — Restore-completion corrections A/B/C, active-attempt binding, and release-binary evidence

**Scope.** Continuation of D8 (not a new phase). Corrects three production gaps
and completes active-attempt binding in the restore-completion boundary, adds
behavioral coverage, and captures release-binary evidence. No authority
activation, anti-rollback, automatic repair, or new bypass flags.

### Changed paths and reused mechanisms

* `crates/qbind-node/src/main.rs` — Correction A ordering (protected VM-v0 open
  deferred to after the durable completion boundary); Correction B mode
  selection (`open_existing_from_config` when admitted via COMPLETE / just
  restored); Correction C + active-attempt binding at the finalization site
  (retain the successfully published INTENT, call `finalize_complete_from_intent`,
  distinct after-replace diagnostic).
* `crates/qbind-node/src/restore_completion.rs` — Correction C `PublishError`
  (`BeforeReplace`/`AfterReplace`) with injectable directory-sync
  (`publish_record_inner`); fail-closed `state_vm_v0_present` (directory-entry
  read errors counted as failure, not presence); active-attempt binding
  (`IntentMismatch`, `FinalizeError`, `finalize_complete_from_intent`,
  `check_intent_matches`).
* `crates/qbind-ledger/src/execution.rs` — `RocksDbAccountState::open_existing`
  (`create_if_missing(false)`); reuses the existing account-storage
  implementation (no new abstraction). Ordinary `open` behavior preserved for
  callers that intentionally create storage.
* `crates/qbind-node/src/vm_v0_runtime.rs` — `open_existing_from_config`
  delegating to a shared `open_from_config_mode`; open marker records the mode
  (`existing-only` vs `create-if-missing`).
* `crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
  — new VM-v0-profile release-binary cases (below).
* Unit tests co-located in `restore_completion.rs` and `execution.rs`.

### Correction dispositions

* **A (complete before opening protected state).** The protected VM-v0 account
  state open is moved after the durable completion boundary. Actual ordering
  (release binary, captured): destination lock → Run 093 storage open → INTENT
  published + install + sync → Run 097 durable epoch effect (epoch persisted,
  synced) → durable COMPLETE published → **only then** VM-v0 persistent-state
  open (`existing-only`) → consumers (LocalMesh loop). Finalization stays at the
  canonical Run 097 site; only dependent state opening/consumers moved.
* **B (a non-empty directory is not an existing database).** A COMPLETE-admitted
  destination opens with `create_if_missing(false)`; absent/empty/unrelated-only
  restored databases fail closed instead of silently initializing a replacement.
  `state_vm_v0_present` is a cheap structural pre-filter only (now fail-closed on
  entry-read errors); the authoritative existing-database check is the
  `open_existing` open. Scope: the existing database-open checks actually
  performed — not a full integrity scrub or authentication of checkpoint
  contents. A refused open may create permitted diagnostic/lock artifacts
  (LOG/LOCK) but never a `CURRENT`/initialized database.
* **C (report publication failures by their actual stage).** `publish_record`
  reports `BeforeReplace` (prior final record authoritative) vs `AfterReplace`
  (final pathname may already hold a valid COMPLETE; no false "INTENT retained"
  assertion). Either failure stops the current startup before protected state
  use; no delete, no restore of an older record, no automatic rollback. A later
  startup classifies the actual final record.

### Active-attempt binding

Finalization retains the identity of the successfully published INTENT and
validates the transition against the authoritative on-disk final record while
ownership is held (`finalize_complete_from_intent`). The transition rejects:
missing/invalid expected intent, wrong state, wrong destination, wrong attempt
nonce, wrong whole-metadata digest, and wrong expected epoch (`None` vs `Some(0)`
preserved). A mismatch suppresses COMPLETE and does NOT overwrite inconsistent
evidence with a reconstructed success record. Ordinary restart supplies no
independent snapshot/nonce and is admitted through the separate ordinary-startup
guard, not the active-attempt comparison.

### Test coverage (distinguishing unit / helper / release-binary)

* **Unit (in-process):** `restore_completion` module tests (34 pass) —
  before/after-replace publication (deterministic test-only directory-sync
  injection), temp-artifact never authorizes, `state_vm_v0_present` absent/empty/
  nonempty and entry-read failure, finalize success + wrong-nonce/digest/
  destination/state/epoch-none-vs-zero/absent/invalid/expected-not-intent.
  `execution` `open_existing` tests (4 pass) — refuses absent, refuses
  unrelated-only, succeeds on a real DB, ordinary `open` still initializes fresh.
* **Release-binary (child-process, VM-v0 profile):**
  `d7d8_correction_a_vm_v0_state_opens_only_after_durable_complete` (ordering:
  INTENT → Run 097 epoch → COMPLETE → VM-v0 open existing-only),
  `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary`
  (unrelated-only ⇒ `[T164] ERROR`, no `CURRENT` created, sentinel preserved;
  empty ⇒ ordinary-startup guard "required installed state is missing/empty"),
  `d7d8_a_complete_then_ordinary_restart_preserves_state` (completion then
  ordinary restart admitted via COMPLETE, existing-only open, no INTENT/COMPLETE
  re-publication, restored account value preserved).
* **Helper-level only (not release-binary):** the injected epoch-durability /
  publication-stage failures are exercised via test-only injection around the
  shared publication operation (no production fault-injection flag). These
  establish the ordering/error-reporting logic; they are NOT release-executable
  observations and are reported as such.

### Release executable identity and validation

```
# Source/checkpoint revision (release build): a333cc8e1425d130cb189086767188c70514aac5
# Build: cargo build --release -p qbind-node --bin qbind-node   (profile: release; features: default/none)
# Executable: target/release/qbind-node
# SHA-256:    023fff95d09533392ef3dfd0586cb2c22c47f5fa07097498124ade8ca72f33d0
# byte_len:   17028960
#   (Hashes are NOT assumed reproducible across links, exactly as the task cautions.)

# Focused D7-D8 cases against the identified release executable:
# QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
#   cargo test -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests d7d8_
# test result: ok. 3 passed; 0 failed; 0 ignored; 28 filtered out

# Full extended D3–D8 integration target against the same release executable:
# QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
#   cargo test -p qbind-node --test run_422_d7d3_binary_snapshot_restore_characterization_tests
# test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
#   (was 28 before the +3 D7-D8 cases; the 31 is a strict superset, NOT a re-labelling
#    of the earlier 28-case run as complete D8 acceptance.)

# Default-production compile: cargo check -p qbind-node => clean.
# Focused Clippy: cargo clippy -p qbind-node --lib / -p qbind-ledger --lib => Finished (no new
#   errors from the changed code; warnings on restore_completion.rs:761 / vm_v0_runtime.rs:265 /
#   execution.rs:2400/2443 point at PRE-EXISTING lines, not the added code).
#   NOTE: `cargo clippy -p qbind-node --tests` without `--features test-utils` fails to compile the
#   PRE-EXISTING `m16_epoch_transition_hardening_tests` target (it calls test-utils-gated
#   `set_inject_write_failure`/`clear_epoch_transition_marker`); unrelated to this change.
```

Release-binary ordered markers observed (Correction A case, transcribed):

```
[binary] Run 422 D7-D8: acquired advisory exclusive destination lock at <dir>/restore.lock
[binary] Run 093 consensus storage: state=present-no-committed-epoch path=<dir>/consensus
[restore] D7-D8 durable INTENT published; installing account state
[restore] D7-D8 INTENT + install + sync complete: height=210 ... deferring epoch barrier + COMPLETE to the Run 097 site
[binary] Run 097: snapshot canonical epoch=7 persisted into <data_dir>/consensus meta:current_epoch.
[restore] D7-D8 durable COMPLETE published at <dir> (height=210 ...)
[binary] LocalMesh mode: starting consensus loop. environment=DevNet profile=vm-v0
   (the VM-v0 existing-only open marker `[vm-v0] opened persistent state at <dir> (mode=existing-only)`
    is asserted by the test to follow the COMPLETE publication.)
```

### Entrypoint / platform / limitations

* **Entrypoint coverage:** the corrected ordering and existing-only open are on
  the `main.rs` startup path and are exercised through the real release binary
  for the VM-v0 execution profile. The LocalMesh default-profile cases never
  open VM-v0 state and cannot witness this boundary.
* **Supported-platform assumption:** destination locking uses Unix `flock`
  advisory locks; the lock file is never truncated/unlinked, and process death
  releases the kernel lock without deleting the lock file.
* **Legacy untracked-directory limitation:** an ordinary (RTR-absent)
  non-empty `state_vm_v0` still starts normally under the ordinary lifecycle;
  the existing-only guarantee applies only to COMPLETE-admitted destinations.
* **Sync vs interruption vs power-loss:** the synced-write / atomic-publish
  operations are implemented and deterministically tested, and SIGKILL/
  process-interruption ordering is observed; neither establishes power-loss
  durability, which remains a separate, unmet evidence obligation.

### Security-tool outcomes (recorded literally)

* Production changes are non-trivial for security tooling; `parallel_validation`
  was run with `codeql.isTrivial=false`. Literal outcomes from this run:
  * **CodeQL (rust):** `Analysis was skipped because the database size is too
    large.` — a **scope/size skip**, NOT a passed scan.
  * **Code Review:** reported "No review comments found", but the reviewer
    backend also emitted `model claude-sonnet-4.6 not found in registry` — a
    **model-registry error**, so the "no comments" result is **not** an
    independent clean pass.
  Earlier D7 recorded skips/qualified outcomes are not overwritten.

### Scoped verdict and remaining limitations

```
D7D8_RESTORE_COMPLETION_CONTAINMENT=PARTIAL
```

Established at CODE-AND-RELEASE-TEST level: Correction A ordering (completion
before protected-state open), Correction B existing-database refusal (missing/
empty/unrelated-only), Correction C publication-stage reporting (unit-level),
active-attempt finalize binding (unit-level over the real transition), and
completion-then-ordinary-restart.

Outstanding (retain PARTIAL): competing-process / process-death and
destination-lock-contention as dedicated release-binary cases; interruption-
boundary fault injection surfaced only through test helpers rather than the
release executable; and power-loss durability evidence. These are reported here
rather than claimed.

### Retained posture

```
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

No readiness promotion, authority activation, or Run 423 work. C4/C5 remain
OPEN.

---

## Run 422 D7-D8 — completion pass: restore-admission corrections and full acceptance evidence (code + test + release evidence)

This pass continues the D7-D8 section above. It confirmed the three corrections
remained gaps at the starting revision, finished the remaining acceptance
coverage (the previously-outstanding dedicated destination-lock-contention and
occupied-then-ordinary release-binary cases), and captured fresh release-binary
evidence. Earlier D7-D8 evidence and its historical `PARTIAL` verdict above are
preserved unchanged as the prior-pass record.

### Checkout and objects

* Branch: `copilot/copilotcopilotrun-422-d7-d8-again` (supplied branch, used
  unchanged; differs from the reviewed `copilot/copilotrun-422-d7-d8`).
* Reviewed references `f1200c8` / `a333cc8` / `a4399a3` are **not present** in
  this shallow single-branch clone (`git cat-file` fails); implementation was
  confirmed by direct source inspection, not ancestry.
* `task/warning.txt` and its pre-existing unrelated warnings were preserved;
  per-file line endings (CRLF in `restore_completion.rs`, `vm_v0_runtime.rs`, and
  the integration test; LF in `main.rs`, `execution.rs`) were preserved.

### Corrections confirmed and implemented this pass

* **Correction A — profile-independent COMPLETE admission.** Every normal startup
  admitted through `COMPLETE` now validates the required restored account database
  with the existing-only implementation (`RocksDbAccountState::open_existing`),
  regardless of execution profile, via
  `vm_v0_runtime::validate_required_restored_account_db`; the VM-v0 runtime reuses
  the successfully opened handle. A non-empty directory alone no longer admits;
  missing/empty/unrelated-only/unopenable databases refuse before dispatch, and no
  replacement database is initialized during validation. This is a bounded
  database-open guarantee, not an integrity scrub.
* **Correction B — bounded RTR read.** `read_rtr` opens the authoritative final
  record once, validates it as a regular file (Unix `O_NONBLOCK` open + `fstat`,
  so a FIFO/special file cannot block the open), reads at most `max + 1` bytes with
  checked arithmetic, rejects over-limit input before decoding, never allocates
  from metadata/encoded length, and maps I/O failure to refusal. Absent-record
  semantics are preserved only for a genuinely absent final record; temporary
  artifacts never count as completion.
* **Correction C — finalization diagnostics.** The generic `main.rs` finalization
  error now reports only what is established (attempt refused; inconsistent final
  record not overwritten; startup stops before protected state use) and never
  claims an on-disk `INTENT` merely because finalization failed. Before- vs
  after-replacement publication failures remain distinguished.

Changed production paths: `crates/qbind-node/src/restore_completion.rs`,
`crates/qbind-node/src/vm_v0_runtime.rs`, `crates/qbind-node/src/main.rs`
(comment-accuracy only in the finalization/admission region plus the new
diagnostics). `crates/qbind-ledger/src/execution.rs` required no change
(`open_existing` + its tests already existed). No changes to
`snapshot_restore.rs`, `production_consensus_storage.rs`, or `storage.rs`.

### Acceptance matrix (this pass)

Unit (compiled + run):

* `restore_completion` unit tests — 46 pass (includes Correction B bounded-reader
  cases: valid/absent/truncated/trailing/oversized/max-boundary, more-bytes-than-
  advertised seam, read-error-after-partial, FIFO/non-regular refusal without a
  blocking open, temp-artifact-never-replaces; plus the `authority_state_v2`
  metadata-digest case).
* `vm_v0_runtime` unit tests — 15 pass (Correction A `correction_a_*`).
* `qbind-ledger::execution` `open*` unit tests — 4 pass.

Release-binary integration target
`run_422_d7d3_binary_snapshot_restore_characterization_tests` — **33/33 pass**
against the release executable via `QBIND_D7D3_NODE_BIN` (was 31; +2 this pass):

* `d7d8_correction_a_vm_v0_state_opens_only_after_durable_complete` — completion
  precedes protected VM-v0 open.
* `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary` — existing-only
  refusal (missing/empty/unrelated) with no re-init.
* `d7d8_a_complete_then_ordinary_restart_preserves_state` — completion then
  ordinary restart preserves restored account value; no INTENT/COMPLETE republish.
* `d7d8_b_occupied_refusal_then_ordinary_start` (**new**) — occupied-target
  refusal (`TargetStateNotEmpty`) with no RTR/INTENT and no snapshot-epoch apply,
  followed by an ordinary startup over the same legitimate destination that
  proceeds through the RTR-absent lifecycle and preserves the pre-existing account.
* `d7d8_c_destination_lock_contention_death_and_reacquire` (**new**) — a holder
  acquires the advisory destination lock and reaches the live consensus loop; a
  competing process refuses with the SPECIFIC lock-contention message before the
  consensus loop (not a port collision/generic error); after the holder is killed
  and reaped the lock file is NOT deleted yet a successor reacquires it; and a
  reacquired lock does not bypass an ordinary-startup `INTENT` refusal (the
  tracked INTENT is neither promoted nor removed). Synchronization is bounded
  marker/status polling (no arbitrary sleeps); the lock file is never unlinked to
  make a step pass.

Unit/helper vs release boundary: the bounded-reader more-bytes-than-advertised and
read-error-after-partial cases use a **deterministic in-test reader seam** around
the shared bounded reader (labelled unit/helper). The finalization publication
before/after-replacement boundary uses the existing `publish_record_inner`
directory-sync seam (unit/helper). All `d7d8_*` and `d7d3/4/5/6` cases above are
**unmodified release-executable** observations. No production fault-injection flag
was added to relabel a helper test as a release test.

### Release executable identity (this pass)

```
source revision : 441c9fb69c71962fee653e6212c86e5613d4ca58
build command   : cargo build --release -p qbind-node --bin qbind-node
profile         : release (optimized)
features        : default production features
executable      : target/release/qbind-node
byte length     : 17031352
sha256          : 3e944560c745ee38e9e74a4cdf70f7c782adc2be69e3ad5eff62ef4098f4e515
integration run : QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
                  cargo test -p qbind-node --test \
                  run_422_d7d3_binary_snapshot_restore_characterization_tests
                  => 33 passed; 0 failed
```

Additional validation: `cargo check -p qbind-node` (default features) clean;
focused Clippy on changed code clean (the one finding in changed code — an
`io::Error::new(Other, _)` in a test seam — was converted to `io::Error::other`).
No repository-wide formatter was run; unrelated pre-existing warnings
(`signed_vote_v1_legacy`, `cert_bound_node_id`) were left untouched.

### Security-tool outcomes (recorded literally)

Production changes declared non-trivial (`codeql.isTrivial=false`). Literal
outcomes from the `parallel_validation` run for this completion pass:

* **CodeQL (rust):** `Analysis was skipped because the database size is too
  large.` — a **scope/size skip**, NOT a passed scan (`Found 0 alerts` here means
  the analysis did not run, not that the code is clean).
* **Code Review:** reported `No review comments found` (9 files reviewed), but the
  reviewer backend also emitted `model claude-sonnet-4.6 not found in registry` —
  a **model-registry error**, so the "no comments" result is **not** an
  independent clean pass.

Earlier D7 skips/qualified outcomes are not overwritten.

### Scoped verdict (this pass)

```
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE
```

The specified restore-admission and startup-containment code plus the
release-binary acceptance scope — profile-independent COMPLETE admission/refusal,
successful completion/restart with progressed/preserved state, occupied-refusal→
ordinary-restart, actual late-failure containment, and destination-lock
contention/death — are demonstrated against the release executable. This verdict
does **not** establish power-loss durability, durable anti-rollback, consensus
recovery, signing-state continuity, or production authority readiness; those axes
remain separately unmet.

### Retained posture (unchanged)

```
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

No readiness promotion, authority activation, or Run 423 work. C4/C5 remain OPEN.

## Run 422 D7-D8 — RTR final-component symlink refusal and completed acceptance evidence (corrections A–D)

This delta continues the D7-D8 completion pass above and resolves the four
review findings that remained after it: (A) the bounded RTR reader followed a
final-component symlink so a dangling symlink at the authoritative RTR pathname
mapped to `Absent`; (B) the invalid-database release-binary integration case
covered only VM-v0; (C) `d7d8_a_complete_then_ordinary_restart_preserves_state`
checked only the original restored account value and discarded the epoch
observation, so it did not prove preservation of *later* progress; and (D) the
lock test used a helper that discarded the kill result/exit status and several
new negative cases asserted marker absence without requiring complete capture.
Earlier D7-D8 evidence and figures above are preserved unchanged as the
prior-pass record.

### Checkout and objects

* Branch: `copilot/copilotcopilotcopilotrun-422-d7-d8-again` (supplied branch,
  used unchanged; differs from the reviewed `copilot/copilotcopilotrun-422-d7-d8-again`).
* Reviewed references `09f7001c85de738a37e340f769011edcf52d3c51` (final revision)
  and `441c9fb69c71962fee653e6212c86e5613d4ca58` (release-build checkpoint) are
  **not present** in this shallow single-branch clone (`git cat-file` fails);
  the accepted implementation was confirmed by direct worktree inspection, not
  ancestry. Content correspondence — not commit ancestry — was used throughout.
* `task/warning.txt` and per-file line endings were preserved. Only the two
  authorized code/test files and the four documentation files were changed.

> **Correction (superseded by the release-symlink pass below).** The claim on
> the preceding line that this test file's *per-file line endings were
> preserved* is inaccurate: the reviewed test file
> `crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
> had been changed from its original uniform CRLF to LF (0 CRLF / all-LF at the
> reviewed revision). The line-ending convention was **not** preserved in that
> pass. The subsequent "release-binary RTR-symlink integration" pass below
> restores uniform CRLF (no final newline) in that file and verifies the fix at
> the raw byte level; its content corrections are retained.

### Correction A — reject final-component RTR symlinks (production change, non-trivial)

The single authorized production change is in
`crates/qbind-node/src/restore_completion.rs`: `open_regular_final_record` now
opens the authoritative final record with `libc::O_NONBLOCK | libc::O_NOFOLLOW`
(previously `O_NONBLOCK` only). The change is atomic at open (no
check-then-follow race) and scoped to the final component only — no
ancestor-path hardening or arbitrary-rollback protection was added.

* Genuine absence → open `NotFound` → `Ok(None)` → `RtrReadResult::Absent`
  (ordinary lifecycle preserved).
* A final-component symlink (valid target **or** dangling) → `ELOOP` → caught by
  the existing catch-all → `RtrError::Io` **refusal**. `symlink_metadata` is used
  in the tests to prove the link itself (and its target) is neither deleted,
  replaced, nor repaired, since `Path::exists()` alone cannot distinguish a
  dangling link from absence.
* FIFO/other non-regular files remain refused by the post-open `fstat`
  regular-file check; the bounded `max + 1` read and decode behavior is
  unchanged.

Unit tests through the real reader (`restore_completion` lib, 51 pass) added
this pass: genuine-absence control; regular valid RTR read normally; symlink→
valid-RTR refused **and preserved**; dangling symlink refused **and preserved**;
ordinary-startup precondition refuses a final-component symlink; requested-
restore precondition refuses a dangling symlink. Existing FIFO/non-regular and
bounded-reader cases remain green. A timeout is treated as a test failure, never
as evidence of refusal.

### Correction B — release-binary profile matrix across both execution profiles

The existing invalid-database integration case was minimally parameterized into
`run_correction_b_matrix`, reusing the genuine binary-produced COMPLETE,
snapshot fixture, runner, and independent-reopen helpers. It is invoked by two
release-binary test wrappers:

* `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary` (VM-v0).
* `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary_nonce_only`
  (the supported non-VM-v0 profile; CLI spelling `--execution-profile nonce-only`,
  confirmed from `crates/qbind-node/src/cli.rs`).

For each profile the matrix covers, with deterministic fixtures (no reliance on
permission denial that disappears under root): valid restored database → admitted
normally; missing database directory → refusal; empty directory → refusal;
unrelated-only directory → refusal **without** initializing a replacement DB;
invalid/unopenable database (a bogus `state_vm_v0/CURRENT` pointing at a missing
manifest) → refusal. Each negative case asserts a natural nonzero exit with the
expected specific refusal, complete capture (`stderr_capture().is_complete()`)
before any forbidden-marker-absence assertion, no service/consensus dispatch, no
replacement-database initialization (no `MANIFEST-*` created; the bogus `CURRENT`
is preserved unchanged), and preserved sentinel/RTR evidence. The guarantee stays
scoped to the existing database-open checks (not a whole-directory byte-identity
scrub); a failed open may leave permitted diagnostic/lock artifacts.

### Correction C — preservation after fixture-driven account and epoch progress

`d7d8_a_complete_then_ordinary_restart_preserves_state` was strengthened to prove
preservation of *progressed* state, not just the original restored value:

1. Produce a genuine COMPLETE through the release binary; reap the child and
   close all handles.
2. Read and retain the actual RTR and the initial account/epoch observations.
3. Using the existing fixture storage APIs (`RocksDbAccountState` /
   `RocksDbConsensusStorage`), advance the account state and consensus epoch to
   **distinct** values; persist and close handles before the next launch.
4. Start ordinarily (no restore flag); observe successful ordinary startup and
   existing-database admission; reap and independently reopen the stores.

Asserted: the advanced account value remains; the advanced consensus epoch
remains; the historical snapshot epoch is **not** reapplied; no restore baseline
is reapplied; **neither INTENT nor COMPLETE** is republished; the authoritative
RTR remains the same historical completion record. The epoch observation is no
longer discarded, and `None` vs `Some(0)` semantics are preserved in the related
epoch-matrix tests. The advancement is described accurately as **fixture-driven**:
it is not authenticated consensus progress, durable anti-rollback, or
signing-state recovery.

### Correction D — classified termination and capture-integrity evidence in the lock test

`d7d8_c_destination_lock_contention_death_and_reacquire` was corrected to use the
runner's established evidence checks:

* The holder is kept **alive** (via `wait_for_marker_alive`) while the contender
  runs.
* The contender is required to fail with the **specific** destination-lock
  refusal (not a generic startup failure or port collision), and
  `stderr_capture().is_complete()` is required before any forbidden-marker
  absence is asserted.
* After contention the holder is terminated through the existing classified
  termination path (`observe_then_terminate` / `expect_observed_then_terminated`),
  requiring a successful deliberate kill with the expected signal
  (`EXPECTED_TERMINATION_SIGNAL = 9`) and completed reaping.
* The successor's positive reacquisition is observed through the same classified
  path; the lock file is never unlinked to force reacquisition; and the
  subsequent proof that a reacquired lock does not bypass an ordinary-startup
  INTENT refusal is retained.

Complete-capture checks were also applied to the occupied-refusal case
(`d7d8_b_occupied_refusal_then_ordinary_start`) and the other newly added
negative cases that assert absence. For occupied-refusal followed by ordinary
startup, the consensus epoch is independently inspected before and after (a
missing epoch-write log alone does not prove storage was unchanged); the account
sentinel and absent-RTR assertions are retained. Best-effort cleanup is left as
cleanup and is never used as affirmative process-death evidence.

### Acceptance matrix (this pass)

Overlapping subsets are identified rather than summed (the 34-case release target
is a strict superset that includes the D3–D7 cases).

| Requirement | Test name | Execution level | Concrete assertion | Result |
|---|---|---|---|---|
| A: genuine absence = ordinary lifecycle | `restore_completion::tests` absence control | unit (real reader) | open `NotFound` → `Absent` | PASS |
| A: valid regular RTR read | `restore_completion::tests` valid-RTR | unit (real reader) | record decoded normally | PASS |
| A: symlink→valid RTR refused + preserved | `restore_completion::tests` symlink-to-valid | unit (real reader) | `ELOOP` → refusal; link+target intact (`symlink_metadata`) | PASS |
| A: dangling symlink refused + preserved | `restore_completion::tests` dangling-symlink | unit (real reader) | `ELOOP` → refusal; link intact, not repaired | PASS |
| A: ordinary-startup precondition symlink refusal | `restore_completion::tests` ordinary-startup symlink | unit (real reader) | refusal before protected use | PASS |
| A: requested-restore precondition dangling refusal | `restore_completion::tests` requested-restore dangling | unit (real reader) | refusal before protected use | PASS |
| A: FIFO/non-regular + bounded reader remain green | existing `restore_completion` cases | unit (real reader) | 51/51 pass | PASS |
| B: VM-v0 valid/missing/empty/unrelated/invalid | `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary` | release binary | valid admitted; 4 negatives exit 1 with specific refusal, capture complete, no re-init | PASS |
| B: nonce-only same matrix | `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary_nonce_only` | release binary | same as above for `--execution-profile nonce-only` | PASS |
| C: preservation after account+epoch progress | `d7d8_a_complete_then_ordinary_restart_preserves_state` | release binary | advanced account+epoch retained; snapshot epoch/baseline not reapplied; no INTENT/COMPLETE republish; RTR unchanged | PASS |
| C: COMPLETE ordering before protected open | `d7d8_correction_a_vm_v0_state_opens_only_after_durable_complete` | release binary | INTENT→epoch→COMPLETE→VM-v0 existing-only open | PASS |
| D: occupied refusal → ordinary start | `d7d8_b_occupied_refusal_then_ordinary_start` | release binary | `TargetStateNotEmpty`; complete capture; epoch before/after inspected; no committed epoch applied | PASS |
| D: classified lock contention/death/reacquire | `d7d8_c_destination_lock_contention_death_and_reacquire` | release binary | specific lock refusal + complete capture; classified SIGKILL(9) + reaping; successor reacquires; lock file never unlinked; INTENT refusal not bypassed | PASS |
| Runner evidence-check guards | `runner_control_*`, `classify_termination_decision_table`, `complete_capture_is_the_only_absence_supporting_outcome`, `capture_*` | unit | termination classifier + capture-completeness self-tests | PASS |

### Validation outcomes (this pass, recorded)

* `cargo test -p qbind-node --lib restore_completion` — **51 pass** (includes the
  6 new symlink/absence cases).
* `cargo test -p qbind-node --lib vm_v0_runtime` — **15 pass**.
* Full extended D3–D8 integration target against the **release** executable via
  `QBIND_D7D3_NODE_BIN` — **34/34 pass**.
* `b3_snapshot_restore_tests` — **10 pass**; `b5_restore_aware_consensus_start_tests`
  — **4 pass**.
* `run_093_production_consensus_storage_lifecycle_tests` — **12 pass**;
  `run_097_snapshot_epoch_parity_tests` — **7 pass**.
* `run_422_startup_refusal_tests` — **4 pass**;
  `run_422_d4_startup_ordering_tests` — **5 pass**.
* `cargo check -p qbind-node` (default production features) — clean.
* Focused Clippy on the changed `restore_completion` region — no findings (the
  pre-existing `acquire_destination_lock` `.create(true)` lint at line 866 is an
  intentional false positive — the lock file must never be truncated — and was
  left untouched). No repository-wide formatter was run; only changed-region
  wrapping/whitespace was hand-checked. `task/warning.txt` preserved.

### Release executable identity (this pass)

```
source revision : 18036eaa54df164ceb60fc0583e76277e9750d0f (pre-doc checkpoint;
                  code/test tree identical to the pushed final revision)
build command   : cargo build --release -p qbind-node --bin qbind-node
profile         : release (optimized)
features        : default production features
executable      : target/release/qbind-node
byte length     : 17031472
sha256          : 9abb0c6e25dbd4d1ec8a4bf3f88e3c8d6ef2ef881b20f6430535b8ed4538dd58
integration run : QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
                  cargo test -p qbind-node --test \
                  run_422_d7d3_binary_snapshot_restore_characterization_tests
                  => 34 passed; 0 failed
```

Unit/helper observations (real reader, in-process) are reported separately from
the unmodified release-executable observations. No new production
fault-injection switch was added; process termination and injected errors do not
prove power-loss durability.

### Security-tool outcomes (recorded literally)

Production change declared non-trivial (`codeql.isTrivial=false`). Literal
outcomes from the `parallel_validation` run for this pass:

* **CodeQL (rust):** `Analysis Result for 'rust'. Found 0 alerts:` followed by
  `rust: Analysis was skipped because the database size is too large.` — this is
  a **scope/size skip**, NOT a passed scan; "Found 0 alerts" here means the
  analysis did not run, not that the code is clean.
* **Code Review:** `Reviewed 5 file(s). No review comments found.` but the
  reviewer backend also emitted `Code review tool is not available in this
  environment: ... model claude-sonnet-4.6 not found in registry` (an
  `autofind ... command_failed` model-registry error) — so the "no comments"
  result is **not** an independent clean pass.

Earlier D7 skips/qualified outcomes are not overwritten.

### Scoped verdict (this pass)

```
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE
```

This applies only to the demonstrated restore-admission and startup-containment
scope: final-component symlink refusal, valid/invalid COMPLETE destinations
across **both** execution profiles, completion followed by fixture-driven
account/epoch progress and ordinary restart, occupied refusal followed by
ordinary startup, classified holder termination/contention/reacquisition, and
retained late-failure containment and requested-retry refusal. It does **not**
establish power-loss durability, durable anti-rollback, consensus recovery,
signing-state continuity, or production authority readiness.

### Retained posture (unchanged)

```
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

No readiness promotion, authority activation, or Run 423 work. C4/C5 remain OPEN.
## Run 422 D7-D8 — release-binary RTR-symlink integration coverage, profile-matrix/restart strengthening, and CRLF restoration

This delta continues the D7-D8 sections above. It is a **test- and
documentation-only** continuation: no production source was changed. It finishes
the remaining acceptance work the prior pass **overclaimed** as complete —
namely (3) release-binary (not merely in-process unit) coverage of a dangling
final-component RTR symlink through both the ordinary-startup and
requested-restore paths; (4) completing the profile-matrix negative assertions;
(5) observing the progressed-state ordinary restart through the consensus-start
boundary; and (6) restoring the test file's original CRLF convention (the prior
pass had changed it to LF). The reviewed production corrections (Correction A
`O_NONBLOCK | O_NOFOLLOW` RTR open, bounded reader + regular-file validation,
profile-independent existing-only admission, active-attempt finalization,
durable epoch/COMPLETE/account-open ordering, destination lock and
ordinary/retry refusal) are preserved unchanged.

### Checkout and objects

* Branch: `copilot/copilotcopilotcopilotcopilotrun-422-d7-d8-again` (supplied
  branch, used unchanged; note it differs from the reviewed
  `copilot/copilotcopilotcopilotrun-422-d7-d8-again` by one `copilot` segment).
* Starting revision: `2aadc012693d3282146b49f16f19cd0a7aca5821` (parent
  `9d96f009e0bdd008b13c9fa48f0ecc1aecc1a181`, the prior starting revision that
  held the CRLF test file).
* Reviewed references `a0d0bb71daaacf0c52ae2b2f743053302ca5862f` (reviewed final
  revision) and `18036eaa54df164ceb60fc0583e76277e9750d0f` (release-build
  checkpoint) are **not present** in this shallow single-branch clone
  (`git cat-file` fails). Missing historical objects do not imply missing
  implementation: source content was inspected directly and ancestry is reported
  separately.
* Only the single authorized test file was changed in this pass at the code
  level; the three authorized documentation files are updated for reconciliation.
  Production source under `crates/*/src` is byte-for-byte unchanged from the
  starting revision (`git diff --name-only 2aadc01..HEAD` lists only the test
  file and docs). `task/warning.txt` and unrelated work are preserved.

### (3) Release-binary dangling-RTR symlink refusal — ordinary + requested restore

The accepted UNIT cases (final-component symlink->valid-regular refused +
preserved; dangling symlink refused + preserved; regular RTR read normally;
genuine absence; non-regular/FIFO refused) remain in `restore_completion::tests`
and are **not** duplicated. This pass adds the missing INTEGRATION coverage to
the existing D3-D8 target, reusing its runner, binary selector
(`QBIND_D7D3_NODE_BIN`), snapshot fixtures, and startup markers:

* `d7d8_d_ordinary_startup_refuses_dangling_rtr_symlink_via_binary` — a dangling
  final-component symlink at the authoritative RTR pathname; ordinary (no-flag)
  startup of the release executable exits **1 naturally** with the specific
  ordinary-startup RTR-invalid guard (`M_D7D8_ORDINARY_INVALID_RTR`) whose detail
  is the RTR no-follow open refusal (`cannot open RTR`). Complete capture is
  required before absence assertions. No protected-account admission
  (`M_VM_V0_OPENED`, `M_VM_V0_VALIDATED_NONRUNTIME`,
  `M_D7D8_GUARD_PROCEED_COMPLETE`) and no consensus dispatch (`M_LOOP_REACHED`,
  `M_CONSENSUS_LOOP_STARTED`). The link is inspected with `symlink_metadata`
  (never `Path::exists()` alone) and remains a symlink; its missing target is
  never created; no restored database (`state_vm_v0/CURRENT`) is materialized.
  The preparatory advisory lock file is a permitted artifact and is **not**
  asserted absent.
* `d7d8_d_requested_restore_refuses_dangling_rtr_symlink_via_binary` — a **valid**
  snapshot plus a dangling final-component RTR symlink; a requested
  `--restore-from-snapshot` exits **1 naturally** at the RTR precondition with
  the specific requested-restore RTR-invalid refusal
  (`M_D7D8_RESTORE_INVALID_RTR`) whose detail is again `cannot open RTR`. No
  INTENT/COMPLETE publication, no account-state materialization, no restore
  audit-marker (`RESTORE_MARKER_FILENAME`) creation, no baseline application
  (`M_BASELINE_APPLIED`, `M_RESTORE_OK`), and no consensus dispatch. The link is
  preserved and its missing target remains absent (`symlink_metadata`);
  `read_rtr` over the destination remains a refusal (no record published).
* **Genuine-absence control (C):** reused
  `d7d4_c_fresh_directory_ordinary_start_control` — a genuinely absent RTR (no
  directory entry) retains the supported ordinary lifecycle and reaches
  `M_CONSENSUS_LOOP_STARTED` with `restore_baseline=false`. This is the
  explicitly-identified reused positive control; no duplicate was added.

### (4) Profile-matrix negative assertions completed

`run_correction_b_matrix` (invoked by the VM-v0 and `nonce-only` wrappers) was
strengthened rather than duplicated. After its genuine binary-produced COMPLETE,
the actual COMPLETE record is retained. The common negative-case assertions were
moved **into** the shared `run_negative` helper so every negative case (missing,
empty, unrelated-only, invalid) — not only the two that inspected the returned
stderr — receives them:

* specific refusal + natural exit 1 + complete capture (kept);
* absence of successful protected-account admission markers — both the VM-v0
  runtime-open marker (`M_VM_V0_OPENED`) and the non-runtime existing-database
  validation-success marker (`M_VM_V0_VALIDATED_NONRUNTIME`);
* absence of LocalMesh/consensus dispatch and the actual consensus-loop-start
  marker (`M_LOOP_REACHED`, `M_CONSENSUS_LOOP_STARTED`);
* neither INTENT nor COMPLETE republished;
* the authoritative RTR re-read and compared equal to the retained historical
  COMPLETE;
* the existing no-reinitialization and sentinel/`CURRENT`-preservation
  assertions (kept). Whole-directory byte identity is **not** asserted; permitted
  diagnostic/lock artifacts stay outside that claim.

### (5) Progressed-state restart observed through the consensus-start boundary

`d7d8_a_complete_then_ordinary_restart_preserves_state` retains its strengthened
account/epoch advancement. The ordinary-restart observation now proceeds PAST
`M_VM_V0_OPENED` and waits through `M_CONSENSUS_LOOP_STARTED` while the child
remains alive, requires the startup output to report `restore_baseline=false`,
keeps the existing-only account-admission observation, terminates through the
classified SIGKILL path with complete capture and completed reaping, and keeps
the assertions that neither INTENT nor COMPLETE is republished and no snapshot
baseline/epoch is reapplied. The advanced account and epoch are independently
re-opened and asserted, and the authoritative RTR equality check is kept. This
advancement remains **fixture-driven**: it does not establish authenticated
consensus progress, signing-state recovery, or durable anti-rollback.

### (6) CRLF convention restored in the test file

The reviewed final revision had changed this test file from CRLF to LF (the
prior pass's "line endings preserved" claim, corrected above). This pass restores
uniform CRLF while preserving the content corrections, and preserves the baseline
EOF convention (no final newline):

```
raw byte-level (restored file):
  CR = 4355, LF = 4355, lone-LF = 0, lone-CR = 0, ends-with-newline = false
diff scope check:
  git diff --numstat                 => 342 added, 1 removed
  git diff --ignore-cr-at-eol        => 342 added, 1 removed   (identical)
  content-only (CR stripped) diff    => 342 added, 1 removed   (identical)
```

The normal and line-ending-insensitive diffs are byte-identical, proving there
are **no** line-ending-only flips — every changed line is an intended test
change. No repository-wide formatter was run; no other file's line endings were
converted.

### Release executable identity (this pass — newly built, NOT the historical binary)

The historical release executable (source checkpoint `18036eaa...`,
sha256 `9abb0c6e...`) was **not available** on disk in this checkout, so it was
rebuilt from the actual starting revision. The rebuilt binary has the SAME byte
length as the historical one but a **DISTINCT** sha256 (release builds are not
bit-reproducible here); it is recorded as a new binary and is **not** relabeled
as the historical executable:

```
source revision : 2aadc012693d3282146b49f16f19cd0a7aca5821 (actual starting rev;
                  test checkpoint is the pushed commit that adds the two new
                  release-symlink cases — kept distinct from this build rev)
build command   : cargo build --release -p qbind-node --bin qbind-node
profile         : release (optimized)
features        : default production features
executable      : target/release/qbind-node
byte length     : 17031472        (equal to the historical binary's length)
sha256          : dfe0737cd9672fc36359d48a9fa3a0d43099fb8a74acc935e3c9dab542564778
                  (DISTINCT from historical 9abb0c6e...; not reproducible, not relabeled)
integration run : QBIND_D7D3_NODE_BIN=<abs>/target/release/qbind-node \
                  cargo test --release -p qbind-node --test \
                  run_422_d7d3_binary_snapshot_restore_characterization_tests
```

### Validation outcomes (this pass, recorded)

* Focused new/strengthened D8 cases against the identified release executable via
  `QBIND_D7D3_NODE_BIN` —
  `d7d8_d_ordinary_startup_refuses_dangling_rtr_symlink_via_binary`,
  `d7d8_d_requested_restore_refuses_dangling_rtr_symlink_via_binary`,
  `d7d8_a_complete_then_ordinary_restart_preserves_state`,
  `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary`,
  `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary_nonce_only`
  — **5 passed; 0 failed**.
* Full extended D3-D8 integration target against the **release** executable via
  `QBIND_D7D3_NODE_BIN` — **36/36 pass** (the prior pass's 34; +2 new
  release-symlink cases; this is a strict superset and is **not** summed with the
  focused 5).
* Focused Clippy on the changed test target — the code added this pass is
  clippy-clean; **one pre-existing** `needless_borrows_for_generic_args` warning
  remains at line 1352 inside the unrelated `d7d5_b` helper and was left
  untouched (out of scope). `-D warnings` cannot be applied crate-wide here
  because the `qbind-node`/`qbind-ledger` **libraries** carry pre-existing
  clippy lints unrelated to this test-only pass.
* Changed-file whitespace/line-ending checks — no trailing whitespace and no hard
  tabs in added lines; CRLF verification as above.

The previously recorded B3/B5, Run 093/097, startup-refusal/ordering, and unit
(`restore_completion` 51, `vm_v0_runtime` 15) results remain at their actual
prior revisions and were **not** re-executed in this pass; they are not re-claimed
here.

### Acceptance matrix (this pass)

| Requirement | Test name | Execution level | Concrete assertion | Result |
|---|---|---|---|---|
| Ordinary startup refuses dangling RTR symlink | `d7d8_d_ordinary_startup_refuses_dangling_rtr_symlink_via_binary` | release binary | natural exit 1; ordinary-startup RTR-invalid guard + `cannot open RTR`; complete capture; no admission/dispatch; link preserved (`symlink_metadata`), target uncreated; no `CURRENT` | PASS |
| Requested restore refuses dangling RTR symlink | `d7d8_d_requested_restore_refuses_dangling_rtr_symlink_via_binary` | release binary | valid snapshot; natural exit 1; requested-restore RTR-invalid precondition + `cannot open RTR`; no INTENT/COMPLETE, no materialization, no audit marker, no baseline, no dispatch; link preserved, target absent | PASS |
| Genuine-absence ordinary lifecycle (reused control) | `d7d4_c_fresh_directory_ordinary_start_control` | release binary | absent RTR -> ordinary lifecycle to `M_CONSENSUS_LOOP_STARTED`, `restore_baseline=false` | PASS (reused) |
| Profile matrix (VM-v0) negatives strengthened | `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary` | release binary | each negative: exit 1 + refusal + complete capture; no VM-v0/nonruntime admission; no dispatch; no INTENT/COMPLETE; RTR == retained COMPLETE; no re-init | PASS |
| Profile matrix (nonce-only) negatives strengthened | `d7d8_correction_b_missing_or_unrelated_state_refuses_via_binary_nonce_only` | release binary | same strengthened assertions under `--execution-profile nonce-only` | PASS |
| Progressed restart through consensus-start | `d7d8_a_complete_then_ordinary_restart_preserves_state` | release binary | observe `M_VM_V0_OPENED`->`M_CONSENSUS_LOOP_STARTED` alive; `restore_baseline=false`; classified SIGKILL + reaping; no INTENT/COMPLETE republish; no baseline/epoch reapplied; advanced account+epoch retained; RTR unchanged | PASS |

Counts are reported per level and are **not** summed across the overlapping
focused (5) and full-target (36) runs.

### Security-tool outcomes (recorded literally)

This pass is test/documentation-only; the CodeQL triviality was declared
accordingly (`codeql.isTrivial=true`, test/doc-only). Literal outcomes from the
`parallel_validation` run for this pass:

* **CodeQL Security Scan:** `Skipped: all changes are trivial.` A trivial-scope
  skip is **not** a passed production scan; prior production-analysis limitations
  and the earlier CodeQL size-skip qualifications above are unchanged.
* **Code Review:** `Reviewed 4 file(s).` `No review comments found.` The reviewer
  backend additionally reported it was unavailable in this environment
  (`model claude-sonnet-4.6 not found in registry`), so this is a backend-limited
  result, not an affirmative production sign-off.
* **Secret scan:** `No secrets detected in the scanned files.` across the three
  changed documentation files; the test file introduced no credentials or tokens.

A scope skip or backend error is **not** a passed scan; prior production-analysis
limitations are unchanged, and the earlier CodeQL size-skip / Code-Review
backend-error qualifications above are not overwritten.

### Scoped verdict (this pass)

```
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE
```

The narrow verdict now covers, at CODE-AND-RELEASE-TEST level, the demonstrated
restore-admission and startup-containment scope: final-component RTR-symlink
refusal executed through BOTH the ordinary-startup and requested-restore release
paths (previously unit-only), the profile-matrix dispatch/state-use absence and
RTR-preservation assertions across both profiles, and the progressed-state
ordinary restart observed through consensus start with `restore_baseline=false`.
It does **not** establish power-loss durability, durable anti-rollback, consensus
recovery, signing-state continuity, or production authority readiness.

### Retained posture (unchanged)

```
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

No readiness promotion, authority activation, or Run 423 work. C4/C5 remain OPEN.
Power-loss durability, signing-state continuity, durable anti-rollback, and
production authority readiness remain separate and unestablished.

## Run 422 D7-D9 — Durable Proposal/Vote Signing-State Continuity Contract (documentation only)

Documentation-only. No Rust, test, dependency, storage key/schema, CLI flag,
configuration, workflow, wire-format, signing-preimage, or activation change.
Signing is not enabled. D7-D2 characterization and D7-D8 restore-completion
evidence are reused as inputs, not re-derived or re-run.

### Inspected revision

* Branch (actual): `copilot/run-422-d7-d9`.
* Starting HEAD (full SHA): `c9025f2f3db06c2a0f1ec5e69514c29bb1fce035`; worktree
  clean before the pass.
* Reviewed D7-D8 objects: `9979c1ef43ce14346b47411d228edcab4afe8e61` (accepted
  final) and `1942c7a89c8871757d26bb2bc59a90573cc006e1` (test checkpoint) are
  ABSENT from this shallow clone (`git cat-file -t` → could not get object info);
  correspondence asserted against worktree content only, not ancestry.
  `2aadc012693d3282146b49f16f19cd0a7aca5821` (release-build source) is PRESENT
  (parent of HEAD).

### Changed paths (documentation-only)

* NEW `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` —
  the single authoritative contract.
* `docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` — concise
  D7-D9 successor reference (requirement C pointer; ordering + storage-inventory
  reconciliation).
* `docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` —
  concise successor reference to the continuity contract.
* This evidence section.
* `docs/whitepaper/contradiction.md` unchanged: no operative claim requires a
  narrow reconciliation (the obsolete "no synced operation" claim was searched
  for and is not present).

### What the contract defines

* Reuse table (existing mechanism → callers → property → limit → missing
  requirement) and traced signing routes classified production-reachable /
  conditionally-reachable / fixture-only. **Two caller families** reach the shared
  `sign_proposal_for_broadcast` / `sign_vote_for_broadcast` helpers (L3646/L3733):
  the immediate-forwarding family inside
  `binary_consensus_loop.rs::forward_actions_to_facade` (L4101; admit L3852 → sign
  → confirm L3913 after signing → facade) **and** the cached-re-emission family in
  `maybe_reemit_on_late_peer_connect` (L3379), which runs its **own**
  `admit_cached_reemission` → sign → confirm cycle and does **not** pass through
  `forward_actions_to_facade`.
* Conflict rule DERIVED from HotStuff decision rules. The canonical position key
  is the **stable validator identity + kind (Proposal vs Vote) + the action's
  originating consensus view** — the view captured when the action was built
  (`on_leader_step` captures `view = self.current_view`, then `advance_view()` at
  L1577 runs **before** the actions are returned at L1581–1584), **never** recomputed
  from a later `engine.current_view()`. For the founding-authority profile a
  `BlockProposal`/`BlockHeader` sets `height = round = view` with **no step field**,
  and a `Vote` sets `height = round = view`, `step = 0`, so height/round (and a
  Vote's step) are **checked redundant encodings** of the originating view
  (correspondence enforced **before** lookup), **not** independent coordinates,
  **not** "committed height," and never filled from an embedded QC's own
  height/round/step. Current key / suite / wire-message version / authority
  commitment / owner generation are **exact-message bindings**, not namespace
  selectors: a validated rotation does not open a new namespace or erase a conflict
  obligation (rotation/epoch continuity is explicitly gated). A new process / owner
  generation / PID / caller label is NOT a fresh identity.
* Bounded, versioned, checked-arithmetic, checksum-integrity record (checksum =
  corruption detection only, not authentication or rollback protection) and a
  five-state machine (NONE / RESERVED / SIGNING / SIGNED / REFUSED) with no
  erase-on-failure transition.
* Durable-before-sign invariant (INV-1): a reservation committed and its
  durability barrier acknowledged BEFORE `signer.sign_*`; the linearization point
  is the acknowledged reservation; exact retry compared by canonical decision,
  not signature bytes; resend vs re-sign kept distinct.
* Failure/recovery matrix — every row keyed to **observable durable evidence**,
  distinguishing a **live** in-process continuation (may sign once) from
  **recovery after process death** (a `RESERVED` position with no usable retained
  result is **potentially signed** → refuse, no re-sign, no release). Covers
  pre-reservation failure, uncertain write, recovery at a reserved position,
  confirmation/handoff failure, exact vs conflicting retry, malformed records,
  ordinary restart, **same-epoch** older-snapshot rollback (correspondence-based,
  not epoch-inequality), whole-directory rollback (locally indistinguishable from a
  valid older state), and same-key dual instances.
* Crash-consistency (local synced journal) separated from rollback-resistance;
  anti-rollback requirements enumerated for **appropriately trusted state/evidence
  outside the attacker's rollback domain** — a **protected local hardware
  mechanism OR a remote witness**, neither selected, implemented, or proven
  (authentication, validator/network + signing-history binding, freshness/
  monotonicity/exclusive use, ordering as a proposed/conditional requirement,
  availability/partial-update). A monotonic number **alone** is insufficient.
  Epoch-only witness, historical QC, source label, and checksum are each declared
  insufficient.

### Decisions and unresolved dependencies (prominent)

* Durable anti-rollback ANCHOR: EXPLICITLY UNRESOLVED. No repository mechanism
  (Run 291 replay backend, D8 restore lock, synced epoch APIs) supplies an
  authenticated, rollback-resistant, freshness-bearing signing-history commitment
  outside the attacker's rollback domain (protected local hardware or a remote
  witness — neither selected). The unsatisfied activation gate is named; no
  unimplementable "authenticated witness" is invented.
* Consensus-lock recovery: unmet PREREQUISITE. Preventing conflicting signatures
  does not restore the HotStuff lock across later views; a high-water mark alone
  does not recover a lock; Timeout/NewView compatibility is an unmigrated
  dependency.
* One bounded successor: a non-authorizing, crash-consistent local signing-
  reservation journal (source + tests only), extending `storage.rs` and a single
  guarded signing entrypoint over the shared `sign_proposal_for_broadcast` /
  `sign_vote_for_broadcast` helpers so it covers **both** caller families — the
  immediate-forwarding callers in `forward_actions_to_facade` **and** the
  cached-re-emission callers in `maybe_reemit_on_late_peer_connect` (a wrapper
  around `forward_actions_to_facade` alone is insufficient). Explicitly excludes
  the domain-external anchor, cross-host/whole-copy rollback detection,
  lock-recovery redesign, and enabling signing. Implementation is NOT begun.

### Checks performed and literal security-tool outcomes

* Path/symbol/caller verification against the `c9025f2` checkout (function line
  numbers and ordering confirmed by direct source view).
* State-transition and failure-matrix rows reviewed for contradictions; every
  freshness/provenance comparison names an independent input or is marked
  unresolved.
* File-specific line endings preserved: the new contract and edited
  `docs/protocol` / `docs/devnet` files use CRLF; no trailing whitespace added;
  each edited file's no-trailing-newline EOF convention preserved;
  `task/warning.txt` and unrelated files untouched.
* No Cargo tests, Clippy, or release rebuild required or claimed for these
  Markdown-only changes; D7-D8's bounded verdict is not reopened.
* Secret scan: run over the changed documentation paths; outcome — no secrets
  detected (Markdown protocol/evidence text only). A CodeQL scope skip is not a
  security pass and none is claimed.

### Scoped verdict and retained posture

```
D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

Design completion does not establish operational signing-state continuity. C4/C5
remain OPEN. No activation, readiness promotion, or Run 423 work. The successor
implementation is not begun.

### D7-D9 correction pass (four material inconsistencies reconciled)

Documentation-only. Re-verified against the actual worktree (branch
`copilot/copilotrun-422-d7-d9`; the reviewed-final object named by the task is
absent from this shallow clone, so correspondence is asserted against worktree
content, not ancestry). Source facts re-confirmed:
`ingest_proposal` derives the view from `proposal.header.height`
(`basic_hotstuff_engine.rs:1732`); locally-emitted Proposals/Votes set
`height = round = view`, `step = 0` (L1503–1504 / L1522–1524 / L1557–1559 /
L1833–1835); `maybe_reemit_on_late_peer_connect` (`binary_consensus_loop.rs:3379`)
calls `sign_proposal_for_broadcast` / `sign_vote_for_broadcast` (L3646/L3733)
through its own `admit_cached_reemission` (L3989) / `confirm_outbound_before_effect`
cycle, **bypassing** `forward_actions_to_facade`; the helpers assign the local
signer's suite (`suite_id`, L3706/L3785) before the D6 preimage is built.

* **A — conflict identity:** canonical position = stable validator identity + kind
  + engine view; height/round/step are checked redundant encodings (not
  independent coordinates, not "committed height"); key/suite/version/commitment/
  owner-generation are exact-message bindings, not namespace selectors; rotation/
  epoch continuity explicitly gated. Field-classification table added.
* **B — recovery:** every matrix row keyed to observable durable evidence; a
  recovered `RESERVED` with no usable retained result is potentially-signed
  (refuse, no re-sign, no release); live continuation vs process-death recovery vs
  resend vs re-sign kept distinct.
* **C — caller coverage:** both the immediate-forwarding and cached-re-emission
  caller families covered by a proposed common boundary over the shared signing
  helpers (a wrapper around `forward_actions_to_facade` alone is insufficient);
  reservation binds the prepared preimage; revalidation preserves the original
  ticket issuer/owner + bound context (generation number alone insufficient).
* **D — rollback:** same-epoch older-snapshot rollback handled via signing-history/
  recovery-state correspondence (not epoch inequality); whole-copy rollback stated
  locally indistinguishable; trust is appropriately-trusted state/evidence outside
  the rollback domain (protected local hardware OR remote witness — neither
  selected); a monotonic number alone is insufficient; anchor UNRESOLVED.

Secret scan re-run over the changed documentation paths; outcome — no secrets
detected (Markdown protocol/evidence text only). No Cargo/Clippy/release rebuild
is required for these Markdown-only changes and none is claimed. D7-D8's accepted
verdict and all earlier results are preserved at their actual revisions and not
re-run. `D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED` is
retained and is not equated with review acceptance.

### D7-D9 correction pass 2 (originating-view binding and message/version field mapping)

Documentation-only; no execution evidence added and none relabelled. Re-verified
against the actual worktree (branch `copilot/copilotcopilotrun-422-d7-d9`; the
reviewed-final object named by the task is ABSENT from this shallow clone, so
correspondence is asserted against worktree content, not ancestry). Two remaining
specification issues in the continuity contract were corrected in place:

* **Originating-view binding.** Reservations are bound to the action's originating
  consensus view, not a later `engine.current_view()`. Source re-confirmed:
  `on_leader_step` captures `view = self.current_view`
  (`basic_hotstuff_engine.rs:1443`), builds the `BlockProposal` + self-`Vote` for
  that `view`, may form a QC from the self-vote, and calls `advance_view()` (L1577)
  **before returning** the already-constructed actions (L1581–1584) — so a returned
  action can carry view `V` while the engine already sits at `V+1`. The contract now
  reads the reserved position from the action and its provenance (and, for inbound
  decisions, the `ingest_proposal` view at L1732), never from a newer `current_view`,
  and keeps decision identity separate from send-time eligibility; cached
  re-emission provenance rules are preserved (contract §3.2, §3.3, §7.1, §7.4-E).
* **Message/version field mapping.** The earlier recital that "every Proposal and
  Vote sets `height = round = view`, `step = 0`" (citing L1522–1524, which is the
  **embedded QC**) is corrected: a `BlockProposal`/`BlockHeader` has **no step**
  (L1500–1504); only a `Vote` has `step` (`= 0`, L1557–1559 / L1833–1835); an
  embedded `QuorumCertificate` has its own height/round/step (L1522–1524) certifying
  its own position and is never substituted for the Proposal. Three independent
  versions are now separated: **wire-message version** (`BlockHeader.version` /
  `Vote.version` = `1`), **D6 signing-format version** (`ProposalVoteSigningDomainV2`
  byte `2`, which does **not** imply wire version 2), and the **journal-record
  format version** (persistence-only). The field-classification table's ambiguous
  "engine view (`current_view` / `ingest_proposal` view)" and
  "message version — pinned domain (v2)" rows are replaced with concrete,
  separately-sourced rows (contract §3.2, §3.3, §7.1, §7.4-F).

Secret scan re-run over the changed documentation paths; outcome — no secrets
detected (Markdown protocol/evidence text only). No Cargo/Clippy/release rebuild is
required for these Markdown-only changes and none is claimed. D7-D8's accepted
verdict and all earlier results are preserved at their actual revisions and not
re-run. `D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED` is retained
and is not equated with review acceptance.
## Run 422 D7-D10 — Local signing-reservation journal and guarded signing boundary

**Scope.** Implement the §7.3 bounded successor of the signing-state continuity
contract: a non-authorizing, crash-consistent local signing-reservation journal
placed before the existing Proposal/Vote signer invocations. Source + tests only;
no production authority activation, no new CLI/config, no signing enabled in
production. The D9 `DEFINED-NOT-IMPLEMENTED` record is preserved; this is a
separate D10 implementation-status entry.

### Changed paths and reused mechanisms

* `crates/qbind-node/src/signing_reservation_journal.rs` (new) — record format,
  5-state machine, conflict rule, exclusivity, `SigningJournalStorage` trait, and
  the `SigningReservationJournal` reserve/sign/record/recover API.
* `crates/qbind-node/src/storage.rs` — reuses the existing CRC-32 facility
  (`signing_journal_crc32`) and the RocksDB synced-write path; adds a `sig:`
  keyspace and `impl SigningJournalStorage` for `RocksDbConsensusStorage` (real
  `set_sync(true)` fsync) and `InMemoryConsensusStorage` (explicitly MODEL).
* `crates/qbind-node/src/binary_consensus_loop.rs` — one shared
  `guarded_sign_{proposal,vote}_for_broadcast` wraps the existing
  `sign_*_for_broadcast` helpers with the contract §4.1 ordering, threaded through
  **both** `forward_actions_to_facade` (immediate) and
  `maybe_reemit_on_late_peer_connect` (cached re-emission); typed journal-outcome
  counters added. The guard is backward-compatible (engages only when a journal is
  wired; production wires none and continues to fail closed).
* `crates/qbind-node/src/lib.rs` — `pub mod signing_reservation_journal;`.

### Journal representation, bounds, durability, exclusivity

* Record: `magic | record-format-version | kind | stage | validator_id |
  network_genesis | originating_view | binding | sig_len | sig | crc32`
  (big-endian; CRC over body = corruption detection only, not authentication or
  rollback protection). Retained signature ≤ 8 KiB; reservation budget with
  checked arithmetic (overflow terminal); exhaustion refuses further signing.
* Durability: RocksDB `WriteOptions::set_sync(true)` fsync on the signing-record
  write itself. Exclusivity: a per-instance `Mutex` serializes read-then-write
  reservation across all handles/callers sharing the journal.

### Ordering before signer invocation (both caller families)

admission/context checks → per-kind identity/position checks (Proposal
`height==round==view`, no step; Vote `height==round==view` and `step==0`) →
prepared suite + existing D6 preimage → exclusive conflict lookup + durable
reservation → owner/ticket + snapshot revalidation → **one** signer call for a
freshly-reserved live op, or validated reuse of an exact retained result →
durable result handling → existing confirmation → delivery / cached re-emission.
No signer call before reservation acknowledgement, and none on conflict,
corrupt/unavailable journal, recovery ambiguity, exhaustion, or failed
authorization.

### Test evidence (direct signer-call / facade counts, not logs)

* **Colocated `binary_consensus_loop` tests** `mod run422_d7d10` — **18 tests, all
  pass**. Categories A (Proposal/broadcast-Vote/directed-Vote success:
  reserve-before-single-sign), B (conflict → zero additional signer calls + no
  delivery; exact retry reuses retained signature; directed/broadcast Vote
  equivalence; Proposal vs self-Vote distinct; binding change ≠ new namespace),
  C (reserve the action's originating view not a later view; conflict survives
  engine progress; inconsistent height/round and unsupported `Vote.step` refused
  before lookup), D (read/write/durability failure → zero signer calls;
  result-persist failure → no facade handoff, reservation preserved, no
  automatic re-sign), F (second handle no second permit; exhaustion refuses),
  G (cached Proposal + cached Vote re-emission reuse retained signatures with
  zero additional signer calls; admission/confirmation preserved).
* **Real-storage integration** `tests/run_422_d7d10_signing_reservation_journal_tests.rs`
  (`--features test-utils`) — **9 tests + 1 child-mode helper, all pass**. Real
  `RocksDbConsensusStorage` close/reopen: reserved-only recovery refuses
  re-signing; signed result survives reopen and supports exact resend; conflict
  stays refused; corruption, truncation, unknown record version, and missing
  signature fail closed; a second handle over the same store cannot obtain a
  second permit; and a **bounded child-process death/reopen** (test-only self
  re-exec + `std::process::abort()` after a durable reservation, before any
  recorded result) recovers `PotentiallySigned` and refuses re-signing.
* Backward compatibility: the 59 existing `run422_d7b` outbound/cached-reemission
  tests still pass with the guard wired.

**Evidence levels (kept separate).** source contract → colocated unit +
injected-failure → real-RocksDB reopen → bounded child-process death/reopen.
Process termination is **not** power-loss evidence; the isolated test signer is
**not** configured production authority.

### Validation

* Tested checkpoint recorded before validation: commit `d9994d15c462a8b97c8a3792a6af7c4f154b04dc`.
* `cargo test -p qbind-node --lib run422_d7d10` → 18 passed.
* `cargo test -p qbind-node --features test-utils --test run_422_d7d10_signing_reservation_journal_tests`
  → 9 passed, 1 ignored (child-mode helper, exercised by the orchestrator).
* `cargo test -p qbind-node --lib run422_d7b` → 59 passed (no regression).
* `cargo check -p qbind-node` (default features) → clean.

### Retained posture

```
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE   (preserved)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

Unresolved (explicitly retained): anti-rollback anchor selection, whole-copy
rollback, copied-key exclusivity, consensus-lock recovery, Timeout/NewView
compatibility, power-loss evidence, and production authority readiness. C4/C5
remain OPEN. No PR and no Run 423 work.

## Run 422 D7-D10 — Review correction pass (scoped; D10 remains PARTIAL)

A subsequent independent review did **not** accept the prior
`D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE` verdict. D10 is
**PARTIAL**. This subsection records only the scoped correction actually landed
in this pass and the reviewed defects that remain OPEN; the historical evidence
above is preserved at its original revisions and is not restated as accepted.

### Landed in this pass

* **Correction C — checked result publication.**
  `SigningReservationJournal::record_signed_result` is now a checked state
  transition rather than a blind overwrite. It publishes a `Signed` record only
  when (a) this instance holds the live continuation for the position and has
  already marked the signer invoked (operation ownership — a missing/foreign
  operation is refused), (b) a matching durable `Reserved` record exists at the
  exact position **and** binding, and (c) the stage is `Reserved`, or already
  `Signed` with byte-identical retained content (idempotent republication). A
  `Signed` record with different content is refused with the new typed
  `JournalError::InvalidResultPublication`; the original obligation is never
  overwritten. The read-validate-write is performed under the journal lock. The
  bounded, durable-acknowledged result write itself is unchanged.
  (`crates/qbind-node/src/signing_reservation_journal.rs`.)
* **§4 (partial) — one-time live continuation.** `note_signer_invoked` now
  fails closed (`InvalidResultPublication`) when the position has no live permit
  or its permit was already consumed, so a single reserved continuation can
  authorize at most one signer invocation.
* **Tests (journal unit, colocated — all pass):** publication without a live
  operation, wrong binding (reservation preserved, not signed), conflicting
  overwrite refused (original retained signature intact), idempotent identical
  republication accepted, a foreign handle cannot publish a result, and
  duplicate/absent continuation consumption refused. Existing 19 journal unit
  tests and 18 colocated `run422_d7d10` handler tests continue to pass.
* **Correction F (default-feature build).** The integration target
  `tests/run_422_d7d10_signing_reservation_journal_tests.rs` previously imported
  the `test-utils`-gated `fabricate_reserved_record_bytes_with_version` seam
  unconditionally, so the **default-feature** build of that target failed to
  compile. The import and its single feature-specific case
  (`unknown_version_record_on_reopen_fails_closed`) are now gated behind
  `#[cfg(feature = "test-utils")]`. Default-feature build/run: 8 cases pass
  (+1 ignored child helper); `--features test-utils`: 9 cases pass (+1 ignored).
  No production API is exposed and the target is not disabled.

### Reviewed defects still OPEN (NOT addressed in this pass)

* **Correction A — missing-journal signing bypass.**
  `guarded_sign_{proposal,vote}_for_broadcast` still delegate to the unguarded
  `sign_*_for_broadcast` when `journal == None`. The required fail-closed
  missing-journal boundary before signing is **not** yet implemented.
* **Correction B — cross-handle exclusivity / operation-bound capability.** Each
  `attach()` still creates a separate mutex; the fresh-reservation race across
  independent handles over one store and an operation-bound (non-reconstructible,
  non-cloneable) continuation are **not** yet implemented. The `note_signer_invoked`
  hardening above narrows, but does not close, this item.
* **Correction D — post-storage revalidation.** The guard does not receive or
  re-check the original admitted owner/ticket after durable reservation; the
  supported-wire-version / local validator-proposer association checks and the
  ordering claim of "owner/ticket + snapshot revalidation" above are **not**
  established.
* **Correction E — initialization vs. established-journal open and persistent
  capacity.** `attach()` still starts empty in-memory accounting and the budget
  resets on reopen; explicit-initialization vs. established-metadata validation
  and persistent/reconstructed bounded accounting are **not** implemented.
* **Correction F (partial) — acceptance-test / default-feature repairs.** The
  default-feature compilation of the integration target is **fixed** (see
  "Landed in this pass"). The remaining F items — direct storage/signer boundary
  instrumentation for reserve-before-sign ordering, deterministic
  ownership/exclusivity cases, real engine-progress evidence, and stricter
  bounded child-process exit classification — are **not** addressed here.

### Corrected posture

```
D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL   (prior CODE-AND-STORAGE-TEST-POSITIVE not accepted)
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE   (preserved)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

Local reservation protection is not activation authorization, current-authority
freshness, consensus-lock recovery, copied-key fencing, or durable anti-rollback.
C4/C5 remain OPEN. No PR beyond the task branch, no production activation, no D11,
no Run 423 work.

## Run 422 D7-D10 — Corrections B/C completion pass (D10 still PARTIAL)

This pass completes **Corrections B and C** for their demonstrated **local**
scope, superseding the earlier `note_signer_invoked` half-measure. It does **not**
touch Corrections A, D, E, or the remaining F work, and does **not** replace the
journal or begin D11/Run 423.

### Landed in this pass

* **B — one enforceable ownership domain.** A single `SigningOwnershipDomain`
  (unique `token`, `Mutex`-guarded live/accounting state) is **owned by the
  backend instance** and fetched through a new
  `SigningJournalStorage::signing_ownership_domain` trait method (cached in a
  per-instance `OnceLock`, implemented for `RocksDbConsensusStorage`,
  `InMemoryConsensusStorage`, and the test stores). Every supported handle
  attached over one backend instance shares that one domain, so a second handle
  cannot bypass coordination by allocating its own mutex; reservation **and**
  checked publication run under the same domain lock. A different backend instance
  over the same directory (real close/reopen, or a modelled restart) is a fresh
  domain — the honest crash-recovery posture. Scope is one local
  journal/storage ownership domain, **not** cross-copy/-key/-host.
* **B — operation-bound, one-use continuation.** `reserve_for_sign` now returns
  `FreshlyReserved(SigningContinuation)`. The continuation is created only after
  the reservation write's durable acknowledgement; is bound to the domain token,
  position, binding, and a unique live operation id; is **non-cloneable** with no
  public constructor (a durable `Reserved` record can never be turned into one);
  and is consumed **at most once by move** (`consume_for_signing`) immediately
  before the signer runs, yielding a `ResultPublicationCapability` for the same
  operation. Dropping/losing it never releases the reservation. An operation
  counter with checked exhaustion provides in-process ids (not an anti-rollback
  anchor).
* **C — checked, capability-gated publication.**
  `record_signed_result(&ResultPublicationCapability, &sig)` requires a matching
  domain + live-and-invoked operation + position + binding, a valid stored record
  with a permitted transition, and a bounded, structurally valid result, then
  performs the durable synced write. It refuses missing/foreign/stale operations,
  arbitrary position/binding arguments, empty/oversized results, and any
  conflicting overwrite (`JournalError::InvalidResultPublication`). Publication
  retry is never permission to sign again.
* **C — uncertainty / durable acknowledgement.** `LiveState.result_acked` tracks
  whether *this* operation obtained a durable acknowledgement in-process. Readable
  byte-equality is not a barrier: after a store-then-error result write,
  publication is not reported successful; an in-process retry sees the
  unacknowledged live operation and returns `PotentiallySigned` (never re-signs);
  republication through the same capability re-issues the synced write until the
  acknowledgement is established; idempotent identical success is reported only
  when already acknowledged; and the operation can never replace its signature
  with different bytes. `reserve_for_sign` applies the same rule to the
  retained-result lookup (`ExactRetryRetained` is withheld while a live
  unacknowledged operation shadows the `Signed` bytes).

### Tests executed (this pass)

* **Journal unit** (`--lib signing_reservation_journal`): **21 passed** — incl.
  foreign-domain continuation/capability rejection, dropped-continuation
  preserving the reservation, second-handle cannot obtain a continuation for a
  live position, conflicting-overwrite/idempotent/oversize publication, and the
  store-then-error uncertainty + conflicting-replacement cases.
* **Colocated handler** (`--lib run422_d7d10`): **21 passed** — incl. the new
  write-uncertainty handler case and **deterministic concurrent** contested
  reservation (bounded `Barrier`, same- and different-binding) proving at most one
  live signing continuation and exactly one facade handoff across supported
  handles.
* **Real-RocksDB integration**
  (`--test run_422_d7d10_signing_reservation_journal_tests`): default features
  **9 passed, 1 ignored**; `--features test-utils` **10 passed, 1 ignored** —
  reserve→consume→publish→reopen→exact retrieval, reserved-only reopen refusing a
  new continuation, conflict-after-reopen, idempotent + conflicting-overwrite over
  the real backend, shared-handle ownership, corruption/truncation/unknown-version
  fail-closed, and the bounded child-process death/reopen orchestrator.
* Broader affected outbound/cached-reemission and storage tests via the full
  `cargo test -p qbind-node --lib` run (see the validation record for the exact
  tested commit and counts). Opaque signature fixtures establish storage behavior
  only; cryptographic resend evidence stays with the real signer/verifier tests.

### What is known / not known

A successful acknowledged write in the live process establishes the in-process
durable barrier. A visible record following an uncertain write establishes
readability only. Reopening stored state after process death establishes the
recovered durable bytes with a fresh (empty) live table. Power-loss durability is
**not** inferred from a read, checksum, or process restart alone.

### Still OPEN (not addressed here)

Correction A (missing-journal refusal across all signing routes), Correction D
(post-storage original-owner revalidation and remaining identity/version checks),
Correction E (established-journal initialization and persistent capacity
accounting), and the remaining F engine-progress/process-runner work. Overall D10
remains **PARTIAL**. Local reservation protection is not activation authorization,
current-authority freshness, consensus-lock recovery, copied-key fencing, or
durable anti-rollback.

### Corrected posture (this pass)

```
D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL   (Corrections B/C complete for demonstrated local scope; A, D, E, F remain OPEN)
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE   (preserved)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain OPEN. No PR beyond the task branch, no production activation, no D11,
no Run 423 work.

## Run 422 D7-D10 — B/C review follow-up correction (tested checkpoint `d9e625c`)

This subsection **supersedes the specific overclaims** in the immediately
preceding *Corrections B/C completion pass* block. That block is retained as
historical evidence; the review found it not yet accepted, so the counts,
the "bounded `Barrier`" concurrency wording, and the "exactly one facade handoff
across supported handles" claim there are corrected below. No prior section is
rewritten.

### Source identity and object availability

* Branch: `copilot/copilotcopilotcopilotrun-422-d7-d10` (the actual checkout;
  note it differs from the problem statement's `copilot/copilotcopilotrun-422-d7-d10`).
* Starting HEAD before this pass: `7a60fd6`. Tested/pushed checkpoint for this
  pass: `d9e625c`.
* The reviewed revision `048215d9c85f8761733646a5a3905ee347f08ecc` is **not
  present** in this shallow single-branch clone (`git cat-file` fails); the
  implementation was inspected and corrected directly. This is a content-
  correspondence review, not an ancestry check; unavailable historical objects
  are not treated as missing source. `task/warning.txt` and unrelated work are
  preserved.

### Findings confirmed at the reviewed implementation (before correction)

1. **Empty result permitted at publication.** `record_signed_result` checked the
   maximum signature length but accepted an empty signature; `encode()` succeeded
   while `decode()` immediately rejected the resulting `Signed` record. A
   "successful" publication therefore wrote bytes the decoder could never read
   back.
2. **Recovered result had no durability barrier.** A live *unacknowledged* result
   was withheld, but an otherwise identical recovered `Signed` record with no live
   entry (after reopening) yielded `ExactRetryRetained` immediately. This is an
   unclosed acknowledgement contract and acceptance-test gap — **not** an observed
   RocksDB data-loss event.
3. **Concurrency was start-barrier-only.** A `Barrier::new(2)` start gate did not
   force the contender to observe an outstanding reservation; one thread could
   finish publication before the other reserved, permitting a legitimate retained
   resend and two handoffs with a single signer invocation.

### Corrections landed this pass

* **A (empty-result refusal at the publication boundary).** `record_signed_result`
  now rejects an empty signature with `JournalError::InvalidResultPublication`
  before any write, alongside the retained oversize refusal. The reserved record
  and its conflict obligation are preserved, no continuation or publication
  capability is minted, and no successful publication is reported. Before/after
  the failed attempt the stored bytes are unchanged and decode as the original
  valid **reserved** record; an exact retry remains potentially signed and a
  conflicting binding remains refused (asserted in
  `empty_result_publication_refused_and_preserves_reservation` and, over real
  RocksDB, `empty_result_publication_refused_over_real_storage`).
* **B (recovered-result durability barrier).** Under the ownership-domain lock the
  journal reads and validates the exact stored `Signed` record and reissues that
  identical record through the existing signing-record synced-write operation
  (`acknowledge_recovered_signed`); `ExactRetryRetained` is returned **only after**
  that write succeeds. A failed/uncertain barrier returns an error and suppresses
  retained-result delivery; retrying re-issues the durable write and never invokes
  the signer or mints a capability. Success caches the acknowledgement bound to the
  exact record (`recovered_acked`, keyed by position and compared on the full
  record) so a differently-associated record cannot be authorized by a cache hit.
  A recovered `Reserved` record stays `PotentiallySigned`; conflicting/malformed/
  missing/mismatched records fail closed before any recovery re-publication and are
  never overwritten.
* **C (deterministic controlled-schedule concurrency).** The start-barrier is
  replaced by a test-controlled `SignGate` (Condvar). Two supported handles share
  one backend; the winner durably reserves, obtains its continuation, and pauses
  inside the signer (`PausingSigner`) **without holding the ownership-domain
  mutex**. The contender then runs against a definitely-outstanding reservation and
  must return `PotentiallySigned` (same binding) or `Conflict` (different binding).
  The winner is released and completes. All coordination waits have explicit
  deadlines (`wait_entered`/`release`, 30s), and the paused worker is released on
  every path (including failures) before join, so a broken schedule cannot
  deadlock. Asserted: exactly one fresh continuation, exactly one winner signer
  invocation, zero contender signer calls, zero contender handoffs during the
  window, one winner handoff, and preservation of the exact reserved decision and
  retained result. A **separate** post-publication exact-retry control confirms
  that a legitimate retained resend after publication costs zero additional signer
  calls — the resend policy is not weakened to satisfy an incorrect global
  "one handoff" assertion.

### Uncertainty / recovery model evidence (lost process-local knowledge)

The store-then-error model test drives: durable reservation → one signer call →
result bytes become readable but publication returns an error → the live ownership
state is discarded → a **fresh** backend ownership domain is created over the
surviving model bytes → a retained lookup cannot succeed merely because those bytes
are readable → a failed recovery durability op still prevents delivery → a later
successful barrier permits only exact retained reuse with no additional signer
invocation. Repeated barrier failure remains failure; a conflicting binding remains
refused without rewrite; a recovered `Reserved` remains potentially signed; a
previously acknowledged result remains recoverable; a second handle over the same
live backend cannot bypass an outstanding unacknowledged operation; corruption /
mismatch fails closed before recovery publication. This is a model of **lost
process-local knowledge**, not a power-loss test.

### Executed validation (checkpoint `d9e625c`, default + `test-utils` as noted)

* Journal unit tests — `cargo test -p qbind-node --lib signing_reservation_journal`
  → **25 passed, 0 failed** (incl. the new empty-result and recovery-uncertainty
  cases). *Supersedes the earlier module counts for this scope.*
* Colocated D10 handler tests — `cargo test -p qbind-node --lib run422_d7d10`
  → **22 passed, 0 failed** (controlled contention same-/different-binding, empty-
  signer facade suppression, post-publication resend control). *Supersedes the
  earlier "21 passed / bounded `Barrier` / one handoff" wording.*
* Outbound + cached-reemission regression superset —
  `cargo test -p qbind-node --lib run422_d7b` → **81 passed, 0 failed**.
* D10 integration (default features) —
  `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests`
  → **10 passed, 1 ignored** (incl. empty-result refusal over real RocksDB and the
  recovery-acknowledgement path over reserve→consume→publish→reopen→exact
  retrieval).
* D10 integration (`--features test-utils`) → **11 passed, 1 ignored**.
* `cargo check -p qbind-node` (default production features) → **Finished** (OK).
* Focused Clippy (`cargo clippy -p qbind-node --lib`) → no new warnings in the
  changed regions (`signing_reservation_journal.rs`, the `run422_d7d10` test
  module). Pre-existing repository-wide warnings (e.g. large `Err` variants) are
  unchanged and not introduced by this pass.
* Changed-region formatting/whitespace: all three source files and both docs are
  **CRLF**; added lines preserve CRLF with no space-before-CR trailing whitespace,
  and the large handler file was not reformatted. The 1,750-test historical result
  is **not** rerun here and remains historical; focused counts above are not
  double-counted into a superset claim.

### Corrected remaining overclaims (still OPEN — not repaired here)

* **Child-process death/reopen is not a bounded, classified process-death test.**
  `reserved_only_child_death_then_reopen_refuses` still uses an unbounded
  `.status()` wait and only asserts an unsuccessful exit. It remains OPEN under F;
  it must not be described as bounded/classified. The "bounded child-process"
  wording in the preceding historical block is corrected by this statement.
  **(Superseded by Correction F execution, below: this runner is now rewritten as a
  `#[cfg(unix)]` deadline-bounded, SIGABRT-classified runner; this historical
  OPEN-under-F statement describes the prior posture only.)**
* **Established-journal initialization and persistent capacity remain OPEN under
  E.** The current `attach` API opens an established/empty journal with an in-
  memory live table; it does **not** implement explicit journal initialization
  versus established-journal opening, nor persistent capacity accounting.
* **Post-storage original-owner/ticket revalidation remains OPEN under D.**
* **Correction A (missing-journal signing refusal across all routes) remains OPEN**
  and is distinct from the empty-result *publication* refusal landed here.

### Security tooling (literal)

Production-source changes (`signing_reservation_journal.rs`) are declared
**non-trivial** for security tooling; CodeQL was requested with
`codeql.isTrivial=false`. Literal outcomes on checkpoint `d9e625c`:

* **CodeQL (rust): analysis SKIPPED** — reported "Found 0 alerts" but with
  "Analysis was skipped because the database size is too large." A size skip with
  an accompanying "0 alerts" is **not** a completed security analysis and is not
  treated as a clean pass.
* **Code review: tool UNAVAILABLE** — returned "No review comments found" but with
  an environment error ("model … not found in registry"); no real review analysis
  was performed.

Tool unavailability is left **visible** and does not erase the independently
obtained test evidence above (journal 25, handler 22, integration 10+1 / 11+1,
d7b regression 81, `cargo check` OK). Completed CodeQL/code-review remains an
outstanding obligation.

### Scoped disposition (posture preserved)

Corrections A(empty-result)/B/C and their required model, real-RocksDB, and handler
evidence are complete for their **demonstrated local scope**. Overall D10 remains
**PARTIAL** because the missing-journal refusal (A), post-storage revalidation (D),
initialization/capacity (E), and remaining engine-progress/process-runner work (F)
are excluded and OPEN. No production activation, readiness promotion, D11, or Run
423 work is performed; no PR, branch rename, force-push, rebase, or history rewrite.

```
D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

## Run 422 D7-D10 — B/C controlled-schedule & recovery-handoff completion (this pass)

Test/doc-only continuation of the reviewed checkpoint `d9e625c` / final `6526b78`
(historical objects absent from this shallow clone; source correspondence inspected
directly). Branch `copilot/copilotcopilotcopilotcopilotrun-422-d7-d10`; starting SHA
`63c547b`; implementation checkpoint `b618b4e`; final SHA is this evidence commit.

### Authorized changes (production behavior unchanged)

* `crates/qbind-node/src/binary_consensus_loop.rs` — the `run422_d7d10` test module
  and its test-local helpers only.
* `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` — §9.3
  attach/initialization overclaim replaced; §9.5 contention/recovery/runner wording
  reconciled.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — this subsection.

No production accessor, error variant, flag, storage API, dependency, or runner was
added; `signing_reservation_journal.rs`, `storage.rs`, and the real-RocksDB
integration target are reused unmodified.

### Correction A — explicit release vs timeout (gate)

The test-local `SignGate::wait_release` now returns an explicit `GateOutcome`
(`Released` / `TimedOut` / `Cancelled`). Only an explicit `Released` lets
`PausingSigner::sign_proposal` invoke the underlying `LocalKeySigner`; a timeout or
a cleanup cancellation returns `SignError::HsmError(..)` (existing error mechanism)
**without** invoking it. Wrapper entry (`proposal_entries`) and underlying-call
(`proposal_calls`) counts are separate, so a counter incremented before the pause
cannot stand in for a real signature. **Bounded waits:** exactly `wait_entered` and
`wait_release` (deadline-bounded condvar waits); the `thread::scope` join is **not**
a deadline — a test-local `GateReleaseGuard` **cancels** (never releases) the gate on
drop so a paused worker returns on a failing/panicking path. Deadlines are
configurable; the timeout control uses an immediate `Duration::ZERO` (no 30 s wait).

Direct controls:
* `d10_gate_release_permits_underlying_sign` — explicit release ⇒ 1 underlying
  signature (D6-verified), 1 handoff, `timed_out()==false`.
* `d10_gate_timeout_prevents_underlying_sign` — immediate timeout ⇒ 1 wrapper entry,
  **0** underlying calls, `signing_failure=1`, 0 delivery, reservation preserved
  (potentially-signed on modelled restart), `timed_out()==true`.

Both contention schedules (`d10_concurrent_same_binding…`, `…_different_binding…`)
now assert entries=1 / underlying=0 during the outstanding window, exactly one
underlying winner signature and handoff after explicit release, `timed_out()==false`,
zero contender signer calls/handoffs (same ⇒ `PotentiallySigned`, different ⇒
`Conflict`), and the separate post-publication exact-retry resend (0 extra signs).

### Correction B — recovered-result recovery-handoff through the guarded handler

`d10_uncertain_result_write_is_not_reported_durably_published` keeps its in-process
assertions and is extended through a **fresh ownership domain** (`D10Store::reopen`)
over the surviving `Signed` bytes, driven through the actual guarded handler with the
real signer and recording facade:
* Recovery durability barrier **fails** (`write_budget=0`) ⇒ `journal_error_total=1`,
  0 delivery, signer count unchanged, exact record preserved; a conflicting binding
  at the same position is still refused with no signature.
* Recovery barrier **uncertain** (store-then-error) ⇒ still suppressed, record preserved.
* Recovery barrier **succeeds** ⇒ exact retained resend delivered, D6-verified and
  byte-identical to the signature decoded from the journal record; **no** additional
  signer invocation. The single signer counter stays **one** across initial signing,
  both failed recovery attempts, and the successful resend.

Labelled as actual guarded-handler + real-signer execution over **model** storage
whose fresh domain represents lost process-local knowledge — **not** a
process-death / power-loss / release-binary / production-authorization claim. The
historical real-RocksDB close/reopen and the still-unrepaired (unbounded `.status()`)
child-process runner remain separately attributed to their own tests/revision.

### Evidence boundaries

* **Journal state-machine (opaque results):** `signing_reservation_journal` unit tests
  (prior revision, unchanged).
* **Real-signer guarded-handler (facade observations):** the `run422_d7d10` module,
  including the extended recovery-handoff test (this pass).
* **Historical real-RocksDB close/reopen + child-process runner:** integration target
  (prior revision, unchanged; runner is unrepaired/unbounded, OPEN under F).

### Commands, counts, outcomes (default features)

* `cargo test -p qbind-node --lib --no-run` — OK (only 2 pre-existing `dead_code`
  warnings, unrelated).
* `cargo test -p qbind-node --lib run422_d7d10` — **24 passed**, 0 failed (incl. the
  two new gate controls and the extended recovery test).
* `cargo test -p qbind-node --lib run422_d7b` — **83 passed**, 0 failed
  (D7-B outbound/cached-reemission regression superset; overlaps the focused D10 set,
  reported separately).
* Changed-region whitespace clean; files remain **CRLF with no final newline**
  (no repository-wide reformat).

### Security-tool limitations (literal)

* This pass is **test/doc-only**; CodeQL declared `codeql.isTrivial=true`
  (test-and-doc-only changes). A CodeQL scope skip is **not** a completed scan.
* An unavailable or errored reviewer is **not** a completed independent review.
* Tool limitations are recorded separately from the executed test results above.

### Scoped disposition

Closes only the remaining **B/C** evidence corrections. **Still OPEN:** A
(missing-journal refusal across all signing routes), D (post-storage
original-owner/ticket revalidation), E (established-journal initialization and
persistent capacity accounting, incl. recovered-record acknowledgement-cache
accounting), and remaining F (engine-progress + bounded/classified child-process
runner). No activation, readiness promotion, D11, or Run 423; no PR, branch rename,
force-push, rebase, or history rewrite.

C4/C5 remain OPEN.

## Run 422 D7-D10 — Correction A: missing-journal signing refusal (repaired checkpoint)

Code + test + doc pass completing Correction A (the missing-journal signing
refusal) and repairing the in-flight checkpoint whose library test target did
not compile.

### Actual branch / SHAs / object limitations

* Branch: `copilot/missing-journal-signing-refusal` — the checkout's real
  branch. The earlier report's `copilot/copilotcopilotcopilotcopilotrun-422-d7-d10`
  name and the B/C revision `cd8a7e0a317aaa546cf707c19d96a77c073817df` are **not**
  present in this shallow single-branch clone.
* Starting HEAD `752c2a7` (parent `e468bc8`). By source inspection **this HEAD**,
  not the named B/C revision, already carried the in-flight Correction-A
  production guard **and** the misplaced tests. Content correspondence is not
  ancestry; no pushed/tested checkpoint was manufactured.
* Repaired tested checkpoint `9ea380c` (module-placement repair). Every
  validation below was run against this tree. Final pushed SHA is this evidence
  commit.
* Object limitation: only these two commits exist locally; historical objects
  (`cd8a7e0…`, `d9e625c`, `b618b4e`, …) are absent and were reasoned about by
  source inspection only.

### Module-placement repair (the compile break)

The block `ca_leader_domain` + `ca_c_leader_tick_missing_journal_refuses_both_families`
+ `ca_d_cached_reemission_missing_journal_prevents_signing_and_reemission` had been
pasted **inside the body** of the test fn
`run422_d6_outbound_vote_wire_chain_refusal_through_forward_actions` (module
`run420`). As inner items they were **not collected as tests**
(`unnameable_test_items` warnings) and could not see the private helpers
`recording_ctx_v2`, `RecordingFacade`, and `OnePeer` defined in the sibling module
`run422_d7b2` (`E0425`/`E0433`). The block was moved verbatim into its owning
module `run422_d7b2` — which defines those helpers and the `d7b2_*` positive
controls the tests reference. No helper was made public, no fixture
(`OnePeer`/`RecordingFacade`/`recording_ctx_v2`) was duplicated, no test was
disabled or ignored, and no production accessor/bypass was added. The historical
line boundary was not used; the fn/module braces were. `cargo test -p qbind-node
--lib --no-run` then compiles (only 2 pre-existing, unrelated `dead_code`
warnings).

### Guard / caller audit (production vs test-only raw helpers)

Every signer-eligible outbound route signs through
`guarded_sign_proposal_for_broadcast` / `guarded_sign_vote_for_broadcast`, which
refuse a missing/unavailable journal **after** the existing context / signer /
wire-chain admission and **before** any signer invocation, reservation, retained
resend, or facade handoff, recording `outbound_proposal_journal_unavailable_total`
/ `outbound_vote_journal_unavailable_total`. Production call sites:
`forward_actions_to_facade` (immediate/broadcast Proposal, broadcast Vote,
directed Vote), `do_leader_tick` (leader Proposal + self-Vote), and
`maybe_reemit_on_late_peer_connect` (cached Proposal/Vote re-emission). The raw
`sign_proposal_for_broadcast` / `sign_vote_for_broadcast` helpers are
`#[cfg(test)]` cryptographic-unit fixtures with **no** production call site (all
raw call sites are inside `#[cfg(test)] mod tests`); their scoped crypto tests do
not substitute for guarded-handler acceptance tests. A present signature does not
exempt the guard; journal presence never constitutes authorization.
`LocalFixtureUnsigned`'s no-context passthrough has no signer (no signing decision
to reserve), but once a signer is supplied a missing journal still refuses.
Production `main` still wires no activated authority/journal and remains
fail-closed under `Required`.

### Per-route observations & positive controls

* Immediate Proposal / broadcast Vote / directed Vote —
  `run422_d7a::run422_d7b::correction_a_immediate` (`ca_a_*`, `ca_b_*`, `ca_e_*`):
  missing-journal negatives use otherwise-valid fixtures and assert the exact
  refusal counter, **0** underlying signer calls, **0** facade handoffs, and no
  false success/reservation/sent counters. `ca_b_*` add journal-present controls
  that actually sign and deliver (passing existing D6 verification); `ca_e_*`
  retain authority/wire-domain earlier-refusal precedence and the no-context
  no-signer passthrough.
* Leader Proposal + self-Vote —
  `run422_d7b2::ca_c_leader_tick_missing_journal_refuses_both_families`: both
  families refuse (proposal & vote unavailable counters = 1), 0 underlying
  signatures, silent facade; positive control
  `d7b2_valid_cache_current_auth_emits_both_families`.
* Cached Proposal/Vote re-emission —
  `run422_d7b2::ca_d_cached_reemission_missing_journal_prevents_signing_and_reemission`:
  caches produced by a journaled leader tick, re-emission then driven with the
  journal absent; nothing signed beyond setup, 0 re-emits, silent facade; positive
  control `d7b2_do_leader_tick_creates_caches_then_real_reemission_uses_them`.

### Cached ordering & evidence limits

In `maybe_reemit_on_late_peer_connect` the cached **Proposal** is signed first;
its missing-journal refusal `return`s and short-circuits the attempt **before**
the paired cached **Vote** branch. `ca_d` therefore reports Proposal counter 1 and
Vote counter 0 and does **not** claim the cached-Vote negative branch executed.
Cached-Vote missing-journal coverage is established instead by the shared Vote
guard negative (`ca_a_vote_*`), the verified cached-Vote call site
(`guarded_sign_vote_for_broadcast` in the re-emit path), and the journal-present
cached-Vote positive control. Production ordering was not changed to manufacture a
path. Leader/self-Vote coverage does **not** close the separate F engine-progress
obligation.

### Validation (all against `9ea380c`, dev profile unless noted, exit 0)

* `cargo test -p qbind-node --lib --no-run` — OK (2 pre-existing `dead_code` warnings).
* `cargo test -p qbind-node --lib correction_a` — **16 passed** (10 handler
  `binary_consensus_loop::run422_d7b::correction_a_immediate` cases + 6 existing
  same-named `vm_v0_runtime` cases; the earlier "8 + 8" breakdown was a
  miscount — the historical total of 16 and checkpoint `9ea380c` are unchanged).
* `cargo test -p qbind-node --lib run420::run422_d7b2` — **26 passed** (leader/cached,
  incl. relocated `ca_c`/`ca_d`).
* `cargo test -p qbind-node --lib run422_d7d10` — **24 passed**.
* `cargo test -p qbind-node --lib run422_d7b` — **95 passed** (d7b/d7b2/d7b3 +
  `correction_a_immediate` superset; overlaps the focused sets, reported separately).
* `cargo test -p qbind-node --lib` — **1769 passed**, 0 failed.
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests`
  — default features **10 passed / 1 ignored**; `--features test-utils`
  **11 passed / 1 ignored**.
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` — **34 passed**.
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests` — **3 passed**.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` — **4 passed**.
* `cargo check -p qbind-node` — Finished, no errors.
* `cargo clippy -p qbind-node --lib` — Finished; **95 pre-existing** style warnings
  (large `Err` variants, `suspicious_open_options`, `ptr_arg`, `unnecessary_sort_by`)
  in unrelated production code, **none** in the relocated test block; no errors.
* `cargo build --release -p qbind-node --bin qbind-node` — Finished (release, optimized).

### Release executable identity

* Path `target/release/qbind-node`; source revision `9ea380c`; profile release
  [optimized]; features **default** (no `--features`); bin `qbind-node`.
* Byte length **17066744**; SHA-256
  `b9046c9d5f4b1150d2db280aa4e35ab14270c0327b95c76e97c0d10e6dabf402`.
* Compilation establishes buildability only — **not** configured-authority runtime
  evidence.

### Security-tool outcomes (literal)

* Code Review: completed over 2 changed files, **no review comments**; the run also
  reported a backend model-registry error, so this is **not** counted as a clean
  completed independent review.
* CodeQL: **Skipped** — declared trivial (test-relocation within `#[cfg(test)]` +
  Markdown only). A CodeQL scope skip is **not** a completed scan.

### Documentation & EOL reconciliation

* `QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`: §9.3 corrected —
  attach **reuses** the backend's existing ownership domain and does **not** empty
  the shared live-operation table; only a newly created domain starts with fresh
  process-local state; the reservation counter is **shared by the domain** and each
  handle applies its configured limit against it (replacing the per-attached-handle
  budget overclaim); persistent-capacity and recovered-record acknowledgement-cache
  accounting remain OPEN under E; the dangling `(see §12)` now points to `§9.5`.
  §9.5 records Correction A as executed and drops it from the Still-OPEN list; the
  marker block adds `D7D10_MISSING_JOURNAL_SIGNING_REFUSAL=CODE-TEST-POSITIVE` and
  keeps `D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL`.
* `contradiction.md`: inspected; **unchanged** — its only re-emission mentions are
  historical B9/B10 milestone/changelog entries; no operative statement claims
  outbound signing or re-emission succeeds without a journal, so nothing
  contradicts this implementation.
* EOL/EOF: `binary_consensus_loop.rs` and both edited docs remain **CRLF with no
  final newline**; no repository-wide reformat; changed regions whitespace-clean.

### Historical honesty

The starting checkpoint `752c2a7` did **not** compile its library test target (the
misplaced block). Its earlier per-module baseline numbers are not validation of the
repaired tree; all pass counts above were produced on the repaired checkpoint
`9ea380c`.

### Scoped disposition

`D7D10_MISSING_JOURNAL_SIGNING_REFUSAL=CODE-TEST-POSITIVE` (local demonstrated
scope). `D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL` unchanged. **Still OPEN:** D
(post-storage original-owner/ticket revalidation + outstanding identity/version
checks), E (established-journal initialization/validation and persistent capacity,
incl. recovered-record acknowledgement-cache accounting), F (remaining
engine-progress evidence + bounded/classified child-process runner). The accepted
D8 result and all posture markers are preserved: D7 partial / production lifecycle
unavailable; durable anti-rollback not established; genesis authority activation
disabled; production wire-chain behavior unchanged; configured-authority
release-binary evidence not yet captured; RS1 OPEN / public-DevNet NO-GO; C4/C5
OPEN. No readiness promotion, D11, Run 423, PR, branch rename, force-push, rebase,
or history rewrite; no activation change.

## Run 422 D7-D10 — Correction D: post-storage authorization revalidation before signing

Code + test + doc pass implementing the bounded Correction-D signing boundary: the
**original** admission identity is carried unchanged through journal work and
revalidated before the signer (fresh path) or before retained-result reuse, and
signer-identity / wire-message-version checks refuse before journal lookup.
Production authority activation remains **disabled**; D10 remains **PARTIAL**.

### Provenance

* Branch `copilot/copilotmissing-journal-signing-refusal` (supplied task branch,
  unchanged). Starting HEAD `ab86e58`. Reference objects `6ee6217` (Correction-A
  final) and `9ea380c` (tested checkpoint) are **not present** in this shallow
  (depth-2) clone, so correspondence is established from implementation content,
  not ancestry. The implementation + test checkpoint validated below is `0276fda`.

### Where the original ticket / context is retained

* `AdmittedSigningIdentity<'a>` (private, `binary_consensus_loop.rs`) holds only
  borrowed references to the admitted `AuthorizedProposalVoteSnapshot` and the exact
  `AuthorizationTicket` its owner issued at admission — never a freshly-minted
  ticket, a separately-supplied authority, or a newly-selected signer. It is
  resolved fail-closed by `resolve_admitted_identity` from the caller's
  `(current_auth, ticket)` pair (both present ⇒ revalidate; neither ⇒ the
  `LocalFixtureUnsigned` no-context passthrough; exactly one ⇒ refuse) and threaded
  into `guarded_sign_{proposal,vote}_for_broadcast` / `_reserved` at all five
  production call sites: three in `forward_actions_to_facade` (broadcast Proposal,
  broadcast Vote, directed `SendVoteTo`) and two in
  `maybe_reemit_on_late_peer_connect` (cached Proposal, cached Vote).

### Exact ordering

* **Fresh path** (`guarded_sign_*_reserved`): existing admission/epoch → context /
  signer / wire-domain / Correction-A missing-journal checks → per-kind
  height/round(/step) position check → **wire-version** check → **signer-identity /
  membership** check → suite assignment + D6 preimage → `reserve_for_sign`
  (`FreshlyReserved`) → `consume_for_signing` (acquires the ownership-domain mutex)
  → **`reconfirm_after_journal(ctx)`** (bound-context pointer identity, then
  `owner().confirm(ticket)`) → `signer.sign_*` → `record_signed_result` →
  `confirm_outbound_before_effect` → delivery. The final pre-sign confirmation is
  placed **after** `consume_for_signing` so the mutex acquisition is not an
  unaccounted wait between confirmation and signing; no journal mutex is held during
  signing and no other blocking storage op sits between the confirmation and the
  signer.
* **Retained-result path** (`ExactRetryRetained`): the B/C recovery-acknowledgement
  barrier completes inside `reserve_for_sign`; then `reconfirm_after_journal` runs
  before the retained signature is treated as an authorized reuse; existing D6
  verification of the exact retained message/signature is retained; confirmation
  before delivery is preserved.

### Rejection behavior (reservation preservation)

* A post-journal confirmation failure performs **zero** signer calls and **zero**
  delivery, publishes no result, drops the operation capability, and **preserves**
  the durable `Reserved` record and its conflict obligation (never deletes,
  releases, resets, or overwrites it); no re-admit/retry occurs within the
  operation. A retry of the same decision therefore resolves to
  `PotentiallySigned` (conservative potentially-signed treatment), asserted by both
  unchanged stored bytes and the retry counter.
* Distinct bounded counters keep the reasons separable:
  `outbound_{proposal,vote}_wire_version_unsupported_total`,
  `outbound_{proposal,vote}_signer_identity_mismatch_total`,
  `outbound_{proposal,vote}_bound_context_unbound_total`, and
  `outbound_{proposal,vote}_post_journal_authorization_revalidation_failed_total`.

### Identity / version checks and trusted sources

* Wire index vs bound signer `ValidatorId` is compared by **widening** the wire
  index to `u64` (`bound_id.as_u64() == proposer_index as u64` /
  `... == validator_index as u64`), so a `ValidatorId` larger than `u16::MAX`
  cannot alias a representable wire index through narrowing; membership uses the
  admitted `ConsensusValidatorSet::contains`. The supported local Proposal/Vote
  wire-message version is `1` (`LOCAL_PROPOSAL_VOTE_WIRE_MESSAGE_VERSION`, matching
  the `BlockHeader` / `Vote` wire structs), kept **distinct** from the D6
  signing-format version (`D6_SIGNING_FORMAT_VERSION = 2`) and the journal-record
  format version. Wire version 2 is therefore refused and is never mistaken for D6
  version 2. No identity or version field is rewritten to make a message pass.
* Earlier Correction-A / admission refusal precedence is intact: the new checks sit
  after the existing authority / current-state / epoch / signer / wire-domain /
  missing-journal rejections and never relabel them.

### Direct observations vs staged/helper evidence

* **Normal-entrypoint controls** drive the real immediate
  (`forward_actions_to_facade` via `drive_j`) and cached
  (`maybe_reemit_on_late_peer_connect`) callers, proving the production wiring
  reaches the boundary and keeps the new counters at 0 on the success path
  (`cd_a_immediate_success_keeps_revalidation_counters_zero`,
  `cd_f_directed_vote_entrypoint_reaches_boundary`,
  `cd_f_cached_reemission_entrypoint_control`).
* **Staged tests** (`cd_b_*`, `cd_c_*`, `cd_d_*`, `cd_e_*`, and the staged success
  control) call the **same** private post-journal continuation the production
  callers use, mutating the fixture owner between explicit phases via the existing
  `owner_mut()` / `replace_for_fixture` / `set_generation_for_exhaustion_fixture`
  APIs — **no** unsafe aliasing, **no** production mutation hook, **no** sleeps,
  **no** fabricated concurrent owner. Signer invocation is observed **directly**
  via the `RecordingSigner` per-call atomics (underlying signer, not wrapper entry).
  These are labelled staged in-source.
* This is a bounded local demonstration on the **serialized** handler (today the
  owner is non-cloneable, replacement needs `&mut`, and the handler is serialized).
  It is **not** configured-authority runtime evidence.

### Current serialized-owner assumption and remaining limitations

* The check-to-sign gap is closed by the serialized outbound handler; no concurrent
  owner mutation or authority-locking redesign is introduced. **E** (explicit
  initialization vs established-journal validation; persistent capacity and
  acknowledgement-cache accounting) and **F** (remaining engine-progress evidence;
  bounded/classified child-process runner) remain **OPEN**.

### Validation (implementation+test checkpoint `0276fda`, dev profile unless noted, exit 0)

* `cargo test -p qbind-node --lib run422_d7d10::...::correction_d` — **19 passed**.
* `cargo test -p qbind-node --lib run422_d7d10` — **43 passed**.
* `cargo test -p qbind-node --lib run422_d7b` — **114 passed** (d7b/d7b2/d7b3 +
  `correction_a_immediate` + `correction_d`; overlaps the focused sets).
* `cargo test -p qbind-node --lib correction_a` — **16 passed** (10 handler
  `correction_a_immediate` + 6 existing `vm_v0_runtime`).
* `cargo test -p qbind-node --lib run420::run422_d7b2` — **26 passed**.
* `cargo test -p qbind-node --lib` — **1788 passed**, 0 failed (1769 prior + 19 new).
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests`
  — default features **10 passed / 1 ignored**; `--features test-utils`
  **11 passed / 1 ignored**.
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` — **34 passed**.
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests` — **3 passed**.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` — **4 passed**.
* `cargo check -p qbind-node` — Finished, no errors.
* `cargo clippy -p qbind-node --lib` — Finished; **0 errors**; the pre-existing
  style warnings (large `Err` variants, `is_multiple_of`, `suspicious_open_options`,
  etc.) are all in unrelated code — **none** reference the Correction-D functions or
  the `correction_d` test module (the sole `too_many_arguments` site is L6644, not a
  changed guard; the new guards take 6 arguments).
* `cargo build --release -p qbind-node --bin qbind-node` — Finished (release, optimized).

### Release executable identity

* Path `target/release/qbind-node`; source revision `0276fda`; profile release
  [optimized]; features **default** (no `--features`); bin `qbind-node`.
* Byte length **17072352**; SHA-256
  `6f87516611a3c0c4e39e7253fdb5caf2d361c3ad858fec8657aa2cb785cec9a9`.
* Compilation establishes buildability only — **not** configured-authority runtime
  evidence.

### Security-tool outcomes (literal)

* Code Review: reported success over 3 changed files with **no review comments**,
  but the same run emitted a backend model-registry error
  (`model claude-sonnet-4.6 not found in registry`); this degraded run is therefore
  **not** counted as a clean completed independent review.
* CodeQL (rust): **0 alerts**, but the analysis was **Skipped — database size too
  large**. A database-size skip is **not** a completed scan.

### Documentation & EOL reconciliation

* `QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`: §4.1 step 2/3 now
  documents the pre-journal wire-version + signer-identity gates and step 5 is
  marked **implemented by Correction D** (`AdmittedSigningIdentity::reconfirm_after_journal`
  after `consume_for_signing`, before the signer; retained-reuse reconfirmation;
  fail-closed pairing). §9.5 adds an Executed (Correction D) bullet and trims the
  Still-OPEN bullet to E + F; the marker block adds
  `D7D10_POST_STORAGE_AUTHORIZATION_REVALIDATION=CODE-TEST-POSITIVE` and keeps
  `D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL`.
* The preceding Correction-A count breakdown is corrected: its `correction_a`
  filter is **10 handler** (`correction_a_immediate`) **+ 6 existing** `vm_v0_runtime`
  cases = **16** (the earlier "8 + 8" split was a miscount; the historical total of
  16 and checkpoint `9ea380c` are unchanged).
* `contradiction.md`: inspected; **unchanged** — no operative statement conflicts
  with carrying/revalidating the admission through journal work.
* EOL/EOF: `binary_consensus_loop.rs` and both edited docs remain **CRLF with no
  final newline**; no repository-wide reformat; changed regions whitespace-clean.

### Scoped disposition

`D7D10_POST_STORAGE_AUTHORIZATION_REVALIDATION=CODE-TEST-POSITIVE` (serialized-handler
local demonstrated scope). `D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL` unchanged.
Preserved: `D7D10_MISSING_JOURNAL_SIGNING_REFUSAL=CODE-TEST-POSITIVE`,
`D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`,
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. **Still OPEN:** E and F (as
above); C4/C5 remain OPEN. No authority activation, readiness promotion, D11, or
Run 423 work; no PR, branch rename, force-push, rebase, or history rewrite.

## Run 422 D7-D10 — Correction D completion: required admission, signer-suite consistency, post-journal evidence

Code + test + doc pass closing the three Correction-D gaps identified in the
source review (required admission at the shared guard, signer-suite/key/backend
consistency, and genuine between-phase invalidation through the actual
production continuation), plus fresh-vs-retained rejection wording. Scope is the
single authorized implementation/test file
`crates/qbind-node/src/binary_consensus_loop.rs` and this doc + the continuity
contract. No new public accessor, unchecked constructor, journal format, storage
API, dependency, CLI flag, production fault-injection hook, parser, cryptographic
implementation, or authority framework. Production startup still leaves
authority/journal activation unavailable.

### Correction A — required admission at the shared boundary

The shared guard is now **policy-aware**. After the preserved missing-journal
refusal, `guarded_sign_{proposal,vote}_for_broadcast` refuse a **missing original
admission** under `ConsensusVerificationPolicy::Required` **before** journal
access (`reserve_for_sign`), retained-result reuse, or signer invocation, via
`outbound_{proposal,vote}_required_admission_missing_total`. This is the shared
guard's own contract — not a claim about the outer callers, which already reject
missing required authorization earlier; the finding concerned the guard's
contract, not an established production-route bypass. `resolve_admitted_identity`
refuses an impossible snapshot-XOR-ticket half-pair fail-closed, and neither
component is accepted through the test-only `LocalFixtureUnsigned` case: a
signer-bearing fixture under that policy still requires a journal and the
identity/version/suite checks; a genuinely unsigned no-context fixture keeps its
existing passthrough. Diagnostics/counters are bounded and accurate — a refusal
before storage is never described as a post-storage confirmation failure.
Direct-guard negatives `cd_g_required_missing_admission_refuses_before_journal_and_signer`
(Proposal + Vote) invoke the actual guard with a valid context, signer, and
journal (reads forced to fail) but no admission under `Required` and assert
refusal, zero journal reads/writes, zero signer calls, and no returned message;
`cd_g_localfixture_unsigned_signer_without_admission_still_signs` is the permitted
control.

### Correction B — governed suite/key/backend consistency

Before any journal lookup or reservation, `check_governed_suite_backend` requires,
reusing the admitted `SuiteAwareValidatorKeyProvider` and
`ConsensusSigBackendRegistry` (no parallel allowlist/parser), that a governed
suite/key entry exists for the selected validator, the bound signer's suite
matches that governed suite, and the admitted backend registry supplies the
governed suite backend — mirroring the inbound `verify_*_msg_with_domain` policy.
Permitted suite assignment precedes D6-preimage construction; validator identity,
epoch, chain, version, and position are never rewritten. These checks establish
signer/governance suite correspondence and backend availability **only** — they do
**not** prove possession of the corresponding private key (no key introspection),
which remains the separate retained-result D6 verification. Negatives
`cd_h_missing_key_entry_refused_before_journal`,
`cd_h_suite_mismatch_refused_before_journal`,
`cd_h_missing_backend_refused_before_journal`, and the Vote counterpart
`cd_h_vote_missing_backend_refused_before_journal` each refuse before journal
access and signing (distinct counters, zero journal error, empty store); the
existing real-signer/D6 positive control is retained.

### Correction C — actual post-journal continuation

`guarded_sign_{proposal,vote}_reserved` are now thin wrappers over a private
`prepare_{proposal,vote}_signing_reservation` → `complete_{proposal,vote}_signing`
split. Prepare performs the per-kind identity/version/suite checks, the D6
preimage + exact-decision binding, the durable reservation, and consumes the
one-use continuation (returning `PreparedProposalSigning::Fresh{proposal,preimage,
publish_cap}` or `::Retained{proposal,retained_sig}`, owned values carrying no
fresh ticket, reconstructed capability, or replacement signer). Complete runs the
post-journal `reconfirm_after_journal` and then EITHER exactly one signer call +
`record_signed_result` (fresh) OR D6-verified authorized reuse (retained). The
**production caller and the staged tests use the same completion implementation**
— reconfirm/sign/publish logic is not duplicated in a test helper.

Fresh staged evidence (`cd_i_between_phase_*`, driven by
`staged_between_phase_proposal`): obtain a valid admission, prepare + complete the
durable reservation and consume its continuation, capture the actual stored
`Reserved` bytes, mutate the fixture authorization state **between** the two owned
phases, then invoke the production completion — asserting zero signer calls, no
publication, no signed output/handoff, byte-identical `Reserved`, exact retry ⇒
`PotentiallySigned`, and a conflicting binding still refused. Cases cover
generation advance, made-unavailable, and terminal exhaustion, with a Vote
counterpart (`cd_i_vote_between_phase_generation_advance_suppresses_before_sign`)
and a positive staged control (`cd_i_staged_success_through_split_signs_once`)
that signs once and D6-verifies. The mutation is a between-phase owner replacement
of an owned snapshot — no unsafe aliasing, sleeps, production mutation hook, or
replacement boolean authorization callback, and no fabricated concurrent mutation
of an immutably borrowed owner.

Recovered-retained evidence (`cd_i_recovered_retained_reuse_suppressed_after_reopen_and_invalidation`,
`cd_i_recovered_retained_reuse_control_signs_once_and_reuses`): a genuine signed
record is produced with the real signer, the store is reopened through the
existing test storage's fresh ownership domain, the journal's recovered-record
acknowledgement completes inside `prepare` (Retained, **no** new signer call), the
original admission is invalidated before `complete`, and completion suppresses
reuse with no new signature, no authorized reuse/handoff, and the exact `Signed`
record byte-preserved; the control resends once (D6-verified) with no additional
signer call. **This is MODEL reopen — not power-loss / real-RocksDB-recovery /
release-binary evidence**; model storage does not become power-loss or
release-binary evidence.

The earlier stale-owner tests (`cd_b_*`, `cd_c_*`, `cd_d_*`, `cd_e_*`) invalidate
the owner (or substitute the context) **before** invoking the whole guard; they
demonstrate stale-ticket / substituted-context refusal for a reservation created
with an already-stale ticket, **not** mutation between journal completion and
signing, and are retained and relabelled accordingly. Normal immediate, directed,
and cached entrypoint controls (`cd_a_*`, `cd_f_*`) are retained. Ordering
established by source inspection (reconfirm sits between `consume_for_signing` and
`signer.sign_*`) is described separately from directly observed test events; the
staged tests detect removal or premature placement of the reconfirmation because a
between-phase mutation with the reconfirm removed would sign and publish.

### Rejection semantics wording

Separated everywhere: fresh pre-sign rejection preserves `Reserved`, invokes no
signer, publishes no result, and dropping `publish_cap` never releases the
obligation; retained-reuse rejection preserves the existing `Signed` record,
produces no additional signature, delivers nothing, never turns the record back
into `Reserved`, and never makes a completed historical signature "never
existed". Comments, logs, the continuity contract §9.5, and this evidence are
reconciled with the actual final tests; prior D10 blocks are retained as
historical evidence at their tested revisions and this block supersedes their
between-phase claims.

### Validation, tooling, and disposition

`contradiction.md`: inspected; **unchanged** — no operative statement conflicts
with policy-aware required admission, governed suite/backend correspondence, or
the prepare/complete continuation split. EOL/EOF: `binary_consensus_loop.rs` and
both edited docs remain **CRLF with no final newline**; no repository-wide
reformat; changed regions whitespace-clean.

`D7D10_POST_STORAGE_AUTHORIZATION_REVALIDATION=CODE-TEST-POSITIVE` (serialized-handler
local demonstrated scope; model reopen, not power-loss/release-binary evidence).
`D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL` unchanged. Preserved:
`D7D10_MISSING_JOURNAL_SIGNING_REFUSAL=CODE-TEST-POSITIVE`,
`D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`,
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. **Still OPEN:** Correction E and
the remaining F work; C4/C5 remain OPEN. No authority activation, readiness
promotion, D11, or Run 423 work; no PR, branch rename, force-push, rebase, or
history rewrite.
> **Superseded (historical).** This section's "Correction E … Still OPEN" verdict
> is the conclusion of its own prior pass and is retained as historical evidence.
> Correction E was subsequently implemented and tested — see "Run 422 D7-D10
> Correction E execution" below; F remains OPEN.
## Run 422 D7-D10 — Correction D finalization: operation binding across the prepare/complete split

### Provenance and object limitations

* **Branch:** `copilot/run-422-complete-correction-d-again` (the reviewed
  `copilot/run-422-complete-correction-d` does **not** exist in this checkout).
* **Starting SHA:** `ce80ee4886a75e9ed94629aa34d4856ba59dd81f` (parent of the
  pre-existing `update` commit; present in `.git/shallow`).
* **Implementation/test checkpoint:** `ae894dd898181845594d4e9bed84fd57aa71f00d`
  (code + tests). Documentation (this evidence + continuity contract §4.1/§9.5) is
  committed **after** the checkpoint and is documentation-only: it does not alter
  the binary or the tests validated at the checkpoint.
* **Historical objects:** the reviewed final `a0f25008…`, the reported checkpoint
  `f94a8f6a…`, and the reported checkpoint `f94a8f6a…` are **not reachable** in
  this shallow single-branch clone (only `ce80ee4` is in `.git/shallow`); current
  source correspondence was inspected directly without manufacturing ancestry.

### Changed paths and operation-binding implementation

Single code/test file: `crates/qbind-node/src/binary_consensus_loop.rs`.

* New private `BoundSigningOperation<'a>` freezes, **before any journal work**, the
  original admission ticket (an owned `AuthorizationTicket` clone preserving exact
  issuer/generation identity), the selected bound context (`&'a ProposalVoteAuthority`),
  and the selected signer (`&'a Arc<dyn ValidatorSigner>`).
* `PreparedProposalSigning`/`PreparedVoteSigning` now carry `{ op: BoundSigningOperation,
  kind }`, where `kind` (`Fresh { proposal, preimage, publish_cap }` /
  `Retained { proposal, retained_sig }`) holds only the message-specific journal
  outcome. The prepared value never carries a fresh ticket, a reconstructed
  capability, or a replacement signer.
* `prepare_{proposal,vote}_signing_reservation` gained an `admission` parameter used
  **only** to freeze the original ticket into `op` before `reserve_for_sign`.
* `complete_{proposal,vote}_signing` **no longer** takes `ctx`/`admission`/`signer`
  parameters; it takes only `current_snapshot: Option<&AuthorizedProposalVoteSnapshot>`
  for drift detection.
* `AdmittedSigningIdentity::reconfirm_after_journal` was replaced by the free function
  `reconfirm_bound_operation(op, current_snapshot)`: it requires the frozen `op.ctx`
  to be the current snapshot's bound verifier by **pointer identity**
  (`ContextUnbound` otherwise), then confirms the **frozen original ticket** against
  the current owner. A required op (`Some` ticket) with `current_snapshot == None`
  refuses fail-closed; a fixture op (`None` ticket) has nothing to reconfirm.
* Fresh-vs-retained diagnostic wording reconciled in the post-journal rejection logs
  (fresh: no signer invocation, `Reserved` preserved; retained: no additional
  signature, existing `Signed` preserved; no delivery).

### What the prepared operation now freezes; which completion inputs remain

Freezes original ticket, bound context, and selected signer. Completion accepts
only the current snapshot (drift detection); it has **no** ticket/context/signer
parameter, so a replacement ticket minted after storage, a substituted context, or
a different signer cannot be supplied at completion. Original-ticket confirmation
after owner change uses the **frozen** ticket against `current.owner().confirm(…)`:
a supplied current owner never becomes the original issuer merely by matching
fields; a newly-minted ticket for the advanced owner is never accepted.

### Test cases and evidence boundaries (`run422_d7d10::correction_d`, 36 tests)

* **A — replacement ticket:** `cd_i_replacement_ticket_t1_cannot_authorize_prepared_t0_operation`
  — prepare/reserve/consume under T0, advance owner generation, obtain a valid T1
  (asserted to confirm against the updated owner), show completion still refuses via
  the frozen (now `Stale`) T0; zero signer calls, byte-identical `Reserved`. The
  replacement-ticket parameter elimination is a source/type guarantee (completion
  has no ticket parameter).
* **B — foreign owner/context:** `cd_i_substituted_current_context_refused_across_split`
  (bound-context pointer identity decisive → `bound_context_unbound`) plus retained
  `cd_b_different_owner_equal_config_generation_foreign_issuer` (foreign issuer via
  the production guard) and `cd_c_substituted_verifier_refused_before_signing`;
  `cd_i_required_operation_without_current_snapshot_refuses_before_sign` (required op
  cannot degrade into a fixture op).
* **C — frozen signer:** `cd_i_completion_signs_through_frozen_signer_not_a_same_id_replacement`
  — an independent same-`ValidatorId(0)`/same-suite signer `Arc` is frozen at prepare;
  completion signs through it exactly once (D6-verifies, publishes) while the
  snapshot's own bound signer counter stays 0. Structural: no completion signer
  parameter to substitute.
* **D — both families + retained reuse:** Vote counterpart
  `cd_i_vote_between_phase_generation_advance_suppresses_before_sign`; generation
  advance / made-unavailable / terminal exhaustion staged cases; recovered-retained
  suppression + control (`cd_i_recovered_retained_reuse_*`) preserving the exact
  `Signed` record with no additional signature. Labelled MODEL reopen — **not** real
  RocksDB, process-death, power-loss, release-binary, or production-authorization
  evidence.
* **E — normal callers:** immediate/directed/leader-self/cached controls (`cd_a_*`,
  `cd_f_*`) retained through their actual shared production guard paths.

Between-phase tests are **staged** tests of the serialized implementation (no sleeps,
no unsafe aliasing, no fabricated concurrent mutation, no duplicated test-only signing
implementation, no new public accessor); they are **not** real-handler concurrency
evidence. The staged split clones the snapshot's verifier/signer `Arc`s into locals
before prepare so the frozen op does not borrow `snap`, permitting the between-phase
`&mut snap` mutation while pointer identity still holds.

### Validation (code+test checkpoint `ae894dd`, dev profile unless noted, all exit 0)

* `cargo test -p qbind-node --lib correction_d` → **36 passed, 0 failed, 0 ignored**
  (1769 filtered out).
* `cargo test -p qbind-node --lib` (default features) → **1805 passed, 0 failed,
  0 ignored** (subsumes Correction-A `ca_*`, required-admission `cd_g_*`,
  suite/backend `cd_h_*`, and the `run422_d7d10`/`run422_d7b`/`run422_d7b2` subsets).
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests`
  (default) → **10 passed, 0 failed, 1 ignored**.
* same target `--features test-utils` → **11 passed, 0 failed, 1 ignored**.
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`
  → **34 passed, 0 failed, 0 ignored**.
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests`
  → **3 passed, 0 failed, 0 ignored**.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests`
  → **4 passed, 0 failed, 0 ignored**.
* `cargo check -p qbind-node` → exit 0.
* `cargo clippy -p qbind-node --lib` → exit 0; 95 pre-existing warnings, **none** in
  the changed functions (`BoundSigningOperation`, `reconfirm_bound_operation`,
  `prepare_*`/`complete_*`). Not repaired (unrelated).
* `cargo build --release -p qbind-node --bin qbind-node` → exit 0.

The one ignored integration test in each `run_422_d7d10` run is the unbounded
child-process death control (F-scope, retained ignored). rustfmt: the file has a
large **pre-existing** repo-wide divergence and was **not** reformatted (task rule);
changed regions match the surrounding hand-format style; CRLF/EOF preserved.

### Release executable identity

* Path: `target/release/qbind-node`; profile: `release` (optimized); features: default.
* Source revision: code at checkpoint `ae894dd` (doc-only edits committed later do
  not alter the binary).
* Byte length: **17084336**; SHA-256: `7553ffd8366a276813e12084861dd19bf5a76b206c60395f373e4272974ac254`.
* Release compilation establishes **buildability only**; it does **not** close
  configured-authority release-binary runtime evidence
  (`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`).

### Security / review outcomes (literal)

* CodeQL security scan and the independent Code Review tool were **not executed** in
  this finalization pass. Per policy this is recorded as **incomplete analysis /
  incomplete independent review** — it is **not** a pass. Historical security
  outcomes from prior passes are **not** copied here as newly executed.
* No secrets/keys/signatures are exposed by the code, tests, logs, or docs changed
  in this pass.

### Documentation & EOL reconciliation

* `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` §4.1 step 5
  rewritten to describe the frozen `BoundSigningOperation` and parameterless
  completion (replacing the obsolete `AdmittedSigningIdentity::reconfirm_after_journal`
  wording); §9.5 adds an Executed (Correction D operation binding) bullet, updates the
  test count to 36, and refreshes the `D7D10_POST_STORAGE_AUTHORIZATION_REVALIDATION`
  marker text. Earlier operative instructions superseded, not deleted.
* `docs/whitepaper/contradiction.md`: inspected; **unchanged** — its "Correction D"
  references concern Run 422 D7-D8 restore-completion, not this signing split; no
  operative statement became inaccurate.
* EOL/EOF: `binary_consensus_loop.rs` and both edited docs remain **CRLF**; no
  repository-wide reformat; changed regions whitespace-clean (the `\r` flagged by
  `git diff --check` is the file's own CRLF convention, preserved).

### Scoped disposition

`D7D10_POST_STORAGE_AUTHORIZATION_REVALIDATION=CODE-TEST-POSITIVE` (serialized-handler
local demonstrated scope; the prepared operation is now bound across the split — model
reopen, not power-loss/release-binary evidence). Retained unchanged:
`D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL`,
`D7D10_MISSING_JOURNAL_SIGNING_REFUSAL=CODE-TEST-POSITIVE`,
`D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`,
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. **Still OPEN:** Correction E and the
remaining F work; C4/C5 remain OPEN. No authority activation, readiness promotion,
D11, or Run 423 work; no PR, branch rename, force-push, rebase, or history rewrite;
`task/warning.txt` and unrelated work preserved.
> **Superseded (historical).** This "Correction E … Still OPEN" verdict is the
> conclusion of its own prior pass, retained as historical evidence. Correction E
> was subsequently implemented and tested — see "Run 422 D7-D10 Correction E
> execution" below; F remains OPEN.


## Run 422 D7-D10 — Correction E: direct-read bounds, remaining acceptance evidence, and final validation

### Provenance and object limitations

Reviewed branch `copilot/copilotcopilotrun-422-complete-correction-d-again` and
reviewed checkpoint `7de6c7698a0567bbc598579f9a9f55e8164be126` were UNAVAILABLE
as objects in this shallow single-branch clone. The supplied task branch
(`copilot/copilotcopilotcopilotrun-422-complete-correction-d-again`) was used
unchanged; source correspondence was inspected directly and no ancestry was
manufactured. Implementation+test checkpoint: `fabb16c`. Normal commits and push
only — no PR, main changes, branch rename, force-push, rebase, or history
rewrite.

### Changed paths and reused mechanisms

* `crates/qbind-node/src/signing_reservation_journal.rs` — made the codec-owned
  `METADATA_ENCODED_LEN` public for backend reuse; bounded the model store's
  direct record/metadata reads before cloning; added recovered-ack FIFO cache
  acceptance tests and model-store direct-read bound tests.
* `crates/qbind-node/src/storage.rs` — bounded RocksDB `get_signing_record`
  (`4 + MAX_RECORD_LEN`) and `get_signing_metadata` (`4 + METADATA_ENCODED_LEN`)
  against the raw backend value before copy/unwrap; bounded the InMemory getters
  before clone; added a minimal `#[cfg(any(test, feature = "test-utils"))]` raw
  signing-namespace write seam to observe the truncation/oversize boundary; added
  InMemory direct-read bound unit tests.
* `crates/qbind-node/src/binary_consensus_loop.rs` — bounded the colocated D10
  store's direct getters before clone (test fixtures/tests only; accepted
  production code preserved); added a D10 direct-read bound test.
* `crates/qbind-node/tests/run_422_d7d10_signing_reservation_journal_tests.rs` —
  added direct-read bounds integration cases over real RocksDB (valid control,
  genuine absence, oversized record, oversized metadata, at-limit, truncated
  record/metadata, oversized-raw-before-unwrap); removed inaccurate "bounded
  child-process" wording from the header and helper comments.

Reused: existing CRC envelope codecs/`unwrap_checksummed`, the per-record and
fixed-metadata length constants, the ownership domain, failure-injection
facilities, recording signers, and the RocksDB fixtures. No production bypass or
general test framework was added.

### Direct-read bounds and backend-specific tests

Each backend's DIRECT reads now apply the applicable length bound to the
backend-owned value BEFORE copying the payload or unwrapping the checksum
envelope (matching the iterator's existing discipline). Tested on the real
RocksDB backend (integration target) and on InMemory / model / D10 stores (unit
tests): valid control, genuine absence (`None`, never an error), oversized record
and metadata (refused `Corruption`), exactly-at-limit (permitted; the gate is a
strict `>`), truncated sub-envelope input (refused), and a raw oversized value
refused before any unwrap. Allocation-limit scope is stated honestly: the RocksDB
`get` still allocates its backend-owned value; the bound limits only the
subsequent application-owned copy/decode and is NOT a complete storage DoS audit.

### Cache-pressure, eviction, re-acknowledgement, signer, and handoff results

Recovered-acknowledgement FIFO cache (small colocated fixtures): the entry limit
holds under pressure (never exceeds the bound; one oldest process-local eviction
per over-capacity insert, FIFO order); a hit returns the exact identical record
bound to its position; re-acknowledging a cached position updates in place with
no growth or peer eviction; revisiting an evicted position re-inserts (repeating
the barrier); zero capacity declines to cache. Eviction drops only process-local
state; durable records, accounting, and conflict obligations are untouched.
Signer/handoff suppression (no re-invocation of the signer, no fresh continuation
minted, no retained delivery on failed/uncertain acknowledgement, exact-only
reuse on success) is covered by the colocated D10 handler tests with direct
signer and handoff observations; opaque journal-result fixtures stay distinct
from cryptographically verified handler results.

### Initialization, uncertainty, and persistent-capacity matrix

Preserved and re-validated: failed initialization write yields no usable handle
and no signing; store-then-error initialization is not reported as a successful
acknowledgement; established-open is explicit and never silently reinitializes;
missing/corrupt/truncated/unsupported/inconsistent metadata fail closed;
duplicate initialization preserves state; opening another handle preserves an
outstanding operation and its identity. Uncertain reservation/accounting is
reconciled against the fixed limit and the prior/attempted counts, refusing
regressed/overrun/limit-changed durable counts; a surviving `Reserved` never
grants a reconstructed continuation; no failed outcome erases an obligation.
Capacity: both `Reserved` and `Signed` positions count; publication, exact retry,
and recovered acknowledgement do not increment usage; capacity is enforced
through another handle and a real-backend reopen; zero/unsupported limits behave
as documented. The backend atomic-write assumption is explicit; local checks are
NOT whole-copy rollback detection.

### Preservation of accepted D and remaining F limitations

The accepted `BoundSigningOperation` finalization and its four restored
regression tests remain collected and pass (`run422_d7d10::correction_d`, 36
tests). Correction F is NOT repaired here:
`d7d10_child_reserve_then_abort` is the ignored helper;
`reserved_only_child_death_then_reopen_refuses` is the active parent that still
uses an unbounded `.status()` and does not classify termination — a passing test
does not close F. Model reopen, real RocksDB reopen, child-process observations,
release compilation, and power-loss evidence are kept distinct.
**(Historical — superseded by the Correction F execution section below, which
repairs both the F-A engine-progress evidence and this F-B child runner.)**

### Validation (implementation+test checkpoint `fabb16c`, dev profile unless noted, exit 0)

* `cargo test -p qbind-node --lib signing_reservation_journal` — 50 passed.
* `cargo test -p qbind-node --lib correction_d` — 36 passed (four restored D regressions present and passing).
* `cargo test -p qbind-node --lib storage` — 61 passed.
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests` — 22 passed, 1 ignored (child helper).
* `cargo test -p qbind-node --features test-utils --test run_422_d7d10_signing_reservation_journal_tests` — 27 passed, 1 ignored (the +5 cases are the `test-utils`-gated unknown-version and raw-seam direct-read cases; the ignored helper and shared passing subset overlap both runs).
* `cargo test -p qbind-node --lib` — 1833 passed.
* `cargo test -p qbind-node --test run_420_production_policy_reachability_tests` — 3 passed.
* `cargo test -p qbind-node --test run_422_startup_refusal_tests` — 4 passed.
* `cargo check -p qbind-node` (binary-inclusive; required; the historical `--lib` check does not substitute) — exit 0.
* `cargo build --release -p qbind-node --bin qbind-node` — exit 0.
* D6 PV-domain isolation target — **correction**: the D6 target is
  `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests`. The
  earlier `cargo test -p qbind-node --test m10_signer_isolation_tests` (13 passed)
  is **remote-signer key-isolation** coverage and **cannot substitute** for the
  PV-domain isolation target; that line is withdrawn. The correct target was run in
  the Correction E execution pass below (`34 passed, 0 failed`).
* Focused Clippy `cargo clippy -p qbind-node --lib` — exit 0; no warnings in the changed files. The changed integration target reports only pre-existing style warnings. A whole-crate `--tests` clippy also compiles `m16_epoch_transition_hardening_tests`, which fails to build WITHOUT `--features test-utils` (pre-existing feature-gating of `set_inject_write_failure`/`clear_epoch_transition_marker`, unrelated to this change).

### Release executable identity (release compilation evidence only)

* Build-source SHA: `fabb16c5b5a0fae104d3e64a2cdd1b24868383ee`
* Path: `target/release/qbind-node`
* Profile / features: `release` / default (`--bin qbind-node`)
* Byte length: `17075336`
* SHA-256: `31ef90a69afc0608b38ca91ef585485168c775a31b2c82c854ba563625ee06df`

This is release compilation evidence only, not configured-authority runtime
evidence.

### Security-tool outcomes (literal)

Independent Code Review and CodeQL were attempted via the harness
`parallel_validation`, production storage changes declared non-trivial for
CodeQL. Literal outcomes: Code Review DID NOT run — the review tool was
unavailable in this environment (`autofind` binary not found), so the empty
result is NOT a clean review. CodeQL DID NOT complete — the `rust` analysis was
SKIPPED because the database size was too large, so the reported 0 alerts is NOT
a successful scan. Both remain unexecuted security obligations. Security posture
remains `RS1-OPEN / PUBLIC-DEVNET-NO-GO`.

### Documentation & EOL reconciliation

Updated the operative contract §9.3–§9.5 and appended superseding §9.6. CRLF docs
retain CRLF with no lone CR/LF; `storage.rs` remains LF; original EOF conventions
preserved. Synced writes implement a durability mechanism under stated storage
assumptions; the executed tests do not establish empirical power-loss behavior.
Journal initialization remains a LOCAL storage operation — not proof a validator
key has never signed and not authorization for production activation.

### Scoped disposition

`D7D10_JOURNAL_INITIALIZATION_AND_CAPACITY=CODE-AND-STORAGE-TEST-POSITIVE`
(explicit initialization/opening, namespace policy, direct-read and iterator
bounds, and persistent position accounting — demonstrated local code-and-storage
scope only; not configured-authority runtime evidence). Retained unchanged:
`D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL`,
`D7D10_MISSING_JOURNAL_SIGNING_REFUSAL=CODE-TEST-POSITIVE`,
`D7D10_POST_STORAGE_AUTHORIZATION_REVALIDATION=CODE-TEST-POSITIVE`,
`D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`,
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. **Still OPEN:** Correction F
(unbounded/unclassified child runner) and C4/C5. No authority activation,
readiness promotion, D11, or Run 423 work; no PR, branch rename, force-push,
rebase, or history rewrite; `task/warning.txt` and unrelated work preserved.

## Run 422 D7-D10 Correction E execution (A–D implemented, freshly validated)

This section records the **newly executed** Correction E work (corrections A–D
implemented as source/test + documentation edits and validated in this pass). It
does **not** relabel the historical figures above (attributed to their prior
report at the unavailable checkpoint `fabb16c…`) as newly executed; those remain
historical. The referenced ancestry objects `1c14369` and `fabb16c` were
unavailable in the shallow single-branch clone and no ancestry was manufactured.

**Baseline / checkpoint identity.** Continuation baseline branch
`copilot/copilotcopilotcopilotcopilotrun-422-complete-corre`, inspected HEAD
`c5ef2bb4990a6f0c753565155baa5d9cf9a0b2dd`. Implementation/test checkpoint
committed at `45542d8` (A/B source/test edits); this evidence record and the
documentation reconciliation (contract §9.3–§9.5 rewritten in place, m10
corrections) are committed in the following checkpoint on the same task branch.

**Scope.** Only the six authorized paths changed. `storage.rs` and the
integration test file `run_422_d7d10_signing_reservation_journal_tests.rs` were
**not** modified; storage-fixture tests therefore did not require a rerun.
Production semantics preserved: the only production-source change is
`SigningOwnershipDomain::new()` delegating to a private
`with_recovered_ack_cache_capacity(DEFAULT)`, with a `#[cfg(test)]`
`new_with_cache_capacity_for_test`; no new production configuration or bypass.

**Correction A (post-eviction journal + handler evidence).** Container-test
comments that claimed storage barriers were removed/softened. New full-flow
journal tests create published `Signed` records, reopen through a fresh ownership
domain, populate the acknowledgement cache through actual journal lookups, force
FIFO eviction via further recovered acknowledgements, revisit the evicted position
and directly observe the additional synced write, show an exact cache hit avoids
that write, show failed and store-then-error acknowledgement produce no successful
retained reuse / usable cache acknowledgement, show later success permits the
exact retained signature, and assert persistent counts/limits/record bytes/
conflict obligations are preserved. A small test-only cache capacity is reached
through private `#[cfg(test)]` access only. The guarded-handler recovery fixture
is extended with the post-eviction failure → uncertainty → success sequence,
directly asserting zero additional signer calls and zero handoffs on
failure/uncertainty and byte-identical D6-verified retained delivery on success.

**Correction B (store-then-error initialization).** Using the existing fault
injector, initialization metadata is made readable while its write returns an
error; the test asserts `initialize` returns an error with no usable handle,
surviving metadata is inspected directly, repeated initialization cannot silently
reset/overwrite (`AlreadyInitialized`), and a subsequent explicit `open` succeeds
over the surviving well-formed consistent metadata (outcome recorded as
implemented; metadata absence is not required; readable bytes are not equated with
a successful initialization acknowledgement). Clean-init, pre-write-failure,
duplicate-init, malformed-metadata, and capacity controls are retained.

**Corrections C/D (docs + D6 target).** The real D6 target was executed:
`cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` ⇒
**34 passed, 0 failed**. The documents were corrected: `m10_signer_isolation_tests`
is remote-signer coverage and does not substitute for this target (fixed in the
operative contract and in this devnet record). Operative contract §9.3–§9.5 were
rewritten **in place** to describe the implemented `initialize`/`open` APIs, the
persisted journal-wide limit/count, the shared ownership domain, and the bounded
recovery-acknowledgement cache; obsolete "attach / per-handle limit /
process-local-only accounting / OPEN under E" instructions were removed and the
superseded wording marked explicitly historical. `docs/whitepaper/contradiction.md`
was inspected read-only (outside write scope): its C4 (production `qbind-node`
binary does not boot a fully operating node) and C5 (`TimeoutCertificate` transport
PKI) remain OPEN and concern the production binary / transport, not the signing
journal — no operative contradiction with this test/documentation work, and this
work resolves none of those entries.

**Executed validation (exact commands, observed counts, real exit statuses).**

* `cargo test -p qbind-node --lib signing_reservation_journal` — **53 passed**, 0 failed (+3 over the historical 50: the two post-eviction full-flow tests and the store-then-error init test).
* `cargo test -p qbind-node --lib run422_d7d10` — **62 passed**, 0 failed (includes the extended post-eviction guarded-handler test).
* `cargo test -p qbind-node --lib correction_d` — **36 passed**, 0 failed (the four restored D regressions remain collected and pass).
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests` — **22 passed, 1 ignored**, 0 failed (default features).
* `cargo test -p qbind-node --features test-utils --test run_422_d7d10_signing_reservation_journal_tests` — **27 passed, 1 ignored**, 0 failed.
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` — **34 passed**, 0 failed (correct D6 target).
* `cargo test -p qbind-node --lib` — **1837 passed**, 0 failed (+4 over the historical 1833).
* `cargo check -p qbind-node` (binary-inclusive) — **exit 0**.
* `cargo clippy -p qbind-node --lib` — **exit 0**; the reported warnings are pre-existing style lints (e.g. `type_complexity`, `contains_key`-then-`insert`, doc-list indentation, `unnecessary_sort_by` in `vm_v0_runtime.rs`), none introduced by the test additions or the small `new()` delegation.
* EOL/whitespace checks on the three changed `.rs`/`.md` files in scope — all lines CRLF, zero trailing-whitespace lines, original no-trailing-newline EOF preserved; `storage.rs` remains LF; `task/warning.txt` untouched.

**Test → requirement mapping.**

* Correction A (journal) ⇒ `post_eviction_recovery_reissues_synced_write_then_cache_hit_avoids_it`, `post_eviction_failed_and_uncertain_recovery_refuse_reuse_then_success_permits_exact_signature`, plus the retained/reworded container cache tests.
* Correction A (handler) ⇒ `run422_d7d10::…::d10_post_eviction_recovery_failure_uncertainty_success_through_handler`.
* Correction B ⇒ `store_then_error_initialization_refuses_handle_but_leaves_readable_consistent_metadata`.
* Corrections C/D ⇒ D6 target execution (34 passed) + contract §9.3–§9.5 in-place rewrite + m10 corrections here and in the contract.

**Release artifact.** No new release build was performed; the historical release
compilation artifact (build-source SHA `fabb16c…`) is retained at its actual
revision as historical evidence only, not re-attested here.

**Security-tool outcomes (literal — prior-pass outcomes).** Code Review and CodeQL
were attempted once via the harness `parallel_validation` in the preceding pass
(production-source change declared non-trivial for CodeQL). The literal outcomes
already reported for that pass, labelled here as prior-pass outcomes (no fresh tool
execution is claimed and no verbatim output beyond what was retained is invented):

* **Code Review DID NOT run** — the reviewer was unavailable: the `autofind` tool
  failed with a model-registry error (`model claude-sonnet-4.6 not found in
  registry`). "No review comments" is therefore NOT a clean review.
* **CodeQL DID NOT complete** — the `rust` analysis was SKIPPED because the
  database size was too large, so the reported "0 alerts" is NOT a successful scan.

Both remain unexecuted security obligations; neither constitutes a passed security
analysis. Security posture remains `RS1-OPEN / PUBLIC-DEVNET-NO-GO`.

**Scoped verdict (unchanged).** Overall D10 remains **PARTIAL**; Correction F and
C4/C5 remain **OPEN**. Genesis authority activation DISABLED, durable anti-rollback
NOT-ESTABLISHED, production lifecycle UNAVAILABLE, configured-authority runtime
evidence NOT-CAPTURED, `PUBLIC-DEVNET-NO-GO`. No F implementation, D11, Run 423,
production signing enablement, or architectural redesign; no PR, main change,
rename, force-push, rebase, or history rewrite.

### Correction E follow-up — post-uncertainty failed-retry assertions strengthened

This test/documentation-only follow-up closes the two remaining review findings on
top of the Correction E execution above. Starting/tested checkpoint
`05b4eca654798d62e804505a3b97388d838385f7` (reported branch
`copilot/copilotrun-422-complete-corre`); the referenced ancestry objects
remained unavailable in the shallow single-branch clone and source correspondence
was inspected directly (reported separately, no ancestry manufactured).

**Strengthened tests (existing tests extended only; no new production scope).**

* `signing_reservation_journal.rs::tests::post_eviction_failed_and_uncertain_recovery_refuse_reuse_then_success_permits_exact_signature` — immediately after the store-then-error recovery attempt, store-then-error is disabled while ordinary writes keep failing, and the SAME evicted position is retried through the actual journal: another `JournalError::Storage`, no retained reuse, and — via the existing `record_writes` counter — no successful synced write and thus no usable cache acknowledgement (cache length unchanged); the exact retained record and its conflict obligation (a conflicting binding still refused without rewrite) are preserved. Permitting the next write and retrying then issues exactly one additional synced recovery write (`record_writes + 1`) and reuses ONLY the exact retained signature. The exact-cache-hit control (an acknowledged cached result served with no further write even when writes are configured to fail) is preserved.
* `binary_consensus_loop.rs::…::run422_d7d10::d10_post_eviction_recovery_failure_uncertainty_success_through_handler` — the same sequence through the actual guarded handler: after the uncertain attempt, store-then-error is disabled with the write budget held at 0 and the evicted view is retried: another `outbound_proposal_journal_error_total`, no delivery or facade handoff, no additional signer call (signer count frozen at 3), unchanged cache length, preserved record, and a preserved conflict obligation (a conflicting payload refused with `outbound_proposal_journal_conflict_total`, no delivery, no signature, no rewrite). Permitting the write then proves exactly one additional synced recovery write via a minimal test-only `write_budget_remaining()` observation (budget decremented by one), delivers the exact retained signature with no additional signer call, and retains the D6 `verify_proposal_msg_with_domain` check and signature-byte equality; an exact-cache-hit control (budget held at 0, served with no write) closes the test.

The only non-test addition is the test-module accessor `D10Store::write_budget_remaining()` (read-only observation of the existing injected budget); no production instrumentation or configuration was introduced.

**Focused validation (freshly executed this follow-up; real exit statuses).**

* `cargo test -p qbind-node --lib signing_reservation_journal` — **53 passed, 0 failed** (exit 0).
* `cargo test -p qbind-node --lib run422_d7d10` — **62 passed, 0 failed** (exit 0).
* Changed-region whitespace / file-specific line endings — both changed `.rs` files remain fully CRLF with zero trailing-whitespace lines and their original no-trailing-newline EOF; `storage.rs` untouched (LF); `task/warning.txt` preserved.
* Tested checkpoint for these counts: `52885e9897a681c6fd1a914d6cea3ea427dadeb7` (the strengthened-tests commit). No full-suite rerun or release rebuild was performed for this test/documentation-only follow-up; the earlier validation is retained at its actual checkpoint. Documentation reconciliation (contract status tokens and this record) is committed in the following checkpoint on the same task branch.

**Documentation reconciliation.** The operative contract status tokens no longer
say "E and F remain OPEN" alongside the completed-E statement: `…POST_STORAGE…`
and `D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL` now read "E is complete for its
demonstrated local scope (see §9.6); F remains OPEN," a new
`D7D10_CORRECTION_E_NAMESPACE_CAPACITY_CACHE=CODE-AND-STORAGE-TEST-POSITIVE` token
records E's scoped positive disposition, and overall
`D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL`, Correction F OPEN, and C4/C5 OPEN are
kept. Historical "Still OPEN: Correction E" section verdicts in this devnet record
are retained and explicitly marked superseded/historical rather than rewritten.

**Security-tool attribution (prior pass).** No fresh tool run was performed in this
follow-up. The literal prior-pass outcomes are recorded above: Code Review DID NOT
run (reviewer unavailable; `autofind` `claude-sonnet-4.6` model-registry error) and
CodeQL DID NOT complete (analysis skipped, database too large; "0 alerts" was not a
successful scan). Both remain unexecuted obligations.

**Scoped E verdict.** `D7D10_CORRECTION_E_NAMESPACE_CAPACITY_CACHE=CODE-AND-STORAGE-TEST-POSITIVE`
(demonstrated local code-and-storage scope only; not configured-authority runtime
evidence; no readiness promotion). Overall D10 remains **PARTIAL**; Correction F and
C4/C5 remain **OPEN**; activation DISABLED, anti-rollback NOT-ESTABLISHED,
production lifecycle UNAVAILABLE, `PUBLIC-DEVNET-NO-GO`.

## Run 422 D7-D10 — Correction F execution: real engine progress and bounded/classified child recovery

Test/documentation-only. Reported branch `copilot/copilotcopilotrun-422-corrections`;
HEAD at start `bdaaf9b…` on a **shallow single-branch clone** (`.git/shallow` =
`c5ef2bb…`): the accepted baseline `c7098cb85c4705aef885a9098acc03d8c856ce72` and
other ancestry objects are **UNAVAILABLE** here, so source correspondence was
inspected directly and no ancestry was manufactured. `task/warning.txt` and unrelated
files preserved. Authorized files only: `crates/qbind-node/src/binary_consensus_loop.rs`
(test code/fixtures only), `crates/qbind-node/tests/run_422_d7d10_signing_reservation_journal_tests.rs`,
and these two docs. Production behavior unchanged.

### Correction F-A — actual engine progress (supersedes synthetic evidence)

The prior lib test `d10_reserves_action_view_not_a_later_view` (synthetic actions +
second journal handle; **not** engine progress) is replaced by
`binary_consensus_loop::tests::run420::run422_d7a::run422_d7b::run422_d7d10::correction_f_engine`
(3 tests). Boundary demonstrated: **real engine → returned action → guarded
signer/journal → facade.**

* Engine view **before = V (0)**, **after `on_leader_step` = V+1 (1)**: a
  single-validator `BasicHotStuffEngine` self-votes, forms a QC, and `advance_view()`s
  to V+1 **before** the returned actions are forwarded.
* Returned originating-action fields: Proposal `height/round = V`; self-Vote
  `height/round = V`, `step = 0` — originating view V, **not** the engine's newer view.
* Guarded forward through the existing Required-policy path: **signer calls = 1**
  (one Proposal entry + one Vote), **facade handoffs = 1** Proposal broadcast + 1 Vote;
  delivered signatures D6-verified (`verify_proposal_msg_with_domain` /
  `verify_vote_msg_with_domain`). Journal positions: Proposal and Vote at their distinct
  kind-specific positions **at V** (direct `get_signing_record(position.storage_key())`
  inspection), never at V+1. Emitted fields unchanged except the permitted suite
  assignment + signature population.
* Conflict preservation: a **deliberately labelled** conflicting variant at the SAME
  originating position (changed message binding only) → journal `Conflict`, **no**
  additional signer call, **no** handoff, original record **byte-identical**.
* Positive controls: exact permitted retry reuses the retained signature with **no**
  new signer call; a second `on_leader_step` at V+1 emits a NEW-originating-view action
  occupying a **distinct** legitimate position without disturbing the V obligation.
* No progress simulated by variable assignment, a second handle, a rewritten view, or a
  restart initializer; engine-current-view equality is NOT a new signing prerequisite;
  cached-reemission eligibility rules preserved.

### Correction F-B — bounded, classified child-process recovery

`reserved_only_child_death_then_reopen_refuses` is rewritten as a `#[cfg(unix)]`
deadline-bounded, termination-classified runner (capture + bounded process-status-wait
+ pure classification adapted **minimally** from the D3 runner; the whole D3 target is
**not** duplicated). Boundary demonstrated: **integration-test child executable → real
RocksDB reservation → classified SIGABRT process death → fresh reopen.**

* Re-executed artifact (the **test executable**, NOT the production node binary):
  * Path: `target/debug/deps/run_422_d7d10_signing_reservation_journal_tests-278b729b96e64c0e`
  * Profile: `dev`/debug (unoptimized + debuginfo); default features
  * Byte length: `306103912`
  * SHA-256: `84a4a38177b849dd5e145a6ba300f9e5362508277c51bd2c3a4788747d54adea`
  * (The filename hash and SHA-256 are build-dependent and change on any rebuild.)
* Child-helper selection via **per-`Command`** env (`QBIND_D7D10_CHILD_DB`); no
  process-global `set_var`. Readiness marker
  `D7D10-CHILD: reserved-durable-ack-before-abort` is emitted+flushed to stderr **only
  after** the real RocksDB reservation returns `FreshlyReserved`, immediately before the
  intentional `std::process::abort()` (before any signer invocation or result
  publication).
* Deadline/cleanup controls: internal 120 s deadline with repeated `try_wait`
  process-status polling (no fixed sleep guessing exit, no outer tool timeout as the
  deadline); FULL `ExitStatus` preserved; drain threads joined (bounded output handling);
  spawn/status/capture/cleanup errors handled explicitly; a deadline is a **failure**
  with explicit kill+reap (never reinterpreted as crash evidence).
* Termination classification: **accepted only** when signal == SIGABRT (6) **and** the
  readiness marker was captured completely. Observed on this Linux profile:
  `AbortedAfterMarker { signal: 6 }`.
* Real-storage reopen after reap: fresh RocksDB handle + ownership domain; the valid
  `Reserved` record is present at the exact position/binding; **exact retry →
  `PotentiallySigned`** (never a fresh continuation or signed result); **conflicting
  binding → `Conflict`**; raw record bytes (`get_signing_record`) and persistent
  accounting (`get_signing_metadata`) **unchanged** across refusals.
* Runner controls (same classification path; single-process `sh` children):
  marker+SIGABRT **accepted**; marker+normal-nonzero-exit (`exit 7`) **rejected**
  (`NormalExit`); marker+unexpected signal (SIGTERM 15) **rejected** (`UnexpectedSignal`);
  SIGABRT **without** marker **rejected** (`SignalButMarkerUnusable`); alive-past-deadline
  (`exec sleep 30`, 2 s deadline) → **Timeout + reaped**, returning within a 20 s outer
  bound (cleanup does not wait on the surviving process); plus a pure constructed-
  `ExitStatus::from_raw` decision table.
* Platform honesty: signal classification uses `ExitStatusExt::signal()` and the
  POSIX-fixed SIGABRT value, so the parent + controls are `#[cfg(unix)]`; supported
  profile Unix/Linux. This establishes crash-consistency of the LOCAL journal across real
  process death — **not** empirical power-loss / whole-copy rollback resistance (no
  DB-wide monotonic anchor established); process-death recovery and power-loss/rollback
  resistance are kept distinct.

> **Superseded in part by “Correction F-B — repair: bound output draining and verify
> child cleanup” (below).** Two operative claims in the bullets above are corrected
> there: “drain threads joined (bounded output handling)” overstated boundedness —
> joining a thread is **not** itself a deadline, so a descendant that inherited the pipe
> after the direct child exited could block the join indefinitely; and “Timeout +
> reaped” did not directly establish reaping, because the prior cleanup discarded a
> failed `wait()` (leaving `reaped=false`) yet still reported `Timeout`. The repair makes
> draining deadline-aware, bounds reaping with `try_wait` polling, and returns a
> structured, asserted `CleanupResult`. The F-A engine-progress evidence and all other
> F-B claims above are unchanged. The per-command figures below are retained at their
> prior checkpoint and are **not** relabelled as newly executed.

### Validation (implementation+test checkpoint on this task branch; dev profile unless noted, exit 0)

Overlapping subsets reported separately (not summed):

* `cargo test -p qbind-node --lib correction_f_engine` — **3 passed, 0 failed** (focused F-A engine-progress).
* `cargo test -p qbind-node --lib run422_d7d10` — **64 passed, 0 failed**.
* `cargo test -p qbind-node --lib correction_d` — **36 passed, 0 failed**.
* `cargo test -p qbind-node --lib signing_reservation_journal` — **53 passed, 0 failed**.
* Outbound/cached-reemission regression subset: `--lib outbound` **25 passed**, `--lib reemit` **3 passed**, `--lib cached_reemission` **3 passed**, 0 failed.
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests` (default features) — **29 passed, 0 failed** (with `--include-ignored`; the child helper runs as a no-op when invoked directly and is re-executed by the active parent).
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests --features test-utils` — **33 passed, 1 ignored, 0 failed** (the +4/ignored-helper difference is the `test-utils`-gated cases and the directly-ignored child helper).
* `cargo test -p qbind-consensus --test run_422_d6_pv_domain_isolation_tests` — **34 passed, 0 failed**.
* `cargo test -p qbind-node --lib` (full, after fixture changes) — **1839 passed, 0 failed**.
* `cargo check -p qbind-node --bins --lib` (binary-inclusive) — exit 0. (`--all-targets` additionally pulls in `m16_epoch_transition_hardening_tests`, which fails to build **without** `--features test-utils` — a pre-existing feature-gating limitation on `set_inject_write_failure`/`clear_epoch_transition_marker`, unrelated to this change; it builds with `--features test-utils`.)
* Focused Clippy `cargo clippy -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests` — exit 0, **no warnings in the changed file** (one `unnecessary_to_owned` suggestion was fixed; remaining warnings are pre-existing in dependency crates).
* Changed-region whitespace / line endings: both changed `.rs` files and both docs remain **CRLF** with their original no-trailing-newline EOF and no space-before-CR trailing whitespace; `task/warning.txt` preserved.

### Security-tool outcomes (literal)

Attempted once via the harness `parallel_validation` with the CodeQL change declared
non-trivial. **Code Review DID NOT run** — the review tool was unavailable in this
environment (the `autofind` binary was not found on any searched path), so "No review
comments found" is **NOT** a clean review. **CodeQL DID NOT complete** — the `rust`
analysis was **SKIPPED because the database size is too large** (the reported "0 alerts"
is therefore **NOT** a successful scan). Neither constitutes a passed security analysis;
both remain unexecuted obligations. Security posture remains RS1-OPEN /
PUBLIC-DEVNET-NO-GO.

### Documentation reconciliation and scoped F disposition

The operative contract statements that described synthetic/fresh-handle "engine
progress" and the active parent's unbounded `.status()` + generic unsuccessful-exit
acceptance are updated: the synthetic/unbounded descriptions are explicitly marked
**historical/superseded**, and the new boundaries (real engine → returned action →
guarded signer/journal → facade; integration-test child executable → real RocksDB
reservation → classified SIGABRT death → fresh reopen; model fixtures vs real storage;
test-executable evidence vs production runtime evidence) are recorded here and in
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`. Earlier
per-command/release figures are retained at their actual historical checkpoints and not
relabelled. `contradiction.md` was inspected read-only (outside this task's write scope);
no new operative contradiction is introduced by this test/documentation-only change.

Scoped verdict (both obligations demonstrated for their code-and-process-test scope):

```
D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE
```

Retained posture (unchanged): overall `D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL` pending
the subsequent aggregate D10 review (closing F does not itself promote readiness);
accepted A/B/C/D/E and D7–D8 scoped verdicts preserved; production lifecycle UNAVAILABLE;
durable anti-rollback NOT-ESTABLISHED; genesis authority activation DISABLED; production
wire-chain behavior unchanged; configured-authority release/runtime evidence
NOT-YET-CAPTURED; `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`; C4/C5 OPEN.

## Run 422 D7-D10 — Correction F-B — repair: bound output draining and verify child cleanup

Test/documentation-only follow-up to the Correction F execution above. It repairs the
two material gaps in the F-B runner (output draining and cleanup were not bounded by the
process-status deadline; cleanup errors were discarded so `Timeout` could claim "killed
and reaped" without establishing reaping). **Only** the existing integration target
`crates/qbind-node/tests/run_422_d7d10_signing_reservation_journal_tests.rs` and these two
docs were changed. No production source, dependency, feature, storage API, journal
semantic, or shared process framework changed. The accepted **F-A engine-progress tests
are unchanged**.

**Checkpoint identity.** Reported branch `copilot/copilotcopilotcopilotrun-422-corrections`
on a **shallow single-branch clone** (`.git/shallow`); the reviewed revision
`3e1b5244771787f47405194d0e2906c45bb0809f` and other ancestry objects are **UNAVAILABLE**
here (`git cat-file` fails), so the current implementation was inspected directly and no
ancestry was manufactured. Starting HEAD for this pass: `c69491d`. Worktree was clean;
`task/warning.txt` and unrelated files preserved. Code/test checkpoint committed before
recording these validation results.

### Deadline policy (how every blocking boundary is bounded)

The process-status wait (`wait_self_termination`) bounds waiting for the child to die on
its own via repeated `try_wait` polling under an internal deadline. Two **separate finite
budgets** then bound the work that follows it, so no blocking boundary is unbounded:

* **Draining** is deadline-aware. Each stream fd is set non-blocking (`fcntl`
  `O_NONBLOCK`); the drain loop polls and, on `WouldBlock`, honours a shared armed stop
  deadline (`DrainDeadline`). `finalize_drains(CAPTURE_FINALIZE_BUDGET = 5 s)` **arms**
  that deadline and then joins the drain threads — the join completes because the thread
  self-terminates at the armed stop, **not** because joining is itself a deadline. A
  drain thread that only sees `WouldBlock` (a descendant inherited the pipe after the
  direct child exited) stops at the deadline and is joined; that stream's capture becomes
  the explicit unusable outcome `CaptureOutcome::DeadlineExceeded`. The 256 KiB capture
  cap bounds **memory**, independently of this time budget. A drain thread is never
  silently abandoned; joining an already-finished thread is the only join performed.
* **Reaping** is bounded by `try_wait` polling within `REAP_BUDGET = 5 s` (never a
  blocking `Child::wait()` on a potentially live child).

Overall wall-clock bound for one runner call ≈ status deadline + `REAP_BUDGET` (timeout
path only) + `CAPTURE_FINALIZE_BUDGET`. **OS-assumption honesty:** these are hard budgets
on a cooperating Unix kernel, **not** a proof the kernel always completes termination —
inability to verify reaping within the budget is surfaced as an explicit cleanup failure,
never a success. `Drop` stays best-effort/non-panicking and reuses the same bounded
cleanup, reintroducing no unconditional blocking after the explicit deadline path returns.

### Cleanup result model and direct reaping observations

Cleanup is a pure, inspectable driver (`drive_cleanup`) over a `ChildCleanup` seam
(`request_termination`, non-blocking `poll_reaped`). `reaped` is set **only** on an
`Ok(true)` observation that establishes reaping. The structured `CleanupResult` is:

* `AlreadyReaped` — the child had already exited and been reaped.
* `KilledAndReaped` — termination requested **and** reaping verified by an observed
  status (covers the exit-vs-kill race: a kill error whose child is then observed reaped
  is still *verified* reaping, never a silent success).
* `TerminationRequestFailed { detail }` — the kill request failed and reaping was not
  verified within the budget.
* `ReapObservationFailed { detail }` — a status/reap observation errored.
* `DeadlineExpired` — the cleanup budget expired without verified reaping.

`SelfTermination::Timeout` now carries this concrete `CleanupResult` **and** the capture
outcome; it is never implicitly "killed and reaped". The child helper
`d7d10_child_reserve_then_abort` now **fails** (panics/non-SIGABRT exit) if the readiness
marker write or flush errors, instead of discarding those results.

### Focused controls (real processes vs injected seam)

Real-process controls on the SAME classification path:

* marker+SIGABRT **accepted** (`AbortedAfterMarker`); marker+normal-nonzero-exit (`exit
  7`) **rejected** (`NormalExit`); marker+unexpected signal (SIGTERM 15) **rejected**
  (`UnexpectedSignal`); SIGABRT-without-marker **rejected** (`SignalButMarkerUnusable`).
* `runner_control_alive_past_deadline_times_out_and_is_reaped` (`exec sleep 30`, 2 s
  deadline) now **asserts** `CleanupResult::KilledAndReaped` and a bounded capture
  (`Complete`/`Truncated`), returning within a 20 s outer bound (elapsed time is
  corroboration only).
* **NEW** `runner_capture_incomplete_after_direct_child_exit_is_unusable`: a backgrounded
  `sleep 45` keeps the pipes open past the direct `sh` child's marker-then-SIGABRT (new
  process group). The runner returns within its capture budget (< 20 s outer bound),
  classifies the capture `DeadlineExceeded`, and **refuses** the incomplete capture
  (`SignalButMarkerUnusable`) despite the SIGABRT and the marker bytes having arrived; the
  descendant's process group is then SIGKILL'd so nothing is leaked.

Injected-seam control (no real process, labelled separately):

* **NEW** `drive_cleanup_classifies_failures_without_false_reaping`: scripted
  kill/observe/expiry results deterministically reach `AlreadyReaped`, `KilledAndReaped`
  (incl. the kill-error exit-race), `TerminationRequestFailed`, `ReapObservationFailed`,
  and `DeadlineExpired` — with **no** false `reaped=true` and **no** accepted crash.

Plus the retained pure constructed-`ExitStatus::from_raw` decision table.

### Real child-recovery outcome (unchanged journal/accounting)

`reserved_only_child_death_then_reopen_refuses` runs through the corrected runner:
observed `AbortedAfterMarker { signal: 6 }`; fresh RocksDB handle + ownership domain on
reopen; valid `Reserved` record present at the exact position/binding; **exact retry →
`PotentiallySigned`**; **conflicting binding → `Conflict`**; raw `get_signing_record`
bytes and `get_signing_metadata` **byte-identical** across the refusals. Unchanged from
the accepted F-B record/refusal assertions.

### Validation (code+test checkpoint on this task branch; dev profile, default features unless noted; exit 0)

Overlapping subsets reported separately (not summed). The one ignored integration test is
the child helper, which runs as a harmless no-op when invoked directly (its recovery
meaning exists only when the active parent re-executes it with `QBIND_D7D10_CHILD_DB`
set); direct invocation is **not** an additional recovery scenario.

* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests -- --include-ignored`
  (default features) — **31 passed, 0 failed, 0 ignored** (29 prior + 2 new focused
  controls; the child helper runs as a no-op).
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests --features test-utils -- --include-ignored`
  — **36 passed, 0 failed, 0 ignored**.
* Focused controls + real child-recovery parent, run directly on the built executable
  (`runner_* reserved_only_child_death drive_cleanup classify_child_crash`) — **9 passed,
  0 failed**.
* `cargo test -p qbind-node --lib run422_d7d10` — **64 passed, 0 failed** (accepted
  handler/engine coverage preserved).
* `cargo test -p qbind-node --lib correction_f_engine` — **3 passed, 0 failed** (accepted
  F-A engine-progress, unchanged).
* `cargo check -p qbind-node --bins --lib` — exit 0.
* Focused Clippy `cargo clippy -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests`
  — **no warnings in the changed file** (one `doc_lazy_continuation` suggestion was
  fixed; remaining warnings are pre-existing in the `qbind-node` lib, unrelated to this
  change).
* Changed-region hygiene: the changed `.rs` file and both docs remain **CRLF** with their
  original no-trailing-newline EOF and no space-before-CR trailing whitespace; the diff is
  confined to the F-B runner module, the child helper marker write, the control/new tests,
  and the module doc; `task/warning.txt` preserved.

### Re-executed integration-test artifact identity

* Tested source checkpoint: `a8c26884845cf6784bb1c8b175c492fafabd655f` (code/test commit;
  these doc edits are committed in the following checkpoint on the same branch and do not
  alter the executable or tests validated at the checkpoint).
* Executable path: `target/debug/deps/run_422_d7d10_signing_reservation_journal_tests-278b729b96e64c0e`
  (the **test executable**, NOT the production node binary).
* Build profile/features: `dev`/debug (unoptimized + debuginfo); default features.
* Byte length: **306280248**.
* SHA-256: `b91ed5e118e9c6528ec87a97b83564a45b413a2cd9987684dbf9c8c63592bee7`.
* (The filename hash and SHA-256 are build-dependent and change on any rebuild; no new
  production-node release build is required for this test-only correction.)

### Security-tool outcomes (literal)

Attempted once via the harness `parallel_validation`. The CodeQL change was declared
**trivial** (test-only + documentation-only changes, matching the CodeQL trivial
categories), and the literal outcomes were:

* **Code Review — DID NOT complete a real review.** The result line read "No review
  comments found", but the accompanying note reported the review tool was **unavailable**
  in this environment (`autofind` `command_failed`: model `claude-sonnet-4.6` "not found
  in registry"). "No review comments found" is therefore **NOT** a clean review.
* **CodeQL — Skipped (not executed).** Reported "Skipped: all changes are trivial" under
  the trivial declaration for this test-only + documentation-only change; no scan ran, so
  there is no "0 alerts" result to claim.

Neither constitutes a completed security analysis. Per the task, unavailable/skipped
tooling was attempted once and recorded literally (not re-run repeatedly, and no
infrastructure was changed). Security posture remains `RS1-OPEN / PUBLIC-DEVNET-NO-GO`;
this test/documentation-only change does not alter it.

### Documentation reconciliation and scoped verdict

The contract (`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`,
F-B paragraph) and the prior F execution bullets above are reconciled: the claims that
joining drain threads makes draining time-bounded, that the timeout outcome necessarily
proves reaping, and that cleanup errors were "handled explicitly" when they were
discarded, are superseded; the new deadline policy, observable `CleanupResult` outcomes,
and the real-vs-seam control distinction are documented. Prior per-command/release figures
remain at their actual historical checkpoints and are not relabelled as newly executed.
`contradiction.md` was inspected **read-only**; no new operative contradiction is
introduced by this test/documentation-only change, and no C4/C5 closure is claimed.

With the repaired F-B requirements demonstrated (deadline-bounded draining + cleanup, and
verified reaping without false success), the scoped verdict is reaffirmed:

```
D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE
```

Retained posture (unchanged): overall `D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL`;
`D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`;
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`; `GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`; C4/C5 OPEN; all accepted A–E scoped
verdicts preserved. No aggregate D10 promotion, D11, Run 423, production journal
initialization, signing enablement, activation, or anti-rollback implementation is
performed here.

## Run 422 D7-D10 — Correction F-B — finalization: unconditional drain deadline and verified control cleanup

Test/documentation-only follow-up to the Correction F-B repair above. It repairs the two
residual F-B findings and **supersedes** the two earlier claims that a `WouldBlock`-only
check bounded all draining and that the discarded process-group kill of a backgrounded
orphan established descendant cleanup. **Only** the existing integration target
`crates/qbind-node/tests/run_422_d7d10_signing_reservation_journal_tests.rs` and these two
docs were changed. No production source, dependency, feature, storage API, journal
semantic, or shared process framework changed. The accepted **F-A engine-progress tests
are unchanged**, and the real child reserve–abort–reopen (E) evidence is preserved.

**Checkpoint identity.** Actual branch
`copilot/copilotcopilotcopilotcopilotrun-422-corrections` on a **shallow single-branch
clone** (`.git/shallow`); the reviewed revisions `2c067a950660583006f13245a26d2fac7734aeb7`
and `a8c26884845cf6784bb1c8b175c492fafabd655f` are **UNAVAILABLE** here (`git cat-file`
fails), so the current implementation was inspected directly and no ancestry was
manufactured. Starting HEAD for this pass: `fdae083`. Worktree was clean; `task/warning.txt`
and unrelated files preserved. Code/test checkpoint committed as
`06c6423e577f9235ea772e2e59267dbe693ee3e6` **before** recording these validation results;
these doc edits are committed in the following checkpoint on the same branch and do not
alter the executable or tests validated at the code/test checkpoint.

### Correction A — the armed drain deadline is enforced on EVERY iteration

`run_drain` now checks the armed stop deadline at the **top of the loop**, BEFORE the next
`read` and regardless of the previous read's outcome. Expiry is therefore independent of
`read()`:

* continuous successful reads (`Ok(n)`) cannot postpone or reset it;
* repeated `Interrupted` retries cannot bypass it (the `Interrupted => continue` arm returns
  to the top-of-loop expiry check);
* output that keeps arriving after the 256 KiB capture cap is reached still stops at the
  deadline — the cap drops bytes, it does not end the loop.

The capture cap bounds **memory only** and is explicitly not a timing mechanism; the armed
deadline is the sole timing bound and makes the drain worker return (and be joined) WITHOUT
relying on EOF or an eventual `WouldBlock`. Pipe reads stay non-blocking; both stdout and
stderr follow this bounded drain. The five capture outcomes remain distinct, and deadline
termination remains the explicit **unusable** `CaptureOutcome::DeadlineExceeded`. Normal
EOF, marker classification, and the existing process/reap budgets are preserved; abort
acceptance was not weakened.

### Deterministic reader-seam controls (A/B) — no real process

Two controls drive the **actual** `run_drain` loop with synthetic `Read` fixtures (a real
`/dev/null` fd only satisfies `set_nonblocking`; the synthetic `read()` drives the logic):

* `drain_deadline_enforced_across_continuous_successful_reads` — a reader that supplies
  successful reads continuously arms an already-expired deadline after a few reads; the loop
  stops with `DeadlineReached` at the next iteration (`calls == arm_at`).
* `drain_deadline_enforced_across_repeated_interrupted_reads` — a reader that returns
  `Interrupted` continuously, arming expiry after a few retries; the loop stops with
  `DeadlineReached` (`calls == arm_at`).

Each fixture is bounded INDEPENDENTLY of the runner deadline by its own `fixture_cap`
(10 000): on the reviewed (regressed) implementation — top-of-loop check removed —
both controls **fail** on a different terminal (fixture EOF) rather than hanging. This was
verified directly: reverting only the top-of-loop check made both controls FAIL (bounded,
`finished in 0.01s`), and restoring it made them pass.

### Correction B — test-owned, verified pipe-holder cleanup (idle, active, and unwind)

The held-pipe control no longer backgrounds a descendant orphaned to init and no longer
discards a process-group kill. `BoundedChild::spawn_with_pipe_holder` builds the TEST's own
stdout+stderr pipes, wires cloned write ends to BOTH the direct child and a separately
spawned **holder process the test owns**, and hands the read ends to the existing drain
threads — so the captured stream stays open after the direct child exits. The holder's
cleanup guard (`OwnedHolder`) is installed **immediately** on creation, before any fallible
observation: its `Drop` performs a best-effort, non-panicking, bounded kill+reap, and the
normal path additionally calls `OwnedHolder::verify_cleanup`, which reuses the pure
`drive_cleanup` driver and returns the structured `CleanupResult`. The kill error is never
discarded and `reaped` is set only on an observed status, so a cleanup failure is reported,
not assumed. No process group, subreaper, or process-global signal handler is used, so
parallel tests are unaffected. The direct child's observed abort is kept distinct from the
independently owned holder.

Real-process controls (runner-resource evidence, NOT journal recovery):

* `runner_idle_held_pipe_after_direct_child_exit_is_unusable_and_holder_reaped` — an **idle**
  owned holder (`exec sleep 45`) holds the shared pipe open with no output; the direct child
  emits the marker and SIGABRTs. The runner returns within its capture policy (< 20 s outer
  bound), the capture is `DeadlineExceeded` (the drain stops via the `WouldBlock` poll path
  at the armed deadline), the marker-present-but-incomplete capture is refused
  (`SignalButMarkerUnusable`, never `AbortedAfterMarker`), and the holder is explicitly
  `KilledAndReaped` on the normal path.
* `runner_active_output_after_direct_child_exit_is_unusable_and_writer_reaped` — an **active**
  owned writer (a POSIX `while :; do printf 'yyyy\n' 1>&2; done` loop, no external binary)
  keeps writing to the shared stderr pipe after the direct child exits, exercising the
  every-iteration deadline under **continuous successful reads**. Same outcomes:
  `DeadlineExceeded`, `SignalButMarkerUnusable`, within the capture policy, writer explicitly
  `KilledAndReaped`.
* `owned_holder_cleanup_guard_runs_on_unwind` — a focused early-failure control owns a holder,
  then panics inside `catch_unwind`; after the unwind it observes (bounded `kill(pid, 0)` →
  ESRCH poll) that the guard killed+reaped the holder during unwinding, demonstrating the
  guard is installed and used on the failure path.

The idle and active controls exercise different drain paths (`WouldBlock`-poll vs.
continuous-successful-read), both terminating at the same armed deadline. The injected-seam
cleanup classifier `drive_cleanup_classifies_failures_without_false_reaping` (no real
process) and the pure constructed-`ExitStatus` decision table are retained.

### Real child-recovery outcome (unchanged journal/accounting)

`reserved_only_child_death_then_reopen_refuses` runs through the corrected runner: observed
`AbortedAfterMarker { signal: 6 }`; fresh RocksDB handle + ownership domain on reopen; valid
`Reserved` record present at the exact position/binding; **exact retry → `PotentiallySigned`**;
**conflicting binding → `Conflict`**; raw `get_signing_record` bytes and `get_signing_metadata`
**byte-identical** across the refusals. Unchanged from the accepted F-B record/refusal
assertions.

### Validation (code/test checkpoint `06c6423e…` on this task branch; dev profile; exit 0)

Overlapping subsets reported separately (not summed). The one ignored integration test is
the child helper `d7d10_child_reserve_then_abort`; it runs as a harmless no-op when invoked
directly (its recovery meaning exists only when the active parent re-executes it with
`QBIND_D7D10_CHILD_DB` set), so a direct `--include-ignored` invocation is **not** an
additional recovery scenario.

* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests`
  (default features) — **34 passed, 0 failed, 1 ignored** (the child helper).
* `cargo test -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests -- --include-ignored`
  (default features) — **35 passed, 0 failed, 0 ignored** (the child helper runs as a no-op).
* `cargo test -p qbind-node --features test-utils --test run_422_d7d10_signing_reservation_journal_tests -- --include-ignored`
  — **40 passed, 0 failed, 0 ignored** (the +5 over the default run are the `test-utils`-gated
  unknown-version and raw-seam direct-read cases).
* Focused new/strengthened controls, run directly on the built executable
  (`drain_deadline_enforced_across_continuous_successful_reads`,
  `drain_deadline_enforced_across_repeated_interrupted_reads`,
  `runner_idle_held_pipe_after_direct_child_exit_is_unusable_and_holder_reaped`,
  `runner_active_output_after_direct_child_exit_is_unusable_and_writer_reaped`,
  `owned_holder_cleanup_guard_runs_on_unwind`) — **all passed**; and the regression check above
  (reverted top-of-loop check) confirmed the two seam controls FAIL bounded, not hang.
* `cargo test -p qbind-node --lib run422_d7d10` — **64 passed, 0 failed**.
* `cargo test -p qbind-node --lib correction_f_engine` — **3 passed, 0 failed** (accepted F-A
  engine-progress, unchanged).
* `cargo check -p qbind-node --bins --lib` — exit 0.
* Focused Clippy `cargo clippy -p qbind-node --test run_422_d7d10_signing_reservation_journal_tests`
  — **no warnings in the changed file** (the reported warnings are pre-existing in the
  `qbind-node` lib, unrelated to this change).
* Changed-region hygiene: the changed `.rs` file and both docs remain **CRLF** with their
  original no-trailing-newline EOF and no space-before-CR trailing whitespace; the diff is
  confined to the F-B runner module (`run_drain`, `DrainDeadline` docs, the new
  `spawn_with_pipe_holder`/`OwnedHolder`, the seam tests) and the control tests;
  `task/warning.txt` preserved.

### Re-executed integration-test artifact identity

The child-recovery test re-executes the **default-feature** test executable. Both artifacts
are recorded with correct attribution (build-dependent; the filename hash and SHA-256 change
on any rebuild; no production-node release build is required for this test-only correction):

* Default features (the artifact the child-recovery test re-executes):
  * Source checkpoint: `06c6423e577f9235ea772e2e59267dbe693ee3e6` (code/test commit).
  * Path: `target/debug/deps/run_422_d7d10_signing_reservation_journal_tests-278b729b96e64c0e`
    (the **test executable**, NOT the production node binary).
  * Profile / features: `dev`/debug (unoptimized + debuginfo); default features.
  * Byte length: **306473976**.
  * SHA-256: `37f28a05cc7d8e566d7545b4f14bca15ee85d62e1f8143e099d06f774b02d429`.
* `--features test-utils`:
  * Path: `target/debug/deps/run_422_d7d10_signing_reservation_journal_tests-3b3133d90dc6ef80`.
  * Profile / features: `dev`/debug; `--features test-utils`.
  * Byte length: **306440280**.
  * SHA-256: `fc8142d7dac29338e7957dc47bc7d5211b138308387a0dbd96ad36a88cc5e83a`.

### Security-tool outcomes (literal)

Attempted once via the harness `parallel_validation`. The CodeQL change was declared
**trivial** (test-only + documentation-only changes, matching the CodeQL trivial categories),
and the literal outcomes were:

* **Code Review — DID NOT complete a real review.** The result line read "No review comments
  found", but the accompanying note reported the review tool was **unavailable** in this
  environment (`autofind` binary not found at the searched paths). "No review comments found"
  is therefore **NOT** a clean review.
* **CodeQL — Skipped (not executed).** Reported "Skipped: all changes are trivial" under the
  trivial declaration for this test-only + documentation-only change; no scan ran, so there
  is no "0 alerts" result to claim.

Neither constitutes a completed security analysis. Per the task, unavailable/skipped tooling
was attempted once and recorded literally (not re-run repeatedly, and no infrastructure was
changed). Security posture remains `RS1-OPEN / PUBLIC-DEVNET-NO-GO`; this
test/documentation-only change does not alter it.

### Documentation reconciliation and scoped verdict

The contract (`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`,
F-B finalization subsection) and the Correction F-B repair bullets above are reconciled: the
claims that a `WouldBlock`-only check bounded all draining and that the discarded
process-group kill of a backgrounded orphan established descendant cleanup are **superseded**
by the every-iteration deadline and the test-owned, verified pipe-holder cleanup. Idle and
active held-pipe controls are documented as exercising different drain paths; real-process
evidence is kept distinct from the deterministic reader/cleanup seams; normal-path cleanup
verification is distinguished from best-effort `Drop` unwind cleanup. Prior per-command,
release, and artifact figures remain at their actual historical checkpoints and are not
relabelled as newly executed. `contradiction.md` was inspected **read-only**; no new
operative contradiction is introduced by this test/documentation-only change, and no C4/C5
closure is claimed.

With the repaired F-B requirements demonstrated (unconditional drain deadline + test-owned
verified control cleanup, with the regression actually caught), the scoped verdict is
reaffirmed:

```
D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE
```

Retained posture at the F-B pass (superseded below by the RUN 422 D10 aggregate consolidation, which reconciles the canonical local verdict to `D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE` for its demonstrated local scope): overall `D7D10_LOCAL_SIGNING_RESERVATION=PARTIAL` at that pass; accepted
A–E and F-A evidence; `D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`;
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`; `GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`;
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`; C4/C5 OPEN. No aggregate D10 promotion,
D11, Run 423, production journal initialization, signing enablement, activation, or
anti-rollback implementation is performed here.

## RUN 422 D10 aggregate A–F consolidation (documentation-only)

This section records the completed aggregate A–F review and the reconciled canonical
local verdict. The authoritative in-contract summary is
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` §9.7. This is
a documentation-only consolidation: no Rust, test, dependency, feature, schema, CLI,
configuration, workflow, wire-format, or activation changes were made, and no new
build, test, or scan was executed by this pass.

### Aggregate-reviewed revision and limitations

* Reviewed/tested HEAD: `2cf125ccd2ee9b4af29280095b48461ec0eae975`.
* Reported branch: `copilot/run-422-corrections` (the actual task branch carrying this
  consolidation is `copilot/run-422-documentation-only-consolidation`; its starting HEAD
  is the same `2cf125c`).
* Shallow, single-branch clone. The previously accepted Correction F references
  `f069bd7dfeaac3dd6e5de91efefe644cf2d9257f` (final) and
  `06c6423e577f9235ea772e2e59267dbe693ee3e6` (code/test checkpoint) are **not present as
  objects** in this checkout.
* The source reviewer verified identical Git blob hashes between `2cf125c` and `f069bd7`
  for the journal, storage, handler, D10 integration target, the continuity contract,
  and this D7 evidence document — establishing correspondence of those files only, not
  ancestry or identity of every repository file.
* The aggregate review was **read-only**: it produced no change set.

### A–F invariant matrix

| Correction | Invariant | Enforcing mechanism | Evidence level | Limitation | Disposition |
| --- | --- | --- | --- | --- | --- |
| A | Missing-journal signing refusal with admission precedence preserved | `guarded_sign_{proposal,vote}_for_broadcast` refuse a missing journal before the signer on every production route; raw `sign_*_for_broadcast` are `#[cfg(test)]` | CODE-TEST | Serialized local handler; no configured-authority runtime evidence | CODE-TEST-POSITIVE |
| B/C | Acknowledged reservation before signing; one-use operation-bound continuation; checked/suppressed publication | Backend-shared `SigningOwnershipDomain` coordinates supported handles; `reserve_for_sign` grants a `SigningContinuation` only after a durable reservation acknowledgement; `consume_for_signing` consumes that operation-bound continuation at most once into its `ResultPublicationCapability`; `record_signed_result` validates ownership, position/binding, stored reservation, permitted transition, and result-write acknowledgement; failed or uncertain publication suppresses delivery while preserving the signing obligation | CODE-AND-STORAGE-TEST | Model reopen; serialized handler; test-only `SignGate`/`GateOutcome` drive the deterministic contention schedule (test evidence, not the production mechanism); not power-loss/release-binary evidence | CODE-AND-STORAGE-TEST-POSITIVE (local) |
| D | Frozen-operation authorization revalidation of the original ticket, bound context, and signer | `BoundSigningOperation` freezes the admission ticket, bound context, and selected signer; completion reconfirms immediately before the signer and before retained reuse; distinct fail-closed counters | CODE-TEST | Serialized local handler; signer/suite correspondence only (no private-key possession); no runtime evidence | CODE-TEST-POSITIVE |
| E | Explicit initialization/opening, namespace validation, persistent capacity, bounded recovery-acknowledgement cache | Explicit initialize/open vs established-journal validation; persisted journal-wide limit/count; bounded recovered-acknowledgement cache with post-eviction failed-retry assertions | CODE-AND-STORAGE-TEST | Serialized/local; no configured-authority runtime evidence | CODE-AND-STORAGE-TEST-POSITIVE |
| F | Engine progress preserves the originating decision and conflict position; bounded child-process abort/reopen recovery | Engine-progress recorder preserves the originating decision/conflict; bounded, classified child-process runner with an unconditional drain deadline and test-owned verified cleanup; real-process abort/reopen | CODE-AND-PROCESS-TEST | Stated storage/OS assumptions; not power-loss durability; not configured-authority runtime evidence | CODE-AND-PROCESS-TEST-POSITIVE |

### Reviewed interactions between corrections

1. Admission precedence and missing-journal refusal.
2. Reservation acknowledgement, one-use capability, and original-ticket revalidation.
3. Failed/uncertain result publication suppressing delivery.
4. Recovery acknowledgement/cache handling followed by authorization revalidation and exact reuse.
5. Cache eviction and failed/uncertain retries requiring a later successful acknowledgement.
6. Capacity or metadata failure refusing without signing or erasing obligations.
7. Engine progress preserving the originating decision and conflict position.

### Conclusion and reconciled canonical verdict

The aggregate A–F review concluded **LOCAL SCOPE SUPPORTED** — **no material findings** in
the reviewed local signing-reservation implementation and evidence. “No material
findings” is attributed to the aggregate review; it is not proof that the
implementation is free of every possible defect. The canonical local verdict is
reconciled to:

```
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE
```

Local scope of this token: a non-authorizing local signing-reservation component;
shared ownership coordination over supported handles of one backend instance;
acknowledged reservation before signing; one-use operation-bound continuation; checked
result publication and exact retained-result reuse; frozen-operation authorization
revalidation; explicit initialization/opening, namespace validation, persistent
capacity, and a bounded recovery-acknowledgement cache; and demonstrated real-process
abort/reopen behavior under the stated storage and operating-system assumptions.
Production wiring was an **explicit exclusion** from this bounded local component and
must not become a newly invented completion requirement for the local token; it is a
scoped local disposition that does not retroactively approve the earlier defective D10
implementation or establish production readiness. The separate process-evidence token is
retained: `D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE`.

### Validation attribution (executed at `2cf125c`, not re-run here)

The aggregate report records these executions at `2cf125c`. They are prior
aggregate-review executions, not commands executed by this documentation-only pass; no
missing logs, timings, artifact hashes, or exact command flags are invented, and no
historical production binary or integration-test artifact is relabelled as newly built.

| Validation | Reported result |
| --- | --- |
| `cargo test -p qbind-node --lib` | 1839 passed, 0 failed, 0 ignored; exit 0 |
| `run_422_d7d10_signing_reservation_journal_tests` (D10 integration, default features) | 34 passed, 0 failed, 1 ignored; exit 0 |
| `run_422_d7d10_signing_reservation_journal_tests` (D10 integration, `test-utils`) | 39 passed, 0 failed, 1 ignored; exit 0 |
| `run_422_d6_pv_domain_isolation_tests` (D6 PV-domain isolation) | 34 passed, 0 failed; exit 0 |
| `run_420_production_policy_reachability_tests` (Run 420 production-policy reachability) | 3 passed; exit 0 |
| `run_422_startup_refusal_tests` (Run 422 startup refusal) | 4 passed; exit 0 |
| `cargo check -p qbind-node --bins --lib` | exit 0 |
| `cargo clippy -p qbind-node --lib --no-deps` | exit 0; reported baseline warnings |
| Focused D10 integration Clippy with `test-utils` | exit 0; reported cosmetic warnings |

The ignored child helper is executed through the active recovery parent; its direct
no-environment invocation is not another recovery scenario. The 1 ignored entry in the
D10 integration target rows is that child helper.

### Security-tool outcomes (aggregate review, recorded literally)

* Independent Code Review — **NOT RUN**.
* CodeQL — **NOT RUN**.
* The aggregate review did not invoke the diff-oriented validation harness because it
  produced no change set. An empty diff does not establish completed source review or
  security analysis.
* Prior tool-unavailable errors and CodeQL skips remain historical outcomes at their own
  revisions. “NOT RUN” is not “unavailable”, “passed”, “zero findings”, or “nothing
  exists to analyze”. The aggregate source review is kept distinct from completed
  independent tooling.

For this documentation-only pass, any repository documentation-validation checks are
recorded with their actual outcomes separately below (“Documentation checks”); skips or
backend errors are never upgraded into passes.

### Remaining obligations (kept separate and OPEN)

Production journal initialization and wiring; activation authorization and
current-authority freshness; consensus-lock and broader consensus-state recovery;
same-epoch snapshot/signing-history correspondence; whole-copy rollback resistance and
independent freshness-anchor selection; copied-key/cross-host signing exclusivity;
Timeout/NewView compatibility; empirical power-loss durability; configured-authority
release/runtime evidence; independent security-analysis obligations; and C4/C5 and
broader production readiness. Preserved literally and unchanged:
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`, and
`D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`. No D11, Run 423,
production initialization, signing enablement, activation, or architectural redesign is
authorized.

### Documentation checks (this pass)

* Only the two authorized Markdown files were changed:
  `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` and
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`.
* Current status sections agree; no operative “F OPEN” or “pending aggregate review”
  statement contradicts the consolidated result. Historical passes remain visibly
  historical at their own checkpoints.
* CRLF line endings and the existing no-final-newline EOF convention are preserved in
  both files; `task/warning.txt` and unrelated work are untouched.
* `docs/whitepaper/contradiction.md` was inspected **read-only**; its C4/C5 posture is
  unchanged (C4 OPEN — partial; C5 OPEN / narrowed). No contradiction-ledger edit was
  made.
* Reported security-tool outcomes of the documentation-consolidation pass ending at `9194638`
  (retained report, recorded literally; not re-executed during this correction):
  * **Code Review:** unavailable because the `autofind` binary was not found; no completed
    independent review was produced. Any “no comments” wrapper result is **not** a successful review.
  * **CodeQL:** skipped as trivial because the changes were Markdown-only; no completed scan ran.
  These prior-pass outcomes are kept distinct from the aggregate review at `2cf125c` (Independent
  Code Review — **NOT RUN**; CodeQL — **NOT RUN**) recorded above; a skip or tool-unavailable
  error is never upgraded into a pass.
* This bounded correction pass invoked the diff-oriented validation harness once over the two
  changed Markdown files; its own outcomes, recorded as fresh executions (not a re-attribution
  of the historical pass above): **Code Review** did not complete an independent review — the
  `autofind` binary was not found on any searched path, so the “no comments” wrapper result is
  **not** a successful review; **CodeQL** was skipped as trivial (Markdown-only), so no scan ran.
* Local positivity here is bounded to the demonstrated local signing-reservation scope
  and must not be read as production, anti-rollback, or security-review completion.

## Run 422 D7-D11 — Consensus-recovery / signing-history correspondence contract (documentation-only)

This section records the D7-D11 **source audit and documentation-only contract**
phase. It answers: *after an ordinary restart or a snapshot restoration, what
observable evidence is required to establish that recovered consensus safety state
and the signing journal are compatible before signing may resume?* No Rust, test,
dependency, feature, schema, CLI, configuration, workflow, wire-format, or
activation change was made; no build, test, or scan was executed by this pass.

### Provenance and object limitations

* **Working branch (actual):** `copilot/copilotcopilotcopilotrun-422-documentation-only-co`,
  used unchanged (no rename/rebase/force-push/history rewrite). The task's reported
  branch string `copilot/copilotrun-422-documentation-only-consolidation` differs
  from the actual branch; the supplied branch is used as-is. (An earlier revision of
  this section recorded a shorter branch string.)
* **Source revision for line locators (actual):** `5435d22b917d1d078c94b633b18bd28d5802c1a3`
  (`update`). The D7-D11 contract was committed on top of it (`80baf08…`, `update`,
  changing only the three authorized documents) and then **corrected** by this pass
  (Corrections A–D); no tracked Rust source changed, so all source locators remain
  valid.
* **Shallow, single-branch clone** (`git rev-list --count HEAD` = 2). The accepted
  D10 final revision `3d7155eddc09f7071d1af277208a070695aabd66` **and** the reviewed
  revision `515b531a321163c1e20458c4ccb9fc963863b54a` named by the task are
  **absent** as objects in this checkout (`git cat-file -t` → *could not get object
  info*); neither is in local ancestry nor referenced by any tracked file.
  Reachability of those reference objects is reported **separately** from content
  correspondence; ancestry to them is **not** manufactured.

### Changed documents

1. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
   — the authoritative owner of the recovery-admission ordering and the
   recovered-consensus ↔ signing-history correspondence requirements. Introduced as
   a new contract and then **corrected** by this pass (Corrections A–D): production
   vs harness recovery boundaries (§1.1, §2), the limits of lock reconstruction with
   a worked view-comparison example and proof obligation (§2.1, INV-R2), the X1–X6
   classification and defect fixes (§5), the withdrawn observer replaced by a single
   bounded characterization successor (§10), and the fresh/reuse / position-count /
   ownership / repair-vs-re-acknowledgement semantics (§5.2, §6).
2. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`
   — the ownership cross-references (§5 header, §6.7) naming the new contract as
   owner of the recovery/correspondence surface, plus a **narrow** correction to its
   §5.3 recovery claim so it no longer calls the harness reconstruction
   unqualifiedly "conservative" and instead references the correction contract's
   §2.1 proof obligation. The journal specification and the D10 verdict remain
   authoritative and unchanged.
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — this section.

### Source-backed recovery inventory (summary; full table in the new contract §2)

* **Committed state + epoch:** exact restoration in production
  (`open_production_consensus_storage`, `verify_epoch_consistency_on_startup`,
  `get_current_epoch`); a height/epoch is **not** a lock and **not** a
  signing-history commitment.
* **Consensus lock (`locked_qc`):** reconstructed only on the **harness** restart
  path (`hotstuff_node_sim.rs::load_persisted_state` chooses the higher-view of the
  separately-stored and embedded QC, no signature re-verification on load) →
  `initialize_from_restart`; the source comments call this "conservative," but its
  **recovery sufficiency is NOT established** — the reconstructed lock can be
  lower-view (and a different block id) than the pre-crash lock (which may have
  advanced via a timeout certificate or later three-chain progress), admitting at
  least one specific candidate — whose ancestry extends neither locked block —
  that `is_safe_to_vote_on_block` would otherwise refuse (see the correction
  contract §2.1 worked example; a per-candidate result, not a whole-set
  enlargement). The
  **production** snapshot-baseline path (`initialize_from_snapshot_baseline`)
  recovers **no** lock, and **production ordinary startup builds a fresh engine and
  recovers nothing**. No recovery entrypoint carries an uncommitted-vote / per-view
  `voted_in_view` record (reset to `false`); consistent with D7-D2.
* **Restore completion (RTR, D7-D8):** `restore_completion.rs` `COMPLETE` proves
  only that *this attempt's* effects passed durability barriers; the SHA3-256
  `snapshot_meta_digest` is integrity/association only; it is **not** anti-rollback,
  freshness, consensus-lock recovery, or signing-history proof.
* **Signing-reservation journal (D10):** `signing_reservation_journal.rs`
  (`open` / `for_each_signing_namespace_entry`, `SigningRecordStage::{Reserved,
  Signed}`, metadata accounting, bounded `RecoveredAckCache`, in-process
  `SigningOwnershipDomain`) is fail-closed on reopen and never auto-initializes,
  repairs, deletes, overwrites, resets counters, or migrates history; it provides
  **no** anti-rollback/freshness property. **It is not opened or wired anywhere in
  production `main.rs`.**
* **Guarded signing routes:** `guarded_sign_{proposal,vote}_for_broadcast` fail
  closed on a missing journal; `forward_actions_to_facade` / `do_leader_tick` /
  `maybe_reemit_on_late_peer_connect` are wired with `journal = None` and
  `current_auth = None` in production, so under `ConsensusVerificationPolicy::Required`
  every outbound action is rejected at admission before the signing stage.

### Production vs harness distinction

Three production boundaries are kept distinct. **(a) Production ordinary startup**
builds a *fresh* engine (`binary_consensus_loop.rs` `BasicHotStuffEngine::new`) and
restores no committed block, lock, or journal state. **(b) Production requested
restoration** applies only `initialize_from_snapshot_baseline` from the supplied
`RestoreBaseline`, reusing the snapshot `block_hash` as an **opaque** baseline /
parent identifier (not an authenticated historical consensus block id) and
recovering **no** lock. **(c) Production storage opening** performs schema /
incomplete-epoch-transition checks and observes a persisted epoch value without
restoring committed blocks, a lock, or journal state into the engine. The harness
lock reconstruction (sufficiency not established) and the journal readers used by
the correspondence comparisons are therefore **harness/test-reachable only**;
`load_persisted_state` has **no** non-test caller. The production recovery path has
no signing-side correspondence input and an incomplete consensus-side safety input.

### Required safety state, correspondence inputs, and decisions

* **Five questions separated:** (Q1) local non-equivocation — bounded D10 scope when
  the journal is opened; (Q2) consensus safety after recovery — **UNMET** lock
  recovery on the production path; (Q3) history correspondence — **no mechanism**
  (journal not opened in production); (Q4) freshness/exclusivity — **UNRESOLVED**
  (no anchor, in-process-only exclusivity); (Q5) authorization — owned by the
  lifecycle contract, not granted by any correspondence match.
* **Correspondence comparisons (X1–X6)** are each **classified** (existing
  structural check / operation-specific check needing independently supplied inputs
  / unresolved recovery-safety predicate / freshness-exclusivity outside local
  detection) and specify the exact representation, source, phase, relation, and the
  **limited** conclusion. A record compared with itself (X2 count vs its own
  records) is **not** independent freshness evidence. X1 (lock vs recovered chain)
  requires its intended relation — identity/ancestry/other — to be stated and does
  **not** assume unrestored ancestry. X3's `BindingDigest` is a one-way hash that
  does **not** decode epoch/key/authority/block/message; a further comparison needs
  independently obtained canonical evidence, and caller claims are not trusted
  provenance. X4's max-view-vs-height is an **observation** only (a position above
  the frontier can be ordinary uncommitted work); it is not a correspondence match
  or stale-state detector, and D10's per-position conflict refusal is distinguished
  from the broader refusal when required recovery safety is unestablished. X5 needs
  the actual candidate decision and trusted context (a stored signature + digest do
  not reconstruct it). X6 binds validated snapshot metadata only during an **active
  restore**; an ordinary restart need not retain/receive it, preserving D8's
  historical-COMPLETE behavior. Whole-copy rollback and copied-key cases remain
  **locally indistinguishable**; no anchor is selected and no structural match
  implies full recovery compatibility.
* **Proposed admission ordering (S1–S8)** keeps storage-open, safety-state
  validation, journal validation, correspondence, authorization/freshness/exclusivity,
  signer invocation, retained-result reuse, and facade handoff distinct; S6 (fresh
  signing) and S7 (retained reuse, **zero new signer calls**) are **alternative
  branches**; the persistent position count advances only on a new reservation
  (Reserved and Signed share one position); a successful local S1–S4 check does
  **not** become production activation authorization, and `COMPLETE` restore
  admission (D8) is **not** proof of lock recovery or signing-history freshness.

### Single unstarted successor

The previously-proposed read-only **correspondence observer** is **withdrawn**: it
cannot implement a meaningful overall `match / non-correspondence` from inputs that
do not exist (X1/X4 unresolved predicates; X3/X5 need independently supplied
evidence; X6 active-restore only), and a non-authorizing label does not compensate
for that. The single replacement successor, **not begun**, is a bounded source+test
**characterization** of the existing lock reconstruction and recovery-input loss
using only existing engine/storage interfaces (`load_persisted_state` →
`initialize_from_restart`, `locked_qc()`, `is_safe_to_vote_on_block`,
`initialize_from_snapshot_baseline`, `get_qc` / embedded `block.qc`). Its precise
question: can the harness-reconstructed lock be strictly lower-view than the
pre-crash lock and thereby enlarge the admitted set (§2.1)? This is **not** covered
by D7-D2 (which characterizes the uncommitted-vote latch loss with an
explicitly-absent QC baseline). Anchor selection, cross-copy/cross-host exclusivity,
lock-recovery redesign, Timeout/NewView migration, any new reader / persistence
format / freshness interface / recovery architecture, opening a journal in the
production signing path, and any activation/readiness change are explicit
exclusions.

### Checks actually executed (this pass) and literal tool outcomes

* Re-traced the source symbols and call order against `5435d22` for Corrections
  A–D (engine recovery; `is_safe_to_vote_on_block`; harness `load_persisted_state`
  lock selection; production `main.rs` startup/restore and the binary-loop fresh
  `BasicHotStuffEngine::new` + conditional `initialize_from_snapshot_baseline`;
  `SigningDecisionRecord` / `BindingDigest`; `reserve_for_sign` /
  `record_signed_result` / `SigningOwnershipDomain`; `restore_completion.rs`).
  Line numbers are locators; symbols are authoritative.
* Verified reference-object reachability with `git cat-file -t` (D10 final
  `3d7155e…` **and** reviewed revision `515b531a…` both absent; reported separately
  from content correspondence).
* Checked cross-document consistency against the continuity contract (§5/§5.2/§5.3/§6,
  including the narrow §5.3 recovery-claim correction),
  the authority lifecycle contract, the snapshot-restore completion contract, and the
  genesis authority / QC integration audit (inspected read-only); `docs/whitepaper/contradiction.md`
  inspected read-only, C4/C5 posture unchanged, no ledger edit made.
* EOL (CRLF) and the existing no-final-newline EOF convention are preserved in all
  three changed files; `task/warning.txt` and unrelated work are untouched.
* **No Cargo tests, Clippy, or release rebuild** were run — none are required for
  this documentation-only correction. No historical result is relabelled; the §2.1
  reasoning example and §8/§10 future tests are labeled as reasoning / not executed.
* **Security-tool outcomes (literal, this correction pass):** `parallel_validation`
  was invoked over the three changed Markdown files. **Code Review** did **not**
  complete an independent review — the reviewer backend errored
  (`model claude-sonnet-4.6 not found in registry`; the `autofind` run failed), so
  its "No review comments found" wrapper is **not** a successful review. **CodeQL**
  was **skipped as trivial** (Markdown-only), so no scan ran. A skip, a
  tool-unavailable/backend error, or a "no comments" wrapper is never upgraded into
  a pass, and these outcomes are kept distinct from earlier historical outcomes at
  their own revisions.

### Scoped verdict and preserved posture

```
D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED
```

Design completion establishes **no** implemented recovery protection. Preserved
unchanged (not reopened): `D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`,
`D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE`,
`D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED`,
`D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`,
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`, and
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. C4/C5 remain OPEN. No production
signing enablement, readiness promotion, or Run 423 work is authorized. Worktree
clean after commit; changes pushed to the task branch; **no PR** opened.

## Run 422 D7-D12 — Lock reconstruction vs. pre-crash voting restriction (tests + documentation only)

This section records the D7-D12 **bounded test-and-documentation
characterization** of what the *existing* committed-state recovery path
reconstructs as a lock, measured against a stronger *pre-crash* lock established
through the real engine lock transition, and evaluated with the **same**
explicitly-supplied candidate. It adds `d7d12_*` cases to the existing
committed-state recovery control and reconciles the narrow D11 documentation
items (§7A–§7E of the task). No production-source, dependency, feature,
storage-schema, CLI, wire-format, signer, authorization, or recovery-algorithm
change was made; no new production accessor or generic test framework was added.
A passing predicate result here characterizes a **gap**; it establishes no
recovery sufficiency, no authenticated consensus safety, no signing continuity,
and no exploitability.

### Provenance and object limitations

* **Working branch (actual):** `copilot/copilotcopilotcopilotcopilotrun-422-documentation`,
  used unchanged (no rename/rebase/force-push/history rewrite). The task's
  reported D11 reference branch string
  `copilot/copilotcopilotcopilotrun-422-documentation-only-co` differs from the
  actual branch; the supplied branch is used as-is.
* **Starting HEAD (actual):** `3275e03361da1aa7001ce788adf8d1d4e90aaeac`
  (`update`). **Tested implementation checkpoint:**
  `17d0fe30dfbe83b9fbe816b53f69b0957fac811a` (the `d7d12_*` test commit). The
  final documentation + validation commit is the last commit on the branch
  (recorded in the branch/PR history). Worktree was clean between checkpoints.
* **Shallow, single-branch clone** (`git rev-list --count HEAD` = 3 at the test
  checkpoint; grafted base `80baf08…`). The D11 reference commit
  `7a9c3d456c439fb2c978536597169700645315da` is **absent** as an object in this
  checkout (`git cat-file -t 7a9c3d…` → *could not get object info*); it is
  neither in local ancestry nor referenced by any tracked file. Reachability of
  that reference object is reported **separately** from content correspondence;
  ancestry to it is **not** manufactured. Content correspondence is established
  by inspecting the current source (the reused interfaces below), not by
  comparison against the absent object.
* `task/warning.txt`, unrelated work, and each file's existing
  line-ending/EOF conventions were preserved (this devnet record remains CRLF
  with no trailing final newline).

### Changed paths and reused interfaces

* **Changed paths (authorized scope only):**
  1. `crates/qbind-node/tests/run_422_d7d2_signing_state_recovery_tests.rs` —
     extended the existing `committed_state_recovery_control` module with
     clearly-named `d7d12_*` cases, reusing its harness, storage, and setup
     helpers (`create_test_setup`, `node_cfg`, `committed_block_and_qc`,
     `NodeHotstuffHarness`, `observe_consensus_storage`, `InMemoryConsensusStorage`).
  2. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
     — §7A–§7E corrections (reachability, S4 missing predicates, X3
     unavailable-vs-non-correspondence, fixture-write permission, lock-update
     order) and promotion of the §2.1 source-level example to executed predicate
     evidence.
  3. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` —
     a **concise** §5.3 successor/evidence correction only (points at the
     executed D12 evidence; does not repeat the contract).
  4. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — this section.
* **Reused interfaces (existing public interfaces only, no new accessor):**
  `NodeHotstuffHarness::load_persisted_state`;
  `BasicHotStuffEngine::{state, state_mut, locked_qc, committed_height, committed_block, current_epoch, current_view}`;
  `HotStuffStateEngine::{register_block, on_vote, is_safe_to_vote_on_block}`;
  the existing committed-block/QC storage APIs (`put_block`/`get_block`,
  `put_qc`/`get_qc`, `put_last_committed`/`get_last_committed`,
  `put_current_epoch`/`get_current_epoch`); `observe_consensus_storage`; and the
  existing D7-D2 committed-state controls (`d7d2_c_*`), preserved intact.

### Lock-update order traced in current source (§7E)

`HotStuffStateEngine::on_qc` (`crates/qbind-consensus/src/hotstuff_state_engine.rs`
~L995) updates `locked_qc` to the higher-view QC (`qc.view > existing.view`)
**before** calling `try_commit_with_qc` (the three-chain rule, ~L1029). Lock
advancement therefore does **not** require a successful three-chain commit. This
is characterized directly by
`d7d12_precrash_lock_advances_via_on_vote_without_a_commit`, which forms a QC via
`on_vote` and asserts `locked_qc.view == 20` while `committed_height() == None`.

### How the common baseline and the advanced pre-restart lock were established, and what was persisted

The corrected primary case (`d7d12_candidate_rejected_by_precrash_lock_accepted_by_reconstructed_lock`)
runs as **one coherent fixture sequence** over a single surviving storage
baseline, rather than comparing a disconnected fresh four-validator engine
against a separately-configured recovered harness:

* **Common baseline, loaded (real reader).** `committed_block_and_qc(7)` lays
  down, via `put_block` / `put_qc` / `put_last_committed`, a committed block id
  `0x77…`, height 7, with a stored wire QC at height 7 whose `signatures` vector
  is **empty** (an unverified reconstruction fixture, no constituent signatures)
  and no embedded `block.qc`. No committed-epoch key is seeded —
  `observe_consensus_storage` reports `PresentNoCommittedEpoch` (an explicit
  **absence**, distinct from an explicit zero). A first harness is constructed
  with a concrete validator configuration and that storage, and the REAL reader
  `NodeHotstuffHarness::load_persisted_state` loads it: committed block `0x77…`,
  committed height `Some(7)`, reconstructed lock `locked_qc == (0x77…, view 7)`,
  resume view 8, engine epoch 0. The committed baseline therefore already exists
  in the pre-crash engine **before** its lock is advanced.
* **Advanced pre-restart lock on that SAME engine (real transition, not
  `set_locked_qc`).** On the loaded engine, `register_block` adds a standalone
  block `0xB0,20` at view 20 and one vote from the single-validator harness
  quorum (local `ValidatorId(1)`, `two_thirds_vp(1) == 1`) is fed through
  `HotStuffStateEngine::on_vote`; the vote forms a QC at view 20 and `on_qc`
  raises `locked_qc` to `(0xB0,20, view 20)`. The **loaded committed baseline is
  unchanged** by this advance (`committed_block() == Some(0x77…)`,
  `committed_height() == Some(7)`; no three-chain existed), and the named
  persisted committed-state values (`get_last_committed`, `get_block(..).height`,
  `get_qc(..).height`, `get_current_epoch`) are re-read and **unchanged** (the
  in-memory lock advance performs no storage writes). A copied four-validator
  quorum is **not** fed into this single-validator harness.
* **Standalone "no committed block" observation kept separate.** The distinct
  test `d7d12_precrash_lock_advances_via_on_vote_without_a_commit` shows that a
  *fresh* `BasicHotStuffEngine::new(ValidatorId(1), 4 validators)` can advance
  its lock to view 20 (3-of-4 quorum) with `committed_height() == None`. That is
  a different, valid observation about lock-vs-commit ordering — **not** the
  primary test's "existing committed baseline unchanged" result above.

### Actual harness reconstruction results (fresh harness, same surviving storage)

After evaluating the pre-restart candidate, the first harness is **discarded**
and a fresh harness is constructed with the same validator configuration over
the **same surviving storage fixture**. `NodeHotstuffHarness::load_persisted_state`
(the real reader, not a reproduction) yields, asserted separately:

* recovered committed block id `== 0x77…`, committed height `== Some(7)`;
* **reconstructed lock** `locked_qc.view == 7` (`== committed QC height`),
  `locked_qc.block_id == 0x77…` — a lock reconstructed from the committed/stored
  QC, selected by the reader's own higher-of-stored/embedded rule; **not** the
  exact latest pre-crash lock;
* resume view `== committed_height + 1 == 8`;
* engine epoch `== 0` (the reader's missing-epoch fallback), distinct from the
  `PresentNoCommittedEpoch` observation;
* read-back of the persisted values confirms what recovery **preserved**
  (`get_last_committed == Some(0x77…)`, `get_block(..).header.height == 7`,
  `get_qc(..).height == 7` with empty `signatures`, `get_current_epoch == None`,
  `observe_consensus_storage == PresentNoCommittedEpoch`). This is a
  specific-value, semantic read-back, **not** a whole-directory byte-identity
  claim; the stored QC remains an unverified fixture (recovery did not
  authenticate it).

The two locks differ in **both** coordinates: the advanced pre-restart lock is
`(0xB0,20, view 20)` and the reconstructed lock is `(0x77…, view 7)` — a
different locked block id **and** a different view, not merely a changed view.

### Candidate identity / ancestry / justification and before/after predicate outcomes

* **Candidate (explicitly test-supplied inputs, not recovered ancestry).**
  Registered via `register_block`: a standalone parent at view 14 (id `0xA1…`,
  no ancestry) and the candidate at view 16 (id `0xC1…`) whose `justify_qc` is an
  unverified logical QC at **view 15** over an unrelated block `0xB1…`. The
  candidate's ancestry (`0xC1… → 0xA1… → ⊥`) contains **neither** locked block
  (`0xB0,20` pre-crash nor `0x77…` reconstructed), so `is_safe_to_vote_on_block`
  can pass only via the justify-view liveness rule.
* **Under the advanced pre-restart lock (block `0xB0,20` / view 20):**
  `is_safe_to_vote_on_block(0xC1…) == false` — `15 >= 20` is false and the
  ancestor walk does not reach the locked block ⇒ **fails the predicate**.
* **Under the reconstructed lock (block `0x77…` / view 7), same candidate id/ancestry/justify:**
  `is_safe_to_vote_on_block(0xC1…) == true` — `15 >= 7` is true ⇒ **passes the
  predicate**.
* **What precisely changed, and the narrowed conclusion.** Both complete lock
  identities are reported: the advanced pre-restart lock `(0xB0,20, view 20)`
  and the reconstructed lock `(0x77…, view 7)` differ in **both** block id and
  view — this is **not** a "only the lock view changed" claim. The controlled
  candidate comparison (same id, same ancestry, same justify view 15 on both
  sides) isolates the predicate outcome to the lock the predicate compares
  against; it asserts **no** whole-engine equivalence (other engine state, e.g.
  the extra advanced-lock block and vote history, also differs after
  reconstruction). The demonstrated statement is narrow: *this candidate, whose
  ancestry extends neither locked block, fails the predicate under the advanced
  pre-restart lock and passes it under the reconstructed lock.* The predicate
  checks ancestry **as well as** view, so a lower view with a different locked
  block does **not** by itself prove any global accepted-set enlargement. This is
  a predicate result only — no emitted vote, no signing, no facade handoff, no
  network transmission; other admission, leader, view, latch, and
  verified-justification checks still gate any real vote and were not bypassed.

### Control results and evidence boundaries (§6)

* `d7d12_control_candidate_below_both_locks_rejected_under_both` — justify view 5
  (below both 7 and 20), non-extending ⇒ rejected under **both** locks; candidate
  identity and reconstructed `locked_qc.{view,block_id}` asserted.
* `d7d12_control_candidate_at_least_both_locks_accepted_under_both` — justify view
  25 (≥ both), non-extending ⇒ accepted by the predicate under **both** locks;
  candidate identity asserted and distinct from each locked block id.
* `d7d12_control_equal_reconstructed_lock_preserves_restriction` — the
  **unchanged-lock** control: both sides reconstruct the **same lock identity**
  (same block id `0x77…` **and** same view 20) from the same persisted baseline
  and configuration — the pre-restart side is established by **loading** that
  baseline, with **no** higher-lock advancement. The same justify-15 candidate
  receives the **same** predicate result (fails) before and after, demonstrating
  **preservation of that tested restriction** — not a proof of complete recovery
  safety. Guards against reading the primary result as "recovery always weakens
  the restriction."
* Boundaries kept separate throughout: reconstruction (harness reader) vs lock
  advancement (engine `on_qc`) vs `is_safe_to_vote_on_block` (pure predicate) vs
  any emitted vote / signing / facade / network (none exercised). Full
  `BasicHotStuffEngine` proposal processing was **not** run here; if it were, its
  outcome would be reported separately and its other checks not bypassed.

### Commands, counts, profiles, and literal tool outcomes

> Historical record at the original `d7d12_*` test checkpoint
> (`17d0fe30dfbe83b9fbe816b53f69b0957fac811a`). Preserved verbatim; **not**
> relabelled as a new execution. The corrected-run results are recorded in the
> "D12 correction" entry below.

```
# Dev profile (unoptimized + debuginfo); default features (no extra features).

cargo test -p qbind-node --test run_422_d7d2_signing_state_recovery_tests
#   test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
#   (5 pre-existing d7d2_* + 5 new d7d12_* cases.)

cargo test -p qbind-node --test hotstuff_restart_semantics_tests
#   test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo test -p qbind-node --test persistence_integration_tests
#   test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo clippy -p qbind-node --test run_422_d7d2_signing_state_recovery_tests
#   Finished (exit 0). The changed integration target generated 0 warnings after a
#   doc-comment list-indentation fix. The qbind-node LIB emits 103 PRE-EXISTING
#   warnings unrelated to this change (not introduced here).
```

* **Security/review tooling (attempted once; literal outcomes).** The automated
  `parallel_validation` wrapper was run once for this diff.
  * **Code Review:** the wrapper reported *"No review comments found"* over 4
    files, **but** also reported that the underlying reviewer **failed to
    initialize** — literal error: *"Code review tool is not available in this
    environment: … model claude-sonnet-4.6 not found in registry …"*
    (`autofind … command_failed`). Per the task's own caution, a wrapper
    reporting "no comments" **after a reviewer failure is NOT a completed
    review**; this is recorded as **reviewer-unavailable**, not a clean review.
  * **CodeQL Security Scan:** **skipped** — the changes were declared trivial
    (test-only + Markdown), and the wrapper returned *"Skipped: all changes are
    trivial."* A skipped CodeQL analysis is **NOT a passed scan**; this is
    recorded as **not-run (skipped)**, not a clean security result.
* No production release-binary evidence is claimed for this harness/predicate
  characterization; no test executable or historical release build is relabelled
  as new production-runtime evidence.

### D12 correction (superseding) — coherent restart sequence and complete lock-identity comparison

This correction **supersedes** the operative claims of the original D12 record
above wherever they conflict. It changes test-and-documentation evidence only;
it preserves the accepted D10/D8 implementations and all activation
restrictions, and adds no production-source, dependency, feature, schema, CLI,
wire-format, signer, authorization, or recovery-algorithm change.

* **Provenance (this correction run).** Working branch
  `copilot/copilotcopilotcopilotcopilotcopilotrun-422-documen` (actual; used
  unchanged — no rename/rebase/force-push/history rewrite). This string differs
  from the task's reported branch
  `copilot/copilotcopilotcopilotcopilotrun-422-documentation`; the supplied
  branch is used as-is. Session starting HEAD
  `f5fa01bdff7dbb921e1208bc41b246710803f255`. The reviewed objects
  `252a4b3665548ded743f7cef04dff1c87cd3ea96` (reviewed final) and
  `17d0fe30dfbe83b9fbe816b53f69b0957fac811a` (reviewed test checkpoint) are
  **absent** in this shallow single-branch checkout (`git cat-file -t` → *could
  not get object info*); content correspondence is established by inspecting the
  current source and tests, not by comparison against those absent objects, and
  ancestry to them is **not** manufactured. `task/warning.txt`, unrelated work,
  and each file's existing line-ending/EOF conventions are preserved.

* **Correction A — one coherent restart sequence.** The reviewed primary test
  compared a *disconnected* fresh four-validator engine (no committed baseline)
  against a separately-configured recovered harness. It is replaced with a
  continuous fixture sequence over a **single** surviving storage baseline:
  (A) prepare the committed-height-7 fixture and **load** it into a first harness
  via the real `load_persisted_state` (committed `0x77…`/height 7, reconstructed
  lock `(0x77…, view 7)`, resume view 8, epoch 0, storage observation
  `PresentNoCommittedEpoch` — explicit absence, not zero); (B) advance **that
  same engine's** lock to `(0xB0,20, view 20)` through the real
  `register_block` → `on_vote` → `on_qc` transition, using the **single-validator
  harness quorum** (`two_thirds_vp(1) == 1`; no copied four-validator quorum),
  with the loaded committed baseline and the named persisted values **unchanged**
  by the advance; (C) register the explicitly test-supplied candidate (`0xC1…`,
  view 16, justify view 15; parent `0xA1…`, view 14; ancestry extends **neither**
  locked block) and evaluate — it **fails** the predicate under the advanced
  lock; (D) **discard** the first harness, build a fresh harness over the **same**
  surviving storage, reconstruct `(0x77…, view 7)` via the real reader, register
  the same test-supplied candidate/ancestry, and evaluate — it **passes** the
  predicate; read back the surviving committed block, stored QC (still empty
  `signatures`), last-committed pointer, and epoch observation (semantic
  read-back, **not** whole-directory byte identity). The separate standalone test
  `d7d12_precrash_lock_advances_via_on_vote_without_a_commit` (fresh engine,
  `committed_height() == None`) is retained as a distinct observation.

* **Correction B — complete lock identity, narrowed conclusion.** Both complete
  locks are reported: advanced pre-restart `(block_id = 0xB0,20, view = 20)` and
  reconstructed `(block_id = 0x77…, view = 7)` — they differ in **both** block id
  and view. The "only the lock view changed," global accepted-set enlargement,
  and equal-view-as-equal-lock claims are **removed**. The demonstrated statement
  is: *this candidate, whose ancestry extends neither locked block, is rejected
  under the advanced pre-restart lock and accepted under the reconstructed lock.*
  Predicate outcomes are described as **passes/fails the predicate**, never as an
  emitted vote, signature, delivery, or attack. The controlled comparison
  isolates the predicate outcome without asserting whole-engine equivalence.

* **Unchanged-lock control corrected.** `d7d12_control_equal_reconstructed_lock_preserves_restriction`
  now reconstructs the **same relevant lock identity** on both sides (same block
  id `0x77…` **and** same view 20) from the same persisted baseline and
  configuration — the pre-restart side is established by **loading** that baseline
  (no higher-lock advancement). The same candidate receives the **same** predicate
  result (fails) before and after: preservation of that tested restriction, not a
  proof of complete recovery safety. The below-both and at-least-both controls and
  all D7-D2 cases are retained with explicit logical/unverified-fixture scope.

* **Corrected-run validation (new execution at this correction checkpoint).**
  Dev profile (unoptimized + debuginfo), default features (no extra features):

  ```
  cargo test -p qbind-node --test run_422_d7d2_signing_state_recovery_tests
  #   test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
  #   (5 d7d2_* + 5 d7d12_* cases; same count, corrected primary + unchanged-lock bodies.)

  cargo test -p qbind-node --test hotstuff_restart_semantics_tests
  #   test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

  cargo test -p qbind-node --test persistence_integration_tests
  #   test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

  cargo clippy -p qbind-node --test run_422_d7d2_signing_state_recovery_tests
  #   Finished (exit 0). The changed integration target emits 0 warnings; the
  #   qbind-node LIB emits 103 PRE-EXISTING warnings unrelated to this change.
  ```

  No production release build is required for this test/documentation correction;
  no historical executable is presented as newly-tested runtime evidence. Counts
  are not summed across the overlapping subsets.

* **Security/review tooling (attempted once this correction run; literal
  outcomes).** `parallel_validation` was invoked once.
  * **Code Review:** the wrapper returned *"No review comments found"* over 4
    files, **but** also reported the underlying reviewer **could not initialize**
    — literal error: *"Code review tool is not available in this environment …
    autofind binary not found …"*. Per the task's caution, "no comments" **after
    a reviewer failure is NOT a completed review**; recorded as
    **reviewer-unavailable**, not a clean review.
  * **CodeQL Security Scan:** returned *"Skipped: all changes are trivial"*
    (test-only Rust + Markdown). A skipped analysis is **NOT a passed scan**;
    recorded as **not-run (skipped)**, not a clean security result.

* **Boundaries retained.** In-process harness reconstruction over surviving model
  storage — **not** real process death, RocksDB durability, empirical power-loss
  evidence, production startup recovery, or authenticated network behavior.
  Fixture-created committed state and the unverified QC material (empty
  `signatures`) remain labeled as such; the coherent sequence does not convert
  them into authenticated consensus history. QC-authentication limitations, the
  epoch-absence distinction, and the separation from signing/network evidence are
  preserved, as are the D11 corrections (production-vs-harness reachability,
  missing correspondence predicates/evidence, unavailable-vs-non-corresponding
  evidence, and permitted fixture writes).

### Documentation corrections carried forward from D11 (§7)

* **A — Reachability:** the absolute "no non-test caller" claim is replaced with
  the precise production-startup claim — `main.rs` invokes neither
  `load_persisted_state` nor `AsyncNodeRunner`; `AsyncNodeRunner::load_persisted_state`
  is a **compiled harness wrapper**, not evidence that the production binary
  startup path invokes recovery.
* **B — Existing coverage:** the correspondence contract now explicitly credits
  the D7-D2 `d7d2_c_*` committed-state control for recovering a **QC-derived
  lock** and states that D12 adds the pre-crash-versus-reconstructed restriction
  comparison.
* **C — Missing correspondence requirements:** §S4 now names the missing
  predicates (X1–X6) **and** their required independently-obtained evidence
  rather than implying a missing reader alone would establish correspondence; the
  X3 refusal wording now distinguishes **unavailable evidence** (undetermined)
  from **demonstrated non-correspondence** (digest mismatch) — either refuses,
  but they are different findings.
* **D — Fixture writes:** the characterization scope's blanket "no writes"
  wording is replaced with explicit permission for **isolated fixture setup
  through existing storage APIs**, while production changes and recovery repair
  remain excluded.
* **E — Lock-update wording:** assertions that lock advancement happens only
  after a successful three-chain commit are corrected to the current source order
  (`on_qc` updates `locked_qc` before `try_commit_with_qc`), with the executed
  evidence cited separately.

Historical results at their actual revisions are preserved; prior tests are not
rewritten as newly executed.

### Scoped verdict and preserved posture

```
D7D12_LOCK_RECOVERY_CHARACTERIZATION=COMPLETE-FOR-TESTED-SCOPE
```

Demonstrated scope: using only existing public interfaces, (i) the real reader
`load_persisted_state` reconstructs a lock at the committed QC height (view 7);
(ii) a strictly higher pre-crash lock (view 20) is reachable via the real
`on_vote` → QC → `on_qc` transition **without** a committed-state advance; and
(iii) a single explicitly-supplied candidate (justify view 15, non-extending
ancestry) is **rejected** by the pre-crash lock and **accepted** by the lower
reconstructed lock, with below-both / at-least-both / equal-lock controls. This
token does **not** establish recovery sufficiency, authenticated consensus
safety, signing continuity, or exploitability.

Preserved unchanged (not reopened):
`D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED`,
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`, and the accepted D10/D8
verdicts. C4/C5 remain OPEN. No recovery repair, correspondence observer,
production journal wiring, anti-rollback mechanism, copied-key fencing,
activation, readiness promotion, or D13 work was performed. Worktree clean after
each commit; changes pushed to the task branch; **no PR** opened.

## Run 422 D7-D13 — Consensus safety-state durability and recovery-ordering contract (documentation only)

This section records the D7-D13 **documentation-only** extension of the existing
recovery contract. It defines *what consensus safety state must survive an
ordinary crash/restart, when it must become durable relative to dependent
signing, and which missing or inconsistent inputs require refusal.* No Rust,
test, dependency, storage key/schema, persistence format, wire format, CLI flag,
configuration, workflow, signing-preimage, or activation change was made or
proposed for implementation. No PR was opened; no branch rename, force-push,
rebase, history rewrite, or Run 423 work was performed.

### Provenance and object limitations

* **Working branch (actual):**
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotrun-422-again`, used
  **unchanged** (no rename/rebase/force-push/history rewrite). The task's reported
  branch string `copilot/copilotcopilotcopilotcopilotcopilotrun-422-documen`
  differs from the actual branch; the supplied branch is used as-is.
* **Starting HEAD (actual):** `a6727febe0a1c4a928f6545742d71aae22278863` (`update`).
  The final documentation + validation commit is the last commit on the branch
  (recorded in the branch history). Worktree was clean before and after.
* **Shallow, single-branch clone** (`git rev-list --count HEAD` = 2; grafted base
  `f5fa01b…`). The accepted D12 final
  `6ca4a72d47cc878a96bfc63b767ac893cbf22ed8` is **absent** as an object in this
  checkout (`git cat-file -t 6ca4a72…` → *could not get object info*); it is
  neither in local ancestry nor referenced by any tracked file. Reachability of
  that reference object is reported **separately** from content correspondence;
  ancestry to it is **not** manufactured. Content correspondence is established by
  inspecting the current source (the reused interfaces below), not by comparison
  against the absent object.
* `task/warning.txt`, unrelated work, and each file's existing line-ending/EOF
  conventions were preserved (all three changed documents remain CRLF with no
  trailing final newline).

### Changed paths (authorized scope only)

1. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
   — the **authoritative owner**: added §12 (D13 contract) and the
   `D7D13_…` header token; marked the completed D12 successor as a historical
   completion pointing to §12.7 for the single next successor.
2. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` —
   **minimal reconciliation only**: a cross-reference in §5.3 naming §12 as the
   owner of the safety-restriction durability boundary and reconciling it with the
   §4.1 durable-before-sign ordering. No §4.1 step, conflict rule, state machine,
   or anchor requirement changed.
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — this evidence entry.

### Source-backed reuse inventory (symbols authoritative; line numbers are locators)

* **Lock raise is immediate and in-memory, before commit.**
  `HotStuffStateEngine::on_qc` (`crates/qbind-consensus/src/hotstuff_state_engine.rs`
  ~L995) sets `locked_qc = Some(qc.clone())` at ~L1004 when `qc.view > existing.view`
  and **then** calls `try_commit_with_qc` at ~L1013 — the lock advances **without**
  requiring a commit, and nothing is persisted at that point.
* **TC lock update.** `BasicHotStuffEngine::on_timeout_certificate`
  (`crates/qbind-consensus/src/basic_hotstuff_engine.rs` ~L2162) calls
  `set_locked_qc(tc.high_qc)` when `tc.high_qc.view > locked_qc.view`, **before**
  the `current_view` advance.
* **Safe-vote predicate.** `is_safe_to_vote_on_block` (~L1312): (no lock) OR
  `justify_qc.view >= locked_qc.view` OR the ancestor walk reaches
  `locked_qc.block_id` — identity and view are distinct claims.
* **Originating-action view immutability.** `on_leader_step` (~L1434) captures
  `let view = self.current_view;` at ~L1443 and fixes `header.height = view` /
  `round = view` at ~L1503–1504; `current_view` advances separately via
  `advance_view` (~L1000). The action binds to its construction view.
* **Durable-before-sign reservation.** `signing_reservation_journal.rs`
  `reserve_for_sign` writes a `Reserved` record + metadata in one atomic synced
  write **before** the signer; `record_signed_result` performs the synced result
  write and sets `result_acked` only **after** the acknowledgement;
  `reserved_positions` advances only on a **new** reservation.
* **Recovery initializers / reconstruction limits.** `initialize_from_restart` /
  `initialize_from_snapshot_baseline` (no `locked_qc`), and the harness
  `load_persisted_state` reconstruction whose sufficiency is unestablished (§2.1;
  D12) — reused unchanged.

### Required safety state and the preservation rule (summary)

The minimal logical contents are: the **lock block id and view**; the
**certificate/evidence** supporting the lock; the **network/genesis +
validator/authority context** to interpret it; the **committed-state
association**; the **locked block identity + view at startup** with **per-candidate
ancestry supplied and checked**; and **view material** that must not relax the
restriction. The preservation rule is a **recovery decision against observable
durable state**, **not** a runtime comparison against the (unobservable) pre-crash
lock: resume only when the recovered **durable** safety state is self-consistent and
establishes `is_safe_to_vote_on_block` **per evaluated candidate** from recovered
inputs. The §2.1 obligation is a **design-level** proof — discharged by **exact lock
restoration** or by an **independently justified restriction-preservation relation**
(no numeric "dominance"). Committed height,
epoch, highest journal position, a valid QC, a higher lock view, D8 `COMPLETE`, or
a checksum/digest are **each insufficient by itself**. Missing candidate ancestry
blocks **only that candidate** and must never become assumed ancestry; missing
lock identity/certificate blocks signing **generally**.

### Durability boundary and protected frontier (summary)

**[SUPERSEDED — corrected, not accurate as originally written; see the "D7-D13 frontier-resolution entry" below and §12.3 per-route ordering.]** The original uniform receive → update-lock → construct-action sequence quoted next was **corrected**: decision binding is **per route** — each production route (`ingest_proposal`, `on_leader_step`, received vote/QC, `on_timeout_certificate`, D10 fresh/reuse) has its own decision/eligibility point, and a self-vote-generated QC must not retroactively justify its own vote — not one uniform ordering. The events are retained only as the historical description. The seven events — receive evidence → update in-memory lock (immediate, not
staged, no durable write) → construct unsigned action (view fixed) → durably
reserve → sign → retain result → confirm/handoff — are kept distinct. The
**protected frontier** is the acknowledged-durable point of the restriction's
supporting material: before a signing decision may depend on a **newly raised**
restriction, that material must be durable and recoverable **as the lock**;
otherwise dependent signing is blocked. Write failure / uncertain acknowledgement
⇒ fail-closed; a readable byte is never acknowledged persistence. Originating-
action semantics are a **proposed integration requirement** — current action types
carry only header fields and do **not** bind the justifying lock/evidence.

### D10 integration (unchanged semantics)

Fresh signing (S6) and retained reuse (S7) remain **separate branches**. Both sit
**after** the §12.2 preservation and §12.3 durability prerequisites; retained
reuse resends with **zero new signer calls** but does **not** bypass recovery
admission, and the fresh-signing rule is **not** automatically sufficient for
resend. The opaque `BindingDigest` cannot reconstruct a canonical message,
authority context, or block history; an independently obtained canonical
preimage/domain plus pinned authority context is required. The withdrawn
correspondence observer is **not** reintroduced.

### Observable-state recovery decisions and trust boundaries

**[SUPERSEDED in part — corrected, not accurate as originally written; see the "D7-D13 frontier-resolution entry" below and §12.5 row D13-8.]** The D13 recovery matrix (now §12.5, rows D13-1…D13-15) covers valid/missing/present-
but-unusable safety state, incomplete publication, write-outcome uncertainty attributed by
phase, recovered `Reserved` (potentially-signed), retained `Signed` (exact resend only), safety
state ahead of the committed baseline (being ahead is **not** itself a refusal reason — a
**validated** safety state with the required correspondence **may proceed**; refusal follows
only from **unavailable** evidence or **demonstrated inconsistency**, never from a number
matching — this corrects the earlier "refuse because safety is unestablished" wording),
same-epoch older snapshot, internally-consistent
whole-copy rollback (locally indistinguishable), and historical D8 `COMPLETE` with
later legitimate progress (must not reapply old state). Trust boundaries (§12.6)
are stated separately: accidental-corruption detection; cryptographic certificate
verification (not performed on load); local storage integrity (T-FS); current
authorization (A) and freshness (B); ordinary crash consistency (the only property
provided); whole-copy rollback resistance (UNMET); copied-key/cross-host
exclusivity (UNMET). `docs/whitepaper/contradiction.md` was inspected read-only;
the remaining contradiction (durable anti-rollback NOT-established; C4/C5 OPEN) is
unchanged and was not edited.

### Resolved choices vs unresolved obligations

* **Resolved (as a documented requirement):** the per-route decision-binding and
  ordering; the protected frontier and the proposed conservative pending-vs-effective
  profile; the field classification (restriction vs verification/ancestry vs
  scheduling/liveness, including engine guards vs D10 durable protection); the
  corrected preservation rule; the refusal matrix and common gates; the D10 branch
  prerequisites; the storage atomicity-vs-durability table.
* **[HISTORICAL — RESOLVED below]** Unresolved at the original revision (now **RESOLVED**: profile (a) selected — see the "D7-D13 frontier-resolution entry" and §12.7; the "PARTIAL" disposition no longer applies): which
  production rule supplies the §12.3 protected-frontier integration boundary — (a) a
  dedicated recoverable safety record at each lock raise (with atomicity/ordering vs
  D10), or (b) an independently justified reconstruction rule proving the §12.2
  restriction-preservation relation. The evidence needed is the relation-(ii)
  construction (§2.1) **or** a durable safety-record design; the anti-rollback
  anchor (continuity §6.6) is a **separate** obligation neither option discharges.
  Production lock recovery, production journal wiring, Timeout/NewView durability
  migration, and cross-host exclusivity remain **UNMET** gates. The design is
  **not** implementation-ready, and the §12.2/§12.3 disposition is **PARTIAL**.

### Future acceptance matrix and the single successor

§12.7 gives a future, non-executed acceptance matrix (G1…G14) with evidence levels
kept separate (unit/model → real-storage → process-death → release-binary →
power-loss); **no row is marked PASS**. The completed D12 successor is recorded as a
historical completion — D12 already executes *lock advancement without commitment →
unchanged stored baseline → reconstruction of the older lock* and retains the
standalone no-commit test, so re-proposing that characterization would be a
**duplicate** and is **withdrawn**. **[SUPERSEDED — this successor is COMPLETED; see the "D7-D13 frontier-resolution entry" below.]** As originally written, the single corrected unstarted successor was a
**design-resolution deliverable**: select and justify one of §12.7 (a)/(b) — the
production rule that supplies the protected-frontier boundary. That design-resolution is
**now complete**: **profile (a) is selected** (§12.7), the §12.2/§12.3 frontier-rule
disposition is **RESOLVED**, and the single remaining unstarted successor is instead to
**specify profile (a)'s record at implementation-design granularity** (logical layout,
cross-artifact publication/recovery protocol, initialization/opening semantics, and
retention) — documentation-only, still unstarted. D12 does not answer it
(it only demonstrated the gap). Output: the three authorized documents only
(design/specification); **no** code, **no** new characterization tests, **no**
promoted acceptance row. Production wiring, a new module/reader/persistence
format/freshness interface, a durable safety-record implementation, signer calls,
recovery-repair writes, **anchor selection**, Timeout/NewView migration, and any
activation/readiness change are **excluded**; local crash-consistency stays separate
from the independent, still-unresolved anti-rollback anchor.

### Checks performed and literal tool outcomes

* **Documentation checks (performed):** re-traced the cited symbols, callers, and
  ordering against the actual checkout (`on_qc` L1004 before `try_commit_with_qc`
  L1013; `on_leader_step` L1443/L1503; `is_safe_to_vote_on_block` L1312;
  `on_timeout_certificate`; the reservation ordering). Verified cross-section
  consistency with D10/D11/D12 and the continuity contract (§4.1, §5.3, §6).
  Checked relative links, Markdown table well-formedness, diff scope (only the
  three authorized files), CRLF line endings, and the preserved no-final-newline
  EOF. A secret scan of the changed files was run.
* **No Cargo / Clippy / release rebuild** was executed — none is required for a
  documentation-only extension, and none was run merely to produce new counts. No
  historical tool outcome is relabelled as a fresh execution.
* **Review / security tooling — prior pass (attribution corrected).** The earlier
  D13 pass's committed paragraph gave generic cautions rather than literal outcomes;
  the only retained evidence from that pass is: a reported **review
  model-availability limitation**, a **CodeQL documentation-scope skip**, and that a
  **completed independent review could not be established**. Exact tool output from
  that pass is **unavailable**; only that summary is attributed, and the
  partial/unavailable review is **not** upgraded to a completed independent review.
  This pass's own tooling outcomes are recorded separately in the correction entry
  below and are not merged with the prior pass's.

### Scoped verdict and preserved posture

```
D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
```

This means a documented contract — not an implemented protection, safety proof,
completed independent review, or activation permission.

Preserved unchanged (not reopened):
`D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED`,
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
`GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`, and the accepted D8/D10/D12
verdicts. C4/C5 remain OPEN. No production wiring, signing enablement, activation,
readiness promotion, or D14 implementation was performed. Worktree clean after
each commit; changes pushed to the task branch; **no PR** opened.

### D7-D13 correction entry (RUN 422 D7-D13 — durability-frontier / decision-binding / recovery-rules)

A later **documentation-only** correction pass revised the §12 D13 contract in
place (no PR, branch rename, force-push, rebase, history rewrite, production
implementation, activation, or Run 423 work).

* **Actual branch / revision / limitations.** Actual branch
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotr` (the task's reported
  branch `copilot/copilotcopilotcopilotcopilotcopilotcopilotrun-422-again` differs;
  the actual branch is used **unchanged**). Starting HEAD
  `6d77e5f17b43494f2db9eb87558061b25a675761`; clean worktree before and after.
  Shallow single-branch clone (count = 2; graft base `a6727feb…`). **Both** named
  reference objects are **absent** as objects here: the reviewed D13 final
  `e40d5c20ee3950da2a1ca1d0bbc57bbbcc9c6762` and the accepted D12 final
  `6ca4a72d47cc878a96bfc63b767ac893cbf22ed8` each return `git cat-file -t` → *could
  not get object info*. Object availability is reported **separately** from
  source-content correspondence, which is asserted against the current source only.
* **Changed documents (authorized scope only):** the recovery contract (§12), the
  continuity contract (§5.3 cross-reference), and this evidence record.
* **Correction dispositions.** **A (frontier):** replaced the "equals/dominates the
  pre-crash lock" rule with a recovery decision against observable durable state +
  a design-level proof obligation (exact restoration **or** a restriction-preservation
  relation); defined one coherent conservative **pending-vs-effective** profile
  (PROPOSED) and named the missing integration boundary; the production frontier
  choice stays **PARTIAL**. **B (decision binding):** replaced the uniform seven-event
  sequence with per-route ordering (`ingest_proposal`, `on_leader_step`, received
  vote/QC, `on_timeout_certificate`, D10 fresh/reuse); a self-vote-generated QC must
  not retroactively justify its own vote; action types do not bind the justifying
  lock/evidence today. **C (recovery):** corrected safety-ahead (refuse only on
  unavailable/inconsistent evidence, never a number), the former G8 (interruption
  after safety persistence before a reservation may proceed), lost-ack vs
  observable records, and made common gates explicit. **D (inventory/storage):**
  fixed `HotStuffStateEngine::on_vote` vs `BasicHotStuffEngine::on_vote_event`,
  `set_locked_qc` direct-assign (caller-enforced guard), and added the
  atomicity-vs-durability table (`put_block`/`put_qc`/`put_last_committed` and
  `apply_epoch_transition_atomic` are not sync barriers; vs
  `put_current_epoch_synced`/`flush_epoch_durable`/D10 synced writes). **E
  (successor):** withdrew the duplicate-D12 characterization and named exactly one
  unstarted **design-resolution** successor (resolve §12.7 (a)/(b)).
* **This pass's tooling outcomes (kept separate from the prior pass).** Documentation
  checks were performed (symbol/caller/ordering re-trace against the checkout;
  cross-section and cross-document consistency; link/table/diff-scope/secret/CRLF/EOF
  checks; secret scan of the changed files). No Cargo/Clippy/release build or new
  test count was run or required. The available automated review and CodeQL scan were
  attempted once for this documentation-only change. Literal outcomes: **CodeQL** —
  **skipped** (declared trivial; three Markdown files, no code). **Automated review**
  — the wrapper returned **"no review comments" over 3 files**, but with a
  **model-availability note** (`model claude-sonnet-4.6 not found in registry`), so a
  **completed independent review could not be established** for this pass either.
  These are recorded as returned and are **not** merged with, or used to upgrade, the
  prior pass's partial/unavailable review.
* **Scoped verdict.** `D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED`
  for the coherent, source-backed scoped contract, with the §12.2/§12.3 frontier
  decision disposition **PARTIAL at that pass** (subsequently **RESOLVED** — profile (a) — in the frontier-resolution entry below). Preserved unchanged: D8/D10/D12 verdicts,
  `D7D11_…=DEFINED-NOT-IMPLEMENTED`, `D7_STATUS=PARTIAL-CODE-TEST /
  PRODUCTION-LIFECYCLE-UNAVAILABLE`, `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`,
  `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
  `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
  `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
  `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. C4/C5 remain OPEN; no readiness
  promotion or D14 implementation.

### D7-D13 frontier-resolution entry (RUN 422 D7-D13 — select profile (a); close surviving-write)

A later **documentation-only** pass executed the single design-resolution successor
that the prior D13 entry had named (resolve §12.7 (a)/(b)). No Rust, test, dependency,
storage key/schema, persistence format, wire format, CLI flag, configuration,
workflow, signing-preimage, or activation change was made or proposed for
implementation. No PR, branch rename, force-push, rebase, history rewrite, production
implementation, activation, or Run 423 / D14 work was performed.

* **Actual branch / revision / object availability.** Actual branch
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-again`, used
  **unchanged** (the task's reported branch
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotr` differs). Starting
  HEAD `fd6a167b99bfe1ce511c10f0be2c1f9eefba5118`; clean worktree before this pass;
  final pushed SHA is the last commit on the branch. The task's reviewed revision
  `9b56dc04ae5d989afef6fee6cdf1ddf172867652` **is** available here (fetched on
  demand): `git cat-file -t 9b56dc04…` → `commit`, its tree content is **identical**
  to the starting worktree (`git diff --stat 9b56dc04 HEAD` is empty), yet it is
  **not** an ancestor of HEAD (`git merge-base --is-ancestor` fails). Content
  correspondence is reported **separately** from ancestry; ancestry is **not**
  manufactured from content equality. `task/warning.txt`, unrelated work, and each
  file's CRLF / no-final-newline convention were preserved.
* **Changed paths (authorized scope only).** `…RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
  (owner §12.1/§12.2/§12.3/§12.5/§12.7/§12.8),
  `…PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` (§5.3 cross-reference only),
  and this evidence record. `docs/whitepaper/contradiction.md` inspected read-only;
  not edited.
* **Selected frontier rule and why.** **Profile (a)** — a durable, recoverable
  **safety-restriction record** persisted at each **effective** lock raise (lock id +
  view + supporting QC/TC evidence + network/genesis/validator context), with a
  stated atomicity + ordering rule relative to D10's reservation/result writes. It is
  the §12.2 relation (i). Selected over the relation-(ii) reconstruction rule
  (profile (b)) because the existing committed-QC reconstruction has the
  **demonstrated D12 gap** (it can be strictly lower-view and admit a candidate the
  pre-crash lock refused) and relation (ii) has **no** supplied construction, inputs,
  or preservation argument (a higher view / valid QC / committed height / epoch /
  checksum is **not** that argument).
* **Publication / acknowledgement / installation / signing ordering.** Distinct
  events: compute transition → publish recoverable record+evidence → receive
  **durability acknowledgement** (the linearization point; the restriction becomes
  irrevocable and **effective** here) → install in-memory → admit a dependent
  decision → reserve (D10 synced) → sign. Before the acknowledged-durable point the
  reserve/sign/retain/confirm steps that depend on the newly raised restriction are
  **blocked**; a readable byte is never an acknowledged write (INV-R7).
* **Surviving-write recovery outcomes (observable inputs only).** The §12.3 schedule
  (L0 → compute L1 → record partly/fully reaches storage → crash before ack/install →
  restart reads surviving records) is closed by a compact matrix over observable
  inputs (SW-1…SW-8, reconciled to §12.5 rows D13-13/14/15): no new record → resume L0;
  incomplete/malformed/mismatched publication → refuse; a valid complete surviving
  record with no process-local ack knowledge → complete it **only after** the PROPOSED
  safety-state durability operation (a synced re-publication; interface does **not**
  exist today and must **not** reuse the epoch/journal synced APIs) confirms it;
  operation succeeds → effective; operation fails/uncertain → refuse (fail-closed);
  valid safety state with no new D10 reservation → may proceed (D13-12/G8); recovered
  `Reserved` → potentially-signed, refuse re-sign; recovered `Signed` → exact resend,
  zero signer calls. The illustrative schedule is kept **separate** from the recovery
  inputs. The prior "exact pre-crash restoration is the only reachable case" claim is
  **corrected**: a surviving valid publication is also reachable.
* **Decision-binding corrections (stale instructions eliminated).** Removed the
  instruction to bind the justifying lock/evidence **at construction** from the §12.1
  originating-action row and the §12.3 originating-action integration bullet; the
  binding is now to the **route-specific decision/eligibility point** (the lock that
  justified the vote/proposal), while the **originating view** stays fixed at
  construction. A self-vote-generated QC must **not** retroactively justify its own
  vote; per-route points (`ingest_proposal` safe-vote check before the self-vote;
  `on_leader_step` parent/justification + Proposal before its self-vote;
  `on_vote_event`; `on_timeout_certificate`) are kept distinct, and action types do
  **not** carry the lock/evidence they justified.
* **Storage atomicity / durability / publication and remaining interface gaps.**
  Re-verified against the checkout: `put_block`/`put_qc`/`put_last_committed` use
  ordinary `db.put` (no `set_sync`); `apply_epoch_transition_atomic` uses a
  same-database `WriteBatch` via `db.write` (atomic, **not** synced);
  `put_current_epoch_synced` sets sync; `flush_epoch_durable` flushes the WAL. The
  §12.5 parenthetical that presented **ordered separate operations** as satisfying
  cross-artifact atomicity is **removed**: where record + supporting evidence cannot
  be co-located, a **specified publication/recovery protocol** is required (ordered
  separate writes do not satisfy atomicity), else the case is **unsupported**. No
  safety-state persistence interface exists today; the §2 inventory carries no
  blanket "synced" attribution over the unsynced committed-QC path.
* **Cross-document reconciliation and the single unstarted successor.** Owner updated
  first; continuity §5.3 reconciled to the selected rule; this evidence entry records
  it. The named design-resolution successor (select (a)/(b)) is now **completed** and
  is **not** left as the next task. Exactly **one** new bounded successor is named
  (§12.7): **specify profile (a)'s record at implementation-design granularity** —
  logical record layout, the non-co-located cross-artifact publication/recovery
  protocol (or mark unsupported), first-initialization-vs-open semantics, and
  retention/pruning — documentation-only, three authorized files, no code, no
  promoted acceptance row, no anchor selection, no new characterization tests, no
  activation. Local ordinary-crash consistency stays **separate** from whole-copy
  rollback; the anti-rollback anchor remains unresolved and is **not** part of it.
* **Checks executed and literal tooling outcomes (this pass).** Re-traced the cited
  symbols/callers/ordering against the checkout (`on_qc` sets `locked_qc` ~L1004
  before `try_commit_with_qc` ~L1013; `on_leader_step` view ~L1443 / header fixed
  ~L1503–1504; `is_safe_to_vote_on_block` ~L1312; `on_timeout_certificate`
  `set_locked_qc`; the storage durability facts above). Cross-section and
  cross-document consistency reviewed; every recovery row walked using only its stated
  observable inputs; Markdown table/link/reference, diff-scope, whitespace, CRLF, and
  no-final-newline EOF checks performed; secret scan of the changed files run. No
  Cargo / Clippy / release build or new test count was run or is required for a
  documentation-only change. Available automated review / CodeQL tooling outcome for
  this pass is recorded verbatim below; a skipped CodeQL is not a completed scan, and
  an unavailable or errored reviewer is not a completed independent review.
* **Scoped verdict.** `D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED`.
  The **frontier-rule decision is now RESOLVED** (profile (a) selected and justified;
  surviving-write case closed; decision binding per-route; storage/publication
  requirements mutually consistent), so the frontier **design** is coherent; but the
  record is **not** implemented (no persistence interface) and the token therefore
  stays DEFINED-NOT-IMPLEMENTED — it implies no implemented protection, empirical
  durability, independent review, or activation. Preserved unchanged:
  `D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`,
  `D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE`,
  the accepted D10 A–E verdicts,
  `D7D12_LOCK_RECOVERY_CHARACTERIZATION=COMPLETE-FOR-TESTED-SCOPE`,
  `D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED`,
  `D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE`,
  `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
  `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
  `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
  `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
  `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. C4/C5 remain OPEN; no readiness
  promotion or D14 implementation. Worktree clean after each commit; changes pushed to
  the task branch; **no PR** opened.
* **Automated review / CodeQL — literal outcome (this pass, kept separate from prior
  passes).** **CodeQL:** **skipped** — declared trivial (three Markdown files, no
  code); a skipped scan is **not** a completed CodeQL analysis. **Automated review:**
  the wrapper reported **"No review comments found"** over **3 files**, but also
  returned a **model-availability error** (`model claude-sonnet-4.6 not found in
  registry`) and noted the **review tool is not available in this environment**, so a
  **completed independent review could not be established** for this pass either. The
  outcome is recorded exactly as returned and is **not** upgraded to a completed
  independent review, nor merged with prior passes.

### D7-D13 recovery-table / evidence reconciliation entry (RUN 422 D7-D13 — D13-5 / G7 / SW-2; storage attribution; evidence supersession)

A later **documentation-only** correction pass resolved the three remaining review
findings in place (no PR, branch rename, force-push, rebase, history rewrite, code,
test, dependency, schema, CLI, configuration, workflow, cryptographic,
production-wiring, activation, or Run 423 / D14 work). Profile (a) selection and the
single unstarted record-design successor are preserved; (a)/(b) is **not** reopened,
D12 is not repeated, and the record is neither implemented nor its design begun.

* **Actual branch / revision / object availability.** Actual branch
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-another-one`, used
  **unchanged** (the task's reported branch
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-again` differs; the
  supplied task branch is used as-is). Starting HEAD
  `5da2820f8a40b3819cd86cfeb6b7788bcfa2ea02`; clean worktree before this pass; the
  final pushed SHA is the last commit on the branch. Shallow single-branch clone
  (`git rev-list --count HEAD` = 2; graft base `fd6a167b…`). The task's reviewed
  revision `bf9420eeb360419f98681674d356a1453fbe17fd` was **absent** as an object on
  open and became available only after an on-demand `git fetch --depth=1`; it then
  resolves (`git cat-file -t bf9420…` → `commit`) and its tree content is
  **identical** to the starting worktree (`git diff --stat bf9420… HEAD` empty),
  yet it is **not** an ancestor of HEAD (`git merge-base --is-ancestor` fails).
  Content correspondence is reported **separately** from ancestry; ancestry is
  **not** manufactured from content equality. `task/warning.txt`, unrelated work, and
  each file's CRLF / no-final-newline convention were preserved.
* **Changed paths (authorized scope only).**
  `…RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md` (§2 inventory row,
  §12.1 QC row, §12.3 SW-2 + protected-frontier paragraph, §12.5 D13-5,
  §12.7 G7) and this evidence record. The continuity contract's §5.3
  cross-reference was inspected and **left unchanged** (already accurate: profile (a)
  selected, per-route decision binding, recovery against observable durable state,
  surviving-write closed, DEFINED-NOT-IMPLEMENTED, anchor separate/unresolved).
  `docs/whitepaper/contradiction.md` was not touched.
* **A — observable recovery decisions.** **D13-5** no longer presents a former
  caller's "uncertain writes (no acknowledged barrier)" as an observable durable
  state; it is re-expressed by **phase**: a live operation knows its **own** failed /
  uncertain write (fails closed then); a restarted process **cannot** observe a former
  caller's acknowledgement and therefore decides only from observable inputs —
  recovered record validity/completeness (D13-4/D13-13) and the outcome of its **own**
  current recovery durability operation (D13-14 success / D13-15 fail-or-uncertain;
  §12.3 SW-3…SW-5) — with no unconditional refusal on an unobservable former
  acknowledgement. **G7** is aligned to the selected recovery rule
  (incomplete/malformed/mismatched/unavailable publication → REFUSE; valid surviving
  publication → no protected use before the **current** recovery barrier; barrier
  succeeds → remaining S2–S5 / frontier / D10 prerequisites; barrier
  fails/uncertain → REFUSE; an illustrative crash location frames the schedule but
  is **not** an input to the restarted process); **G8** and D10/D13-12 are preserved.
  **SW-2** states the refusal scope explicitly (blocks protected signing **and**
  retained-result reuse; "keep L0" = preserve existing durable evidence, **not**
  permission to fall back to L0 and continue signing; no delete/repair/overwrite/
  discard; SW-1's valid-prior-state case unaffected; all shared recovery /
  authorization / freshness / exclusivity / D10 gates intact).
* **B — storage durability attribution (re-verified against the checkout).**
  `apply_epoch_transition_atomic` (`storage.rs` ~L1110) commits a same-database
  `WriteBatch` via `db.write` (~L1163) with **no** `set_sync` (atomic, **not** a
  durability barrier); the D7-D8 restore-completion path
  (`persist_restored_snapshot_epoch_durable`, `production_consensus_storage.rs` ~L716)
  uses `put_current_epoch_synced` (`WriteOptions::set_sync(true)`, ~L1042) /
  `flush_epoch_durable` (`flush_wal(true)`, ~L1071). The §2 current-epoch row no
  longer carries a blanket "synced" attribution over both producers. The §12.1 QC
  row now states that ordinary `put_block`/`put_qc`/`put_last_committed` (`db.put`,
  no `set_sync`) persist bytes **without** an acknowledged sync barrier. §12.3's
  "the only durability is incidental" is replaced by a distinction between
  **incidental** committed-state persistence/reconstruction and the **absent**
  dedicated, acknowledged safety-state durability channel. The §12.5
  atomicity-vs-durability table remains authoritative and consistent.
* **C — evidence reconciliation.** Three stale passages in the earlier D13 summary
  were marked **superseded in place** with cross-references to the current rule: the
  uniform receive → update-lock → construct-action sequence (corrected to per-route
  decision binding, §12.3); the broad safety-ahead refusal (corrected — being ahead
  is **not** itself a refusal reason; §12.5 D13-8; matrix now D13-1…D13-15); and the
  "unresolved (a)/(b) / disposition PARTIAL" status and the "select and justify one of
  (a)/(b)" successor (profile (a) is selected; the remaining successor is to specify
  profile (a)'s record at implementation-design granularity, still unstarted). Each
  passage is labelled as **corrected**, not as technically correct at its original
  revision. Genuine historical facts (revision identities, commands/counts, executable
  identities, tool outcomes and execution limitations) are preserved.
* **Checks executed (this pass).** Source verification of the changed storage claims
  against `storage.rs` / `production_consensus_storage.rs`; cross-section and
  cross-document consistency (§2 / §12.1 / §12.3 / §12.5 / §12.7 and the
  continuity §5.3 cross-reference); each affected recovery row (D13-5, SW-2, G7)
  walked using only its stated observable inputs; confirmed SW-2 cannot authorize
  fallback signing; confirmed no remaining operative uniform ordering, blanket sync
  claim, or unresolved (a)/(b) status; Markdown table column counts and links,
  diff-scope (two files; continuity unchanged), whitespace, CRLF, and no-final-newline
  EOF verified; secret scan of the changed files run (none detected). No Cargo /
  Clippy / release build or new test count was run or is required.
* **Automated review / CodeQL — literal outcome (this pass, kept separate from prior
  passes).** **CodeQL:** **skipped** — declared trivial (documentation-only; no code);
  a skipped scan is **not** a completed CodeQL analysis. **Automated review:** the
  wrapper reported **"No review comments found"** over the changed files but also
  returned a **model-availability error** (`model claude-sonnet-4.6 not found in
  registry`) and that the **review tool is not available in this environment**, so a
  **completed independent review could not be established** for this pass either. The
  outcome is recorded exactly as returned and is **not** upgraded to a completed
  independent review, nor merged with prior passes.
* **Scoped verdict and preserved posture.**
  `D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED` (the
  frontier-rule decision stays **RESOLVED** — profile (a) — with the record
  **not** implemented and its detailed design **unstarted**). Preserved unchanged:
  the accepted D8/D10/D12 dispositions,
  `D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED`,
  `D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED`,
  `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
  `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
  `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
  `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
  `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. C4/C5 remain OPEN; no readiness
  promotion or D14 implementation. Worktree clean after each commit; changes pushed to
  the task branch; **no PR** opened.

## Run 422 D7-D14 — Recoverable consensus safety record (profile (a) implementation-design, documentation only)

This section records the D7-D14 **documentation-only** pass that executes the single
§12.7 successor: it specifies the D13-selected **profile (a)** safety-restriction
record at **implementation-design** granularity (contents, operations, publication/
recovery, ownership, engine/D10 binding, retention/capacity). No Rust, test,
dependency, actual storage key/schema, concrete serialized persistence/wire format,
signing preimage, CLI, configuration, workflow, production wiring, or activation
change was made or proposed for implementation. The (a)/(b) choice is **not**
reopened and D12 is **not** repeated. No PR; no branch rename, force-push, rebase,
history rewrite, or Run 423 / D15 work.

### Provenance and object limitations

* **Working branch (actual):**
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-yet-again`, used
  **unchanged** (no rename/rebase/force-push/history rewrite). The task's reported
  branch string `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-another-one`
  differs from the actual branch; the supplied task branch is used as-is.
* **Starting HEAD (actual):** `6b1a942ad882645691707dcfede02d510d045a61` (`update`);
  clean worktree before this pass. The final documentation + validation commit is the
  last commit on the branch (recorded in the branch history); worktree clean after.
* **Shallow, single-branch clone** (`git rev-list --count HEAD` = 2; graft/root base
  `5da2820f8a40b3819cd86cfeb6b7788bcfa2ea02`). The accepted D13 revision
  `696c30754b3fc41f401be39da03e58ae1ee2f2bd` was **absent** as an object on open
  (`git cat-file -t 696c3075…` → *could not get object info*) and became available
  only after an on-demand `git fetch --depth=1 origin 696c3075…`; it then resolves
  (`git cat-file -t` → `commit`) and its tree content is **identical** to the starting
  worktree (`git diff --stat 696c3075… HEAD` empty), yet it is **not** an ancestor of
  HEAD (`git merge-base --is-ancestor 696c3075… HEAD` fails). Reference-object
  availability and content correspondence are reported **separately** from ancestry;
  ancestry is **not** manufactured from content equality.
* `task/warning.txt`, unrelated work, and each changed file's existing line-ending /
  EOF conventions were preserved (all three changed documents remain CRLF with no
  trailing final newline).

### Changed paths (authorized scope only)

1. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
   — the **authoritative owner**: added **§13 (D14)** and the
   `D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED` header token and Run
   line; the D13 **§12 is unchanged** and remains consistent (it already names this
   record-design as its single successor).
2. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` —
   **minimal reconciliation only**: one concise §5.3 cross-reference naming §13 as the
   owner of the record design (ordering-not-spanning-transaction, one authoritative
   record with pruning disabled, DEFINED-NOT-IMPLEMENTED, anchor separate). No §4.1
   step, conflict rule, state machine, or anchor requirement changed; no competing
   contract created.
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — this evidence entry.

`docs/whitepaper/contradiction.md` was inspected **read-only** (durable anti-rollback
NOT-established; C4/C5 OPEN — unchanged) and **not** edited.

### Supported storage / publication profile and exclusions

One supported arrangement: the record **and** all required supporting material
(lock id+view, supporting QC or TC+`high_qc`, network/genesis + validator/authority
context reference) **co-located in the one canonical consensus database**, made
visible in **one atomic publication unit** = a single same-database `WriteBatch`
committed with `WriteOptions::set_sync(true)` (atomic **and** acknowledged-durable in
one `db.write(batch, sync)`). The **atomic-plus-sync pattern already exists**: D10's
`put_signing_record_and_metadata_synced` (`storage.rs` ~L1417) commits a multi-key
`WriteBatch` with `WriteOptions::set_sync(true)`; what is missing is the
**safety-state-specific** interface with validation/ownership integration (not routed
through the epoch or D10 APIs). `apply_epoch_transition_atomic`'s `db.write` (~L1163) is
atomic-but-not-synced and `put_current_epoch_synced` (~L1042) is synced-but-epoch-only
are only the narrower precedents.
**Non-co-located** publication is **explicitly unsupported** in the initial profile
(no distributed-transaction framework / second journal / two-phase commit invented).
Single local writer; `fsync`-honoured, no-silent-device-rollback (T-FS) stated as the
profile assumption, not an empirical claim. Six properties distinguished; only
**atomic visibility**, **acknowledged durability**, and **validation of contents +
transition eligibility** belong to this record — authorization/freshness (A/B),
whole-copy rollback resistance, and cross-host/copied-key exclusivity remain
**separate** and UNMET/UNRESOLVED.

### Record fields, evidence sources, bounds, and validation (summary)

The proposed bounded, versioned `SafetyRestrictionRecord` (logical; concrete byte
framing deferred to the successor) carries, each with a **named** recovery/validation
consumer: `persistence_format_version` (distinct from wire and signing-domain
versions and from D10's `SIGNING_RECORD_FORMAT_VERSION`/`SIGNING_METADATA_FORMAT_VERSION`,
`signing_reservation_journal.rs` ~L52/~L92); `network_genesis_id` + `authority_context_ref`
(**obtained independently** from the pinned `ExpectedGenesisIdentity::load_pinned`
context, compared not trusted); `lock_block_id`+`lock_view` (stored directly);
`supporting_certificate` (the **wire** QC carrying `signer_bitmap`+`signatures` — the
logical `qc.rs` QC has **no** cryptographic material; bounded by `MAX_BITMAP_LEN`=8192 /
`MAX_SIGNATURE_COUNT`=`MAX_SIGNATURE_LEN`=`u16::MAX`, `ceil(2W/3)` in `u128`; a TC whose
only form is **logical** is **not** recovery-verifiable — a named material design gap **[SUPERSEDED — see the “RUN 422 D7-D14 complete source grounding” correction entry below: a serialized `TimeoutCertificate` and a wired `verify_timeout_certificate_with_evidence` over `tc.signed_timeouts` DO exist (`timeout_verify.rs` ~L350 / `binary_consensus_loop.rs` ~L6892); the TC-derived rule is now selected as restriction-persisted / evidence-unverified, not a design gap]**);
`evidence_lock_binding` (SHA3-256 `BindingDigest` over lock+certificate+context,
recomputed on read); `committed_state_assoc` (checked against recovered committed
state); `publication_revision` (monotonic local **bookkeeping**, not an anti-rollback
anchor); `integrity_checksum` (CRC32 via `compute_crc32`/`signing_journal_crc32`,
corruption only); and `bounds_metadata` (checked lengths/arithmetic). Per-candidate
ancestry is **not** stored — supplied and checked per candidate; missing ancestry
blocks **that candidate** only. Four checks kept distinct — **structural decode**,
**evidence verification** (T-TRUST-STORAGE; not wired today; empty-signer QC is not
authentication), **context binding**, **current authorization (A/B; never granted
here)** — and the empty-signer-QC / digest-is-not-bytes / snapshot-id-is-not-authenticated /
per-candidate-ancestry source facts are carried forward so the record cannot
over-claim. Named missing integration obligations: the engine→writer boundary,
recovery-time certificate verification, the decision→evidence binding, and the
synced-atomic publication API.

### Initialization / opening and uncertainty behavior (summary)

Five distinct operations, each with inputs/preconditions/allowed-writes/success/
failure/uncertainty: **O1 initialize** (genuine absence + explicit intent + pinned
context; refuses over any existing unrelated/partial/legacy/malformed/unsupported
state; duplicate init over a survived write refused; init metadata written
**atomically with** the initial record — **always** a `BootstrapNoLock` record, never
metadata-only); **O2 open** (read-only; refuses missing /
malformed / partial / inconsistent established state; does **not** auto-initialize);
**O3 read-validate** (structural + bounds + CRC + association); **O4 publish**; **O5
re-acknowledge**. An empty directory is **not** equated with an unused validator. The
initialization layout has **two explicit variants** — `BootstrapNoLock` (lock/evidence
fields absent by variant) and `Locked` (all §13.2 fields present) — with no third
metadata-only shape; a **bootstrap no-lock** state is **representable** and **distinct
from missing**, requires the external initialization prerequisite, and fabricates **no**
QC/epoch/authorization (the first view-zero lock uses the engine's actual first
`locked_qc`, no synthetic predecessor; and no production first-use legitimacy is
established). Absence is scoped to **this component's owned namespace** (unrelated
consensus-DB namespaces need not be empty). No automatic adoption, repair, reset, or
migration.

### Recovery acknowledgement and ownership / concurrency rules (summary)

Durability contract: publication returns success only after an `fsync`-acknowledged
barrier over the whole unit; **only then** is the transition **effective** and
installed in memory, admitting dependent work. Recovery decides **only** from
observable durable records (reusing §12.3 SW-1…SW-8 and §12.5 D13-1…D13-15): a valid
complete surviving record is completed via **O5** — a **synced re-publication of
identical validated bytes**, identity established by a **complete-content** comparison
against the currently stored publication (under the owner boundary and the expected
revision, never overwriting a newer publication; **not** a CRC32-plus-`evidence_lock_binding`
equivalence — the checksum detects corruption and the binding covers selected fields,
neither establishes complete identity) before re-acknowledging, **never** a silent
repair — and returns failure on any failed/uncertain durability acknowledgement. The D13 surviving-write case is preserved: recovery **cannot**
use former-caller acknowledgement knowledge. A single in-process **safety-record
owner** (a **new** coordinator, reusing the D10 single-writer **pattern** but not its
instance) serializes validation/publish/recover/install; every O4/O5 carries the
**expected `publication_revision`** so a stale handle cannot overwrite or
re-acknowledge a newer record with an older one; after an uncertain write no dependent
signing is admitted until O2/O3/O5 re-establish state; after process death O2 rebuilds
the authoritative state from the durable record. Local ownership does **not** fence a
copied database/key on another host.

### Prepared-decision policy and D10 integration (summary)

Per-route decision binding (inbound `Proposal` → `is_safe_to_vote_on_block` ~L1810
before the self-vote; leader `on_leader_step` ~L1434 proposal built before self-vote
~L1538; received vote/QC `on_vote_event` ~L1867; TC `on_timeout_certificate` ~L2162
before the view advance; D10 fresh S6; retained reuse S7). The L0→L1 prepared-decision
policy is **explicit**: a self-vote-generated L1 is recorded **separately** and must
**not** retroactively justify the decision (decision stays bound to L0; rejected if
invalid under L0); an externally-driven effective L1 **blocks** the prepared L0
decision, **permitted only if** per-candidate revalidation against L1 passes, else
**rejected** — explicit serialization / conservative refusal, no concurrency
machinery. D10 preserved unchanged (position identity, prepared-preimage binding,
frozen ticket/context/signer, post-storage revalidation, durable reservation before
signing, one-use checked continuation, recovered `Reserved` potentially-signed,
exact retained reuse with zero signer calls, no conflict released by a safety-state
transition). A **single transaction spanning** safety + D10 writes is **not** required
— the two are related by **ordering**, and each supported crash state is independently
recoverable from the two ordered barriers (crash before the safety barrier;
after-safety-before-reservation = D13-12/G8, not unsafe; after-reservation = D10's own
invariant).

### Retention / replacement / capacity (summary)

Exactly **one** authoritative **disk** generation is retained (no disk generation
history); an outstanding prepared L0 decision that still needs its originating lock/
evidence is served by **bounded immutable in-memory** L0 evidence (D10's `BindingDigest`
cannot reconstruct L0's lock/evidence), not a second disk generation. Replacement keeps
the **storage publication** (atomic), the **caller-observed acknowledgement**, and the
**in-memory install** distinct: because the storage publication is atomic, a crash
leaves the intact predecessor **or** a complete successor (never a torn mix) — and a
complete successor may be durable **even when the caller observed an error or died
before success**, so the predecessor is **not** assumed to remain stored after an
uncertain replacement (recovery decides via O3/O5 and never discards/repairs/overwrites
a possibly-published successor); **pruning is disabled** because a safe discharge condition cannot be reduced to observable local
inputs without the unresolved anti-rollback anchor (so no undefined "prune after
discharge" rule and **no** unbounded second journal); oversize → **fail-closed**
(prior record preserved); restart preserves the bounded single-record invariant;
**D10 signing records are never pruned** by this component.

### Future acceptance matrix and the unstarted successor

The §13.8 H-matrix (H1…H23, **no row a current PASS**) covers the D12 advanced-lock
case, initialize/open/duplicate-init/uncertain-init, valid/invalid lock-evidence-context
association, size/arithmetic/version/corruption, atomic publication and partial/uncertain
outcomes, crash before ack/install, successful/failed recovery re-acknowledgement,
competing handles / stale publication, prepared L0 across L1, fresh signing vs exact
retained reuse, D10 conflict preservation, capacity/replacement/disabled pruning,
ordinary restart vs requested snapshot restore, and explicitly unsupported arrangements
— each with observable inputs, allowed/refused behavior, protected effect, and the
eventually-required evidence level (unit/model → real-storage → process-death →
release-binary → power-loss / production-authority, kept separate). **Exactly one
bounded, unstarted successor:** implement and unit/real-storage-test the co-located
single-database `SafetyRestrictionRecord` O1…O5 operations and the synced-atomic
publication unit behind a **disabled-by-default, non-production-wired** interface
(H-matrix as target cases), **without** engine integration, signer calls, anchor
selection, activation, or readiness change. It is **not** full production integration
and does not authorize it.

### Checks actually executed (this pass)

* **Source tracing** against the checkout: storage atomicity/durability APIs
  (`apply_epoch_transition_atomic` ~L1110 / `db.write` ~L1163 no `set_sync`;
  `put_current_epoch_synced` ~L1042 `set_sync(true)`; `flush_epoch_durable` ~L1071),
  CRC32 (`compute_crc32` ~L531 / `signing_journal_crc32` ~L545), SHA3-256
  `BindingDigest` (~L221), D10 record/metadata versions (~L52/~L92), `qc_verify_domain`
  bounds (`MAX_BITMAP_LEN`/`MAX_SIGNATURE_LEN`, `ceil(2W/3)` in `u128`), and the engine
  symbols reused from §12.1 (`on_qc` ~L1004, `set_locked_qc`/`on_timeout_certificate`
  ~L2162, `is_safe_to_vote_on_block` ~L1312, `on_leader_step` ~L1434/~L1538,
  `ingest_proposal` ~L1720/~L1810, `on_vote_event` ~L1867). Symbols are authoritative;
  line numbers are locators.
* **Cross-document consistency:** §13 reconciled with §12 (D13 unchanged), §5–§7, and
  the continuity §5.3 cross-reference; no competing contract; D10/D12/D13 dispositions
  preserved.
* **Recovery-state walkthroughs:** each H-row and each referenced recovery row
  (SW-3→SW-4→SW-5, D13-12/13/14/15) walked using only its stated observable inputs;
  confirmed O5 republishes identical bytes (no repair) and that an uncertain write
  admits no dependent signing.
* **Link / table checks:** all four §13 tables verified column-consistent; internal
  section references (§12.2/§12.3/§12.5/§12.7, continuity §4.1/§6) resolve.
* **Diff-scope / whitespace / EOL / EOF:** three files changed (owner §13 + header,
  continuity §5.3 paragraph, this entry); all remain CRLF with no final newline;
  `task/warning.txt` and unrelated work untouched; `contradiction.md` read-only.
* **Secret scan** of the changed files: none detected.
* No Cargo / Clippy / release build / new test count / empirical durability claim was
  run or is required.

### Automated review / CodeQL — literal outcome (this pass, kept separate from prior passes)

* **CodeQL:** declared **trivial** (documentation-only; no code) and **skipped**; a
  skipped scan is **not** a completed CodeQL analysis.
* **Automated review:** attempted once. The wrapper reported **"No review comments
  found"** over the three changed files but also returned a **model-availability error**
  (`model claude-sonnet-4.6 not found in registry` / `Code review tool is not available
  in this environment`), so a **completed independent review could not be established**
  for this pass. The outcome is recorded exactly as returned and is **not** upgraded to a
  completed independent review, nor merged with prior passes; a skipped or unavailable
  tool is **not** a pass.

### Scoped verdict and preserved posture

```
D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED
```

A coherent, source-backed **specified component design** — concrete component-level
choices, a named consumer per field, four separated checks, observable-input recovery,
D10 and the D13 surviving-write case preserved, and stated exclusions — implemented by
**nothing**. No material **record-design** requirement is left unresolved; the
anti-rollback anchor, whole-copy rollback resistance, cross-host exclusivity, and
recovery-time certificate verification are **separate** prerequisites tracked
elsewhere, explicitly out of scope. Preserved unchanged (not reopened):

```
D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain OPEN. No production signing enablement, anchor selection, readiness
promotion, D15 implementation, or Run 423 work. Worktree clean after the commit;
changes pushed to the actual task branch; **no PR** opened.

## Run 422 D7-D14 correction pass — Resolve safety-record design findings (documentation only)

This entry records the bounded **documentation-only** correction pass that resolved the
five D14 design findings and the storage-inventory correction **in place** in the
authoritative § 13, reconciled the continuity cross-reference, and updated this
evidence. O1–O5 were **not** implemented and D15 was **not** started. Prior D14 history
(SHAs, counts, artifact identities, tool outcomes) above is **preserved**, not
rewritten.

### Provenance and object limitations (this pass)

* **Working branch (actual):** `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-one-more-time`,
  used **unchanged** (no rename/rebase/force-push/history rewrite). The task's reported
  branch `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-yet-again` differs
  from the actual branch; the supplied task branch is used as-is.
* **Starting HEAD (actual):** `a83d673ff5bc12404955f6fb048c62fbd0c49440` (`update`);
  clean worktree before this pass (`git rev-list --count HEAD` = 2; root/graft base
  `6b1a942ad882645691707dcfede02d510d045a61`).
* **Reference object.** The reviewed D14 revision
  `a646e29ab68e3dc393221209389b589bd1804f9a` was **absent** as an object on open
  (`git cat-file -t a646e29…` → *could not get object info*) and became available only
  after an on-demand `git fetch origin a646e29…`; it then resolves
  (`git cat-file -t` → `commit`) and its tree content is **identical** to the starting
  worktree for the three changed documents (`git diff --stat a646e29… HEAD` empty), yet
  it is **not** an ancestor of HEAD (`git merge-base --is-ancestor a646e29… HEAD` fails).
  Object availability, content correspondence, and ancestry are reported **separately**;
  ancestry is **not** manufactured from content equality.
* `task/warning.txt`, `task/RUN_422_TASK.txt`, and unrelated work were **preserved**;
  each changed file keeps its CRLF line endings and no-final-newline EOF convention.

### Changed paths (authorized scope only)

1. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
   — authoritative owner: corrections A–E and the storage-inventory correction applied
   **in place** in § 13 (§ 13.1–§ 13.9).
2. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` — the one
   § 5 D14 cross-reference reconciled (complete-content O5 identity; atomic-plus-sync
   pattern exists in D10; one disk generation + bounded in-memory L0 evidence). No § 4.1
   step, conflict rule, state machine, or § 6 anchor requirement changed.
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — in-place summary corrections and
   this entry.

`docs/whitepaper/contradiction.md` was inspected **read-only** (durable anti-rollback
NOT-established; C4/C5 OPEN) and **not** edited.

### A–E dispositions and the storage-inventory correction

* **A — Exact O5 identity (RESOLVED).** Removed every statement equating byte-for-byte
  equality with matching `integrity_checksum` + `evidence_lock_binding`. O5 now receives
  the **complete** recovered publication, the independently supplied context, and the
  expected revision; compares the **complete authoritative content** against the
  **currently stored** publication under the owner/serialization boundary; refuses stale
  or mismatched input; republishes identical bytes **without** changing revision,
  initialization state, association fields, or supporting material; returns **failure**
  on failed/uncertain durability acknowledgement; and cannot overwrite a newer
  publication between comparison and re-publication. CRC32/digest retained as
  **additional** checks only; no new cryptography.
* **B — Prepared L0 evidence vs single-record retention (RESOLVED).** One disk
  generation remains; an outstanding prepared L0 decision carries **bounded immutable
  in-memory** L0 evidence for its own lifetime (D10's `BindingDigest` cannot reconstruct
  L0's lock/evidence — `signing_reservation_journal.rs` ~L190/~L281). Defined: what is
  retained/referenced and for how long; same-event self-vote L1 keeps the captured L0
  eligibility; external L1 blocks then revalidates the exact candidate; pending/uncertain
  publication blocks protected work; nothing volatile survives process death; and
  authoritative-record replacement is safe because no consumer reads a superseded L0
  **disk** record. No failure authorizes fallback L0 signing; D10 records untouched.
* **C — Publication vs acknowledgement (RESOLVED).** Removed
  “atomic-after-acknowledgement” as the description of stored replacement; distinguished
  validation, **atomic storage publication**, **caller-observed acknowledgement**,
  **in-memory install**, and **recovery's own durability acknowledgement**. A complete
  successor can survive a missing acknowledgement; a crash before acknowledgement is
  **not** universally “nothing to reconcile”; “uncertain bytes” is not a stored format; a
  live uncertain result blocks dependent work; the predecessor is not assumed to remain
  stored; a possibly-published successor is neither discarded, repaired, nor overwritten.
  Reconciled § 13.5–§ 13.7, INV-D14-5, and H8/H9/H16.
* **D — Evidence, semantic checks, and bounds (RESOLVED, with one named gap).** The
  persisted `supporting_certificate` is the **wire** QC (`signer_bitmap`+`signatures`);
  the logical `qc.rs` QC carries **no** cryptographic material and cannot be the stored
  evidence. Empty-signer certificates are refused **structurally** (stage 1 threshold),
  resolving the O3/H6 conflict; an **unverified** stored certificate is carried as
  unverified and never satisfies a verified-evidence prerequisite; O5's “effective” is a
  durability (not authentication) result. `committed_state_assoc` comparison defined
  (anchor present on recovered committed chain; committed progress allowed; refuse when
  unestablished). “Fixed maxima” replaced with concrete constants (`MAX_BITMAP_LEN`=8192,
  `MAX_SIGNATURE_COUNT`/`MAX_SIGNATURE_LEN`=`u16::MAX`, 32-byte ids/digests, checked `u64`
  revisions) and the honest allocation-bound note (`MAX_AGGREGATE_SIGNATURE_BYTES`
  ≈ 4.29 GB is not a buffer size; the real cap is validator-set-derived). **Named
  material design gap:** no wire `TimeoutCertificate` / `signed_timeouts` verifier exists,
  so a logical-only TC-derived lock is not recovery-verifiable — the successor must
  persist the wire `high_qc` or refuse TC-derived locks on recovery (no invented
  signatures). **[SUPERSEDED — see the “RUN 422 D7-D14 complete source grounding” correction entry below: a serialized `TimeoutCertificate` and a wired `verify_timeout_certificate_with_evidence` over `tc.signed_timeouts` DO exist (`timeout_verify.rs` ~L350 / `binary_consensus_loop.rs` ~L6892); the TC-derived rule is now selected as restriction-persisted / evidence-unverified, not a design gap]** The absence-of-verifier premise was **incorrect**: a wired
  TC/`signed_timeouts` evidence verifier exists; the corrected rule carries TC-derived
  evidence **unverified** while enforcing the restriction (no new verifier invented).
* **E — Coherent bootstrap/initialization (RESOLVED).** One layout: initialized
  metadata is **never** written without an associated record. Two explicit variants
  (`BootstrapNoLock` / `Locked`) with required/absent fields each; initial revision with
  checked increments and wrap-→-refuse; first view-zero lock uses the engine's actual
  first `locked_qc` (no fabricated predecessor QC); O2/O3/O5 defined per variant;
  duplicate and survived-but-unacknowledged initialization handled; absence scoped to
  this component's **owned** namespace; `initialize` and `open` kept separate; no
  adoption/repair/reset/migration.
* **Storage-inventory correction (APPLIED).** `storage.rs::put_signing_record_and_metadata_synced`
  (~L1417) already commits an atomic `WriteBatch` with `WriteOptions::set_sync(true)`, so
  the claim that no existing mechanism combines atomicity and sync is **corrected**: the
  missing element is the **safety-state-specific** interface plus its validation/ownership
  integration, not the atomic-plus-sync pattern. Safety records are **not** routed through
  the epoch or D10 APIs.

### Selected design rules (operative)

Co-located single-database profile; one atomic-plus-sync safety-scoped publication unit
(pattern exists, interface missing); wire-QC supporting evidence; four separated checks
(structural / evidence verification / context binding / current authorization) plus the
distinct durability-acknowledgement and eligibility levels; complete-content O5
re-acknowledgement; single-writer ownership with an expected-revision fence; one disk
generation + bounded in-memory L0 evidence; pruning disabled; two initialization
variants; D10 preserved by ordering, not a spanning transaction.

### Remaining material gaps and the single successor

The **TC recovery-verifiability** sub-case is the one named record-design obligation
left to the successor (persist the wire `high_qc`, or refuse TC-derived locks on
recovery). Separate prerequisites remain out of scope: the durable **anti-rollback
anchor** (UNRESOLVED), whole-copy rollback resistance and cross-host/copied-key
exclusivity (UNMET), and recovery-time certificate-verification wiring (stage 2).
Exactly **one** bounded, unstarted successor is retained: implement and
unit/real-storage-test the O1–O5 operations and the safety-scoped synced-atomic
publication interface behind a disabled-by-default, non-production-wired interface,
resolving the TC obligation, **without** engine integration, signer calls, anchor
selection, activation, or readiness change. Not executed here.

### Future acceptance (requirements, not executed tests)

Added/updated future cases for: a complete identity change **outside**
`evidence_lock_binding` (caught only by complete-content comparison, not CRC+binding); a
**stale** O5 against a newer publication (refused, no older-over-newer overwrite);
outstanding **L0 evidence** during an L1 replacement (served by bounded in-memory
evidence, revalidated or rejected); a **complete publication surviving a missing
acknowledgement** (O5 re-acknowledges; not “nothing to reconcile”); a certificate/lock
**mismatch despite valid CRC and recomputed digest** (refused — digest is not semantic
correspondence); **verified vs unverified** outcomes (unverified never satisfies a
verified prerequisite); **committed-state** comparison failures (refuse when
unestablished); **bootstrap / view-zero / duplicate / survived** initialization; and
**bounds / revision exhaustion** (checked, wrap-→-refuse). These are future requirements.

### Checks executed and literal tool outcomes (this pass)

* **Source/type/API checks** against the checkout: `put_signing_record_and_metadata_synced`
  (`storage.rs` ~L1417, atomic `WriteBatch` + `set_sync(true)`); logical QC
  (`qc.rs` — `block_id`/`view`/`signers`, no crypto) vs wire QC
  (`qbind-wire/src/consensus.rs` — `signer_bitmap`/`signatures`/`suite_id`);
  `verify_quorum_certificate_with_domain` consumes the **wire** QC
  (`qc_verify_domain.rs`); **[SUPERSEDED — see the “RUN 422 D7-D14 complete source grounding” correction entry below: a serialized `TimeoutCertificate` and a wired `verify_timeout_certificate_with_evidence` over `tc.signed_timeouts` DO exist (`timeout_verify.rs` ~L350 / `binary_consensus_loop.rs` ~L6892); the TC-derived rule is now selected as restriction-persisted / evidence-unverified, not a design gap]** a serialized `TimeoutCertificate` (`timeout.rs` ~L232) and the `verify_timeout_certificate_with_evidence` verifier over `tc.signed_timeouts` DO exist (the earlier “no verifier” statement is corrected);
  `BindingDigest`/`SigningDecisionRecord` (`signing_reservation_journal.rs` ~L190/~L281);
  bound constants `MAX_BITMAP_LEN`/`MAX_SIGNATURE_LEN`/`MAX_SIGNATURE_COUNT`/
  `MAX_AGGREGATE_SIGNATURE_BYTES`.
* **Cross-document consistency:** § 13 reconciled internally (field table, four checks,
  O1–O5, § 13.5–§ 13.9, INV-D14-x, H-matrix) and with the continuity § 5 cross-reference;
  D10/D12/D13 dispositions preserved; stage numbering (1–4) kept stable.
* **Observable-state / field-consumer / bound walkthroughs, links/tables, scope,
  whitespace, EOL/EOF, secrets:** all three files remain CRLF with no final newline;
  tables column-consistent; no secret introduced.
* **No** Cargo tests, Clippy, or release rebuild run or claimed.
* **Automated review / CodeQL:** attempted once where appropriate; outcomes recorded
  literally and **separately** from history. A skip, unavailable tool, model error, or
  “no comments” wrapper is **not** a completed independent review.

### Status (stated separately)

All **five** findings (A–E) and the storage-inventory correction are **resolved** in
the authoritative § 13, with **one** named remaining record-design obligation (TC
recovery-verifiability) left to the successor. Implementation readiness is **not**
justified by this pass: the token below marks a defined-not-implemented design, not
acceptance; O1–O5 remain unimplemented and the separate prerequisites remain open.

```
D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED
```

Preserved restrictions (unchanged): D8/D10/D11/D12/D13 dispositions; profile (a); the
co-located canonical-consensus-DB arrangement; non-co-located publication unsupported;
`D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`,
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`,
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`,
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. C4/C5 remain OPEN. No activation,
readiness promotion, anchor selection, D15 implementation, or Run 423 work.
`task/warning.txt` and unrelated work preserved; worktree clean after the commit;
changes pushed to the actual task branch; **no PR** opened.

## Run 422 D7-D14 — complete source grounding, bootstrap rules, and component bounds (correction pass, documentation only)

This entry records the bounded **documentation-only** pass that completes the D7-D14
source grounding in the authoritative § 13, correcting the five findings A–E **in place**,
reconciling the continuity cross-reference, and updating this evidence. O1–O5 were **not**
implemented and D15 was **not** started. All prior D14 history above (SHAs, counts,
artifact identities, tool outcomes) is **preserved**; the superseded "no TC verifier"
claims above are **annotated in place**, not rewritten as if originally correct.

### Provenance and object limitations (this pass)

* **Working branch (actual):** `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-please-work`,
  used **unchanged** (no rename/rebase/force-push/history rewrite). The task's reported
  branch `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-one-more-time` differs
  from the actual branch; the supplied task branch is used as-is.
* **Starting HEAD (actual):** `9edd44d945642ff64cf2e4fa29be34c0fbb5f441` (`update`); clean
  worktree before this pass.
* **Reference object.** The reviewed revision `e58eaded78c8dcca5fe0a2d928deee16d1c7a1e9`
  was **absent** as an object on open (`git cat-file -t e58eade…` → *could not get object
  info*) and became available only after an on-demand `git fetch origin e58eade…`; it then
  resolves (`git cat-file -t` → `commit`), and its content for the three changed documents
  is **identical** to the starting worktree (`git diff e58eade… HEAD --` over the three
  paths empty), yet it is **not** an ancestor of HEAD
  (`git merge-base --is-ancestor e58eade… HEAD` fails). Object availability, content
  correspondence, and ancestry are reported **separately**; ancestry is **not**
  manufactured from content equality.
* `task/warning.txt`, `task/RUN_422_TASK.txt`, and unrelated work were **preserved**; each
  changed file keeps its CRLF line endings and no-final-newline EOF convention.

### Changed paths (authorized scope only)

1. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md` —
   authoritative owner: corrections A–E applied **in place** in § 13 (§ 13.2 field table,
   new § 13.3A predicate table + TC rule, § 13.3 stage-3, § 13.4 O3 inputs + variants,
   § 13.6 TC row, § 13.7 retention/capacity/pruning, § 13.8 invariants + H24–H27, § 13.9).
2. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` — the one § 5
   D14 cross-reference reconciled (TC verifier exists / restriction-unverified, explicit
   predicates, checked size cap, bootstrap/no-commit). No § 4.1 step, conflict rule, state
   machine, or § 6 anchor requirement changed.
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` — in-place superseded-claim
   annotations and this entry.

`docs/whitepaper/contradiction.md` was inspected **read-only** (durable anti-rollback
NOT-established; C4/C5 OPEN) and **not** edited.

### Correction A — TC source inventory repaired; evidence rule selected

The claim that no TC/`signed_timeouts` verifier exists is **corrected**. Traced in the
executable code (not stale module comments): `TimeoutCertificate` (`timeout.rs` ~L232)
carries `signed_timeouts: Vec<TimeoutMsg>` and is a serialized/decoded type;
`verify_timeout_certificate_with_evidence` (`timeout_verify.rs` ~L350) is called over
`tc.signed_timeouts` on every inbound `NewView` **before** `engine.on_timeout_certificate`
(`binary_consensus_loop.rs` ~L6892). Stated boundaries: it verifies **timeout** signatures,
membership/quorum (`two_thirds_vp`), and the **derived `high_qc` identity**
(`high_qc_eq` = `view` + `block_id` only, ~L435); it does **not** authenticate the
embedded logical `high_qc`'s constituent votes, and establishes **nothing** about D14
persisted-record recovery, current authority, anti-rollback, or production readiness. The
absence of a `qbind-wire` `TimeoutCertificate` type does **not** imply no serialized TC or
verifier. **Selected evidence rule (§ 13.3A):** because the TC carries its `high_qc` only
in **logical** form (no constituent signatures on any path), a TC-derived lock's
**restriction** (`lock_block_id`+`lock_view`) is persisted and enforced, while its evidence
is carried **unverified** and may not satisfy any verified-evidence prerequisite —
distinguishing *persisting a restriction* from *authenticating/replaying the whole TC
view-change event*. No signatures invented, no logical→wire upgrade, no verifier added.

### Correction B — Bootstrap non-circular path and no-commit lock

`BootstrapNoLock` is a **durable no-lock restriction state**, distinct from missing state,
that governs **candidate eligibility** (under `is_safe_to_vote_on_block` a no-lock state
imposes no lock-ancestry refusal) **without** being signing authorization (A/B separate).
Non-circular path: established `BootstrapNoLock` → first bootstrap vote under no-lock
eligibility + separate A/B → **first real QC** → `on_qc` sets `locked_qc` → O4 publishes
the first `Locked` (view-zero). No genesis QC fabricated, no external certificate assumed.
A lock can form **before any commit** (`committed_height`/`committed_block` both `None`;
`run_422_d7d2_signing_state_recovery_tests::d7d12_precrash_lock_advances_via_on_vote_without_a_commit`):
a **`Locked`-with-no-commit** variant with an explicit no-commit discriminant omits
`committed_state_assoc` **by variant** — never coercing `None` to height zero or
manufacturing a committed block — kept distinct from the committed-anchor variant and from
missing/corrupt state. O1–O5 handling specified per variant (§ 13.4).

### Correction C — Semantic predicates and independent inputs

New § 13.3A names, for each association, Value A + source, independent Value B + source,
the exact predicate, the phase (stage 3 / O3), failure-or-unavailable behavior, and what a
match proves/leaves unproven: **P1** block identity (`certificate.block_id == lock_block_id`),
**P2** view (`certificate.height == lock_view`, with **`height`** the view carrier because the engine reads the wire `height` into the logical QC view — `QuorumCertificate::new(…, wire_qc.height, …)` at `basic_hotstuff_engine.rs` ~L1771 and `…, evidence.certificate().height, …` at `hotstuff_state_engine.rs` ~L866; `round` is **not** read as the view, and `height == round` holds only for locally-emitted messages, carried as an **optional** additional eligibility predicate, not a verifier guarantee — corrected D7-D14, superseding the earlier round-as-view-carrier wording), **P3** committed anchor (present on the
recovered committed chain; skipped when no-commit), **P4** context/domain
(`chain_id`/`epoch`/`suite_id` vs the pinned context). Mapping traced to the actual
wire↔logical conversion (`basic_hotstuff_engine.rs` ~L1771 and `hotstuff_state_engine.rs` ~L866, both reading the certificate `height` into the logical view; `qc_verify_domain.rs` ~L976 copies both `height` and `round` verbatim into the reconstructed Vote and does not establish which is the view),
not inferred from names. A valid CRC and a recomputed `evidence_lock_binding` are
integrity/co-publication checks and are **not** a substitute for P1–P4 (H21). O3's inputs
now include the **pinned context** and, for anchored records, the **recovered committed
baseline**; a missing independent input → the dependent predicate cannot be established →
refuse. Production startup is **not** claimed to reconstruct lock history (committed +
QC-derived lock only, D7-D2).

### Correction D — Record and outstanding-evidence bounds

`MAX_SAFETY_RECORD_BYTES` is no longer deferred: it is a **checked formula**
`FIXED_OVERHEAD + ceil(N/8) + N × S_sig` over hard-bounded parameters — `N` validator/member
count (so `signatures.len()` ≤ `N`, bitmap span `ceil(N/8)`), `S_sig` per-signature suite
length (aggregate ≤ `N × S_sig`), `FIXED_OVERHEAD` the summed fixed members + framing — with
the quorum `ceil(2W/3)` over voting power `W` kept **distinct** from the count `N`. Summed
with checked arithmetic; enforced **before** application-owned allocation/copy; the
`u16×u16` structural ceiling (≈ 4.29 GB) retained only as an honest over-read guard, and
backend-internal allocation explicitly out of this cap. Retained L0 evidence is bounded:
`MAX_OUTSTANDING_PREPARED_L0` count; per-operation = identity (32+8) + a **shared
reference** (not a certificate copy); aggregate ≤ count × per-op (shared evidence counted
once); acquired at decision time, released at end of the operation's lifetime; **refusal at
capacity** that never evicts an admitted operation's evidence or releases a D10 conflict;
all volatile across process death. No cache or generation journal added.

### Correction E — Retention, successor, status reconciled

Distinguished **unpublished preparation** (droppable, pre-submit) from **possibly-published**
state (post-submit, resolved via O2/O3/O5) — removing "acknowledged or discarded".
"Pruning disabled" now explicitly separates **authoritative replacement** (allowed; no
anchor needed), **deletion/reset of required state** (never), **release of volatile
evidence** (allowed; no anchor needed), and **D10-history pruning** (D10's own, untouched);
only superseded-historical-generation pruning is disabled, and with one disk generation
there is none to prune. No claim that local replacement or memory release requires the
anti-rollback anchor. With bounds and predicates now fixed, **all material
component-design choices are resolved**, so exactly **one** bounded, unstarted successor is
retained: the **storage-component implementation** with an explicit acceptance subset
(§ 13.8 H2–H12, H16, H18–H27), excluding engine-integration rows. The anti-rollback anchor
remains a **separate** unmet prerequisite, not something to invent or select here.

### Selected design rules (operative, this pass)

TC-derived → restriction persisted/enforced, evidence **unverified** (§ 13.3A);
bootstrap → non-circular first-QC path from a durable no-lock state; no-commit lock →
explicit `Locked`-with-no-commit discriminant (no coerced zero); semantic comparison →
explicit P1–P4 on the certificate's own fields vs independent sources (CRC/digest not a
substitute); bounds → checked `MAX_SAFETY_RECORD_BYTES` formula + bounded retained-L0
evidence.

### Remaining material design gap and the single successor

**No material record-design choice remains open.** The one named separate prerequisite is
the durable **anti-rollback anchor** (UNRESOLVED); whole-copy rollback resistance and
cross-host/copied-key exclusivity remain UNMET; recovery-time stage-2 wire-QC verification
wiring remains a named integration obligation. The single bounded, unstarted successor is
the storage-component implementation above; it is not started here.

### Checks executed and literal tool outcomes (this pass)

* **Source/type/caller verification** against the checkout: `TimeoutCertificate` +
  `signed_timeouts` (`timeout.rs` ~L232/~L244); `verify_timeout_certificate_with_evidence`
  + `high_qc_eq` (`timeout_verify.rs` ~L350/~L435); inbound NewView call over
  `tc.signed_timeouts` (`binary_consensus_loop.rs` ~L6869/~L6892);
  `on_timeout_certificate` / `set_locked_qc` (`basic_hotstuff_engine.rs` ~L2162);
  logical QC (`qc.rs` — `block_id`/`view`/`signers`) vs wire QC (`qbind-wire/src/consensus.rs`
  ~L282 — `height`/`round`/`epoch`/`chain_id`/`block_id`/`signer_bitmap`/`signatures`/`suite_id`);
  `qc_verify_domain` vote reconstruction (~L976); `header.round = current_view`
  (`basic_hotstuff_engine.rs` ~L1180); the no-commit lock test
  (`run_422_d7d2_signing_state_recovery_tests.rs` ~L1103). Symbols authoritative; line
  numbers are locators.
* **Cross-section / cross-document consistency:** § 13 reconciled internally (field table,
  § 13.3A, four checks, O1–O5, § 13.5–§ 13.9, INV-D14-x incl. new 7/8, H1–H27) and with the
  continuity § 5 cross-reference; D8/D10/D11/D12/D13 dispositions preserved; stage numbering
  (1–4) stable.
* **Walkthroughs:** bootstrap/first-lock, pre-commit (no-commit) and later-commit,
  surviving-publication/stale-O5, field-input/predicate (P1–P4), and resource-bound (size
  cap + L0 capacity) walked from stated observable inputs only.
* **Table/link/reference, scope, whitespace, EOL/EOF, secret checks:** all three files
  remain CRLF with no final newline; tables column-consistent; `task/warning.txt` and
  unrelated work untouched; no secret introduced.
* **No** Cargo tests, Clippy, or release rebuild run or claimed.
* **Automated review / CodeQL (literal, this pass, separate from history):** the
  `parallel_validation` wrapper returned **Code Review ✅ "Reviewed 3 file(s). No review
  comments found."**, but the **same output carried a backend error** —
  `Code review tool is not available in this environment: … model claude-sonnet-4.6 not
  found in registry …` with `ERROR autofind command_failed`. Per this pass's own standard a
  "no comments" wrapper emitted alongside a backend/model error is **not** a completed
  independent review; it is recorded literally as **attempted, tool unavailable (backend
  model error), no independent review obtained**. **CodeQL Security Scan ✅ "Skipped: all
  changes are trivial"** (documentation-only; declared trivial for CodeQL).
  **Secret scan:** `No secrets detected in the scanned files` across the three paths.

### Status (stated separately) and preserved verdicts

Findings **A–E are resolved** in the authoritative § 13; **no material record-design
obligation remains** (the earlier "TC recovery-verifiability" gap is dissolved by the
corrected source inventory and the selected rule). The component design is **ready for
implementation at the design level**, by the single storage-component successor; the token
marks a defined-not-implemented design, **not** acceptance, and O1–O5 remain unimplemented.
Separate prerequisites (anti-rollback anchor, rollback resistance, cross-host exclusivity,
stage-2 wiring) remain **open**.

```
D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED
```

Preserved unchanged (not reopened): D8/D10/D11/D12/D13 dispositions; profile (a); the
co-located canonical-consensus-DB arrangement; non-co-located publication unsupported.

```
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain OPEN. No activation, readiness promotion, anchor selection, D15
implementation, or Run 423 work. **Final commit SHA:** the substantive content of this
pass landed in commit `cc5c8568fe0cc24b356b406eb15ff7a51c579da1` (branch
`copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-please-work`, starting HEAD
`9edd44d945642ff64cf2e4fa29be34c0fbb5f441`); this SHA line is recorded in the immediately
following trailing metadata commit on the same branch. `task/warning.txt`
and unrelated work preserved; worktree re-checked after committing and pushing (the three
authorized documents are the only tracked changes — this is the pre-commit scope, not a
claim that an uncommitted worktree is clean); changes pushed to the actual task branch;
**no PR** opened.

## Run 422 D7-D14 — QC-view / TC-representation / bounds / recovery-input correction (this pass)

**Provenance (three observations kept separate).** Actual task branch: `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-380659ca-7af4-4d85-9e4e-2e0a4c9766b8` (used unchanged; the problem statement's reported `...-please-work` branch name was **not** the supplied branch). Starting HEAD `db95e17c485b694627e4b5b463fc649d52815d34`, worktree clean before editing. **Object availability:** the reviewed revision `37ceaefe41f6a6d0c2c696598cd0969930a76dcb` was **unavailable** in the initial shallow checkout and became fetchable only after a targeted `git fetch --depth=1`. **Content correspondence:** at that revision the three authorized documents are byte-identical to this branch's HEAD copies. **Ancestry:** `merge-base --is-ancestor` reports the reviewed object is **not** an ancestor of HEAD (exit 1). Availability, content correspondence, and ancestry are reported independently; none implies another.

**Findings corrected (operative, documentation-only).**

- **A — lock view source.** A prior D14 pass asserted the logical QC view is carried by the wire `round`. Re-tracing both conversions shows the engine reads the certificate **`height`** into the logical view: `ingest_proposal` → `QuorumCertificate::new(wire_qc.block_id, wire_qc.height, vec![])` (`crates/qbind-consensus/src/basic_hotstuff_engine.rs` ~L1771) and `register_block_with_verified_justification` → `QuorumCertificate::new(evidence.certificate().block_id, evidence.certificate().height, …)` (`crates/qbind-consensus/src/hotstuff_state_engine.rs` ~L866); `QuorumCertificate::new(block_id, view, signers)` (`qc.rs` ~L62, field `view` ~L33). P2 now binds `height == lock_view`; `height == round` is an **optional** additional eligibility predicate sourced only from local emission (`basic_hotstuff_engine.rs` ~L1503/~L1522/~L1557) and the continuity § 3 message-admission refusal — **not** a stored-record verifier guarantee (`qc_verify_domain.rs` ~L976 copies both fields verbatim and checks neither equality). A `height != round` proposed counterexample and acceptance row (H30) added.
- **B — TC representability.** `verify_timeout_certificate_with_evidence` (`timeout_verify.rs` ~L350) is wired at inbound NewView (`binary_consensus_loop.rs` ~L6892) over `tc.signed_timeouts` and verifies the timeout quorum (`two_thirds_vp`) and the derived `high_qc` **identity** (`high_qc_eq`: view+block_id), but **not** the `high_qc`'s constituent vote signatures, and it is **not** a persisted-record recovery verifier. The TC's `high_qc` is logical-only (no wire QC on any path). The field table and `Locked` variant are now a **discriminated** evidence field — `QcDerived` (wire `QuorumCertificate`) vs `TcDerived` (logical `high_qc` + retained serialized `TimeoutCertificate`, `timeout.rs` ~L232) — with wire-only predicates marked inapplicable to `TcDerived` and replaced by `high_qc` identity predicates; the TC-derived record is carried **unverified** and refuses every verified-evidence prerequisite. The unsupported "only narrows voting" claim was removed (lock replacement depends on both view and ancestry and does not preserve the eligible-candidate subset).
- **C — bounds.** `MAX_SAFETY_RECORD_BYTES` now covers both variants; `ceil(N/8)` is used **only** under an explicit dense-index profile, otherwise the identifier-span bound `MAX_BITMAP_LEN` (=8192) already demonstrated by `qc_verify_domain` (`qc_verify_domain.rs` ~L163) is used; validator count, bitmap span, signature count/bytes, and voting power `W` are kept distinct; application allocation/copy bounds stay distinct from backend allocations. Retained-L0: `MAX_OUTSTANDING_PREPARED_L0 = 2`, charging each distinct Arc-shared allocation once (reusing `VerifiedQuorumCertificate::retained_byte_size`, `qc_verify_domain.rs` ~L618, whose existing accounting does **not** cover this new superseded-generation lifecycle) while still charging handles; scope includes the current authoritative record and superseded generations pinned by outstanding operations; acquisition/release/refusal-at-capacity/uncertainty specified without evicting admitted evidence or releasing a D10 obligation. Future acceptance rows H28/H29 added.
- **D — O3 committed-history inputs & production/harness boundary.** P3 now requires an independently-supplied, **proposed** read-only committed-history relation (labelled proposed, not an existing production service); a current tip `(block_id, height)` alone cannot establish older-anchor membership. Ordinary production startup constructs a **fresh** `BasicHotStuffEngine` (`binary_consensus_loop.rs` ~L2493, reconstructing no lock/committed history); requested restore may supply `initialize_from_snapshot_baseline` (`basic_hotstuff_engine.rs` ~L1201, committed baseline only, no lock); D12's `load_persisted_state` (`hotstuff_node_sim.rs` ~L2035) is a **harness** path. `BootstrapNoLock`, `Locked`-with-no-commit, and committed-anchor distinctions preserved; no absent commit coerced to height zero.

**Reconciliation.** § 13 field table, four checks, P1–P4, invariants (INV-D14-2/-7), the future acceptance matrix, and the single successor subset (§ 13.9) were re-reviewed: H25 split into storage-level bootstrap→first-`Locked` (supplied/fixture evidence) vs excluded real-engine integration (H25e); H26 split into storage-only record-size cap vs excluded decision-integration retained-L0 lifecycle (H26l); H28/H29/H30 added. Exactly one bounded, unstarted, non-production-wired storage successor is retained; the optional `height == round` predicate is named as a bounded profile choice that does not block or establish readiness. Continuity contract cross-reference reconciled (`height` view-source, discriminated evidence, per-variant bounds, proposed O3 input).

**Checks executed (this pass).** Source/type/caller re-verification against the cited symbols; cross-section consistency (field table ↔ P1–P4 ↔ invariants ↔ H-matrix ↔ successor subset); table/link scan; scoped `git diff` review limited to the three authorized documents; whitespace/EOL/EOF verification (all three remain CRLF with no final newline; zero bare-LF lines introduced); secret scan (no secrets). Required review/security tooling attempted once this pass; the actual outcome is recorded with the final report, separate from historical outcomes. **No** Cargo tests, Clippy, or release rebuild were run or claimed (Markdown-only).

**Limitations / disposition.** This is a documentation-only correction pass; it changes no Rust, tests, schema, wire format, signing preimage, CLI, configuration, workflow, or initialization, and performs no D15 or Run 423 work. `D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED` is retained and is **not** equated with implementation readiness, independent review, or operational protection. Preserved posture: `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`, `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`, `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`, `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`, `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`; accepted D8/D10/D11/D12/D13 dispositions and C4/C5=OPEN unchanged. Changed paths this pass: the recovery/correspondence contract, the proposal/vote continuity contract, and this evidence document. No PR, no force-push, no rebase, no history rewrite.

## Run 422 D7-D14 correction pass — TC association, nested serialized bounds, retained-memory accounting, evidence attribution (this pass)

This entry records the bounded **documentation-only** pass that corrects the six residual
findings from the review of revision `0994fd887aa450ab18d488cd49617f9c63687f8e`. It implements
no storage successor and does **not** advance to D15 / Run 423.

**Provenance (four observations kept separate; none inferred from another).**

* **Branch (used unchanged).** `copilot/run-422-d7-d14` (`git rev-parse --abbrev-ref HEAD`, exit 0).
* **Starting HEAD.** `ce8296a103474b5db691480e3bc8b26bab2a5075` (`git rev-parse HEAD`, exit 0);
  worktree **clean** before editing (`git status --porcelain` empty).
* **Object availability.** The reviewed revision `0994fd887aa450ab18d488cd49617f9c63687f8e` was
  **unavailable** in the initial shallow checkout — `git cat-file -t 0994fd8…` returned
  `fatal: git cat-file: could not get object info` (exit 128). A **targeted fetch** `git fetch
  origin 0994fd887aa450ab18d488cd49617f9c63687f8e` succeeded (exit 0), after which
  `git cat-file -t 0994fd8…` → `commit`. Availability is reported as its own observation.
* **Ancestry.** `git merge-base --is-ancestor 0994fd8… HEAD` → **exit 1** (the reviewed object
  is **not** an ancestor of HEAD); `git merge-base 0994fd8… HEAD` →
  `db95e17c485b694627e4b5b463fc649d52815d34`. Ancestry is reported independently of availability
  and of content correspondence (Correction 5).

**Correction 5 — named comparison baseline (scoped, not repository-wide).** The byte-content comparison this pass relies on names **both** full SHAs and the **exact compared path scope**: starting HEAD `ce8296a103474b5db691480e3bc8b26bab2a5075` vs reviewed revision
`0994fd887aa450ab18d488cd49617f9c63687f8e`. The compared paths are the **three authorized
documents** plus the **six source paths cited by this pass** —
`docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`,
`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`, `crates/qbind-consensus/src/timeout.rs`,
`crates/qbind-consensus/src/timeout_verify.rs`, `crates/qbind-consensus/src/qc_verify_domain.rs`,
`crates/qbind-consensus/src/basic_hotstuff_engine.rs`, `crates/qbind-node/src/hotstuff_node_sim.rs`,
and `crates/qbind-consensus/src/ids.rs`. **Outcome:** `git diff --stat 0994fd8… HEAD -- <those
nine paths>` produced **empty output** (exit 0) — **byte-identical** across the compared paths.
Separately observed: the two commits' **tree** objects are equal
(`git rev-parse HEAD^{tree}` = `git rev-parse 0994fd8…^{tree}` = `68cfa9bd2515df89f2a435cc50a104b7007aecba`),
so content corresponds across the whole tree — but that is stated as a **tree-equality**
observation, **not** inferred from ancestry (the reviewed revision is not an ancestor). **No**
repository-wide correspondence is claimed beyond the compared paths and this tree-equality note.
The cited `~Lnnnn` source locators were (re-)read against the worktree copies of those paths this
pass, which the comparison shows are byte-identical to the reviewed revision.

**Correction 6 — literal tooling outcomes (executed / failed / unavailable / not-run).** Recorded
here, in this document, not deferred:

| Command / check | Literal outcome |
|---|---|
| `git rev-parse --abbrev-ref HEAD` | `copilot/run-422-d7-d14` (exit 0) — **executed** |
| `git rev-parse HEAD` | `ce8296a103474b5db691480e3bc8b26bab2a5075` (exit 0) — **executed** |
| `git cat-file -t 0994fd8…` (initial, shallow clone) | `fatal: … could not get object info` (exit 128) — **failed / object unavailable** |
| `git fetch origin 0994fd887aa450ab18d488cd49617f9c63687f8e` | exit 0; `git cat-file -t` then → `commit` — **executed** (targeted fetch) |
| `git merge-base --is-ancestor 0994fd8… HEAD` | **exit 1** (not an ancestor) — **executed** |
| `git merge-base 0994fd8… HEAD` | `db95e17c485b694627e4b5b463fc649d52815d34` — **executed** |
| `git diff --stat 0994fd8… HEAD -- <3 docs + 6 source paths>` | **empty** (exit 0) = byte-identical — **executed** |
| `git diff --name-only` (working tree, after edits) | the **three** authorized documents only — **executed** |
| Whitespace / EOL / EOF check (per changed file) | each remains **CRLF**, last byte `.` (no final newline), bare-LF line count **1** = the pre-existing no-final-newline EOF line only; **zero** bare-LF lines introduced — **executed** |
| Secret scan (3 authorized files) | **No secrets detected** — **executed** |
| Code review + CodeQL (`parallel_validation`) | **executed this pass**; literal outcome in the validation addendum at the end of this section |
| `cargo test` / `cargo check` / `cargo clippy` | **NOT RUN** (documentation-only; no Rust, test, schema, or wire change). No PASS, test count, or source result is claimed |
| Release-binary acceptance | **NOT RUN** this pass (documentation-only). Earlier release-binary evidence is preserved with its **original** scope; no release-binary observation is invented here |

**Corrections applied (operative locations).**

1. **TC semantic association (§ 13.3A).** Added the explicitly named predicates **TA1–TA8**
   linking the recovered logical lock, the retained `TimeoutCertificate.high_qc`, and the
   `select_max_high_qc` derivation over `signed_timeouts`, with duplicate-signer rejection (TA3),
   authorized membership (TA4), signer-set correspondence (TA5), timeout-view consistency (TA6),
   and power-quorum accounting kept distinct from validator count (TA7); absent high-QCs,
   equal-view candidates (first-seen, iteration-order, **no** invented tie-break), and inconsistent
   equal-view identities are described **as the code behaves** (`timeout.rs` ~L410/~L419/~L420,
   `timeout_verify.rs` ~L350/~L419/~L435, `basic_hotstuff_engine.rs` ~L2162/~L2177–L2185);
   structural/semantic checks are separated from timeout-signature cryptography (TA8), and a valid
   CRC/digest or matching lock fields do **not** admit unrelated TC evidence. The selected
   persist-restriction / carry-unverified TC rule is preserved.
2. **Complete serialized TC bounds (§ 13.2 `bounds_metadata`; INV-D14-7; H26).** Replaced the
   incomplete `N × T_msg` term with the explicit checked sum
   `FIXED_OVERHEAD + D_ev + TC_SIGNERS + TC_HIGH_QC + SIGNED_TIMEOUTS`, covering the TC's own
   signer list, the logical `high_qc` + its nested signer list, the `signed_timeouts` count, and
   each timeout's fixed fields / signer id / signature (suite length bounds a **signature**, not
   the message) / framing / optional `high_qc` with its nested signer list, plus all discriminants
   and length/count prefixes; identifier width `W_id` (encoded `u64` = 8 bytes, `ids.rs` ~L29/~L11)
   and prefix/discriminant widths are defined explicitly, encoded lengths are bounded rather than
   in-memory `size_of`, overflow/excess is refused before allocation/copy, and the
   backend-internal-allocation limitation is preserved.
3. **Separate retained-memory accounting (§ 13.7; INV-D14-7; H28/H29).** Removed the assertion
   that each decoded generation is ≤ `MAX_SAFETY_RECORD_BYTES`; defined a separate per-generation
   `retained_generation_bytes` (decoded objects/descriptors, vector capacities + backing
   allocations, signer arrays + signature buffers, owned context allocations, shared
   control-block overhead, per-operation identity + handle, and bounded candidate
   decode/preparation/encoding/publication buffers coexisting at peak) modelled on the
   `VerifiedQuorumCertificate::retained_byte_size` **precedent** (`qc_verify_domain.rs` ~L618),
   noting that method is a `VerifiedQuorumCertificate` accessor, **not** an implemented
   safety-record accounting service; stated three distinct caps (serialized-record /
   retained-generation / aggregate-peak), shared-once ownership-scope counting with superseded
   generations charged until the last `Arc` is released, capacity-normalization + admission limits,
   and refusal-at-capacity that never evicts admitted evidence or releases a D10 conflict.
4. **Removed false committed-history attribution (§ 13.4 inputs).** Removed the “only existing
   realization” claim for `load_persisted_state`; described its actual scope (loads the **last
   committed block + its QCs** for the harness restart path, `hotstuff_node_sim.rs` ~L2035) and
   that it establishes **no** arbitrary older-anchor membership; kept the committed-history relation
   explicitly **proposed** and independently supplied, with the dependent comparison (P3) unable to
   succeed when the relation is unavailable. The continuity-contract cross-reference was reconciled
   accordingly.
5. **Named comparison baseline** — see above.
6. **Literal tooling outcomes** — see the table above.

**Preserved decisions and status (unchanged by this pass).** QC logical view binds to certificate
height (`round` is not the view carrier); any `height == round` rule remains separately labelled;
`BootstrapNoLock` vs `Locked`-with-no-commit remain distinct; H25 (storage supplied-evidence
acceptance) / H25e (real-engine) / H26 (serialized-record) / H26l/H28/H29 (decision-lifecycle)
splits are intact; O1–O5, complete-content O5 comparison, stale-publication fencing, and
surviving complete-but-unacknowledged successor semantics are intact; D10
reservation/conflict/exact-reuse behavior is unchanged. `contradiction.md` was **not** touched.

```
D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain **OPEN**. This component-design correction does **not** establish implementation
readiness or authorize the successor. No Rust, tests, dependencies, schemas, storage keys,
CLI/configuration, workflows, wire formats, signing preimages, or production wiring changed; no
signing enablement, activation, or transport-boundary weakening; fail-closed
`CurrentEpochUnavailable` preserved.

**Validation addendum (literal `parallel_validation` outcome, this pass).** Code Review:
**completed**, 3 files reviewed, **no review comments** (the run also reported the review model
unavailable in this environment, a registry/tool-availability caveat, not a clean-vs-findings
signal). CodeQL Security Scan: **skipped — all changes trivial** (documentation-only; no
CodeQL-analyzable surface). No other review/security result is claimed.

## Run 422 D7-D14 — Complete serialized field accounting and enforceable peak-memory bounds (correction pass, documentation only)

This entry records the bounded **documentation-only** correction pass applied to the design reviewed at `fd6f64ee26ffc2fc627b28ef253d502ee70dd189`. It resolves **two** remaining accounting defects and **one** authentication-wording defect. It implements **no** storage, does **not** advance to D15 / Run 423, and reopens **no** accepted architectural decision. `contradiction.md` and every other tracked file outside the three authorized paths are unchanged. Prior D7-D14 entries above are **preserved** as historical evidence; this is a clearly identified new correction entry.

### Provenance (four observations, each stated separately; none inferred from another)

* **Branch (used unchanged).** `copilot/run-422-d7-d14-again` (`git rev-parse --abbrev-ref HEAD`, exit 0).
* **Starting HEAD.** `89b17f2d094cf98ca442324899a693eb3f972006` (`git rev-parse HEAD`, exit 0); worktree **clean** before editing (`git status --porcelain` empty). Starting HEAD is **not** assumed equal to the reviewed revision.
* **Reviewed-object availability.** The reviewed revision `fd6f64ee26ffc2fc627b28ef253d502ee70dd189` was **unavailable** in the initial shallow checkout — `git cat-file -t fd6f64e…` returned `fatal: git cat-file: could not get object info` (exit 128). A **targeted fetch** `git fetch origin fd6f64ee26ffc2fc627b28ef253d502ee70dd189` succeeded (exit 0), after which `git cat-file -t fd6f64e…` → `commit`. The reviewed commit's first parent is `3851851b8a2a5bef15f6f08ffe986f59b1db8be3`.
* **Ancestry (reported independently of availability and correspondence).** `git merge-base --is-ancestor fd6f64e… HEAD` → **exit 1** (the reviewed object is **not** an ancestor of starting HEAD); `git merge-base fd6f64e… HEAD` → `ce8296a103474b5db691480e3bc8b26bab2a5075`.
* **Scoped content correspondence (full revisions + exact compared paths named).** `git diff --stat fd6f64ee26ffc2fc627b28ef253d502ee70dd189 HEAD -- <the three authorized documents>` produced **empty output** (exit 0) — the three authorized paths were **byte-identical** between the reviewed revision and starting HEAD **before** this pass. Separately observed: the two commits' **tree** objects are equal (`git rev-parse HEAD^{tree}` = `git rev-parse fd6f64e…^{tree}` = `108e1b322e596fddb62c76c43653564531e4c45d`), a **tree-equality** note **not** inferred from ancestry (the reviewed revision is not an ancestor). The cited `~Lnnnn` source locators (`timeout.rs` ~L73/L82/L232/L235/L238/L241/L244/L246/L353–L388, `qc.rs` ~L29–L38, `timeout_verify.rs` ~L350/L404/L411/L435, `ids.rs` ~L29) were re-read against the worktree this pass.

### Changed paths (authorized scope only)

1. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
2. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (this entry)

### Correction 1 — Complete serialized field accounting (§ 13.2; reconciled in INV-D14-7, H26, continuity cross-reference)

The `TcDerived` serialized cap was incomplete: it omitted the `TimeoutMsg.suite_id: u8`, the `TimeoutCertificate.view` and `TimeoutCertificate.timeout_view` (`u64` each), and it conflated the record's **own** logical `high_qc` with the retained `TimeoutCertificate`'s **own** `high_qc` (a single ambiguous `TC_HIGH_QC` term). The record retains a **separate** logical `high_qc` alongside the TC's `high_qc`, so **both** serialized copies are now charged — each exactly once — with their **required correspondence** stated (byte-identical identity; a mismatch → refuse; neither silently dropped). The corrected, checked serialized formula (§ 13.2 `bounds_metadata`, with the same terms mirrored in INV-D14-7 and H26, and in the continuity-contract cross-reference) is: **`MAX_SAFETY_RECORD_BYTES(TcDerived) = FIXED_OVERHEAD + D_ev + REC_HIGH_QC + TC_VIEW + TC_TIMEOUT_VIEW + TC_HIGH_QC + TC_SIGNERS + SIGNED_TIMEOUTS`**, where `REC_HIGH_QC = D + 32 + 8 + (C + N × W_id)` (record-level logical `high_qc`), `TC_VIEW = 8`, `TC_TIMEOUT_VIEW = 8` (the two fixed `u64` fields, previously omitted), `TC_HIGH_QC = D + 32 + 8 + (C + N × W_id)` (the retained TC's own `high_qc`, required byte-identical to `REC_HIGH_QC`), `TC_SIGNERS = C + N × W_id`, and `SIGNED_TIMEOUTS = C + N × T_msg` with the per-entry checked sum **`T_msg = 8 (view) + W_id (validator_id) + 1 (suite_id: u8) + (C + S_sig) (signature length-prefix + bytes ≤ S_sig) + D (high_qc discriminant) + [ 32 + 8 + (C + N × W_id) ] (optional nested high_qc) + per-message framing`**. Every record field, variant/option discriminant, count/length prefix, and framing contribution is accounted; encoded widths (`W_id` = encoded `ValidatorId`, a `u64` = 8 bytes; `C`/`D` prefixes/discriminants) are explicit bounded profile parameters, **not** native struct sizes; the encoding is labelled **proposed** (not attributed to an existing codec). Maximum bounds use the maximum permitted presence/count (≤ `N`) of nested members; actual records validate discriminants, declared counts, offsets, and total length with **checked `u128`/`usize` arithmetic**, refusing unsupported profile parameters, excessive lengths/counts, and overflow **before** any application-owned allocation or copy of the variable members. The storage-backend internal-allocation limitation is preserved.

### Correction 2 — Enforceable peak-memory accounting (§ 13.7; reconciled in INV-D14-7, H26l/H28/H29)

The prior text asserted that **every** transient buffer — including the **candidate decode** buffer and the **preparation** buffer — was bounded by `MAX_SAFETY_RECORD_BYTES`. That is removed: `MAX_SAFETY_RECORD_BYTES` now bounds **only** an explicitly **encoded byte buffer with that enforced capacity**; a **decoded** candidate/preparation object's in-memory footprint is **not** inferred from a serialized length. The eight allocation kinds are distinguished and each charged once in a stated ownership scope: encoded input/output byte buffers; the decoded candidate object; the current authoritative decoded generation; superseded pinned generations; preparation-owned decoded objects; capacity-normalization overlap; publication-owned encoded buffers; and bounded validation scratch. The **candidate** generation is charged **in addition to** current/pinned generations whenever they coexist during O3. Shared allocations are counted once (Arc handles belong to holders; a shared control block is charged once to its designated owner; shared context is neither omitted nor double-charged). `MAX_RETAINED_GENERATION_BYTES` is now a **checked formula** over bounded profile parameters (`GEN_STRUCT + SIGNERS_CAP + SIG_TERMS + CTX_OWNED + ARC_CTRL`, decoded capacities at `capacity()`), and `MAX_AGGREGATE_RETAINED_BYTES` is a **checked peak** with **finite multiplicity**: `(MAX_OUTSTANDING_PREPARED_L0 × (identity + Arc-handle)) + ((MAX_OUTSTANDING_PREPARED_L0 + 1 + MAX_CONCURRENT_CANDIDATES) × MAX_RETAINED_GENERATION_BYTES) + (MAX_CONCURRENT_CANDIDATES × CAPNORM_OVERLAP) + ((MAX_CONCURRENT_CANDIDATES + MAX_CONCURRENT_PUBLICATIONS) × MAX_SAFETY_RECORD_BYTES) + VALIDATION_SCRATCH`, where `MAX_CONCURRENT_CANDIDATES`/`MAX_CONCURRENT_PUBLICATIONS`/`MAX_OUTSTANDING_PREPARED_L0` are **proposed component limits** (initial profile 1/1/2), not claims about existing engine enforcement. Capacity-normalization that reallocates a vector while the original remains live charges **both** at peak (the `CAPNORM_OVERLAP` term); a shrink is **not** assumed to yield exact capacity (bounded `CAPNORM_SLACK` or a bounded allocation representation). The five-step **allocation admission sequence** is stated: (1) validate profile parameters/shapes; (2) compute conservative coexistence charges; (3) **check available capacity before** the protected allocations; (4) allocate within admitted bounds; (5) validate actual capacities and retain only admissible objects — with the explicit note that the step-(5) post-allocation check is a **confirmation**, **not** prevention (prevention is step (3)). Capacity refusal preserves established evidence, outstanding operations' evidence, and D10 conflict obligations, and adds **no** new cache, journal, or production memory-accounting framework. The storage-local vs decision-integration acceptance split (H25/H25e; H26 storage vs H26l/H28/H29 decision-integration) is preserved.

### Correction 3 — TA7 authentication wording (§ 13.3A)

TA7 no longer claims “verified signers” or that it “proves ≥ 2/3 power timed out.” It now states precisely that **membership, uniqueness, signer-set correspondence, and power summation** (the **logical** `TimeoutCertificate::validate`, `timeout.rs` ~L362–L386, over the **claimed** `tc.signers`, with **no** signatures checked) establish the **quorum weight of the claimed signer set**; they do **not** authenticate **timeout participation**, which requires successful **per-entry timeout-signature verification** against the trusted context (`verify_timeout_msg` inside `verify_timeout_certificate_with_evidence`, `timeout_verify.rs` ~L238/~L404); and that even authenticated timeouts do **not** authenticate the logical `high_qc`'s **constituent votes** (not carried). The selected `TcDerived` behavior is preserved: the lock restriction is persisted/enforced, the record is carried explicitly **unverified** where required evidence verification is unavailable, and it refuses any verified-evidence-dependent use.

### Literal validation outcomes (executed / failed / unavailable / not-run)

| Command / check | Literal outcome |
|---|---|
| `git rev-parse --abbrev-ref HEAD` | `copilot/run-422-d7-d14-again` (exit 0) — **executed** |
| `git rev-parse HEAD` | `89b17f2d094cf98ca442324899a693eb3f972006` (exit 0) — **executed** |
| `git status --porcelain` (before edits) | empty (clean) — **executed** |
| `git cat-file -t fd6f64e…` (initial, shallow clone) | `fatal: … could not get object info` (exit 128) — **failed / object unavailable** |
| `git fetch origin fd6f64ee26ffc2fc627b28ef253d502ee70dd189` | exit 0; subsequent `git cat-file -t` → `commit` — **executed** (targeted fetch) |
| `git merge-base --is-ancestor fd6f64e… HEAD` | **exit 1** (not an ancestor) — **executed** |
| `git merge-base fd6f64e… HEAD` | `ce8296a103474b5db691480e3bc8b26bab2a5075` — **executed** |
| `git diff --stat fd6f64e… HEAD -- <3 authorized docs>` | **empty** (exit 0) = byte-identical at baseline; trees equal `108e1b3…` — **executed** |
| `git diff --name-only` (working tree, after edits) | the **three** authorized documents only — **executed** |
| Whitespace / EOL / EOF check (per changed file) | each remains **CRLF**; last byte `.` (no final newline); exactly **one** bare-LF line = the pre-existing no-final-newline EOF line; **zero** bare-LF lines introduced — **executed** |
| Secret scan (`runtime-tools-secret_scanning`, 3 authorized files) | **No secrets detected** — **executed** |
| Code review + CodeQL (`parallel_validation`) | **executed this pass**; literal outcome in the validation addendum below |
| `cargo test` / `cargo check` / `cargo clippy` | **NOT RUN** (documentation-only; no Rust, test, schema, or wire change). No PASS, test count, or source result is claimed |
| Release-binary acceptance | **NOT RUN** this pass (documentation-only). Earlier release-binary evidence is preserved with its **original** scope |

### Preserved status and remaining ambiguity

Preserved without reopening: QC logical-view binding to certificate `height`; the separately labelled `height == round` eligibility choice; `BootstrapNoLock` vs `Locked`-with-no-commit; TA1–TA6 association requirements and the documented first-encountered equal-view selection behavior; the proposed, independently supplied committed-history relation; O1–O5, complete-content O5 comparison, and stale-publication fencing; complete-but-unacknowledged successor handling; D10 reservation/conflict/exact-reuse semantics; H25 storage acceptance vs H25e engine integration. Fail-closed `CurrentEpochUnavailable`, activation boundaries, and transport boundaries are preserved. No signing enablement, validator change, epoch consumption for trust activation, sequence/marker/`LivePqcTrustState` mutation, peer-driven apply/propagation, anchor selection, launch publication, or readiness promotion. Remaining ambiguity is unchanged and explicit: the anti-rollback anchor remains unresolved and the design stays DEFINED-NOT-IMPLEMENTED.

```
D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain **OPEN**. This correction does **not** authorize storage implementation or establish production readiness. This pass completes here and does **not** begin the storage successor.

**Validation addendum (literal `parallel_validation` outcome, this pass).** Code Review: **completed**, 3 files reviewed, **no review comments** (the run also reported the review model unavailable in this environment — `model claude-sonnet-4.6 not found in registry` — a tool-availability caveat, not a clean-vs-findings signal). CodeQL Security Scan: **skipped — all changes trivial** (documentation-only; no CodeQL-analyzable surface). Secret scan over the three authorized files: **no secrets detected**. No other review/security result is claimed.
## Run 422 D7-D14 — Close serialized framing and decoded-allocation accounting (correction pass, documentation only)

This entry records the bounded **documentation-only** correction pass applied to the design reviewed at `e31512b3a4c529085e0655055698024d32c3440a`. It resolves the **remaining resource-accounting findings** by producing **explicit field and allocation tables** from which the bounds derive mechanically, rather than substituting broader assertions of completeness. It implements **no** storage, does **not** advance to D15 / Run 423, and reopens **no** accepted architectural decision. `contradiction.md` and every other tracked file outside the three authorized paths are unchanged. Prior D7-D14 entries above are **preserved** as historical evidence; this is a clearly identified new correction entry.

### Provenance (reported separately; none inferred from another)

* **Branch (used unchanged).** `copilot/run-422-d7-d14-another-one` (`git rev-parse --abbrev-ref HEAD`, exit 0).
* **Starting HEAD.** `302e51c1abf1bd8746cb5c4a75dada8cdf938e2a` (`git rev-parse HEAD`, exit 0); worktree **clean** before editing (`git status --porcelain` empty). Starting HEAD is **not** assumed equal to the reviewed revision.
* **Reviewed-object availability.** The reviewed revision `e31512b3a4c529085e0655055698024d32c3440a` was **unavailable** in the initial shallow checkout — `git cat-file -t e31512b…` → `fatal: git cat-file: could not get object info` (exit 128). A **targeted fetch** `git fetch origin e31512b3a4c529085e0655055698024d32c3440a` succeeded (exit 0), after which `git cat-file -t e31512b…` → `commit` (`copilot-swe-agent[bot]`, "docs(run422-d7d14): complete serialized field accounting, enforceable peak-memory bounds, TA7 wording").
* **Ancestry (reported independently of availability and correspondence).** `git merge-base --is-ancestor e31512b… HEAD` → **exit 1** (the reviewed object is **not** an ancestor of starting HEAD); `git merge-base e31512b… HEAD` → `89b17f2d094cf98ca442324899a693eb3f972006` (the shared base).
* **Scoped content correspondence (full revisions + exact compared paths named).** `git diff --stat e31512b3a4c529085e0655055698024d32c3440a HEAD -- docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` produced **empty output** (exit 0) — the three authorized paths were **byte-identical** between the reviewed revision and starting HEAD **before** this pass; the whole-tree `git diff --stat e31512b… HEAD` was likewise empty (tree-equal), a note **not** inferred from ancestry. Source locators (`consensus.rs` ~L282/~L304/~L316/~L321/~L324 wire `QuorumCertificate` + encoder, `qc.rs` ~L29–L38 logical QC, `timeout.rs` ~L72/~L75/~L78/~L80/~L82/~L84/~L232/~L235/~L238/~L241/~L244/~L246, `ids.rs` ~L11/~L29 `ValidatorId`) were re-read against the worktree this pass. No `AGENTS.md` applies to the three authorized documentation paths (none found in the tree).

### Changed paths (authorized scope only)

1. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
2. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (this entry)

### Correction 1 — Explicit serialized persistence profile (new § 13.2A)

The ambiguous inline `C`, "per-message framing," and `FIXED_OVERHEAD` descriptions in the § 13.2 `bounds_metadata` cell are **replaced** by a new **§ 13.2A** titled *Proposed serialized persistence profile — explicit field, prefix, and contribution tables*, labelled a **proposed persistence encoding distinct from** the `qbind-wire` encoding (`consensus.rs` ~L304) and every signing preimage, changing **no** implementation or signing bytes. It provides:

* **(a) Profile-parameter table** with concrete widths / bounded ranges / validation rules, each **fixed before encode/decode** and **never accepted from an untrusted record as policy**: `C = 2` (`u16`, allowed {2,4}); `W_id = 8` (encoded `ValidatorId`); `D = 1`; `S_sig ∈ 1..=MAX_SIGNATURE_LEN`; `N ∈ 1..=MAX_SIGNATURE_COUNT`; and **framing `F = 0`, stated explicitly** (no `MSG_TYPE` byte, no envelope).
* **(b) Common-record-field table** whose named rows sum to **`FIXED_OVERHEAD = 153` bytes**, derived mechanically (version 2 + four 32-byte ids/digests + two 8-byte `u64`s + CRC 4 + three always-present discriminants + `F = 0`), not an unexplained constant.
* **(c)** Committed-anchor (`32 + 8`) and predecessor-reference (`8`) present-only payloads, gated by the always-present discriminants of (b).
* **(d) `QcDerived`** table enumerating the stored wire QC's fixed members (`QC_FIXED = 64`), the **bitmap outer length prefix**, the **signatures outer count prefix**, and — charged in the **variable** part — the **per-signature length prefix `C` multiplied by the count** (`N × (C + S_sig)`), explicitly **not** folded into fixed overhead.
* **(e) `TcDerived`** table preserving `TimeoutMsg.suite_id: u8`, `TC.view`/`TC.timeout_view` (8 each), **both** logical `high_qc` copies (record-level and the TC's own) **charged once each and required byte-identical**, the TC signer list, and the `signed_timeouts` count with a per-entry `T_msg` sub-table (view/optional nested `high_qc`/`validator_id`/`suite_id`/signature length prefix + bytes, framing `F = 0`).
* **(f)** **Actual-length and worst-case formulas stated separately**, every stored byte attributable to exactly one named row (the only non-row byte is `F = 0`); the `O(N²)` nested-`high_qc` signer term inside `SIGNED_TIMEOUTS` is charged explicitly. Checked `u128`/`usize` arithmetic, **refusal before any affected variable allocation/copy**, the `MAX_AGGREGATE_SIGNATURE_BYTES` over-read guard as an honest allocation-bound limitation, and the retained backend-internal allocation limitation are all preserved. The § 13.2 cell now **points to** § 13.2A and no longer carries the ambiguous constants.

### Correction 2 — Complete decoded-generation allocation tables (new § 13.7A)

The incomplete `GEN_STRUCT + SIGNERS_CAP + SIG_TERMS` prose in § 13.7 is **replaced** by a new **§ 13.7A** with **variant-specific** per-allocation tables. Each row names its **owner**, **element type and in-memory element size**, **maximum admitted capacity**, **charged bytes**, whether descriptors are **inline or in an outer backing allocation**, and **sharing/lifetime**. The tables explicitly **distinguish the encoded `ValidatorId` width (`W_id = 8`) from the in-memory `size_of::<ValidatorId>()`** (newtype over `u64`) and charge `Vec<T>` as a 3-word inline descriptor (24 B) **plus** an outer `capacity() × size_of::<T>()` backing. The `TcDerived` table surfaces the **`8N²`** per-entry nested-`high_qc` signer backing explicitly. A generation's heap is charged **once** per distinct `Arc`-shared allocation and the shared control block **once to its canonical owner**; these decoded charges feed `MAX_RETAINED_GENERATION_BYTES` / `MAX_AGGREGATE_RETAINED_BYTES` and are **never** bounded by the serialized `MAX_SAFETY_RECORD_BYTES`.

### Mirror in the state-continuity contract

The summarizing paragraph of `QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` (§ 9.x) now points to the § 13.2A serialized field tables (with `FIXED_OVERHEAD = 153`, `F = 0`, actual-vs-worst-case) and the § 13.7A allocation tables (encoded vs in-memory `ValidatorId`, `O(N²)` term), without changing any decision.

### Scope boundaries (unchanged by this pass)

Only resource-accounting **presentation** is corrected: no new verifier, no logical-to-wire QC upgrade, no fabricated signature, no implementation, no signing-preimage change. The design remains **DEFINED-NOT-IMPLEMENTED**; anti-rollback / lock-recovery / current-authority remain **UNRESOLVED**; C4/C5 remain **OPEN**. This pass completes here and does **not** begin the storage successor, D15, or Run 423.

## Run 422 D7-D14 — Reconcile authoritative bounds and complete outstanding corrections (correction pass, documentation only)

This entry records the bounded **documentation-only** reconciliation pass applied to the
design reviewed at `709495d936c2a263ffdaa89f19ef8485b4508c98`. It **preserves** the accepted
§ 13.2A serialized-field tables and § 13.7A allocation tables, reconciles the operative
serialized formulas to those tables, completes the decoded-generation and peak-memory
accounting, and records this pass's **own** evidence. It implements **no** storage, does
**not** advance to D15 / Run 423, and reopens **no** accepted decision. `contradiction.md`
and every other tracked file outside the three authorized paths are unchanged. All prior
entries above are **preserved** as historical evidence; this is a clearly identified new
correction entry.

### Provenance (each reported separately; none inferred from another)

* **Branch (used unchanged).** `copilot/run-422-d7-d14-reconcile-authoritative-bounds`
  (`git rev-parse --abbrev-ref HEAD`, exit 0).
* **Starting HEAD.** `ffc0e92b9b946b486c7bae9a881100a15a98b8d9` (`git rev-parse HEAD`,
  exit 0); worktree **clean** before editing (`git status --porcelain` empty). Starting
  HEAD is **not** assumed equal to the reviewed revision.
* **Reviewed-object availability.** The reviewed revision
  `709495d936c2a263ffdaa89f19ef8485b4508c98` was **unavailable** in the initial shallow
  single-branch checkout — `git cat-file -t 709495d…` → `fatal: git cat-file: could not
  get object info` (exit 128). A **targeted fetch**
  `git fetch --depth=200 origin 709495d936c2a263ffdaa89f19ef8485b4508c98` succeeded
  (exit 0), after which `git cat-file -t 709495d…` → `commit` (`copilot-swe-agent[bot]`,
  `Mon Oct 5 09:15:47 2026 +0000`, message "docs(run422-d7d14): explicit serialized-framing
  (§13.2A) and decoded-allocation (§13.7A) tables").
* **Ancestry (reported independently of availability and correspondence).**
  `git merge-base --is-ancestor 709495d… HEAD` → **exit 1** (the reviewed object is **not**
  an ancestor of starting HEAD); `git merge-base 709495d… HEAD` →
  `302e51c1abf1bd8746cb5c4a75dada8cdf938e2a` (the shared parent — both HEAD and the reviewed
  commit are sibling children of `302e51c`). `git rev-list --count 709495d…HEAD` = 1 and
  `git rev-list --count HEAD…709495d…` = 1 (one commit each side of the shared base).
* **Scoped content correspondence (full revisions + exact compared paths named).**
  `git diff --stat 709495d936c2a263ffdaa89f19ef8485b4508c98 ffc0e92b9b946b486c7bae9a881100a15a98b8d9 -- docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`
  reported the **two protocol paths byte-identical** (no stat line) and the **evidence path
  differing by `41` insertions / `41` deletions** (`git diff --numstat` → `41  41  …RUN_422_D7.md`).
  A `git diff --word-diff=porcelain` over the evidence path showed **no word-level content
  change** — the 41/41 delta is purely **line-ending / final-newline** normalization of the
  previously-appended block (the reviewed blob carried LF / a final newline on those lines;
  the repository HEAD carries CRLF / no final newline). As instructed, **repository content
  (HEAD) is used as the baseline**; the previously uploaded evidence attachment did **not**
  match the reviewed commit's evidence blob and was **not** used to overwrite repository
  content.
* **Applicable AGENTS.md.** `git ls-files | grep -i AGENTS.md` → **empty**: no `AGENTS.md`
  exists anywhere in the tree, so none applies to the three authorized documentation paths.
* **Source re-inspection (locators verified against the worktree this pass).**
  `timeout.rs` — `TimeoutMsg` L73 (`view` L75, `high_qc: Option<QuorumCertificate>` L78,
  `validator_id` L80, `suite_id: u8` L82, `signature: Vec<u8>` L84), `TimeoutCertificate`
  L232 (`view` L235, `high_qc` L238, `signers: Vec<ValidatorId>` L241,
  `signed_timeouts: Vec<TimeoutMsg>` L244, `timeout_view` L246) — **all match** the § 13.2A
  cited lines. `ids.rs` — `ValidatorId(pub u64)` L29, `validator_index` (u16) note L11 —
  **match**. `qc_verify_domain.rs` — `MAX_BITMAP_LEN = 8192` L163, `MAX_SIGNATURE_LEN` L170,
  `MAX_AGGREGATE_SIGNATURE_BYTES` L198 — **match**. **Locator caveat (honest):** the accepted
  § 13.2A table cites `consensus.rs ~L282/~L304` for the wire `QuorumCertificate` + encoder,
  but **`crates/qbind-consensus/src/consensus.rs` is not present** in this tree; the
  `QuorumCertificate` struct is in `crates/qbind-consensus/src/qc.rs` L29. The accepted table
  is **preserved** (not edited for citations this pass); this caveat is recorded so the
  locator is not over-attributed.

### Changed paths (authorized scope only)

1. `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`
2. `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`
3. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (this entry)

`git status --porcelain` after editing lists **exactly** these three paths (changed-path
check: no unauthorized file touched; `contradiction.md` unchanged).

### Correction 1 — Reconcile serialized bounds to the authoritative § 13.2A

§ 13.2A is now the **authoritative owner** of the serialized formulas via two **named
variant caps** added to § 13.2A(f):

* **`MAX_QC_BYTES`** derived mechanically from the (b)/(c)/(d) rows at the initial profile
  `C = 2`: `FIXED_OVERHEAD 153 + anchor 40 + predecessor 8 + QC_FIXED 64 + bitmap-length
  prefix 2 + signatures-count prefix 2 + B_span + N × (2 + S_sig)` = **`269 + B_span +
  N × (2 + S_sig)`** (worst case with both optional payloads present; actual-length form
  uses real discriminants/counts).
* **`MAX_TC_BYTES` = `FIXED_OVERHEAD + [40 + 8]_{anchor+pred} + REC_HIGH_QC + TC_VIEW +
  TC_TIMEOUT_VIEW + TC_HIGH_QC + TC_SIGNERS + SIGNED_TIMEOUTS`**, mechanically from the (e)
  table, with **`D_ev` NOT re-added** (the evidence discriminant is already one of the
  always-present (b) rows summed into `FIXED_OVERHEAD = 153`). Both `high_qc` copies charged
  once each and required byte-identical; the `O(N²)` nested-`high_qc` signer term charged
  explicitly.
* **Reader enforcement stated.** `MAX_SAFETY_RECORD_BYTES = max(MAX_QC_BYTES, MAX_TC_BYTES)`
  (checked `u128`); a post-discriminant reader enforces the variant-specific cap, a
  pre-discriminant size gate enforces the cross-variant maximum.

The previously **divergent** operative formulas were **replaced by references** to these
names (no bound now has two different formulas): the § 13.2 `bounds_metadata` cell (which had
`FIXED_OVERHEAD + B_span + N × S_sig` for `QcDerived` and `FIXED_OVERHEAD + D_ev + …` for
`TcDerived`), **INV-D14-7**, **H26**, and the continuity-contract § 9.x summary. The stale
`QcDerived` form omitted the anchor/predecessor payloads (48), `QC_FIXED` (64), and the
count/length prefixes; the stale `TcDerived` form **double-counted** `D_ev`. A worktree grep
confirms **zero** remaining occurrences of either stale string in the two protocol files.

### Correction 2 — Complete decoded-generation caps (§ 13.7A authoritative; `CAPNORM_SLACK` defined)

§ 13.7A remains the authoritative owner of decoded-allocation accounting; § 13.7's
`MAX_RETAINED_GENERATION_BYTES = GEN_STRUCT + SIGNERS_CAP + SIG_TERMS + CTX_OWNED + ARC_CTRL`
explicitly defers its per-allocation breakdown to § 13.7A. `CAPNORM_SLACK` — previously
referenced but undefined — is now a **concrete bounded profile parameter** in **elements**
per vector (`capacity() ≤ len() + CAPNORM_SLACK`, **initial profile = 0**), applied to each
named decoded growable backing (both variants enumerated), with per-vector byte contribution
`CAPNORM_SLACK × size_of::<element>()` and an explicit **finite multiplicity** (`O(N)`
vectors + `O(N)` per-entry buffers/nested-signer backings), charged into
`MAX_RETAINED_GENERATION_BYTES`; over-capacity beyond the slack → **refuse**. Both decoded
`high_qc` copies are retained and charged **separately** (no implicit sharing). The charge is
honestly an **application-owned allocation** charge, **not** a process-RSS bound.

### Correction 3 — O3/O4/O5 phase/coexistence table, `VALIDATION_SCRATCH` bound, derived peak (new § 13.7B)

A new **§ 13.7B** adds the O3/O4/O5 **phase/coexistence table** identifying which
allocations are simultaneously live per phase (current / superseded-pinned / candidate
decoded generations; preparation-owned objects; normalization old+new; encoded input;
encoding; publication; O5 comparison/re-publication; validation scratch). Two decisions are
**made and documented**: preparation-owned objects **alias** the already-charged
candidate/current `Arc` (no extra copy in the selected profile); the **encoding** and
**publication** buffers are **separate owned allocations, both charged**. `VALIDATION_SCRATCH`
is given an **explicit finite bound** `UNIQ_SET + ASSOC_MAP + CMP_SPAN` (signer
uniqueness/membership over ≤ `N`, TC-association scratch over ≤ `N`, and one
`≤ MAX_SAFETY_RECORD_BYTES` comparison span, multiplicity 1). The single conservative peak
`MAX_AGGREGATE_RETAINED_BYTES` is **derived from the union of the table rows** (preserving the
proposed limits `MAX_OUTSTANDING_PREPARED_L0 = 2`, `MAX_CONCURRENT_CANDIDATES = 1`,
`MAX_CONCURRENT_PUBLICATIONS = 1`). Admission checks the conservative charges **before** the
protected allocations; the post-allocation check only confirms. Capacity refusal preserves
established/outstanding evidence and D10 obligations, kept separate from future
decision-lifecycle integration.

### Correction 4 — EOL terminology correction (historical) and this pass's EOL/EOF results

**Historical terminology correction (no command outcome manufactured).** Prior D7-D14
entries in this file described the no-final-newline EOF as "**bare-LF line count 1** = the
pre-existing no-final-newline EOF line" (and "exactly one bare-LF line"). That label is
**imprecise**: these files are **all-CRLF**, and an **unterminated final line is not a
bare-LF newline** (it contains **no** LF at all). The byte-accurate measure is
**`bare-LF newline bytes = count(LF) − count(CRLF)`**, which is **0** for every file here
(every LF belongs to a CRLF). The historical entries' underlying byte observations
(all-CRLF, final byte `.`, no final newline) are **not** disputed or altered — only the
"bare-LF" wording is corrected; no different historical command output is claimed.

**This pass's EOL/EOF results (per changed file, measured this pass).** Method:
`CRLF = grep -c $'\r' <file>`; `LF = tr -cd '\n' | wc -c`;
`bare-LF newline bytes = LF − CRLF`; `final byte = tail -c1 | xxd`.

| Changed file | CRLF count | LF total | bare-LF newline bytes (LF−CRLF) | final byte | final newline present |
|---|---|---|---|---|---|
| `QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md` | 2887 | 2887 | **0** | `0x2e` (`.`) | **no** |
| `QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md` | 1967 | 1967 | **0** | `0x2e` (`.`) | **no** |
| `QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` | 12947 (re-measured after this append) | 12947 | **0** (every LF is part of a CRLF) | `0x2e` (`.`) | **no** |

The evidence file's own CRLF/LF counts change as this block is appended; it retains the
**CRLF, no-final-newline, zero-bare-LF** convention (re-measurable after commit with the same
commands). Existing conventions are preserved on all three files.

### Validation / coverage checks (this pass's literal outcomes)

* **Field-to-formula coverage.** Every § 13.2A(b)/(c)/(d)/(e) row maps to exactly one term of
  `MAX_QC_BYTES` / `MAX_TC_BYTES`; the only non-row byte is `F = 0`. `D_ev` appears **once**
  (in `FIXED_OVERHEAD`), not twice. **Covered.**
* **Allocation-to-charge coverage.** Every § 13.7A row (GEN_STRUCT inline, outer backings,
  per-signature / per-entry buffers, nested `O(N²)` signer backing, `CTX_OWNED`, `ARC_CTRL`)
  plus `CAPNORM_SLACK` is charged into `MAX_RETAINED_GENERATION_BYTES`; both `high_qc` copies
  charged separately. **Covered.**
* **Phase/coexistence coverage.** Each § 13.7B table row is placed in O3/O4/O5 and mapped to
  a peak term; preparation aliases a charged owner; encoding and publication charged
  separately; `VALIDATION_SCRATCH` bounded. **Covered.**
* **Changed-path check.** Exactly the three authorized files changed (`git status
  --porcelain`); `contradiction.md` and all other tracked files unchanged. **Covered.**
* **EOL/EOF.** All three files CRLF, final byte `.`, no final newline, **0** bare-LF newline
  bytes (table above). **Covered.**
* **Available review/security tooling (this pass's literal outcomes; not reused from prior
  passes).** `parallel_validation` was run **this pass**: **Code Review — completed, 3 files
  reviewed, no review comments** (with an environment **availability caveat**: the review
  model was reported unavailable — `model claude-sonnet-4.6 not found in registry` — a
  tooling caveat, not a clean-vs-findings signal). **CodeQL Security Scan — skipped: all
  changes trivial** (documentation-only Markdown; no analyzable code surface). **Secret scan**
  over the three authorized files — **no secrets detected**. **No** Cargo build, Cargo tests,
  Clippy, or release-binary rebuild were run or claimed; they are recorded as **not run**
  (documentation-only pass; prior evidence preserved with its original scope). No other
  review/security result is claimed.

### Remaining unresolved items (completeness claims narrowed honestly)

* The accepted § 13.2A citation `consensus.rs ~L282/~L304` does not resolve in this tree (the
  wire `QuorumCertificate` is in `qc.rs` L29); the citation is **preserved** per the
  "preserve accepted tables" instruction and flagged here rather than silently edited.
* Anti-rollback anchor, lock-recovery, and current-authority remain **UNRESOLVED**; the
  design stays **DEFINED-NOT-IMPLEMENTED**; C4/C5 remain **OPEN**. This pass corrects
  resource-accounting **presentation** only — no storage, verifier, signing-preimage, wire,
  schema, CLI, workflow, or production wiring changed.

### Preserved required status

`D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED`;
`DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`; `GENESIS_AUTHORITY_ACTIVATION=DISABLED`;
`SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`. C4/C5 remain **OPEN**. Fail-closed
`CurrentEpochUnavailable` and the activation/transport boundaries are preserved. This pass
completes here and does **not** begin the storage successor, D15, or Run 423.