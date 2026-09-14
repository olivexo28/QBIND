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