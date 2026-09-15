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