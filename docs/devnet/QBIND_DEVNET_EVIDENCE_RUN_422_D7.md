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

* Actual working branch: `copilot/run-422-d7-d7-again`.
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