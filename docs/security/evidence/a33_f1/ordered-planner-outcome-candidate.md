# A33-F1 / E27 test-only ordered-planner and outcome candidate

**TEST-ONLY PLANNER/OUTCOME CANDIDATE — INDEPENDENT REVIEW PENDING.**
The candidate is isolated under `crates/qbind-consensus/tests/` and is not
wired into production. It is not the real engine, a quarantine mechanism,
or a participation gate. A33-F1 / E27 and remaining obligations stay
**OPEN**; activation is **DISABLED**; public DevNet is **NO-GO**.

## Contract represented by the model

The later owner-approved v3 catch-up direction and stay-closed contract
remain the controlling design basis: refuse existing-ID replacement,
refuse a new ID without a fully safe slot, report known and unknown effects
without assuming rollback, and do not resume participation from unresolved
state. Earlier v2 recovery alternatives are superseded where inconsistent;
the model selects no durable intent format, recovery authority, clear rule,
retry policy, or production capacity policy.

The audit basis is A5.3 (`Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`,
A:L15337-L15465) and A22.1-C2/C3 (A:L9230-L9263); A17-F1's catch-up
effects and valid-prefix behavior are recorded at A:L15805-L15859 and
A:L15953-L15963. The candidate follows
`catchup-quarantine-contract-proposal-v3.txt` sections 1, 2.1 and 2.2
(approved direction and admission/effect contract) and
`stay-closed-contract.md` sections "Safety invariant and allowed scope",
"Startup refusal: required ordering", and "Barrier and in-flight ownership".
The v3 defaults supersede conflicting recovery alternatives in
`catchup-contract-review-proposal-v2.txt` as noted in maintained-plan
sections 25-28; the stay-closed contract adds durable-intent, startup and
in-flight-work prerequisites, not permission to clear or resume. Relevant
source trace anchors are maintained-plan section 25:
`qbind-consensus/src/hotstuff_state_engine.rs:1098-1175,1455-1488`,
`qbind-consensus/src/basic_hotstuff_engine.rs:3954-4030`, and
`qbind-node/src/binary_consensus_loop.rs:8437-8506`. This task changes none
of those production paths.

`tests/support/a33_f1_ordered_planner.rs` models `N + 1` with checked
arithmetic and computes `D = max(0, N + 1 - M)`. Existing IDs refuse before
planning. For a new ID, a successful plan contains exactly `D` distinct
retained victims. `D = 0` does not scan unrelated graph components, but the
candidate's required parent lineage is still checked. For `D > 0`, the
model also checks committed, lock, and every own-QC root and its parent
lineage. A required missing parent, cycle, exhausted lineage budget,
accounting inconsistency/overflow, excessive victim plan, or insufficient
safe victims refuses without changing the model.

The candidate's complete retained parent lineage is protected, including
the R -> A -> P -> C witness: selecting A while preserving only direct
parent P fails the common invariant; preserving the full lineage passes.
This conservative full-lineage rule is a test-model choice, not a selected
production policy. The candidate lineage is checked even when `D = 0`;
unrelated cycles are not scanned in that case.

Victim selection first scans the synthetic queue, skipping stale IDs,
duplicates and protected IDs. It then uses sorted `BTreeMap` keys as a
deterministic fallback. That fallback is specific to this model; it does
not claim stable production `HashMap` ordering or exact legacy queue
semantics. Successful publication removes all queue occurrences of selected
victims while retaining unrelated stale and duplicate entries. The planner
checks local charges with checked subtraction/addition and shared-evidence
ownership, releasing shared charge only when its final modeled owner is
removed. Accounting projection is completed before publication.

The plan owns a cloned snapshot and generation. Publication rejects a stale
or substituted model before effects, then rechecks required ancestry,
victim distinctness/protection and candidate-lineage preservation. It
revalidates expected accounting, queue, retained candidate/victims and
accounting consistency after publication. This is a single-threaded model,
not an exclusive engine owner: production would need exclusive ownership
or another reviewed admission/revocation mechanism plus cancellation-safe
observation and revalidation before effects.

Publication faults after queue edit, first victim removal, and registration
are injected test controls, not demonstrated production failure paths. They
leave modeled partial state and return explicit unresolved phase/effect
observations; they do not simulate rollback. A final postcondition failure
is also unresolved. After each actual modeled victim removal, the phase is
advanced before any subsequent generation/accounting failure can be reported.
The outcome model keeps completed prefix items separate
from current-item phase (`BeforeMutation`, `Registered`, or
`ReplayingSigners { completed }`). It keeps signer dispositions separate
from whether a QC formed. The four effect observations are ordered as
registration, eviction/accounting, vote replay, and QC/lock/commit.
`NotObserved` differs from `ConfirmedNoEffect`; `KnownDetailsUnavailable`
preserves a known effect without asserting its details. Exhaustion retains
unresolved ownership and a count of known effects that could not be
recorded; that count is not a reconstruction of their payload. Neither
`Complete` nor a no-effect refusal permits participation in this model.
If the late/conflicting-evidence storage limit is exceeded, the model
records `EvidenceLimitExhausted` and unresolved ownership but does not retain
the over-limit evidence payload.

All fixture bounds are synthetic only: 4 input items, 4 signers per item,
4 victims, 32 lineage visits, 8 prefix effect observations and 2
late/conflicting evidence records. The `u16` block identifiers and model
metadata are also fixture choices. A planner bound applied after decoding
does not bound transport, deserialization or earlier vector allocations.
The 128-item outbound setting is not an inbound limit; 64-KiB production
sufficiency remains unestablished.

## Controls and execution record

The dedicated integration test is a separate Cargo test crate importing the
support module explicitly by path. It has no participation capability and
does not invoke the actual catch-up engine. Its 11 tests cover:

* R -> A -> P -> C and the direct-parent-only negative control;
* zero, free, exact-capacity and already-over-limit deficits;
* existing-ID refusal, committed/lock/own-QC ancestry protection and the
  full deficit;
* deterministic fallback, stale/duplicate queue handling, missing and
  cyclic required lineage, work-budget exhaustion and unrelated cycles
  when `D = 0`;
* refusal without mutation when the full safe victim set is unavailable;
* checked local/shared accounting, final-owner shared release and
  stale/substituted snapshot refusal;
* injected partial-publication failures with explicit unresolved outcomes;
* bounded prefix/current-item outcomes, signer dispositions, distinct
  unknown/no-effect states, late/conflicting evidence, and refusal to infer
  QC formation or participation from a completed signer loop.

Fresh final command:

```text
cargo test -p qbind-consensus --test a33_f1_ordered_planner_model_tests -- --nocapture --test-threads=1
exit 0; 11 passed, 0 failed, 0 ignored
```

Toolchain/platform: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`,
`cargo 1.99.0 (5f94df478 2026-08-27)`,
`rustfmt 1.10.0-stable (58cf8f9c35 2026-10-13)`,
Linux x86_64 (`6.12.8+`, `adc-sandbox`). The full captured output is
`ordered-planner-focused-tests.log`, SHA-256
`f9fb7091b9af9cd2572d2654374e12e07243591138a2d1ffcd4282677809d6ec`.
It reports 37 warnings from the existing
`qbind-consensus` library compilation; none is a test failure. No tests
were ignored. `rustfmt --edition 2021 --check` on the two Rust files
completed with exit 0.

The focused test was iterated after test compile/expectation failures. The
initial partial-move failure is retained in
`ordered-planner-initial-compile-failure.log` (15,219 bytes, SHA-256
`7db0e41f1653d1ff89f03e3d5631ba4797e7fb11add2ca364d869250504f7c19`).
The first fixture failure is retained in
`ordered-planner-fallback-expectation-failure.log` (15,570 bytes, SHA-256
`c8f6a50d9104d2b9a03e90c8d3f50c863097cc788b0eaba10161b71dd0021272`):
the full deficit was two victims, not one. Three intermediate failures
were observed but their temporary full logs were overwritten by later
attempts; their captured-output hashes and causes are recorded here, not
represented as archived raw files:

* SHA-256 `227e40721ed5699c6486e87925efdc696034823196e58d0f3f8bce8bca01306b`:
  the initial overflow fixture released the selected victim's charge and
  therefore did not overflow.
* SHA-256 `04f5c955a064fed094c716e99121c63f409f9540321c40036c5e32d72e244ccc`:
  protecting the only possible victim caused the expected safe-victim
  refusal before accounting overflow.
* SHA-256 `04b5c164c50e96c53182c326569683e715615883499f6c9dc3ee8eb29bad9fc5`:
  the corrected two-block fixture reused an existing candidate ID.

An earlier successful 10-test iteration was observed with captured-output
SHA-256 `1a4f01886f2a2858128efbff5b66f7e6d4e4bd95ca11661521a7128d94799d09`,
but its temporary raw log was overwritten and is not retained as a full
file. Three earlier 11-test iterations are retained as
`ordered-planner-prior-11-test-iteration.log`, SHA-256
`82ad342700d16d4b62fe38ad124561117910e7f0ebe69bee5587e1b7de284e57`, and
`ordered-planner-pre-exhaustion-11-test-iteration.log`, SHA-256
`767bd5e6f3b575b84ad074898f97bc626042cf753bdea76f772a7338bc2d8036`.
These precede the correction that prevents exhaustion from inventing known
effects. The third is
`ordered-planner-pre-phase-update-11-test-iteration.log`, SHA-256
`8c6c3a0d1ed698b23e9416fe5993c586cc3dbb6f32d6b33e2e36bb40a5b0d1f2`;
it includes the effect-accounting correction but precedes the final
post-removal phase update. The final 11-test execution is the current
verification.

No existing engine, node, RUN 422, authority-reset, integration, or
historically accepted tests were rerun for this isolated model task. No
production source, caller, startup, signer, storage, network behavior,
authentication, crypto setting, operational gate, audit register or prior
evidence was changed. This does not establish a global block-capacity
bound, input-allocation bound, actual engine/caller correctness, atomic
rollback, retry safety, durable quarantine, production readiness,
authenticated remote exploitability, or permission to resume.

The targeted check of the nine newly appended checksum entries passes;
this is not a rerun or pass of the historical ordinary checksum check.
The full staged `git diff --cached --check` exited 2 because the byte-
preserved raw logs contain trailing whitespace: one test-result line in the
fallback-failure log and blank lines at EOF in four successful logs. Its
captured diagnostic output was retained outside the checkout at
`/tmp/a33-f1-ordered-planner-whitespace-check.log` (SHA-256
`c304b6d81c3a2fbc21b7414b76ffac096a2c8f2845638d2fe72da60c34baad74`).
The same check restricted to Rust source, plan, manifest and this evidence
file exited 0. Those raw logs are not normalized, so their captured bytes
and hashes remain intact. Historical ordinary-checksum and whitespace
non-passes remain accurately classified.

The manifest includes the support source, focused test source, plan,
evidence document and six raw logs. It does not hash itself, so no
self-referential checksum cycle is created.
