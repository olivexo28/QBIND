# Empty RestoreCatchupResponse containment implementation

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.**
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**.
Activation remains **DISABLED**; public DevNet remains **NO-GO**.

## Authority, starting identities and preserved evidence

The user supplied **PASS WITH LIMITATIONS** for the candidate contract.
No reviewer identity or unavailable raw review artifact is asserted. The
[pre-implementation qualifications](QUALIFICATIONS.md) were added before
source changes; the [earlier contract](../containment-contract-20261107/README.md)
and investigation remain byte-for-byte historical evidence, including their
then-FUTURE acceptance cases. This record reports new executions separately.

Repository: `olivexo28/QBIND`, origin `https://github.com/olivexo28/QBIND`.
The clean starting branch was `investigation/empty-restore-response-20261107`;
local HEAD and direct remote task ref both matched
`30a79a21996c11f97f1c496082551dba4cbd3a45`, tree
`d903a8671192f09be763fdb6c11b7ad4c883d62e`, parent
`fb29cef67ba4d7c918f4299a9b60de79cd6f41ef`.
Protected direct remote main matched
`541d9a6c9a43fe10410260d9c2494a5fc4416c7a`, tree
`0b0e597a29dc8f2d95d93f9bd04364cc140a9db1`, and was an ancestor.
Worktree/staging were clean. No reset, rebase, discard or force was used.

The main source tree is identical to the earlier reviewed endpoint
`2d3b2f7a4c4055882525e3af1814d57e87c01c76`. The historical manifests
are checked against their producing revisions, not against today's appended
plan: investigation at `fb29cef67ba4d7c918f4299a9b60de79cd6f41ef`,
contract at `30a79a21996c11f97f1c496082551dba4cbd3a45`.
The plan's entire starting blob is preserved as an exact byte prefix.
Audit register, prior evidence, main/configuration and engine source are
unchanged. `CHANGED_PATHS.txt` lists the complete delivery;
`SHA256SUMS` binds every changed file except itself.

## Exact implementation boundary and metric semantics

Only `binary_consensus_loop.rs` and `metrics.rs` change production source:

1. Generic inbound observation and installed-gate sender admission remain.
   An installed gate rejects absent/unknown/ambiguous/mismatched origins
   before receipt accounting, ignored accounting or non-empty rejection.
2. Receipt's existing saturating update remains after admission.
3. The unconditional A17 non-empty rejection block is preserved verbatim.
4. Empty input attempts one `saturating_add(1)` on
   `restore_catchup_empty_responses_ignored_total`, then returns. No direct
   response-helper call, peer-height evaluation, mode clear/rearm, anchor
   correlation, outbound action or per-frame empty log is introduced.
5. The loop's existing metrics synchronization passes that counter through
   `RestoreCatchupMetrics::set` and exports
   `qbind_restore_catchup_empty_responses_ignored_total` without labels.

At `u64::MAX` an attempted update remains `MAX`, never wraps or panics, and
is a lower bound on lifetime qualifying events. Receipt, ignored and
non-empty rejection counters saturate independently. Receipt-plus-ignored
is intentional stage accounting, not two ignored events. The counter is
observability only and cannot authorize recovery, clearance or participation.

The callable no-gate compatibility/test path still returns `Ok(claimed)`.
It does not authenticate the origin; empty input still returns at the same
boundary. Bound self-labelled fixtures and inactive mode receive no exemption.

The direct helper's function body and engine import operation are unchanged,
not made transactional. Its unchanged old scalar behavior remains available
only for direct characterization, not current production response dispatch.
Source comments now distinguish that retained behavior from live ingress.
Omitted/after-helper sensitivity controls are confined to `#[cfg(test)]`
code and a thread-local, RAII-reset test control. They traverse the same
actual handler's binding, receipt and non-empty guard. Production compilation
contains neither the hook's call nor the test-only defects.

### Pinned source and evidence types

Historical binding, handler and downstream references remain pinned in the
accepted contract to frozen `541d9a6c9a43fe10410260d9c2494a5fc4416c7a`.
For example: [binding admission](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/peer_consensus_binding.rs#L388-L447),
[original response arm](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L7393-L7425),
[retained direct helper](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/binary_consensus_loop.rs#L8450-L8505),
and [production Required wiring](https://github.com/olivexo28/QBIND/blob/541d9a6c9a43fe10410260d9c2494a5fc4416c7a/crates/qbind-node/src/main.rs#L8680-L8710).
Post-change source and tests are pinned by the exact source SHA-256 entries
in this delivery's manifest and the final-source validation logs; publication
identifies the resulting commit/tree/parent without a self-referential hash
inside this commit.

Earlier user reports/accepted tests remain evidence within their scopes.
The new deterministic handler/downstream results below are new runtime test
evidence, not executed exploits, deployed peer behavior, production transport
authentication, positive recovery or external implementation compatibility.

## Executed acceptance map

All new tests call the actual handler where applicable, use the A17 recording
facade and the same `a17_check_protected` oracle, and separately assert permitted
generic/binding/receipt/ignored/rejection accounting. The correct path also
compares the entire statistics bag after normalizing only those permitted
updates. The oracle observes the same engine's Debug state, mode and outbound
record; it does not inventory allocation capacities or opaque recorder internals.

| Contract row | Executed controls | Qualification |
|---|---|---|
| H1, H2 | `empty_containment_h1_h2_h4_h5_h6_h7_handler_matrix` | Installed four-member gate; admitted non-self and local-origin/self fixtures. These are constructed origins, not live transport sessions. |
| H3 | `empty_containment_h3_installed_binding_failures_and_no_gate_compatibility` | Six installed-gate failure categories with reason counters; 12 absent-gate compatibility cases. Compatibility is not authenticated admission. |
| H4, H5, H7 | Same 480-combination matrix / 960 handler calls | `None`, lower/equal/higher/MAX height; five prior-target values; local None/4/5/8 versus baseline 5; active/inactive; deliberately mismatched request height/ID and no emitted/outstanding request. Missing/below-local and mismatched startup baselines are fixture states, not production initialization histories. |
| H6 | Matrix repeats plus `empty_containment_h6_repeated_differing_heights_do_not_clear_or_rearm` | Same-state None/lower/equal/inflated/MAX/lower sequence, including directly established historical inactive state. No production clearing is claimed. |
| H8, H9 | `empty_containment_h8_h9_same_oracle_detects_omitted_and_after_helper_guards` | Correct path returns `Ok(())`; both defective test-only paths yield `Err(["restore_mode"])` from the SAME oracle, with old target/exit-height effects and no outbound action. Passing these tests means sensitivity was detected, not that defects were accepted. |
| H10 | Existing A17 handler controls plus new saturation/sensitivity controls | Preserved non-empty refusal, self/non-self/anchors/authority/no-gate shapes, populated vote/QC state and non-transactional import sensitivity. New ignored counter stays unchanged on non-empty rejection. |
| Saturation qualification | `empty_containment_counter_saturation_and_distinct_nonempty_accounting` | 27 receipt/ignored/rejected combinations of 0/MAX-1/MAX; repeated empties, repeated non-empty responses, installed-gate failure; independent saturating updates without panic or wrapping. |
| D1 | `empty_containment_d1_request_cadence_anchor_facade_and_honest_empty_export` | Active/inactive, missing/present committed anchor, absent/success/failing recording facade, cadence and honest empty-export no-response behavior. Failed sends are recorded attempts, not successful sends. |
| D2 | `empty_containment_d2_proposal_deferral_requires_independent_current_authority` | 18 active/inactive, near/correct-parent, near/wrong-parent, far, absent-PV/no-owner/admitted-snapshot combinations. Real test signatures; no embedded QC invented. Current authority precedes deferral; admitted near proposals mutate engine in active mode, but missing PV signer prevents outbound vote signing. |
| D3 | `empty_containment_d3_timeout_active_suppression_and_inactive_prerequisites` plus targeted timeout/F7 regressions | Active suppression, disabled threshold, absent facade, below/exact timing boundary, absent context/signer, identity mismatch, eligible NoQc test-signing/once-per-view, and present logical-QC/no-authority refusal. Separate retained exact-proof and mandatory signer/refusal regression cases remain distinct from NoQc. |
| D4 | `empty_containment_d4_single_validator_leader_progress_is_not_bound_peer_evidence` | Six real leader ticks per active/inactive single-validator fixture establish local committed progress above baseline with publication suppressed by Required/no-current-authority. No inadmissible non-self peer is added; H1 separately uses four members. |
| Separate routes | `empty_containment_downstream_inbound_timeout_newview_are_not_mode_fenced` | Four active/inactive Timeout/NewView cases with real peer test signatures, installed origin admission, quorum and absent high-QC; engine view advances independently while restore mode stays unchanged. No local timeout signer is needed for peer evidence. |

The 480-case matrix is a Cartesian fixture characterization, not proof that
all combinations arise in the integrated production binary. A progressed
multi-validator production instance coexisting with a valid non-self responder,
external wire compatibility and actual deployed transport/configuration remain
**UNRESOLVED** without separately authorized evidence. No production checks
were weakened to manufacture those states.

## Commands, results and unsuccessful attempts

Cargo commands use `PATH=/usr/local/cargo/bin:$PATH`. Every named log retains
complete stdout/stderr, the exact cargo command and exit status; final-source
regression/production logs also record the exact production-source hashes.

| Log / command | Result |
|---|---|
| `focused-verified.log`: `cargo test -p qbind-node --lib empty_containment_ -- --nocapture` | Exit 0; 10 passed, 0 failed/ignored; 2236 filtered out. |
| `regressions-verified.log`: same lib runner with filters `a17_`, `restore_mode_`, `b14_view_timeout_`, `run422_mandatory_timeout_`, `run422_f7_retained_qc_local_timeout_`, `ca_c_leader_tick_missing_journal` | Six exits 0; respectively 9/9/5/4/3/1 passed; 31 distinct regression tests. |
| `production-verified.log`: `cargo check -p qbind-node --lib --bin qbind-node` | Exit 0; default production library/binary compilation, no node launched. Compiler warnings retained. |
| Same log: `cargo test -p qbind-node --test run_420_production_policy_reachability_tests -- --nocapture` | Exit 0; 3 source-only tests passed; no subprocess/node/network test. |
| `documentation-checks.log` | Exact validation script/commands/output: historical hashes/producing manifests, unchanged plan prefix/helper/guard/binding, scope, formatting, and final integrity verification. |

Final successful selections execute **44 distinct tests** (10 new, 31 focused
regressions, 3 production-policy source controls), not the full historical
suite. Regression selection specifically checks the changed A17 oracle/
empty expectation, retained helper behavior, and the reviewed downstream
timing, signer, journal and retained-QC obligations. Unrelated historical
suites and node-spawning integration tests were not run.

`tooling-attempts.log` records unsuccessful PATH/discovery commands.
`focused-attempt-1.log` failed with exit 101 because libclang was absent;
no tests ran. Only then was libclang-dev installed; the complete dependency
install output/exit 0 is retained. `focused-attempt-2.log` passed 9 tests.
`focused-final.log` also passed 9, but a newly added H6 test was accidentally
nested and not discovered: this was **incomplete coverage**, despite exit 0.
Its warnings are preserved; after correction, `focused-complete.log` passed
all 10. The subsequent final strengthened D2 oracle passes in
`focused-verified.log`. Precursors without recorded source hashes are not
retroactively asserted to be final-source executions.

`whitespace-attempt.log` preserves the unsuccessful plain `git diff --check`
attempt (exit 2), which treats the existing CRLF source convention as trailing
whitespace. New test code was rustfmt-formatted in isolation, retaining original
source CRLF and avoiding unrelated formatting. The CRLF-aware whitespace check
and append-only documentation checks are the applicable final controls.
The first two documentation validator attempts exited 1 after incorrectly
requiring a terminal newline, first on the binary-loop source and then on
metrics source (their reviewed and delivered blobs lack one). The validator
was corrected to compare both source files' original EOF conventions; failed
outputs and revised scripts/executions are retained.

## Remaining obligations and liveness impact

An empty response cannot now update the existing maximum, clear or rearm mode
or drive a handler-originated action, irrespective of optional height, self
label, prior target, mode, anchor or absent request. It does not authenticate
reported height or supply recovery/currentness authority.

Restore mode may remain active indefinitely, preserving eligible request
attempts, selected proposal deferral and local-timeout suppression. Pinned
honest empty-export handling emits no response; external behavior remains
unverified. No allow/clear/resume mechanism or fallback was added.

Active mode is not a complete engine/signer fence. Eligible proposals, leader
ticks, verified peer Timeout/NewView routes and their remaining authority,
signer, journal, timing, quorum, F7 and publication checks remain separate.
Positive recovery/currentness, global signer exclusivity, durable quarantine
and clear/resume authority are separate open obligations. This implementation
does not authorize participation, activation or public DevNet.

No operational signing keys, live network, node activation, PR, merge,
main push or force push forms part of this task. Only the existing task
branch is committed/pushed; final identities and clean state are verified
and reported after publication.
