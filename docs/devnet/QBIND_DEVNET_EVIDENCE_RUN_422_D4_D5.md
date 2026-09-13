# QBIND Public DevNet — Run 422 D4/D5 Evidence

**Consensus-security preflight ordering (D4) and message-family authority
separation (D5) — code + test evidence**

- Actual working branch (as checked out): `copilot/copilotcopilotrun-422-follow-up-d4-d5-startup`
  (the environment supplied a doubled-`copilot` prefix; recorded verbatim
  rather than the `copilot/copilotrun-422-follow-up-d4-d5-startup` named in the
  task).
- Checkout shape: **shallow, squashed single-branch** clone. `git rev-list
  --count HEAD` = 2; `git rev-parse --is-shallow-repository` = true.
- Reviewed tip named by the task: `6ecec71439afec6c007d628ab6d31d5190b7be51` —
  **ABSENT** from this checkout (`git cat-file -t` cannot resolve the object).
  Previously-tested revision named by the task:
  `e1b95948c6ce604aa97f317e88f8c8b2e41a6b2b` — also **ABSENT**. Git ancestry to
  either object therefore **cannot be established** and is not claimed. The
  reviewed D4/D5 implementation is nonetheless **demonstrably present** in the
  worktree (the D4 process-test file, the D5 `mod run420` tests, and the
  message-family split in `binary_consensus_loop.rs` are all in tree and pass),
  so this continuation proceeds and records the deviation honestly.
- Comparison base for this continuation's diff: `5a19be10a32eac91fd8210b163c91ff259dd7b92`
  (the checked-out HEAD before this continuation's commits).
- Tested revision (all test counts below): this continuation's tip
  (`43dedea…` for the A/B code/test commit; documentation commits follow).
  The re-run test targets execute against the current worktree, not against the
  absent `e1b959…`.
- This is a **continuation** of the existing D4/D5 work (Findings A–D of the
  final review). Run 423 is **not** started and genesis authority is **not**
  activated.

## Verdict (scoped code + test result)

```text
RESULT=POSITIVE-FOR-CONSENSUS-SECURITY-PREFLIGHT-AND-CONTEXT-SEPARATION-CODE-TEST
D4_STATUS=PRE-P2P-AND-CONSENSUS-PREFLIGHT-CODE-TEST-POSITIVE
D5_STATUS=MESSAGE-FAMILY-AUTHORITY-SEPARATION-CODE-TEST-POSITIVE
GENESIS_AUTHORITY_ACTIVATION=DISABLED-PENDING-REMAINING-BOUNDARIES
LEGACY_TIMEOUT_CONTEXT=EXISTING-POLICY-PRESERVED
PROPOSAL_VOTE_AUTHORITY_FROM_LEGACY_CLI=DISALLOWED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

Implementation, validation, and runtime-evidence axes are kept separate. The
POSITIVE label is a **code + test** result. It is not a runtime,
release-binary, or public-deployment claim.

## What this run adds

This continuation resolves Findings A–D of the final review. The D5 test
inventory is described **by setup category** below; not every D5 test supplies
both contexts, an authenticated origin, a binding gate, and a recording facade,
and this document no longer implies that.

1. **Finding A — bounded D4 process runner**
   (`crates/qbind-node/tests/run_422_d4_startup_ordering_tests.rs`). The
   negative helper no longer calls `Command::output()` with no timeout, and the
   positive case no longer sleeps a fixed six seconds before reading piped
   output. A single shared `DrainedChild` runner now:
   - uses an explicit finite deadline measured with a monotonic clock
     (`std::time::Instant`; `NEGATIVE_DEADLINE`/`POSITIVE_DEADLINE` = 30s);
   - drains **both** stdout and stderr on dedicated threads WHILE the child
     runs, so a full OS pipe buffer can never block startup;
   - waits for **natural** termination within the deadline for negative cases —
     a timeout is a hard **TEST FAILURE**, never an acceptable nonzero refusal;
   - waits for the readiness markers within the deadline for the positive case;
   - kills and reaps the child (and joins the drain threads) on timeout, on
     successful positive observation, and on assertion-driven unwinding (via
     `Drop`) — an exited child is still reaped, because a zombie requires an
     explicit `wait()`;
   - caps captured output for bounded memory while keeping a diagnostic prefix;
   - clears inherited env (`QBIND_METRICS_HTTP_ADDR`, `QBIND_MUTUAL_AUTH`,
     `QBIND_DRAIN_ONCE_DELAY_SECS`, `QBIND_DEVNET_FORGED_INJECTION`) so fixtures
     stay isolated, and binds `127.0.0.1:0` for the positive case.
   The four negative cases and the positive legacy-configuration control are
   retained unchanged in intent; the resource-discipline module comment is
   corrected (no “deterministic exit ⇒ no reaping” claim; absence of a log line
   is interpreted together with inspected source ordering, not as standalone
   proof that no listener was opened).

2. **D5 combined-context inbound tests** (`binary_consensus_loop.rs`,
   `mod run420`) — a valid `TimeoutVerificationContext` (live signer), a real
   `PeerConsensusBindingGate` + matching `AuthenticatedConsensusOrigin`,
   `proposal_vote_authority = None`, `Required` policy, encoded Proposal/Vote
   through the real `handle_inbound_consensus_msg`:
   - `run422_d5a_authenticated_proposal_timeout_only_rejects_before_crypto`
   - `run422_d5b_authenticated_vote_timeout_only_rejects_before_crypto`

3. **D5 F6-mismatch tests** — same combined context, but the authenticated
   origin is deliberately mismatched to the claimed sender, proving F6
   rejection precedes the Proposal/Vote authority lookup (a recording binding-
   gate metric proves the crypto verifier was never reached):
   - `run422_d5c_proposal_f6_mismatch_precedes_pv_authority_lookup`
   - `run422_d5c_vote_f6_mismatch_precedes_pv_authority_lookup`

4. **D5 action-forwarding test** — drives the actual
   `forward_actions_to_facade` engine→facade boundary with a **recording
   facade** and `proposal_vote_authority = None`; no context/origin/gate are
   involved because outbound forwarding does not consult them:
   - `run422_d5d_outbound_forwarding_suppressed_without_pv_authority`

5. **D5 type/source-wiring inspection** — asserts the Timeout context is valid
   for its own family and that a correctly-signed authenticated Proposal is
   still rejected authority-unavailable; it does **not** itself sign or verify a
   Timeout (see “Timeout coverage attribution” below):
   - `run422_d5f_timeout_context_usable_only_for_its_own_family`

6. **Finding B-A — NEW Required-policy late-peer re-emission test.** Drives the
   actual `maybe_reemit_on_late_peer_connect` function (the B9/B10 tests only
   exercise it under `LocalFixtureUnsigned`, which cannot prove Required-policy
   suppression) with `Required`, absent Proposal/Vote authority, a cached
   current-view proposal **and** cached vote, a leader/current-view engine, a
   genuine newly-connected-peer transition, and a **recording facade**. All
   re-emission preconditions (gates 1–7) are satisfied so control reaches the
   authority/signing boundary — proven by
   `outbound_proposal_verification_context_unavailable_total == 1` — and the
   fail-closed signer refusal suppresses the broadcast. **Control-flow honesty:**
   the proposal is signed first and returns `None`, so the function returns
   before the paired cached-vote branch; the vote-signing branch is therefore
   **not** independently exercised (the outbound *vote* authority-unavailable
   counter stays 0) and no such claim is made:
   - `run422_d5g_late_peer_reemit_suppressed_under_required_without_pv_authority`

7. **Finding B-B — NEW active restore-mode Proposal rejection test.** Restore
   catchup mode is made demonstrably **active** (snapshot baseline at height 5),
   with a valid Timeout context, absent Proposal/Vote authority, `Required`
   policy, a real binding gate + matching origin, and a Proposal shaped (height
   7 > committed+1) to reach restore deferral if admitted. A positive control
   proves the same-shaped proposal **is** deferred once a Proposal/Vote
   authority is present. The main case proves F6 admission succeeds, then the
   Proposal/Vote authority-unavailable rejection fires **before** the restore-
   deferral branch: no deferral, no delivery, no reconfig observation, no engine
   delivery, and (via a **recording facade**) no outbound response; restore and
   engine state are unchanged:
   - `run422_d5h_active_restore_mode_proposal_rejected_authority_unavailable`

8. **D4 startup-ordering process tests** (Finding A file). Five bounded tests
   spawn the real `qbind-node` via `CARGO_BIN_EXE_qbind-node` with valid
   temporary DevNet configuration:
   - four RequireOrFail negative cases (missing local signer; invalid peer
     key-provider hex; unsupported suite id; local key mismatches the loaded
     signer) each asserting a nonzero natural exit, the `[binary] Run 032:`/`Run
     033:` preflight positive-control present, and the post-build
     `[binary] P2P transport up.` marker absent — refusal **before** P2P service
     construction (`builder.build()`), peer dialing, and consensus-task startup;
   - one positive case (valid legacy configuration) that passes preflight,
     activates the Timeout/NewView context, and reaches
     `[binary] P2P transport up.` with Proposal/Vote authority still absent.

9. **Stale-comment corrections** in `binary_consensus_loop.rs`: the
   `ConsensusVerificationPolicy` doc block, the `verification_ctx` and
   `verification_policy` field docs, and the inbound-handler comment name the
   `proposal_vote_authority` dependency for the Proposal/Vote family (previously
   mis-attributed to `verification_ctx`). The legacy activation route is
   described precisely: its Timeout/NewView policy is preserved, but its former
   ability to also enable Proposal/Vote has been removed. Historical Run 420–422
   facts are retained and separated from the current successor behavior.

## Timeout coverage attribution (Finding C-B)

`run422_d5f_timeout_context_usable_only_for_its_own_family` checks the Timeout
context's fields and a Proposal-family rejection; **it does not itself sign or
verify a Timeout/NewView.** Actual Timeout/NewView cryptographic coverage is
provided by the existing **run030** tests in the same `binary_consensus_loop`
library suite — e.g. `run030_outbound_signs_locally_emitted_timeout` (signs a
locally-emitted Timeout with a live signer and round-trips it through
`verify_timeout_msg`) and `run030_outbound_fail_closed_when_signer_missing`
(no-signer context ⇒ no Timeout broadcast, fail-closed), plus the inbound
`TimeoutMsg` verification-gate tests. Those tests use a
`TimeoutVerificationContext` built from the same ML-DSA-44 (suite 100) fixture
keys over `QBIND_DEVNET_CHAIN_ID` and drive `maybe_emit_view_timeout` /
`handle_inbound_consensus_msg`; the outbound path is exercised under the
context's own signer policy (present ⇒ signs; absent ⇒ fail-closed). No new
production Timeout implementation was added to satisfy a documentation claim.

## The metrics exception (D4 scope)

`main()` may spawn the optional metrics HTTP server (`main.rs:4643`, gated by
`QBIND_METRICS_HTTP_ADDR`) **before** entering the per-mode P2P function and
its consensus-security preflight. Therefore D4 is scoped as *preflight before
P2P service construction, peer dialing, and consensus-task startup* — **not**
before "any networking", "all listeners", or "every service". The preflight
function itself starts no network service, and no unrelated metrics/storage
startup was moved. See
`run_422_d4_d5_preflight_context_separation/startup_order.txt`.

## Evidence archive

`docs/devnet/run_422_d4_d5_preflight_context_separation/` contains: `README.md`,
`summary.txt`, `source_trace.txt`, `activation_matrix.txt`, `startup_order.txt`,
`message_family_matrix.txt`, `commands.txt`, `test_results.txt`,
`SHA256SUMS.txt`, `.gitignore`. `SHA256SUMS.txt` covers every publish-safe file
in that directory except itself and `.gitignore`.

## Validation summary (Finding C-F)

Commands are listed with profile/features/exit code in `commands.txt`; per-target
counts are in `test_results.txt`. Re-run test targets executed against this
continuation's worktree (default test profile, default features):

- `binary_consensus_loop` lib module — **106 passed** (was 104; +2 new:
  `run422_d5g`, `run422_d5h`).
- `run420::run422_d5` filter — **12 passed**. This is a **subset** of the 106
  above (same lib binary), listed for locating the D5 cases; it is **not**
  additive and must not be double-counted.
- `run_422_d4_startup_ordering_tests` — 5 passed.
- `run_422_startup_refusal_tests` — 4 passed;
  `run_420_production_policy_reachability_tests` — 3 passed;
  `run_418_authenticated_peer_consensus_sender_binding_tests` — 18 passed;
  `run_422_genesis_consensus_authority_tests` — 15 passed (unchanged);
  `b9_late_peer_connect_proposal_reemit_tests` — 6 passed.

Clippy (`cargo clippy -p qbind-node --lib --tests`) introduced no new warnings
from the changed regions. rustfmt was applied to the changed test file only; no
mass-formatting. Because these are **tests-only + documentation** corrections,
the previously-recorded production check (`cargo check -p qbind-node`) and
release build (`cargo build --release -p qbind-node --bin qbind-node`) are
**preserved at their original tested SHA** and are **not** relabeled as freshly
executed against this tip (no production code or build configuration changed).
The `m16_epoch_transition_hardening_tests` target needs `--features test-utils`
(pre-existing, unrelated) and is recorded separately. “All validation passed” is
**not** asserted: security analysis was not completed (below).

## Security analysis / CodeQL status (Finding C-D)

CodeQL analysis was **attempted** via this environment's scan tool and was
**skipped / did not complete because the database size is too large** (the tool
reported "Analysis was skipped because the database size is too large"). The
accompanying "0 alerts" figure is a consequence of that **skip**, **not** a
completed clean/zero-alert result, and is not represented as one. No execution
timestamp or zero-alert conclusion is asserted or invented. The parallel Code
Review invocation returned a **model-registry error** (`model claude-sonnet-4.6
not found in registry`); it is therefore **not** described as an unqualified
successful review, and a code review is in any case **not** a substitute for
completed CodeQL analysis. `test_results.txt` records this CodeQL status as
`ATTEMPTED-SKIPPED (database too large)`. Incomplete security analysis is
tracked on a separate validation axis from the scoped POSITIVE code/test result.
Secret / privacy scan of changed files is clean.

## Preserved limitations and readiness (unchanged)

Genesis-authority activation remains DISABLED pending D4-D7. D6 (signed-domain)
and D7 (epoch/restore authority lifetime) remain UNRESOLVED. F3/F4/F8 are not
fully remediated/activated in production; F6 remains partial; F1/F2/F5/F7 are
unresolved (F5 — TimeoutCertificate signer — is **not** closed). RS1 and C4/C5
remain OPEN. M4/M6/S5/S7 remain Yellow. Public DevNet remains **NO-GO**; no
live-seed / TestNet / MainNet readiness is claimed. Configured-authority
release-binary adversarial evidence is **not** captured (default-profile
process tests are not standalone release-binary evidence). The liveness
limitation is intentional: under Required with Proposal/Vote authority absent,
inbound Proposal/Vote are rejected and outbound Proposal/Vote are suppressed
(fail-closed). Run 423 is **not** started.