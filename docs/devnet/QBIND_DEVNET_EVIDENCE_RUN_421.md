# QBIND DevNet Evidence — Run 421

**F3/F4/F8 unavailable-authority fail-closed release-binary evidence.** Run 421
captures the **standalone release-binary runtime evidence that Run 420 left
`NOT-CAPTURED`**: it proves, through real loopback KEMTLS traffic and live
`/metrics`, that a fresh `target/release/qbind-node` built from the recorded
Run 421 runtime commit enforces the Run 420 `ConsensusVerificationPolicy::Required`
policy on its deployed binary path when consensus verification authority is
**unavailable**. This is **Route A — evidence-only**: no production Rust,
`Cargo.toml`, `build.rs`, or CLI change; only a Cargo-example driver helper, a
harness, and curated publish-safe evidence.

This run proves **fail-closed deployed behavior under unavailable authority**. It
does **not** prove configured-authority cryptographic success — no consensus
signing authority exists on the standalone binary, so
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-CAPTURED`.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
local loopback · standalone release binary · unavailable-authority fail-closed
boundary only · **NOT configured-authority signing/verification** · **NOT
off-host attestation** · **NOT liveness-positive** · **M4 Yellow /
launch-blocking** · M6 Yellow/Partial · S5 Yellow · S7 Yellow · **RS1 OPEN /
launch-blocking** · **C4/C5 OPEN** · public DevNet **NO-GO** · no TestNet
readiness · no MainNet readiness. **No private key material, certificate, raw
log, raw metric dump, or data directory is committed.**

## 1. Exact verdict

```
RESULT=PARTIAL-POSITIVE-FOR-F3-F4-F8-UNAVAILABLE-AUTHORITY-FAIL-CLOSED-RELEASE-BINARY-EVIDENCE
F3_STATUS=CONFIGURED-PATH-CODE-TEST-REMEDIATED / UNAVAILABLE-AUTHORITY-RELEASE-BINARY-FAIL-CLOSED
F4_STATUS=CONFIGURED-PATH-CODE-TEST-REMEDIATED / UNAVAILABLE-AUTHORITY-RELEASE-BINARY-FAIL-CLOSED
F8_STATUS=CONFIGURED-PATH-CODE-TEST-REMEDIATED / UNAVAILABLE-AUTHORITY-RELEASE-BINARY-FAIL-CLOSED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

The verdict is `PARTIAL-POSITIVE` (not `POSITIVE`) because the two naturally
**outbound** suppression scenarios (S7 Proposal, S8 Vote) are **UNREACHABLE** on
the standalone binary without activating consensus authority or adding unsafe
controls: with no configured authority and no connected authenticated peers, the
node never advances views to a natural leader-Proposal emission opportunity
(`leader_changes_total = 0`), and because inbound Proposal is rejected before
engine ingestion, no outbound Vote is ever generated. All **inbound**
fail-closed scenarios (S2–S6), the S1 baseline, and the S9 CLI/fixture denial
pass on the deployed release binary.

## 2. Trust model (explicit)

* **KEMTLS** authenticates the transport session only.
* **Run 418 F6** binds the authenticated peer to the claimed immediate consensus
  sender. A transport-authenticated frame is **not** cryptographically
  authenticated at the consensus-message level.
* **Run 420** would verify Proposal/Vote signatures and suites **if**
  authoritative consensus context were available. On this standalone binary it is
  not (`verification_ctx == None`), so the correct behavior is
  **rejection/suppression, not signature acceptance**.
* Live metrics and logs are **local** observations, not independent off-host
  attestation. `SHA256SUMS.txt` protects curated files after capture but does
  not independently authenticate the original observations.

## 3. Runtime topology

Three validators on `127.0.0.1`, OS-assigned loopback ports, fresh data
directory per scenario:

| Validator | Role |
|-----------|------|
| 0 | legitimate leader/victim identity (impersonated in S4) |
| 1 | authenticated driver (Cargo-example client) |
| 2 | **standalone `target/release/qbind-node` receiver — system-under-test** |

The SUT is launched with `--env devnet --network-mode p2p --enable-p2p
--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` and a temporary
trusted transport root + leaf credentials. It has **no** consensus verification
context configured, so the production-default `ConsensusVerificationPolicy::Required`
is active and `verification_ctx == None`.

## 4. Source trace (production wiring unchanged by Run 421)

Run 421 changes no production source. The exercised gates are:

* `binary_consensus_loop::handle_inbound_consensus_msg` — **F6 `bind_sender`
  runs first**; then the Run 420 gate: `match verification_ctx { Some(ctx) =>
  verify…, None => if verification_policy.requires_context() { …context-unavailable
  counter += 1; return } }`. F6 mismatch returns **before** the Run 420 gate.
* `main.rs` — the production binary hard-selects
  `verification_policy: ConsensusVerificationPolicy::Required`; the test-only
  `LocalFixtureUnsigned` policy is unreachable from any production constructor.
* `metrics.rs` — the four
  `qbind_consensus_{inbound,outbound}_{proposal,vote}_verification_context_unavailable_total`
  families are exposed on `/metrics` (fed from the loop's `BinaryConsensusLoopInboundStats`
  via `set_run420`).

See `run_421_f3_f4_f8_unavailable_authority_release_binary_evidence/source_trace.txt`.

## 5. Scenarios and live `/metrics` deltas

Runtime commit `85bb3a73e6fe2686c074cee5c0f15ff3cf1d2103`;
`target/release/qbind-node` sha256 `7f79e2a98a127010ddc6c364baf1c440d5a9a4951a4b4208416dff7aa39e000f`,
ELF Build ID `40d1798893226b3b73f40e7ba79c907f0d9ed072`.

| Scenario | Exercised | Observed live delta | Result |
|----------|-----------|---------------------|--------|
| **S1** production-policy + unavailable-authority baseline | no traffic | all four context counters `0`; all F6 counters `0`; startup `mutual_auth=Required`, `verification_ctx=None`; no `LocalFixtureUnsigned` | **PASS** |
| **S2** authenticated honest Proposal(1) | F6 accepts, Run 420 gate rejects | `inbound_proposal_verification_context_unavailable_total +1`; F6 `accepted +1`; all downstream delivered/engine/aggregation/QC/view/commit/outbound counters unchanged at `0` | **PASS** |
| **S3** authenticated honest Vote(1) | F6 accepts, Run 420 gate rejects | `inbound_vote_verification_context_unavailable_total +1`; F6 `accepted +1`; downstream unchanged at `0` | **PASS** |
| **S4** F6 mismatch (Proposal(0)+Vote(0) as validator 1) | F6 rejects before Run 420 gate | `claimed_sender_mismatch +2`; **both** proposal/vote context counters unchanged; no signature/suite verifier counters touched; downstream unchanged | **PASS** |
| **S5** malformed-signature Proposal+Vote | F6 accepts, context gate rejects before signature parsing | `inbound_proposal_verification_context_unavailable_total +1`, `inbound_vote_… +1`; F6 `accepted +2`; **no** `rejected_bad_signature`/`rejected_missing_signature` increment | **PASS** |
| **S6** wrong-suite Proposal+Vote | F6 accepts, context gate rejects before suite enforcement | `inbound_proposal_… +1`, `inbound_vote_… +1`; F6 `accepted +2`; **no** `rejected_unsupported_suite`/`rejected_wrong_suite` increment; no classical/fallback suite attempted | **PASS** |
| **S7** outbound Proposal suppression | not naturally reachable | `outbound_proposal_verification_context_unavailable_total = 0`, `leader_changes_total = 0` — the standalone node never reaches a leader-Proposal emission opportunity | **PARTIAL / UNREACHABLE** |
| **S8** outbound Vote suppression | not naturally reachable | inbound Proposal is fail-closed before engine ingestion, so no vote is generated; `outbound_vote_verification_context_unavailable_total = 0` | **PARTIAL / UNREACHABLE** |
| **S9** fixture / CLI denial | real release binary `--help` | no `LocalFixtureUnsigned` / `verification-policy` / forged-message / arbitrary signer-suite-injection flag; invented `--consensus-verification-policy local-fixture-unsigned` exits non-zero; production default remains `Required` | **PASS** |

The corroborating deployed-binary rejection log lines are captured in
`socket_log_extract.txt`, e.g.:

```
[binary-consensus] Run 420: inbound proposal REJECTED (verification context unavailable) height=0 proposer=ValidatorId(1) policy=Required — fail-closed, not delivered
[binary-consensus] Run 420: inbound vote REJECTED (verification context unavailable) height=0 voter=ValidatorId(1) policy=Required — fail-closed, not delivered
[binary-consensus] Run 418: inbound proposal REJECTED (sender binding) claimed_proposer=ValidatorId(0) reason=claimed_sender_mismatch
```

**Socket-capture limitation (honest):** the KEMTLS sessions are short-lived and
were already torn down by the time the per-scenario `ss --tcp` snapshot ran, so
the curated `ss` extract shows only the listening receiver with no live peer
row. Session establishment and frame delivery are instead evidenced by the
KEMTLS/static-root handshake log lines, the driver's `connected=true` /
`saw_receiver_node_id=true` outputs, and the deployed-binary rejection logs
above. No OS socket observation is claimed from the empty `ss` extract.

**Downstream honesty:** every relevant downstream counter that was **captured**
(`proposals_total{result="accepted"}`, `votes_total`, `votes_observed_total`,
`validator_votes_total`, `qcs_formed_total`, `committed_height`, `current_view`,
`view_number`, `outbound_new_views_sent_total`, outbound signing-success
counters, and the typed proposal/vote signature/suite reject-reason counters)
remained unchanged at `0` before and after every rejected frame. No claim is made
about counters that were not captured.

## 6. What this does and does not establish

* **Establishes:** the deployed release binary, under `Required` with authority
  unavailable, **fails closed** on inbound Proposal/Vote (F3/F4/F8 configured
  path); F6 sender-mismatch rejection **precedes** the Run 420 context gate;
  missing/malformed signatures and wrong suites **cannot bypass** the
  unavailable-authority boundary; no rejected frame reaches delivery, engine
  acceptance, aggregation, QC formation, view/lock/high-QC/commit mutation, or
  outbound actions; the production binary does not select `LocalFixtureUnsigned`
  and exposes no fixture/injection CLI.
* **Does not establish:** configured-authority cryptographic signature/suite
  **success** on the release binary (no authority exists —
  `NOT-CAPTURED`); outbound Proposal/Vote **suppression** on the standalone
  binary as live runtime evidence (S7/S8 UNREACHABLE — Run 420 code/tests remain
  the only direct proof of the outbound suppression helpers); anything about
  external reachability or off-host attestation.

## 7. Preserved posture (unchanged by Run 421)

F3/F4/F8 are **not** fully remediated in production; configured-authority
release-binary evidence remains absent. **F1, F2, F5, F7 remain unresolved**;
**F6 remains partial** (Run 419). **RS1 remains OPEN / launch-blocking**;
**C4/C5 remain OPEN**; **M4 Yellow / launch-blocking**, M6 Yellow/Partial,
S5/S7 Yellow; **no readiness item moves Green**; `devnet-seeds.live.json` stays
absent; candidate seed status and reachability evidence unchanged;
TestNet/MainNet untouched; **public DevNet remains NO-GO**. Runs 417–420 history
is unchanged.

## 8. Deliverables

* Helper: `crates/qbind-node/examples/run_421_f3_f4_f8_release_binary_driver.rs`
  (Cargo example; DevNet- and loopback-only; fixed enumerated scenarios).
* Harness:
  `scripts/devnet/run_421_f3_f4_f8_unavailable_authority_release_binary_evidence.sh`.
* Curated archive:
  `docs/devnet/run_421_f3_f4_f8_unavailable_authority_release_binary_evidence/`
  (`summary.txt`, `scenario_matrix.txt`, `metrics_before_after.txt`,
  `socket_log_extract.txt`, `binary_identity.txt`, `source_trace.txt`,
  `commands.txt`, `test_results.txt`, `SHA256SUMS.txt`, `.gitignore`).

## 9. Recommended next smallest security-first run

Because the configured-authority release-binary path remains unavailable, the
next smallest security-first step is **production consensus authority /
key-provider activation** (a genuine signer + suite-aware key provider + backend
registry wired into the standalone binary so `verification_ctx` becomes
`Some`). Only after that lands can a dedicated **configured-authority
release-binary adversarial run** capture the still-absent
`CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE`. Run 421 does **not** implement
either; it recommends them.
