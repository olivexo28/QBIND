# QBIND DevNet Evidence — Run 420

**Fail-closed consensus verification-policy boundary for inbound and outbound
Proposal/Vote.** Run 420 replaces the fail-open `verification_ctx == None`
behavior in the binary consensus loop with an **explicit typed
`ConsensusVerificationPolicy`** whose production default (`Required`) rejects
inbound and suppresses outbound Proposal/Vote when verification authority is
unavailable. This is a **code + test remediation of the configured verification
boundary**. It does **not** activate genuine production consensus signing
authority on the standalone `target/release/qbind-node` binary.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
code/test fail-closed boundary only · **RELEASE-BINARY AUTHORITY UNAVAILABLE** ·
**M4 Yellow / launch-blocking** · M6 Yellow/Partial · S5 Yellow · S7 Yellow ·
**RS1 OPEN / launch-blocking** · **C4/C5 OPEN** · public DevNet **NO-GO** · no
TestNet readiness · no MainNet readiness. **No private key material,
certificate, raw log, raw metric dump, or data directory is committed.**

## 1. Exact verdict

```
RESULT=PARTIAL-POSITIVE-FOR-F3-F4-F8-CODE-TEST-FAIL-CLOSED-BOUNDARY
F3_STATUS=CONFIGURED-PATH-REMEDIATED / ACTIVE-BINARY-AUTHORITY-UNAVAILABLE
F4_STATUS=CONFIGURED-PATH-REMEDIATED / ACTIVE-BINARY-AUTHORITY-UNAVAILABLE
F8_STATUS=CONFIGURED-PATH-REMEDIATED / ACTIVE-BINARY-AUTHORITY-UNAVAILABLE
RELEASE_BINARY_EVIDENCE=NOT-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

The verdict is `PARTIAL-POSITIVE` and not `POSITIVE` because, although every
production-code Proposal/Vote path now fails closed when verification authority
is unavailable and the configured-context signing/verification path passes all
tests, the standalone binary still has **no authoritative consensus keys**.
Genuine production signer/authority activation remains unavailable, so F3/F4/F8
are explicitly **not** claimed fully remediated in production.

## 2. The exact former `None` bypass

Before Run 420 (commit `1c22f7d`), inbound verification ran only inside
`if let Some(ctx) = verification_ctx { … }`, so a `None` context fell through
to delivery/engine/aggregation:

```rust
// inbound Proposal (former)
if let Some(ctx) = verification_ctx {
    let res = verify_proposal_msg(&proposal, from, ctx.validators.as_ref(),
        ctx.key_provider.as_ref(), ctx.backend_registry.as_ref(), …);
    …
}
// (fell through to delivered counters / reconfig / engine when None)

// inbound Vote (former)
if let Some(ctx) = verification_ctx {
    let res = verify_vote_msg(&vote, from, …);
    …
}
```

Outbound signing was symmetric: with `ctx == None` the sign helpers returned
the message **unsigned** for broadcast. The standalone production binary supplied
`verification_ctx == None`, so the active production path was unsigned/unverified
and fail-open.

## 3. The new explicit policy type and its default

`crates/qbind-node/src/binary_consensus_loop.rs`:

```rust
pub enum ConsensusVerificationPolicy { Required, LocalFixtureUnsigned }
impl Default for ConsensusVerificationPolicy { fn default() -> Self { Required } }
pub fn requires_context(self) -> bool { matches!(self, Required) }
```

* `Required` — production/authenticated P2P Proposal/Vote processing; the
  **Default**. A `None` context ⇒ inbound reject, outbound suppress.
* `LocalFixtureUnsigned` — **test-only** local fixture compatibility policy
  preserving the historical LocalMesh unsigned passthrough. Never selectable
  from the production CLI, TestNet, MainNet, authenticated P2P, restore/replay,
  or public DevNet.

It is a typed enum, **not** another optional boolean, so the former ambiguity is
not recreated. When `verification_ctx` is `Some`, the policy has no effect —
verification/signing run identically.

## 4. Every production constructor and its selected policy

| Constructor | Policy |
|-------------|--------|
| `main.rs` production `BinaryConsensusLoopIo` literal (~7796) | `ConsensusVerificationPolicy::Required` |
| binary consensus loop `io == None` fallback (~1903) | `ConsensusVerificationPolicy::Required` |
| `p2p_node_builder.rs` | never references `LocalFixtureUnsigned` |
| every `LocalFixtureUnsigned` selection | inside `#[cfg(test)]` / integration-test literals only |

## 5. Proof: `Required + None` rejects inbound Proposal/Vote

`mod tests::run420` (`binary_consensus_loop.rs`):

* `run420_required_none_inbound_proposal_rejected_fail_closed`
* `run420_required_none_inbound_vote_rejected_fail_closed`

Both assert: rejection; the matching context-unavailable counter +1; delivered
counter unchanged; reconfiguration detector empty; engine state unchanged; no
vote/outbound action. See `verification_order.txt` for the exact non-mutation
assertions.

## 6. Proof: `Required + None` blocks outbound Proposal/Vote

* `run420_required_none_outbound_proposal_suppressed`
* `run420_required_none_outbound_vote_suppressed`
* `run420_required_ctx_signer_none_outbound_suppressed`
* `run420_outbound_fail_closed_when_signer_missing`

No broadcast and no local self-injection; the outbound context-unavailable /
signing-failure counters increment; no dummy or unsigned fallback exists;
a `None` signing result is never enqueued and produces no emitted-success metric.
`run420_required_valid_signer_signs_and_roundtrip_verifies` proves a validly
configured signer produces a message that verifies back through the inbound
verifier.

## 7. Proof: fixture bypass unreachable from the production binary

`crates/qbind-node/tests/run_420_production_policy_reachability_tests.rs`:

* `main_rs_selects_required_and_never_fixture_policy`
* `p2p_node_builder_never_selects_fixture_policy`
* `fixture_policy_only_selected_from_test_module`

plus `default_policy_is_required`. These are source-level guards proving the
production entrypoint selects `Required` and never assigns
`LocalFixtureUnsigned`, and that every executable fixture-policy selection lives
in the test module.

## 8. Exact non-mutation assertions

See `run_420_consensus_proposal_vote_signature_fail_closed_evidence/verification_order.txt`.
Summary for Required+None inbound Proposal: context-unavailable counter +1;
`inbound_proposals_delivered` unchanged; `BinaryReconfigDetector.header_cache`
stays empty; engine view/locked/high-QC/committed-height unchanged; no facade
action. For Vote: context-unavailable counter +1; `inbound_votes_delivered`
unchanged; aggregation tally unchanged; no QC formed; view/commit unchanged; no
facade action.

## 9. Typed missing-context outcome and metrics

Distinct, bounded, attacker-label-free Prometheus series
(`crates/qbind-node/src/metrics.rs`), separate from the invalid/missing/
unsupported-suite `*_verify_rejected_total` families:

```
qbind_consensus_inbound_proposal_verification_context_unavailable_total
qbind_consensus_inbound_vote_verification_context_unavailable_total
qbind_consensus_outbound_proposal_verification_context_unavailable_total
qbind_consensus_outbound_vote_verification_context_unavailable_total
```

Proposal and Vote counters are distinct; inbound and outbound are distinct;
missing local configuration is never mislabeled as `InvalidSignature`; exactly
one terminal rejection outcome is emitted per rejected message.

## 10. Honest F3/F4/F8 classification and active-binary limitation

F3 (proposal signing/verification), F4 (vote signing/verification), and F8
(outbound emission authenticity) are **CONFIGURED-PATH-REMEDIATED**: when a
verification context and signer are wired, the loop verifies inbound and signs
outbound, and fails closed otherwise. They are **ACTIVE-BINARY-AUTHORITY-
UNAVAILABLE**: the standalone `qbind-node` binary has no authoritative consensus
keys, so under the default `Required` policy it refuses Proposal/Vote traffic
and emits none — liveness loss is accepted; silent unauthenticated operation is
eliminated. `RELEASE_BINARY_EVIDENCE=NOT-CAPTURED`. This run does **not** claim
F3/F4/F8 are fully remediated in production, does not generate or auto-enroll
consensus authority, does not reuse KEMTLS transport roots/leaves as consensus
signing authority, and adds no classical/dummy signer.

## 11. Validation

Exit codes are recorded verbatim in
`run_420_consensus_proposal_vote_signature_fail_closed_evidence/test_results.txt`.
Highlights (all exit 0 unless noted): `proposal_vote_verify` (20),
`binary_consensus_loop` (94), `run420` (31), `run030` (20), reachability guard
(3), six edited integration targets (5/5/3/6/18/5), clippy (warnings only, no
net-new), `git diff --check` clean, Run 417 audit
(`POSITIVE-FOR-AUDIT-COMPLETENESS`, security verdict `NEGATIVE` preserved), Runs
404/405/410–415 (`POSITIVE`). Blocked/not-captured (reported, not passes): Run
418 harness (pre-existing CRLF, exit 2), Run 419 harness (release-binary /
loopback KEMTLS, PARTIAL preserved, not executed here).

## 12. Branch, commits, worktree, and PR status

- **Branch:** `copilot/copilotrun-420-consensus-proposal-vote-signature`
  (existing task branch; no new branch, no `main` change, no force-push, no
  history rewrite).
- **Corrective commits (this continuation):**
  `e07f1e1` fail-closed policy · `f894c59` comment corrections ·
  `bfbfb75` io=None→Required + reachability guard · `b204ed4` clippy suppression
  · plus this evidence commit.
- **Worktree:** clean after each `report_progress`.
- **Pull request:** **none opened.** Run 421 is not started.

## 13. Reconciliation

Run 420 makes no readiness item Green. M4/M6/S5/S7 stay Yellow; C4/C5 stay OPEN;
RS1 stays OPEN; N1–N7 stay Red; TestNet/MainNet untouched; public DevNet stays
NO-GO. Run 417–419 historical verdicts are unchanged. Comments and docs that
previously implied Proposal/Vote signatures are universally required have been
corrected to state the policy-gated boundary.
