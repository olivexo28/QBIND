# Run 420 — Consensus Proposal/Vote fail-closed verification-policy boundary

This directory holds **curated, publish-safe** evidence that the fail-open
`verification_ctx == None` behavior for inbound and outbound Proposal/Vote
handling in the binary consensus loop has been replaced by an **explicit typed
policy boundary** that fails closed under the production-default `Required`
policy.

* **Route**: source + test remediation of the *configured* verification
  boundary. No live seed, no port, no trust/validator/epoch mutation.
* **Trust model**: this proves the code/test boundary. It does **not** activate
  genuine production consensus signing authority on the standalone release
  binary.

## Verdict

```
RESULT=PARTIAL-POSITIVE-FOR-F3-F4-F8-CODE-TEST-FAIL-CLOSED-BOUNDARY
F3_STATUS=CONFIGURED-PATH-REMEDIATED / ACTIVE-BINARY-AUTHORITY-UNAVAILABLE
F4_STATUS=CONFIGURED-PATH-REMEDIATED / ACTIVE-BINARY-AUTHORITY-UNAVAILABLE
F8_STATUS=CONFIGURED-PATH-REMEDIATED / ACTIVE-BINARY-AUTHORITY-UNAVAILABLE
RELEASE_BINARY_EVIDENCE=NOT-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

The configured-context signing/verification path passes all tests, and the
fixture-only bypass is proven unreachable from the production binary. Genuine
production signer/authority activation for the standalone binary remains
unavailable, so F3/F4/F8 are **not** claimed fully remediated in production.

Regardless of outcome: **RS1 stays OPEN**, C4/C5 stay OPEN, M4/M6/S5/S7 stay
Yellow, N1-N7 stay Red, TestNet/MainNet are untouched, no readiness item moves
Green, and **public DevNet remains NO-GO**.

## Files

| File | Contents |
|------|----------|
| `summary.txt` | verdict, positive/negative axes, per-requirement result |
| `source_trace.txt` | exact former `None` bypass; new policy type + default; production constructors; metric series |
| `scenario_matrix.txt` | adversarial inbound/outbound matrix → expected outcome + test |
| `verification_order.txt` | canonical F6 → signature → mutation ordering + exact non-mutation assertions |
| `performance.txt` | cost model and indicative test wall-clock |
| `commands.txt` | representative commands |
| `test_results.txt` | exact exit codes (incl. blocked/not-captured items) |
| `SHA256SUMS.txt` | integrity digests for the curated files above |

## Reproduce

```
cargo test -p qbind-node --lib run420
cargo test -p qbind-node --test run_420_production_policy_reachability_tests
cargo test -p qbind-consensus --lib proposal_vote_verify
( cd docs/devnet/run_420_consensus_proposal_vote_signature_fail_closed_evidence \
  && sha256sum -c SHA256SUMS.txt )
```

Private keys, certificates, raw logs, raw metric dumps and data directories are
temporary and are **never** committed (see `.gitignore`).
