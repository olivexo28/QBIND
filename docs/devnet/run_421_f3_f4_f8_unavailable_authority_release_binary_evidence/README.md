# Run 421 — F3/F4/F8 unavailable-authority fail-closed release-binary evidence

Curated, **publish-safe** evidence that the Run 420 fail-closed Proposal/Vote
verification-policy boundary is live on the standalone
`target/release/qbind-node` binary when consensus verification authority is
**unavailable** (`verification_ctx == None`, production-default
`ConsensusVerificationPolicy::Required`).

* **Route A**: evidence-only. No production behavior change. Run 421 adds a
  Cargo-example driver helper, a harness, and curated docs.
* **Scope**: local loopback, multi-process, DevNet-only, standalone release
  receiver as the system-under-test.
* **Proves**: an authenticated, F6-authorized Proposal/Vote is REJECTED because
  consensus verification authority is unavailable. F6 sender mismatch rejects
  BEFORE the Run 420 context gate. Missing/malformed signatures and wrong suites
  cannot bypass the unavailable-authority boundary. No rejected frame reaches
  delivery, engine acceptance, aggregation, QC formation, view/commit mutation,
  or outbound actions.
* **Does NOT prove**: configured-authority cryptographic signature/suite success
  (no consensus signing authority exists on the standalone binary —
  `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-CAPTURED`).
* **Trust model**: automated LOCAL cross-process operational evidence. **Not**
  independent off-host attestation. KEMTLS authenticates the transport session
  only; a transport-authenticated frame is not consensus-message authenticated.

## Verdict

See `summary.txt`. Regardless of outcome: **RS1 remains OPEN**, C4/C5 remain
OPEN, F1/F2/F5/F7 remain unresolved, F6 remains partial, no M/S item moves
Green, and **public DevNet remains NO-GO**.

## Files

| File | Contents |
|------|----------|
| `summary.txt` | verdict, labels, trust model, per-scenario results |
| `scenario_matrix.txt` | scenario → expected/observed metric deltas + exit code |
| `metrics_before_after.txt` | before/after live counters per scenario |
| `socket_log_extract.txt` | curated `ss` + KEMTLS + rejection + S1 baseline lines |
| `binary_identity.txt` | runtime commit, SHA-256, ELF Build IDs, toolchain |
| `source_trace.txt` | Run 418/420 production wiring references (unchanged) |
| `commands.txt` | representative commands, temp paths normalized |
| `test_results.txt` | validation-suite exit codes |
| `SHA256SUMS.txt` | integrity digests for the curated files above |

## Reproduce

```
scripts/devnet/run_421_f3_f4_f8_unavailable_authority_release_binary_evidence.sh
```

Private keys, certificates, raw logs, raw metric dumps and data directories are
temporary and are **never** committed (see `.gitignore`).
