# Run 419 — F6 standalone release-binary consensus-binding runtime evidence

This directory holds **curated, publish-safe** evidence that the Run 418
authenticated-peer → consensus-sender **binding gate (F6)** is live on the
standalone `target/release/qbind-node` binary.

* **Route A**: evidence-only. No production behavior change. Run 419 adds a
  Cargo-example driver helper, this harness, and curated docs.
* **Scope**: local loopback, multi-process, DevNet-only, standalone release
  receiver as the system-under-test.
* **Trust model**: automated LOCAL cross-process operational evidence. **Not**
  independent off-host attestation. Does **not** prove external reachability.

## Verdict

See `summary.txt`. Core scenarios S1/S2/S3/S6 are exercised through real
KEMTLS sessions against the standalone binary with live
`qbind_consensus_binding_total{result=...}` deltas. S4/S5 (unauthenticated
ingress) and S7 (outbound actual-server identity) are partial where the present
transport configuration cannot establish the real socket without production
changes or an unsafe general-purpose helper.

Regardless of outcome: **RS1 remains OPEN**, C4/C5 remain OPEN, no M/S item
moves Green, and **public DevNet remains NO-GO**.

## Files

| File | Contents |
|------|----------|
| `summary.txt` | verdict, qualifiers, per-scenario results |
| `scenario_matrix.txt` | scenario → expected/observed delta + exit code |
| `metrics_before_after.txt` | before/after live binding counters per scenario |
| `socket_log_extract.txt` | curated `ss` + KEMTLS/static-root/mutual-auth lines |
| `binary_identity.txt` | runtime commit, SHA-256, ELF Build IDs, toolchain |
| `source_trace.txt` | F6 production wiring references (unchanged by Run 419) |
| `commands.txt` | representative commands, temp paths normalized |
| `test_results.txt` | validation-suite exit codes |
| `SHA256SUMS.txt` | integrity digests for the curated files above |

## Reproduce

```
scripts/devnet/run_419_f6_standalone_release_binary_binding_evidence.sh
```

Private keys, certificates, raw logs, raw metric dumps and data directories are
temporary and are **never** committed (see `.gitignore`).
