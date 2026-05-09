# QBIND DevNet Evidence Run 029 — Partial Timeout Evidence Landing

## Objective
Close the smallest honest part of the binary-path timeout/new-view cryptographic verification gap by landing evidence-bearing `TimeoutCertificate` wire data and chain-aware timeout signing interfaces, then record the exact remaining boundary.

## Binary identity
- Branch: `copilot/continue-qbind-timeout-verification`
- Commit used for binary build: `e8d34b104a1097c45493adf13ff6ba7bf686b960`
- Dirty/clean status at build: clean
- Binary: `target/debug/qbind-node`
- Binary sha256: `27885261c41bb6a12a4def94ff2e5e09be9ab3fadeaca08e3db55c35333a2d82`
- ELF BuildID: `263b3a24d663c1f5c30c5b4bbf6b98646da20d65`

## Files changed
- `Cargo.lock`
- `crates/qbind-consensus/Cargo.toml`
- `crates/qbind-consensus/src/timeout.rs`
- `crates/qbind-node/src/hsm_pkcs11.rs`
- `crates/qbind-node/src/remote_signer.rs`
- `crates/qbind-node/src/validator_signer.rs`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_029.md`
- `docs/whitepaper/contradiction.md`

## Commands run
- `cargo test -p qbind-consensus timeout --lib`
- `cargo test -p qbind-consensus --test t146_timeout_types_tests`
- `cargo test -p qbind-node binary_consensus_loop --lib`
- `cargo check -p qbind-node --lib`
- `cargo build -p qbind-node --bin qbind-node`
- `sha256sum target/debug/qbind-node`
- `readelf -n target/debug/qbind-node | grep -A1 'Build ID'`

## Tests and status
| Check | Status |
|---|---:|
| Baseline targeted timeout/binary-loop tests before edits | PASS |
| `cargo test -p qbind-consensus timeout --lib` | PASS, 54 passed |
| `cargo test -p qbind-consensus --test t146_timeout_types_tests` | PASS, 24 passed |
| `cargo test -p qbind-node binary_consensus_loop --lib` | PASS, 32 passed |
| `cargo check -p qbind-node --lib` | PASS |
| `cargo build -p qbind-node --bin qbind-node` | PASS |

## Topology
No N=4 real-binary topology was executed in this pass. This run is a source/test partial landing only.

## Positive results
- `TimeoutCertificate<BlockIdT>` now carries `signed_timeouts: Vec<TimeoutMsg<BlockIdT>>`.
- `TimeoutAccumulator::maybe_tc_for` populates exact signed timeout evidence from accumulated timeout messages.
- Consensus tests prove serialization/deserialization preserves `signed_timeouts` and that TC signer set equals evidence signer set.
- Local, remote, and HSM signer abstractions now expose chain-aware timeout signing using `timeout_signing_bytes_with_chain_id`.
- Existing consensus timeout verification tests still pass.
- Existing binary-loop B14 tests still pass, meaning the landed wire-shape change did not regress current B14 behavior.

## Negative results / not proven
- Binary-path inbound `TimeoutMsg` verification before `engine.on_timeout_msg` is not wired in this pass.
- Binary-path inbound `NewView` / `TimeoutCertificate` verification before `engine.on_timeout_certificate` is not wired in this pass.
- Locally emitted binary-loop `TimeoutMsg`s are not yet signed in this pass.
- Precise timeout/new-view verification metrics are not wired in this pass.
- N=4 real-binary Required-mode verified-timeout evidence was not executed.
- Real-binary negative injection was not executed.

## Metrics snapshots
No new live metrics snapshots were collected because no real-binary topology was executed. Existing targeted binary-loop tests passed.

## Pass/fail table
| Requirement area | Verdict |
|---|---|
| Evidence-bearing TC wire shape | PASS |
| Accumulator populates signed evidence | PASS |
| Signer chain-aware timeout signing interface | PASS |
| Binary inbound Timeout verification | NOT DONE |
| Binary inbound NewView/TC verification | NOT DONE |
| Outbound binary-loop timeout signing | NOT DONE |
| Verification metrics | NOT DONE |
| N=4 real-binary positive evidence | NOT RUN |
| Real-binary negative evidence | NOT RUN |

## Remaining open items
- Wire signer into binary-loop timeout emission and fail closed if signing is unavailable.
- Wire `verify_timeout_msg` before inbound timeout engine ingestion.
- Wire `verify_timeout_certificate_with_evidence(&tc, &tc.signed_timeouts, ...)` before inbound NewView engine ingestion.
- Add per-reason verification counters and latency where supported.
- Run N=4 real-binary positive evidence and deterministic/real negative invalid-traffic evidence.

## Exact verdict
Partial positive: the TC wire-evidence and signer-interface prerequisites landed and passed targeted tests, but Run 029 did not close the binary-path timeout-signature sub-item end-to-end.