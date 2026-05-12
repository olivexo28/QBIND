# QBIND DevNet Evidence — Run 053: Trust-Bundle Chain-ID Crosscheck

## Exact objective

Run 053 closes the smallest remaining C4 trust-bundle lifecycle item after Runs 050–052: enforce a present `trust-bundle.json` `chain_id` against the runtime `NodeConfig.chain_id()`.

Scope is intentionally narrow:

- `chain_id: null` remains accepted for Run-050 compatibility.
- A present chain id must parse as exactly 16 lowercase hexadecimal characters representing a 64-bit value (`<16 hex>`, `0x<16 hex>`, or `chain_<16 hex>`).
- A parsed chain id must match the runtime chain id or bundle loading fails closed.
- No sequence persistence, activation epoch/height gating, CA playbook, transport redesign, or consensus redesign is included.

## Exact verdict

**Positive for the scoped C4 chain-id crosscheck.** `TrustBundle::validate_at_with_signing_keys_and_chain_id` now enforces a present bundle `chain_id`, and `qbind-node` passes `config.chain_id()` into the live `--p2p-trust-bundle` load path. Wrong-chain and malformed-chain bundles fail closed before roots are merged into the PQC trust set; existing null-chain DevNet fixtures continue to load.

## Exact files changed

| File | Change |
| --- | --- |
| `crates/qbind-node/src/pqc_trust_bundle.rs` | Add `InvalidChainIdFormat` / `WrongChainId`; add explicit-chain-id load/validate entry points; strictly parse optional bundle `chain_id`; compare against runtime chain id when present; add 3 unit tests. |
| `crates/qbind-node/src/main.rs` | Pass `config.chain_id()` into the trust-bundle loader used by `--p2p-trust-bundle`. |
| `crates/qbind-node/tests/run_050_pqc_trust_bundle_tests.rs` | Add integration coverage proving a TestNet chain id inside a DevNet bundle is rejected fail-closed. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_053.md` | This evidence document. |
| `docs/whitepaper/contradiction.md` | Append C4 Run 053 narrowing note. |

## Tests run

| Suite | Result |
| --- | --- |
| `cargo test -p qbind-node --lib pqc_trust_bundle` | 68 / 68 pass |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` | 14 / 14 pass |
| `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` | 12 / 12 pass |
| `cargo check -p qbind-node --bin qbind-node` | pass; only pre-existing `bincode::config` deprecation warnings |

## Remaining boundaries

Run 053 does not close full C4. Still open from the trust-bundle/lifecycle surface: activation epoch/height gating, sequence-number monotonicity persistence across restarts, operator CA/rotation playbook, and live-binary release-build smoke artifacts for the newest trust-bundle negative fixtures. Broader C4/C5 boundaries remain tracked separately.