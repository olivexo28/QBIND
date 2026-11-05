# Fully verified synthetic authority-reset acceptance evidence

**TEST-ONLY ACCEPTANCE EVIDENCE — INDEPENDENT REVIEW PENDING.**
A33-F1 / E27 and all other unresolved obligations **OPEN**.
Activation **DISABLED**; public DevNet **NO-GO**.

## Entry and historical distinction

Repository `olivexo28/QBIND`, existing branch
`copilot/a33-f1-bounded-eviction`. Starting/producer-parent commit
`11bb930e005abd082a1dbb296f0b8fe90dcf4fc0`, tree
`9106f4e4e6123c072239ed7f46e90155edbc269d`, parent
`6506faf18485769a2c852b7609149f908b807848`.
Before editing, repository URL, branch, exact local/remote task tip,
protected local/remote main and clean worktree/staging all matched.
Main remains `c9aaef40b045e896ddfa8b01bad230f6b680715e`.
No reset, discard, overwrite or force update.

Earlier [baseline](authority-reset-collision-evidence.md),
[path correction](authority-reset-correction-evidence.md) and
[error-reporting evidence](authority-reset-errors-evidence.md) remain
unchanged. They accurately recorded full verified success as untested
then. The new test supplies that previously missing evidence for the
normal synthetic Devnet success path only. Earlier private sequencing
tests remain seam controls, not retroactively end-to-end success tests.
The original baseline pass reproduced a defect, not security assurance.

## Fixture and actual production path

New test source:
`crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs`.
It creates an isolated `tempfile` directory and uses existing helpers
from the adjacent authority tests:

* `MlDsa44Backend::generate_keypair` for ephemeral synthetic bundle-signing
  and genesis-authority credentials; `mint_devnet_root` for a transport
  root. No operational keys or signing services.
* `GenesisAuthorityRoot::with_public_key_bytes`, real genesis constructors
  and Devnet canonical genesis hashing. The genesis file carries the
  synthetic authority root, policy/sequence/epoch and matching chain.
* `sign_bundle_devnet_helper` signs the chain-bound Devnet trust bundle
  with a synthetic signing key. Production `KEYID:SUITE:PK` parsing is
  used by the reset inputs (no unchecked key-set injection).
* Ledger `test_helpers::build_signed_ratification` creates the signed
  v1 ratification binding the synthetic genesis hash, authority public
  key and bundle-signing key.

Relevant unchanged source mechanisms are
`crates/qbind-node/src/pqc_authority_state_reset.rs`
(`verify_authority_reset_inputs`, `execute_authority_state_reset`,
`write_authority_reset_audit`),
`pqc_boot_genesis.rs` (`load_external_genesis`),
`pqc_trust_bundle.rs` (signature verification/key-spec parsing), and
`crates/qbind-ledger/src/bundle_signing_ratification.rs`
(`test_helpers::build_signed_ratification` and Strict enforcement).
Prior art: `crates/qbind-node/tests/run_121_sighup_authority_marker_tests.rs`
(`devnet_harness`, `build_signed_bundle`, `build_valid_ratification`).

The test calls the **actual public verifier** and then the **actual public
reset orchestrator**, which verifies again, publishes pending audit through
the guarded writer, persists through the real marker writer and publishes
the final success audit through the guarded writer. It does not construct
`VerifiedAuthorityResetPlan`, call private sequencing functions, override
verification or inject successful writer results. The returned verifier
plan is used only as an independently obtained expected derivation for
assertions; it is never passed into reset execution.

Private keys remain in test memory. Only public genesis/bundle/ratification
material and signatures are serialized to temporary files. Neither keys
nor fixture payloads are printed to logs or retained evidence. Success/
failure diagnostics are fixed observation strings, not key bytes. Tests
delete only their owned temporary directory on completion. No live node,
peer network, operational signing, deployment or activation.

## Actual outcomes

One focused test executes five scenarios:

| Scenario | Actual assertions/results |
|---|---|
| Fresh marker, valid signed fixture | Public reset returns success. Marker loads, equals real verifier derivation and matches chain, environment, genesis, policy/sequence/epoch, authority/key fingerprints, ratification digest, `OperatorReset` source and informational timestamp. Returned digest equals canonical marker digest. Final audit parses as success, matches marker/returned digest, genesis, chain, environment, ratification and verified bundle fingerprint, with no refusal |
| Existing marker, same valid fixture | Verifier/public reset succeed again; old-marker parsed archive and SHA3-256 raw-byte hash match prior marker. Final success audit matches new derivation/returned digest. Resulting marker bytes are identical (same fixed informational timestamp) |
| Valid fixture, equal audit/marker destination | Real verifier accepts the otherwise valid inputs. Public reset returns `UnsafeAuditPath` at its **pre-verification separation guard**, before pending/refusal/success publication. Marker remains byte-identical/loadable and distinct previous success audit is unchanged |
| Signed bundle tampered without re-signing | Increment bundle sequence; real verifier and public reset return `InvalidTrustBundle`. Marker bytes unchanged; distinct audit parses as refused with that stable reason and no new-marker record |
| Ratification signature tampered | Restore original signed bundle; flip one signature byte in ratification. Real verifier and public reset return `RatificationEnforcementFailed` under actual Strict enforcement. Marker stays byte-identical/loadable; distinct refusal audit identifies that reason, no new-marker record |

Final focused run: **1 passed; 0 failed; 0 ignored; 0 measured;
0 filtered out**, 16.87 seconds. Existing path regressions in the same
runner invocation: **6 passed**, 0 failed/ignored/measured/filtered,
47.87 seconds, 18 isolated scenarios.

Existing reset/error regressions: **22 passed**, 0 failed/ignored/measured,
2,204 filtered out, 111.06 seconds (18 legacy tests plus four error-seam controls).
The module-seam controls remain distinct from the new public verified
success test. No Linux controls skipped; this success test is Linux-only
because the existing production path guard refuses other target platforms.

## Exact commands and artifacts

Commands from `/workspaces/QBIND/olivexo28/QBIND`:

```text
rustfmt --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs
cargo test -p qbind-node --test a33_f1_authority_reset_verified_success_tests -- --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_verified_success_tests --test a33_f1_authority_reset_audit_collision_tests -- --nocapture --test-threads=1
cargo test -p qbind-node --lib pqc_authority_state_reset:: -- --nocapture --test-threads=1
rustfmt --check --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs
python docs/security/evidence/a33_f1/authority-reset-verified-checks.py
git diff --check
git -c core.whitespace=-blank-at-eof diff --cached --check
(cd docs/security/evidence/a33_f1 && sha256sum -c SHA256SUMS)
```

Exit statuses **0**. Merged stdout/stderr for Cargo was redirected first to
session files `authority-reset-verified-success.log`,
`authority-reset-verified-focused.log`, and
`authority-reset-verified-regressions.log`, then copied byte-for-byte to
this evidence directory. [Intermediate run](authority-reset-verified-intermediate.log):
1 pass, 13.59 seconds, before the ratification-tamper control and expanded
audit assertions; not counted as final coverage.
[Final focused/path output](authority-reset-verified-focused.log),
[module regressions](authority-reset-verified-regressions.log),
[empty format output](authority-reset-verified-format.log),
[platform](authority-reset-verified-platform.log),
[scope script](authority-reset-verified-checks.py),
[check output](authority-reset-verified-checks.log).
Existing compiler warnings remain in raw output.
No failed/unsuccessful build, test or check attempt occurred in this task.
No dependencies installed, manifests/lockfile changed or unrelated suites
rerun. Whitespace checking permits raw Cargo's final blank line without
rewriting raw output. All other new text has standard whitespace checks.

Source SHA-256 at this producer:

```text
a46e955d205c820d6fdb0ecbd059a0a3ec5986a49e117d91b6fc4b518619a626  crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs
31858871b21358d1f8135bfc40fae347dbfbfafb685f4af3414ddcab9cf150e7  crates/qbind-node/src/pqc_authority_state_reset.rs
75ce5a368fc76ce6867ba112deb89afafd1c7b1840e3974154f48dc307938d12  crates/qbind-node/src/pqc_authority_state.rs
```

Production source is unchanged from the starting revision. The check
script verifies every non-whitelisted tracked byte unchanged, exact
historical plan/manifest prefixes, local links and expected observed test
counts. Manifest adds new evidence checksums only.

## Limits and delivery

This is actual normal-path synthetic **function-level** verified success,
not CLI/process/startup, multi-node or deployment acceptance. Existing
stable operator-controlled, case-sensitive Linux filesystem assumptions
remain; no hostile-local-race/complete-alias assurance, power-loss
durability, crash/restart/rollback or signer-exclusivity claim. Actual OS
fsync/rename failures and compound failures with a fully verified success
fixture are not injected here; existing private error seams remain the
reported layer for those errors. No Mainnet/Testnet successful reset,
activation, recovery, quarantine, automatic clear/resume or fencing.

Changed paths: new integration test above, append-only plan §40 and
manifest, plus eight new `authority-reset-verified-*` artifacts listed by
the scope script/output. Historical evidence and audit register are
unchanged. Final commit/tree/parent, remote equality, protected main and
clean worktree are reported after commit, avoiding self-referential
identities in committed evidence. Only existing task branch is pushed.
