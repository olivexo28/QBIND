# QBIND Deep Audit Tracker

Companion to [`QBIND_DEEP_AUDIT_PLAYBOOK.md`](./QBIND_DEEP_AUDIT_PLAYBOOK.md).
**This tracker is the single source of truth for audit status.** One row per
audit item; one evidence bundle under `docs/security/evidence/<id>/` per row
that reaches a verdict.

## Pinned audit baseline

Fill these in once, when the audit cycle begins, so every row refers to the
same frozen target:

| Field | Value |
|---|---|
| Audited commit | `<git rev-parse HEAD>` |
| Audited tree | `<git rev-parse HEAD^{tree}>` |
| Toolchain pin | `<rust-toolchain.toml contents>` |
| Started | `<date>` |
| Auditor(s) | `<name/handle>` |

## Columns

- **ID** — playbook item (`A1`, `B1-a`, `C3`, `D2`, `E-02`, …).
- **Area** — A/B/C/D/E workstream + short name.
- **Target** — primary file(s) or gate.
- **Track** — `DEVNET-BLOCK` · `CARRY-FORWARD` · `DEFERRABLE` (see playbook §0.3 / §6).
- **Severity** — Critical/High/Medium/Low/Info (blank until a finding exists).
- **Status** — `TODO` · `IN-PROGRESS` · `PASS` · `FINDING` · `FIXED` · `DEFERRED` · `WONTFIX(justified)`.
- **Evidence** — path to `docs/security/evidence/<id>/` (must exist for any non-TODO verdict).
- **Reproducer** — the exact command that produces the verdict.
- **Notes** — one line: the claim tested and the outcome.

## Status legend

`TODO` not started · `IN-PROGRESS` under audit · `PASS` checked, no defect,
evidence attached · `FINDING` defect open · `FIXED` defect closed with
regression test + evidence · `DEFERRED` moved to a later phase by decision ·
`WONTFIX(justified)` accepted risk with written justification.

---

## A — Baseline (enforced, repeatable)

| ID | Area | Target | Track | Sev | Status | Evidence | Reproducer | Notes |
|---|---|---|---|---|---|---|---|---|
| A1 | Pin toolchain + lint cfg | `rust-toolchain.toml`, `rustfmt.toml`, `clippy.toml` | DEVNET-BLOCK | | TODO | | `cargo fmt --all --check` | |
| A2 | CI build+test+lint | `.github/workflows/` | DEVNET-BLOCK | | TODO | | CI run URL | 18,900 tests must actually run |
| A3 | Supply chain | `deny.toml`, SBOM | DEVNET-BLOCK | | TODO | | `cargo deny check` / `cargo audit` | 368 locked crates |
| A4 | Static analysis | CodeQL workflow, `cargo geiger` | DEVNET-BLOCK | | TODO | | CodeQL run URL | the cited-but-absent gate |
| A5 | Coverage baseline | `cargo llvm-cov` | CARRY-FORWARD | | TODO | | `cargo llvm-cov --workspace` | flag genesis/gov/remote-signer |

## B — Deep code audit

| ID | Area | Target | Track | Sev | Status | Evidence | Reproducer | Notes |
|---|---|---|---|---|---|---|---|---|
| B1-a | Toy-suite gate | `consensus_sig.rs`·`crypto_verifier.rs`·`startup_validation.rs` | CARRY-FORWARD | | TODO | | negative-start test | suite 0 must be refused |
| B1-b | Suite agility/downgrade | `startup_validation.rs` | CARRY-FORWARD | | TODO | | epoch-transition test | no cross-epoch downgrade |
| B1-c | Keystore + KDF | `keystore.rs`·`kdf.rs` | CARRY-FORWARD | | TODO | | perms/zeroize check | plaintext backend forbidden on prod; 0600; PBKDF2 iters |
| B1-d | Signer trust boundary | `remote_signer.rs`·`qbind-remote-signer/` | CARRY-FORWARD | | TODO | | | signer channel authn/replay |
| B2-a | unsafe memory safety | `received_vote_evidence.rs` (49) | CARRY-FORWARD | | TODO | | `cargo +nightly miri test -p qbind-consensus` | #1 memory target |
| B2-b | unsafe allocator | `basic_hotstuff_engine.rs` (8) | CARRY-FORWARD | | TODO | | Miri/ASAN | |
| B2-c | QC duplicate/equivocation | `qc.rs`·`vote_accumulator.rs` | CARRY-FORWARD | | TODO | | property test | no double-count; equivocation rejected |
| B2-d | Timeout/view-change safety | `timeout.rs`·`pacemaker.rs`·`driver.rs` | CARRY-FORWARD | | TODO | | adversarial sim (C3) | whitepaper §8.10 incomplete |
| B3 | Slashing reality | `slashing/`·`slashing_ledger.rs`·`ledger_slashing_backend.rs` | CARRY-FORWARD | | TODO | | wiring trace | Noop vs Penalty engine live? |
| B4-a | Public DoS default posture | `public_devnet_abuse_dos_runtime.rs` | DEVNET-BLOCK | | TODO | | config inspection + live test | limiter default-disabled |
| B4-b | Transport re-verify | `cookie.rs`·`session.rs`·`handshake.rs` | CARRY-FORWARD | | TODO | | test | cookie-before-decap; nonce monotonic |
| B4-c | Peer table / eclipse | `p2p_diversity.rs`·`p2p_session_eviction.rs` | CARRY-FORWARD | | TODO | | | inbound-flood isolation |
| B5-a | Decoder robustness | `qbind-wire`·`qbind-serde` | CARRY-FORWARD | | TODO | | fuzz (C1) | length-prefix bounds, no panic |
| B5-b | Storage durability | `storage.rs` (`flush_epoch_durable`) | CARRY-FORWARD | | TODO | | crash-recovery test (C4) | torn/ahead-of-durable state |
| B5-c | Merkle construction | `runtime/src/block.rs` (`merkle_root`) | CARRY-FORWARD | | TODO | | second-preimage test | odd-leaf duplication |
| B6-a | Value conservation / saturation | `monetary_state.rs`·`monetary_engine.rs`·`account.rs` | CARRY-FORWARD | | TODO | | conservation property test | `saturating_*` census |
| B6-b | T201 silent failure | `monetary_state.rs` ~1367 | CARRY-FORWARD | | TODO | | | treasury-credit must hard-error |
| B6-c | Replay / nonce / chain-id | `mempool.rs`·`dag_mempool.rs`·`qbind_tx.rs` | CARRY-FORWARD | | TODO | | replay test | cross-chain-id replay |
| B6-d | Casts census | ledger/runtime/consensus/node | CARRY-FORWARD | | TODO | | grep + per-site verdict | ~997 `as` casts |
| B7-a | verify_envelope | `qbind-gov/src/verify.rs`·`council.rs` | CARRY-FORWARD | | TODO | | duplicate-signer test | M-of-N; malleability |
| B7-b | Genesis authority consumption | `genesis_authority_record_correspondence.rs` | CARRY-FORWARD | | TODO | | | "not consumed by live verifier" |
| B8 | Panic-surface triage | attacker-reachable paths | CARRY-FORWARD | | TODO | | non-test panic census | DEVNET-BLOCK if remote-crash |

## C — Dynamic & adversarial

| ID | Area | Target | Track | Sev | Status | Evidence | Reproducer | Notes |
|---|---|---|---|---|---|---|---|---|
| C1 | Fuzzing | wire/serde/handshake/tx/QC | CARRY-FORWARD | | TODO | | `cargo fuzz run <target>` | currently zero fuzzing |
| C2 | Property tests | consensus/ledger/serde | CARRY-FORWARD | | TODO | | `cargo test` proptest | expand beyond t177/t179 |
| C3 | Adversarial sim | `sim.rs`·`multi_sim.rs`·`adversarial_multi_sim.rs` | CARRY-FORWARD | | TODO | | sim run | safety + liveness assertions |
| C4 | Multi-node soak + chaos | `scripts/devnet/run_*` | DEVNET-BLOCK | | TODO | | soak log | cross-node state-root agreement |
| C5 | Sanitizers | consensus/net | CARRY-FORWARD | | TODO | | Miri/ASAN/TSAN/loom | |

## D — Release & ops readiness

| ID | Area | Target | Track | Sev | Status | Evidence | Reproducer | Notes |
|---|---|---|---|---|---|---|---|---|
| D1 | Reproducible build | `scripts/build-mainnet-release.sh` | DEVNET-BLOCK | | TODO | | two-build hash compare | genesis hash pin |
| D2 | Operator surface | `metrics_http.rs`·`node_config.rs`·seeds | DEVNET-BLOCK | | TODO | | bind/config check | metrics not 0.0.0.0; M4 seeds |
| D3 | Ops drills | `docs/ops/` runbooks | DEVNET-BLOCK(restore) | | TODO | | drill log | backup/restore executed |
| D4 | Policy artifacts | `SECURITY.md`·`LICENSE`·threat model | DEVNET-BLOCK | | TODO | | files committed | + CHANGELOG, CODEOWNERS |

## E — Evidence-vs-reality reconciliation

| ID | Claim | Reality check | Track | Status | Evidence | Notes |
|---|---|---|---|---|---|---|
| E-01 | CodeQL is the security gate | no workflow / did not run | — | TODO | `evidence/E-drift/` | → A4 |
| E-02 | Tests enforce quality | no CI runs `cargo test` | — | TODO | `evidence/E-drift/` | → A2 |
| E-03 | Slashing present | live engine may be Noop | — | TODO | `evidence/E-drift/` | → B3 |
| E-04 | Timeout/view-change works | §8.10 incomplete | — | TODO | `evidence/E-drift/` | → B2-d |
| E-05 | Genesis authority governs | not consumed by live verifier | — | TODO | `evidence/E-drift/` | → B7-b |
| E-06 | DoS protections on | inbound limiter default-disabled | — | TODO | `evidence/E-drift/` | → B4-a |

---

## DevNet Go/No-Go roll-up (mirror of playbook §7.2)

- [ ] Gate A green (build+test+clippy+fmt+deny+CodeQL+coverage in CI)
- [ ] Gate B: no open Critical; every §6 CORRECT-NOW row audited
- [ ] Gate C: fuzz+proptest+sim+soak in CI; crash → consistent state root
- [ ] Gate D: reproducible build; safe defaults; SECURITY.md+LICENSE+threat model; M-gates Green
- [ ] Gate E: drift report complete; every claim has a verdict
- [ ] Every checked box has a reproducible evidence bundle

Any unchecked box ⇒ **NO-GO**.
