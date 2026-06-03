# QBIND DevNet evidence — Run 177

**Title.** Release-binary live inbound `0x05` peer-candidate envelopes
carrying `governance_authority_proof` material under
`GovernanceProofPolicy::RequiredForLifecycleSensitive`.

**Status.** PASS — release-binary evidence captured (see harness +
archive at
`docs/devnet/run_177_live_0x05_governance_proof_release_binary/`).

**Driving spec.** `task/RUN_177_TASK.txt`.

## 1. Strict scope

Run 177 closes the Run 176-deferred release-binary boundary by exercising
on real `target/release/qbind-node` nodes (real DevNet N=3 V0/V1/V2
topology, real live P2P, real ML-KEM-768 / ML-DSA-44 /
ChaCha20-Poly1305 path), the live inbound `0x05` peer-candidate envelope
**carrying** the additive Run 176
`governance_authority_proof: Option<GovernanceAuthorityProofWire>` field.
Run 176 stopped short of release-binary multi-node evidence because the
existing Run 080 publish path
(`PeerCandidateWireEnvelopeV1::from_run076_envelope` in
`crates/qbind-node/src/pqc_peer_candidate_wire.rs`) hardcodes
`governance_authority_proof: None`, making real release-binary
proof-carrying frames otherwise impossible.

This run does **not**:

* enable peer-driven apply on MainNet (Run 147 FATAL invariant must hold);
* perform governance execution / on-chain governance / KMS-HSM /
  validator-set rotation;
* mutate authority-marker, sequence-file, or trust-bundle schema beyond
  Run 176's optional envelope field;
* claim full closure of Whitepaper contradictions C4 or C5.

## 2. Source delta (tiny, harness-only)

The Run 080 publish path (`from_run076_envelope`) hardcodes the carrier
field to `None`. Run 177 adds the smallest possible publish-time
injection point so a release-built binary can publish proof-carrying
live `0x05` frames in a controlled harness:

* `crates/qbind-node/src/cli.rs` — new hidden CLI flag (clap
  `hide=true`):
  `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path`
  → `Option<PathBuf>` field
  `p2p_trust_bundle_peer_candidate_wire_publish_governance_proof_path`.
  Mirrors the Run 080 / Run 142 / Run 171 hidden-flag policy. Absent
  from `qbind-node --help`.
* `crates/qbind-node/src/pqc_peer_candidate_wire.rs` —
  `PeerCandidateWirePublishConfig` extended with
  `governance_proof_path: Option<PathBuf>` (default `None`).
  `PeerCandidateWirePublishError` extended with `GovernanceProofIo`
  and `GovernanceProofParse` variants. `publish_once_from_config`
  parses the JSON as `GovernanceAuthorityProofWire` immediately after
  `from_run076_envelope` and sets
  `wire_envelope.governance_authority_proof = Some(...)` before
  `encode_peer_candidate_wire_frame`. Fail-closed on parse or I/O
  failure.
* `crates/qbind-node/src/main.rs` — Run 080 publish-once block
  populates `publish_cfg.governance_proof_path` from the new CLI arg.

Default behaviour is unchanged: when the new flag is absent, the binary
emits exactly the same wire bytes Run 080 / Run 176 already emit (no
carrier). No schema / wire / metric drift beyond Run 176's optional
envelope field. No public API surface change visible from `--help`.

## 3. Source reachability proof

Captured under
`docs/devnet/run_177_live_0x05_governance_proof_release_binary/reachability/source_reachability.txt`
on every harness invocation. The harness greps for and asserts presence
of:

* `governance_authority_proof` on `PeerCandidateWireEnvelopeV1`;
* `governance_proof_load_status` helper;
* `preflight_live_inbound_0x05_validation_only_marker_check_with_governance_proof_carrier`
  shim (Run 176);
* `GovernanceProofContext::Available` reachable from the live `0x05`
  dispatcher;
* the new Run 177 publish-time carrier flag and field across `cli.rs`,
  `main.rs`, and `pqc_peer_candidate_wire.rs`;
* `GovernanceProofPolicy::RequiredForLifecycleSensitive` selector +
  `governance_proof_policy_from_cli_or_env` helper.

## 4. Hidden-flag proof

`qbind-node --help` is captured to
`logs/help_no_hidden.stdout.log` and asserted to contain **none** of:

* `p2p-trust-bundle-governance-proof-required` (Run 171 selector,
  hidden);
* `p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path`
  (new Run 177 publish-time carrier flag, hidden);
* `p2p-trust-bundle-peer-candidate-wire-publish-enabled` (Run 080
  publish-side flag, hidden);
* `p2p-trust-bundle-peer-candidate-staging-enabled` (Run 080+ staging
  flag, hidden).

## 5. Topology

Real DevNet N=3:

* **V0** publisher: real `target/release/qbind-node` invoked with
  `--p2p-trust-bundle-peer-candidate-wire-publish-enabled`,
  `--p2p-trust-bundle-peer-candidate-wire-publish-once`,
  `--p2p-trust-bundle-peer-candidate-wire-publish-path <envelope>`,
  and (per scenario)
  `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path <proof>`.
* **V1** receiver: real `target/release/qbind-node` invoked with
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled` and
  either `--p2p-trust-bundle-governance-proof-required` (CLI Required)
  or `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1` (env
  Required). V1 is validation-only across every scenario: no staging,
  no apply, no drain.
* **V2** observer: validation-only with
  `--p2p-trust-bundle-peer-candidate-propagation-enabled`. Used to
  prove invalid proof-carrying candidates do not propagate.

`P2P_BASE` defaults to 29770; per-scenario ports are `P2P_BASE +
scenario_index*10 + node_index`. All three nodes share a baseline
`PeerSignedTrustBundle` and per-validator signing keys minted by the
Run 177 helper. Real ML-KEM-768 / ML-DSA-44 keys; real seeded V2
ratification corpus from
`crates/qbind-node/examples/run_177_live_0x05_governance_proof_release_binary_helper.rs`.

## 6. Acceptance scenarios (A1–A6)

| ID | Mode | Wire | Proof | Expected | Notes |
|----|------|------|-------|----------|-------|
| A1 | NotRequired (no selector, no env) | `peer-candidate.candidate.json` | none | accept; no V1 mutation | Legacy/no-proof path preserved; existing Run 130/142 boundary intact. |
| A2 | CLI Required | `peer-candidate.rotated.json` | `proof.valid.json` | accept at gate; no V1 mutation | V1 stderr shows `governance policy=RequiredForLifecycleSensitive`. |
| A3 | env Required | `peer-candidate.rotated.json` | `proof.valid.json` | accept at gate; no V1 mutation | Mirrors A2 via `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`. |
| A4 | Required + Revoke | n/a (release-binary) | n/a | `skipped(deferred-source-test)` | Lifecycle classification routes via Run 161 metadata-prefix; release-binary representability bounded. Source: Run 176 A4. |
| A5 | Required + EmergencyRevoke | n/a (release-binary) | n/a | `skipped(not-representable-at-v2-action-enum)` | `BundleSigningRatificationV2Action` does not include `EmergencyRevoke`. Source: Run 176 A5. |
| A6 | Required + idempotent (same-bytes replay) | `peer-candidate.rotated.json` | `proof.valid.json` | accept; no V1 mutation across two passes | Two full multi-node runs with same bytes; `marker_pre.sha256 == marker_post.sha256` on both passes. |

Per-scenario rc and assertions are in `summary.txt` and
`scenario_assertions.txt`.

## 7. Rejection scenarios (R1–R22)

| ID | Construction | Expected | Source |
|----|--------------|----------|--------|
| R1 | Required + no proof | reject; `GovernanceAuthorityRequiredButMissing` | binary |
| R2 | Required + malformed proof | reject | binary (`proof.malformed.json`) |
| R3 | Required + invalid issuer signature | reject | binary (`proof.invalid_signature.json`) |
| R4 | Required + wrong-env proof | `skipped(deferred-source-test)` | Run 130 verifier trips upstream; Run 173/176 source-test |
| R5 | Required + wrong-chain proof | `skipped(deferred-source-test)` | Run 130 verifier trips upstream; Run 173/176 source-test |
| R6 | Required + wrong-genesis proof | `skipped(deferred-source-test)` | Run 130 verifier trips upstream; Run 173/176 source-test |
| R7 | Required + wrong authority root | reject | binary (`proof.wrong_root.json`) |
| R8 | Required + wrong lifecycle action | reject | binary (`proof.wrong_action.json`) |
| R9 | Required + wrong candidate digest | reject | binary (`proof.wrong_digest.json`) |
| R10 | Required + wrong authority-domain sequence | reject | binary (`proof.wrong_sequence.json`) |
| R11 | Required + unsupported issuer suite | reject | binary (`proof.unsupported_suite.json`) |
| R12 | Required + non-PQC suite | covered_by_R11 | non-PQC suite ids fall through unsupported-suite refusal |
| R13 | Required + OnChainGovernance | reject (unsupported / fail-closed) | binary (`proof.onchain_governance.json`) |
| R14 | Required + local-operator-config | covered_by_R1 | no operator-config carrier in Run 176/177 schema |
| R15 | Required + peer-majority | covered_by_R1 | no peer-majority carrier in Run 176/177 schema |
| R16 | proof-valid + lifecycle-invalid | `skipped(deferred-source-test)` | Run 161/165 source-test |
| R17 | lifecycle-valid + proof-invalid | covered_by_R2_R3 | |
| R18 | invalid candidate not propagated | asserted_per_case (V2 observer log) | |
| R19 | invalid candidate not staged | asserted_per_case (no staging flag) | |
| R20 | invalid candidate not drained | asserted_per_case (no drain flag) | |
| R21 | valid candidate does not apply on receipt | asserted_per_case A2/A3/A6 (V1 marker/sequence non-mutation) | |
| R22 | MainNet peer-driven apply refused even with Required + valid proof | `rc=1`; `Run 147 FATAL` | binary single-node refusal |

## 8. No-mutation invariant

Across **every** A* and R* scenario the harness records
`marker_pre.sha256` and `marker_post.sha256` for V1's
`pqc_authority_state.json` and asserts equality, and asserts V1's
`pqc_trust_bundle_sequence.json` is not written. The harness also
asserts V1's stderr log is clean of:

* `Run 070: trust-bundle candidate APPLIED`
* `[run-134] reload-apply v2 ratification path SELECTED`
* `[run-134] v2 authority-marker persisted`
* `sequence_commit=ok`

This proves R21 (no apply on receipt) on every accept case and
reinforces R18/R19/R20 across the rejection matrix.

## 9. Propagation / staging / drain proof

* V2 is a propagation-enabled validation-only observer. Its log is
  asserted clean of any `[run-088] propagation REBROADCAST` for any R*
  scenario.
* No node in any scenario is invoked with
  `--p2p-trust-bundle-peer-candidate-staging-enabled`. R19 holds by
  construction across the validation-only matrix.
* No node in any scenario is invoked with
  `--p2p-trust-bundle-peer-candidate-drain-once`. R20 holds by
  construction.

## 10. Denylist (captured in `grep_summaries/denylist.txt`)

Each of the following greps must return nothing (or the harness
records the explicit `OK:` line):

* `MainNet.*APPLIED` / `trust-bundle candidate APPLIED .* env=mainnet`
* `autonomous apply` / `apply on receipt`
* `peer.majority.*authoritative` / `peer-majority authority`
* `fallback to --p2p-trusted-root` / `p2p-trusted-root.*fallback`
* `DummySig` / `DummyKem` / `DummyAead`
* `[run-134] reload-apply v2 ratification path SELECTED`
* `[run-134] v2 authority-marker persisted`
* `Run 070: trust-bundle candidate APPLIED`

## 11. Cross-checks (release tests)

The harness runs the following release-mode `cargo test` suites and
records rc to `summary.txt`:

* `run_176_live_0x05_governance_proof_carrier_tests`
* `run_173_validation_only_governance_required_policy_tests`
* `run_171_governance_required_policy_selector_tests`
* `run_169_governance_proof_loader_surface_integration_tests`
* `run_167_governance_proof_carrier_tests`
* `run_165_governance_marker_integration_tests`
* `run_163_governance_authority_verifier_tests`
* `run_161_lifecycle_marker_integration_tests`
* `run_159_authority_signing_key_lifecycle_tests`
* `run_157_unified_testnet_fixture_universe_tests`
* `run_152_binary_reachable_peer_drain_plumbing_tests`
* `run_150_peer_driven_apply_drain_tests`
* `run_148_peer_driven_apply_devnet_tests`
* `run_142_live_inbound_0x05_v2_validation_tests`
* `run_138_sighup_v2_authority_marker_tests`
* `run_134_reload_apply_v2_authority_marker_tests`
* `pqc_authority_lib`

## 12. Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
    --example run_177_live_0x05_governance_proof_release_binary_helper

bash scripts/devnet/run_177_live_0x05_governance_proof_release_binary.sh

cargo test --release -p qbind-node --test \
    run_176_live_0x05_governance_proof_carrier_tests
cargo test --release -p qbind-node --test \
    run_173_validation_only_governance_required_policy_tests
cargo test --release -p qbind-node --test \
    run_171_governance_required_policy_selector_tests
cargo test --release -p qbind-node --test \
    run_169_governance_proof_loader_surface_integration_tests
cargo test --release -p qbind-node --test \
    run_167_governance_proof_carrier_tests
cargo test --release -p qbind-node --test \
    run_165_governance_marker_integration_tests
cargo test --release -p qbind-node --test \
    run_163_governance_authority_verifier_tests
cargo test --release -p qbind-node --test \
    run_161_lifecycle_marker_integration_tests
cargo test --release -p qbind-node --test \
    run_159_authority_signing_key_lifecycle_tests
cargo test --release -p qbind-node --test \
    run_157_unified_testnet_fixture_universe_tests
cargo test --release -p qbind-node --test \
    run_152_binary_reachable_peer_drain_plumbing_tests
cargo test --release -p qbind-node --test \
    run_150_peer_driven_apply_drain_tests
cargo test --release -p qbind-node --test \
    run_148_peer_driven_apply_devnet_tests
cargo test --release -p qbind-node --test \
    run_142_live_inbound_0x05_v2_validation_tests
cargo test --release -p qbind-node --test \
    run_138_sighup_v2_authority_marker_tests
cargo test --release -p qbind-node --test \
    run_134_reload_apply_v2_authority_marker_tests
cargo test --release -p qbind-node --lib pqc_authority
```

## 13. Honest limitations preserved

* R4/R5/R6 (wrong-env / wrong-chain / wrong-genesis) covered at source
  level by Run 173 and Run 176 source-tests + Run 168 helper symbol
  coverage. Release-binary representability bounded by the Run 130
  upstream verifier. Reported as `rc=skipped(deferred-source-test)`.
* A4 / A5 (Revoke / EmergencyRevoke release-binary representability)
  bounded by the Run 161 metadata-prefix lifecycle classifier and the
  v2 ratification action enum (no `EmergencyRevoke` variant).
  Reported as `rc=skipped(deferred-source-test)` and
  `rc=skipped(not-representable-at-v2-action-enum)`.
* Whitepaper C4 / C5 are **not** claimed closed. Run 177 closes the
  release-binary boundary for the live inbound `0x05` proof carrier
  shim added in Run 176; the operator-config / on-chain-governance /
  KMS-HSM / validator-set-rotation surfaces remain open.

## 14. Cross-references

* `task/RUN_177_TASK.txt`
* `docs/devnet/run_177_live_0x05_governance_proof_release_binary/`
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_176.md`
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_175.md`
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_173.md`
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_167.md`
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_165.md`
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_158.md`
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
* `docs/whitepaper/contradiction.md`
