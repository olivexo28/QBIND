# Run 177 — Release-binary live inbound `0x05` governance-proof carrier evidence

## Scope

Closes the Run 176-deferred release-binary boundary by exercising, on real
`target/release/qbind-node` nodes (real DevNet N=3 V0/V1/V2 topology, real live
P2P, real ML-KEM-768 / ML-DSA-44 / ChaCha20-Poly1305 path), the live inbound
`0x05` peer-candidate envelope **carrying the additive Run 176
`governance_authority_proof` field**.

Run 176 added the optional `governance_authority_proof:
Option<GovernanceAuthorityProofWire>` field to `PeerCandidateWireEnvelopeV1`
and the Run 173 → Run 169 → Run 165 governance-gate validation-only shim
(`preflight_live_inbound_0x05_validation_only_marker_check_with_governance_proof_carrier`).
Run 176 stopped short of release-binary multi-node evidence because the
existing publish path (`PeerCandidateWireEnvelopeV1::from_run076_envelope`)
hardcodes `governance_authority_proof: None`. Run 177 closes that gap with a
**tiny harness-only source delta** (a hidden CLI flag) and a multi-node
release-binary harness driving the A1–A6 / R1–R22 scenario matrix end-to-end.

## What was committed

Only `README.md`, `summary.txt`, and `.gitignore` are tracked. Every per-run
artifact under this directory (`logs/`, `data/`, `exit_codes/`,
`marker_hashes/`, `sequence_hashes/`, `data_inventories/`, `grep_summaries/`,
`reachability/`, `test_results/`, `fixtures/`, `provenance.txt`,
`fixture_manifest.txt`, `scenario_assertions.txt`, `negative_invariants.txt`)
contains absolute paths and ephemeral data and is `.gitignore`d on purpose,
matching the Run 153/155/158/175 evidence-archive convention.

## Reproducibility

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
    --example run_177_live_0x05_governance_proof_release_binary_helper
bash scripts/devnet/run_177_live_0x05_governance_proof_release_binary.sh
```

`OUTDIR` defaults to this directory. The harness is **idempotent** — it wipes
`logs/`, `data/`, `exit_codes/`, `fixtures/`, etc. on every invocation and
re-mints fixtures from the release-built helper. The summary line written at
the end of `summary.txt` is the canonical verdict.

## Source delta (tiny, harness-only)

The existing publish path
(`PeerCandidateWireEnvelopeV1::from_run076_envelope` in
`crates/qbind-node/src/pqc_peer_candidate_wire.rs`) hardcodes
`governance_authority_proof: None`. To emit real release-binary live `0x05`
frames carrying real `GovernanceAuthorityProofWire` (Run 167 schema) JSON
material, Run 177 adds the smallest possible publish-time injection point:

* New hidden CLI flag (clap `hide=true`):
  `--p2p-trust-bundle-peer-candidate-wire-publish-governance-proof-path`
  (`crates/qbind-node/src/cli.rs`).
* New `governance_proof_path: Option<PathBuf>` field on
  `PeerCandidateWirePublishConfig` and two new error variants
  (`GovernanceProofIo`, `GovernanceProofParse`) on
  `PeerCandidateWirePublishError`
  (`crates/qbind-node/src/pqc_peer_candidate_wire.rs`).
* Injection block in `publish_once_from_config` immediately after
  `from_run076_envelope`: parse the JSON as
  `GovernanceAuthorityProofWire` and set
  `wire_envelope.governance_authority_proof = Some(...)` before
  `encode_peer_candidate_wire_frame`. Fail-closed on parse failure.
* CLI wiring in `crates/qbind-node/src/main.rs` Run 080 publish-once
  block populates `publish_cfg.governance_proof_path`.

No schema / wire / metric drift beyond Run 176's optional envelope field.
The flag is not surfaced in `--help`, mirroring Run 080 / Run 142 / Run 171
hidden-flag policy. Default behaviour is unchanged: when the flag is absent,
the publish path emits exactly the same wire bytes Run 080 / Run 176 emit
(no carrier).

## Topology

Real DevNet N=3:

* **V0** — publisher of the live `0x05` proof-carrying peer-candidate envelope
  via Run 080 publish-once + the new Run 177 carrier flag.
* **V1** — receiver with `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
  and either `--p2p-trust-bundle-governance-proof-required` (CLI Required) or
  `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1` (env Required). V1 is
  validation-only across every scenario: no
  `--p2p-trust-bundle-peer-candidate-staging-enabled`, no
  `--p2p-trust-bundle-peer-candidate-apply-enabled`, no
  `--p2p-trust-bundle-peer-candidate-drain-once`.
* **V2** — propagation/staging observer. Confirms invalid proof-carrying
  candidates never propagate / stage / drain (R18/R19/R20 invariants).

`P2P_BASE` defaults to 29770; per-scenario ports are
`P2P_BASE + scenario_index*10 + node_index` so concurrent runs do not collide.

## Scenario matrix — verdicts in `summary.txt`

Accepted (A1–A6) and rejected (R1–R22) scenarios match
`task/RUN_177_TASK.txt` exactly. Per-scenario rc and assertions are written
to `summary.txt`, `scenario_assertions.txt`, and the per-scenario
`logs/<NAME>/v0.stderr.log`, `v1.stderr.log`, `v2.stderr.log` files.

## Honest limitations preserved

* **R4/R5/R6 (wrong-environment / wrong-chain / wrong-genesis proofs)** are
  not bit-for-bit expressible as static fixtures consumable by the binary
  without changing the production environment / chain / genesis the binary
  is invoked with: the Run 130 verifier trips upstream of the Run 165
  governance gate. Mirrors Run 174 / Run 175 precedent. Covered at source
  level by Run 173 source-test (`run_173_validation_only_governance_required_policy_tests`)
  and Run 176 source-test (`run_176_live_0x05_governance_proof_carrier_tests`),
  and at symbol level by the Run 168 helper. Reported in `summary.txt` as
  `rc=skipped(deferred-source-test)`.
* **A4 / A5 (Revoke / EmergencyRevoke release-binary representability)** —
  A4 routes lifecycle classification via Run 161 metadata-prefix; the
  binary's V2 `BundleSigningRatificationV2Action` enum does not include an
  `EmergencyRevoke` variant. Reported as
  `rc=skipped(deferred-source-test)` and
  `rc=skipped(not-representable-at-v2-action-enum)` respectively. Source-
  level coverage is in Run 176.
* **R12 / R14 / R15 / R17** are constructively covered by R11 / R1 / R2 / R3
  per the Run 176/177 schema (no operator-config or peer-majority carrier
  exists; non-PQC suite ids fall through unsupported-suite refusal;
  lifecycle-valid + proof-invalid is the R2/R3 path).
* **R22** (MainNet peer-driven apply refusal even with Required + valid
  proof + valid candidate) confirms the Run 147 FATAL invariant survives
  the Run 177 carrier wiring.
* **No claim of full C4 / C5 closure.** Governance execution / on-chain
  governance / KMS-HSM / validator-set rotation remain open. No
  authority-marker / sequence-file / trust-bundle schema change.

## Negative invariants

Captured in `negative_invariants.txt` (regenerated each run). Highlights:

* No V1 marker write, no V1 `pqc_trust_bundle_sequence.json` write,
  no `Run 070: trust-bundle candidate APPLIED`,
  no `[run-134] reload-apply v2 ratification path SELECTED`,
  no `[run-134] v2 authority-marker persisted`,
  no `sequence_commit=ok`
  on **any** scenario (validation-only across the matrix; R21 invariant).
* No `DummySig` / `DummyKem` / `DummyAead` symbol in any captured log.
* No `fallback to --p2p-trusted-root` and no peer-majority authority claim.
* The Run 177 publish-time carrier flag and the Run 171 governance-proof
  selector are absent from `qbind-node --help` (clap `hide=true`).

## Cross-references

* `task/RUN_177_TASK.txt` — driving spec (acceptance / rejection matrix,
  validation commands, deliverables).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_177.md` — canonical evidence
  report for this run.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_176.md` — Run 176 closes the
  source-level governance-proof carrier on `PeerCandidateWireEnvelopeV1`.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_175.md` — Run 175 closes the
  release-binary V2 ratification proof-carrier sidecar evidence
  (single-node).
* `docs/devnet/run_158_testnet_positive_peer_driven_apply_release_binary/` —
  multi-node release-binary template Run 177 inherits its V0/V1/V2
  orchestration from.