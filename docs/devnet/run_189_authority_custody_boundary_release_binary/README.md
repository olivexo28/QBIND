# Run 189 — Release-binary KMS/HSM authority-custody boundary evidence

## Scope

Closes the Run 188-deferred release-binary boundary for the
source/test KMS/HSM authority-custody layer added by
[`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs).
Run 188 added the typed authority-custody surface:
[`AuthorityCustodyClass`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs)
(`FixtureLocalKey` / `LocalOperatorKey` / `RemoteSigner` / `Kms` /
`Hsm` / `Unknown`),
[`AuthorityCustodyPolicy`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs)
(`Disabled` (default) / `FixtureOnly` / `DevnetLocalAllowed` /
`TestnetLocalAllowed` / `ProductionCustodyRequired` /
`MainnetProductionCustodyRequired`), the typed
[`AuthorityCustodyAttestation`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs)
binding to environment / chain id / genesis / authority-root / signing-
key fingerprint / governance authority class / lifecycle action /
candidate digest / authority-domain sequence / custody class / custody
key id / custody attestation digest / optional freshness+expiry, the
typed
[`AuthorityCustodyValidationOutcome`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs)
(`AcceptedFixtureCustody` / `AcceptedLocalOperatorCustody` /
`ProductionCustodyUnavailable` /
`MainNetProductionCustodyUnavailable` / `KmsUnavailable` /
`HsmUnavailable` / `RemoteSignerUnavailable` /
`FixtureCustodyRejectedForMainNet` /
`LocalCustodyRejectedForMainNet` / `PolicyRefusesCustodyClass` /
`UnknownCustodyClassRejected` / wrong-environment / wrong-chain /
wrong-genesis / wrong-authority-root / wrong-signing-key fingerprint /
wrong-candidate-digest / wrong-authority-domain-sequence /
wrong-lifecycle-action / `CustodyAttestationMissing` /
`CustodyAttestationMalformed` / `CustodyAttestationExpired` /
`CustodyKeyIdMismatch` / `UnsupportedCustodySuite`), the pure validator
[`validate_authority_custody_attestation`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs),
the typed combined helper
[`validate_lifecycle_governance_and_custody`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs)
returning a typed
[`LifecycleGovernanceCustodyOutcome`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs)
(`Accepted` / `LifecycleRejected` / `CustodyRejected` /
`MainNetPeerDrivenApplyRefused`), and three explicit grep-verifiable
named helpers
(`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
`peer_majority_cannot_satisfy_custody`,
`local_operator_config_alone_cannot_satisfy_mainnet_production_custody`).
Run 188 is source/test only with 48 tests (A1–A8 / R1–R29 plus extras
for fixture-vs-production custody separation, MainNet-fixture / -local
masquerade refusal, KMS/HSM/remote-signer placeholder fail-closed under
every policy, helper purity, deterministic re-evaluation, and short-
circuit of custody under a rejected lifecycle), all passing;
release-binary custody-boundary evidence is **this Run 189**.

Run 189 captures **release-binary** evidence that real
`target/release/qbind-node` preserves the Run 188 typed
authority-custody boundary contract end-to-end:

* the production default `AuthorityCustodyPolicy::Disabled` is
  preserved on every binary surface — Run 188 added no operator-
  visible selector, so `target/release/qbind-node --help` surfaces no
  custody flag, no KMS/HSM/remote-signer flag, and no production-
  custody flag, and the default `--print-genesis-hash --env
  {devnet,testnet,mainnet}` invocations emit no Run 188 custody
  enablement banner and no MainNet peer-driven apply enablement claim
  (S1 / S2 / S3 / S4);
* the existing Run 187 hidden fixture selector
  `--p2p-trust-bundle-onchain-governance-fixture-allowed` (and the
  matching `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
  env var) does not enable any Run 188 custody backend — armed on
  MainNet it still refuses MainNet peer-driven apply and emits no
  KMS/HSM/production-custody claim (S5);
* the release-built Run 189 helper
  [`run_189_authority_custody_boundary_release_binary_helper`](
    ../../../crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs)
  exercises the Run 188 A1–A8 / R1–R29 corpus end-to-end in **release
  mode** through the production library symbols
  `pqc_authority_custody::*` —
  `AuthorityCustodyClass`, `AuthorityCustodyPolicy`,
  `AuthorityCustodyAttestation`, `AuthorityCustodyValidationOutcome`,
  `LifecycleGovernanceCustodyOutcome`,
  `validate_authority_custody_attestation`,
  `validate_lifecycle_governance_and_custody`,
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
  `peer_majority_cannot_satisfy_custody`,
  `local_operator_config_alone_cannot_satisfy_mainnet_production_custody`;
* every `RemoteSigner` / `Kms` / `Hsm` attestation routes to the
  typed `RemoteSignerUnavailable` / `KmsUnavailable` / `HsmUnavailable`
  outcome regardless of policy or environment; every
  `ProductionCustodyRequired` / `MainnetProductionCustodyRequired`
  policy routes to `ProductionCustodyUnavailable` /
  `MainNetProductionCustodyUnavailable` (or the placeholder-specific
  `*Unavailable`); every fixture / local-operator class on MainNet
  routes to `FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet` ahead of the policy gate, encoding
  the honest unavailability of any real production custody backend in
  this tree and explicitly forbidding fixture/local-as-MainNet-
  production-custody;
* the Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal
  invariant survives unchanged at the binary surface AND at the typed
  custody boundary via the
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`
  helper regardless of attestation contents or policy;
* every rejected scenario is captured with bit-equal candidate /
  persisted snapshots before and after the rejecting custody
  validation (no marker write, no sequence write, no live trust
  swap, no session eviction, no Run 070 call); deterministic
  re-evaluation is asserted across the corpus.

## Strict scope (no production-source change)

Per `task/RUN_189_TASK.txt`:

* **Release-binary evidence only.** Run 189 introduces no new
  production module, no new production CLI flag, no new env knob,
  no new schema bump, no new wire shape, no new sidecar field, no
  new metric, and no new exit code beyond the Run 188 typed
  authority-custody surface already in the tree. The only new files
  committed by Run 189 are this evidence archive, the harness shell
  script
  [`scripts/devnet/run_189_authority_custody_boundary_release_binary.sh`](
    ../../../scripts/devnet/run_189_authority_custody_boundary_release_binary.sh),
  the release-built helper example
  [`crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs`](
    ../../../crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs),
  the canonical evidence report
  [`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_189.md`](
    ../QBIND_DEVNET_EVIDENCE_RUN_189.md),
  and narrow append-only Run 189 update sections in the
  contradiction ledger and three protocol/runbook design docs.

* **Real `target/release/qbind-node`** is used for every binary
  scenario. Library-layer typed custody-boundary outcomes are
  captured by the release-built Run 189 helper through the
  production library symbols.

* **No production source change.** No production-source line under
  `crates/` is modified by Run 189.

* **No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.**
  Every production custody class fails closed at the typed Run 188
  validator with a typed `*Unavailable` outcome.

* **No MainNet peer-driven apply enablement.** The Run 147 / 148 /
  152 FATAL invariant is preserved.

* **No real on-chain governance proof verifier.** Run 186's
  `OnChainGovernanceVerifierKind::Disabled` default is preserved on
  every surface; Run 189 adds no proof-verifier path.

* **No governance execution engine. No bridge / light-client
  integration. No validator-set rotation. No autonomous apply. No
  apply-on-receipt. No peer-majority authority.**

* **No schema/wire/metric drift.** The v2 ratification sidecar shape,
  the additive Run 184 `onchain_governance_proof` sibling, the v2
  marker layout, the Run 055 sequence-file layout, the
  `qbind_ledger::BundleSigningRatificationV2` core schema, and every
  metric remain unchanged.

* **Runs 070, 130–188** are **not** weakened. Run 189 adds only
  release-binary evidence; the Run 188 typed boundary contract is
  preserved bit-identically.

* **Full C4 / C5 remain OPEN.** Run 189 does not claim closure of
  C4 (real on-chain governance proof verification + governance
  execution end-to-end) or C5 (real KMS/HSM + validator-set rotation
  + autonomous apply gates).

## Layout (tracked vs. generated)

This archive uses the same convention as Run 153 / 155 / 179 / 181 /
183 / 185 / 187:

* **Tracked in git** (committed):
  * `README.md` — this file.
  * `summary.txt` — committed placeholder; the harness rewrites it.
  * `.gitignore` — declares the generated subtrees below.

* **Generated by the harness** (gitignored, contain absolute paths
  and ephemeral data; reproducible from
  `scripts/devnet/run_189_authority_custody_boundary_release_binary.sh`):
  * `logs/` — per-scenario stdout/stderr.
  * `exit_codes/` — per-scenario `*.rc` files.
  * `helper_evidence/run_189/` — Run 189 helper output:
    `manifest.txt`, `expected_outcomes.txt`, `actual_outcomes.txt`,
    `custody_class_table.txt`, `named_helpers_table.txt`,
    `no_mutation_evidence.txt`, `determinism_evidence.txt`,
    `helper_summary.txt`, plus per-scenario subdirectories under
    `scenarios/`.
  * `reachability/` — `source_reachability.txt`, the production
    grep proof for every Run 188 authority-custody symbol.
  * `test_results/` — captured `cargo test --release` logs for the
    targeted regression slice in `task/RUN_189_TASK.txt`.
  * `provenance.txt` — git commit / branch / status, rustc /
    cargo versions, host, qbind-node + helper SHA-256 + ELF
    Build IDs.
  * `negative_invariants.txt` — denylist proven empty.
  * `mutation_proof.txt` — accepted-compatibility scenario proof
    scaffold.
  * `no_mutation_proof.txt` — rejected-scenario non-mutation proof.

## Reproducibility

```
$ cargo build --release -p qbind-node --bin qbind-node
$ cargo build --release -p qbind-node --example \
    run_189_authority_custody_boundary_release_binary_helper
$ bash scripts/devnet/run_189_authority_custody_boundary_release_binary.sh
```

The harness is idempotent: it wipes and regenerates every gitignored
subtree above, then writes a fresh `summary.txt` with a canonical
PASS/FAIL verdict line (the verdict line is referenced verbatim by
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_189.md`).

## Honest limitations preserved

* **No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend
  is implemented.** Every `RemoteSigner`, `Kms`, and `Hsm` custody
  class fails closed at the typed Run 188 validator with a typed
  `RemoteSignerUnavailable` / `KmsUnavailable` / `HsmUnavailable`
  outcome, regardless of attestation contents or active policy.

* **Fixture / local-operator custody remains DevNet/TestNet
  evidence-only.** It is reachable only under the explicit
  `FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed`
  policies, and is rejected by symbol whenever the trust-domain
  environment is MainNet (`FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet`) ahead of the policy gate.

* **Fixture / local-operator custody cannot satisfy MainNet
  production custody.** The MainNet rejection layer is intentionally
  ahead of the policy gate so a misconfigured policy can never
  silently elevate fixture / local-operator material to MainNet
  production custody.

* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal** regardless of custody outcome. The grep-verifiable
  helper
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`
  encodes the rule at the typed Run 188 boundary.

* **Governance execution remains unimplemented.** Run 189 does not
  call the Run 163 / 178 / 186 governance verifier itself; the
  composition helper takes the already-validated governance class
  from the calling surface.

* **Real on-chain governance proof verification remains
  unimplemented.** Run 186's
  `OnChainGovernanceVerifierKind::Disabled` default is preserved on
  every surface; Run 189 adds no new proof-verifier path.

* **Validator-set rotation, autonomous apply, apply-on-receipt,
  peer-majority authority, and bridge / light-client integration all
  remain unimplemented.**

* **No schema/wire/metric drift.**

* **Full C4 and C5 remain OPEN.** Run 189 is release-binary boundary
  evidence; it does not enable any real KMS / HSM / remote-signer
  backend, real on-chain governance proof verifier, or real
  governance execution engine.