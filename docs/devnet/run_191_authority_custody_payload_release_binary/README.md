# Run 191 — Release-binary authority-custody metadata carrying evidence

## Scope

Closes the Run 190-deferred release-binary boundary for the
source/test authority-custody **metadata carrying** layer added by
[`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs).
Run 190 added the typed authority-custody payload-carrying surface on
top of the Run 188 typed authority-custody boundary
[`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs):
[`AuthorityCustodyAttestationWire`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
(stable wire types for class / governance authority class /
attestation),
[`AuthorityCustodyClassWire`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
/
[`GovernanceAuthorityClassWire`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs),
[`AuthorityCustodyLoadStatus`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
(`Loaded` / `Absent` / `Malformed { … }`), the optional sibling JSON
parser
[`parse_optional_authority_custody_attestation_sibling_from_json_value`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs),
[`AuthorityCustodyCallsiteContext`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
binding the seven trust-bundle production callsites (reload-check,
reload-apply, startup-p2p-trust-bundle, SIGHUP, local-peer-candidate-
check, live-inbound-0x05, peer-driven-drain), the typed callsite
context constructor
[`callsite_context_for_authority_custody`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs),
the typed
[`AuthorityCustodyPayloadCarryingDecisionOutcome`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
(`Callsite` / `Refused` / `Unhandled`), the seven per-surface routing
helpers
`route_loaded_authority_custody_attestation_to_reload_check_callsite_decision`,
`route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision`,
`route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision`,
`route_loaded_authority_custody_attestation_to_sighup_callsite_decision`,
`route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision`,
`route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision`,
`route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision`,
and the explicit grep-verifiable named helper
`mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`.
Run 190 is source/test only with the A1–A10 / R1–R32 corpus
[`crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs`](
  ../../../crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs)
all passing; release-binary payload-carrying evidence is **this Run 191**.

Run 191 captures **release-binary** evidence that real
`target/release/qbind-node` preserves the Run 190 typed authority-
custody payload-carrying contract end-to-end:

* the production default `AuthorityCustodyPolicy::Disabled` is
  preserved on every binary surface — Run 190 added no operator-visible
  selector, so `target/release/qbind-node --help` surfaces no custody
  flag, no KMS/HSM/remote-signer flag, and no production-custody flag,
  and the default `--print-genesis-hash --env {devnet,testnet,mainnet}`
  invocations emit no Run 190 custody enablement banner and no MainNet
  peer-driven apply enablement claim (S1 / S2 / S3 / S4);
* the existing Run 187 hidden fixture selector
  `--p2p-trust-bundle-onchain-governance-fixture-allowed` (and the
  matching `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
  env var) does not enable any Run 190 custody payload backend — armed
  on MainNet it still refuses MainNet peer-driven apply and emits no
  KMS/HSM/production-custody claim (S5);
* the release-built Run 191 helper
  [`run_191_authority_custody_payload_release_binary_helper`](
    ../../../crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs)
  exercises the Run 190 A1–A10 / R1–R32 corpus end-to-end in **release
  mode** through the production library symbols
  `pqc_authority_custody_payload_carrying::*` —
  `AuthorityCustodyAttestationWire`, `AuthorityCustodyClassWire`,
  `GovernanceAuthorityClassWire`, `AuthorityCustodyLoadStatus`,
  `parse_optional_authority_custody_attestation_sibling_from_json_value`,
  `AuthorityCustodyCallsiteContext`,
  `callsite_context_for_authority_custody`,
  `AuthorityCustodyPayloadCarryingDecisionOutcome`, the seven
  per-surface routing helpers, and
  `mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`,
  composed with the Run 188 typed boundary symbols
  `pqc_authority_custody::*`;
* every `RemoteSigner` / `Kms` / `Hsm` attestation (carried through the
  Run 190 wire layer and parsed back to the Run 188 typed
  `AuthorityCustodyAttestation`) routes to the typed
  `RemoteSignerUnavailable` / `KmsUnavailable` / `HsmUnavailable`
  outcome regardless of policy or environment; every
  `ProductionCustodyRequired` / `MainnetProductionCustodyRequired`
  policy routes to `ProductionCustodyUnavailable` /
  `MainNetProductionCustodyUnavailable` (or the placeholder-specific
  `*Unavailable`); every fixture / local-operator class on MainNet
  routes to `FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet` ahead of the policy gate, encoding
  the honest unavailability of any real production custody backend in
  this tree and explicitly forbidding fixture/local-as-MainNet-
  production-custody — even when the rejecting metadata is wire-carried
  through the new sibling;
* legacy / no-custody payloads (sibling absent) remain compatible under
  default `Disabled`: the seven routing helpers return
  `Callsite { lifecycle_outcome, custody_outcome:
  CustodyAttestationMissing }` only when policy demands custody, and
  return `Callsite { custody_outcome: AcceptedNoCustodyRequired }` (or
  symbolic equivalent) when policy is `Disabled`, never producing a
  schema or wire drift relative to Run 184's existing optional-sibling
  shape;
* malformed sibling JSON (non-object, missing-field, unknown class,
  expired, etc.) is parsed by
  `parse_optional_authority_custody_attestation_sibling_from_json_value`
  to a typed `AuthorityCustodyLoadStatus::Malformed { … }` and routed
  by every per-surface helper to a typed
  `Callsite { custody_outcome: CustodyAttestationMalformed }` (or to
  the surface-specific peer-driven-drain MainNet refusal where applicable),
  with no panic, no allocation surprise, and no schema drift;
* the Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal
  invariant survives unchanged at the binary surface AND at the typed
  custody payload-carrying boundary via the
  `mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`
  helper regardless of attestation contents, sibling presence, or
  active policy;
* every rejected scenario is captured with bit-equal candidate /
  persisted snapshots before and after the rejecting custody routing
  call (no marker write, no sequence write, no live trust swap, no
  session eviction, no Run 070 call); deterministic re-evaluation is
  asserted across the corpus.

## Strict scope (no production-source change)

Per `task/RUN_191_TASK.txt`:

* **Release-binary evidence only.** Run 191 introduces no new
  production module, no new production CLI flag, no new env knob,
  no new schema bump, no new wire shape, no new sidecar field, no
  new metric, and no new exit code beyond the Run 190 typed
  authority-custody payload-carrying surface already in the tree.
  The only new files committed by Run 191 are this evidence archive,
  the harness shell script
  [`scripts/devnet/run_191_authority_custody_payload_release_binary.sh`](
    ../../../scripts/devnet/run_191_authority_custody_payload_release_binary.sh),
  the release-built helper example
  [`crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs`](
    ../../../crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs),
  the canonical evidence report
  [`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_191.md`](
    ../QBIND_DEVNET_EVIDENCE_RUN_191.md),
  and narrow append-only Run 191 update sections in the
  contradiction ledger and three protocol/runbook design docs.

* **Real `target/release/qbind-node`** is used for every binary
  scenario. Library-layer typed payload-carrying outcomes are captured
  by the release-built Run 191 helper through the production library
  symbols.

* **No production source change.** No production-source line under
  `crates/` is modified by Run 191.

* **No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.**
  Every production custody class (whether constructed in-process or
  parsed back from the Run 190 wire sibling) fails closed at the typed
  Run 188 validator with a typed `*Unavailable` outcome.

* **No MainNet peer-driven apply enablement.** The Run 147 / 148 /
  152 FATAL invariant is preserved.

* **No real on-chain governance proof verifier.** Run 186's
  `OnChainGovernanceVerifierKind::Disabled` default is preserved on
  every surface; Run 191 adds no proof-verifier path.

* **No governance execution engine. No bridge / light-client
  integration. No validator-set rotation. No autonomous apply. No
  apply-on-receipt. No peer-majority authority.**

* **No schema/wire/metric drift beyond Run 190's additive optional
  custody sibling.** The v2 ratification sidecar shape, the Run 184
  `onchain_governance_proof` sibling, the v2 marker layout, the Run
  055 sequence-file layout, the `qbind_ledger::BundleSigningRatificationV2`
  core schema, and every metric remain unchanged. Run 190's optional
  authority-custody sibling is purely additive.

* **Runs 070, 130–190** are **not** weakened. Run 191 adds only
  release-binary evidence; the Run 190 typed payload-carrying contract
  (and the Run 188 typed boundary contract it composes over) is
  preserved bit-identically.

* **Full C4 / C5 remain OPEN.** Run 191 does not claim closure of
  C4 (real on-chain governance proof verification + governance
  execution end-to-end) or C5 (real KMS/HSM + validator-set rotation
  + autonomous apply gates).

## Layout (tracked vs. generated)

This archive uses the same convention as Run 153 / 155 / 179 / 181 /
183 / 185 / 187 / 189:

* **Tracked in git** (committed):
  * `README.md` — this file.
  * `summary.txt` — committed placeholder; the harness rewrites it.
  * `.gitignore` — declares the generated subtrees below.

* **Generated by the harness** (gitignored, contain absolute paths
  and ephemeral data; reproducible from
  `scripts/devnet/run_191_authority_custody_payload_release_binary.sh`):
  * `logs/` — per-scenario stdout/stderr.
  * `exit_codes/` — per-scenario `*.rc` files.
  * `helper_evidence/run_191/` — Run 191 helper output:
    `manifest.txt`, `expected_outcomes.txt`, `actual_outcomes.txt`,
    `wire_round_trip.txt`, `sibling_parse_table.txt`,
    `routing_helpers_table.txt`, `named_helpers_table.txt`,
    `no_mutation_evidence.txt`, `determinism_evidence.txt`,
    `helper_summary.txt`, plus per-scenario subdirectories under
    `scenarios/`.
  * `reachability/` — `source_reachability.txt`, the production
    grep proof for every Run 188 / Run 190 authority-custody and
    payload-carrying symbol.
  * `test_results/` — captured `cargo test --release` logs for the
    targeted regression slice in `task/RUN_191_TASK.txt`.
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
    run_191_authority_custody_payload_release_binary_helper
$ bash scripts/devnet/run_191_authority_custody_payload_release_binary.sh
```

The harness is idempotent: it wipes and regenerates every gitignored
subtree above, then writes a fresh `summary.txt` with a canonical
PASS/FAIL verdict line (the verdict line is referenced verbatim by
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_191.md`).

## Honest limitations preserved

* **No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend
  is implemented.** Every `RemoteSigner`, `Kms`, and `Hsm` custody
  class — whether constructed in-process or wire-carried through the
  Run 190 sibling and parsed back — fails closed at the typed Run 188
  validator with a typed `RemoteSignerUnavailable` / `KmsUnavailable`
  / `HsmUnavailable` outcome, regardless of attestation contents or
  active policy.

* **Fixture / local-operator custody remains DevNet/TestNet
  evidence-only.** It is reachable only under the explicit
  `FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed`
  policies, and is rejected by symbol whenever the trust-domain
  environment is MainNet (`FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet`) ahead of the policy gate, even
  when the metadata is carried through the Run 190 wire sibling.

* **Fixture / local-operator custody cannot satisfy MainNet
  production custody.** The MainNet rejection layer is intentionally
  ahead of the policy gate so a misconfigured policy can never
  silently elevate fixture / local-operator material to MainNet
  production custody.

* **Existing no-custody payloads remain compatible under default
  `Disabled`.** Sibling-absent payloads route through the Run 190
  routing helpers without producing a schema or wire drift; the
  decision routes to `Callsite` with the typed
  `CustodyAttestationMissing` (when policy demands custody) or
  `AcceptedNoCustodyRequired` symbolic equivalent (when policy is
  `Disabled`).

* **Existing Run 184 / Run 185 / Run 187 governance fixture proof
  paths remain compatible.** Run 191 wire-carrying evidence is
  layered additively next to the Run 184 governance-proof sibling;
  the v2 ratification sidecar shape is unchanged.

* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal** regardless of custody outcome. The grep-verifiable
  helper
  `mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`
  encodes the rule at the typed Run 190 payload-carrying boundary.

* **Governance execution remains unimplemented.** Run 191 does not
  call the Run 163 / 178 / 186 governance verifier itself; the
  routing helpers take the already-validated governance class from
  the calling surface.

* **Real on-chain governance proof verification remains
  unimplemented.** Run 186's
  `OnChainGovernanceVerifierKind::Disabled` default is preserved on
  every surface; Run 191 adds no new proof-verifier path.

* **Validator-set rotation, autonomous apply, apply-on-receipt,
  peer-majority authority, and bridge / light-client integration all
  remain unimplemented.**

* **No schema/wire/metric drift beyond Run 190's additive optional
  custody sibling.**

* **Full C4 and C5 remain OPEN.** Run 191 is release-binary
  payload-carrying evidence; it does not enable any real KMS / HSM /
  remote-signer backend, real on-chain governance proof verifier, or
  real governance execution engine.
