# QBIND DevNet evidence — Run 184

**Title.** Source/test OnChainGovernance proof carrying through the
production v2 ratification sidecar payload that feeds the Run 182
production call-site wrappers.

**Status.** PASS (source/test, partial-positive) — the Run 178 typed
`OnChainGovernanceProof` material can now be carried through the
existing production v2 ratification sidecar JSON as an additive,
optional `onchain_governance_proof` sibling field, parsed into a typed
`OnChainGovernanceProofWire`, and routed into the `proof:
Option<&OnChainGovernanceProof>` slot of an
`OnChainGovernanceCallsiteContext` consumed by the seven Run 182
named production call-site entries
(`--p2p-trust-bundle-reload-check`,
`--p2p-trust-bundle-reload-apply`, startup `--p2p-trust-bundle`,
SIGHUP live trust-bundle reload, local
`--p2p-trust-bundle-peer-candidate-check`, live inbound `0x05`, and
the Run 150 peer-driven apply drain coordinator in
`ProductionV2MarkerCoordinator`). The carrier is purely additive: legacy
v2 sidecars without the sibling continue to deserialize byte-for-byte
identically and load with `proof: None`. The default
policy on every surface remains
`OnChainGovernanceProofPolicy::Disabled`. MainNet peer-driven apply
remains refused even when a fully-valid DevNet fixture proof is
carried through the new payload path. Malformed payload bytes /
malformed wire / unknown schema-version are rejected as a typed
`OnChainGovernanceProofPayloadParseError` *before* any policy decision
runs, so the carrier is fail-closed at every surface regardless of
policy. Real on-chain governance proof verification, governance
execution, KMS/HSM custody, validator-set rotation, bridge /
light-client integration, autonomous apply, and apply-on-receipt all
remain unimplemented. Release-binary boundary evidence covering the
new payload-carrying surface is **deferred to Run 185**.

**Driving spec.** `task/RUN_184_TASK.txt`.

## 1. Strict scope

Run 184 closes the gap identified by Run 183's release-binary
boundary evidence: every Run 182 production call-site reached
`OnChainGovernanceCallsiteContext` with `proof: None` because the
real production v2 ratification sidecar payload carried no
`OnChainGovernanceProof` material. Run 184 introduces, at source/test
level only, an additive optional sibling on the existing v2 sidecar
JSON wire that delivers a typed
[`OnChainGovernanceProofWire`](
  ../../crates/qbind-node/src/pqc_onchain_governance_proof.rs)
through the same parsing path used by Run 167's `governance_authority_proof`
sibling carrier, and routes the parsed proof into the `proof` slot of
`OnChainGovernanceCallsiteContext` for each of the Run 182 named
call-site entries.

Run 184 is **strictly source/test** and adds **only**:

* A new module
  [`pqc_onchain_governance_payload_carrying`](
    ../../crates/qbind-node/src/pqc_onchain_governance_payload_carrying.rs)
  defining:
  * `OnChainGovernanceProofLoadStatus` (`Absent` / `Available(_)` /
    `Malformed(_)`).
  * `OnChainGovernanceProofPayloadParseError`
    (`Json{error}` / `Wire(OnChainGovernanceProofWireParseError)`).
  * `LoadedV2RatificationSidecarWithOnChainGovernanceProof`
    bundling the parsed v2 ratification sidecar with its load status.
  * Path/bytes loaders that parse the sidecar JSON, extract the
    optional sibling **before** re-deserializing into the strict
    `BundleSigningRatificationV2` (so unknown sibling fields cannot
    poison the v2 parse), and reject malformed sibling payloads as a
    typed `OnChainGovernanceProofPayloadParseError`.
  * `OnChainGovernancePayloadCarryingDecisionOutcome` and
    `callsite_context_with_loaded_onchain_governance_proof` that
    materialize an `OnChainGovernanceCallsiteContext` consumed by
    Run 182 entries — with the typed proof reference attached when
    `Available`, with `proof: None` when `Absent`, and with a
    routing-level `MalformedPayloadFailedClosed` short-circuit when
    `Malformed`.
  * Seven `route_loaded_onchain_governance_proof_to_*_callsite_decision`
    helpers — one per Run 182 named call-site entry — that drive the
    matching Run 182 entry with the loaded payload regardless of
    policy state, with the malformed-payload short-circuit applied
    surface-uniformly.
* A wire helper
  `V2RatificationSidecarWithOnChainGovernanceProofWire` providing the
  serde shape `BundleSigningRatificationV2 + optional
  onchain_governance_proof` for symmetric round-trip tests.

Run 184 does **not**:

* bump any wire schema version,
* add any new metric / counter / log line,
* change any default policy,
* enable MainNet peer-driven apply,
* implement any real on-chain proof verifier,
* implement governance execution / KMS-HSM / validator-set rotation,
* expose anything new on the public binary CLI surface.

## 2. Acceptance summary

All A1–A7 acceptance scenarios and R1–R26 rejection scenarios listed
in `task/RUN_184_TASK.txt` are encoded as integration tests in
[`tests/run_184_onchain_governance_payload_carrying_tests.rs`](
  ../../crates/qbind-node/tests/run_184_onchain_governance_payload_carrying_tests.rs)
and pass at source/test level.

Run command:

```text
cargo test -p qbind-node --test run_184_onchain_governance_payload_carrying_tests
```

Result: `test result: ok. 44 passed; 0 failed; 0 ignored; 0 measured;
0 filtered out`.

## 3. Honest limitations

* **Source/test only.** Run 184 ships no release-binary harness and
  no `target/release/qbind-node` evidence — that is the explicit
  Run 185 deliverable.
* **Default Disabled preserved.** Carrying a fully-valid DevNet
  fixture proof through the new sibling has zero observable effect
  unless the hidden Run 180 `AllowFixtureSourceTest` selector is
  armed via the existing CLI flag /env var (Run 181/183 surface).
* **MainNet still refused.** The Run 182 peer-driven drain entry
  continues to refuse MainNet peer-driven apply *before* invoking
  the underlying verifier, so even a fully-valid DevNet fixture
  proof carried through the new payload cannot enable MainNet
  peer-driven apply.
* **Malformed payload is fail-closed surface-uniformly.** When the
  optional sibling is structurally malformed, every surface
  short-circuits to `MalformedPayloadFailedClosed` *before* the
  Run 182 entry runs, regardless of the active policy.
* **No real on-chain proof verifier.** Run 184 carries proof
  *material* — it does not introduce any real on-chain governance
  proof verification beyond the Run 178 fixture-only verifier.
* **No governance execution.** Carrying / accepting an
  `OnChainGovernance` fixture proof at the production call-site
  context **does not** mutate authority state, does not enable
  MainNet apply, does not advance the validator set, and does not
  execute any governance action. The accepted outcome is observable
  only through the Run 180/182 typed surface.
* **C4/C5 remain open.** Run 184 does not close C4 or C5; both
  remain open invariants tracked by the contradiction ledger.
