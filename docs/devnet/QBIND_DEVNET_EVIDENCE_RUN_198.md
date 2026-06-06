# QBIND DevNet evidence — Run 198

**Title.** Source/test hidden RemoteSigner policy selector and production
preflight integration.

**Status.** PASS (source/test only). Run 198 adds a hidden,
disabled-by-default RemoteSigner policy selector (one hidden CLI flag
plus one environment variable) and wires the resolved
`RemoteSignerPolicy` into all seven production v2 marker-decision
preflight contexts through the Run 196 RemoteSigner payload/call-site
routing layer.

Run 198 does NOT implement a real RemoteSigner backend. The default
remains `RemoteSignerPolicy::Disabled`; legacy no-RemoteSigner payloads
remain accepted exactly as before (Run 196 compatibility). Fixture
loopback RemoteSigner material remains DevNet/TestNet evidence-only and
cannot satisfy MainNet production RemoteSigner; production RemoteSigner
material reaches the boundary and fails closed as unavailable;
malformed/invalid material fails closed; and MainNet peer-driven apply
remains the Run 147 / 148 / 152 FATAL refusal even with
`MainnetProductionRemoteSignerRequired` and fixture loopback material.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 199).
* Hidden selector only (one hidden CLI flag + one env var).
* Disabled by default.
* No real RemoteSigner backend; no networked signer service.
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No marker / sequence-file / authority-marker / trust-bundle core /
  ratification-sidecar wire / schema change. Run 198 only adds
  source-level selector parsing and thin preflight wrappers around the
  Run 196 routing helpers.
* Run 198 does not weaken any prior run (Runs 070, 130–197) and does not
  claim full C4 or C5 closure.

## Run 198 deliverables

* Production source module:
  [`crates/qbind-node/src/pqc_remote_signer_policy_surface.rs`](
    ../../crates/qbind-node/src/pqc_remote_signer_policy_surface.rs).
* Hidden CLI flag `--p2p-trust-bundle-remote-signer-policy` in
  [`crates/qbind-node/src/cli.rs`](../../crates/qbind-node/src/cli.rs).
* Focused test suite:
  [`crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`](
    ../../crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## Selector surface

The hidden selector is exposed via:

* CLI: `--p2p-trust-bundle-remote-signer-policy <value>` (clap
  `hide = true`).
* Env: `QBIND_P2P_TRUST_BUNDLE_REMOTE_SIGNER_POLICY=<value>`.

Both share one pure parser. The grep-verifiable helpers in
`pqc_remote_signer_policy_surface` are:

* `remote_signer_policy_from_selector` — pure string → policy parser.
* `remote_signer_policy_env_selector` — single env readback.
* `remote_signer_policy_from_cli_or_env` — CLI/env resolver.

The parser accepts these case-insensitive tags (whitespace trimmed),
matching `RemoteSignerPolicy::tag` exactly:

| value                                       | resolved policy                                        |
|---------------------------------------------|--------------------------------------------------------|
| `disabled`                                  | `RemoteSignerPolicy::Disabled`                         |
| `fixture-loopback-allowed`                  | `RemoteSignerPolicy::FixtureLoopbackAllowed`           |
| `production-remote-signer-required`         | `RemoteSignerPolicy::ProductionRemoteSignerRequired`   |
| `mainnet-production-remote-signer-required` | `RemoteSignerPolicy::MainnetProductionRemoteSignerRequired` |

Empty / whitespace-only values return
`RemoteSignerPolicySelectorParseError::Empty`. Unknown non-empty values
return `RemoteSignerPolicySelectorParseError::UnknownValue { value }`.
The resolver never silently downgrades to `Disabled` when an explicit
value is present but invalid.

**Default.** Both the CLI flag and the env var absent ⇒
`RemoteSignerPolicy::Disabled`. The env var unset yields `Ok(None)` from
`remote_signer_policy_env_selector`, which the resolver maps to
`Disabled`.

**Precedence.** When both the CLI flag and the env var are supplied, the
CLI flag wins. This mirrors the Run 192 authority-custody policy selector
precedence and the standard CLI/env convention: the operator-supplied
command line is authoritative for a single invocation. Either source
alone is sufficient to select a non-default policy.

### Policy constraints

* `FixtureLoopbackAllowed` — DevNet/TestNet evidence only; cannot satisfy
  MainNet production RemoteSigner (the MainNet peer-driven drain surface
  refuses unconditionally, and a MainNet-binding fixture candidate is
  rejected before acceptance).
* `ProductionRemoteSignerRequired` — fails closed because no real backend
  exists (`RemoteSignerOutcome::ProductionRemoteSignerUnavailable`).
* `MainnetProductionRemoteSignerRequired` — fails closed
  (`RemoteSignerOutcome::MainNetProductionRemoteSignerUnavailable`);
  MainNet peer-driven apply remains refused regardless.
* Invalid selector values fail closed with a typed parse error at
  startup/preflight.

### Per-surface preflight wrappers

Seven thin wrappers bind the resolved policy into the Run 196
[`RemoteSignerCallsiteContext`](
  ../../crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs)
for each of the seven production v2 marker-decision preflight contexts
and dispatch to the matching Run 196
`route_loaded_remote_signer_attestation_to_*_callsite_decision` helper:

* `preflight_v2_marker_remote_signer_for_reload_check`
* `preflight_v2_marker_remote_signer_for_reload_apply`
* `preflight_v2_marker_remote_signer_for_startup_p2p_trust_bundle`
* `preflight_v2_marker_remote_signer_for_sighup`
* `preflight_v2_marker_remote_signer_for_local_peer_candidate_check`
* `preflight_v2_marker_remote_signer_for_live_inbound_0x05`
* `preflight_v2_marker_remote_signer_for_peer_driven_drain`

These wrappers exist so the Run 198 source-reachability claim ("the
selected policy reaches all seven production-context helpers") is
grep-verifiable from each surface. They are pure: no I/O, no marker
write, no sequence write, no live-trust swap, no session eviction, no
Run 070 invocation. Mutating callers continue to honor the existing
`commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`
sequence-before-marker ordering AFTER acceptance.

### A11 — live inbound `0x05`

The live inbound `0x05` validation-only surface receives the selected
policy through
`preflight_v2_marker_remote_signer_for_live_inbound_0x05`. An invalid
live `0x05` RemoteSigner candidate (malformed, absent under a
non-`Disabled` policy, or rejected by the Run 194 verifier) short-circuits
at the routing helper and is not propagated, staged, or applied
(R33). No live-config wiring limitation applies at the source/test
level; release-binary live wiring evidence is deferred to Run 199.

## Tests added

[`crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs`](
  ../../crates/qbind-node/tests/run_198_remote_signer_policy_selector_tests.rs)
covers the A1–A11 / R1–R34 matrix from `task/RUN_198_TASK.txt`:

* selector parsing and precedence — default, CLI, env, CLI-over-env,
  invalid value fail-closed (CLI and env), unrelated env does not enable
  policy;
* A1–A11 accepted scenarios (where representable) — default disabled
  bypass, CLI/env `fixture-loopback-allowed`, `production-remote-signer-
  required` and `mainnet-production-remote-signer-required` typed
  fail-closed at the verifier, no Disabled-time governance behaviour
  change, mutating DevNet fixture acceptance, live `0x05` policy
  reachability;
* R1–R34 rejection scenarios — invalid CLI/env selector, unrelated env,
  no-RemoteSigner under FixtureLoopbackAllowed / ProductionRemoteSigner-
  Required, fixture rejection under production/MainNet production,
  production/MainNet production unavailable, every binding-tuple mismatch
  (env / chain / genesis / authority-root / custody-key-id / signing-key
  fingerprint / lifecycle action / candidate digest / authority-domain
  sequence / request digest / replay nonces / expiry / suite / signature),
  malformed material short-circuit, local-operator-key and peer-majority
  cannot satisfy RemoteSigner, custody-valid-but-RemoteSigner-invalid and
  RemoteSigner-valid-but-custody-invalid, validation-only and mutating
  rejection non-mutation, live-`0x05` invalid candidate not propagated,
  MainNet peer-driven apply refused under MainnetProductionRemoteSigner-
  Required with fixture loopback material;
* source reachability — the resolved policy reaches all seven
  production-context per-surface preflight wrappers (single test
  exercising every wrapper for accept and required-but-absent).

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests`
* `cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests`
* `cargo test -p qbind-node --test run_194_remote_authority_signer_boundary_tests`
* `cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests`
* `cargo test -p qbind-node --test run_190_authority_custody_payload_callsite_tests`
* `cargo test -p qbind-node --test run_188_authority_custody_boundary_tests`
* `cargo test -p qbind-node --test run_186_onchain_governance_production_verifier_boundary_tests`
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
* `cargo test -p qbind-node --lib pqc_remote_signer_policy_surface`
* `cargo test -p qbind-node --lib pqc_authority`

All commands run on this checkout completed successfully, including:

* `run_198_remote_signer_policy_selector_tests`: 53 passed.
* `run_196_remote_signer_payload_callsite_tests`: 58 passed.
* `run_194_remote_authority_signer_boundary_tests`: 44 passed.
* `run_192_authority_custody_policy_selector_tests`: 46 passed.
* `run_190_authority_custody_payload_callsite_tests`: 55 passed.
* `run_188_authority_custody_boundary_tests`: 48 passed.
* `run_186_onchain_governance_production_verifier_boundary_tests`: 44 passed.
* `pqc_remote_signer_policy_surface` lib self-tests: 7 passed.

## Acceptance summary

1. A hidden RemoteSigner policy selector exists (CLI hidden flag + env
   var, both routed through pure parsers in
   `pqc_remote_signer_policy_surface`). ✅
2. Default remains `RemoteSignerPolicy::Disabled`. ✅
3. Selector reaches production preflight contexts at source/test level
   via the seven `preflight_v2_marker_remote_signer_for_*` wrappers. ✅
4. Fixture loopback RemoteSigner material passes only where the selected
   policy allows (A2/A3/A10/A11). ✅
5. Missing/malformed/invalid RemoteSigner material fails closed under
   explicit policy (R4/R5/R10–R26). ✅
6. Production RemoteSigner remains fail-closed as unavailable
   (A4/A5/R8/R9). ✅
7. Validation-only surfaces remain non-mutating (R31). ✅
8. Mutating rejection surfaces produce no mutation (R32 — the wrappers
   are pure data transforms; malformed carriers short-circuit before the
   verifier). ✅
9. MainNet peer-driven apply remains refused even with
   `MainnetProductionRemoteSignerRequired` and fixture loopback material
   (R34). ✅
10. Release-binary RemoteSigner-policy selector evidence deferred to
    Run 199. ✅
11. No real RemoteSigner / KMS / HSM / governance execution / real
    on-chain proof / validator-set rotation claim is made. ✅
12. No full C4 or C5 closure is claimed. ✅

## Deferred

* Release-binary RemoteSigner-policy selector evidence: **Run 199**.
* Real RemoteSigner / KMS / HSM / cloud-KMS / PKCS#11 backend remains
  unimplemented.
* Real on-chain governance proof verification remains unimplemented.
* Governance execution remains unimplemented.
* Validator-set rotation remains open.
* Full C4 remains open.
* C5 remains open.
