# QBIND DevNet evidence — Run 209

**Title.** Source/test hidden custody-attestation policy selector and
production preflight integration.

**Status.** PASS (source/test only). Run 209 adds a hidden,
disabled-by-default custody-attestation policy selector (one hidden CLI
flag plus one environment variable) and wires the resolved Run 205
`CustodyAttestationPolicy` into all seven production v2 marker-decision
preflight contexts through thin per-surface wrappers around the Run 207
custody-attestation payload-carrying / call-site routing layer.

Run 209 is **source/test only**. Release-binary custody-attestation
policy selector evidence is deferred to **Run 210**.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 210).
* Hidden selector only (clap `hide = true` flag + env var).
* Disabled by default.
* No real cloud-KMS attestation verifier.
* No real PKCS#11 attestation verifier.
* No real HSM-vendor attestation verifier.
* No real KMS implementation.
* No real HSM implementation.
* No real RemoteSigner backend; no networked signer daemon.
* No production signing-key custody.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No schema/wire change; no authority-marker schema change; no
  sequence-file schema change; no trust-bundle core schema change; no
  authority-lifecycle semantics change.
* Run 209 does not weaken any prior run (Runs 070, 130–208) and does not
  claim full C4 or C5 closure.

## Selector design

A single hidden CLI flag and a single environment variable share the same
case-insensitive, ASCII-whitespace-trimmed value grammar. The recognized
tags match `CustodyAttestationPolicy::tag` exactly:

| value                                     | resolved policy                                            |
|-------------------------------------------|------------------------------------------------------------|
| `disabled`                                | `CustodyAttestationPolicy::Disabled`                       |
| `fixture-attestation-allowed`             | `CustodyAttestationPolicy::FixtureAttestationAllowed`      |
| `remote-signer-attestation-required`      | `CustodyAttestationPolicy::RemoteSignerAttestationRequired` |
| `kms-attestation-required`                | `CustodyAttestationPolicy::KmsAttestationRequired`         |
| `hsm-attestation-required`                | `CustodyAttestationPolicy::HsmAttestationRequired`         |
| `production-attestation-required`         | `CustodyAttestationPolicy::ProductionAttestationRequired`  |
| `mainnet-production-attestation-required` | `CustodyAttestationPolicy::MainnetProductionAttestationRequired` |

* **CLI flag:** `--p2p-trust-bundle-custody-attestation-policy <value>`
  (hidden via clap).
* **Env var:** `QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY=<value>`.

**Default.** When both the CLI flag and the env var are absent/empty the
resolved policy is `CustodyAttestationPolicy::Disabled` — legacy
no-attestation payloads remain bit-for-bit compatible (Run 207
invariants).

**Precedence (deterministic).** When both sources are supplied the **CLI
flag wins**, mirroring the Run 192 authority-custody and Run 198
RemoteSigner policy-selector precedence and the standard CLI/env
convention. The env var still propagates when the CLI flag is absent.

**Fail-closed parsing.** Invalid / unknown selector values are surfaced
as a typed `CustodyAttestationPolicySelectorParseError`
(`Empty` / `UnknownValue`). The resolver never silently downgrades an
explicit-but-invalid value to `Disabled`.

## Policy constraints

* `FixtureAttestationAllowed` — DevNet/TestNet evidence only; must not
  satisfy MainNet production attestation.
* `RemoteSignerAttestationRequired` — fails closed; no real RemoteSigner
  attestation verifier exists.
* `KmsAttestationRequired` — fails closed; no real KMS attestation
  verifier exists.
* `HsmAttestationRequired` — fails closed; no real HSM attestation
  verifier exists.
* `ProductionAttestationRequired` — fails closed; no real production
  attestation verifier exists.
* `MainnetProductionAttestationRequired` — fails closed; MainNet
  peer-driven apply remains refused regardless.

## Run 209 deliverables

* Production source module:
  [`crates/qbind-node/src/pqc_custody_attestation_policy_surface.rs`](
    ../../crates/qbind-node/src/pqc_custody_attestation_policy_surface.rs)
  — env-var name `QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY`, a
  typed `CustodyAttestationPolicySelectorParseError`, the pure parsers
  `custody_attestation_policy_from_selector` /
  `custody_attestation_policy_env_selector` /
  `custody_attestation_policy_from_cli_or_env`, and the seven per-surface
  preflight wrappers `preflight_v2_marker_custody_attestation_for_*`.
* Module registration in
  [`crates/qbind-node/src/lib.rs`](../../crates/qbind-node/src/lib.rs).
* Hidden CLI flag `--p2p-trust-bundle-custody-attestation-policy` in
  [`crates/qbind-node/src/cli.rs`](../../crates/qbind-node/src/cli.rs).
* Source/test matrix:
  [`crates/qbind-node/tests/run_209_custody_attestation_policy_selector_tests.rs`](
    ../../crates/qbind-node/tests/run_209_custody_attestation_policy_selector_tests.rs).

## Source reachability — all seven production preflight contexts

The resolved policy is bound into the Run 207
`CustodyAttestationCallsiteContext` and dispatched to the matching Run 207
`route_loaded_custody_attestation_to_*_callsite_decision` routing helper
by one grep-verifiable wrapper per surface:

1. reload-check — `preflight_v2_marker_custody_attestation_for_reload_check`
2. reload-apply — `preflight_v2_marker_custody_attestation_for_reload_apply`
3. startup `--p2p-trust-bundle` —
   `preflight_v2_marker_custody_attestation_for_startup_p2p_trust_bundle`
4. SIGHUP — `preflight_v2_marker_custody_attestation_for_sighup`
5. local peer-candidate-check —
   `preflight_v2_marker_custody_attestation_for_local_peer_candidate_check`
6. live inbound `0x05` —
   `preflight_v2_marker_custody_attestation_for_live_inbound_0x05`
7. peer-driven drain —
   `preflight_v2_marker_custody_attestation_for_peer_driven_drain`

The wrappers are pure: no marker write, no sequence write, no live trust
swap, no session eviction, no Run 070 call. Mutating callers continue to
honor sequence-before-marker ordering AFTER acceptance.

## Accepted / rejection scenario coverage

The Run 209 test target covers A1–A15 and R1–R40 where representable at
the selector + payload-carrying layer (51 tests):

* Selector parsing + precedence: default (absent ⇒ `Disabled`), CLI, env,
  CLI-over-env (`A9`), empty/unknown typed fail-closed (`R1`, `R2`),
  unrelated env does not enable a policy (`R3`).
* `A1`/`A10`/`A11` — legacy no-attestation payload bypassed under
  `Disabled` across all surfaces; governance-class proof behavior
  unchanged under `Disabled`.
* `A2`/`A3`/`A14` — fixture attestation accepted under
  `FixtureAttestationAllowed`, reaching all seven production-context
  wrappers on DevNet and TestNet.
* `A4`–`A8` / `R8`–`R14` — RemoteSigner / KMS / HSM / cloud-KMS / PKCS#11
  / production / MainNet attestation reaches the Run 205 verifier and
  fails closed as unavailable.
* `R4`/`R5` — no-attestation payload rejected (required-but-absent) under
  `FixtureAttestationAllowed` / `ProductionAttestationRequired`.
* `R6`/`R7` — fixture attestation rejected under
  `ProductionAttestationRequired` / `MainnetProductionAttestationRequired`.
* `R15` — malformed material rejected, verifier not invoked.
* `R16`–`R34` — environment / chain / genesis / authority-root /
  signing-key / custody-class / backend-provider / key-id / suite /
  lifecycle-action / candidate-digest / authority-domain-sequence /
  governance-proof / request / response / transcript digest mismatches,
  stale/replayed, expired, and invalid-commitment all reach the verifier
  and fail closed.
* `R35`/`R36` — local operator / peer majority cannot satisfy a
  production-required policy.
* `R37` — validation-only rejection is non-mutating.
* `R38` — mutating rejection produces no apply-path side effect.
* `R39` — invalid live inbound `0x05` candidate is not propagated.
* `A8`/`R40` — MainNet peer-driven apply remains refused even with
  `MainnetProductionAttestationRequired` and fixture attestation material.

### A15 limitation (live inbound `0x05`)

At this source/test layer the live-inbound `0x05` wrapper receives and
honors the resolved policy exactly like the other six surfaces. The
binary-level live-config plumbing that threads the selector into the live
`0x05` receive path in a running release binary is **deferred to
Run 210** together with the rest of the release-binary selector evidence.

## What remains open

* Default remains `CustodyAttestationPolicy::Disabled`.
* Fixture attestation remains DevNet/TestNet evidence-only and cannot
  satisfy MainNet production attestation.
* Production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation
  remains unavailable / fail-closed.
* MainNet peer-driven apply remains refused.
* No real cloud-KMS attestation verifier is implemented.
* No real PKCS#11 attestation verifier is implemented.
* No real HSM-vendor attestation verifier is implemented.
* No real KMS / HSM backend is implemented.
* No real RemoteSigner backend is implemented.
* Governance execution remains unimplemented.
* Real on-chain proof verification remains unimplemented.
* Validator-set rotation remains open.
* Release-binary custody-attestation policy selector evidence is deferred
  to **Run 210**.
* **Full C4 remains OPEN. C5 remains OPEN.**

## Validation commands

```
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_209_custody_attestation_policy_selector_tests
cargo test -p qbind-node --test run_207_custody_attestation_payload_callsite_tests
cargo test -p qbind-node --test run_205_custody_attestation_verifier_tests
cargo test -p qbind-node --lib pqc_custody_attestation_policy_surface
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```