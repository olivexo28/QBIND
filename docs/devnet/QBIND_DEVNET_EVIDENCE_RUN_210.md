# QBIND DevNet evidence — Run 210

**Title.** Release-binary custody-attestation policy-selector evidence.

**Status.** PASS (release-binary). Run 210 is the release-binary evidence run
for the Run 209 source/test hidden custody-attestation policy selector
([`crates/qbind-node/src/pqc_custody_attestation_policy_surface.rs`](
  ../../crates/qbind-node/src/pqc_custody_attestation_policy_surface.rs)).
It proves, on the **real** `target/release/qbind-node` plus a release-built
helper linking the production library symbols, that real production surfaces
exercise the hidden custody-attestation policy selector from Run 209 and route
the selected [`CustodyAttestationPolicy`](
  ../../crates/qbind-node/src/pqc_custody_attestation_verifier.rs) into the
seven Run 207 production preflight contexts and the Run 205 custody-attestation
verifier
([`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`](
  ../../crates/qbind-node/src/pqc_custody_attestation_verifier.rs)),
while preserving the default `CustodyAttestationPolicy::Disabled` behavior,
legacy no-attestation payload compatibility, and the MainNet
peer-driven-apply refusal.

Run 210 is **release-binary evidence only**. It makes **no production source
change** (helper + harness + docs only). It does **not** implement a real
cloud-KMS attestation verifier, a real PKCS#11 attestation verifier, a real
HSM-vendor attestation verifier, a real KMS/HSM implementation, or a real
RemoteSigner backend. The hidden CLI/env selector is additive and disabled by
default; an invalid selector value fails closed with a typed parse error.
Fixture attestation is DevNet/TestNet evidence-only; the production, cloud-KMS,
PKCS#11, HSM-vendor, and RemoteSigner attestation paths remain
unavailable/fail-closed regardless of the selected policy; the RemoteSigner
path (Runs 194–202) and the KMS/HSM backend path (Runs 203–204) remain
separate, unchanged backend-boundary options; and MainNet peer-driven apply
remains the Run 147 / 148 / 152 FATAL refusal even when
`mainnet-production-attestation-required` is selected and a fixture attestation
is carried.

## Strict scope

* Release-binary evidence only; uses real `target/release/qbind-node`.
* Uses release-built helper(s) to mint custody-attestation-carrying
  sidecars / peer-candidate material and to drive the Run 209 selector.
* No production source change unless a tiny harness-only fix is required
  (none was required).
* No real cloud-KMS / PKCS#11 / HSM-vendor attestation verifier.
* No real KMS implementation; no real HSM implementation.
* No real RemoteSigner backend; no networked signer daemon.
* No production signing-key custody.
* No MainNet peer-driven apply enablement.
* No governance execution engine; no real on-chain proof verifier; no
  validator-set rotation; no autonomous apply; no apply on receipt; no
  peer-majority authority.
* No schema/wire change; no authority-marker / sequence-file / trust-bundle
  core schema change; no authority-lifecycle semantics change.
* Does not weaken Runs 070, 130–209; does not claim full C4 or C5 closure.

## Run 210 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_210_custody_attestation_policy_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_210_custody_attestation_policy_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_210_custody_attestation_policy_release_binary.sh`](
    ../../scripts/devnet/run_210_custody_attestation_policy_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_210_custody_attestation_policy_release_binary/`](
    run_210_custody_attestation_policy_release_binary/)
  (tracks `README.md`, `summary.txt`, `.gitignore`; all per-run artifacts
  are `.gitignore`d).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`](
      ../protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md)
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](
      ../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## Release-binary surface invariants

The harness drives the real `target/release/qbind-node`:

* **S1** `--help` hides the Run 209 selector flag
  `--p2p-trust-bundle-custody-attestation-policy` (clap `hide = true`) and
  advertises no custody-attestation / KMS / HSM / cloud-KMS / PKCS#11 /
  RemoteSigner-backend surface, no `run-205`/`run-207`/`run-209`/`run-210`
  token, no governance-execution and no validator-set-rotation claim.
* **S2–S4** default DevNet / TestNet / MainNet `--print-genesis-hash` surface
  emits no custody-attestation enablement banner and no MainNet peer-driven
  apply enablement claim.
* **S5** Run 209 CLI selector `fixture-attestation-allowed` armed on DevNet —
  the selector is accepted with no custody-attestation / KMS-HSM / cloud-KMS /
  PKCS#11 enablement drift.
* **S6** Run 209 env selector `kms-attestation-required` armed on DevNet — no
  enablement drift.
* **S7** Run 209 CLI-over-env precedence armed on DevNet (env
  `fixture-attestation-allowed`, CLI `disabled`) — no enablement drift.
* **S8** Run 209 invalid CLI selector value armed on DevNet — fails closed at
  the library level, no enablement banner.
* **S9** MainNet with `mainnet-production-attestation-required` armed (CLI +
  env) — MainNet peer-driven apply refusal preserved (Run 147 FATAL
  invariant), no custody-attestation / KMS-HSM / cloud-KMS / PKCS#11 /
  validator-set-rotation enablement.
* **S10** Run 193 custody-policy selector + Run 198 RemoteSigner-policy
  selector armed alongside the Run 209 selector on DevNet — no enablement
  drift, no RemoteSigner backend connect.

> Honest limitation: the Run 209 CLI flag is defined (hidden) in
> `crates/qbind-node/src/cli.rs` and parsed by the release binary, and the
> selector is consumed by the policy-selector surface at the library level; the
> binary does not yet wire its resolved policy into a long-running node
> runtime, so arming the selector at the binary surface enables no production
> custody attestation. The full env/CLI → resolved-policy → preflight-context
> chain is therefore proven in release mode through the production library
> symbols by the release-built helper.

## Release-helper corpus

The release-built helper
`run_210_custody_attestation_policy_release_binary_helper` exercises the Run
209 selector and Run 207 routing in **release mode through the production
library symbols** (`selector`, `accepted`, `rejection`, `loader`,
`reachability` tables; all `verdict: PASS`):

* **A1** unset CLI/env resolves to `CustodyAttestationPolicy::Disabled`.
* **A2 / A3** the hidden CLI selector and the env selector each resolve every
  canonical tag (`disabled`, `fixture-attestation-allowed`,
  `remote-signer-attestation-required`, `kms-attestation-required`,
  `hsm-attestation-required`, `production-attestation-required`,
  `mainnet-production-attestation-required`).
* **A4** CLI `fixture-attestation-allowed` resolves and accepts DevNet fixture
  attestation through every preflight surface.
* **A5** env `fixture-attestation-allowed` resolves and accepts TestNet
  fixture attestation (via the JSON sibling round-trip) through the
  reload-check preflight wrapper.
* **A6–A9** CLI `remote-signer- / kms- / hsm- / production-attestation-required`
  resolve and reach the typed unavailable outcome.
* **A10** env `mainnet-production-attestation-required` resolves and reaches
  the typed MainNet production unavailable outcome.
* **A11** CLI-over-env precedence is deterministic (both directions).
* **A12** no-attestation payload remains compatible under default `Disabled`
  (`NoCustodyAttestationSupplied` bypass).
* **A13** GenesisBound / EmergencyCouncil / OnChainGovernance proof behavior
  unchanged when the attestation policy is `Disabled`.
* **A14** Run 193 custody-policy selector behavior remains compatible (custody
  policy and attestation policy are independent selectors).
* **A15** Run 199 RemoteSigner-policy selector behavior remains compatible.
* **R1 / R2** invalid CLI / env selector values rejected with typed
  `CustodyAttestationPolicySelectorParseError` (`UnknownValue` / `Empty`).
* **R3** an unrelated env var does not enable the custody-attestation policy.
* **R4 / R5** no-attestation payload rejected under `FixtureAttestationAllowed`
  / `ProductionAttestationRequired` (`CustodyAttestationRequiredButAbsent`).
* **R6 / R7** fixture attestation rejected under `ProductionAttestationRequired`
  / `MainnetProductionAttestationRequired`.
* **R8–R14** RemoteSigner / KMS / HSM / cloud-KMS / PKCS#11 / production /
  MainNet production attestation rejected as unavailable.
* **R15** malformed custody-attestation material rejected (fail-closed before
  the verifier).
* **R16–R31** wrong environment / chain / genesis / authority-root /
  signing-key fingerprint / custody class / backend-provider-signer id /
  key id / suite / lifecycle action / candidate digest / authority-domain
  sequence / governance-proof / request / response / transcript digest
  rejected at the Run 205 verifier.
* **R32 / R33 / R34** stale-or-replayed / expired / invalid-commitment
  attestation rejected.
* **R35 / R36** local operator and peer majority cannot satisfy a production
  attestation (reload-check and peer-driven-drain surfaces).
* **R37** validation-only rejection is pure (stable repeat results; no marker
  and no sequence write).
* **R38** mutating-surface rejection produces a typed reject and no apply.
* **R39** invalid live `0x05` custody-attestation candidate is not
  propagated / staged / applied (malformed-payload fail-closed).
* **R40** MainNet peer-driven apply remains refused even with
  `MainnetProductionAttestationRequired` and a fixture attestation
  (`MainNetPeerDrivenApplyRefused` +
  `mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying`).
* **selector** unset → `Disabled`; CLI/env tags resolve; CLI-over-env
  precedence; invalid CLI/env typed errors; unrelated env stays `Disabled`;
  case-insensitive / trimmed parsing.
* **loader** legacy v2 sidecar without sibling → `Absent`; sidecar with
  sibling → `Available` with matching parts; sidecar with malformed sibling →
  `Malformed` while the ratification still parses; canonical sibling field /
  schema version; unsupported future schema version → `Malformed`; absent when
  missing or explicitly null.
* **reachability** wire round-trip digests byte-identical across repeats and
  bound to the source evidence; all seven production preflight wrappers reach
  the Run 205 verifier and accept the fixture carrier on DevNet; the
  MainNet-refusal helper returns `true` only on MainNet; the peer-driven drain
  wrapper refuses MainNet even under `MainnetProductionAttestationRequired`.

## Source/release reachability proof

The harness records `grep` call-site proof under
`reachability/source_reachability.txt` for: the module
`pqc_custody_attestation_policy_surface`; the env var
`QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY`; the hidden CLI field
`p2p_trust_bundle_custody_attestation_policy` (also recorded under
`reachability/cli_flag_reachability.txt`); the parsers
`custody_attestation_policy_from_selector`,
`custody_attestation_policy_from_cli_or_env`, and
`custody_attestation_policy_env_selector`; the seven per-surface
custody-attestation-policy preflight wrappers
`preflight_v2_marker_custody_attestation_for_*`; the
`CustodyAttestationPolicy::{Disabled, FixtureAttestationAllowed,
RemoteSignerAttestationRequired, KmsAttestationRequired, HsmAttestationRequired,
ProductionAttestationRequired, MainnetProductionAttestationRequired}` variants;
the Run 207 custody-attestation payload routing helpers; the
production/cloud-KMS/PKCS#11/HSM/RemoteSigner attestation unavailable variants;
and the MainNet attestation refusal helper.

## No-mutation / denylist proof

For every rejected custody-attestation-policy scenario the harness records
(`no_mutation_proof.txt`): no Run 070 apply call, no live trust swap, no
session eviction, no sequence write, no marker write, no `.tmp` residue, no
fallback to `--p2p-trusted-root`, and no active DummySig / DummyKem /
DummyAead. An invalid selector value fails closed with a typed parse error
**before** any custody-attestation material parse; a malformed carrier
short-circuits **before** the Run 205 verifier and **before** any
marker/sequence write, live trust swap, session eviction, or Run 070 call. The
denylist (`negative_invariants.txt`) is proven empty across all captured logs
for the forbidden-claim corpus (no MainNet apply, no autonomous apply, no
apply-on-receipt, no peer-majority authority, no real
KMS/HSM/cloud-KMS/PKCS#11/RemoteSigner backend or attestation-active claim, no
production custody attestation active, no governance execution, no real
on-chain governance proof, no validator-set rotation, no schema/wire/metric
drift, no marker-before-sequence, no marker/sequence write on validation-only
surfaces).

## Validation commands

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_210_custody_attestation_policy_release_binary_helper
bash scripts/devnet/run_210_custody_attestation_policy_release_binary.sh
cargo test -p qbind-node --test run_209_custody_attestation_policy_selector_tests
cargo test -p qbind-node --test run_207_custody_attestation_payload_callsite_tests
cargo test -p qbind-node --test run_205_custody_attestation_verifier_tests
cargo test -p qbind-node --test run_203_kms_hsm_backend_boundary_tests
cargo test -p qbind-node --lib pqc_custody_attestation_policy_surface
cargo test -p qbind-node --lib
```

The harness additionally cross-checks the broader Run 134–209 regression
target set named in `task/RUN_210_TASK.txt` (recording any target absent
from this tree as `skipped(not-present)`), and writes the canonical
`docs/devnet/run_210_custody_attestation_policy_release_binary/summary.txt`
verdict line. Observed result: the release node binary and Run 210 helper
build clean; the release helper reports `verdict: PASS` over its `selector` /
`accepted` / `rejection` / `loader` / `reachability` tables; the S1–S10
real-binary surface scenarios pass; the denylist is proven empty; and the
regression targets pass unchanged. (If a referenced test target name differs
in a future checkout, locate the nearest existing target and document the
exact command/result.)

## Why C4 / C5 remain OPEN

Run 210 only proves, in release mode, that the Run 209 hidden
custody-attestation policy selector resolves correctly, fails closed on invalid
input, and routes the selected policy into the seven Run 207 production
preflight contexts and the Run 205 verifier. It implements no real cloud-KMS /
PKCS#11 / HSM-vendor attestation verifier, no real RemoteSigner backend, no
governance execution engine, no real on-chain proof verifier, and no
validator-set rotation; the fixture attestation remains DevNet/TestNet
evidence-only and is refused on MainNet; production attestation remains
unavailable/fail-closed regardless of the selected policy; and MainNet
peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal. **Full C4
remains OPEN; C5 remains OPEN.**