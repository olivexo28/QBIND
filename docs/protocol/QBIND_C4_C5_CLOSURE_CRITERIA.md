# QBIND C4 / C5 Closure Criteria

**Status as of Run 211:** Full **C4 remains OPEN**. **C5 remains OPEN**.
This document is a formal closure checklist introduced by Run 200
(docs/spec/crosscheck only). It defines C4 and C5, records their current
status, provides a green/yellow/red matrix, enumerates the required
closure evidence, states the explicit non-closure positions, lists the
MainNet readiness gates, enumerates the negative invariants that must
hold, and states the release-binary evidence requirements.

Run 200 does **not** implement any backend and does **not** close C4 or
C5. See [`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md`](
  ../devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md) for the consolidation
report and [`docs/whitepaper/contradiction.md`](
  ../whitepaper/contradiction.md) for the canonical C4 / C5 tracking
entries (C4 = "Production `qbind-node` Binary Does Not Boot a Fully
Operating Node"; C5 = "`TimeoutCertificate` Wire Shape / production
signing + transport custody lifecycle").

## 1. Definitions

### C4 — production trust-anchor authority lifecycle

C4 covers the production `qbind-node` binary operating a fully real
trust-anchor authority lifecycle: a real production custody backend, a
real on-chain governance proof verifier, a governance execution policy,
production-authenticated MainNet lifecycle transitions
(rotate / retire / revoke / emergency-revoke) under production custody,
and the supporting recovery / rollback / sequence-replay protections,
all release-binary evidenced. C4 also encompasses the broader production
node-boot pieces tracked historically in `contradiction.md` (production
fast-sync / consensus-storage restore, production PQC KEMTLS
AEAD/lifecycle), which remain outside the authority-lifecycle scope of
Runs 130–199.

### C5 — production cryptographic key custody and signing lifecycle

C5 covers production cryptographic key custody, rotation, and the
operational signing lifecycle: a production custody backend with
attestation, no raw local production signing keys, key
rotation / revocation / emergency-revoke ceremonies, validator-set
rotation / authority-set synchronization, operational signing audit
trails, a crypto-agility activation policy, a production
incident-response runbook, and full MainNet release-binary evidence under
production custody.

## 2. Current status

| Convergence | Status | Notes |
|-------------|--------|-------|
| **C4** | ⚠️ **OPEN** | Authority-lifecycle typed boundaries, fixture/loopback evidence paths, custody/governance/RemoteSigner policy selectors, and DevNet/TestNet release-binary evidence landed (Runs 130–199). Real production custody backend, real on-chain governance proof verifier, governance execution engine, and validator-set rotation remain unavailable. |
| **C5** | ⚠️ **OPEN** | Production key custody, rotation/revocation ceremonies, hardware/remote signing attestation, operational audit trail, crypto-agility activation policy, and full MainNet release-binary evidence under production custody remain unavailable. |

## 3. Green / yellow / red matrix

**Green** = landed and accepted. **Yellow** = typed boundary / fixture /
selector / evidence path landed, but the real production backend is not
implemented. **Red** = not started / unavailable.

| Capability | State | Evidence / blocker |
|------------|-------|--------------------|
| Anti-rollback v2 authority marker | 🟢 Green | Runs 130–143 |
| Validation-only non-mutation (reload-check / local peer-candidate-check / live `0x05`) | 🟢 Green | Runs 130–177 |
| Mutating-surface ordering (`validate → swap → evict_sessions → commit_sequence`) | 🟢 Green | Run 070; preserved by Runs 130–199 |
| Peer-driven staging / apply / drain (DevNet/TestNet) | 🟢 Green | Runs 144–158 |
| MainNet peer-driven apply refusal | 🟢 Green | Runs 147 / 148 / 152 FATAL refusal |
| Authority lifecycle transition validation (typed, pure) | 🟢 Green | Runs 159–162 |
| Governance authority verifier + proof carrier + Required policy | 🟢 Green | Runs 163–177 |
| OnChainGovernance fixture verifier + production boundary (fail-closed) | 🟡 Yellow | Runs 178–187; real on-chain verifier unavailable |
| Authority custody boundary + metadata + policy selector | 🟡 Yellow | Runs 188–193; real custody backend unavailable |
| RemoteSigner boundary + payload + policy selector | 🟡 Yellow | Runs 194–199; real RemoteSigner backend unavailable |
| Real production RemoteSigner backend | 🔴 Red | Not implemented |
| Real KMS / HSM / cloud-KMS / PKCS#11 custody backend | 🔴 Red | Not implemented |
| Real custody attestation verifier | 🔴 Red | Not implemented |
| Real on-chain governance proof verifier | 🔴 Red | Not implemented |
| Governance execution engine | 🔴 Red | Not implemented |
| Validator-set rotation / authority-set synchronization | 🔴 Red | Not implemented |
| MainNet authority rotation/revocation under production custody | 🔴 Red | Not proven |
| Production signing audit trail / crypto-agility activation / incident response | 🔴 Red | Not production-real |
| Full MainNet release-binary evidence under production custody | 🔴 Red | Not produced |

## 4. Required closure evidence

### 4.1 C4 closure evidence

* Real production custody backend implemented (RemoteSigner / KMS / HSM)
  **or** an explicitly accepted, documented, approved alternative.
* Real production on-chain governance proof verifier implemented **or**
  an explicitly accepted, documented, approved alternative.
* Governance execution policy implemented (proofs gate *and* drive
  lifecycle transitions under policy).
* MainNet policy admits only production-authenticated lifecycle
  transitions; fixture / local / loopback material rejected for MainNet.
* Authority lifecycle rotate / retire / revoke / emergency-revoke proven
  under production custody.
* Rejected production lifecycle updates produce no mutation.
* Recovery / rollback / sequence-replay protections release-binary
  evidenced.
* MainNet peer-driven apply policy explicitly specified — either remains
  refused or is safely enabled under production criteria.
* Release-binary evidence covers startup, reload-check, reload-apply,
  SIGHUP, snapshot/restore, local peer-candidate-check, live `0x05`, and
  peer-driven drain/apply where applicable.

### 4.2 C5 closure evidence

* Production custody backend with attestation.
* No raw local production signing keys.
* Key rotation / revocation / emergency-revoke ceremonies, production-real
  and exercised.
* Validator-set rotation / authority-set synchronization implemented and
  exercised.
* Operational audit logs and reproducible signing evidence.
* Crypto-agility policy for future PQC algorithm changes.
* Production incident-response runbook (including key-compromise /
  emergency-revoke).
* Release-binary evidence and a negative-invariant corpus over the
  production custody / rotation / revocation paths.

## 5. Explicit non-closure statements

* **Full C4 is NOT closed.** The typed custody / governance / RemoteSigner
  boundaries, fixture/loopback evidence paths, and policy selectors do
  not constitute a real production backend.
* **C5 is NOT closed.** No production key custody, attestation, rotation
  ceremony, or full MainNet release-binary evidence under production
  custody exists.
* **Fixture / local / loopback evidence is NOT MainNet production
  authority.** It is DevNet/TestNet evidence-only.
* **Production RemoteSigner / KMS / HSM remain unavailable** and
  fail-closed.
* **MainNet peer-driven apply remains refused** (Runs 147 / 148 / 152
  FATAL refusal).
* **No real governance execution exists.**
* **No validator-set rotation exists.**

## 6. MainNet readiness gates

MainNet authority operation must not be enabled until **all** of the
following gates pass:

1. **Custody gate.** Production custody backend with attestation is
   active; no raw local production signing key is in use.
2. **Governance gate.** Real production on-chain governance proof verifier
   and a governance execution policy are active; MainNet admits only
   production-authenticated lifecycle transitions.
3. **Authority-set gate.** Validator-set rotation / authority-set
   synchronization is implemented and exercised.
4. **Lifecycle gate.** Rotate / retire / revoke / emergency-revoke are
   proven end-to-end under production custody, with rejected updates
   producing no mutation.
5. **Recovery gate.** Recovery / rollback / sequence-replay protections
   are release-binary evidenced.
6. **Apply-policy gate.** The MainNet peer-driven apply policy is
   explicitly specified; it remains refused unless every production
   criterion above is satisfied.
7. **Evidence gate.** Full MainNet release-binary evidence under
   production custody, plus the negative-invariant corpus, is produced.

Until every gate passes, MainNet peer-driven apply remains refused and no
MainNet enablement claim may be made.

## 7. Negative invariants

The following must remain true through C4 / C5 closure work; any
violation is a regression:

* Default custody / RemoteSigner selector resolution remains `Disabled`.
* Fixture / local / loopback material cannot satisfy MainNet production
  authority.
* Production custody / governance / RemoteSigner material that lacks a
  real backend fails closed.
* No marker write, no sequence write, no Run 070 apply, no live trust
  swap, and no session eviction on any rejected candidate.
* No `.tmp` residue and no fallback to `--p2p-trusted-root` on rejection.
* No DummySig / DummyKem / DummyAead activation on the production path.
* No autonomous apply, no apply-on-receipt, and no peer-majority
  authority.
* No marker / sequence-file / trust-bundle core / wire / schema change
  without an explicit, versioned, backward-compatible design.
* MainNet peer-driven apply remains refused absent a satisfied
  apply-policy gate.

## 8. Release-binary evidence requirements

* Real `target/release/qbind-node` must accept any new hidden selector /
  flag without `--help` drift and without emitting an enablement banner.
* Release-built helpers (Cargo examples) must remain dead code in the
  production runtime; production call-site wiring must be evidenced
  separately and explicitly.
* Each production-backend milestone must produce a release-binary
  evidence archive (`docs/devnet/run_NNN_*/`) and a canonical evidence
  report, covering positive acceptance and the negative-invariant corpus.
* MainNet refusal must be reasserted in every release-binary run until
  the §6 apply-policy gate is satisfied.
* Default `Disabled` resolution must be reasserted in every release-binary
  selector run.

## 9. Change log

* **Run 200** — Introduced this document. Defined C4 / C5, recorded
  current OPEN/OPEN status, the green/yellow/red matrix, required closure
  evidence, explicit non-closure statements, MainNet readiness gates,
  negative invariants, and release-binary evidence requirements.
  Docs/spec/crosscheck only; no backend implemented; C4 and C5 remain
  OPEN.
* **Run 201** — Source/test production RemoteSigner transport boundary
  (`crates/qbind-node/src/pqc_remote_signer_transport.rs`). Adds a typed
  transport identity/endpoint config, request/response envelopes wrapping
  the Run 194 RemoteSigner request/response, deterministic
  transcript-binding digests, a pure/mockable `RemoteSignerTransport`
  trait with a DevNet/TestNet-only fixture loopback transport and a
  fail-closed `ProductionRemoteSignerTransport`, and a typed outcome
  taxonomy. Advances the C4 "production RemoteSigner backend" criterion
  toward a future implementation without implementing one: no real
  RemoteSigner backend, no networked signer daemon, no production signing
  custody, no KMS/HSM, no MainNet apply. Production transport remains
  unavailable/fail-closed; MainNet peer-driven apply remains refused.
  Source/test only; release-binary transport-boundary evidence deferred to
  **Run 202**. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 202** — Release-binary evidence for the Run 201 production
  RemoteSigner transport boundary
  (`crates/qbind-node/examples/run_202_remote_signer_transport_release_binary_helper.rs`,
  `scripts/devnet/run_202_remote_signer_transport_release_binary.sh`,
  `docs/devnet/run_202_remote_signer_transport_release_binary/`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_202.md`). Proves on the real
  `target/release/qbind-node` plus a release-built helper linking the
  production library symbols that the fixture loopback transport remains
  DevNet/TestNet evidence-only, the production transport remains
  unavailable/fail-closed (including the MainNet variant), the
  request/response/transcript digests are deterministic and domain-bound,
  the transport composes with the Run 194 RemoteSigner request/response
  and the custody/RemoteSigner validation path, rejected
  transport-boundary cases produce no mutation, and MainNet peer-driven
  apply remains the Run 147 / 148 / 152 FATAL refusal. Provides the C4
  "release-binary evidence for the production RemoteSigner backend
  boundary" criterion for the transport boundary only. Release-binary
  evidence only; no production source change; no real RemoteSigner
  backend, networked signer daemon, KMS/HSM, governance execution, or
  validator-set rotation; no MainNet apply. **Full C4 remains OPEN; C5
  remains OPEN.**
* **Run 203** — Source/test KMS/HSM backend abstraction boundary
  (`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs`). Adds a
  typed, provider-neutral KMS/HSM backend abstraction: a `BackendKind`
  (`Disabled`, `FixtureKms`, `FixtureHsm`, `CloudKmsUnavailable`,
  `Pkcs11HsmUnavailable`, `ProductionKmsUnavailable`,
  `ProductionHsmUnavailable`, `Unknown`), a `BackendPolicy` (`Disabled`
  default, `FixtureKmsAllowed`, `FixtureHsmAllowed`,
  `ProductionKmsRequired`, `ProductionHsmRequired`,
  `MainnetProductionCustodyRequired`), a `BackendIdentity` config,
  `BackendRequest` / `BackendResponse`, deterministic
  identity/request/response/transcript digests, a pure/mockable
  `AuthorityCustodyBackend` trait (`sign_authority_lifecycle_request`)
  with DevNet/TestNet-only `FixtureKmsBackend` / `FixtureHsmBackend` and
  fail-closed `ProductionKmsBackend` / `ProductionHsmBackend` /
  `CloudKmsBackend` / `Pkcs11HsmBackend`, a pure verifier
  `verify_authority_custody_backend_response`, a custody-class router
  composing the Run 188 `AuthorityCustodyClass::{Kms, Hsm}` classes, and
  a `validate_lifecycle_governance_custody_and_backend` composition.
  Advances the C4 "production KMS/HSM backend" criterion toward a future
  implementation without implementing one: no real KMS backend, no real
  HSM backend, no cloud-KMS integration, no PKCS#11 integration. Fixture
  KMS/HSM are DevNet/TestNet source-test only; production / cloud /
  PKCS#11 backends remain unavailable/fail-closed; the RemoteSigner path
  (Runs 194–202) remains a separate, unchanged custody option; MainNet
  peer-driven apply remains refused. Source/test only; release-binary
  KMS/HSM backend-boundary evidence deferred to **Run 204**. **Full C4
  remains OPEN; C5 remains OPEN.**
* **Run 204** — Release-binary KMS/HSM backend-boundary evidence
  (`scripts/devnet/run_204_kms_hsm_backend_release_binary.sh`,
  `crates/qbind-node/examples/run_204_kms_hsm_backend_release_binary_helper.rs`).
  Closes the Run 203-deferred release-binary boundary: the real
  `target/release/qbind-node` keeps every existing Run 070 / 130–203
  surface KMS/HSM-backend-silent (no KMS / HSM / cloud-KMS / PKCS#11 /
  RemoteSigner backend banner, no MainNet peer-driven apply enablement),
  and a release-built helper exercises the Run 203 A1–A15 / R1–R41 corpus
  in release mode through the production library symbols
  (`pqc_authority_kms_hsm_backend::*` over `pqc_authority_custody::*`):
  fixture KMS/HSM accepted on DevNet/TestNet only; production / cloud /
  PKCS#11 backends fail-closed as unavailable; identity / request /
  response / transcript digests deterministic and domain-bound; backend
  boundary composes with the Run 188 custody classes; rejected cases
  produce no mutation; MainNet peer-driven apply remains the Run 147 FATAL
  refusal even with fixture KMS/HSM material. Release-binary evidence
  only; no production source change (helper + harness + docs); no real
  KMS/HSM / cloud-KMS / PKCS#11 / RemoteSigner backend, governance
  execution, or validator-set rotation; RemoteSigner path remains separate
  and unchanged; no MainNet apply. **Full C4 remains OPEN; C5 remains
  OPEN.**
* **Run 205** — Source/test production custody attestation verifier
  skeleton (`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`).
  Advances the C4 "production custody attestation" criterion toward a
  future implementation without implementing one: no real cloud-KMS
  attestation verifier, no real PKCS#11 attestation verifier, no real HSM
  vendor attestation verifier, no real RemoteSigner attestation verifier.
  Adds a typed `CustodyAttestationClass` / `CustodyAttestationPolicy`,
  typed `CustodyAttestationEvidence` / `CustodyAttestationInput`,
  deterministic domain-bound evidence / input / transcript /
  provider-identity digests, a pure/mockable `CustodyAttestationVerifier`
  trait with a DevNet/TestNet `FixtureCustodyAttestationVerifier` and
  fail-closed production / cloud-KMS / PKCS#11 / HSM / RemoteSigner
  verifiers, a typed `CustodyAttestationOutcome`, the pure verifier
  `verify_custody_attestation`, and composition helpers
  (`validate_custody_metadata_and_attestation` /
  `validate_lifecycle_custody_and_attestation`) layering attestation over
  the Run 188 custody validator. Fixture attestation is DevNet/TestNet
  source-test only; production / cloud / PKCS#11 / HSM-vendor /
  RemoteSigner attestation remains unavailable/fail-closed; the
  RemoteSigner path (Runs 194–202) and the KMS/HSM backend path (Runs
  203–204) remain separate, unchanged backend-boundary options; MainNet
  peer-driven apply remains refused even with a fixture attestation.
  Source/test only; release-binary custody-attestation verifier-boundary
  evidence deferred to **Run 206**. **Full C4 remains OPEN; C5 remains
  OPEN.**
* **Run 206** — Release-binary custody-attestation verifier-boundary
  evidence (`scripts/devnet/run_206_custody_attestation_release_binary.sh`,
  `crates/qbind-node/examples/run_206_custody_attestation_release_binary_helper.rs`).
  Closes the Run 205-deferred release-binary boundary: the real
  `target/release/qbind-node` keeps every existing Run 070 / 130–205
  surface custody-attestation-silent (no custody-attestation / KMS / HSM /
  cloud-KMS / PKCS#11 attestation banner, no MainNet peer-driven apply
  enablement), and a release-built helper exercises the Run 205 A1–A15 /
  R1–R40 corpus in release mode through the production library symbols
  (`pqc_custody_attestation_verifier::*` over `pqc_authority_custody::*`,
  `pqc_authority_kms_hsm_backend::*`, and the Run 201 RemoteSigner
  transport boundary): fixture custody attestation accepted on
  DevNet/TestNet only; production / cloud-KMS / PKCS#11 / HSM / RemoteSigner
  attestation verifiers fail-closed as unavailable; evidence / input /
  transcript / provider-identity digests deterministic and domain-bound;
  attestation boundary composes with the Run 188 custody classes and the
  Run 203 / Run 201 backend / RemoteSigner transport evidence; rejected
  cases produce no mutation; MainNet peer-driven apply remains the Run 147
  FATAL refusal even with fixture attestation material. Release-binary
  evidence only; no production source change (helper + harness + docs); no
  real KMS/HSM attestation / cloud-KMS / PKCS#11 / RemoteSigner backend,
  governance execution, or validator-set rotation; RemoteSigner and KMS/HSM
  remain backend-boundary only and unchanged; no MainNet apply. **Full C4
  remains OPEN; C5 remains OPEN.**
* **Run 207** — Source/test custody-attestation payload carrying and
  production preflight integration
  (`crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs`,
  `crates/qbind-node/tests/run_207_custody_attestation_payload_callsite_tests.rs`).
  Makes the Run 205 typed custody-attestation evidence/input reachable from
  production call-site contexts via an additive, optional
  `custody_attestation` sibling on the v2 ratification sidecar, wire types
  that convert into the Run 205 internal types, a typed
  `CustodyAttestationLoadStatus`, a pure sibling parser, a combined v2
  sidecar loader, a typed `CustodyAttestationCallsiteContext`, and seven
  per-surface routing helpers (reload-check, reload-apply, startup
  `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live inbound
  `0x05`, peer-driven drain) that drive the carrier into the Run 205
  `verify_custody_attestation` /
  `validate_custody_metadata_and_attestation` /
  `validate_lifecycle_custody_and_attestation` boundary. Additive/optional
  payload-context fields only; legacy/no-attestation payload compatibility
  preserved; default `CustodyAttestationPolicy::Disabled` unchanged.
  Fixture attestation is DevNet/TestNet source-test only; production /
  cloud-KMS / PKCS#11 / HSM-vendor / RemoteSigner attestation remains
  unavailable/fail-closed; the RemoteSigner path (Runs 194–202) and the
  KMS/HSM backend path (Runs 203–204) remain separate, unchanged
  backend-boundary options; a malformed carrier short-circuits before the
  verifier and before any sequence/marker write, live trust swap, session
  eviction, or Run 070 call; MainNet peer-driven apply remains the Run 147
  / 148 / 152 FATAL refusal even with a fixture attestation. Source/test
  only; no real KMS/HSM attestation / cloud-KMS / PKCS#11 / RemoteSigner
  attestation verifier or backend, governance execution, or validator-set
  rotation is implemented; release-binary custody-attestation
  payload/carrying evidence deferred to **Run 208**. **Full C4 remains
  OPEN; C5 remains OPEN.**
* **Run 208** — Release-binary evidence for the Run 207 custody-attestation
  payload carrying and production-context routing surface
  (`crates/qbind-node/examples/run_208_custody_attestation_payload_release_binary_helper.rs`,
  `scripts/devnet/run_208_custody_attestation_payload_release_binary.sh`,
  `docs/devnet/run_208_custody_attestation_payload_release_binary/`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_208.md`). Proves on the real
  `target/release/qbind-node` plus a release-built helper linking the
  production library symbols that the Run 207 typed custody-attestation
  material can be carried through the v2 ratification sidecar
  `custody_attestation` sibling and routed through the seven per-surface
  helpers into the Run 205 verifier, while the default
  `CustodyAttestationPolicy::Disabled` behavior, legacy/no-attestation
  payload compatibility, and the MainNet peer-driven-apply refusal are all
  preserved. Release-binary evidence only; no production source change
  (helper + harness + docs only). No real cloud-KMS / PKCS#11 / HSM-vendor
  attestation verifier, no real KMS/HSM backend, no real RemoteSigner
  backend, no governance execution, no real on-chain proof verifier, and no
  validator-set rotation is implemented; fixture attestation remains
  DevNet/TestNet evidence-only and is refused on MainNet; production
  attestation remains unavailable/fail-closed; MainNet peer-driven apply
  remains the Run 147 / 148 / 152 FATAL refusal even with a fixture
  attestation. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 209** — Source/test hidden custody-attestation policy selector and
  production preflight integration
  (`crates/qbind-node/src/pqc_custody_attestation_policy_surface.rs`,
  `crates/qbind-node/tests/run_209_custody_attestation_policy_selector_tests.rs`).
  Adds a hidden, disabled-by-default custody-attestation policy selector —
  one hidden clap flag `--p2p-trust-bundle-custody-attestation-policy`
  (`hide = true`) plus the env var
  `QBIND_P2P_TRUST_BUNDLE_CUSTODY_ATTESTATION_POLICY` — sharing one
  case-insensitive value grammar
  (`disabled` | `fixture-attestation-allowed` |
  `remote-signer-attestation-required` | `kms-attestation-required` |
  `hsm-attestation-required` | `production-attestation-required` |
  `mainnet-production-attestation-required`), a typed
  `CustodyAttestationPolicySelectorParseError`, the pure parsers
  `custody_attestation_policy_from_selector` /
  `custody_attestation_policy_env_selector` /
  `custody_attestation_policy_from_cli_or_env`, and seven per-surface
  preflight wrappers `preflight_v2_marker_custody_attestation_for_*` that
  bind the resolved Run 205 `CustodyAttestationPolicy` into the Run 207
  `CustodyAttestationCallsiteContext` and dispatch to the matching Run 207
  routing helper for each of the seven production v2 marker-decision
  preflight contexts (reload-check, reload-apply, startup
  `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live inbound
  `0x05`, peer-driven drain). Unset CLI/env resolves to
  `CustodyAttestationPolicy::Disabled`; CLI wins over env when both are
  set; invalid values fail closed with a typed parse error. Default
  remains `Disabled` with legacy/no-attestation payload compatibility;
  fixture attestation is DevNet/TestNet evidence-only and cannot satisfy
  MainNet production attestation; production / cloud-KMS / PKCS#11 / HSM /
  RemoteSigner attestation reaches the Run 205 verifier and fails closed as
  unavailable; the wrappers are pure (no marker/sequence write, no live
  trust swap, no session eviction, no Run 070 call); MainNet peer-driven
  apply remains the Run 147 / 148 / 152 FATAL refusal even with
  `MainnetProductionAttestationRequired` and fixture attestation.
  Source/test only; no real cloud-KMS / PKCS#11 / HSM-vendor attestation
  verifier, no real KMS/HSM backend, no real RemoteSigner backend, no
  governance execution, no real on-chain proof verifier, and no
  validator-set rotation is implemented; release-binary custody-attestation
  policy selector evidence deferred to **Run 210**. **Full C4 remains
  OPEN; C5 remains OPEN.**
* **Run 210** — Release-binary evidence for the Run 209 hidden
  custody-attestation policy selector
  (`crates/qbind-node/examples/run_210_custody_attestation_policy_release_binary_helper.rs`,
  `scripts/devnet/run_210_custody_attestation_policy_release_binary.sh`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_210.md`). Proves on the real
  `target/release/qbind-node` that `--help` hides the Run 209 selector flag
  `--p2p-trust-bundle-custody-attestation-policy` (`hide = true`), that the
  hidden CLI/env selector is accepted without enabling any production custody
  attestation, and that every Run 070 / 130–209 surface stays
  custody-attestation-silent with the MainNet peer-driven apply refusal
  preserved even with `mainnet-production-attestation-required` armed. A
  release-built helper exercises the Run 209 selector resolver
  (`custody_attestation_policy_from_selector` /
  `custody_attestation_policy_env_selector` /
  `custody_attestation_policy_from_cli_or_env`) and the seven per-surface
  preflight wrappers in release mode through the production library symbols:
  unset resolves to `Disabled`; CLI/env tags resolve; CLI-over-env precedence
  is deterministic; invalid values fail closed with typed parse errors; the
  resolved policy reaches all seven Run 207 preflight contexts; fixture
  attestation is accepted on DevNet/TestNet only where the policy allows;
  production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation reaches the
  Run 205 verifier and fails closed as unavailable; rejected cases produce no
  mutation. Release-binary evidence only; no production source change; no real
  cloud-KMS / PKCS#11 / HSM-vendor attestation verifier, no real KMS/HSM
  backend, no real RemoteSigner backend, no governance execution, no real
  on-chain proof verifier, and no validator-set rotation is implemented. The
  Run 209 CLI flag is parsed by the binary but its resolved policy is not yet
  wired into a long-running node runtime. **Full C4 remains OPEN; C5 remains
  OPEN.**
* **Run 211** — Source/test governance execution policy boundary
  (`crates/qbind-node/src/pqc_governance_execution_policy.rs`,
  `crates/qbind-node/tests/run_211_governance_execution_policy_tests.rs`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_211.md`). Adds a typed
  `GovernanceExecutionClass` (`Disabled` default / `FixtureGovernance` /
  `EmergencyCouncilFixture` / `OnChainGovernanceUnavailable` /
  `ProductionGovernanceUnavailable` / `MainnetGovernanceUnavailable` /
  `Unknown`), a typed `GovernanceExecutionPolicy` (`Disabled` default /
  `FixtureGovernanceAllowed` / `EmergencyCouncilFixtureAllowed` /
  `ProductionGovernanceRequired` / `MainnetGovernanceRequired`), a typed
  `GovernanceAction` (authority signing-key initial activation / rotate /
  retire / revoke / emergency revoke plus policy-change, custody-policy,
  remote-signer-policy, custody-attestation-policy, and validator-set-rotation
  request placeholders and unknown), typed `GovernanceExecutionInput`,
  `GovernanceExecutionDecision`, and `GovernanceExecutionExpectations`,
  deterministic domain-separated digest helpers (`input_digest`,
  `decision_digest`, `governance_execution_transcript_digest`, optional
  `governance_execution_policy_digest`), a pure/mockable
  `GovernanceExecutionEvaluator` trait with `evaluate_governance_execution_policy`,
  a DevNet/TestNet source/test-only `FixtureGovernanceExecutionEvaluator`, and
  production/on-chain/MainNet evaluators that are callable but fail closed as
  unavailable, plus a typed `GovernanceExecutionOutcome` and a
  peer-driven-apply guard. Governance execution authorizes a lifecycle action
  only when the action, candidate digest, and sequence match; emergency action
  is separate and explicit; production and MainNet governance execution remain
  unavailable/fail-closed; fixture governance is DevNet/TestNet source-test
  only and is refused on MainNet; MainNet peer-driven apply remains the Run
  147 / 148 / 152 FATAL refusal even with fixture governance approval; the
  boundary is pure (no marker/sequence write, no live trust swap, no session
  eviction, no Run 070 call); Run 163/178/205 governance / on-chain / custody
  material is bound only as opaque digests and changed in no way. Source/test
  only; no real governance execution engine, no real on-chain governance proof
  verifier, no MainNet governance, no real KMS/HSM/RemoteSigner backend, and no
  validator-set rotation is implemented; release-binary governance execution
  policy-boundary evidence deferred to **Run 212**. **Full C4 remains OPEN; C5
  remains OPEN.**