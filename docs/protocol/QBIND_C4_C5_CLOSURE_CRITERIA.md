# QBIND C4 / C5 Closure Criteria

**Status as of Run 233:** Full **C4 remains OPEN**. **C5 remains OPEN**.
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
* **Run 212** — Release-binary governance execution policy-boundary evidence
  for Run 211 (`crates/qbind-node/examples/run_212_governance_execution_policy_release_binary_helper.rs`,
  `scripts/devnet/run_212_governance_execution_policy_release_binary.sh`,
  `docs/devnet/run_212_governance_execution_policy_release_binary/`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_212.md`). Proves on the real
  `target/release/qbind-node` plus a release-built helper linking the
  production library symbols that the Run 211 governance execution policy
  corpus holds in release mode: fixture governance execution accepted on
  DevNet/TestNet only under the explicit fixture policy; emergency council
  fixture accepted only under the explicit emergency fixture policy;
  production / on-chain / MainNet governance execution unavailable/fail-closed;
  input/decision/transcript/policy digests deterministic and domain-bound; a
  lifecycle action authorized only when the action, candidate digest, and
  sequence match; validator-set rotation unsupported; rejected cases produce no
  mutation; and MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal even with a fixture governance approval. Release-binary evidence only;
  no production source change; no real governance execution engine, on-chain
  proof verifier, KMS/HSM backend, RemoteSigner backend, or validator-set
  rotation is implemented; existing custody / KMS-HSM / RemoteSigner /
  custody-attestation / governance proof paths remain compatible. **Full C4
  remains OPEN; C5 remains OPEN.**
* **Run 213** — Source/test governance-execution payload carrying and
  production-context preflight wiring for Run 211
  (`crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs`,
  `crates/qbind-node/tests/run_213_governance_execution_payload_callsite_tests.rs`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_213.md`). Makes the Run 211 typed
  governance-execution input/decision material carryable through the production
  v2 ratification sidecar via an additive optional `governance_execution`
  sibling, and routable into the seven production v2 marker-decision call-site
  contexts (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP,
  local peer-candidate-check, live inbound `0x05`, peer-driven drain) where it
  reaches the Run 211 evaluator. Preserves legacy no-governance-execution
  payload compatibility under the default `Disabled` policy; a present-but-
  malformed or required-but-absent carrier fails closed before the evaluator;
  fixture governance execution reaches and passes the production-context path on
  DevNet/TestNet only under the explicit fixture policy; production / on-chain /
  MainNet governance execution reaches the evaluator and fails closed as
  unavailable; validator-set rotation unsupported; rejected cases produce no
  mutation; and MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal even with a fixture governance approval. Source/test evidence only; no
  schema change beyond the additive optional sibling; no real governance
  execution engine, on-chain proof verifier, KMS/HSM backend, RemoteSigner
  backend, or validator-set rotation is implemented; existing custody / KMS-HSM
  / RemoteSigner / custody-attestation / governance proof paths remain
  compatible. Release-binary governance-execution payload/carrying evidence
  deferred to **Run 214**. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 214** — Release-binary governance-execution payload/carrying evidence
  for Run 213
  (`crates/qbind-node/examples/run_214_governance_execution_payload_release_binary_helper.rs`,
  `scripts/devnet/run_214_governance_execution_payload_release_binary.sh`,
  `docs/devnet/run_214_governance_execution_payload_release_binary/`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_214.md`). Proves on the real
  `target/release/qbind-node` plus a release-built helper linking the
  production library symbols that the Run 213 payload/carrying boundary holds
  end-to-end in release mode: a legacy no-governance-execution payload remains
  compatible under default `Disabled`; fixture governance execution carried
  through the production-context routing helpers reaches the Run 211 evaluator
  and is accepted on DevNet/TestNet only under the explicit fixture policy;
  production / on-chain / MainNet governance execution material reaches the
  evaluator and fails closed as unavailable; malformed/invalid material fails
  closed; input/decision/transcript/policy digests are preserved through wire
  conversion and remain deterministic and domain-bound; a carried lifecycle
  action is authorized only when the action, candidate digest, and sequence
  match; validator-set rotation unsupported; rejected cases produce no
  mutation; and MainNet peer-driven apply remains the Run 147 / 148 / 152
  FATAL refusal even with a fixture governance approval. Release-binary
  evidence only; no production source change; no real governance execution
  engine, on-chain proof verifier, KMS/HSM backend, RemoteSigner backend, or
  validator-set rotation is implemented; existing custody / KMS-HSM /
  RemoteSigner / custody-attestation / governance proof paths remain
  compatible. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 215** — Source/test hidden governance-execution policy selector and
  production preflight integration for Run 213
  (`crates/qbind-node/src/pqc_governance_execution_policy_surface.rs`,
  `crates/qbind-node/tests/run_215_governance_execution_policy_selector_tests.rs`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_215.md`). Adds a hidden,
  disabled-by-default governance-execution policy selector — one hidden clap
  flag (`--p2p-trust-bundle-governance-execution-policy`) plus the
  `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` env var, with
  deterministic CLI-over-env precedence — and seven per-surface preflight
  wrappers (`preflight_v2_marker_governance_execution_for_*`) that bind the
  resolved `GovernanceExecutionPolicy` into the Run 213 per-surface routing
  helpers for all seven production v2 marker-decision contexts (reload-check,
  reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local
  peer-candidate-check, live inbound `0x05`, peer-driven drain). When both the
  flag and env var are absent the resolved policy is
  `GovernanceExecutionPolicy::Disabled` bit-for-bit, so legacy
  no-governance-execution payloads remain compatible (Run 213); an empty /
  unknown selector value fails closed with a typed
  `GovernanceExecutionPolicySelectorParseError` rather than silently
  downgrading to `Disabled`. Fixture / emergency-council fixture governance
  execution passes only under the matching explicit policy on DevNet/TestNet
  and cannot satisfy MainNet production governance execution; production /
  on-chain / MainNet governance execution reaches the Run 211 evaluator and
  fails closed as unavailable; missing / malformed material fails closed;
  validation-only surfaces remain non-mutating and mutating rejection paths
  produce no mutation; validator-set rotation unsupported; and MainNet
  peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal even with
  `MainnetGovernanceRequired` and a fixture governance approval. The live
  inbound `0x05` runtime config does not yet thread the per-connection policy;
  the source/test wrapper exposes the injection and the limitation is
  documented (deferred to Run 216). Source/test evidence only; no schema /
  wire / authority-marker / sequence-file / trust-bundle core change; no real
  governance execution engine, on-chain proof verifier, KMS/HSM backend,
  RemoteSigner backend, or validator-set rotation is implemented; existing
  Run 192 custody / Run 198 RemoteSigner / Run 209 custody-attestation policy
  selectors remain compatible. Release-binary governance-execution-policy
  selector evidence deferred to **Run 216**. **Full C4 remains OPEN; C5
  remains OPEN.*** **Run 216** — Release-binary governance-execution policy-selector evidence (`crates/qbind-node/examples/run_216_governance_execution_policy_release_binary_helper.rs`, `scripts/devnet/run_216_governance_execution_policy_release_binary.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_216.md`). Mirrors Run 210 for the Run 215 governance-execution selector: real `target/release/qbind-node` hides but accepts `--p2p-trust-bundle-governance-execution-policy` and `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY`; the release helper proves default `GovernanceExecutionPolicy::Disabled`, CLI/env selection, deterministic CLI-over-env precedence, typed invalid-value fail-closed behavior, all seven preflight wrappers, A1–A16 accepted/compatible cases, and R1–R40 rejection/no-mutation cases. Fixture / emergency-council fixture execution remains DevNet/TestNet evidence-only and non-production; production / on-chain / MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused; existing custody / KMS-HSM / RemoteSigner / custody-attestation / governance-proof paths remain compatible. No real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 217** — Source/test governance-execution runtime policy arming wiring (`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`, `crates/qbind-node/tests/run_217_governance_execution_runtime_arming_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_217.md`). Adds the runtime-config carrier `GovernanceExecutionRuntimeArmingConfig` that resolves the Run 215 hidden selector once via `GovernanceExecutionRuntimeArmingConfig::from_cli_or_env` (calling `governance_execution_policy_from_cli_or_env`) and routes the resolved `GovernanceExecutionPolicy` into the seven runtime preflight wrappers (`preflight_{reload_check,reload_apply,startup_p2p_trust_bundle,sighup,local_peer_candidate_check,live_inbound_0x05,peer_driven_drain}`), through which the policy reaches the Run 213 routing helpers and the Run 211 evaluator. Default remains `GovernanceExecutionPolicy::Disabled` (Run 214 no-governance-execution payloads remain compatible); CLI-over-env precedence is preserved through the runtime config; invalid selectors fail closed before any runtime mutation. Fixture / emergency-council fixture execution remains DevNet/TestNet source/test only and non-production; production / on-chain / MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused even with `MainnetGovernanceRequired` and fixture approval; validation-only and mutating rejection surfaces remain non-mutating; Run 193 custody / Run 199 RemoteSigner / Run 210 custody-attestation sibling selectors remain independent and compatible. The Run 217 test target's deterministic hang in `compatibility_with_sibling_run_selectors` (a non-reentrant `env_lock` mutex self-deadlock from two `EnvGuard`s alive on one thread) was fixed test-only by scoping each env guard so only one is alive at a time; no production behavior, schema, wire, marker, or sequence changed. Source/test evidence only; no real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented. Release-binary governance-execution runtime-arming evidence deferred to **Run 218**. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 218** — Release-binary governance-execution runtime-arming evidence (`crates/qbind-node/examples/run_218_governance_execution_runtime_arming_release_binary_helper.rs`, `scripts/devnet/run_218_governance_execution_runtime_arming_release_binary.sh`, `docs/devnet/run_218_governance_execution_runtime_arming_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_218.md`). Closes the release-binary limitation Run 216 recorded by proving on real `target/release/qbind-node` plus a release-built helper that the resolved policy is consumed through the Run 217 carrier `GovernanceExecutionRuntimeArmingConfig` (`from_cli_or_env` → `arm_surface` / the seven `preflight_*` methods) and routed into the production preflight contexts. Default remains `GovernanceExecutionPolicy::Disabled`; the hidden CLI flag and env var reach runtime arming; CLI-over-env precedence is deterministic at the runtime config boundary; an invalid selector value fails closed before any runtime mutation (the binary emits the Run 217 FATAL and exits non-zero before the unrelated `--print-genesis-hash` check, with no runtime config armed). Fixture / emergency-council fixture execution remains DevNet/TestNet evidence-only and non-production; production / on-chain / MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused even with `MainnetGovernanceRequired` and fixture approval; rejected runtime-armed scenarios remain non-mutating; the live inbound `0x05` per-connection runtime-config policy threading remains the documented limitation. Run 193 custody / Run 199 RemoteSigner / Run 210 custody-attestation sibling selectors and the Run 204 KMS/HSM and Run 202 RemoteSigner transport boundaries remain compatible. Release-binary evidence only; no real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented; no weakening of Runs 070, 130–217. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 219** — Governance-execution runtime-surface gap audit and next-closure plan (`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_219.md`). Audit/spec/docs-only: maps every governance-execution runtime surface from the Run 211–218 sequence and classifies each by evidence level. Findings: the selector/policy surfaces (group A) are fully wired and real-binary evidenced; the runtime arming carrier (group B) is partially wired — `from_cli_or_env` resolution is complete and the carrier is constructed on the live path, but at every live call site the resolved outcome is discarded (`let _outcome = …`) with the payload load status hard-coded `GovernanceExecutionLoadStatus::Absent`; the payload-carrying surfaces (group C) are helper-evidenced/source-test complete but not consumed live (no sidecar emits the carrier, same wire blocker as the Run 182 on-chain hooks); of the seven runtime call sites (group D) reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP, and local peer-candidate-check are partially wired (reached, outcome discarded, carrier `Absent`) while live inbound `0x05` and peer-driven drain are helper-evidenced only (no production call site); and the compatibility surfaces (group E: governance proof Runs 171/172, OnChainGovernance Runs 178–187, custody Run 193, RemoteSigner Run 199, custody-attestation Run 210, KMS/HSM Runs 203–204, RemoteSigner transport Runs 201–202) are intentionally out of scope, independent, and unchanged. Across all seven surfaces rejection is non-mutating and MainNet peer-driven apply remains refused; the gap is consumption, not safety — no surface reaches "real-binary long-running runtime + consumed". Because long-running consumption is incomplete, the chosen next sequence is **Run 220** (source/test long-running node governance-execution runtime consumption wiring) and **Run 221** (release-binary long-running node governance-execution runtime consumption evidence); the alternate evaluator-skeleton branch is not selected. No new runtime behavior, no real governance execution engine, no real on-chain governance proof verifier, no MainNet enablement, no MainNet peer-driven apply enablement, no validator-set rotation, no KMS/HSM or RemoteSigner backend, and no schema/wire/marker/sequence/trust-bundle change is implemented. Contradiction crosscheck recorded in `docs/whitepaper/contradiction.md` (no new contradiction). **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 220** — Source/test long-running governance-execution runtime consumption wiring (`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`, `crates/qbind-node/src/main.rs`, `crates/qbind-node/src/pqc_live_trust_reload.rs`, `crates/qbind-node/tests/run_220_governance_execution_runtime_consumption_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_220.md`). Acts on the Run 219 finding: the four binary runtime hooks (reload-apply, startup `--p2p-trust-bundle`, reload-check, local peer-candidate-check) and the SIGHUP runtime hook now **consume** the selected `GovernanceExecutionPolicy` and the **real** governance-execution sidecar load status, removing the `let _outcome = arming.arm_surface(…)` discard and the hard-coded `GovernanceExecutionLoadStatus::Absent` on those surfaces. A new consumption layer (`GovernanceExecutionRuntimeConsumption::{ProceedLegacyBypass, ProceedAccepted, FailClosed}`, `consume_surface`, `consume_surface_from_optional_sidecar_value`, `governance_execution_load_status_from_optional_sidecar_value`) maps the Run 213 decision outcome to a proceed/fail-closed verdict; on rejection the call site fails closed before any mutation via `MutatingSurfaceMarkerV2Error::Conflict(MalformedOrUnsupportedMarkerRejected)`. Default remains `GovernanceExecutionPolicy::Disabled` and the Disabled + absent-carrier path maps to `ProceedLegacyBypass`, proceeding bit-for-bit as before Run 217 (Run 214 compatibility); CLI-over-env precedence is preserved; invalid selectors fail closed before any runtime mutation. Fixture / emergency-council fixture execution remains DevNet/TestNet source/test only and non-production; production / on-chain / MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused even with `MainnetGovernanceRequired` and fixture approval; validation-only and mutating rejection surfaces remain non-mutating; Run 193 custody / Run 199 RemoteSigner / Run 210 custody-attestation sibling selectors remain independent and compatible. Honest limitation deferred to **Run 221**: binary/SIGHUP candidate metadata carries no governance proposal/decision bindings, so a present carrier at the binary surface reaches the Run 211 evaluator and fails closed on the expectation mismatch; the live inbound `0x05` per-connection policy is still not threaded; full positive binary acceptance and release-binary runtime-consumption evidence are deferred to Run 221. Source/test evidence only; no real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented; no weakening of Runs 070, 130–219. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 221** — Release-binary long-running governance-execution runtime-consumption evidence (`crates/qbind-node/examples/run_221_governance_execution_runtime_consumption_release_binary_helper.rs`, `scripts/devnet/run_221_governance_execution_runtime_consumption_release_binary.sh`, `docs/devnet/run_221_governance_execution_runtime_consumption_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_221.md`). Closes the release-binary limitation Run 220 recorded by proving on real `target/release/qbind-node` plus a release-built helper that the Run 220 consumption layer (`GovernanceExecutionRuntimeConsumption::{ProceedLegacyBypass, ProceedAccepted, FailClosed}`, `consume_surface`, `consume_surface_from_optional_sidecar_value`, `governance_execution_load_status_from_optional_sidecar_value`) gates the long-running path: the consumed outcome proceeds on the Run 214 legacy bypass (Disabled + absent carrier), fails closed before any mutation on a rejected verdict, and reads the **real** governance-execution sidecar load status from the optional sidecar value rather than a forced `Absent` where representable. Default remains `GovernanceExecutionPolicy::Disabled`; the hidden CLI flag and env var reach runtime consumption; CLI-over-env precedence is deterministic at the runtime config boundary; an invalid CLI or env selector value fails closed before any runtime mutation (the binary emits the Run 217 FATAL and exits non-zero before the unrelated `--print-genesis-hash` check, with no runtime config armed). Fixture / emergency-council fixture execution remains DevNet/TestNet evidence-only and non-production; production / on-chain / MainNet governance execution remains unavailable/fail-closed; MainNet peer-driven apply remains refused even with `MainnetGovernanceRequired` and fixture approval; rejected runtime-consumed scenarios remain non-mutating; the live inbound `0x05` per-connection runtime-config policy threading remains the documented limitation. Run 193 custody / Run 199 RemoteSigner / Run 210 custody-attestation sibling selectors and the Run 204 KMS/HSM and Run 202 RemoteSigner transport boundaries remain compatible. Release-binary evidence only; no real governance execution engine, on-chain verifier, KMS/HSM backend, RemoteSigner backend, or validator-set rotation is implemented; no weakening of Runs 070, 130–220. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 222** — Source/test production governance execution evaluator interface boundary (`crates/qbind-node/src/pqc_governance_execution_evaluator.rs`, `crates/qbind-node/tests/run_222_governance_execution_evaluator_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_222.md`). Acts on the Run 219 finding that, although the runtime now consumes governance-execution policy and payload status (Runs 211–221), the production governance execution evaluator was still only a boundary/fixture concept with no typed interface. Run 222 adds the typed `ProductionGovernanceExecutionEvaluator` trait (`evaluate_governance_decision_source` / `verify_governance_evaluator_response`), the `EvaluatorSourceKind::{Disabled, FixtureDecisionSource, EmergencyCouncilFixtureSource, OnChainDecisionSourceUnavailable, ProductionDecisionSourceUnavailable, MainnetDecisionSourceUnavailable, Unknown}` and `EvaluatorPolicy::{Disabled, FixtureDecisionSourceAllowed, EmergencyCouncilFixtureSourceAllowed, ProductionDecisionSourceRequired, MainnetDecisionSourceRequired}` selectors, the `DecisionSourceIdentity` / `EvaluatorRequest` / `EvaluatorResponse` typed records, deterministic domain-separated digest helpers (`source_identity_digest`, `request_digest`, `response_digest`, `evaluator_transcript_digest`), and a typed `EvaluatorOutcome` distinguishing every accept/reject case (fixture / emergency acceptance, response authorization, evaluator-disabled, production / on-chain / MainNet unavailable, every trust-domain / proposal / decision / lifecycle / candidate / sequence / epoch / proof-digest binding mismatch, expired / stale-replayed decision, quorum insufficiency, emergency-action authorization, validator-set-rotation / policy-change unsupported, malformed source identity / request / response, unsupported evaluator version, invalid response commitment, and the local-operator / peer-majority cannot-satisfy fail-closed helpers). The interface models how a future governance engine supplies decisions from a decision source, validates provenance, tracks replay, checks proposal/decision state, and returns fail-closed production outcomes, and composes with the Run 211 governance-execution input/decision types, the Run 213 payload material, and the Run 220 runtime consumption as a *future* production evaluator target **without changing runtime behaviour** (the `Disabled` evaluator policy is inert). No real governance execution engine and no real on-chain governance proof verifier is implemented; the fixture evaluator is DevNet/TestNet source/test only; the emergency fixture evaluator is explicit and non-production; production / on-chain / MainNet evaluators are callable but fail closed as unavailable; MainNet peer-driven apply remains refused even with fixture approval; validator-set rotation remains unsupported; KMS/HSM/RemoteSigner/custody-attestation remain boundary-only. Validation-only and mutating rejection paths remain non-mutating (the module has no mutation API). Release-binary evaluator-interface evidence is deferred to **Run 223**. Source/test evidence only; no weakening of Runs 070, 130–221. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 223** — Release-binary governance-execution evaluator-interface evidence for Run 222 (`crates/qbind-node/examples/run_223_governance_execution_evaluator_release_binary_helper.rs`, `scripts/devnet/run_223_governance_execution_evaluator_release_binary.sh`, `docs/devnet/run_223_governance_execution_evaluator_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_223.md`). Closes the release-binary limitation Run 222 recorded by proving on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`ProductionGovernanceExecutionEvaluator`, `EvaluatorSourceKind` / `EvaluatorPolicy`, `DecisionSourceIdentity` / `EvaluatorRequest` / `EvaluatorResponse`, the deterministic `source_identity_digest` / `request_digest` / `response_digest` / `evaluator_transcript_digest` helpers, the typed `EvaluatorOutcome` / `EvaluatorComposedOutcome`, and `evaluate_governance_evaluator_with_peer_driven_guard`) that the release-built code exposes and exercises the interface: the digests are stable and field-binding in release mode; the fixture evaluator accepts only DevNet/TestNet decision sources under the explicit `FixtureDecisionSourceAllowed` policy; the emergency-council fixture evaluator accepts only an explicit emergency decision under the explicit `EmergencyCouncilFixtureSourceAllowed` policy; an evaluator response authorizes a lifecycle action only when the authorized action, candidate digest, and sequence all match; the production / on-chain / MainNet evaluators are callable but return the typed unavailable / fail-closed outcome; the `Disabled` evaluator policy stays inert so the Run 221 runtime-consumption behaviour is unchanged; and the peer-driven guard preserves the MainNet peer-driven apply refusal even when a fixture evaluator would otherwise approve. The release helper records 111 typed checks across accepted (49) / rejection (42) / reachability (20) covering the full A1–A18 / R1–R40 matrix, and the harness drives the real release binary to prove `--help` exposes no evaluator-interface surface and the default DevNet/TestNet/MainNet surfaces make no evaluator / production-governance / MainNet-governance / on-chain-verifier / validator-set-rotation / KMS-HSM / RemoteSigner / autonomous-apply / apply-on-receipt / peer-majority / MainNet-peer-driven-apply enablement claim (22 forbidden patterns proven empty). No real governance execution engine and no real on-chain governance proof verifier is implemented; the fixture evaluator remains DevNet/TestNet evidence-only; the emergency fixture evaluator is explicit and non-production; production / on-chain / MainNet evaluators remain unavailable/fail-closed; MainNet peer-driven apply remains refused; validator-set rotation remains unsupported; KMS/HSM/RemoteSigner/custody-attestation remain boundary-only. Release-binary evidence only; no weakening of Runs 070, 130–222. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 224** — Source/test governance evaluator runtime integration (`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`, `crates/qbind-node/tests/run_224_governance_evaluator_runtime_integration_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_224.md`). Acts on the Run 223 finding that runtime consumption (Runs 220–221) and the typed evaluator interface (Runs 222–223) were both proven but the evaluator interface was not yet integrated as the production evaluation target inside the governance-execution runtime-consumption pipeline. Run 224 adds a pure integration layer that composes the Run 220 runtime consumption (`GovernanceExecutionRuntimeConsumption` / `consume_surface`), the Run 222 evaluator request/response/interface (`ProductionGovernanceExecutionEvaluator`, `EvaluatorRequest`, `EvaluatorResponse`, `EvaluatorOutcome`), the Run 211 governance execution decision validation (`GovernanceExecutionInput` / `Decision` / `Expectations`, `GovernanceAction`), and the Run 213 payload material (the evaluator request's `governance_execution_input_digest` carries the Run 211 input digest the Run 213 carrier transports). The typed `GovernanceEvaluatorRuntimeIntegrationOutcome` distinguishes `ProceedLegacyBypass` (disabled arming with an absent carrier), `ProceedMutate` (runtime consumption accepted **and** the evaluator authorized the same lifecycle action / candidate digest / authority-domain sequence — the only mutation-authorizing outcome, a precondition for the existing ordered mutating path rather than a mutation itself), `RuntimeConsumptionFailClosed`, `EvaluatorRejected`, and `MainNetPeerDrivenApplyRefused`. The integration preserves the required ordering (selector resolution → load-status derivation → runtime consumption → evaluator request construction → evaluator evaluation → governance execution decision validation → mutation only after all required checks pass) so the evaluator evaluation happens before any mutation authorization, and mutation authorization is produced only when both stages agree. Every rejection is non-mutating (no Run 070 call, no live trust swap, no session eviction, no sequence write, no marker write); the integration module exposes no mutation API. No real governance execution engine and no real on-chain governance proof verifier is implemented; the fixture evaluator remains DevNet/TestNet source-test only; the emergency fixture evaluator is explicit and non-production; production / on-chain / MainNet evaluators are callable but fail closed as unavailable; MainNet peer-driven apply remains refused even with fixture approval; validator-set rotation remains unsupported; KMS/HSM/RemoteSigner/custody-attestation remain boundary-only. Validation: `cargo build -p qbind-node --lib` PASS; run_224 (48), run_222 (60), run_220 (30), run_217 (45), run_215 (55), run_213 (61), run_211 (55), `--lib pqc_authority` (164), and `--lib` (1350) all PASS. Release-binary evidence is deferred to **Run 225**. Source/test evidence only; no weakening of Runs 070, 130–223. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 225** — Release-binary governance evaluator runtime integration evidence (`crates/qbind-node/examples/run_225_governance_evaluator_runtime_integration_release_binary_helper.rs`, `scripts/devnet/run_225_governance_evaluator_runtime_integration_release_binary.sh`, `docs/devnet/run_225_governance_evaluator_runtime_integration_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_225.md`). Closes the release-binary limitation Run 224 recorded: the release-built helper drives the full A1–A15 / R1–R30 matrix through the production `pqc_governance_execution_evaluator_runtime_integration` symbols (`integrate_governance_evaluator_runtime_consumption` / `..._from_optional_sidecar_value`, `GovernanceEvaluatorRuntimeIntegrationContext`, the typed `GovernanceEvaluatorRuntimeIntegrationOutcome`), proving in release mode that runtime consumption composes with the evaluator interface, the request/response binding is deterministic and field-checked, `ProceedMutate` is produced only when both the Run 220 runtime-consumption stage and the Run 222 evaluator stage agree (after the required ordering), the default `ProceedLegacyBypass` is preserved, production/on-chain/MainNet evaluators are reached and fail closed as unavailable, and MainNet peer-driven apply remains refused. The harness drives the real `target/release/qbind-node` to prove `--help` exposes no integration surface and the default DevNet/TestNet/MainNet surfaces make no integration / governance-execution / MainNet-governance / on-chain-verifier / validator-set-rotation / KMS-HSM / RemoteSigner / autonomous-apply / apply-on-receipt / peer-majority / MainNet-peer-driven-apply enablement claim (24 forbidden patterns proven empty). Validation: release helper corpus `pass=112`, `fail=0`; run_224 (48), run_222 (60), run_220 (30), run_217 (45), run_215 (55), run_213 (61), run_211 (55), `--lib pqc_authority`, and `--lib` all PASS. No real governance execution engine, on-chain proof verifier, KMS/HSM/RemoteSigner backend, MainNet governance enablement, or validator-set rotation; the integration layer is a pure typed composition surface; existing Run 221 and Run 223 release behaviour remains compatible; no weakening of Runs 070, 130–224. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 226** — Source/test governance evaluator runtime call-site wiring (`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs` call-site entry points, `crates/qbind-node/src/main.rs`, `crates/qbind-node/src/pqc_live_trust_reload.rs`, `crates/qbind-node/tests/run_226_governance_evaluator_runtime_callsite_wiring_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_226.md`). Closes the call-site wiring gap Runs 224–225 recorded: where Run 224 landed the pure integration layer and Run 225 proved it in release mode, the Run 220 runtime call sites (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live inbound `0x05`, peer-driven drain) still called the Run 220 `consume_surface` path directly. Run 226 adds the call-site wiring entry points (`wire_governance_evaluator_runtime_callsite` and `wire_governance_evaluator_runtime_callsite_without_evaluator_context`) and routes the representable call sites (`consume_run_220_governance_execution_runtime_outcome`, `consume_run_220_sighup_governance_execution_marker_decision`) through the integration layer so the typed `GovernanceEvaluatorRuntimeIntegrationOutcome` — not the bare runtime consumption — gates each call site. The default Disabled + absent-carrier `ProceedLegacyBypass` is preserved; any present carrier at the binary call sites fails closed (production unavailable or runtime-consumption rejection), strictly stricter than the Run 220 behaviour it replaces; rejections are non-mutating (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write). The binary marker/candidate metadata cannot yet carry a governance proposal/decision evaluator binding, so the live inbound `0x05` and peer-driven drain surfaces are wired at the source/test level but their full positive evaluator binding is not yet representable from the binary (documented honestly; deferred to Run 227). Production/on-chain/MainNet evaluators remain unavailable/fail-closed; fixture evaluator DevNet/TestNet source-test only; emergency fixture explicit and non-production; MainNet peer-driven apply remains refused; validator-set rotation remains unsupported; no real governance engine or on-chain proof verifier. Validation: `cargo build -p qbind-node --lib` and `--bin qbind-node` PASS; run_226 (59), run_224 (48), run_222 (60), run_220 (30), run_217 (45), run_215 (55), run_213 (55), run_211 (45), `--lib pqc_authority` (164), and `--lib` all PASS. Release-binary call-site wiring evidence is deferred to **Run 227**. Source/test evidence only; no weakening of Runs 070, 130–225. **Full C4 remains OPEN; C5 remains OPEN.*** **Run 227** — Release-binary governance evaluator runtime call-site wiring evidence (`crates/qbind-node/examples/run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper.rs`, `scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh`, `docs/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_227.md`). Closes the release-binary limitation Run 226 recorded: where Run 226 wired the representable Run 220 runtime call sites through the Run 224 integration layer at the source/test level, Run 227 proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`wire_governance_evaluator_runtime_callsite` / `wire_governance_evaluator_runtime_callsite_without_evaluator_context`, the typed `GovernanceEvaluatorRuntimeCallsiteFailClosed`, and the `Result<GovernanceEvaluatorRuntimeIntegrationOutcome, _>` discipline) that the release-built code exposes and exercises the Run 226 wiring. The release helper records 144 typed checks across accepted (71) / rejection (46) / reachability (27) covering an A1–A23 / R1–R31 matrix in release mode: the representable call sites consume the `GovernanceEvaluatorRuntimeIntegrationOutcome` (consumed, not discarded — `Ok`/`Err` derived from the outcome's proceed/fail discipline), the call-site wiring outcome equals the underlying Run 224 integration outcome, the default Disabled + absent-carrier `ProceedLegacyBypass` is preserved at every wired call site (including the `without_evaluator_context` entry point for all governance execution runtime surfaces on DevNet), a present carrier without evaluator context fails closed, production/on-chain/MainNet evaluators are reached and fail-closed as unavailable, and MainNet peer-driven apply remains refused. The harness drives the real release binary to prove `--help` and the default surfaces make no call-site wiring claims, a hidden governance-execution selector still parses, and an invalid governance-execution selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a 26-pattern denylist is proven empty. The binary marker/candidate metadata cannot yet carry a governance proposal/decision evaluator binding, so the live inbound `0x05` and peer-driven drain surfaces remain wired but not fully representable from the binary (documented honestly). Validation: release helper corpus `pass=144`, `fail=0`; release builds of `--bin qbind-node` and the Run 227 example PASS; run_226 (59), run_224 (48), run_222 (60), run_220 (30), run_217 (45), run_215 (55), run_213 (55), run_211 (45), `--lib pqc_authority`, and `--lib` all PASS. No real governance execution engine, on-chain proof verifier, KMS/HSM backend, RemoteSigner backend, MainNet governance enablement, or validator-set rotation; no production source behavior change; existing Run 221/223/225 release behaviour remains compatible; no weakening of Runs 070, 130–226. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 228** — Source/test peer evaluator-context representation boundary for live inbound `0x05` and peer-driven drain (`crates/qbind-node/src/pqc_governance_evaluator_peer_context.rs`, `crates/qbind-node/src/lib.rs` registration, `crates/qbind-node/tests/run_228_peer_evaluator_context_representation_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_228.md`). Closes the representability gap Run 226 recorded: where Run 226 wired the representable Run 220 runtime call sites through the Run 224 integration layer but documented that live inbound `0x05` and peer-driven drain could not yet carry a full positive evaluator binding, Run 228 adds a typed evaluator-context representation boundary that lets these surfaces carry or reference an evaluator context in source/test plumbing where representable and routes it into the Run 226 call-site wiring → Run 224 integration layer → Run 222 evaluator interface. The boundary is local/source-test only and changes no wire/schema/marker/sequence/trust-bundle format. The carrier taxonomy (`Absent`, `Present`, `Malformed`, `UnsupportedSurface`, `WireSchemaUnavailable`, `PeerMajorityUnsupported`, `MainNetRefused`) makes the live-wire path that cannot carry an evaluator binding a typed `WireSchemaUnavailable` fail-closed status — never an approval. The default Disabled + absent-carrier path preserves legacy validation; a present well-formed context routes through the integration layer; any unsupported/malformed/no-carrier status under an explicit evaluator policy is typed fail-closed; only the routed `ProceedMutate` outcome authorizes apply. Invalid live inbound `0x05` candidates are not propagated, staged, or applied; invalid peer-driven drain candidates are not applied; all rejections are non-mutating (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write). MainNet peer-driven apply remains refused; production/on-chain/MainNet evaluators remain unavailable/fail-closed; fixture/emergency fixture evaluators remain non-production; validator-set rotation remains unsupported; no real governance engine or on-chain proof verifier. Validation: `cargo build -p qbind-node --lib` and `--bin qbind-node` PASS; run_228 (48), run_226 (59), run_224 (48), run_222 (60), run_220 (30), run_217 (45), run_215 (55), run_213 (55), run_211 (45), run_157 (16), run_152 (20), run_150 (19), run_148 (23), run_142 (16), `--lib pqc_authority` (164), and `--lib` all PASS. Release-binary evidence is deferred to **Run 229**. Source/test evidence only; no weakening of Runs 070, 130–227. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 229** — Release-binary peer evaluator-context representation evidence (`crates/qbind-node/examples/run_229_peer_evaluator_context_representation_release_binary_helper.rs`, `scripts/devnet/run_229_peer_evaluator_context_representation_release_binary.sh`, `docs/devnet/run_229_peer_evaluator_context_representation_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_229.md`). Closes the release-binary limitation Run 228 recorded: where Run 228 landed the peer evaluator-context representation boundary at the source/test level, Run 229 proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`GovernanceEvaluatorPeerContext`, `evaluate_peer_evaluator_context`, `evaluate_peer_evaluator_context_wire_only`, the full carrier taxonomy `Absent`/`Present`/`Malformed`/`UnsupportedSurface`/`WireSchemaUnavailable`/`PeerMajorityUnsupported`/`MainNetRefused`, and the `PeerEvaluatorContextOutcome` taxonomy) that the release-built code exposes and exercises the Run 228 representation boundary. The release helper records 170 typed checks across accepted (77) / rejection (58) / reachability (35) covering an A1–A18 / R1–R27 matrix in release mode: the default Disabled + absent-carrier path preserves legacy validation, a `Present` DevNet/TestNet fixture context binds selected policy / candidate digest / evaluator request+response digests / lifecycle action / sequence / environment / chain id / genesis hash and routes through the Run 226 call-site wiring into the Run 224 integration reaching `RoutedProceedMutate` where representable, missing/unsupported/malformed carrier under an explicit evaluator policy is typed fail-closed, `WireSchemaUnavailable` is fail-closed and never an approval, invalid live inbound `0x05` is not propagated/staged/applied, invalid peer-driven drain is not applied, production/on-chain/MainNet evaluators are reached and fail-closed as unavailable, and MainNet peer-driven apply remains refused. The harness drives the real release binary to prove `--help` and the default surfaces make no peer evaluator-context claims, a hidden governance-execution selector still parses, and an invalid governance-execution selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a 26-pattern denylist is proven empty. Validation: release helper corpus `pass=170`, `fail=0`; release builds of `--bin qbind-node` and the Run 229 example PASS; run_228 (48), run_226 (59), run_224 (48), run_222 (60), run_220 (30), run_217 (45), run_215 (55), run_213 (55), run_211 (45), run_157 (16), run_152 (20), run_150 (19), run_148 (23), run_142 (16), `--lib pqc_authority`, and `--lib` all PASS. No real governance execution engine, on-chain proof verifier, KMS/HSM backend, RemoteSigner backend, MainNet governance enablement, or validator-set rotation; no production source behavior change; existing Run 227/225/223 release behaviour remains compatible; no weakening of Runs 070, 130–228. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 230** — Source/test governance evaluator replay and freshness state boundary (`crates/qbind-node/src/pqc_governance_evaluator_replay_state.rs`, `crates/qbind-node/src/lib.rs` registration, `crates/qbind-node/tests/run_230_governance_evaluator_replay_state_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_230.md`). Closes the production-governance gap Run 229 recorded: evaluator requests/responses bind a replay nonce, freshness window, and expiry, but there was not yet a typed state boundary that decides whether an evaluator decision is fresh, expired, stale, replayed, superseded, or already consumed before any mutation. Run 230 adds a typed pure fail-closed replay/freshness state boundary that distinguishes `Fresh` / `FreshButNotYetEffective` / `Expired` / `Stale` / `ReplayDetected` / `AlreadyConsumed` / `Superseded` / wrong-binding (`WrongEpoch` / `WrongEnvironment` / `WrongChain` / `WrongGenesis` / `WrongSurface` / `MalformedState`) / unavailable (`StateUnavailable` / `ProductionStateUnavailable` / `MainNetStateUnavailable`) states and maps them to a typed outcome where only `ProceedFresh` authorizes mutation and `ProceedDeferred` is not an approval. It adds deterministic digest helpers (replay state key / observation / consumed decision / freshness transcript), the `GovernanceEvaluatorReplayStateReader`/`Writer` boundary traits, a DevNet/TestNet in-memory `FixtureReplayStateStore` that records a consumed decision only on an explicit consume call (read-only validation never consumes), and callable-but-unavailable `ProductionReplayStateReader`/`MainnetReplayStateReader`. The boundary composes the Run 222 evaluator request/response/identity digests and the Run 211 lifecycle action / candidate / sequence binding, and the Run 224 integration and Run 228 peer context remain compatible when the replay state policy is Disabled / not wired. No real governance engine or on-chain proof verifier and no RocksDB/file/schema/migration/storage-format/marker/sequence/wire/trust-bundle change is introduced; the boundary is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write) so every rejection is non-mutating; MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation and policy-change actions remain unsupported. Validation: `cargo build -p qbind-node --lib` PASS; run_230 (52), run_228 (48), run_226 (59), run_224 (48), run_222 (60), run_220 (30), `--lib pqc_authority` (164), and `--lib` (1353) all PASS. Release-binary replay/freshness evidence is deferred to **Run 231**. Source/test evidence only; no weakening of Runs 070, 130–229. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 231** — Release-binary governance evaluator replay/freshness state evidence (`crates/qbind-node/examples/run_231_governance_evaluator_replay_state_release_binary_helper.rs`, `scripts/devnet/run_231_governance_evaluator_replay_state_release_binary.sh`, `docs/devnet/run_231_governance_evaluator_replay_state_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_231.md`). Closes the release-binary limitation Run 230 recorded: where Run 230 landed the governance evaluator replay/freshness state boundary at the source/test level, Run 231 proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`classify_evaluator_replay_freshness`, `evaluate_evaluator_replay_freshness`, `gate_evaluator_replay_freshness`, the `ReplayFreshnessState` and `EvaluatorReplayFreshnessOutcome` taxonomies, the deterministic digest helpers, the `GovernanceEvaluatorReplayStateReader`/`Writer` boundary traits, the `FixtureReplayStateStore`, and the callable-but-unavailable `ProductionReplayStateReader`/`MainnetReplayStateReader`) that the release-built code exposes and exercises the Run 230 replay/freshness state boundary. The release helper records 207 typed checks across accepted / rejection / reachability in release mode: only `ProceedFresh` authorizes a mutation; fresh, not-yet-effective (deferred), expired, stale, replayed, already-consumed, superseded, wrong-binding (`WrongEpoch`/`WrongEnvironment`/`WrongChain`/`WrongGenesis`/`WrongSurface`/`MalformedState`), and unavailable (`StateUnavailable`/`ProductionStateUnavailable`/`MainNetStateUnavailable`) outcomes are distinguished and every non-`ProceedFresh` outcome is non-mutating; the DevNet/TestNet `FixtureReplayStateStore` records a consumed decision only on an explicit consume call while read-only validation never consumes; and the production/MainNet replay-state readers remain callable-but-unavailable/fail-closed. The harness drives the real release binary to prove the default surfaces make no replay/freshness state claims and an invalid governance-execution selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist is proven empty. Validation: release helper corpus `pass=207`, `fail=0`; release builds of `--bin qbind-node` and the Run 231 example PASS; run_230 (52), run_228 (48), run_226 (59), run_224 (48), run_222 (60), run_220 (30), run_217 (45), run_215 (55), run_213 (55), run_211 (45), run_157 (16), run_152 (20), run_150 (19), run_148 (23), run_142 (16), `--lib pqc_authority`, and `--lib` all PASS. No real governance execution engine, on-chain proof verifier, KMS/HSM backend, RemoteSigner backend, MainNet governance enablement, or validator-set rotation; no production source behavior change; existing Run 229/227/225/223 release behaviour remains compatible; no weakening of Runs 070, 130–230. **Full C4 remains OPEN; C5 remains OPEN.*** **Run 232** — Source/test governance evaluator replay/freshness runtime integration (`crates/qbind-node/src/pqc_governance_evaluator_replay_runtime_integration.rs`, `crates/qbind-node/src/lib.rs` registration, `crates/qbind-node/tests/run_232_governance_evaluator_replay_runtime_integration_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_232.md`). Closes the integration gap Run 231 recorded: the Run 230 replay/freshness state boundary was proven (and release-evidenced in Run 231) as a standalone module but was not yet integrated into the evaluator runtime integration path as a mandatory pre-mutation gate. Run 232 adds a pure integration layer (`integrate_governance_evaluator_replay_runtime`) that composes the Run 224 evaluator-runtime integration, the Run 226 runtime call-site wiring, the Run 228 peer evaluator context (where relevant), and the Run 230 replay/freshness state boundary so the runtime integration path calls replay/freshness validation **before any mutation authorization**. The typed `GovernanceEvaluatorReplayRuntimeOutcome` distinguishes `ProceedLegacyBypass`, `ProceedDeferred`, `ProceedFresh` (the only mutation-authorizing outcome, produced only after the Run 224 layer authorized a mutate **and** the Run 230 state classified the decision fresh), `ReplayFreshnessFailClosed`, `RuntimeIntegrationFailClosed`, and `MainNetPeerDrivenApplyRefused`. Ordering is enforced: selector resolution → sidecar/load-status → runtime consumption → evaluator request → evaluator evaluation → governance execution decision validation → replay/freshness validation → lifecycle/governance/custody/custody-attestation checks → mutation authorization only after replay/freshness returns fresh. `ProceedDeferred` is not approval; expired/stale/replayed/consumed/superseded/wrong-binding/unavailable replay states fail closed before mutation. The integration is pure (no Run 070 call, no live trust swap, no session eviction, no sequence/marker write) and never marks a decision consumed; read-only validation does not consume; explicit consume remains fixture-only and is performed by the caller after a fresh authorization. Fixture replay state remains DevNet/TestNet source-test only; production/MainNet replay state remains unavailable/fail-closed; MainNet peer-driven apply remains refused even when state is fresh; validator-set rotation and policy-change actions remain unsupported. No RocksDB/file/schema/migration/storage-format change and no wire/schema/marker/sequence/trust-bundle change is implemented. Validation: `cargo build -p qbind-node --lib` PASS; run_232 (47), run_230 (52), run_228 (48), run_226 (59), run_224 (48), run_222 (60), run_220 (30), `--lib pqc_authority` (164), and `--lib` (1355) all PASS. Release-binary replay/freshness runtime-integration evidence is deferred to **Run 233**. Source/test evidence only; no weakening of Runs 070, 130–231. **Full C4 remains OPEN; C5 remains OPEN.**
* **Run 233** — Release-binary governance evaluator replay/freshness runtime integration evidence (`crates/qbind-node/examples/run_233_governance_evaluator_replay_runtime_integration_release_binary_helper.rs`, `scripts/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary.sh`, `docs/devnet/run_233_governance_evaluator_replay_runtime_integration_release_binary/`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_233.md`). Closes the release-binary limitation Run 232 recorded: where Run 232 landed the governance evaluator replay/freshness runtime integration at the source/test level, Run 233 proves on real `target/release/qbind-node` plus a release-built helper using the production library symbols (`integrate_governance_evaluator_replay_runtime`, `wire_governance_evaluator_replay_runtime_callsite`, `wire_governance_evaluator_replay_runtime_peer_context`, the `GovernanceEvaluatorReplayRuntimeOutcome` taxonomy `ProceedLegacyBypass`/`ProceedDeferred`/`ProceedFresh`/`ReplayFreshnessFailClosed`/`RuntimeIntegrationFailClosed`/`MainNetPeerDrivenApplyRefused`, and the invariant guard functions) that the release-built code exposes and exercises the Run 232 composed runtime integration. The release helper records 184 typed checks across accepted (A1–A17) / rejection (R1–R27) / reachability in release mode: only `ProceedFresh` authorizes a mutation, and only after the Run 224 layer authorized a mutate and the Run 230 replay/freshness state classified the decision fresh; `ProceedDeferred` is not approval; expired, stale, replayed, already-consumed, superseded, wrong-binding, malformed, and unavailable replay states fail closed before mutation and every non-`ProceedFresh` outcome is non-mutating; read-only validation never consumes; explicit consume remains fixture-only; and the production/MainNet replay-state readers remain callable-but-unavailable/fail-closed. The harness drives the real release binary to prove the default surfaces make no replay-runtime claims and an invalid governance-execution selector fails closed before mutation (no marker/sequence write, no live trust swap, no session eviction, no Run 070 call); a denylist is proven empty. Validation: release helper corpus `pass=184`, `fail=0`; release builds of `--bin qbind-node` and the Run 233 example PASS; run_232, run_230, run_228, run_226, run_224, run_222, run_220, run_217, run_215, run_213, run_211, run_157, run_152, run_150, run_148, run_142, `--lib pqc_authority`, and `--lib` all PASS. No real governance execution engine, on-chain proof verifier, KMS/HSM backend, RemoteSigner backend, MainNet governance enablement, or validator-set rotation; no production source behavior change; existing Run 231/229/227/225/223 release behaviour remains compatible; no weakening of Runs 070, 130–232. **Full C4 remains OPEN; C5 remains OPEN.**