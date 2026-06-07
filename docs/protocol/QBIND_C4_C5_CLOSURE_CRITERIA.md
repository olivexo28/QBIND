# QBIND C4 / C5 Closure Criteria

**Status as of Run 204:** Full **C4 remains OPEN**. **C5 remains OPEN**.
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