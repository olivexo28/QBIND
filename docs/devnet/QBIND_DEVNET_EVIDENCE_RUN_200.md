# QBIND DevNet evidence — Run 200

**Title.** Authority lifecycle C4/C5 consolidation, closure criteria, and
remaining-work specification (docs/spec/crosscheck only).

**Status.** PASS (documentation/specification/crosscheck). Run 200 is a
consolidation and specification pass over Runs 130–199. It defines
exactly what has been closed, exactly why full C4 remains open, exactly
why C5 remains open, the minimum criteria that must be met before C4 and
C5 can be closed, and the proposed implementation sequence after Run 200.
Run 200 makes **no production source change**, implements **no backend**,
and **does not close C4 or C5**.

## 1. Scope statement

* Run 200 is **docs/spec/crosscheck only**.
* Run 200 **does not implement any backend** — no RemoteSigner, no KMS,
  no HSM, no cloud KMS, no PKCS#11, no governance execution engine, and
  no real on-chain proof verifier.
* Run 200 **does not close C4** and **does not close C5**.
* Run 200 adds documentation (this report, a formal C4/C5 closure
  criteria document, an optional static run index) and append-only Run
  200 sections to four existing design/spec/ops documents. It changes no
  production source, no CLI/env surface, no marker / sequence-file /
  trust-bundle core schema, and no wire format.
* Run 200 does not weaken Runs 070 or 130–199, and does not enable
  MainNet peer-driven apply.

## 2. Accepted evidence map (Runs 130–199)

The following phases are accepted from the canonical per-run evidence
reports (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_130.md` …
`_RUN_199.md`) and the corresponding release-binary evidence archives
(`docs/devnet/run_1NN_*/`). A per-run static index is provided in
[`QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md`](
  QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md).

* **v2 authority marker (Runs 130–143).** Anti-rollback v2 authority
  marker, governance proof scaffolding, validation-only and live `0x05`
  v2 validation, and release-binary evidence for v2 validation-only,
  reload-apply, startup, SIGHUP, snapshot/restore, and live inbound
  `0x05`.
* **reload-check / reload-apply / startup / SIGHUP / snapshot-restore /
  local peer-candidate-check.** The v2 marker decision is exercised
  across all of the existing trust-bundle decision surfaces; the
  validation-only surfaces (reload-check, local peer-candidate-check,
  live inbound `0x05`) remain non-mutating, and the mutating surfaces
  (reload-apply, startup, SIGHUP) preserve the Run 070
  `validate → swap → evict_sessions → commit_sequence` ordering.
* **live inbound `0x05` (Runs 143, 147, 177).** Live inbound `0x05`
  frames are validated under the v2 marker / governance-proof path;
  invalid material is not propagated, not staged, and not applied.
* **peer-driven staging / apply / drain (Runs 144–158).** Peer-driven
  apply safety, staging, bounded drain, and DevNet/TestNet release-binary
  peer-driven apply evidence; MainNet peer-driven apply remains the
  Run 147 / 148 / 152 FATAL refusal.
* **authority lifecycle (Runs 159–162).** Typed pure v2 signing-key
  lifecycle transition validation (`ActivateInitial`, `Rotate`,
  `Retire`, `Revoke`, `EmergencyRevoke`), marker integration, and
  release-binary lifecycle enforcement evidence.
* **governance authority (Runs 163–177).** Governance authority verifier,
  proof carrier, Required-policy selector, validation-only and live
  `0x05` proof-carrying evidence.
* **OnChainGovernance fixture and production-boundary (Runs 178–187).**
  OnChainGovernance fixture verifier, production verifier boundary,
  production call-site wiring, payload carrying, release-binary
  accepted-proof evidence, and production-class fail-closed evidence.
* **custody boundary (Runs 188–193).** Authority custody boundary,
  custody metadata carrying, custody policy selector, and release-binary
  custody-policy evidence.
* **RemoteSigner boundary (Runs 194–199).** RemoteSigner boundary,
  RemoteSigner payload carrying, RemoteSigner policy selector, and
  release-binary RemoteSigner policy evidence.

## 3. Current safety properties proven

The following safety properties are proven by the accepted Runs 130–199
evidence and remain in force:

* **Anti-rollback v2 marker enforcement.** A persisted v2 authority
  marker cannot be silently rolled back to a lower authority epoch /
  sequence.
* **Sequence-before-marker ordering.** The Run 070 apply contract
  (`validate → swap → evict_sessions → commit_sequence`) and the
  sequence/marker write ordering are preserved on every mutating surface.
* **Validation-only non-mutation.** reload-check, local
  peer-candidate-check, and live inbound `0x05` are pure validation
  surfaces that never mutate the marker, sequence, or live trust.
* **Rejected-candidate no-mutation.** A rejected candidate on any surface
  produces no marker write, no sequence write, no Run 070 apply, no live
  trust swap, no session eviction, no `.tmp` residue, and no fallback to
  `--p2p-trusted-root`.
* **Invalid live `0x05` no-propagation / no-staging / no-apply.** Where
  evidenced, invalid live inbound `0x05` material is neither propagated,
  staged, nor applied.
* **MainNet peer-driven apply refusal.** MainNet peer-driven apply
  remains the Run 147 / 148 / 152 FATAL refusal even with custody /
  governance / RemoteSigner policy selectors armed and fixture material
  present.
* **Fixture / local / loopback evidence-only status.** Fixture
  governance proofs, fixture custody material, and fixture loopback
  RemoteSigner material are DevNet/TestNet evidence-only and cannot
  satisfy MainNet production authority.
* **Production-class proof fail-closed.** Production / mainnet-production
  governance, custody, and RemoteSigner material reaches the relevant
  boundary and fails closed as unavailable.
* **KMS / HSM / RemoteSigner placeholders fail-closed.** No real KMS,
  HSM, cloud-KMS, PKCS#11, or RemoteSigner backend exists; all such
  material fails closed.
* **Default Disabled selector behavior.** The custody and RemoteSigner
  policy selectors default to their `Disabled` value when neither the
  hidden CLI flag nor the environment variable is present.
* **Hidden selector CLI/env behavior.** The hidden custody and
  RemoteSigner policy selectors are accepted via one hidden CLI flag
  (clap `hide = true`) plus one environment variable each, and remain
  hidden from `--help`.
* **CLI-over-env precedence.** Where applicable, the hidden CLI flag wins
  over the environment variable deterministically, and invalid explicit
  values fail closed with a typed parse error rather than silently
  downgrading to `Disabled`.
* **Release-binary evidence boundaries.** Release-binary evidence
  exercises the real `target/release/qbind-node` for surface acceptance
  (flag/env accepted, no banner / `--help` drift, MainNet refusal
  preserved) and a release-built helper for selector resolution and
  routing semantics; the helpers are Cargo examples and are dead code in
  the production runtime.

## 4. Why C4 remains open

C4 (production `qbind-node` binary operating a fully real trust-anchor
authority lifecycle) remains **OPEN**. The following production blockers
are unresolved:

* **Real production RemoteSigner backend unavailable.** The RemoteSigner
  boundary (Runs 194–199) is a typed boundary plus a fixture-loopback
  evidence path only; no real RemoteSigner backend or networked signer
  service exists.
* **Real KMS / HSM backend unavailable.** No real KMS, HSM, cloud-KMS, or
  PKCS#11 custody backend exists.
* **Real custody attestation unavailable.** The custody boundary
  (Runs 188–193) carries custody metadata and a policy selector only; no
  real custody attestation verifier exists.
* **Real on-chain governance proof verifier unavailable.** The
  OnChainGovernance work (Runs 178–187) is a fixture verifier plus a
  production boundary that fails closed; no real on-chain proof verifier
  exists.
* **Governance execution engine unavailable.** No governance execution
  engine exists; governance proofs gate decisions but do not execute
  governance transitions.
* **Validator-set rotation unavailable.** Validator-set rotation /
  authority-set synchronization is not implemented.
* **MainNet governance policy artifacts incomplete.** The MainNet
  production governance policy artifacts (authorized authority set,
  required-proof policy, activation policy) are not complete.
* **MainNet production custody policy not satisfiable.** No production
  custody backend can satisfy the MainNet production custody policy;
  fixture/local material is rejected for MainNet.
* **Emergency governance / recovery ceremony not production-real.** The
  emergency governance / recovery ceremony exists as typed lifecycle
  transitions and fixtures only, not as a production-real ceremony.
* **End-to-end MainNet authority rotation/revocation under production
  custody not proven.** No end-to-end MainNet authority
  rotation/retire/revoke/emergency-revoke under real production custody
  has been demonstrated.

## 5. Why C5 remains open

C5 (production cryptographic key custody, rotation, and operational
signing lifecycle) remains **OPEN**. The following production blockers
are unresolved:

* **Production key custody unavailable.** No production custody backend
  (KMS / HSM / RemoteSigner) exists; production signing material is not
  custodied in hardware or a remote signer.
* **Production CA / root / authority rotation ceremony incomplete.** The
  production CA / root / authority rotation ceremony is not complete.
* **Hardware or remote signing attestation unavailable.** No hardware or
  remote-signing attestation is available or verified.
* **Operational signing audit trail unavailable.** No production
  operational signing audit trail / reproducible signing evidence exists.
* **Validator-set rotation / cryptographic reconfiguration incomplete.**
  Validator-set rotation and cryptographic reconfiguration are
  incomplete.
* **Long-term crypto-agility activation policy incomplete.** The
  crypto-agility activation policy for future PQC algorithm changes is
  incomplete.
* **Production incident-response and key-compromise procedure
  incomplete.** The production incident-response and key-compromise /
  emergency-revoke procedure is not production-real.
* **No full MainNet release-binary evidence under production custody.**
  No full MainNet release-binary evidence exists under real production
  custody.

## 6. Minimum C4 closure criteria

C4 may be considered for closure only when all of the following are met
(or an explicitly accepted, documented alternative is recorded):

* A **real production custody backend** is implemented (RemoteSigner /
  KMS / HSM) or an explicitly accepted alternative is documented and
  approved.
* A **real production on-chain governance proof verifier** is implemented
  or an explicitly accepted alternative is documented and approved.
* A **governance execution policy** is implemented (proofs gate *and*
  drive authority lifecycle transitions under policy).
* The **MainNet policy allows only production-authenticated lifecycle
  transitions** — fixture / local / loopback material remains rejected
  for MainNet.
* The **authority lifecycle rotate / retire / revoke / emergency-revoke**
  transitions are **proven under production custody**.
* **Rejected production lifecycle updates produce no mutation** (no
  marker write, no sequence write, no Run 070 apply, no live swap, no
  session eviction).
* **Recovery / rollback / sequence-replay protections** are
  **release-binary evidenced** under the production path.
* The **MainNet peer-driven apply policy** is explicitly specified and
  either **remains refused** or is **safely enabled under production
  criteria** (production custody + production governance proof +
  production-authenticated authority set).
* **Release-binary evidence** covers startup, reload-check, reload-apply,
  SIGHUP, snapshot/restore, local peer-candidate-check, live `0x05`, and
  peer-driven drain/apply where applicable.

## 7. Minimum C5 closure criteria

C5 may be considered for closure only when all of the following are met
(or an explicitly accepted, documented alternative is recorded):

* A **production custody backend with attestation** is available and
  verified.
* **No raw local production signing keys** are used — production signing
  material is custodied (hardware or remote signer).
* **Key rotation / revocation / emergency-revoke ceremonies** are
  production-real and exercised.
* **Validator-set rotation / authority-set synchronization** is
  implemented and exercised.
* **Operational audit logs and reproducible evidence** for production
  signing are available.
* A **crypto-agility policy** for future PQC algorithm changes is
  defined and activatable.
* A production **incident-response runbook** (including key-compromise /
  emergency-revoke) is complete.
* **Release-binary evidence** and a **negative-invariant corpus** cover
  the production custody / rotation / revocation paths.

## 8. Run 201+ proposed implementation sequence

The following is the **proposed** next implementation branch. These runs
are **not** final and are subject to readiness; the order may change.

* **Run 201:** Source/test production RemoteSigner backend interface
  transport boundary.
* **Run 202:** Release-binary production RemoteSigner transport-boundary
  evidence.
* **Run 203:** Source/test KMS/HSM backend abstraction boundary.
* **Run 204:** Release-binary KMS/HSM backend-boundary evidence.
* **Run 205:** Source/test real custody attestation verifier skeleton.
* **Run 206:** Release-binary custody attestation verifier-boundary
  evidence.
* **Run 207+:** Real governance verifier / governance execution /
  validator-set rotation planning, depending on readiness.

These proposed runs do not themselves close C4 or C5; each backend-real
milestone must satisfy the §6 / §7 closure criteria before any closure
claim is made.

## 9. Crosscheck

Run 200 crosschecks the new and modified documents against the existing
design/spec (`docs/whitepaper/contradiction.md`,
`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, and the Runs 130–199
evidence reports). The crosscheck result is recorded in
[`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
under the Run 200 entry. Summary: **no contradiction found**; C4 and C5
are intentionally still open; fixture/local/loopback evidence is not
described as production MainNet authority; production RemoteSigner / KMS /
HSM remain unavailable; MainNet peer-driven apply remains refused; and no
real governance execution exists.

## 10. Run 200 deliverables

* Canonical consolidation report (this file).
* Formal closure checklist:
  [`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`](
    ../protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md).
* Static run index:
  [`docs/devnet/QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md`](
    QBIND_RUN_130_199_AUTHORITY_LIFECYCLE_INDEX.md).
* Append-only Run 200 sections in:
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](
      ../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## 11. Validation commands

Run 200 is docs/spec/crosscheck only. The following were run and their
results recorded:

```bash
grep -R "Full C4.*closed\|C5.*closed\|MainNet.*enabled\|RemoteSigner.*production active\|KMS/HSM.*active\|validator-set rotation.*complete" docs/ crates/qbind-node/src crates/qbind-node/examples || true
grep -R "Run 200" docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_200.md docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md docs/whitepaper/contradiction.md docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md
cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests
cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests
cargo test -p qbind-node --test run_194_remote_authority_signer_boundary_tests
cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests
cargo test -p qbind-node --test run_190_authority_custody_payload_callsite_tests
cargo test -p qbind-node --test run_188_authority_custody_boundary_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

The forbidden-claim grep matches only **negated** statements (for
example `C5 remains NOT closed`, `no MainNet apply enabled`); no new
positive closure or enablement claim is introduced by Run 200. The
`Run 200` grep confirms the Run 200 marker is present in all six target
documents.

Recorded results on this checkout (docs-only scope — the grep checks and
the newest custody/RemoteSigner test slice were run):

* forbidden-claim grep — only pre-existing negated statements match; no
  new positive closure/enablement claim in the Run 200 documents.
* `Run 200` marker grep — present in all six target documents.
* `cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests`
  — **53 passed; 0 failed**.
* `cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests --test run_188_authority_custody_boundary_tests`
  — **46 passed; 0 failed**.
* `cargo test -p qbind-node --lib pqc_authority` — **164 passed;
  0 failed**.

## 12. Acceptance summary

1. Consolidates Runs 130–199 into a single accepted evidence map. ✅
2. Defines C4 and C5 closure criteria
   (`QBIND_C4_C5_CLOSURE_CRITERIA.md` + §6 / §7 here). ✅
3. Explicitly states **full C4 remains OPEN**. ✅
4. Explicitly states **C5 remains OPEN**. ✅
5. Identifies the remaining production blockers (§4 / §5). ✅
6. Proposes the next implementation sequence (§8). ✅
7. Prevents fixture/local/loopback evidence from being misrepresented as
   MainNet production authority (§3 / §9). ✅
8. Records the contradiction crosscheck (§9 + `contradiction.md`). ✅
9. Makes **no production source change**. ✅
10. Makes **no MainNet enablement claim**. ✅

## Standing invariants (unchanged by Run 200)

* No real RemoteSigner backend is implemented.
* No real KMS / HSM / cloud-KMS / PKCS#11 backend is implemented.
* No real on-chain governance proof verifier is implemented.
* No governance execution engine is implemented.
* No validator-set rotation is implemented.
* Fixture / local / loopback evidence is DevNet/TestNet evidence-only and
  cannot satisfy MainNet production authority.
* MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal.
* Default custody / RemoteSigner selector resolution remains `Disabled`.
* Run 200 does not weaken Runs 070 or 130–199.
* Full C4 remains OPEN.
* C5 remains OPEN.
