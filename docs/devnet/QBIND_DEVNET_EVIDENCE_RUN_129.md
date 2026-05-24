# QBIND DevNet Evidence — Run 129

**Subject:** Ratification v2 per-authority-domain monotonic schema specification (spec-first) + Run 128 doc-sync correction.  
**Verdict:** **positive**  
**Date:** 2026-05-24  
**Task:** `task/RUN_129_TASK.txt`  
**Type:** Docs/spec only (no runtime implementation).

---

## 1. Exact verdict

**positive.**

Run 129 is complete at the specification level:

- Run 128 documentation sync issues are corrected in protocol/runbook/contradiction tracking.
- Ratification v2 object schema is defined.
- Monotonic model is defined and selected.
- Canonical v2 preimage domain and digest rules are defined.
- Marker v2 evolution is defined.
- v1/v2 compatibility and downgrade refusal policy is defined.
- Future implementation staging is defined.
- No runtime behavior was changed.

---

## 2. What changed

- Added Run 129 evidence document:
  - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_129.md`
- Updated protocol design tracking:
  - `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- Updated operator runbook tracking:
  - `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- Updated contradiction tracker:
  - `docs/whitepaper/contradiction.md`

### Run 128 doc-sync fix captured in Run 129

The three tracking docs now explicitly and consistently state:

- Run 128 produced release-binary evidence for offline authority-state reset CLI.
- DevNet valid reset writes marker + audit.
- MainNet local reset refuses.
- Missing/bad ratification, wrong expected genesis hash, corrupt marker, missing audit flag, wrong-chain ratification, and wrong-environment ratification all refuse.
- Refusals do not write or mutate marker bytes.
- Reset exits before normal startup surfaces.
- MainNet governance artifact support remains open.
- Ratification v2 monotonic schema remained open before this Run 129 specification.
- Rotation/revocation, KMS/HSM, peer-driven live apply, full C4, and C5 remain open.

**Production runtime source changes (`crates/**/src/**`): none.**

---

## 3. Key design decisions

### 3.1 Selected monotonic model

Run 129 selects **per-authority-domain monotonic sequence** (`authority_domain_sequence`) over per-key sequence.

Authority domain binding:

- `environment`
- `chain_id`
- `genesis_hash`
- `authority_root_fingerprint`

Rationale:

- Provides one total order across `ratify`, `rotate`, `revoke`.
- Prevents cross-key ordering ambiguity during rotation.
- Enables deterministic replay/downgrade detection at marker-comparison time.

### 3.2 Ratification v2 object fields (design)

Conceptual v2 schema fields:

- `schema_version = 2`
- `environment`
- `chain_id`
- `genesis_hash`
- `authority_policy_version`
- `authority_root_fingerprint`
- `authority_root_suite_id`
- `target_bundle_signing_key_fingerprint`
- `target_bundle_signing_key_suite_id`
- `target_bundle_signing_public_key` (or canonical reference once standardized)
- `authority_domain_sequence`
- `key_lifecycle_action` (`ratify | rotate | revoke`)
- `previous_key_fingerprint_if_rotation`
- `previous_ratification_digest_if_rotation`
- `valid_from_epoch_if_used`
- `valid_until_epoch_if_used`
- `revocation_reason_if_revoke`
- `capabilities_scope`
- `signature`

### 3.3 Canonical preimage/domain tag

- Domain tag: `QBIND:BUNDLE-SIGNING-RATIFICATION:v2`
- Deterministic length-prefixed encoding (big-endian integers).
- Includes all security-relevant fields except `signature`.
- Digest: `sha3_256(v2_preimage)`.
- No JSON ambiguity in signed material.

### 3.4 Marker v2 evolution (design-only)

`PersistentAuthorityStateRecord` future extension target:

- `authority_schema_version`
- `latest_authority_sequence`
- `latest_key_lifecycle_action`
- `active_key_fingerprint`
- `previous_key_fingerprint`
- `latest_ratification_digest`
- `revoked_key_set_digest` (or future revocation accumulator field)

### 3.5 v1/v2 compatibility policy

- v1 on no-marker node: allowed pre-v2 activation.
- v1 on v1-marker node: allowed pre-v2 activation.
- v2 on v1-marker node: allowed migration path.
- v1 after v2-marker exists: **refuse fail-closed**.
- v2 lower sequence: refuse.
- v2 same sequence + same digest: idempotent accept.
- v2 same sequence + different digest: refuse (equivocation).
- v2 higher sequence: accept.

### 3.6 Downgrade/refusal policy

Fail-closed refusal for:

- downgrade/replay sequence attempts;
- same-sequence conflicting digest;
- wrong domain/environment/chain/genesis/root;
- malformed lifecycle/action-linked fields;
- wrong domain tag/preimage ambiguity;
- ambiguous v1/v2 combinations not covered by explicit migration rules.

### 3.7 Future implementation staging

- **Run 130** — v2 schema/types/preimage/verifier tests.

- **Run 131** — marker v2 extension + migration.

- **Run 132** — enforcement wiring under compatibility gates.

- **Run 133** — release-binary v2 acceptance/rejection evidence.

- **Run 134+** — rotation lifecycle; later revocation lifecycle, KMS/HSM, governance artifacts.

---

## 4. What was proven

### 4.1 Docs/spec proof

Run 129 proves (at spec level):

- explicit v2 schema model;
- explicit monotonic-ordering model;
- explicit fail-closed compatibility/downgrade policy;
- explicit marker evolution model;
- explicit staged implementation boundary;
- synchronized Run 128 historical status across tracking docs.

### 4.2 Code/test proof

- No runtime code changed.
- No runtime tests executed for behavior changes (none introduced).

### 4.3 Release-binary evidence

- None required for Run 129.
- None claimed.

---

## 5. What was not changed

- No v2 verifier implementation.
- No production runtime code change.
- No trust-bundle wire change.
- No peer-candidate wire change.
- No reset CLI behavior change.
- No authority marker persistence behavior change.
- No signing-key rotation/revocation lifecycle implementation.
- No KMS/HSM implementation.
- No MainNet governance artifact support implementation.
- No peer-driven apply implementation.
- No full C4 closure claim.
- No C5 closure claim.

---

## 6. Contradictions or inconsistencies

Cross-check performed against:

- Run 100 authority model;
- Run 101 genesis authority implementation;
- Run 102 boot verification;
- Run 103 verifier;
- Run 104 key material registry;
- Runs 105–115 ratification enforcement/evidence;
- Run 116 model;
- Run 117 primitive;
- Run 118 helper layer;
- Runs 119/120/121 mutating-surface wiring;
- Run 122 release-binary mutating-surface evidence;
- Run 123 validation-only marker checks;
- Run 124 restore conflict enforcement;
- Run 125 restore evidence;
- Run 126 reset specification;
- Run 127 reset CLI skeleton;
- Run 128 reset CLI release-binary evidence;
- `docs/whitepaper/contradiction.md`;
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`;
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

Result:

- No new contradiction introduced by Run 129 updates.
- Prior Run 128 sync gap is explicitly corrected and documented in this run.

---

## 7. Evidence references

- Evidence document:
  - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_129.md`
- Updated docs:
  - `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
  - `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
  - `docs/whitepaper/contradiction.md`
- Source anchors used for v1 investigation:
  - `crates/qbind-ledger/src/bundle_signing_ratification.rs`
  - `crates/qbind-node/src/pqc_authority_state.rs`
- Docs/test commands:
  - No repository docs-lint command discovered in this workspace.

---

## 8. Residual risks and next recommended run

### Residual risks

- v2 remains specification-only until verifier and marker support are implemented.
- Rotation/revocation runtime lifecycle remains unimplemented.
- MainNet governance artifact design/verification remains unimplemented.
- KMS/HSM custody remains unimplemented.
- Peer-driven live apply remains unimplemented.

### Next recommended run

Proceed with **Run 130**: implement the ratification v2 schema/types, canonical preimage, and verifier tests exactly per this Run 129 spec, preserving current fail-closed v1 behavior and no-local-config-only MainNet authority posture.