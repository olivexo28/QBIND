# QBIND DevNet Evidence — Run 126

**Subject:** Explicit authority-state reset/recovery procedure specification.
**Verdict:** **positive**
**Date:** 2026-05-23
**Task:** `task/RUN_126_TASK.txt`
**Type:** Spec-first / docs-only. No production runtime code changed.

---

## 1. Exact verdict

**positive.**

Run 126 is **spec-first** — no production runtime code was changed, no CLI
reset command was implemented, and no runtime behavior was modified.

The reset/recovery specification is complete:

- environment policy is defined (DevNet / TestNet / MainNet);
- operator ceremony is defined (12-step staged process);
- refusal cases are defined (13 mandatory refusal conditions);
- audit record schema is defined (17-field conceptual schema);
- MainNet local reset remains disallowed by default;
- docs are synchronized (Run 125 doc-sync verified as already present).

---

## 2. Run 125 doc-sync verification (Checkpoint 1)

The task required verifying Run 125 content in three tracking documents before
writing new Run 126 material.

**Verification result:** All three documents already contain explicit Run 125
updates that satisfy the required statements:

| Document | Location | Content |
|----------|----------|---------|
| `docs/whitepaper/contradiction.md` | Line 1566 | Full Run 125 evidence-only paragraph with all 7 scenarios, marker preservation, B3 non-write on reject, C4 status, future items |
| `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` | Lines 1670–1692 | Run 125 update section with scenario matrix, evidence references, C4 status, remaining items |
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | Lines 3893–3929 | Run 125 operator section with scenario table, evidence archive reference, explicit non-changes list |

All required statements are present:

- [x] Run 125 produced release-binary evidence for snapshot/restore authority-marker conflict enforcement.
- [x] All seven restore scenarios passed.
- [x] Legacy no-marker restore remains compatible.
- [x] Legacy snapshot with local marker rejects.
- [x] Matching marker restores.
- [x] Conflicting/corrupt/wrong-domain/no-context cases reject fail-closed.
- [x] Local marker bytes remain unchanged on rejection.
- [x] B3 restore audit marker is not written on rejected restore.
- [x] Reset/recovery remains open until Run 126+.
- [x] Ratification v2 per-key monotonic schema remains future work.
- [x] Full C4 and C5 remain open.

**No doc-sync correction was needed.** The Run 125 deliverables already
synchronized all three tracking documents.

---

## 3. Authority-state reset/recovery specification

### 3.1 Threat model

The following threats motivate strict controls on any future reset capability:

| # | Threat | Consequence if unmitigated |
|---|--------|---------------------------|
| T1 | Malicious operator rollback | Attacker replays a prior ratification to suppress a key revocation or policy upgrade; the network accepts a stale or compromised signing key. |
| T2 | Accidental data-dir restore | Operator restores an old backup that contains a stale `pqc_authority_state.json`; the node accepts bundles signed by a revoked or superseded key. |
| T3 | Stale snapshot restore | An old snapshot carrying a lower `authority_sequence` is applied; if reset is allowed, the node regresses to an older authority epoch. |
| T4 | Stale ratification sidecar reuse | A ratification file from a previous authority epoch is supplied during reset; the new marker incorrectly asserts the stale key is current. |
| T5 | Conflicting marker injection | An attacker with data-dir write access injects a marker with a different ratification hash for the same sequence (equivocation). |
| T6 | Corrupt marker recovery temptation | Operator sees `RejectLocalMarkerCorrupt` and is tempted to delete the marker file directly; this bypasses all anti-rollback checks. |
| T7 | DevNet flags leaking into MainNet | A `--allow-authority-state-reset` flag designed for DevNet is accidentally or maliciously used on a MainNet node. |
| T8 | Peer-triggered reset attempt | A malicious peer sends a crafted message that the node interprets as a reset instruction. |
| T9 | Local config-only authority escalation | An operator configures a local key as the sole authority without any genesis-bound or ratification-proven chain of trust. |

### 3.2 Existing authority marker failure modes (Runs 117–125)

| Failure condition | Source run | Classification | Recovery posture |
|-------------------|-----------|----------------|-----------------|
| Corrupt local marker (non-JSON / unsupported `record_version`) | Run 117, evidenced Run 125 Scenario 5 | **Evidence-only / investigation-required** | Node refuses all mutating + restore surfaces. Operator must investigate cause (disk corruption, manual edit, attack). DevNet: may reset with ceremony. TestNet: may reset with ceremony + stronger proof. MainNet: governance-required. |
| Conflicting local marker (same sequence, different ratification hash) | Run 118, evidenced Run 122 Scenario 3 / Run 125 Scenario 4 | **Environment-reset-only (DevNet/TestNet) / MainNet governance-required** | Two distinct ratifications cannot share the same authority_sequence. This indicates equivocation or state tampering. |
| Wrong-domain marker (genesis_hash / chain_id / env mismatch) | Run 118, evidenced Run 125 Scenario 6 | **Operator-recoverable** | Node was likely moved between networks or the data directory was swapped. DevNet/TestNet: reset with correct genesis. MainNet: investigate before any action. |
| Legacy snapshot with local marker (Run 124 `RejectMissingSnapshotMarker`) | Run 124, evidenced Run 125 Scenario 2 | **Operator-recoverable** | The snapshot predates the authority marker system. Operator must obtain a snapshot from a marker-aware producer or use the reset ceremony after verification. |
| No-genesis-context restore with local marker (`AuthorityContextMissing`) | Run 124, evidenced Run 125 Scenario 7 | **Operator-recoverable** | The restore was invoked without `--genesis-path`. Supply the correct genesis file and retry. No reset needed. |
| Marker persist failure after commit (Run 119 stale-by-one crash window) | Run 119 | **Operator-recoverable** | Next startup's reload-apply will re-derive and persist the correct marker (Upgrade path handles this). No reset needed. |
| Validation-only marker conflict (reload-check / peer-candidate-check / live `0x05`) | Run 123 | **Forbidden local recovery** | Validation-only surfaces never persist. The conflict indicates the incoming candidate would violate anti-rollback. Reject is correct; no recovery action on the local marker. |
| Live `0x05` marker conflict | Run 123 | **Forbidden local recovery** | Same as above. The conflict is in the candidate, not in local state. |

### 3.3 Environment policy

#### 3.3.1 DevNet

- **May allow** explicit reset for test automation and local recovery.
- **Must require** explicit command (no implicit or automatic reset).
- **Must require** audit output (even in DevNet, produce the audit record for traceability).
- **May relax** the ratification proof requirement to accept unratified DevNet bundles (matching existing `--p2p-trust-bundle-allow-unratified-testnet-devnet` behavior).
- **Must not** allow peer-triggered reset.

#### 3.3.2 TestNet

- **May allow** controlled reset under explicit operator ceremony.
- **Must require** stronger proof: valid ratification sidecar, correct genesis hash, matching chain_id and environment.
- **Must produce** full audit artifacts (old marker, new marker, hashes, timestamps).
- **Must not** allow peer-triggered reset.
- **Should require** operator confirmation step (interactive or explicit `--confirm` flag).

#### 3.3.3 MainNet

- **Local reset disallowed by default.**
- Any MainNet recovery **must require** a future governance/ratification procedure or offline signed recovery artifact.
- **Must not** accept local config alone as authority.
- **Must not** accept `--allow-authority-state-reset` without a signed governance artifact (future design).
- The future implementation run must default-refuse on MainNet and document what governance-level artifact would be needed to override.

### 3.4 Operator artifact requirements

Before any future reset, the following must be archived:

| # | Artifact | Purpose |
|---|----------|---------|
| 1 | Old `pqc_authority_state.json` bytes (verbatim copy) | Preserve evidence of pre-reset authority state |
| 2 | Old marker SHA-256 hash | Integrity proof of archived marker |
| 3 | Candidate new marker bytes (derived from target ratification) | Document what the reset will install |
| 4 | Candidate new marker SHA-256 hash | Integrity proof of candidate |
| 5 | Genesis file hash (canonical Run 101 computation) | Bind reset to correct trust domain |
| 6 | Expected genesis hash (from `--expected-genesis-hash` or runtime) | Cross-check against computed hash |
| 7 | `chain_id` | Environment identification |
| 8 | Environment (`devnet` / `testnet` / `mainnet`) | Policy gate |
| 9 | Snapshot metadata (if restore-related failure) | Link reset to specific snapshot state |
| 10 | Ratification sidecar path + hash | Prove the target key is ratified under genesis authority |
| 11 | Trust bundle fingerprint | Identify which bundle the new marker represents |
| 12 | Timestamp (ISO 8601 UTC) | Audit trail |
| 13 | Operator note (free-form, hashed into audit record) | Human context |
| 14 | Binary SHA-256 | Identify exact binary performing the reset |
| 15 | Binary build-id (if available) | Additional binary identification |

### 3.5 Reset safety invariants

The following invariants are **mandatory** for any future implementation:

1. Reset must **never** run implicitly (no auto-repair, no silent overwrite, no startup-time automatic reset).
2. Reset must **never** run during normal startup (separated command / subcommand; never triggered by `qbind-node` main entry point).
3. Reset must **never** be triggered by peer input (no wire message, no peer-driven path, no gossip-based trigger).
4. Reset must **never** persist from validation-only surfaces (reload-check, peer-candidate-check, live `0x05`).
5. Reset must **never** synthesize marker from legacy snapshot bytes (the restore surface's existing refusal of synthesis is preserved).
6. Reset must **never** bypass ratification verification (the target key must be provably ratified under genesis authority).
7. Reset must **never** allow transport root authority (transport roots authorize KEMTLS, not bundle-signing keys).
8. Reset must **never** allow local config alone as MainNet authority.
9. Reset must **always** produce an audit record (the audit record is not optional even for DevNet).
10. Reset must be **irreversible** without another explicit audited ceremony (no "undo reset" shortcut).

### 3.6 Recovery classification table

| Failure condition | DevNet | TestNet | MainNet | Required artifacts | Future implementation behavior |
|-------------------|--------|---------|---------|-------------------|-------------------------------|
| Corrupt local marker | Allow with ceremony | Allow with ceremony + stronger proof | Governance-required | All 15 artifacts (§3.4) | `authority-state-reset` refuses without valid ratification; MainNet refuses without signed governance artifact |
| Conflicting marker (equivocation) | Allow with ceremony | Allow with ceremony + investigation | Governance-required | All 15 + investigation report | Must verify no active equivocation attack before allowing reset |
| Wrong-domain marker | Allow with ceremony | Allow with ceremony | Governance-required | All 15 + explanation of domain mismatch | Verify operator did not accidentally move data between chains |
| Legacy snapshot with local marker | Allow with ceremony | Allow with ceremony | Governance-required | All 15 + snapshot metadata | Verify the snapshot predates the marker system; do not synthesize |
| No-genesis-context restore | Not a reset case | Not a reset case | Not a reset case | Supply `--genesis-path` and retry | No reset needed; the error is correctable without state mutation |
| Marker persist failure (stale-by-one) | Not a reset case | Not a reset case | Not a reset case | Restart node; reload-apply re-derives | No reset needed; self-healing on next startup |
| Validation-only conflict | Forbidden | Forbidden | Forbidden | None (candidate is wrong, not local state) | No reset; the candidate is refused correctly |
| Authority sequence rollback attempt | Allow with ceremony (test scenarios only) | Refuse unless extraordinary | Governance-required | All 15 + justification | Must prove the rollback is legitimate (e.g., coordinated chain reset) |
| Policy version regression | Allow with ceremony | Refuse unless extraordinary | Governance-required | All 15 + justification | Must prove the regression is intentional |

### 3.7 Reset ceremony (staged operator process)

The following procedure defines the operator ceremony for a controlled
authority-state reset. This is NOT a routine maintenance action.

```
STAGE 1: STOP
─────────────
  1. Stop the node (SIGTERM / SIGKILL).
  2. Confirm the node process is not running (`pgrep qbind-node` returns empty).

STAGE 2: ARCHIVE
────────────────
  3. Copy the current data directory to a timestamped archive location:
       cp -a <data-dir> <archive-dir>/data-pre-reset-<ISO8601>
  4. Copy `<data-dir>/pqc_authority_state.json` to the archive:
       cp <data-dir>/pqc_authority_state.json <archive-dir>/marker-pre-reset.json
  5. Compute SHA-256 of the archived marker:
       sha256sum <archive-dir>/marker-pre-reset.json
  6. If snapshot-related: archive snapshot metadata.

STAGE 3: VERIFY
───────────────
  7. Verify the genesis file exists and compute the canonical genesis hash:
       qbind-node --print-genesis-hash --genesis-path <GENESIS_PATH>
  8. Verify chain_id and environment match the target deployment.
  9. Verify the candidate ratification under genesis authority:
       qbind-node --p2p-trust-bundle <BUNDLE> \
                  --p2p-trust-bundle-ratification <RATIFICATION> \
                  --genesis-path <GENESIS_PATH> \
                  --p2p-trust-bundle-reload-check \
                  --data-dir <TEMP_EMPTY_DIR>
     (This validates the bundle + ratification without touching the real data dir.)

STAGE 4: COMPARE
────────────────
  10. Document old marker record fields vs. candidate new marker fields.
      Note: authority_sequence, ratification_object_hash, genesis_hash_hex,
      chain_id_hex, environment, policy_version changes.

STAGE 5: EXECUTE (future — not implemented in Run 126)
──────────────────────────────────────────────────────
  11. Run the future reset command:
       qbind-node authority-state-reset \
         --data-dir <DATA_DIR> \
         --genesis-path <GENESIS_PATH> \
         --expected-genesis-hash <HASH> \
         --p2p-trust-bundle <BUNDLE> \
         --p2p-trust-bundle-ratification <RATIFICATION> \
         --output-audit <AUDIT_PATH> \
         --environment <devnet|testnet|mainnet> \
         [--confirm]
  12. Verify the command produced a non-empty audit record at <AUDIT_PATH>.

STAGE 6: RESTART AND VERIFY
────────────────────────────
  13. Start the node normally:
       qbind-node --data-dir <DATA_DIR> \
                  --genesis-path <GENESIS_PATH> \
                  --p2p-trust-bundle <BUNDLE> \
                  --p2p-trust-bundle-ratification <RATIFICATION> \
                  ...
  14. Verify the node starts without authority-marker errors.
  15. Verify the new marker on disk matches the candidate:
       cat <DATA_DIR>/pqc_authority_state.json | jq .
  16. Verify the audit record is complete and archived.
```

### 3.8 Refusal cases

The future implementation MUST refuse to execute a reset when:

| # | Condition | Reason |
|---|-----------|--------|
| R1 | Missing genesis hash | Cannot verify trust domain binding |
| R2 | Wrong genesis hash (computed ≠ expected) | Trust domain mismatch |
| R3 | Wrong `chain_id` | Network mismatch |
| R4 | Wrong environment | Policy gate violated |
| R5 | Malformed authority root | Cannot derive valid marker |
| R6 | Transport root attempting to authorize bundle signing key | Transport roots are not bundle-signing authorities |
| R7 | Missing ratification sidecar | Cannot prove key is authorized under genesis authority |
| R8 | Bad ratification (signature invalid, key not in genesis authority set) | Ratification verification failure |
| R9 | Local config-only MainNet reset (no governance artifact) | MainNet requires governance authority |
| R10 | Peer-provided reset request | Reset is an operator-only action; peers cannot request it |
| R11 | Node is running (process still alive) | Reset must be offline-only |
| R12 | Missing audit output path | Audit record is mandatory |
| R13 | Attempt to erase marker without replacement on MainNet/TestNet | Authority continuity must be maintained on production networks |

### 3.9 Audit record schema (conceptual)

The following fields define the future audit record. No implementation in Run 126.

```
record_version          : u32     (schema version, starts at 1)
action                  : string  ("authority_state_reset")
environment             : string  ("devnet" | "testnet" | "mainnet")
chain_id                : hex     (0x-prefixed chain identifier)
genesis_hash            : hex     (canonical Run 101 genesis hash)
old_marker_hash         : hex     (SHA-256 of pre-reset pqc_authority_state.json bytes)
old_marker_record       : object  (full deserialized old marker, or "corrupt"/"absent")
new_marker_hash         : hex     (SHA-256 of newly persisted pqc_authority_state.json bytes)
new_marker_record       : object  (full deserialized new marker)
ratification_hash       : hex     (SHA-256 of the ratification sidecar file)
trust_bundle_fingerprint: hex     (Run 055 canonical bundle fingerprint)
snapshot_metadata_hash  : hex     (SHA-256 of snapshot meta.json, or null if not snapshot-related)
operator_note_hash      : hex     (SHA-256 of operator-supplied note text, or null)
binary_sha256           : hex     (SHA-256 of the qbind-node binary performing the reset)
binary_build_id         : string  (ELF build-id if available, else null)
timestamp               : string  (ISO 8601 UTC)
result                  : string  ("success" | "refused:<reason>")
```

### 3.10 Interaction with future ratification v2 monotonic schema

- The current marker system can detect conflict, wrong-domain, corruption, and same-sequence equivocation, but it does **not** prove per-key monotonic authority progression (i.e., it cannot prove that key K2 is a legitimate successor of K1 via an explicit rotation record).
- Future `BundleSigningRatification` v2 **must** add a canonical per-key monotonic field (e.g., `authority_epoch` or `key_generation`) that chains key transitions.
- Reset/recovery **must not** be used as a substitute for a rotation/revocation lifecycle. A reset does not constitute a rotation; it merely corrects a local state corruption.
- Any future reset after ratification v2 lands **must** respect the monotonic authority sequence: a reset cannot install a marker that would violate the per-key monotonic chain.
- Reset with ratification v2 must additionally verify that the candidate's monotonic field is ≥ the old marker's monotonic field (unless the old marker is corrupt, in which case the corruption classification in §3.2 applies).

### 3.11 Future CLI / command design (conceptual, not implemented)

```
qbind-node authority-state-reset \
  --data-dir <PATH> \
  --genesis-path <PATH> \
  --expected-genesis-hash <HASH> \
  --p2p-trust-bundle <BUNDLE_PATH> \
  --p2p-trust-bundle-ratification <RATIFICATION_PATH> \
  --output-audit <AUDIT_OUTPUT_PATH> \
  --environment <devnet|testnet|mainnet> \
  [--operator-note <TEXT>] \
  [--confirm] \
  [--mainnet-governance-artifact <PATH>]   # future: required for MainNet
```

**Behavior by environment:**

- `--environment devnet`: Allow with valid ratification + genesis + audit output.
- `--environment testnet`: Allow with valid ratification + genesis + audit output + require `--confirm` (or interactive prompt).
- `--environment mainnet`: **Refuse by default.** Require `--mainnet-governance-artifact` pointing to a signed governance authorization (future design — the artifact format and signing ceremony are not defined in Run 126).

The exact flag names and subcommand structure should follow repository conventions established at implementation time. The spec binds the semantic requirements, not the exact CLI ergonomics.

---

## 4. Future implementation plan

| Run | Scope | Depends on |
|-----|-------|-----------|
| **Run 127** | Implement `authority-state-reset` CLI skeleton with typed refusal cases, DevNet-only allow path, TestNet ceremony path, MainNet default-refuse. Produce audit record. | Run 126 spec |
| **Run 128** | Release-binary evidence for reset refusal/allowed cases (DevNet: corruption → reset → verify; TestNet: wrong-domain → refuse; MainNet: refuse without governance artifact). | Run 127 |
| **Run 129+** | Ratification v2 per-key monotonic schema design. | Run 126 spec; independent of Run 127/128 |
| **Future** | Signing-key rotation lifecycle. | Run 129 (ratification v2) |
| **Future** | Signing-key revocation lifecycle. | Run 129 (ratification v2) |
| **Future** | MainNet governance artifact design and signed recovery ceremony. | Run 127 + organizational governance |
| **Future** | KMS/HSM custody integration. | Independent |
| **Future** | Validator-set rotation. | Independent |

---

## 5. What changed

- **Docs created:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_126.md` (this file).
- **Docs updated:** `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 126 section).
- **Docs updated:** `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 126 operator procedure).
- **Docs updated:** `docs/whitepaper/contradiction.md` (Run 126 C4/C5 tracking update).
- **Run 125 doc-sync:** Verified as already present in all three tracking documents. No correction needed.
- **No runtime code changed.** Zero modifications to any file under `crates/**/src/**`.
- **No CLI flag added.** No `--allow-authority-state-reset` exists.
- **No tests added or modified.** This is a spec-only run.

---

## 6. Key design decisions

| Decision | Rationale |
|----------|-----------|
| MainNet local reset disallowed by default | Prevents T7 (DevNet flag leak) and T9 (local config authority escalation). |
| Explicit subcommand, not a flag on normal startup | Prevents T1 (implicit rollback) and enforces operator intentionality. |
| Mandatory audit record (even DevNet) | Creates a forensic trail regardless of environment. |
| Ratification verification required before reset | Prevents T4 (stale ratification reuse) and T6 (corrupt marker temptation). |
| Offline-only (node must be stopped) | Prevents race conditions and T8 (peer-triggered reset). |
| Transport roots cannot authorize reset | Preserves Run 100/101 authority separation. |
| Future monotonic schema interaction specified | Ensures Run 129+ does not conflict with the reset model. |

---

## 7. What was proven

### Docs/spec proof

- The reset/recovery procedure specification is formally written with threat model, environment policy, operator ceremony, refusal cases, audit schema, and future implementation boundaries.
- All three tracking documents verified as synchronized with Run 125.
- C4/C5 honestly updated with Run 126 narrowing (specification only, not implementation).

### Code/test proof

- None. No code changed. No tests added or modified.

### Release-binary evidence

- None required. Run 126 is a design/spec run.

---

## 8. What was not changed

Explicitly confirmed:

- [x] No reset command implemented.
- [x] No runtime code changed (`crates/**/src/**` untouched).
- [x] No marker deletion/rewrite behavior changed.
- [x] No trust-bundle wire format changed.
- [x] No peer-candidate wire format changed.
- [x] No peer-driven apply implemented.
- [x] No KMS/HSM implemented.
- [x] No signing-key rotation/revocation implemented.
- [x] No authority monotonic schema implemented.
- [x] No full C4 closure claimed.
- [x] No C5 closure claimed.
- [x] No `--allow-authority-state-reset` flag added.
- [x] No `pqc_authority_state.json` deleted or rewritten.
- [x] No snapshot restore behavior changed.
- [x] No validation-only marker behavior changed.
- [x] No mutating-surface marker behavior changed.
- [x] No Run 055 trust-bundle sequence anti-rollback weakened.
- [x] No Run 097 snapshot epoch parity weakened.
- [x] No Run 102 genesis verification weakened.
- [x] No Run 103 ratification verifier weakened.
- [x] No Run 105–115 ratification enforcement weakened.
- [x] No static production source-code anchors added.

---

## 9. Contradictions or inconsistencies

Cross-checked against Runs 100–125, contradiction.md, runbook, and protocol docs.

**No contradictions found.**

The Run 126 specification does not conflict with any existing behavior because:

1. It defines no runtime behavior — it is purely prescriptive for future runs.
2. Its refusal cases align with existing rejection semantics (e.g., wrong genesis hash is already refused by Run 102; wrong chain_id is already refused by existing enforcement; ratification failure is already refused by Run 103/105).
3. Its environment policy mirrors existing `--p2p-trust-bundle-allow-unratified-testnet-devnet` gating but for the recovery surface.
4. Its audit schema uses the same fields already present in `PersistentAuthorityStateRecord` (Run 117) plus standard metadata.
5. Its MainNet default-refuse posture is consistent with the existing pattern where MainNet has the strictest gates (Run 100 §5, Run 104 §3.3).

---

## 10. Residual risks and next recommended run

### Residual risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| The specification may need revision once implementation reveals edge cases (e.g., exact governance artifact format) | Low | Run 127 may amend the spec; the spec is not immutable |
| MainNet governance artifact format is undefined | Medium | This is intentionally deferred; MainNet reset is forbidden until governance is designed |
| Per-key monotonic schema does not yet exist | Medium | Reset without monotonic checks is safe only because ratification v1 already proves key authorization under genesis authority; v2 will add ordering |
| No automated enforcement of the ceremony steps | Low | The ceremony is operator-facing; enforcement comes via the future CLI refusal cases |

### Next recommended run

**Run 127:** Implement the `authority-state-reset` CLI skeleton with typed
refusal cases, DevNet-only allow path, TestNet ceremony path, and MainNet
default-refuse. Produce audit record on success. Exercise refusal on wrong
genesis, wrong chain_id, missing ratification, and MainNet-without-governance.

Run 127 should NOT implement:

- MainNet governance artifact verification (future design);
- Ratification v2 monotonic schema;
- Signing-key rotation/revocation;
- KMS/HSM;
- Peer-driven anything.

---

## 11. Evidence references

| Type | Path |
|------|------|
| Evidence document | `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_126.md` (this file) |
| Authority model update | `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 126 section) |
| Runbook update | `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 126 section) |
| Contradiction tracker update | `docs/whitepaper/contradiction.md` (Run 126 paragraph) |
| Task specification | `task/RUN_126_TASK.txt` |