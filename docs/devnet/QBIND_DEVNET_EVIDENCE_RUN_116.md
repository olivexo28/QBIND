# QBIND DevNet Evidence — Run 116

**Run:** 116
**Title:** Authority Anti-Rollback Persistence Model for Ratified Bundle-Signing Authority
**Date:** 2026-05-22
**Verdict:** positive (spec-first; no runtime code change)
**Scope:** Design and persistence model only. No implementation lands in
Run 116. Implementation is staged to Run 117.

This document is the canonical Run 116 deliverable. It is **spec-first**:
no production runtime code, no wire format, no verifier semantics, no
storage schema, and no policy is changed by this run. Run 116 defines the
durable anti-rollback model that Run 117 will implement and Run 118 will
wire into mutating surfaces, with release-binary evidence in Run 119.

Run 116 also documents one artifact-hygiene check on the prior run's
archive (§9.1).

---

## 1. What Run 116 changed

### 1.1 Docs changed

- **New:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_116.md` (this document).
- **Updated:** `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — appended
  a Run 116 update section that records the anti-rollback model and the
  staged implementation plan (Run 117 → Run 120).
- **Updated:** `docs/whitepaper/contradiction.md` — appended a Run 116 C4
  update narrowing the "authority anti-rollback persistence" sub-item from
  "OPEN, no design" to "OPEN, design landed, implementation staged to Run
  117".
- **Updated:** `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — appended a
  Run 116 operator section. **No operator action is required** for Run
  116; the section sets expectations for the Run 117 marker file
  (`<data_dir>/pqc_authority_state.json`) and the new operator-recovery
  workflows that arrive with it.

### 1.2 Code changed

**None.** Run 116 is spec-first. No `.rs` file under `crates/` is
modified. No `Cargo.toml`, no script, no example, no test target is
added or modified.

### 1.3 Storage model changed

**None on disk.** Run 116 specifies the structure and on-disk JSON layout
of `<data_dir>/pqc_authority_state.json` (see §3.2), but does **not**
create any file, add any persistence path, or change any existing file.
The atomic-write primitives that Run 117 will reuse already exist in
`crates/qbind-node/src/pqc_trust_sequence.rs` (Run 055 pattern); no
storage code is added in Run 116.

### 1.4 Tests added

**None.** Run 116 is spec-first per the task. No test target is
created or modified.

### 1.5 Explicit no-runtime-code-change statement

Run 116 explicitly does NOT change any runtime code. The only changes are
to documentation under `docs/`. This is the strongest possible
non-regression guarantee against weakening any of the Run 100–115
invariants (Run 102 genesis verification, Run 103 ratification verifier,
Run 104 key material, Run 105 enforcement body, Run 106 default-strict
policy, Run 107/109/112/114 surface wiring, Run 055 trust-bundle sequence
anti-rollback, Run 097 snapshot epoch parity).

---

## 2. Core security problem (recap)

Runs 100 → 115 have proven that on every local and live trust-bundle
validation / apply surface a bundle-signing key must be ratified by a
genesis-bound bundle-signing authority root before any mutation
(snapshot, swap, session eviction, sequence commit, root merge) can
occur. That is the **authorisation** layer.

Run 116 addresses the **monotonicity** layer: the node must also persist
the highest authority state it has ever accepted, so that an attacker or
operator cannot cause the node to silently re-accept an older / weaker
authority state across:

1. process restart;
2. operator file rollback (overwriting genesis or ratification sidecar
   with an older version on disk);
3. old ratification sidecar reuse (replay of a previously-valid sidecar
   after the authority has rotated forward);
4. snapshot restore;
5. data-dir copy / restore (operator restores a tar of `<data_dir>` from
   an older host);
6. partial crash during authority update (process killed between
   "validated new authority" and "persisted new state");
7. DevNet / TestNet / MainNet environment confusion (e.g. a DevNet
   sidecar handed to a MainNet binary, or a TestNet data-dir mounted into
   a MainNet container).

Without a persistent monotonic marker, the existing Run 100–115 checks
are stateless across boots: a node restarted with an older valid
genesis-authority block + sidecar will accept that older state because it
has nothing to compare against.

---

## 3. Authority anti-rollback model

### 3.1 Required investigation findings

#### 3.1.1 Ratification object sequencing today

`crates/qbind-ledger/src/bundle_signing_ratification.rs::BundleSigningRatification`
(Run 103) currently carries:

- `version: u32` (schema version, currently `1`);
- `chain_id: String`;
- `environment: RatificationEnvironment` (DevNet / TestNet / MainNet);
- `genesis_hash: GenesisHash` (32 bytes, equal to
  `crate::genesis::compute_canonical_genesis_hash`);
- `authority_root_fingerprint: String` (lowercase hex);
- `signature_suite_id: GenesisAuthoritySuiteId` (Run 103 = ML-DSA-44 = 100);
- `bundle_signing_public_key: Vec<u8>` (full 1312-byte ML-DSA-44 PK);
- `bundle_signing_public_key_fingerprint: String` (SHA3-256 hex);
- `signature: Vec<u8>` (2420-byte ML-DSA-44 signature).

It also exposes a canonical, domain-separated preimage and a 32-byte
SHA3-256 digest via `canonical_ratification_preimage` and
`canonical_ratification_digest`. That digest is the canonical
"ratification object hash" referenced by the model below.

**Critical gap:** the ratification object has **no monotonic per-key
field** (no `authority_sequence`, no `key_sequence`, no
`activation_epoch`, no `valid_from` / `valid_until` window). The module
header itself documents this explicitly: *"Run 103 does NOT include
rotation, revocation, anti-rollback sequence numbers, or validity
windows — those are explicitly out of scope per `task/RUN_103_TASK.txt`
'Strict non-goals'"* (`bundle_signing_ratification.rs` lines 162–164).

By contrast, the **genesis-authority block**
`crates/qbind-ledger/src/genesis.rs::GenesisAuthorityConfig` (Run 101)
**does** carry a monotonic anchor:

- `authority_policy_version: u32` (currently `1`);
- `authority_sequence: u64` (monotonic anchor; currently always `0`);
- `authority_epoch: Option<u64>` (optional, hash-bound only at present).

The Run 101 source comment is explicit: *"Monotonic authority-sequence
anchor for Run 102+ anti-rollback. Run 101 hash-binds this value but does
NOT persist it (no `<data_dir>/pqc_authority_state.json` yet)"*
(`genesis.rs` lines 760–764).

**Conclusion.** The genesis-authority block carries the correct monotonic
anchor and the correct binding to chain_id / environment / genesis_hash
already. The ratification object does **not** carry a per-ratification
monotonic field; it carries only the authorising authority root
fingerprint and the bundle-signing public key fingerprint. This is
sufficient to model authority-level anti-rollback in Run 116 (anchored on
the genesis-bound `authority_sequence`), but it is **not** sufficient to
model per-key rotation anti-rollback. Per-key rotation anti-rollback
requires a future schema bump (Run 120) that adds an explicit
`key_issuance_sequence` (or equivalent) field to `BundleSigningRatification`.

Run 116 therefore separates the two:

- **Run 117 / 118 (committed plan):** persist authority-level state
  anchored on `genesis.authority.authority_sequence` and the canonical
  ratification digest of the current ratification object.
- **Run 120 (deferred plan):** schema-bump `BundleSigningRatification` to
  carry an explicit per-key monotonic field before signing-key rotation
  lifecycle lands.

This separation is the documented model decision of Run 116 and is the
reason Run 116 does not implement persistence: implementing it without
making this two-layer separation explicit would risk conflating
authority-level monotonicity with per-key rotation monotonicity.

#### 3.1.2 Existing persistent stores

Run 116 inspected every durable store under `<data_dir>` and the
production `ConsensusStorage` surface:

- **`<data_dir>/pqc_trust_bundle_sequence.json`** (Run 055) — atomic
  tmp+rename writer via `pqc_trust_sequence::atomic_write_record`,
  schema-versioned (`record_version`), chain_id + environment bound,
  bundle-fingerprint anchored. Run 055 already implements the exact
  atomicity discipline Run 117 needs and has been release-binary
  evidenced repeatedly (Run 067/068/093/094/111/113/115).
- **`ConsensusStorage` / RocksDB** (Runs 093–097) — used for ledger
  / consensus state, not for trust / authority. Schema versioning lives
  on the column-family level. Run 116 explicitly does **not** propose
  to place the authority anti-rollback marker inside RocksDB because
  (a) trust-bundle sequence state already lives in a dedicated JSON
  file alongside `<data_dir>` for the same reason — operator
  visibility, atomic single-file replace, and decoupling from
  consensus-storage corruption — and (b) the authority marker must
  remain readable and rejectable by a node that has not yet opened the
  ledger / consensus DB (e.g. on fast-sync restore or first boot
  against a restored snapshot).
- **Snapshot metadata** (Run 097) — already carries `snapshot_epoch`
  parity fields. Run 097's lesson is reused conceptually below
  (§3.6).
- **Node config / CLI flags** — not durable from the node's point of
  view (operator can change them between boots); ineligible.

**Conclusion (persistence location).** The correct persistence surface
for authority anti-rollback state is a new dedicated JSON file at
`<data_dir>/pqc_authority_state.json`, written via the same atomic
tmp+rename + fsync(parent-dir) pattern Run 055 already uses. The Run
055 helpers in `crates/qbind-node/src/pqc_trust_sequence.rs`
(`atomic_write_record`, `load_record`, `validate_record_for_domain`)
are the model. Run 117 will introduce a sibling module
`pqc_authority_state.rs` that mirrors that pattern but for the new
record type defined in §3.2.

#### 3.1.3 Current apply / validation surface interaction

The following surfaces currently enforce Run 105 ratification:

| # | Surface | Enforces ratification | Mutates trust state | Mutates sequence file |
|---|---|---|---|---|
| 1 | Startup trust-bundle load (Run 105/106) | Yes | Yes (initial install of `bundle_signing_authority_roots` into the live PQC trust set) | Yes (Run 055 first-load write) |
| 2 | Reload-check (Run 069 + Run 106) | Yes | No (validation only) | No |
| 3 | Local peer-candidate check (Run 077 + Run 107) | Yes | No (validation only) | No |
| 4 | Live inbound `0x05` peer-candidate validation (Run 088/109) | Yes | No (intentionally non-mutating per Run 109 contract) | No |
| 5 | Process-start reload-apply (Run 070/073 + Run 112) | Yes | Yes | Yes |
| 6 | SIGHUP live reload (Run 074 + Run 114) | Yes | Yes | Yes |

For Run 117 (implementation) the **mutating surfaces** are #1, #5, #6
(the surfaces that already cause a `pqc_trust_bundle_sequence.json`
write). Authority anti-rollback persistence MUST be enforced on these
three surfaces first. The non-mutating surfaces #2, #3, #4 are
validation-only today and Run 116 does **not** make any of them
mutating; however, once a persisted authority-state marker exists, the
validation-only surfaces must still **reject** any candidate that would
roll back the persisted authority state (so that a lower authority state
cannot be silently "validated as acceptable" by an operator running a
preflight). The model below (§3.5) makes this explicit.

#### 3.1.4 Existing sequence anti-rollback relation

The model is **deliberately layered** and must not conflate the
following sequences:

- **Trust-bundle sequence** (Run 055,
  `PersistentTrustBundleSequenceRecord::highest_sequence`): per-bundle
  monotonic counter. Advances when a node accepts a strictly newer
  signed trust bundle. Bound to (chain_id, environment, bundle
  fingerprint). **Does NOT prove anything about which signing key is
  authorised to sign that bundle.** A trust-bundle sequence can advance
  without the authority changing (most common case).
- **Bundle-signing-key ratification** (Run 103,
  `BundleSigningRatification`): the authorisation object that says "this
  authority root permits this bundle-signing key". Carries no monotonic
  field today (§3.1.1).
- **`activation_epoch`** (Runs 091–099): trust-bundle activation height.
  Orthogonal to authority anti-rollback.
- **Genesis `authority_sequence`** (Run 101): monotonic authority-level
  anchor. Hash-bound in the genesis-authority block. Run 117 will
  persist this value in `pqc_authority_state.json`.
- **Future per-key rotation sequence** (Run 120): not in the schema
  today; must be added to `BundleSigningRatification` before signing-key
  rotation lifecycle lands.

Run 116 explicitly refuses to derive authority anti-rollback from the
trust-bundle sequence, because:

- the same trust-bundle sequence can be replayed under a different
  authority context (different genesis-authority block, different
  ratification object) and the trust-bundle sequence alone cannot
  distinguish those;
- the trust-bundle sequence record (Run 055) is bound to (chain_id,
  environment, bundle fingerprint), not to (chain_id, environment,
  genesis_hash, authority_root, ratified_key);
- a future signing-key rotation that ratifies a new key against the
  same authority root MUST advance some monotonic value, but does not
  necessarily advance the trust-bundle sequence (rotation can happen
  with a re-signed but functionally identical bundle).

The two records (`pqc_trust_bundle_sequence.json` and `pqc_authority_state.json`)
are therefore independent and must be updated under independent
ordering rules (§3.4).

#### 3.1.5 Snapshot / restore risk

See §3.6.

### 3.2 Authority state record

Run 117 will introduce a typed record. The Run 116 specification of that
type is **binding** on Run 117. Field names below are normative; the
Rust type name (`PersistentAuthorityStateRecord` is the proposed name,
mirroring `PersistentTrustBundleSequenceRecord`) is suggestive and may
be adjusted by Run 117 to match the final module layout.

```text
PersistentAuthorityStateRecord {
    record_version:                      u32,                    // schema, Run 117 = 1
    chain_id:                            String,                 // 16 lower-hex, matches Run 055 chain_id_hex
    environment:                         AuthorityStateEnvironment, // DevNet | TestNet | MainNet
    genesis_hash:                        [u8; 32],               // canonical genesis hash (Run 102)
    authority_policy_version:            u32,                    // mirrors GenesisAuthorityConfig.authority_policy_version
    authority_sequence:                  u64,                    // mirrors GenesisAuthorityConfig.authority_sequence
    authority_epoch:                     Option<u64>,            // mirrors GenesisAuthorityConfig.authority_epoch
    authority_root_fingerprint:          String,                 // lower-hex SHA3-256 of authorising root PK
    ratified_bundle_signing_key_fingerprint: String,             // lower-hex SHA3-256 of ratified PK
    ratification_object_hash:            [u8; 32],               // canonical_ratification_digest(ratification)
    last_update_source:                  AuthorityStateSource,   // StartupLoad | ReloadApply | LiveReloadSighup
    updated_at_unix_secs:                u64,                    // informational only, never used in policy
}
```

with helper enums:

```text
AuthorityStateEnvironment ∈ { Devnet, Testnet, Mainnet }            // tag-equal to RatificationEnvironment
AuthorityStateSource      ∈ { StartupLoad, ReloadApply, LiveReloadSighup }
```

**On-disk encoding.** Single JSON file at
`<data_dir>/pqc_authority_state.json`. UTF-8, LF line endings,
canonicalised key order to allow operator-side `sha256sum` comparisons
to be meaningful across runs. Byte-by-byte format is fixed by the Run
117 implementation; Run 116 does not pin a literal-bytes spec because
the canonical schema is the Rust struct and the JSON shape follows
serde's default `#[derive(Serialize)]` exactly as `PersistentTrustBundleSequenceRecord`
does today.

**Schema versioning.** `record_version: 1` for Run 117. Any other value
fails closed on load (mirrors `TrustBundleSequenceError::UnsupportedRecordVersion`).

**Optionality.** `authority_epoch` is `Option<u64>` mirroring the
genesis field; absence is distinguishable from presence of `Some(0)`.

**No private keys.** The record never contains private key material,
never contains the full ratification object (only its 32-byte SHA3-256
digest), and never contains the full ratified PK (only its 64-hex
fingerprint).

### 3.3 Monotonic comparison rule

Let `OLD = PersistentAuthorityStateRecord` loaded from disk (may be
absent on first boot) and `NEW = AuthorityStateProposal` derived from
the currently-validated ratification + genesis-authority block.

Run 117 will implement `compare_authority_state(OLD, NEW) -> Decision`
returning:

1. **`FirstLoad`** — `OLD = None`. Accept `NEW`, persist as initial
   marker. Environment-specific safety on first-load is in §3.7.
2. **`EqualIdempotent`** — every field equal (including
   `ratification_object_hash`). Accept, **do not rewrite** the file
   (avoids unnecessary writes and preserves the file's mtime as a
   coarse "last actual change" signal for operators).
3. **`Upgrade`** — `NEW.authority_sequence > OLD.authority_sequence`
   AND (chain_id, environment, genesis_hash) equal AND
   `authority_policy_version` not lower. Accept, persist new record
   atomically.
4. **`RollbackRefused`** — `NEW.authority_sequence < OLD.authority_sequence`.
   **Fail closed.** No mutation. Typed error
   `AuthorityStateError::SequenceRollback { old, new }`.
5. **`SameSequenceConflictingHash`** — `NEW.authority_sequence ==
   OLD.authority_sequence` AND `NEW.ratification_object_hash !=
   OLD.ratification_object_hash`. **Fail closed.** No mutation. Typed
   error `AuthorityStateError::SameSequenceConflictingRatification {
   sequence, old_hash, new_hash }`. This is the equivocation /
   sidecar-swap detection. **No "explicitly allowed" loophole** in Run
   117; if rotation-within-sequence ever becomes legitimate it requires
   the Run 120 schema bump and explicit operator recovery (§3.8).
6. **`SameSequenceConflictingKey`** — same sequence, same ratification
   hash, but different `ratified_bundle_signing_key_fingerprint` (this
   would indicate the ratification hash was computed inconsistently and
   is a corruption signal). **Fail closed.**
7. **`ChainMismatch`** — `NEW.chain_id != OLD.chain_id`. **Fail closed.**
8. **`EnvironmentMismatch`** — `NEW.environment != OLD.environment`.
   **Fail closed.** (DevNet / TestNet / MainNet confusion;
   environment-specific recovery in §3.7.)
9. **`GenesisHashMismatch`** — `NEW.genesis_hash != OLD.genesis_hash`.
   **Fail closed.** This catches genesis-file rollback / replacement.
10. **`PolicyVersionRegression`** — `NEW.authority_policy_version <
    OLD.authority_policy_version`. **Fail closed.** A node that has
    seen policy v2 must refuse to drop back to policy v1.
11. **`Corrupt`** — load-time JSON parse error, schema-version unknown,
    chain_id not 16-hex, fingerprints malformed, etc. **Fail closed.**
    On MainNet / TestNet, the binary exits non-zero. On DevNet, see
    §3.7.

Run 117 will mirror the existing `TrustBundleSequenceError` typed-reason
discipline so operator logs carry a precise reason without any "invalid
authority state" catch-all.

### 3.4 Persistence location, atomicity, and crash consistency

**Location.** `<data_dir>/pqc_authority_state.json` (sibling of
`<data_dir>/pqc_trust_bundle_sequence.json`). Same `<data_dir>` is used
because:

- both records belong to the same "trust" domain of node state;
- both must be readable before any consensus-storage / RocksDB open;
- both must survive `<data_dir>` snapshot / tar round-trip together to
  preserve consistency (§3.6);
- operator tooling already iterates `<data_dir>` for backups.

**Atomicity (per write).** Reuse Run 055 pattern verbatim:

1. Serialize `NEW` to bytes.
2. Write to sibling temp file (`pqc_authority_state.json.tmp.<pid>`).
3. `fsync(tmp_fd)`.
4. `rename(tmp, pqc_authority_state.json)` — atomic on POSIX.
5. `fsync(parent_dir_fd)`.

Run 117 will reuse the `atomic_write_record` shape from
`pqc_trust_sequence.rs` (which already implements steps 1–4 via
`std::fs::rename` and tests crash safety) and add the parent-dir fsync
that Run 055 currently omits — this is a minor strengthening, scoped to
the new file only, and does not change any Run 055 behaviour.

**Ordering relative to the trust-bundle sequence write.** The two
records must be updated in an order that is fail-closed against partial
crash. Define the apply pipeline as the existing Run 070 four-step:

```
validate → snapshot → swap → evict_sessions → commit_sequence
```

Run 117 will insert **`commit_authority_state` after `commit_sequence`**
on the mutating surfaces (startup-load / reload-apply / SIGHUP):

```
validate → snapshot → swap → evict_sessions → commit_sequence → commit_authority_state
```

Crash-consistency analysis of every interleaving:

- **Crash before `commit_sequence`.** Neither file is written. On
  restart: trust state is the prior baseline; authority state is the
  prior baseline. Safe.
- **Crash between `commit_sequence` and `commit_authority_state`.**
  Trust bundle on disk is the new one; authority state on disk is the
  prior one. On restart: the new trust bundle is loaded, ratification
  is re-verified against the supplied (still-new) genesis-authority
  block + sidecar, and the comparison `OLD = prior, NEW = new` runs.
  - If `NEW.authority_sequence > OLD.authority_sequence`, the
    `commit_authority_state` step re-runs and completes — idempotent
    forward progress. **Safe.**
  - If the operator has since rolled the genesis-authority block
    *back* (e.g. they restored an older genesis after the crash), the
    comparison detects `SequenceRollback` and the node exits non-zero
    on MainNet/TestNet — **safe, fail-closed**, no silent acceptance.
- **Crash during `commit_authority_state` (partial tmp file).** The
  tmp+rename protocol guarantees `pqc_authority_state.json` is either
  the prior file or the new file, never a torn file. The orphaned tmp
  is cleaned by Run 117 on next boot (mirrors `pqc_trust_sequence`).

Run 117 will pin each of these three scenarios with a crash-simulation
test that drops the in-process file handle between steps and reloads.

### 3.5 Surface enforcement model

For each Run 105-enforced surface, Run 117 will:

| # | Surface | Mutating? | Run 117 enforcement |
|---|---|---|---|
| 1 | Startup trust-bundle load | Yes | Compare `(genesis + sidecar) → proposal` against `pqc_authority_state.json`. On `FirstLoad`/`Upgrade`/`EqualIdempotent` → continue. On any reject → exit non-zero on MainNet/TestNet, error+exit on DevNet under opt-in, see §3.7. |
| 2 | Reload-check (validation-only) | No | If `pqc_authority_state.json` exists and the candidate would imply a rollback, the reload-check **rejects** with a typed reason. The marker file is **not** mutated by this path. |
| 3 | Local peer-candidate check (validation-only) | No | Same as #2. |
| 4 | Live inbound `0x05` peer-candidate (validation-only) | No | Same as #2. Stays consistent with the Run 109 "intentionally non-mutating" contract. |
| 5 | Process-start reload-apply | Yes | Same as #1; inserted **after** `commit_sequence` (§3.4). |
| 6 | SIGHUP live reload | Yes | Same as #1; inserted **after** `commit_sequence`. |

The validation-only surfaces (#2, #3, #4) are explicitly required to
reject a candidate that would imply a lower / conflicting authority
state, even though they do not write the marker themselves. This is the
operator-preflight guarantee: an operator running a reload-check on a
bad sidecar cannot have the node "say OK" only to then refuse on the
real apply.

Run 116 does **not** wire any of this. Run 116 only specifies it.

### 3.6 Snapshot / restore interaction

QBIND's snapshot mechanism (Run 097) currently carries `snapshot_epoch`
parity metadata so that a restored snapshot cannot be silently mounted
into a node at a different chain epoch.

Run 117 will extend the snapshot-restore contract as follows:

- **Snapshot creation:** if `<data_dir>/pqc_authority_state.json` exists
  at snapshot-time, the snapshot metadata MUST carry a copy of:
  - `chain_id`,
  - `environment`,
  - `genesis_hash`,
  - `authority_policy_version`,
  - `authority_sequence`,
  - `authority_epoch`,
  - `authority_root_fingerprint`,
  - `ratification_object_hash`.

  If the marker is absent at snapshot-time (e.g. snapshot taken before
  Run 117), the metadata records "absent" explicitly (not silently).

- **Snapshot restore:**
  - If the restored snapshot's authority metadata is **higher** than
    the node's existing `pqc_authority_state.json`, restore is allowed
    and the marker is updated to the restored value (forward progress).
  - If the restored snapshot's authority metadata is **lower or
    conflicting**, restore **fails closed** with a typed error and
    requires an **explicit operator recovery procedure** (§3.8). No
    silent rollback. This is the direct generalisation of the
    "old snapshot must not silently roll back authority state"
    requirement.
  - If the restored snapshot lacks authority metadata (legacy /
    pre-Run-117 snapshot) **and** the node has a populated
    `pqc_authority_state.json`, the restore fails closed. Operator
    must either (a) re-take the snapshot on a Run-117+ binary or (b)
    invoke the explicit operator-recovery `--allow-authority-state-reset`
    flag (§3.8), which Run 117 defines.
  - If the restored snapshot lacks authority metadata **and** the node
    has no `pqc_authority_state.json`, restore proceeds and the
    `pqc_authority_state.json` is populated from the next valid
    startup-load (FirstLoad path).

- **Data-dir copy / restore (operator-level tar of `<data_dir>`).** The
  `pqc_authority_state.json` is part of `<data_dir>` and is therefore
  carried with the trust-bundle sequence file. The two travel together,
  so naive `tar`-based recovery preserves the (trust-bundle, authority)
  pair consistently. The operator-recovery flag for the asymmetric case
  (operator copies a fresh trust-bundle sequence file but forgets the
  authority file, or vice versa) is in §3.8.

The conceptual reuse of Run 097's `snapshot_epoch` parity lesson is:
**the snapshot must carry enough authority-context metadata for the
restore to verify it is forward-only, and the restore must fail closed
on any backward step.**

### 3.7 Environment policy

The Run 106 / Run 112 / Run 114 per-environment policy is reused
verbatim for the authority anti-rollback marker.

| Env | First-boot (marker absent) | Missing on subsequent boot (had been present) | Corrupt | Rollback / conflicting | Opt-in flag |
|---|---|---|---|---|---|
| **MainNet** | FirstLoad write, mandatory | FATAL — exit non-zero. (Disappearance ≡ rollback.) | FATAL | FATAL | n/a (always enforced) |
| **TestNet** | FirstLoad write, mandatory | FATAL | FATAL | FATAL | n/a (always enforced) |
| **DevNet (default, no opt-in)** | No-op — marker not written, not checked. Preserves Run 089 / Run 106 DevNet ergonomics bit-for-bit. | n/a (not written) | n/a | n/a | not present |
| **DevNet (opt-in `--p2p-trust-bundle-ratification-enforcement-enabled`)** | FirstLoad write | FATAL | FATAL | FATAL | required for enforcement |

Key invariants:

- **Local config alone is never enough on MainNet.** The marker is
  derived from the operator-supplied genesis-authority block (which
  must be hash-bound by `--expect-genesis-hash` per Run 102) plus the
  operator-supplied ratification sidecar (Run 105). The marker is just
  the persisted *outcome* of those two operator-supplied inputs being
  validated; it is not an authority anchor on its own.
- **No fallback authorities.** Missing marker on a node that previously
  had one is never silently re-bootstrapped. The operator MUST use the
  explicit recovery procedure (§3.8).
- **No "DevNet promotion".** A DevNet `pqc_authority_state.json` is
  bound to `environment = Devnet`; mounting that data-dir into a
  TestNet or MainNet binary triggers `EnvironmentMismatch` and exits
  non-zero. This addresses risk (7) "DevNet/TestNet/MainNet environment
  confusion".

### 3.8 Explicit operator recovery procedure (Run 117 contract)

Run 117 will define a single operator-recovery flag with this exact
semantic:

```
--allow-authority-state-reset
```

When supplied:

- The node logs a structured `[run-117] OPERATOR-RECOVERY` line naming
  the path, the prior marker fingerprint, and the operator-supplied
  recovery reason from a sibling flag (`--authority-state-reset-reason
  <string>`, mandatory when `--allow-authority-state-reset` is
  supplied).
- The node deletes the existing `pqc_authority_state.json` atomically
  (rename-out-of-the-way then unlink) and continues the boot as if it
  were `FirstLoad`. The first valid startup-load then writes the new
  marker.
- The recovery flag is single-shot and is required again on the next
  recovery; the binary does **not** persist "recovery acknowledged"
  across boots. The flag is honoured on every environment including
  MainNet — there is no `local-config-alone-grants-MainNet-authority`
  loophole, because the post-reset state still requires a valid Run
  105 sidecar + valid Run 102 genesis to validate, and any of those
  failing still exits non-zero.
- The recovery flag is the **only** way the marker is ever deleted by
  the binary. The marker is never auto-pruned, never time-expired, and
  never bypassed by any other flag.

Run 116 specifies this flag; Run 117 implements it.

---

## 4. Run 117 → Run 120 implementation plan

Concrete staged plan (sizes are scope, not effort estimates):

| Run | Title | Allowed scope |
|---|---|---|
| **Run 117** | Implement authority anti-rollback persistent marker | New module `crates/qbind-node/src/pqc_authority_state.rs` mirroring `pqc_trust_sequence.rs`. Types `PersistentAuthorityStateRecord`, `AuthorityStateError`, `AuthorityStateSource`. APIs `load`, `validate_for_domain`, `compare_authority_state`, `atomic_write_record`, `peek`, `apply_with_check`. Snapshot-metadata extension per §3.6. **No surface wiring yet.** Targeted unit tests covering every §3.3 decision and every §3.4 crash interleaving. |
| **Run 118** | Wire marker checks into mutating surfaces | Insert `commit_authority_state` after `commit_sequence` on startup-load, process-start reload-apply, and SIGHUP live reload. Wire validation-only rejection on reload-check, local peer-candidate check, and live `0x05` validation. Implement `--allow-authority-state-reset` and `--authority-state-reset-reason`. Integration tests on each surface mirroring the Run 112 / Run 114 style. **No release-binary evidence yet.** |
| **Run 119** | Release-binary evidence for rollback rejection | Evidence-only harness + fixture helper (mirrors Run 113 / Run 115 style). Scenarios: first-write accepted; equal idempotent; lower-sequence rejected; same-sequence different-hash rejected; wrong-chain / wrong-environment / wrong-genesis-hash rejected; corrupt marker rejected; snapshot-restore happy path; snapshot-restore backward rejected; data-dir copy of mismatched files rejected; `--allow-authority-state-reset` happy path; missing reason flag rejected. |
| **Run 120** | Signing-key rotation object / lifecycle (schema-first) | Schema-bump `BundleSigningRatification` to v2 carrying an explicit per-key monotonic field (e.g. `key_issuance_sequence: u64`). Backwards-compatible verifier (accepts v1 as `key_issuance_sequence = 0` only on a single-key cluster; refuses v1 once any v2 has been seen). This is the **prerequisite** for the future signing-key rotation lifecycle and the per-key-sequence anti-rollback layer that complements the per-authority-sequence anti-rollback Run 117 implements. |
| **Later** | Revocation lifecycle; KMS/HSM custody; peer-driven live apply; fast-sync / consensus-storage-restore ratification parity; governance; validator-set rotation. | Out of scope for Run 116–120. |

The Run 117 / 118 / 119 sequence mirrors the proven Run 105 / 106 /
107–109 / 113 / 115 cadence: define the primitive, wire it into
surfaces, then release-binary-evidence it.

---

## 5. What Run 116 actually proved

Run 116 is **spec-first** and produces only design / evidence proof:

### 5.1 Source-level proof

- The Run 103 ratification object **does not** carry a per-key
  monotonic field (`bundle_signing_ratification.rs` lines 162–218); the
  module header explicitly states this is by design and deferred.
- The Run 101 genesis-authority block **does** carry an
  `authority_sequence: u64` anchor and an `authority_epoch: Option<u64>`
  (`genesis.rs` lines 760–768) and the source comment names the file
  this run specifies: *"no `<data_dir>/pqc_authority_state.json` yet"*.
- The Run 055 trust-bundle sequence store
  (`pqc_trust_sequence.rs::atomic_write_record`,
  `load_record`,
  `validate_record_for_domain`) provides a reusable atomic-write +
  schema-versioned + chain/env-bound record-store pattern that Run 117
  can mirror verbatim.
- Every Run 105-enforced surface (Runs 105 / 107 / 109 / 112 / 114) is
  classified in §3.1.3 as mutating or non-mutating, and the
  corresponding Run 117 wiring is specified surface-by-surface.

### 5.2 Test proof

No tests run (no code changed). Run 116's spec is the input contract
for Run 117's tests; Run 117 will run the targeted unit and integration
suites listed in §4.

### 5.3 Docs / design proof

- Authority state record (§3.2): exact normative field list.
- Monotonic comparison rule (§3.3): 11 enumerated decision variants,
  each typed and fail-closed.
- Persistence location (§3.4): `<data_dir>/pqc_authority_state.json`,
  Run 055 atomic-write pattern, parent-dir fsync addition.
- Crash consistency (§3.4): three interleavings enumerated and shown
  to be fail-closed or idempotent.
- Surface enforcement (§3.5): per-surface decision matrix.
- Snapshot / restore (§3.6): forward-only contract; restored-without-metadata
  fail-closed; operator-recovery flag.
- Environment policy (§3.7): MainNet / TestNet / DevNet matrix.
- Operator recovery procedure (§3.8): `--allow-authority-state-reset`
  + mandatory `--authority-state-reset-reason`.
- Future implementation plan (§4): Run 117 / 118 / 119 / 120
  staged scopes.

### 5.4 Release-binary evidence

None in Run 116 (spec-first; the task explicitly allows this). Run 119
will land release-binary evidence for the rollback rejection
scenarios.

---

## 6. What was not changed

Run 116 explicitly confirms:

- **No peer-driven live apply.** The `0x05` peer-candidate apply path
  remains intentionally non-mutating per the Run 109 contract.
- **No signing-key rotation lifecycle.** Rotation requires the Run 120
  schema bump; Run 116 only documents the gap and stages the future
  run.
- **No signing-key revocation lifecycle.** Out of scope; the model
  documents that the marker carries `ratification_object_hash`, which
  is the natural pin against which a future revocation list will be
  compared.
- **No KMS / HSM custody.** Out of scope.
- **No governance.** Out of scope.
- **No validator-set rotation.** Out of scope.
- **No trust-bundle wire-format change.** No bytes on the
  `--p2p-trust-bundle` JSON or on the `0x05` envelope are touched.
- **No peer-candidate wire-format change.** Same.
- **No full C4 closure.** Authority anti-rollback persistence is one
  C4 sub-item; the design lands in Run 116, the implementation does
  not.
- **No C5 closure.** Unchanged.
- **No weakening of any Run 100–115 invariant.** No file under
  `crates/` is touched; every existing test target on the codebase
  remains exactly as Run 115 left it.

---

## 7. Contradictions or inconsistencies

Run 116 was cross-checked against:

- **Run 100 authority model** (`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`):
  Run 100 §8 already names "authority anti-rollback persistence" as a
  required Run 102+ topic and §13 already names the future operator
  recovery procedure as a model component. Run 116 narrows both, no
  contradiction.
- **Run 101 genesis authority implementation**: the genesis block
  already exposes `authority_sequence` and `authority_epoch` and the
  source comment names the file path Run 116 specifies. **Consistent.**
- **Run 102 boot verification**: Run 116 reuses the canonical genesis
  hash exactly as Run 102 binds it; no genesis-verification semantics
  change. **Consistent.**
- **Run 103 verifier**: Run 116 documents the per-key monotonic gap in
  `BundleSigningRatification` and defers schema bump to Run 120. **No
  weakening** of Run 103's typed reject reasons; the new
  `AuthorityStateError` variants are strictly additive at a different
  layer (post-verifier).
- **Run 104 key material registry**: Run 116 stores only a fingerprint
  of the ratified key, not the full PK, so no parallel key registry is
  introduced. **Consistent** with Run 104's "authority-key registry
  resolves fingerprints to full PKs" contract.
- **Run 105–115 ratification enforcement / evidence**: Run 116 wires
  nothing new and weakens nothing. The Run 117 wiring plan (§3.5) is
  strictly additive: validation-only surfaces become *stricter* (they
  gain a rejection condition they did not have); mutating surfaces gain
  one extra `commit_authority_state` step after `commit_sequence`,
  preserving the Run 070 four-step ordering bit-for-bit.
- **contradiction.md**: every C4 sub-item that was OPEN before Run 116
  remains OPEN after Run 116, except that "authority anti-rollback
  persistence" narrows from "no design" to "design landed,
  implementation staged".
- **`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`**: no operator
  workflow changes in Run 116. The Run 116 operator section names the
  future `pqc_authority_state.json` and the future
  `--allow-authority-state-reset` flag so operators have advance
  notice.

**No contradictions found.** No silent regressions.

One artifact-hygiene observation is recorded in §9.1 (Run 115 summary
was verified correct, not stale).

---

## 8. Evidence references

- **This document:** `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_116.md`.
- **Authority model update:** `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
  (Run 116 update section appended).
- **Contradictions:** `docs/whitepaper/contradiction.md` (Run 116 C4 update
  appended).
- **Operator runbook:** `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
  (Run 116 operator section appended).
- **Source citations in this document:**
  - `crates/qbind-ledger/src/bundle_signing_ratification.rs` lines
    162–218 (Run 103 schema, no monotonic field), 292–326 (canonical
    preimage / digest), 360–410 (typed reject reasons).
  - `crates/qbind-ledger/src/genesis.rs` lines 755–791 (Run 101
    `GenesisAuthorityConfig` with `authority_sequence`,
    `authority_epoch`, and the `pqc_authority_state.json` source
    comment).
  - `crates/qbind-node/src/pqc_trust_sequence.rs` lines 140–250
    (`PersistentTrustBundleSequenceRecord`), 392–602 (`load_record`,
    `validate_record_for_domain`, `atomic_write_record`,
    `check_and_update_sequence`).
- **Tests run:** none (spec-first; no runtime code change). The
  existing test corpus is unchanged; Run 115's pinned counts
  (`qbind-ledger --lib` 222/0, `qbind-crypto --lib` 68/0, plus the per-run
  suites) remain valid because no source file under `crates/` is
  modified.
- **Release-binary logs:** none in Run 116. Run 119 will produce them.

---

## 9. Residual risks and next recommended run

### 9.1 Artifact-hygiene check on the Run 115 archive

The Run 116 task explicitly required: *"Before starting Run 116, ensure
the Run 115 archive's `summary.txt` is the correct Run 115 summary, not
a stale Run 113 summary. If still stale, fix that artifact hygiene issue
first and document the correction in Run 116 evidence."*

Verified:
`docs/devnet/run_115_sighup_ratification_release_binary/summary.txt`
contains the correct Run 115 SIGHUP-ratification scenario ledger (10
scenarios, MainNet valid / missing / bad-signature / wrong-chain /
wrong-environment / unknown-authority / DevNet legacy / DevNet opt-in
valid / DevNet opt-in missing / repeated-trigger; release-binary sha256
`c9680b3cff34fc4def081bd7ec5a55650863652ccade7ec5db95e30c3b9b30b0`).
The summary is **not** a stale Run 113 reload-apply summary. **No
correction was needed; no archive file was modified by Run 116.** This
record is the documented evidence of that check.

### 9.2 Residual risks (honest list)

- **`BundleSigningRatification` carries no per-key monotonic field**
  (§3.1.1). Run 117 / 118's authority-level marker addresses
  authority-rotation rollback but **does not** address a hypothetical
  "same authority, different ratified key, no rotation event" attack
  on a single authority block. This is intentional and is the explicit
  reason Run 120 is staged before any signing-key rotation lifecycle
  lands. Until Run 120, the system **must not** advertise signing-key
  rotation as supported.
- **Snapshot mechanism interaction is specified, not implemented.**
  The Run 097 snapshot metadata extension (§3.6) requires Run 117 (or
  a sibling run alongside it) to actually emit and verify the
  authority-context fields on every snapshot. Run 116 specifies the
  contract; if Run 117 ships the marker without the snapshot
  extension, the snapshot-restore-backward attack remains possible.
  Run 117's task statement MUST therefore include the snapshot-metadata
  extension as a non-negotiable part of the implementation.
- **`--allow-authority-state-reset` is a powerful flag.** It is the
  documented operator-recovery loophole and must be used only with a
  recorded reason. Run 117 will emit a structured log line on use;
  Run 119 evidence MUST include a positive scenario for the flag and a
  negative scenario for missing `--authority-state-reset-reason`.
- **Operator awareness gap.** Until Run 117 ships, operators have no
  way to detect a rollback attempt on a fresh boot (the system is
  stateless across boots today). The runbook section (§ Run 116
  operator update) makes this gap explicit so MainNet operators are
  not surprised by it.
- **No production runtime change in Run 116.** The Run 100–115
  authorisation layer is unchanged. Anything Run 115 authorised today
  is still authorised after Run 116; anything Run 115 refused is still
  refused after Run 116.

### 9.3 Next recommended run

**Run 117 — implement the `pqc_authority_state.json` persistent marker
+ snapshot-metadata extension, no surface wiring yet.** This matches
the task-statement staging (§4) and the proven Run 100 → 103 → 105 →
106 → 107 → 109 → 112 → 114 cadence: define the primitive, then wire,
then evidence.

If Run 117 turns out to be too large in one PR, the safe split is:

- Run 117a — `PersistentAuthorityStateRecord` + atomic-write +
  `compare_authority_state` + unit tests.
- Run 117b — snapshot-metadata extension + `--allow-authority-state-reset`
  + integration tests.

Either split is acceptable; the un-split form is the default.

---

## 10. Verdict

**positive** — Run 116 delivers a complete spec-first authority
anti-rollback persistence model. Every required design output (§3.2 →
§3.8), every required investigation question (§3.1.1 → §3.1.5), and
every required deliverable (§1.1) is in this document or in the
companion docs. No runtime code changed; no Run 100–115 invariant is
weakened. The next implementation runs (Run 117 → Run 120) are scoped.