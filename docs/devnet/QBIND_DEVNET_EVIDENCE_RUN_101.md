# QBIND Run 101 — DevNet Evidence: Genesis Authority Fields and Boot-Time Genesis Hash Binding

**Run:** 101
**Status:** Implementation step 1 after Run 100 design.
**Date:** 2026-05-21
**Verdict:** partial-positive (see §9).
**Scope:** Implements additive genesis authority fields, canonical
domain-separated genesis hash, per-environment boot-time refusal rules. Does
**not** implement bundle-signing-key ratification, KMS/HSM custody,
peer-driven live apply, governance, or anti-rollback persistence beyond
hash binding (those remain Run 102–106+ per Run 100 §13).

This document is the canonical evidence record for Run 101 and the
companion to:

- `task/RUN_101_TASK.txt` — the run definition.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — the Run 100 spec
  that Run 101 begins to implement (see Run 101 update appended to §13 and
  §16 in that document).
- `docs/whitepaper/contradiction.md` — Run 101 update, C4 narrowing.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 101 row appended to
  §11 mapping and prose note.

When this document and any of the above disagree, the trust-bundle binary
in `crates/qbind-node` wins; the conflicting document is a defect.

---

## 1. Investigation summary

Per task §"Required investigation":

### 1.1 Existing genesis config

- **Struct:** `qbind_ledger::genesis::GenesisConfig`
  (`crates/qbind-ledger/src/genesis.rs:447–489` pre-Run 101 / extended in
  Run 101).
- **Genesis load path:** indirect today — the release binary
  `crates/qbind-node` accepts `--genesis-path` (`cli.rs:833`) and stores it
  in `node_config.rs` `GenesisSourceConfig` (`node_config.rs:2515`). The
  loaded `GenesisConfig` is consumed by the embedded/external code path.
- **File format:** JSON (`serde_json` + `#[derive(Deserialize)]`).
- **chain_id representation:** `String` (`GenesisConfig.chain_id`); the
  runtime side uses `qbind_types::ChainId` / `NetworkEnvironment`
  (`qbind-types/src/primitives.rs:102`).
- **Environment representation:** `qbind_types::NetworkEnvironment`
  (Devnet / Testnet / Mainnet). Maps to ASCII scope `DEV` / `TST` / `MAIN`
  used by domain-separated digests across the project.
- **Validator-set genesis fields:** `GenesisConfig.validators:
  Vec<GenesisValidator>` (existing, preserved).
- **Genesis hash:** existing T233 file-bytes hash
  `compute_genesis_hash_bytes` (`genesis.rs:753`,
  `ledger lib.rs:142`) — kept unchanged; new canonical hash added beside it
  (see §2 below).
- **Canonical serialization:** none pre-Run 101. Run 101 adds the smallest
  canonical helper with domain separation `QBIND:GENESIS:v1` (§2).
- **Used by release-binary startup:** yes — `expected_genesis_hash` is part
  of `NodeConfig` (`node_config.rs:3985`), with MainNet refusal if missing
  (`node_config.rs:5868`, error variant
  `MainnetConfigError::ExpectedGenesisHashMissing`). Run 101 preserves this
  enforcement bit-for-bit.

### 1.2 Current trust-anchor authority inputs

Classification (per Run 100 spec §4 plus Run 101 verification):

| Input                            | Classification           | Run 101 change |
|----------------------------------|--------------------------|----------------|
| `--p2p-trust-bundle`             | production intended      | unchanged      |
| `--p2p-trusted-root`             | DevNet/TestNet only      | unchanged      |
| signed trust-bundle roots        | production intended      | unchanged      |
| bundle-signing key config        | not yet ratified         | unchanged      |
| DevNet helper-generated roots    | DevNet/TestNet only      | unchanged      |
| peer-candidate bundles           | validation-only (Run 088)| unchanged      |
| reload-check / reload-apply      | local operator surface   | unchanged      |
| static/test roots                | test fixture only        | unchanged      |
| genesis-related trust fields     | **introduced by Run 101**| `authority` block added |

Run 101 introduces the *genesis-bound* surface only; none of the existing
inputs are weakened, re-routed, or made fall-back-capable.

### 1.3 Genesis hash / canonicalization risks

- Pre-Run 101 `compute_genesis_hash_bytes` is a hash of the *exact file
  bytes*. Risks: any whitespace/key-ordering edit changes the hash even if
  the structured content is identical. The existing T233 surface (and
  `--expect-genesis-hash`) is the operator's canonical reference and is
  preserved bit-for-bit.
- Run 101 adds `compute_canonical_genesis_hash(&GenesisConfig, env)` with
  the `QBIND:GENESIS:v1` domain tag and explicit length-prefixed framing of
  every field (chain_id, env scope, allocations, validators, council,
  monetary, authority) so the canonical hash is stable across JSON
  whitespace differences and includes the authority block. The two hashes
  coexist; Run 102+ ratification objects will bind to the canonical one.

### 1.4 Authority field schema

Implemented in `qbind_ledger::genesis::{GenesisAuthorityConfig,
GenesisAuthorityRoot}` (`crates/qbind-ledger/src/genesis.rs`, Run 101
additions). Fields, types, encoding, validation, and Run-101-vs-Run-102+
consumption are documented in §2 of this file and in the rustdoc on the
types themselves.

### 1.5 Boot-time enforcement point

Today the boot order, before Run 101, is:

```
parse CLI → build NodeConfig → validate_mainnet_invariants (incl.
    ExpectedGenesisHashMissing check) → load genesis JSON → compute
    file-bytes genesis hash → compare to expected_genesis_hash → continue
    startup → trust-bundle processing / network startup
```

Run 101 adds, **at the boundary `qbind_ledger::verify_boot_time_genesis`**,
authority + canonical-hash enforcement. The release-binary integration
point in `qbind-node` is unchanged in Run 101: the new helper is exposed
as a public function and exercised end-to-end by
`crates/qbind-node/tests/run_101_genesis_authority_tests.rs`. The pre-Run
101 `MainnetConfigError::ExpectedGenesisHashMissing` MainNet refusal
remains in place; Run 102 will wire the canonical-hash refusal into the
same pre-network startup point. This staging is documented honestly as
the reason the verdict is **partial-positive** rather than positive.

---

## 2. What was implemented

### 2.1 Files changed

| File                                                          | Change |
|---------------------------------------------------------------|--------|
| `crates/qbind-ledger/src/genesis.rs`                          | Additive: `GenesisAuthorityRoot`, `GenesisAuthorityConfig`, `NetworkEnvironmentPolicy`, `GenesisAuthorityValidationError`, `BootGenesisVerificationError`, `BootGenesisVerification`, `GenesisAuthorityRootKind`, `compute_canonical_genesis_hash`, `verify_boot_time_genesis`, `GENESIS_AUTHORITY_*` constants, `CANONICAL_GENESIS_HASH_DOMAIN_V1`, `authority: Option<GenesisAuthorityConfig>` field on `GenesisConfig` (`#[serde(default)]`), `GenesisValidationError::AuthorityValidationFailed(_)` variant, `GenesisConfig::validate_for_environment`. 24 new unit tests.                       |
| `crates/qbind-ledger/src/lib.rs`                              | Re-exports for the new types and helpers.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `crates/qbind-node/tests/run_101_genesis_authority_tests.rs`  | New: 11 release-binary-facing integration tests covering Scenarios 1–5 plus additional refusal coverage.                                                                                                                                                                                                                                                                                                                                                                                              |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_101.md`                | New: this evidence document.                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `docs/devnet/run_101_genesis_authority_evidence/*.log`        | New: release-binary CLI evidence (see §5).                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`         | Run 101 update appended (§13/§16) — narrows status of "initial production authority comes from a genesis configuration file bound by a boot-time cryptographic hash" from spec-only to *implemented for fields/hash/validation, not yet consumed by live ratification*.                                                                                                                                                                                                                                |
| `docs/whitepaper/contradiction.md`                            | Run 101 update appended — narrows C4 sub-piece "genesis-bound authority root surface and boot-time hash binding" from OPEN to partial-positive (fields + canonical hash + per-env refusal land; ratification verifier, KMS/HSM, anti-rollback persistence beyond hash binding, peer-driven apply remain OPEN).                                                                                                                                                                                          |
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`               | Run 101 row appended to the mapping table; prose note pointing at this evidence document and at the new `authority` field shape; explicit non-claims restated.                                                                                                                                                                                                                                                                                                                                         |

**No changes** to: trust-bundle wire format, peer-candidate wire format,
KEMTLS, consensus message formats, `activation_epoch` semantics, Run 065
minimum-margin policy, revocation, reload-check non-mutation, reload-apply
ordering, monetary/economic model, or any source-code static authority
constant. **No new dependency, no new CLI flag, no new metric, no new
`Cargo.toml` edit.**

### 2.2 Genesis fields added

- `GenesisConfig.authority: Option<GenesisAuthorityConfig>` —
  backward-compatible via `#[serde(default)]`. Existing DevNet/legacy JSON
  files without this key continue to parse and validate on DevNet (see
  test `test_backward_compat_legacy_json_without_authority_parses`).
- `GenesisAuthorityConfig { authority_policy_version: u32,
  authority_sequence: u64, authority_epoch: Option<u64>,
  pqc_transport_roots: Vec<GenesisAuthorityRoot>,
  bundle_signing_authority_roots: Vec<GenesisAuthorityRoot> }`.
- `GenesisAuthorityRoot { suite_id: u8, key_fingerprint: String,
  label: String, not_before_epoch: Option<u64> }`.

### 2.3 Canonical hash changes

New function `compute_canonical_genesis_hash(&GenesisConfig, env)`
returning `[u8; 32]`. Domain-separated by `b"QBIND:GENESIS:v1"`. Hashes:

```
SHA3-256(
    "QBIND:GENESIS:v1"
  || u32_be(env_scope_len)    || env_scope_bytes
  || u32_be(chain_id_len)     || chain_id_bytes
  || u64_be(genesis_time_unix_ms)
  || u32_be(allocation_count) || allocations_canonical_bytes
  || u32_be(validator_count)  || validators_canonical_bytes
  || u32_be(council_threshold)|| council_canonical_bytes
  || monetary_canonical_bytes
  || authority_canonical_bytes  -- empty framed block if authority is None
)
```

Every variable-length string is length-prefixed; every optional field
carries a discriminator byte so `None` ≠ `Some("")` and `None authority` ≠
`Some empty authority` (test:
`test_canonical_hash_distinguishes_none_vs_empty_authority`).

The existing file-bytes `compute_genesis_hash_bytes` (T233) is preserved
unchanged and remains the operator-facing `--expect-genesis-hash` target;
the canonical hash is exposed for Run 102+ ratification binding.

### 2.4 Expected hash verification

`verify_boot_time_genesis(env, &GenesisConfig, Option<&GenesisHash>)`:

- MainNet: refuses missing `expected_canonical_hash`
  (`BootGenesisVerificationError::ExpectedCanonicalHashMissing`).
- MainNet/TestNet: refuses any mismatched `expected_canonical_hash`
  (`CanonicalHashMismatch`).
- All envs: refuses malformed expected hash through the existing
  `parse_genesis_hash` parser at the CLI boundary
  (`crates/qbind-node/src/cli.rs:1535` →
  `cli::CliError::InvalidGenesisHash`).
- DevNet: allows missing expected hash (explicit non-production behavior;
  the boot-time helper logs nothing on its own, but operators can wrap it
  with the existing DevNet banner).

### 2.5 Authority validation

`GenesisConfig::validate_for_environment(env)` runs the existing structural
validation **plus** `GenesisAuthorityConfig::validate_for_environment` when
applicable. Refusals on MainNet:

- missing authority block → `Missing { env: Mainnet }`
- empty `bundle_signing_authority_roots` → `EmptyBundleSigningRoots`
- non-ML-DSA-44 `suite_id` → `UnsupportedSuite`
- short / non-hex / oversized / odd-length `key_fingerprint` →
  `MalformedFingerprint`
- empty `label` → `EmptyLabel`
- empty `key_fingerprint` → `EmptyFingerprint`
- duplicate `(suite_id, key_fingerprint)` pair across the combined set →
  `DuplicateAuthorityRoot`
- `authority_policy_version == 0` or `> 1` → `InvalidPolicyVersion`
- chain_id without `"mainnet"` substring on MainNet (or `"testnet"` on
  TestNet) → `BootGenesisVerificationError::ChainEnvironmentMismatch`

TestNet relaxes only the absence of `pqc_transport_roots`; everything else
matches MainNet. DevNet is permissive (legacy local tests preserved).

### 2.6 MainNet refusal behavior

Strict, fail-closed, before any trust-bundle or network startup work can
take an authority-dependent action. Run 101 routes this through the
public helper `verify_boot_time_genesis`; the release-binary integration
point that calls this helper from the boot sequence is the
**only** place that authority-dependent behavior can branch off. (Wiring
that call into the `async_runner` startup happens as the small
follow-on in Run 102 alongside the ratification verifier; this is the
single reason Run 101 ships as partial-positive rather than positive —
see §6 verdict.)

### 2.7 DevNet/TestNet behavior

- **DevNet:** missing `authority` block remains accepted; missing
  expected canonical hash remains accepted; helper-generated short
  fingerprints accepted; behavior matches Run 100 spec §7.1.
- **TestNet:** authority required; canonical hash recommended but not yet
  forced when absent (Run 101 partial-positive — Run 100 spec §7.2
  describes this as the *intermediate* TestNet state allowed during the
  101→102 transition).

### 2.8 CLI / config additions

**None.** Run 101 reuses the existing
`--genesis-path` / `--expect-genesis-hash` / `--print-genesis-hash` CLI
surface (`crates/qbind-node/src/cli.rs:833–871`). No new flag is added.
No new metric family is introduced.

### 2.9 Failure behavior

All failure paths produce distinct error variants with precise operator
messages (`Display` implementations on `GenesisAuthorityValidationError`
and `BootGenesisVerificationError`) — no vague "invalid config" string.
The exhaustive variant set is given in §2.5.

---

## 3. What was proven

### 3.1 Source-level proof

- `crates/qbind-ledger/src/genesis.rs`: new types, validation, canonical
  hash, and boot helper compile cleanly with no new warnings introduced
  by Run 101. Existing `qbind-node` build remains warning-free w.r.t.
  Run 101 surface (the two unrelated pre-Run-101 `bincode::config`
  deprecation warnings predate this run).

### 3.2 Test proof

```
cargo test -p qbind-ledger --lib genesis::
  → 40 passed; 0 failed   (16 pre-existing + 24 new Run 101)

cargo test -p qbind-node --test run_101_genesis_authority_tests
  → 11 passed; 0 failed   (Scenarios 1–5 + extra refusal coverage)

cargo test -p qbind-node --test t232_genesis_mainnet_profile_tests
  → 7 passed; 0 failed    (T232 regression)

cargo test -p qbind-node --test t233_genesis_cli_tests
  → 16 passed; 0 failed   (T233 regression — --print-genesis-hash,
                           --expect-genesis-hash, MainNet refusal)

cargo test -p qbind-ledger --lib
  → 177 passed; 0 failed  (full ledger lib regression)

cargo test -p qbind-genesis
  → 6 passed; 0 failed    (genesis crate regression)

cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests \
                          --test run_091_pqc_trust_bundle_activation_epoch_tests \
                          --test run_098_activation_epoch_canonical_wiring_tests
  → all passed; 0 failed  (Run 050 / 091 / 098 trust-bundle lifecycle
                           regression — no behaviour change)
```

### 3.3 Release-binary evidence proof

| Scenario                                                                | Outcome                                                                                                                                                                                                  |
|-------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **1. DevNet legacy path remains explicit**                              | PASS — `run_101_scenario_1_devnet_legacy_path_remains_usable` exercises the public `qbind_ledger::verify_boot_time_genesis` path the release binary links against; DevNet with no authority+no expected hash succeeds. |
| **2. MainNet missing expected hash rejects**                            | PASS — `run_101_scenario_2_mainnet_missing_expected_hash_rejects` proves `BootGenesisVerificationError::ExpectedCanonicalHashMissing { env: Mainnet }` fires; the existing release-binary MainNet refusal (`MainnetConfigError::ExpectedGenesisHashMissing`) continues to apply at the higher CLI layer (T233 regression unchanged). |
| **3. MainNet hash mismatch rejects**                                    | PASS — `run_101_scenario_3_mainnet_hash_mismatch_rejects` proves `CanonicalHashMismatch` fires before any authority is accepted; release-binary CLI evidence in `scenario_3_malformed_expected_hash.stderr.log` shows the binary rejects a malformed `--expect-genesis-hash` at startup with a precise message and exits with code 1.            |
| **4. MainNet missing authority rejects**                                | PASS — `run_101_scenario_4_mainnet_missing_authority_rejects` proves the authority error surfaces *before* the canonical hash compare even when the operator supplies a matching expected hash; no fallback root path can mask a missing authority block.                                                                                          |
| **5. MainNet valid genesis authority passes boot validation**           | PASS — `run_101_scenario_5_mainnet_valid_genesis_passes` proves a valid MainNet genesis with `authority` block and a matching canonical hash passes `verify_boot_time_genesis`; no static source-code anchor is consulted (grep audit in §4 confirms).                                                                                              |
| **Auxiliary: release-binary CLI surface unchanged**                     | PASS — `scenario_0_cli_help_genesis_surface.txt` snapshots `--genesis-path`, `--print-genesis-hash`, `--expect-genesis-hash` from the release binary; no new CLI flags were added by Run 101.                                                                                                                                                       |

Full release-binary N-node MainNet boot is not produced in this run; that
is reserved for Run 104 release-binary rotation/revocation evidence per
Run 100 spec §13 staging. Run 101 produces release-binary-facing evidence
via the public-API path that the release binary links against and via the
CLI smoke logs.

---

## 4. Key security decisions

- **No production static source-code anchors.** Grep audit:
  `git grep -nE 'pqc_transport_root|bundle_signing_authority_root'
  crates/**/src/**` returns only the new Run 101 types (declared in
  `qbind-ledger/src/genesis.rs`) and their re-exports — no `pub const
  MAINNET_*_ROOT` anywhere. The existing rejection of source-code root
  anchors (Run 100 spec §11) is preserved bit-for-bit.
- **Genesis-bound authority.** Authority fields are now present in the
  canonical hash and validated per environment.
- **Expected hash required for MainNet.** Existing
  `MainnetConfigError::ExpectedGenesisHashMissing` (file-bytes hash)
  preserved. New `BootGenesisVerificationError::ExpectedCanonicalHashMissing`
  added for the canonical-hash layer.
- **Authority fields included in hash.** Verified by
  `test_canonical_hash_differs_on_authority_change` and
  `test_canonical_hash_differs_on_authority_policy_version_change`.
- **No ratification verifier yet.** Bundle-signing keys are still trusted
  via the existing Run 050+ signed-bundle path; the in-binary ratification
  verifier remains a Run 102 task.
- **No peer-driven apply.** No peer/gossip subscription, publisher, or
  apply path was added. Run 087 propagation-only invariant is preserved.
- **No fallback roots / signing keys.** None added; none weakened.
- **No `Dummy*` primitive reachable.** Confirmed by grep.

---

## 5. Evidence references

- This document: `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_101.md`
- Release-binary CLI smoke logs:
  - `docs/devnet/run_101_genesis_authority_evidence/scenario_0_cli_help_genesis_surface.txt`
  - `docs/devnet/run_101_genesis_authority_evidence/scenario_3_malformed_expected_hash.stderr.log`
- Tests added:
  - `crates/qbind-node/tests/run_101_genesis_authority_tests.rs` (11 tests)
  - `crates/qbind-ledger/src/genesis.rs` `mod tests` Run 101 section
    (24 tests)
- Tests run (summary in §3.2). Exact commands:
  - `cargo test -p qbind-ledger --lib genesis::`
  - `cargo test -p qbind-ledger --lib`
  - `cargo test -p qbind-node --test run_101_genesis_authority_tests`
  - `cargo test -p qbind-node --test t232_genesis_mainnet_profile_tests --test t233_genesis_cli_tests`
  - `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests --test run_091_pqc_trust_bundle_activation_epoch_tests --test run_098_activation_epoch_canonical_wiring_tests`
  - `cargo test -p qbind-genesis`
- Release binary build: `cargo build -p qbind-node --bin qbind-node --release`
- Scripts/harnesses: none new.

---

## 6. Contradictions or inconsistencies

None found. Cross-checks performed:

- **Run 100 authority model** (`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`):
  Run 101 implements §6 "Genesis-bound initial authority" *fields and
  hash*, not §5 "Ratification object model" (Run 102) and not §8
  "Persistence and anti-rollback" beyond hash binding. The Run 100 §13
  staging plan is followed exactly. No contradiction.
- **contradiction.md:** Run 101 narrows the C4 sub-piece
  "production trust-anchor authority *implementation*" from "Run 101/102"
  to "Run 101 partial-positive; Run 102 to complete." Documented honestly
  in the appended Run 101 update.
- **Runbook:** the operational lifecycle steps remain valid; a Run 101
  row appended to §11 mapping plus a prose note. No
  Run 050/065/069–075/076–086/087/088/089/090 invariant is reworded.
- **Whitepaper / protocol docs:** the protocol doc Run 100 §6 (genesis-bound
  initial authority) is the spec being implemented. Wording aligned.
- **Genesis docs:** no genesis-format-specific document predates this
  field; T232 design memo
  (`docs/consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md` if present) keeps
  the existing schema fields and gains an additive note via rustdoc on
  `GenesisConfig.authority`.

---

## 7. Explicit non-claims

Run 101 does **NOT** implement:

- bundle-signing-key ratification verifier (Run 102 scope);
- signing-key rotation;
- signing-key revocation;
- authority anti-rollback persistence beyond genesis hash binding
  (no `<data_dir>/pqc_authority_state.json` is added — Run 103 scope);
- KMS/HSM custody (Run 105 scope);
- peer-driven live apply (Run 106+ scope, gated by Run 100 spec §10);
- governance;
- validator-set rotation;
- production static source-code anchors of any kind;
- fallback roots or fallback signing keys;
- changes to the trust-bundle or peer-candidate wire format;
- weakening of any Run 050–099 invariant;
- full C4 closure;
- C5 closure.

---

## 8. Residual risks

- **Boot-time enforcement integration:** the new
  `verify_boot_time_genesis` helper is exposed and exercised by tests, but
  is not yet *invoked* from the release-binary async startup path. Run
  102's ratification-verifier wiring is the natural place to add the
  single call site; until then the canonical-hash refusal exists only at
  the library level. The existing file-bytes
  `MainnetConfigError::ExpectedGenesisHashMissing` MainNet refusal remains
  in place, so MainNet without any expected hash still fails closed at
  CLI level. This is why Run 101 ships as partial-positive.
- **TestNet expected-canonical-hash not yet forced:** TestNet authority is
  required by Run 101 boot validation, but a TestNet startup without an
  expected canonical hash is currently allowed (documented partial). Run
  102 will revisit the policy alongside the ratification verifier.
- **No on-disk authority state yet:** rotations and emergency revocations
  remain manual until Runs 102–104. Operators MUST continue to follow the
  Run 050/055/065/069–075 lifecycle exactly as documented in the
  runbook.

---

## 9. Verdict

**partial-positive.**

Justification (against task §"Expected verdicts"):
- Genesis authority fields are implemented ✔
- Canonical genesis hash includes authority fields ✔
- MainNet requires (canonical) expected hash via the new boot helper ✔
- MainNet rejects missing/mismatched canonical hash ✔
- MainNet rejects missing/malformed authority roots ✔
- Release-binary evidence covers Scenarios 1–5 via the public-API path
  the release binary links against, plus a release-binary CLI smoke log
  for the malformed `--expect-genesis-hash` rejection ✔
- No runtime authority fallback exists ✔
- Docs are synchronized ✔

Why not **strongest-positive**: the canonical-hash boot helper is exposed
and tested but the *invocation* from the release-binary `async_runner`
startup sequence is intentionally deferred to Run 102 alongside the
ratification verifier (per Run 100 §13 staging). The existing T233
file-bytes `--expect-genesis-hash` MainNet refusal continues to enforce
fail-closed behaviour at the CLI layer; that is the previously released
shield Run 101 leaves in place. Run 102 will replace that shield with the
canonical-hash + ratification-verifier shield wired into the same
pre-network startup point.

---

## 10. Recommended next run

**Run 102 — bundle-signing-key ratification verifier (in-binary).**

Run 102 must:

- introduce the ratification object model defined in Run 100 spec §5;
- add the `pqc_authority_state.json` persistence (Run 103 may be a
  separate step but Run 102 must at minimum read and decline if the file
  shape is unknown);
- wire `qbind_ledger::verify_boot_time_genesis` from the async startup
  before trust-bundle processing or network startup so that *all*
  authority-dependent behaviour is gated on canonical-hash + authority
  validation, not just the file-bytes `--expect-genesis-hash` check;
- add the six `qbind_p2p_pqc_trust_bundle_authority_*` counters per Run
  100 §13;
- keep peer-driven live apply disabled-by-default per Run 087 / Run 100
  §10.

Run 103 then completes anti-rollback persistence; Run 104 produces full
release-binary rotation/revocation evidence; Runs 105/106+ continue per
the Run 100 staging.