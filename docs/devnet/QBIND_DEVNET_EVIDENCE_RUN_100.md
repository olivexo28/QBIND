# Run 100 — Trust-Anchor Authority and Bundle-Signing-Key Ratification Model (DESIGN / SPEC ONLY)

**Date:** 2026-05-21
**Verdict:** positive (design / specification only)
**Scope:** spec-first; no runtime code changed; no protocol or wire change.

This evidence record documents Run 100 as executed against the scope of
`task/RUN_100_TASK.txt`. Run 100 is a design / specification run that
introduces a formal authority and ratification model for PQC trust
anchors and bundle-signing keys across DevNet, TestNet, and MainNet. It
does NOT implement any of that behavior; the canonical specification
lives at `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

---

## 1. Investigation performed

### 1.1 Current trust-anchor input surfaces

A complete inventory of every current source of trust-anchor authority
on the production binary is recorded in
`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` §4.1. Summary:

- **Production-intended:** `--p2p-trust-bundle <PATH>`, the bundle's
  `roots[*]` merged after Run 050/051/053/057/065 validation, the local-
  operator hot-reload paths (Runs 069/070/073/074), and the peer-
  candidate validation-only / propagation-only paths (Runs 076 / 078 /
  079 / 088 — validation-only, propagation-only, never apply).
- **DevNet shortcut only:** `--p2p-trusted-root ROOTID:100:HEXPK`,
  refused on TestNet/MainNet when combined with `--p2p-trust-bundle`;
  never silently substituted on failure of the bundle path.
- **Dev/test only and statically unreachable on production:**
  `make_test_crypto_provider`, `DummySig` / `DummyKem` / `DummyAead`
  registration sites (refused on MainNet/TestNet at the top of
  `main.rs`).
- **Helper-generated:** `devnet_pqc_root_helper`,
  `devnet_pqc_trust_bundle_helper` — evidence-tool examples; NOT a
  production custody source.
- **Genesis-bound:** **none today.** `crates/qbind-ledger/src/genesis.rs::GenesisConfig`
  carries `chain_id`, `genesis_time_unix_ms`, `allocations`, `validators`,
  `council`, `monetary`, and `extra` — but no PQC trust anchors and no
  bundle-signing authority root.

### 1.2 Current bundle-signing-key authority

A bundle is authenticated today by the operator-supplied
`--p2p-trust-bundle-signing-key KEYID:100:HEXPK` set, plus
environment / chain_id binding through the canonical signing preimage
(`pqc_trust_bundle::canonical_signing_bytes`), plus Run 055 sequence
anti-rollback, plus Run 057 / Run 062 / Run 065 / Run 091 activation
gating, plus Run 052 leaf-fingerprint revocation. The current
production gap is that the operator-configured signing key set is
implicitly trusted: there is **no formal ratification source** proving
the signing key is authorized by genesis or governance authority.

### 1.3 Genesis configuration surface

- `--genesis-path <PATH>` lands at `crates/qbind-node/src/cli.rs:830-834`
  and threads through `NodeConfig::genesis_source.genesis_path`
  (`crates/qbind-node/src/node_config.rs:2528`).
- MainNet REQUIRES `genesis_path` to be set
  (`crates/qbind-node/src/node_config.rs:2608-2609`).
- `GenesisConfig` lives at `crates/qbind-ledger/src/genesis.rs:448-489`.
- Canonical genesis hash machinery is already present:
  `compute_genesis_hash_bytes` (`genesis.rs:753`), `format_genesis_hash`
  (`genesis.rs:769`), `parse_genesis_hash` (`genesis.rs:802`),
  `ChainMeta` binding `(chain_id, genesis_hash)`
  (`genesis.rs:855-873`).
- `GenesisConfig` does NOT carry PQC transport trust anchors or a
  bundle-signing authority root. The shape is forwards-compatible via
  `#[serde(default)]` and the existing `extra: serde_json::Value`
  placeholder.

### 1.4 Cross-document scan

The following existing docs were scanned for contradictions with the
new spec:

- `docs/whitepaper/QBIND_WHITEPAPER.md` — no contradiction (no contrary
  authority model is specified).
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` §2.1 (authorities and
  key separation), §4 (key generation and custody), §5 (per-environment
  policy) — describes the operator-facing layer; does not yet describe
  genesis-bound authority or ratification. Run 100 adds a runbook note
  pointing to the new spec; existing §2 / §4 / §5 prose is preserved.
- `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` §3
  (trust and authority model) — already states "peers are advisory
  only unless a future ratification mechanism exists". Run 100 §10
  is the canonical extension and is fully consistent.
- `docs/whitepaper/contradiction.md` — C4 already records the
  "production trust-anchor authority model" and "bundle-signing-key
  ratification" sub-items as OPEN. Run 100 narrows those sub-items
  with a formal design model without claiming closure.

No silent contradictions were ignored.

---

## 2. Design decisions

The full design lives in
`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`. The binding
architectural decisions are:

1. **Genesis-bound initial authority.** Initial production authority
   comes from a genesis configuration file bound by a boot-time
   cryptographic hash. Rust source-code constants MUST NOT be used as
   authoritative MainNet root anchors. Test/dev constants behind
   explicit non-production gates remain allowed.
2. **Ratification object model (§5).** Every bundle-signing key is
   authorized by a typed, PQC-signed, deterministically-encoded
   ratification object bound to `(chain_id, environment, genesis_hash,
   authority_epoch)`. Suite-agile (PQC-only). Domain-separated.
3. **Anti-rollback (§8).** `highest_authority_epoch` is monotonically
   non-decreasing across reload, SIGHUP, restart, and snapshot restore.
   Atomic-rename persistence pattern matching Run 055. Restore behavior
   mirrors Run 097's epoch-parity pattern. Pre-Run-103 snapshots
   restore cleanly; missing authority epoch is NOT silently `0`.
4. **Per-environment policy (§7).** DevNet may use explicit local
   shortcuts; TestNet requires genesis-bound authority with staged
   ratification; MainNet requires genesis-bound authority and
   ratification with no operator-only shortcuts and no fallback static
   roots. Run 065 minimum margins extend to authority rotation.
5. **Emergency authority (§9).** Three revocation classes
   (`Retired`, `Revoked`, `EmergencyRevoked`); the third bypasses
   Run 065 minimum margin and applies on next observation. Genesis-
   authority compromise has no in-protocol recovery (out-of-band).
   Equivocating ratifications at the same epoch fail closed with
   `AuthorityEpochEquivocation`.
6. **Peer-driven apply dependency (§10).** Peer-driven live apply
   remains forbidden until the ratification verifier (Run 102), the
   anti-rollback machinery (Run 103), defined KMS/HSM custody
   assumptions (Run 105), operator override / emergency controls
   (§9), and release-binary evidence (Run 104) all exist. Even then,
   peer-driven apply MUST stay disabled-by-default.

---

## 3. Non-goals (binding for Run 100)

Run 100 explicitly does NOT:

- implement bundle-signing-key ratification verifier;
- implement KMS/HSM custody;
- implement peer-driven live apply;
- implement governance;
- implement validator-set rotation;
- claim full C4 closure;
- claim any C5 closure;
- change the trust-bundle wire format;
- change the peer-candidate wire format;
- change consensus, KEMTLS, or `activation_epoch` semantics;
- add production static root anchors as source-code constants;
- add fallback roots or fallback signing keys;
- weaken any existing signed-bundle, chain_id, environment,
  sequence anti-rollback, activation-height, `activation_epoch`,
  Run 065 minimum-margin, revocation, reload-check non-mutation, or
  reload-apply ordering check.

These non-goals are preserved verbatim through Run 100. No source code
under `crates/**/src/**` or test code under `crates/**/tests/**` is
modified.

---

## 4. Implementation plan for later runs

(Reproduced from `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
§13 — see the spec for full detail.)

- **Run 101** — additive genesis-config fields, canonical-serialization
  extension, boot-time `expected_genesis_hash` comparison, initial
  `LiveAuthorityState` derivation, environment separation.
- **Run 102** — in-binary bundle-signing-key ratification verifier per
  §5; new persistent file `<data_dir>/pqc_authority_state.json`; new
  CLI flag for ratification install; six new
  `qbind_p2p_pqc_trust_bundle_authority_*` counters.
- **Run 103** — authority-state persistence and anti-rollback per §8.
- **Run 104** — release-binary signing-key rotation / revocation
  evidence (N=2/N=3 DevNet, N=4 MainNet matrices); emergency
  revocation immediate-apply proven on release binary.
- **Run 105** — KMS/HSM custody model; `Arc<dyn AuthoritySigner>`
  trait; per-environment minimum custody policy.
- **Run 106+** — peer-driven apply gates per §10 (NOT before Runs
  102–104 are positive).

Numbering may shift; the staged architecture MUST be preserved.

---

## 5. Contradictions found

None silently. The previously-implicit "the operator-supplied
`--p2p-trust-bundle-signing-key` set is the production authority" prose
in `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` §2.1 / §4.2 is
narrowed (operationally) by Run 100 to "candidate set; the authorized
subset is chosen by ratification per the spec once Run 102 lands". The
runbook is updated to point to the spec for the formal model. No
existing prose is deleted or weakened; the runbook continues to
describe the today-operator-distributes-signing-keys lifecycle
verbatim, because Run 102 is not yet implemented.

`docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` §3 is
consistent with §10 of the new spec (peers advisory only; ratification
is future work). No update required there.

`docs/whitepaper/contradiction.md` records the Run 100 update as a
narrowing of the C4 sub-pieces "production trust-anchor authority"
and "bundle-signing-key ratification" — without claiming closure.

---

## 6. Current unresolved items (after Run 100)

The following remain OPEN. Run 100 is a spec; none of these is closed
by writing the spec:

- production trust-anchor authority **implementation** (Run 101 / 102);
- bundle-signing-key ratification **verifier** (Run 102);
- authority-state **persistence and anti-rollback** (Run 103);
- release-binary rotation / revocation **evidence** (Run 104);
- **KMS / HSM custody** (Run 105);
- **peer-driven live apply** (Run 106+, gated by §10);
- in-binary / on-chain signing-key ratification (Run 102 covers
  in-binary; on-chain is a later, distinct surface);
- production fast-sync / broader consensus-storage restore (separate
  C4 sub-piece outside Run 100 scope);
- per-environment production trust-anchor operation (depends on Runs
  101–104);
- MainNet governance authorization path (depends on Runs 102 / 105 and
  a separate governance design run);
- full C4 closure;
- C5 closure.

---

## 7. Files changed in Run 100

| File | Action |
|------|--------|
| `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` | **created** (the spec). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_100.md` | **created** (this record). |
| `docs/whitepaper/contradiction.md` | **updated** — Run 100 update appended under C4. |
| `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` | **updated** — Run 100 row added to §11 mapping; Run 100 prose note added in §5 / §11 pointing to the spec. |
| `task/RUN_100_TASK.txt` | unchanged (task scope reference). |

**No `crates/**/src/**` source change. No `crates/**/tests/**` test
change. No `Cargo.toml` change. No new dependency. No new metric
family. No new CLI flag. No protocol or wire format change.**

---

## 8. Validation performed

Run 100 is documentation-only. The task explicitly states:

> Run 100 is spec-first. Tests are not required unless small
> docs/check tests already exist.
> If no code changes are made, state explicitly:
> No runtime code changed. No new tests required.

**No runtime code changed. No new tests required.** This is recorded
verbatim above.

The following lightweight validation was performed:

- The new spec was cross-checked against
  `docs/whitepaper/QBIND_WHITEPAPER.md`,
  `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`, and
  `docs/whitepaper/contradiction.md` (§1.4 / §5 above).
- The genesis-surface investigation (§1.3) was anchored in actual file
  + line citations in `crates/qbind-ledger/src/genesis.rs` and
  `crates/qbind-node/src/{cli.rs,node_config.rs}`.
- The trust-anchor input inventory (§1.1) was anchored in the existing
  Run 050–098 evidence and code references already enumerated in the
  runbook §11 mapping.

The repository's existing trust-bundle, peer-candidate, and
consensus-storage test suites were NOT re-run because no source code
under `crates/**` changed in Run 100. Their continued passing status
is recorded as of Run 099.

---

## 9. Verdict

**positive** (design / specification only).

The complete authority and ratification model is now formally specified.
Future implementation runs (101–106) have a single spec to follow.
Existing trust-bundle behaviour is unchanged. Full C4 remains OPEN; C5
is not touched.