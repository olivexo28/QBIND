# QBIND DevNet Evidence — Run 356

Canonical public DevNet genesis package + network-parameter publication + genesis-hash publication.

Run 356 is **docs / artifact / verification only**. It publishes a canonical public DevNet genesis package and the
associated network-parameter and genesis-hash artifacts, with verification evidence. It does **not** launch a public
DevNet, deploys **no** seed nodes / bootnodes / faucet / RPC gateway / explorer / status page, adds **no** public CLI
flag, enables **no** MainNet, performs **no** runtime authority-lifecycle wiring, performs **no** validator-set
mutation, and performs **no** epoch transition or execution-sink write. Full **C4 remains OPEN**, **C5 remains OPEN**,
and MainNet authority rotation/revocation remains **Red**. The Run 353/354 boundary remains **Green-for-scope only**.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.

## 1. Exact verdict

**PASS (public-DevNet-genesis-publication positive; docs/artifact/verification-only; public DevNet NOT launch-ready;
M1/M19/M20 moved Yellow → Green for the public DevNet readiness track only; M3/M4 remain Red; Run 353/354
Green-for-scope only; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

The canonical genesis artifact, genesis hash, network parameters, verification docs, this evidence file, the
readiness-matrix updates, the required tests, the secret scan, and provenance all landed. Verification succeeded via
the pre-existing `--genesis-path` / `--print-genesis-hash` / `--expect-genesis-hash` surfaces. No public DevNet,
TestNet, or MainNet readiness is claimed.

## 2. Files changed

New (genesis package):

- `docs/release/public-devnet/genesis/README.md`
- `docs/release/public-devnet/genesis/devnet-genesis.json`
- `docs/release/public-devnet/genesis/devnet-genesis.sha256`
- `docs/release/public-devnet/genesis/devnet-network-parameters.md`
- `docs/release/public-devnet/genesis/VERIFY.md`

New (evidence):

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_356.md` — this file.

Narrow updates:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — M1/M19/M20 moved to Green; matrices, blocker summary,
  next-run recommendations, and summary updated.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — Run 356 note; C4/C5 remain OPEN.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 356 note.
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — Run 356 note.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 356 note.
- `docs/whitepaper/contradiction.md` — Run 356 entry (no contradiction found).

No production runtime source code was changed. No CLI flag was added. No boundary was wired into runtime.

## 3. Genesis package contents

`docs/release/public-devnet/genesis/`:

| File | Contents |
|------|----------|
| `README.md` | Environment (DevNet only), chain id, genesis hash, file SHA-256, network name, safe-to-publish params, validator set, council/allocation/monetary params, PQC trust-root/signing-key status, fixture/dev-only declaration, resettable/no-value label, operator verification steps, print/verify + boot commands, what is still missing. |
| `devnet-genesis.json` | Canonical DevNet `GenesisConfig` JSON (public material only), derived from the existing in-repo fixture `docs/devnet/run_139_sighup_v2_live_reload_release_binary/fixtures/devnet/genesis.json`. |
| `devnet-genesis.sha256` | File-byte SHA-256 of `devnet-genesis.json`. |
| `devnet-network-parameters.md` | Canonical operator-facing network parameters (identity, validator/allocation/council, monetary, PQC authority), each row sourced to genesis or source constants. |
| `VERIFY.md` | Exact operator verification commands + expected outputs (8 checks). |

The location `docs/release/public-devnet/genesis/` is the preferred canonical location named by the Run 356 task; it
sits under the existing `docs/release/` public-DevNet release-readiness track (`QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`).

## 4. Published network parameters

- Environment: DevNet only; domain scope `DEV`.
- Runtime ChainId: `0x51424E4444455600` = `5855328520645203456` (`QBIND_DEVNET_CHAIN_ID`,
  `crates/qbind-types/src/primitives.rs`).
- Genesis config `chain_id` (string): `qbind-devnet-v0`.
- `genesis_time_unix_ms`: `1738000000000`.
- Validators: 1 (fixture/dev-only public: address `0x2222…`, pqc public key `abab…`, stake `100`).
- Allocation: 1 (`100` → `0x1111…`).
- Council: members `0x3333…`/`0x4444…`/`0x5555…`, threshold `2`.
- Monetary: DevNet monetary parameters as embedded in `devnet-genesis.json` (full table in
  `devnet-network-parameters.md`).
- PQC authority: `authority_policy_version=1`, `authority_sequence=0`, `authority_epoch=null`,
  `pqc_transport_roots=[]`, one bundle-signing authority root (`suite_id=100`,
  `label=run133-bundle-signing-authority`) as **public** fingerprint + **public** key hex.

## 5. Published genesis hash and SHA-256

- Canonical Run 101 genesis hash (`--print-genesis-hash`, `--env devnet`):
  `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`
- `devnet-genesis.json` file SHA-256:
  `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`

## 6. Verification commands and results

All commands run from the repository root against a `cargo build -p qbind-node --release` binary
(`./target/release/qbind-node`), build `Finished release profile ... in 7m 30s` (exit 0).

1. **Valid JSON** —
   `python3 -c "import json; json.load(open('docs/release/public-devnet/genesis/devnet-genesis.json')); print('valid json')"`
   → `valid json`. ✅

2. **Parseable by QBIND tooling** —
   `./target/release/qbind-node --env devnet --genesis-path docs/release/public-devnet/genesis/devnet-genesis.json --print-genesis-hash`
   → parses as `GenesisConfig`, exit 0; stderr `env=Devnet, chain_id=5855328520645203456`. ✅

3. **Printed genesis hash matches published hash** —
   stdout `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f` equals §5. ✅
   Pin path accepted:
   `--expect-genesis-hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f` → exit 0. ✅
   Tamper check: mutating `chain_id` produced a **different** hash
   (`0xd241ec44864e29e92dc48ab69e897672c1f26e68012e2f9d21af4a926055feb6`), confirming content-sensitivity. ✅

4. **SHA-256 matches committed file** —
   `cd docs/release/public-devnet/genesis && sha256sum -c devnet-genesis.sha256` → `devnet-genesis.json: OK`. ✅

5. **Network parameters match genesis/source** — `devnet-network-parameters.md` rows transcribed from
   `devnet-genesis.json`; runtime ChainId cross-checked against `QBIND_DEVNET_CHAIN_ID` in
   `crates/qbind-types/src/primitives.rs` and confirmed by the `chain_id=5855328520645203456` provenance line. ✅

6. **MainNet not affected** — `--env devnet` only; no MainNet artifact created/modified. ✅

7. **TestNet not affected** — `--env devnet` only; no TestNet artifact created/modified. ✅

8. **No public DevNet launch claim** — README/VERIFY/readiness docs explicitly state NOT launch-ready; M3/M4 Red. ✅

## 7. Readiness matrix deltas for M1/M19/M20

| Item | Before (Run 355) | After (Run 356) | Basis |
|------|------------------|-----------------|-------|
| M1 genesis package | 🟡 | 🟢 | Canonical committed genesis artifact, verified, operator-facing (`docs/release/public-devnet/genesis/`). |
| M19 network parameter publication | 🟡 | 🟢 | `devnet-network-parameters.md` canonical operator artifact, checked against genesis + source constants. |
| M20 genesis hash publication | 🟡 | 🟢 | Canonical hash published + verifiable via `--print-genesis-hash` / `--expect-genesis-hash`. |

M3 (reproducibility/BuildID) and M4 (seed/bootnodes) **unchanged — remain Red**. No other must-have changed.

## 8. Current public DevNet readiness status

**NOT launch-ready.** Green must-haves are now **M1, M16, M19, M20**; all others remain Yellow or Red. Because at
least one must-have is not Green (notably M3/M4 Red), public DevNet is not launch-ready.

## 9. Remaining public DevNet blockers

- **Red:** M3 (release-binary reproducibility / BuildID), M4 (seed/bootnode list for public join).
- **Yellow (must reach Green):** M2, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15, M17, M18.
- Plus external reachability, status page, alert rules, and seed-node runbook (should/Red items in §16 matrix).

## 10. Public TestNet blockers

Public TestNet remains a **separate, later** track: network-scale governance-proof hardening (T5), live validator-set
rotation (T6), sustained multi-node operation, performance/adversarial validation. No TestNet readiness is claimed.

## 11. MainNet blockers

MainNet custody (N1) and MainNet authority rotation/revocation under production custody (N2, **Red**), runtime
authority-lifecycle wiring (N3), production economic finalization, and SLSA-grade provenance. No MainNet readiness is
claimed. MainNet authority rotation/revocation remains **Red**.

## 12. C4 / C5 status

Full **C4 remains OPEN**. **C5 remains OPEN**. Run 356 does not close, advance, or reinterpret C4/C5. MainNet
authority rotation/revocation remains **Red**. Run 353/354 remains **Green-for-scope only** and is not wired into
runtime. Public DevNet readiness remains a **separate** release-readiness track.

## 13. Tests run

- `cargo test -p qbind-node --lib` → **1377 passed; 0 failed; 0 ignored** (finished in 181.33s). ✅
- `cargo test -p qbind-ledger genesis` → **14 passed; 0 failed** (5 filtered). ✅
- `cargo test -p qbind-genesis` → **6 passed; 0 failed** + doc-tests **0**. ✅
- `cargo build -p qbind-node --release` → Finished (exit 0), used for CLI verification. ✅

## 14. Security scans

- **Secret scanning** over all changed genesis-package files (`devnet-genesis.json`, `README.md`,
  `devnet-network-parameters.md`, `devnet-genesis.sha256`, `VERIFY.md`) → **no secrets detected**. The genesis
  artifacts contain only DevNet-only **public** material (public addresses, a public validator PQC key placeholder,
  a public bundle-signing authority fingerprint + public key hex). No private keys, private signing material,
  mnemonics, seed phrases, tokens, credentials, API keys, or production-like secrets are present.
- **CodeQL:** Run 356 is docs / artifact / verification only — it changes **no source code**. CodeQL is therefore
  **not meaningful for the Run 356 diff and no CodeQL coverage is claimed** for this run. (The trivial-change
  declaration for the security checker is set accordingly: non-code / docs-and-JSON-only changes.)

## 15. Provenance

- **Repository:** `olivexo28/QBIND`
- **Branch:** `copilot/run-356-task`
- **Base commit (before Run 356 artifacts):** `ad0c755a2bac8932c1070445c235d7403736b555`
- **Working-tree state at authoring:** dirty only with the Run 356 additions listed in §2; committed and pushed via
  the Run 356 progress commit (no unexplained dirty state remains after commit).
- **Artifact paths + SHA-256:**
  - `docs/release/public-devnet/genesis/devnet-genesis.json` →
    `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`
- **Canonical Run 101 genesis hash:** `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`
- **Commands run:** see §6 (verification) and §13 (tests/build).
- **Test results:** see §13 (all PASS).
- **Security-scan result:** see §14 (secret scan clean; CodeQL not meaningful / not claimed).
- **Readiness matrix deltas:** see §7 (M1/M19/M20 Yellow → Green; M3/M4 unchanged Red).

## 16. Honest limitations

- The `--print-genesis-hash` path exits after printing; operator verification of M20 is **compare-the-printed-hash**
  plus the `--expect-genesis-hash` pin flag. Full external-reachability boot verification is out of scope (no
  seed/bootnode deployment in Run 356).
- The published genesis `authority` block is **not consumed by any live ratification verifier** (unchanged Run 101
  non-claim); it is fixture/dev-only public material.
- Moving M1/M19/M20 to Green reflects the **public DevNet readiness track only**; it does not imply any TestNet or
  MainNet readiness, and does not close C4/C5.
- The DevNet genesis fixture values (chain_id string, validator, allocation, council, monetary, authority root) are
  inherited from an existing in-repo DevNet fixture; they are resettable and carry no value.

## 17. Suggested Run 357 next step

Publish a canonical **DevNet seed/bootnode list format + placeholder DevNet seed list (docs-only)** to begin
narrowing **M4** (currently Red), and/or a **release-binary reproducibility / BuildID** run to begin narrowing
**M3** (currently Red) — these two Red must-haves are the primary remaining launch blockers. A consolidated
onboarding+identity+key-management+quickstart+disclaimers documentation run would additionally clear several Yellow
must-haves (M5/M6/M7/M17/M18). No item should be marked Green without operator-facing evidence.