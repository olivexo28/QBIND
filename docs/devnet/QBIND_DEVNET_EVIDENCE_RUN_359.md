# QBIND DevNet Evidence — Run 359

Public DevNet release-binary provenance + reproducibility / BuildID record publication.

Run 359 is **docs / artifact / verification only**. It publishes the canonical public DevNet
**release-binary provenance package** (`docs/release/public-devnet/binary/`) — README, release
provenance record, reproducibility/BuildID record, build-input record, SHA-256 checksum, and a
verification doc — for the `qbind-node` release binary, validated against the real toolchain and
repo-available tooling. It launches **no** public DevNet; deploys **no** seed node / bootnode / faucet
/ RPC gateway / explorer / status page; adds **no** public CLI flag; changes **no** P2P wire format /
peer-admission logic / default network behaviour; enables **no** MainNet; performs **no** runtime
authority-lifecycle wiring; and performs **no** validator-set mutation / epoch transition /
execution-sink write. It commits **no** binary blob (only the checksum text). Full **C4 remains OPEN**,
**C5 remains OPEN**, and MainNet authority rotation/revocation remains **Red**. The Run 353/354
boundary remains **Green-for-scope only**.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim.

## 1. Exact verdict

**PASS (public-DevNet-release-binary-provenance positive; docs/artifact/verification-only; public
DevNet NOT launch-ready; M2 moved Yellow → Green and M3 moved Red → Green for the public DevNet
readiness track only; M4 remains Yellow/launch-blocking; M6–M15 unchanged; Run 353/354 Green-for-scope
only; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

The binary provenance package (README, RELEASE_PROVENANCE, REPRODUCIBILITY, BUILDINFO,
qbind-node.sha256, VERIFY), this evidence file, the readiness-matrix updates, the narrow protocol/ops/
whitepaper-doc updates, the required test, the secret scan, and provenance all landed. The
`qbind-node` release binary was built three independent times with the documented `--locked` command
and produced a byte-identical artifact; its SHA-256, size, and ELF BuildID were recorded. No public
DevNet, TestNet, or MainNet readiness is claimed.

## 2. Files changed

New (binary provenance package):

- `docs/release/public-devnet/binary/README.md`
- `docs/release/public-devnet/binary/RELEASE_PROVENANCE.md`
- `docs/release/public-devnet/binary/REPRODUCIBILITY.md`
- `docs/release/public-devnet/binary/BUILDINFO.md`
- `docs/release/public-devnet/binary/qbind-node.sha256`
- `docs/release/public-devnet/binary/VERIFY.md`

New (evidence):

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_359.md` — this file.

Narrow updates:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — M2 Yellow → Green; M3 Red → Green; status
  header, checklist, owner table, status matrix, next-run table, blocker summary, consolidated gap
  matrix, and §17 summary updated. M4/M6–M15 unchanged.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status header + run log: Run 359 entry; C4/C5 stay OPEN.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 359 no-change-to-model entry.
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — Run 359 no-change-to-surface entry.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 359 trust-lifecycle-inert note.
- `docs/whitepaper/contradiction.md` — Run 359 "No contradiction found" entry.
- `docs/release/public-devnet/operator/README.md`, `docs/release/public-devnet/operator/QUICKSTART.md`
  — cross-link to the new binary provenance package only.

No source code changed. No Run 356 / Run 357 / Run 358 artifact was modified.

## 3. Canonical location decision

The canonical location is `docs/release/public-devnet/binary/`, a new sibling of the Run 356 genesis
package (`docs/release/public-devnet/genesis/`), the Run 357 seed-list package
(`docs/release/public-devnet/network/`), and the Run 358 operator package
(`docs/release/public-devnet/operator/`) under the shared `docs/release/public-devnet/` tree. This
matches the exact directory specified by the Run 359 task; no better pre-existing canonical location
existed for a published release-binary provenance package.

## 4. Binary provenance package contents

| File | Purpose |
|------|---------|
| `README.md` | Scope, what it is / is not, safety labels, verification pointers, remaining blockers. |
| `RELEASE_PROVENANCE.md` | Repo/commit/branch/state, host, `rustc`/`cargo` verbose, profile, build command, lockfile use, SHA-256, size, timestamp policy, BuildID. |
| `REPRODUCIBILITY.md` | Two-build (+default) same-host experiment, per-build SHA-256, match result, BuildID, reproducibility taxonomy, no-SLSA/no-signing statement. |
| `BUILDINFO.md` | Full build-input record (commit, branch, state, command, target triple, versions, profile, debug/strip/LTO/codegen-units/panic, size, SHA-256, BuildID, limitations). |
| `qbind-node.sha256` | `f916af6d…b22990  qbind-node` — checksum of the locally built release artifact (no committed blob). |
| `VERIFY.md` | Ten exact operator verification commands + expected outputs. |

## 5. Release provenance summary

- **Repository:** `olivexo28/QBIND` (GitHub); workspace member `crates/qbind-node`.
- **Git commit:** `420bb571281fc243fb0581150b0f628f6ee8d284`.
- **Git branch:** `copilot/run-359-update-user-documentation`.
- **Clean/dirty:** clean at build time (Run 359 change is docs/artifact-only; touches no build input).
- **Build host:** Ubuntu 24.04.4 LTS, Linux x86-64 (ephemeral sandbox; not a canonical reference env).
- **Build command:** `cargo build -p qbind-node --release --locked`.
- **`Cargo.lock`:** present (89,859 bytes) and used via `--locked`; not `--offline`/`--frozen`.
- **Profile:** `release` (workspace defaults; no `[profile.release]` override; no `.cargo/config*`).
- **Timestamp:** intentionally excluded from artifact identity.

## 6. Build inputs / BUILDINFO summary

- **Target triple:** `x86_64-unknown-linux-gnu` (default host target).
- **rustc:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`, LLVM 22.1.6.
- **cargo:** `cargo 1.97.1 (c980f4866 2026-06-30)`.
- **Profile knobs (defaults):** `opt-level=3`, `debug=false`, `strip=false` (ELF `not stripped`),
  `lto=false`, `codegen-units=16`, `panic=unwind`, `incremental=false`.
- **Env for reproducibility:** none required; only `CARGO_TARGET_DIR` varied for the two-build
  experiment. No `SOURCE_DATE_EPOCH` / `RUSTFLAGS` / path remapping set.
- **Toolchain pinning:** no `rust-toolchain*` file; host toolchain recorded above.

## 7. `qbind-node` SHA-256 and binary metadata

- **SHA-256:** `f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990`.
- **Binary size:** `16557072` bytes.
- **ELF BuildID (sha1):** `274fdaf3ded72362e87e11ccffce6912bde5208b`.
- **`--version`:** `qbind-node 0.1.0`.
- **`file`:** `ELF 64-bit LSB pie executable, x86-64 … dynamically linked … not stripped`.

## 8. Reproducibility / BuildID result

- **Experiment:** three independent clean `--locked` release builds of commit `420bb571…` —
  `CARGO_TARGET_DIR=/tmp/qbind-run359-a`, `CARGO_TARGET_DIR=/tmp/qbind-run359-b`, and the default
  `target/`. `--locked` was supported; no substitution needed.
- **Per-build SHA-256:** all three equal `f916af6d…b22990`; all `16557072` bytes.
- **Match:** **byte-identical** (`cmp -s` exit 0 for A vs B and A vs target).
- **BuildID:** **present**; identical across all three (`274fdaf3…5208b`) via `readelf -n` / `file`.
- **Classification:** **same-host + clean-tree reproducibility = Green for scope.** Cross-host
  reproducibility, SLSA-grade provenance, and signed-release are **NOT** claimed.

## 9. Commands run

```
git rev-parse HEAD ; git rev-parse --abbrev-ref HEAD ; git status --porcelain
rustc --version --verbose ; cargo --version --verbose ; uname -a ; cat /etc/os-release
CARGO_TARGET_DIR=/tmp/qbind-run359-a cargo build -p qbind-node --release --locked
CARGO_TARGET_DIR=/tmp/qbind-run359-b cargo build -p qbind-node --release --locked
cargo build -p qbind-node --release --locked
sha256sum /tmp/qbind-run359-a/release/qbind-node /tmp/qbind-run359-b/release/qbind-node target/release/qbind-node
cmp -s /tmp/qbind-run359-a/release/qbind-node /tmp/qbind-run359-b/release/qbind-node
cmp -s /tmp/qbind-run359-a/release/qbind-node target/release/qbind-node
file target/release/qbind-node ; readelf -n target/release/qbind-node ; objdump -f target/release/qbind-node
target/release/qbind-node --version
( cd target/release && sha256sum -c "$OLDPWD/docs/release/public-devnet/binary/qbind-node.sha256" )
cargo test -p qbind-node --lib
```

## 10. Verification commands and results

All from `docs/release/public-devnet/binary/VERIFY.md`, executed from repo root:

1. **Build** `cargo build -p qbind-node --release --locked` → succeeds; `target/release/qbind-node`
   exists (16,557,072 bytes). **PASS**
2. **Checksum** `sha256sum -c … qbind-node.sha256` → `qbind-node: OK`. **PASS**
3. **`rustc --version --verbose`** → `rustc 1.97.1 (8bab26f4f 2026-07-14)`. **PASS**
4. **`cargo --version --verbose`** → `cargo 1.97.1 (c980f4866 2026-06-30)`. **PASS**
5. **BuildID/version extraction** → BuildID `274fdaf3…5208b`; `--version` `qbind-node 0.1.0`. **PASS**
6. **Two-build reproducibility** → both SHA-256 `f916af6d…b22990`; `cmp` IDENTICAL. **PASS**
7. **Not launch-ready** → README asserts NOT launch-ready; no positive launch-ready claim. **PASS**
8. **C4/C5 not closed** → docs carry "C4 remains OPEN / C5 remains OPEN / no C4/C5 closure". **PASS**
9. **No MainNet/TestNet readiness** → only negative statements. **PASS**
10. **No binary blob committed** → only text files tracked; `.sha256` is ASCII. **PASS**

## 11. Readiness matrix deltas (M2/M3)

- **M2 release binary provenance:** 🟡 Yellow → 🟢 **Green**. Canonical operator-verifiable provenance
  record published (`binary/RELEASE_PROVENANCE.md`): commit, toolchain, build command, SHA-256, size,
  BuildID.
- **M3 release binary reproducibility / BuildID:** 🔴 Red → 🟢 **Green**. Same-host, clean-tree
  two-build reproducibility demonstrated (byte-identical `qbind-node`) **and** ELF BuildID recorded
  (`binary/REPRODUCIBILITY.md`). This satisfies the M3 move rule (same-host two-build reproducibility
  demonstrated and recorded, plus a BuildID/debug-id record). Cross-host/SLSA/signed **not** claimed.
- **M4 (seed/bootnodes):** unchanged, 🟡 **Yellow / launch-blocking** — no live seed/bootnode
  reachability evidence landed. **M6 (identity):** unchanged, 🟡 **Yellow/Partial**. **M7–M15:** unchanged.

## 12. Provenance

- **git commit:** `420bb571281fc243fb0581150b0f628f6ee8d284` (Run 359 artifacts added in this run's commit).
- **branch:** `copilot/run-359-update-user-documentation`.
- **clean/dirty state:** working tree was clean before this run; after this run it contains only the
  Run 359 additions/updates in §2, which are committed (no unexplained `git_status: dirty`). The
  release builds consumed no uncommitted source.
- **artifact paths:** §2; **qbind-node SHA-256 / size / BuildID / rustc-cargo / target triple:** §5–§8.
- **reproducibility result:** §8 (byte-identical; Green for same-host scope).
- **commands run:** §9. **test results:** §13. **security scan:** §14. **readiness deltas:** §11.

## 13. Test results

`cargo test -p qbind-node --lib`:

```
test result: ok. 1377 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 82.74s
```

Result: **PASS** (1377 passed, 0 failed). No Rust source was changed by Run 359; the run confirms no
regression.

## 14. Security scans

- **Secret scanning** over all changed files: **no secrets detected.** The provenance docs contain no
  private keys, mnemonics, seed phrases, credentials, API keys, tokens, private infrastructure, real
  production hostnames, or unapproved live endpoints. Only public build metadata is recorded (commit,
  toolchain versions, SHA-256, ELF BuildID). No full `env` dump is included; only explicitly selected,
  non-secret values (OS, kernel, target triple) are shown.
- **CodeQL:** not meaningful for the Run 359 diff — this is docs/artifact-only with **no source-code
  change** (no `.rs`, `Cargo.toml`, or `Cargo.lock` modification). No CodeQL coverage is claimed for
  this run. (If CodeQL were invoked and skipped/unavailable/timed-out/too-large, that exact result
  would be recorded here rather than being called clean.)

## 15. Honest limitations

- **Same-host only.** The byte-identical result is a same-host, clean-tree observation on one Ubuntu
  24.04 / `rustc` 1.97.1 sandbox. A different host, toolchain version, target triple, or lockfile can
  change both the SHA-256 and the ELF BuildID. Cross-host reproducibility was not tested and is not
  claimed.
- **No signing / no SLSA.** No signing material or attestation pipeline exists; no signed-release and
  no SLSA-grade provenance claim is made.
- **Build host is ephemeral.** The recorded host values are for provenance context, not a canonical
  reproducible reference environment.
- **Docs/artifact only.** Publishing provenance does not deploy infrastructure. **M4** (live
  seed/bootnodes) remains a launch blocker, so public DevNet remains **NOT launch-ready**.
- The Run 356 genesis file's raw byte SHA-256 differs from its published (LF) SHA-256 due to CRLF line
  endings in the committed blob (Run 358 observation). Run 359 does **not** modify the Run 356 genesis
  artifact; this is referenced only as a known limitation.

## 16. Suggested Run 360 next step

Attack **M4** — the remaining launch-blocking must-have: deploy a real DevNet seed/bootnode, capture
external reachability evidence, and replace the Run 357 placeholder seed-list with live entries
(structurally requiring `last_reachability_evidence`). Alternatively, close **M6** by exposing and
documenting a stable operator-facing node/peer/validator identity-**generation** command plus a
registration path. Optionally, extend the Run 359 provenance package toward **cross-host**
reproducibility (a second independent host reproducing `f916af6d…b22990`) as a future hardening step —
but that is beyond the current same-host scope.
