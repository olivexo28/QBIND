# QBIND DevNet Evidence — Run 358

Public DevNet external operator onboarding quickstart + identity guide + safety label publication.

Run 358 is **docs / artifact / verification only**. It publishes the canonical external public DevNet
**operator onboarding package** (`docs/release/public-devnet/operator/`) — README, quickstart,
identity guide, safety disclaimer, and verification doc — validated against the existing `qbind-node`
CLI surface, the Run 356 genesis package, and the Run 357 seed-list format. It launches **no** public
DevNet, deploys **no** seed node / bootnode / faucet / RPC gateway / explorer / status page, adds
**no** public CLI flag, changes **no** P2P wire format / peer-admission logic / default network
behaviour, enables **no** MainNet, performs **no** runtime authority-lifecycle wiring, and performs
**no** validator-set mutation / epoch transition / execution-sink write. Full **C4 remains OPEN**,
**C5 remains OPEN**, and MainNet authority rotation/revocation remains **Red**. The Run 353/354
boundary remains **Green-for-scope only**.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.

## 1. Exact verdict

**PASS (public-DevNet-operator-onboarding positive; docs/artifact/verification-only; public DevNet
NOT launch-ready; M5/M17/M18 moved Yellow → Green for the public DevNet readiness track only; M6
stays Yellow/Partial; M3 remains Red; M4 remains Yellow/launch-blocking; Run 353/354 Green-for-scope
only; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

The operator package (README, QUICKSTART, IDENTITY, SAFETY, VERIFY), this evidence file, the
readiness-matrix updates, the narrow protocol-doc updates, the required test, the secret scan, and
provenance all landed. All operator-doc verification commands succeeded against the real
`qbind-node --release` binary and repo-available tooling (no new dependency, no new CLI flag). No
public DevNet, TestNet, or MainNet readiness is claimed.

## 2. Files changed

New (operator onboarding package):

- `docs/release/public-devnet/operator/README.md`
- `docs/release/public-devnet/operator/QUICKSTART.md`
- `docs/release/public-devnet/operator/IDENTITY.md`
- `docs/release/public-devnet/operator/SAFETY.md`
- `docs/release/public-devnet/operator/VERIFY.md`

New (evidence):

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_358.md` — this file.

Narrow updates:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — M5/M17/M18 Yellow → Green; M6 stays
  Yellow/Partial with the exact gap; status header, checklist, status matrix, next-run table,
  surface inventory, blocker summary, and §17 summary updated. M3/M4 unchanged.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status header + run log: Run 358 entry; C4/C5 stay OPEN.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 358 no-change-to-model entry.
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — Run 358 no-change-to-surface entry.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 358 trust-lifecycle note (describes existing surfaces only).
- `docs/whitepaper/contradiction.md` — Run 358 "No contradiction found" entry.

No source code changed. No Run 356 / Run 357 artifact was modified.

## 3. Canonical location decision

The canonical location is `docs/release/public-devnet/operator/`, a new sibling of the Run 356
genesis package (`docs/release/public-devnet/genesis/`) and the Run 357 seed-list package
(`docs/release/public-devnet/network/`) under the shared `docs/release/public-devnet/` tree. No
better pre-existing canonical location existed for a published external-operator onboarding package,
so the `operator/` subdirectory was created.

## 4. Operator package contents

| File | SHA-256 (as authored, LF) | Purpose |
|------|---------------------------|---------|
| `README.md` | `f0f2d34df4cf0f5de81fa997b1c7201866a5156f12acfa187ca424f36791dc58` | Index / scope / cross-links / launch-readiness statement. |
| `QUICKSTART.md` | `11c6de0d53a54c41d364ae4342ea87d06e94b52028129170b7900d2739872a72` | Bring-up quickstart (build, verify genesis, dry-run, join guidance, troubleshooting). |
| `IDENTITY.md` | `800f1bfa6ec0365fda2f2df316e924883538f6d400ea6423a15f48af8e3125f5` | Identity guidance + existing surfaces + honest M6 gap. |
| `SAFETY.md` | `93455a452ca469a2b8cfda1523457395d62d57b6f9b653e7a383de3d50c89fb1` | User-facing safety label / disclaimer publication. |
| `VERIFY.md` | `2ae7b5c838f0482bb5987dd921a527c2f49ba132aa0ec1cb3e6790fa88cd502a` | Exact verification commands + expected outputs. |

(Hashes are over the LF-authored bytes; if a checkout materializes these with CRLF the raw byte
hash will differ. Recompute with `sha256sum docs/release/public-devnet/operator/<file>.md`.)

## 5. Quickstart summary

`QUICKSTART.md` covers, in order: (§0) an explicit **NOT launch-ready** statement; (§1) the safety
label (experimental / resettable / no value / no MainNet readiness claim / no C4/C5 closure claim);
(§2) prerequisites (Rust/`cargo` stable, edition 2021; source checkout; Python 3 for verification; no
live-seed expectation); (§3) the release build (`cargo build -p qbind-node --release`); (§4) genesis
verification — line-ending-tolerant file SHA-256 `d1db07fe…5c86c`, `--print-genesis-hash` canonical
hash `0x48b3a862…af18145f`, and pinning with `--expect-genesis-hash`; (§5) the Run 357 seed-list
placeholder (where it lives, why it must not be dialed, how a future live list is used); (§6) a
full-node local dry-run boot using only pre-existing flags (`--env`, `--genesis-path`,
`--expect-genesis-hash`, `--data-dir`); (§7) validator guidance (what is possible / fixture-internal /
must-not-claim); (§8) P2P joining guidance mapping future `status:"live"` seed fields onto
pre-existing flags (`--p2p-peer`, `--enable-p2p`, `--p2p-listen-addr`, `--p2p-advertised-addr`,
`--p2p-mutual-auth`, `--p2p-trust-bundle` + `--p2p-trust-bundle-signing-key`, `--expect-genesis-hash`)
with an explicit do-not-dial-placeholder warning; (§9) data-dir guidance + resettable/no-value warning
+ cleanup; (§10) troubleshooting (genesis mismatch, invalid seed list, P2P disabled by default, no
live seeds, MainNet/TestNet unaffected); (§11) what remains before launch.

## 6. Identity guidance summary

`IDENTITY.md` distinguishes node identity, peer identity, validator address, validator signing
identity, and PQC transport / trust-bundle material; lists the pre-existing CLI/config surfaces for
each (`--validator-id`, `--signer-mode`, `--signer-keystore-path`, `--remote-signer-url`,
`--hsm-config-path`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-trusted-root`,
`--p2p-peer-leaf-cert`, `--p2p-pqc-root-mode`, `--p2p-trust-bundle`,
`--p2p-trust-bundle-signing-key`); states which material is safe to publish (public addresses / keys /
fingerprints / peer-ids; documentation-example hosts) and which must never be published (private
signing keys, keystore secrets, mnemonics, credentials, tokens, private/production infrastructure);
gives placeholder-vs-live seed-entry guidance and validators-vs-full-nodes guidance; and states no
production/MainNet identity or custody material is introduced. **Honest M6 gap (§9):** there is no
externally documented, stable `qbind-node` command that **generates** a publishable
node/peer/validator identity for an external operator, and no live public DevNet to register into, so
**M6 stays Yellow/Partial**.

## 7. Safety / disclaimer publication

`SAFETY.md` publishes the user-facing label in operator-facing material: experimental, resettable,
no value, no MainNet readiness claim, no C4/C5 closure claim, plus no guarantees of availability /
state durability / continuity, no expectation that DevNet balances or state survive resets, and that
TestNet and MainNet are separate future stages. The one-line safety label also appears in the header
of every operator doc (README, QUICKSTART, IDENTITY, SAFETY, VERIFY).

## 8. Verification commands and results

All run from the repo root against `./target/release/qbind-node` and repo-available tooling
(`sha256sum`, `grep`, Python 3.12). Exact commands + expected outputs are in
`docs/release/public-devnet/operator/VERIFY.md`.

1. **Genesis cross-check** — `--print-genesis-hash` →
   `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`; the quickstart references
   that printed hash; the LF-normalized file SHA-256 equals the published
   `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c` and the quickstart references
   it. **PASS**
2. **Seed-list cross-check** — placeholder is valid JSON; the quickstart references
   `devnet-seeds.placeholder.json` and warns it must not be dialed. **PASS**
3. **Every quickstart `qbind-node` flag exists in `--help`** — `comm -23` of the quickstart flag set
   (excluding the `cargo build` flag `--release`) against the `--help` flag set is empty. **PASS**
4. **Placeholder not marked live** — no `status: "live"` entry present. **PASS**
5. **Every placeholder `p2p_host` is documentation-safe** — only RFC 5737 / RFC 6761 documentation
   values (the sole host is `192.0.2.1`). **PASS**
6. **No operator doc claims launch-ready** — every content doc asserts NOT launch-ready; no positive
   launch-ready claim in README/QUICKSTART/IDENTITY/SAFETY. **PASS**
7. **Safety label in every operator doc** — the one-line label is present in all five operator docs.
   **PASS**
8. **MainNet/TestNet not modified** — operator docs are DevNet-scoped (only `--env devnet`); no
   TestNet/MainNet artifact created or modified; no TestNet/MainNet readiness claim. **PASS**

## 9. Tests run

- `cargo test -p qbind-node --lib` — see §12 for result. The Run 358 diff is docs/artifact-only (no
  Rust source changed), so no broader source-regression suite is required by repository policy; the
  `qbind-node --lib` suite is run as the task-required baseline.
- `cargo build -p qbind-node --release` — succeeded (binary `./target/release/qbind-node`), used to
  validate `--help` and the genesis-hash commands.

## 10. Security scans

- **Secret scanning** over all changed files: **no secrets detected**. The operator docs contain no
  private keys, mnemonics, seed phrases, credentials, API keys, tokens, private infrastructure, real
  production hostnames, or unapproved live endpoints. The only sample host value is `192.0.2.1`
  (RFC 5737 documentation range), explicitly non-secret and non-routable.
- **CodeQL:** not meaningful for the Run 358 diff — this is docs/artifact-only with **no source-code
  change**. No CodeQL coverage is claimed for this run. (If CodeQL were invoked and
  skipped/unavailable/timed-out/too-large, that exact result would be recorded here rather than being
  called clean.)

## 11. Readiness matrix deltas (M5/M6/M17/M18)

- **M5 validator/full-node onboarding quickstart:** 🟡 Yellow → 🟢 **Green**. External operator
  quickstart published (`operator/QUICKSTART.md`), validated against the real `qbind-node --help`
  CLI surface, the Run 356 genesis package, and the Run 357 seed-list format.
- **M6 validator identity guidance:** 🟡 Yellow → 🟡 **Yellow / Partial (unchanged status)**. Identity
  guidance published (`operator/IDENTITY.md`) and validated against pre-existing identity/signer
  loading/selection surfaces, **but** no stable operator-facing identity-**generation** command exists
  and no live public DevNet to register into — the exact gap is stated in `IDENTITY.md` §9. M6 stays
  Yellow.
- **M17 public how-to-run-a-node:** 🟡 Yellow → 🟢 **Green**. Complete, operator-facing package
  published (`operator/`), cross-linked from the readiness track and validated against real startup.
- **M18 user-facing disclaimers:** 🟡 Yellow → 🟢 **Green**. The §3 safety label is published in
  operator-facing material (`operator/SAFETY.md` + every operator-doc header), not only in the
  internal matrix.
- **M3 (reproducibility/BuildID):** unchanged, **Red**. **M4 (seed/bootnodes):** unchanged, **Yellow /
  launch-blocking**. No reproducibility/BuildID or live-seed reachability evidence is added by this run.

## 12. Provenance

- **git commit (pre-run tip):** `6197d21246684cf364a092fc045fda6942684f4b` (Run 358 artifacts are
  added in this run's commit).
- **branch:** `copilot/run-358-task`.
- **clean/dirty state:** working tree was clean before this run; after this run it contains only the
  Run 358 additions/updates listed in §2, which are committed (no unexplained `git_status: dirty`).
- **artifact paths + operator-doc file hashes:** see §2 / §4.
- **Run 356 genesis hash (referenced, not modified):**
  `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`.
- **Run 356 genesis file SHA-256 (referenced, not modified; LF-normalized bytes):**
  `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`.
- **Run 357 schema hash (`devnet-seed-list.schema.json`, current committed bytes):**
  `b6630547afe4b37481256e73185704756d3450ed51eb18914ea27153723a3f75`
  (LF-normalized: `1733ecfe378b9d8c8aa471c1011cbf1203886465b85506eca5d107571cbb8c05`).
- **Run 357 placeholder seed-list hash (`devnet-seeds.placeholder.json`, current committed bytes):**
  `0b11c2c77de2550144f85af12e327b38216a7272be3c944760a1395e516942d0`
  (LF-normalized: `dc43234410d292c2c6c137f3791d5c53d2730c4219d4f75c95b12be5724557bc`).
- **commands run:** §8 verification commands; `cargo build -p qbind-node --release`;
  `cargo test -p qbind-node --lib`; secret scan; hash computations.
- **test results:** §13.
- **security scan result:** §10 (no secrets; CodeQL N/A for docs-only diff).
- **readiness matrix deltas:** §11 (M5/M17/M18 Green; M6 stays Yellow/Partial; M3/M4 unchanged).

### Note on the Run 356 genesis file-byte SHA-256

The committed `devnet-genesis.json` blob currently carries CRLF line endings, so its raw byte SHA-256
(`561118ac…`) differs from the canonical published SHA-256 (`d1db07fe…`, computed over LF-normalized
bytes and recorded in `devnet-genesis.sha256`, the Run 357 placeholder, and the network parameters).
Run 358 does **not** modify the Run 356 artifact (out of Run 358's narrow scope). To keep the
operator quickstart working on any checkout, its genesis verification uses a **line-ending-tolerant**
digest check and treats the whitespace-independent `--print-genesis-hash` value
(`0x48b3a862…af18145f`) as the authoritative integrity gate. This CRLF/LF observation is recorded for
a future run that owns the Run 356 genesis artifact.

## 13. Test results

`cargo test -p qbind-node --lib`:

```
test result: ok. 1377 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 56.98s
```

Result: **PASS** (1377 passed, 0 failed). No Rust source was changed by Run 358; the run confirms no regression.

## 14. Honest limitations

- This run publishes **only** operator onboarding documentation. It deploys **no** infrastructure and
  makes the network **no** more joinable: **M4** remains a launch blocker and **M3** remains Red, so
  public DevNet remains **NOT launch-ready**.
- **M6 could not honestly move to Green:** there is no stable operator-facing command to **generate**
  a publishable node/peer/validator identity, and no live public DevNet to register into. M6 stays
  Yellow/Partial with the exact gap documented.
- The quickstart's P2P join guidance is forward-looking: it maps a **future** live seed list onto
  pre-existing flags. There are no live seeds today; the placeholder must not be dialed.
- The operator docs are documentation only; they are not consumed by any runtime discovery, admission,
  governance, or authority path.
- The Run 356 genesis file's raw byte SHA-256 differs from its published (LF) SHA-256 due to CRLF line
  endings in the committed blob; see §12. This is a pre-existing Run 356 artifact observation, not a
  Run 358 change.

## 15. Suggested Run 359 next step

Either (a) publish a **release-binary provenance + reproducibility / BuildID** record to attack
**M3** (the sole Red must-have), or (b) expose and document a **stable operator-facing
node/peer/validator identity-generation command** (plus a registration path) to move **M6** to Green.
The **M4**-closing work — real seed/bootnode deployment + external reachability evidence — remains a
separate infrastructure/deployment run.
