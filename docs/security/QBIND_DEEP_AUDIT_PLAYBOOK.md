# QBIND Deep Audit Playbook — toward Public DevNet

**Status:** methodology document. It fixes no finding, closes no gate, and
authorizes no release. It is a *runnable* procedure for auditing QBIND deeply
enough that (a) the public DevNet has no gap and (b) a future public TestNet or
MainNet release does not fail because of a defect that was present but
unexamined at DevNet.

**Release authority is unchanged.** This playbook feeds, but does not replace,
the existing gate system: the
[readiness criteria](../release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md),
the [blocker register](../release/public-devnet/BLOCKER_REGISTER.md), and the
[launch decision](../release/public-devnet/LAUNCH_GO_NO_GO.md). Findings here
map to M-series gates / RS1 where one applies; this document introduces no
substitute gate and makes no existing gate Green.

---

## §0 — How to use this playbook

### 0.1 The one rule that matters: verify, don't trust

QBIND carries a very large self-generated readiness corpus — the ~5.5 MB
[`Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`](../../Audit/QBIND_SECURITY_FINDINGS_REGISTER.md),
~599 files under `docs/security/evidence/`, ~2400 run records under
`docs/devnet/`, the whitepaper, and the readiness criteria. **None of that is
evidence for the purposes of this audit.** It is a set of *claims to be
checked* against (1) the source as it is on the audited commit and (2) a live
run of the built binary. The audit exists precisely because exploration found
claims that reality does not back:

- CI is claimed to run tests and CodeQL; no workflow runs either.
- Slashing is described as present; the live node may wire a no-op engine.
- Timeout/view-change is referenced as working; the whitepaper (§8.10) itself
  marks it incomplete.

Every item below is "pass" **only** with a reproducer that someone else can
run from a clean checkout and get the stated output.

### 0.2 Severity

| Severity | Meaning |
|---|---|
| **Critical** | Loss of funds/value, consensus safety violation (two conflicting commits), remote node takeover, or key compromise. |
| **High** | Remote liveness kill (crash/halt) from attacker input, incorrect value accounting, or a security control that is absent/bypassable. |
| **Medium** | Local DoS, degraded liveness under adversarial-but-bounded conditions, or a control that is weak but present. |
| **Low** | Hardening gap with no direct exploit path. |
| **Info** | Doc/code drift, missing policy artifact, observation. |

### 0.3 The two-track gate model (this is what makes it forward-looking)

Every finding gets **exactly one track**:

- **`DEVNET-BLOCK`** — must be resolved before the public DevNet opens.
- **`CARRY-FORWARD`** — need not block DevNet (DevNet has no value and is
  resettable), **but the code is correct-now-or-never**: it ships unchanged
  into TestNet/MainNet, where the same defect *does* cause loss or halt.
  Consensus safety, crypto suite enforcement, `unsafe` memory safety, and
  value math are the canonical carry-forward classes. They are audited to
  MainNet standard *during the DevNet cycle*.
- **`DEFERRABLE`** — genuinely a later-phase concern (operational scale, live
  seed topology, on-chain governance execution maturity). Recorded so the
  deferral is a decision, not an oversight.

The §6 matrix is the authoritative list of what is carry-forward. **"DevNet
carries no value" is never a reason to skip a carry-forward item** — it is only
a reason to defer a `DEFERRABLE` one.

### 0.4 Evidence convention (reuse the existing one)

For each finding or "pass", create `docs/security/evidence/<audit-id>/`
following the repository's established layout:

- `README.md` — what was checked, the claim it tests, the verdict, the exact
  commit, and the reproducer command.
- `producer.txt` — who/what produced it and when.
- `*.log` — captured command output.
- `SHA256SUMS` — `sha256sum *` over the artifacts, so the bundle is tamper-evident.

Pin the audited commit in every bundle:

```bash
git rev-parse HEAD && git rev-parse HEAD^{tree}
```

### 0.5 Audit IDs and the tracker

Use the companion [`QBIND_DEEP_AUDIT_TRACKER.md`](./QBIND_DEEP_AUDIT_TRACKER.md).
IDs follow the workstream: `A1`, `B1-a`, `C3`, `E-02`, etc. One tracker row per
item; one evidence dir per row that reaches a verdict.

### 0.6 Positioning

This is an **internal self-audit that stays external-ready**: the artifacts it
emits (threat model in §4/D4, scoped findings register, reproducible evidence,
coverage report) are exactly what a third-party audit firm would ask for, so a
later external engagement is cheap and fast rather than a from-scratch effort.

---

## §1 — Workstream A: Audit baseline (make the audit repeatable and enforced)

**Why first.** An audit finding that is fixed but not *enforced* silently
regresses on the next commit. Today nothing mechanically prevents that: there
is no `rust-toolchain.toml`, no committed lint config, and CI builds release
packages without building or testing the workspace. Establish the gates first
so the rest of the audit measures a frozen, reproducible target.

| ID | Task | Command / change | Exit gate | Track |
|---|---|---|---|---|
| **A1** | Pin toolchain + lint config | Add `rust-toolchain.toml` (pin exact stable + components `clippy,rustfmt,llvm-tools-preview`); commit `rustfmt.toml` and `clippy.toml`; decide a workspace `lints` policy in root `Cargo.toml` (`[workspace.lints.rust] warnings = "deny"` or documented exceptions). | A clean checkout builds with one pinned compiler; `cargo fmt --all --check` and `cargo clippy` use committed config. | DEVNET-BLOCK |
| **A2** | CI that builds + tests + lints | New workflow (PR + merge) running `cargo build --workspace --all-targets`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`. Add Rust caching; record MSRV. | The ~18,900 tests actually execute in CI and are green; clippy/fmt enforced on every PR. Capture the run URL as evidence. | DEVNET-BLOCK |
| **A3** | Supply-chain gates | `cargo deny check` (advisories, bans, licenses, sources) with a committed `deny.toml`; `cargo audit`; dependabot or renovate config; SBOM via `cargo cyclonedx` (or `syft`) attached to release artifacts. | Zero un-triaged RUSTSEC advisories across the 368 locked crates; `deny.toml` present and enforced; SBOM produced. | DEVNET-BLOCK |
| **A4** | Static analysis actually wired | Add a **CodeQL** workflow (the control the docs cite but that never ran); run `cargo geiger` to produce an authoritative `unsafe` inventory to drive B2. | CodeQL runs on every PR and results are triaged (not merely referenced in prose); `cargo geiger` output committed. | DEVNET-BLOCK |
| **A5** | Coverage baseline | `cargo llvm-cov --workspace --lcov` to learn what the test suite exercises. Flag the under-tested crates: `qbind-genesis` and `qbind-gov` (1 test file each) and `qbind-remote-signer` (untested). | Per-crate coverage report committed; agreed floor for the §2 critical-surface crates; coverage gap for signer/genesis/gov has a remediation task. | CARRY-FORWARD |

**Gate A (baseline complete):** a reviewer can check out the audited commit,
run one documented command sequence, and reproduce build + full test + clippy +
fmt + deny + coverage locally and in CI.

---

## §2 — Workstream B: Deep code audit of the critical surface

Scope note: `qbind-node` is ~394k LOC, but ~140 of its files are decomposed
`pqc_*_completion` / `pqc_production_live_epoch_*` scaffolding. The
security-relevant logic is far more concentrated than the file count suggests.
Audit the targets below to depth; sweep the rest for the §2.9 panic surface.

Each sub-area: **scope · threat questions · exact files · technique · exit
gate**.

### B1 — Cryptography & key management  *(highest priority)*

**The toy-suite production gate is the single most important crypto boundary.**
`SUITE_TOY_SHA3 = ConsensusSigSuiteId(0)` (`crates/qbind-crypto/src/consensus_sig.rs`,
~line 59, marked "NOT FOR PRODUCTION") is wired into real consensus via
`crates/qbind-consensus/src/crypto_verifier.rs` (`with_toy_sha3`,
`SingleSuiteKeyProviderAdapter`). The gate lives in
`crates/qbind-node/src/startup_validation.rs`
(`ToySuiteNotAllowed`, `allow_toy_suites`, `InsufficientSecurityBits`,
`SuiteDowngradeAcrossEpochs`).

- **Threat questions:**
  - Can any DevNet/TestNet/MainNet config path reach consensus with suite 0?
    Is `allow_toy_suites` reachable outside unit tests, via env/CLI/config?
  - Is `InsufficientSecurityBits` enforced for *every* validator key at
    startup *and* at epoch/keyset transitions — not only at genesis?
  - Can a keyset rotation or governance action downgrade the suite across an
    epoch boundary (`SuiteDowngradeAcrossEpochs`)?
  - PBKDF2 `DEFAULT_PBKDF2_ITERATIONS = 100_000` (`crates/qbind-crypto/src/kdf.rs`)
    vs. OWASP 600k for PBKDF2-HMAC-SHA256 — keystore passphrase strength.
  - Keystore: is `LocalFsValidatorKeystore` (plaintext hex JSON) forbidden on
    non-DevNet profiles? Are key files written `0600`? Is `zeroize` applied on
    every load path (`crates/qbind-node/src/keystore.rs`)?
  - HSM/remote-signer trust boundary: what does the consensus host trust from
    `crates/qbind-remote-signer/` and `remote_signer.rs` /
    `pqc_remote_authority_signer.rs`? Replay/authn of the signer channel.
- **Technique:** targeted reading + a **negative test**: construct a config/env
  that *tries* to start consensus with suite 0 or a short key on the
  devnet/testnet/mainnet profile and assert startup is refused. Add this as a
  permanent regression test, not a one-off.
- **Exit gate:** a committed test proves suite 0 and sub-threshold security are
  rejected on all non-DevNet profiles and across an epoch transition; keystore
  perms + zeroize confirmed or filed. Track: **CARRY-FORWARD** (suite gate,
  key handling) + DEVNET-BLOCK for the devnet-profile startup refusal.

### B2 — Consensus safety & liveness

- **Memory safety of hand-rolled `unsafe`** — the #1 memory target:
  `crates/qbind-consensus/src/received_vote_evidence.rs` (**~49 `unsafe`
  blocks**: manual `alloc`/`dealloc`, `Vec::from_raw_parts`, `NonNull`,
  raw-pointer `ExactBuffer`, `ptr::read`, `unsafe impl Send/Sync`) in
  consensus-critical evidence handling, and
  `crates/qbind-consensus/src/basic_hotstuff_engine.rs` (~8, manual
  leader-signer buffer alloc). Also the manual-alloc blocks in
  `crates/qbind-node/src/safety_record_store/owner/` and the `libc::kill` /
  `raise(SIGTERM)` in `.../owner/model.rs`.
  - **Threat questions:** any use-after-free, double-free, leak, uninitialized
    read, alignment or provenance violation? Are the `unsafe impl Send/Sync`
    claims actually sound under concurrent access?
  - **Technique:** `cargo +nightly miri test` on `qbind-consensus` and the
    affected `qbind-node` modules; ASAN build (`RUSTFLAGS=-Zsanitizer=address`)
    over the consensus tests; `loom` models for the `Send/Sync` types. **If any
    `unsafe` block is not justified by a measured need, the finding is "replace
    with safe `Vec`/`Box`"** — hand-rolled allocators in consensus are a
    liability regardless of current correctness.
  - **Exit gate:** Miri clean (or every residual documented and justified);
    each `unsafe` block has a safety comment stating its invariant; no
    `Send/Sync` claim unbacked. Track: **CARRY-FORWARD (Critical class)**.
- **QC / voting correctness:** `crates/qbind-consensus/src/qc.rs`,
  `qc_verify_domain.rs`, `vote_accumulator.rs`, `block_state.rs`.
  - **Threat questions:** can the same validator's vote be counted twice toward
    a quorum (duplicate-vote)? Is equivocation (two votes, same height,
    different block) detected and rejected before QC formation? Is the 2f+1
    voting-**power** (stake-weighted) threshold computed with no
    integer-overflow and no off-by-one? Is the signing domain
    (`qbind-wire` proposal-vote domain, see `QBIND_PROPOSAL_VOTE_SIGNING_DOMAIN_V2`)
    bound to height/view/chain so a vote can't be replayed into another context?
  - **Exit gate:** property/sim tests assert "no two conflicting QCs can form
    with < f+1 Byzantine power" and "duplicate signer never double-counts".
    Track: **CARRY-FORWARD (Critical)**.
- **Timeout / view-change (self-declared incomplete, whitepaper §8.10):**
  `crates/qbind-consensus/src/timeout.rs`, `timeout_verify.rs`, `pacemaker.rs`,
  `driver.rs`.
  - **Threat questions:** under leader failure or partition, does the engine
    make progress (liveness) *without* ever violating safety? What exactly is
    "incomplete" per §8.10, and is the incomplete part reachable on the DevNet
    path? A safety bug here is Critical and carries forward.
  - **Exit gate:** the gap in §8.10 is characterized precisely (what works,
    what doesn't, what is reachable); adversarial sim (C3) covers leader
    failure + partition with a safety assertion. Track: **CARRY-FORWARD**;
    DEVNET-BLOCK if the incomplete path is reachable in single/low-validator
    DevNet.

### B3 — Slashing & validator-economics reality

Determine **which engine the live node actually wires**: `NoopSlashingEngine`
(records evidence only) vs. the real `PenaltySlashingEngine` /
`LedgerSlashingBackend` (`burn_stake_bps`, `jail_validator`,
`apply_penalty_atomic`). Files: `crates/qbind-consensus/src/slashing/mod.rs`,
`crates/qbind-ledger/src/slashing_ledger.rs`,
`crates/qbind-node/src/ledger_slashing_backend.rs`, and the wiring in the node
startup / consensus loop. Cross-check
[`docs/protocol/SLASHING_INVARIANTS_AUDIT.md`](../protocol/SLASHING_INVARIANTS_AUDIT.md).

- **Threat questions:** if the live wiring is Noop, misbehavior (offenses
  O1–O5: double-sign, invalid proposer sig, lazy voting, invalid DAG cert,
  DAG/consensus coupling) has *no economic consequence* — acceptable for DevNet,
  not for a value-bearing network. Is penalty application atomic with state
  commit (no partial burn)? Can jailing be gamed (self-jail to dodge a larger
  penalty)? Is stake math overflow-safe?
- **Exit gate:** the live-wired engine is documented with code evidence; if
  Noop, a `CARRY-FORWARD` finding records that real enforcement is a
  TestNet/MainNet gate with an owner. Track: **CARRY-FORWARD**.

### B4 — Networking / P2P DoS and transport

Files: `crates/qbind-net/src/{handshake.rs,handshake_packet.rs,cookie.rs,session.rs,transport.rs,framed_io.rs,hkdf.rs}`
and `crates/qbind-node/src/{p2p_inbound.rs,p2p_discovery.rs,p2p_diversity.rs,p2p_session_eviction.rs,peer_rate_limiter.rs,consensus_net*.rs,dag_net*.rs,public_devnet_abuse_dos_runtime.rs,public_devnet_abuse_dos_config.rs}`.

- **Threat questions:**
  - The global **inbound connection-rate limiter is disabled in the default
    profile** (`public_devnet_abuse_dos_runtime.rs`). For a *public* DevNet
    with an open port, should the default flip to on? (DEVNET-BLOCK candidate.)
  - Re-verify the good designs actually hold on the audited commit: server
    issues `ServerCookie` and validates it **before** ML-KEM decapsulation
    (`cookie.rs`/`handshake.rs`); session AEAD nonce
    `flag‖session_id‖counter` is monotonic and **errors at `u64::MAX` before
    reuse** (`session.rs`). Confirm no code path resets the counter or reuses a
    session id.
  - Message decoders: can an attacker-sized length prefix cause a large
    allocation before validation (alloc-DoS), or a panic (liveness-DoS)? See
    B5 and §2.9.
  - Eclipse/partition: peer diversity and eviction logic — can an attacker fill
    the inbound table and isolate a node?
- **Technique:** fuzz the handshake/frame parser (C1); send oversized/short/
  malformed frames at a live node and assert graceful rejection, bounded
  memory, no panic.
- **Exit gate:** default DoS posture for public DevNet decided and justified;
  cookie-before-decap and nonce-monotonicity re-confirmed with a test;
  decoder fuzz runs clean. Track: **DEVNET-BLOCK** (default DoS posture) +
  **CARRY-FORWARD** (decoder robustness).

### B5 — State, storage, serialization

Files: `crates/qbind-wire/`, `crates/qbind-serde/`,
`crates/qbind-node/src/{storage.rs,production_consensus_storage.rs,block_store.rs,commit_index.rs,snapshot_restore.rs,restore_completion.rs}`,
`crates/qbind-ledger/src/{store.rs,state_snapshot.rs,state_pruning.rs}`,
Merkle in `crates/qbind-runtime/src/block.rs` (`merkle_root`).

- **Threat questions:**
  - Decoders take `&mut &[u8]` and return `Result` (good) — but are all
    length prefixes bounds-checked *before* allocation, and are the ~36
    slice/`as usize` index patterns panic-free on truncated/oversized input?
  - RocksDB default write path is async/un-fsync'd with explicit
    `flush_epoch_durable` / `*_synced` barriers — on crash exactly at a commit,
    can the node come back with a torn/ahead-of-durable state that violates
    safety? Is the durability barrier actually invoked on the commit path?
  - Merkle (`merkle_root`): second-preimage via odd-leaf duplication, or
    leaf/internal-node domain confusion? `tx_root`/`receipts_root` integrity.
  - Snapshot/restore and pruning: can a crafted snapshot corrupt state on
    restore? Is the restored state root verified?
- **Technique:** `cargo-fuzz` round-trip + malformed-input targets on wire/serde
  (C1); crash-injection on the storage commit path (C4); a Merkle unit test for
  the odd-leaf case.
- **Exit gate:** fuzz targets exist and run clean in CI; durability barrier
  proven on the commit path with a crash-recovery test; Merkle construction has
  a second-preimage regression test. Track: **CARRY-FORWARD**.

### B6 — Execution & value math

Files: `crates/qbind-ledger/src/{account.rs,monetary_engine.rs,monetary_state.rs,execution.rs,execution_gas.rs,parallel_exec.rs}`,
`crates/qbind-node/src/{mempool.rs,dag_mempool.rs}`,
`crates/qbind-runtime/src/{qbind_tx.rs,gas_model.rs,revm_engine.rs,vm_v0_runtime.rs}`.

- **Threat questions:**
  - **`saturating_*` on balances/issuance silently caps instead of rejecting**
    — enumerate every `saturating_` on a monetary quantity and decide whether
    silent cap is correct or must become a checked error. Value that saturates
    is value created or destroyed.
  - **`monetary_state.rs` ~line 1367 (`TODO(T201)`):** on treasury-credit
    failure the code only `eprintln!`s and returns — a silent failure in a
    value path. Must become a hard error.
  - ~997 `as u64/u128/usize` casts — which are truncating on attacker- or
    state-controlled values?
  - Mempool: nonce monotonicity, replay protection, and **cross-`chain_id`
    replay** — `chain_id` is a plain string (`"qbind-devnet-v0"`); is it bound
    into the tx signing domain so a DevNet tx can't be replayed on TestNet?
    Fee/gas underflow in `compute_tx_mempool_cost`.
  - EVM (`revm`) + `vm_v0`: gas metering correctness, state-commit consistency
    between the two execution paths.
- **Technique:** property tests asserting **conservation of value** (total
  supply invariant across apply), overflow fuzzing on the gas/fee path (extend
  the existing `t177/t179` proptests), and a grep-driven census of
  `saturating_`/`as` on monetary types with a per-site verdict.
- **Exit gate:** T201 fixed-or-filed; every monetary `saturating_`/cast has a
  verdict; conservation-of-value property test green; cross-chain replay
  protection proven. Track: **CARRY-FORWARD (Critical class — value)**.

### B7 — Governance & upgrade authority

Files: `crates/qbind-gov/src/{verify.rs,council.rs,envelope.rs,hash.rs}`,
`crates/qbind-node/src/{genesis_consensus_authority.rs,pqc_boot_genesis.rs,genesis_authority_record_correspondence.rs}`.
Cross-check [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
and [`QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md`](../protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md).

- **Threat questions:**
  - `verify_envelope`: can the **same council member be counted twice** toward
    the M-of-N threshold (duplicate-signer)? Is each signature checked against a
    distinct, known member? Any ML-DSA signature malleability admitted?
  - The genesis `authority` block is "**not yet consumed by any live
    ratification verifier**" — is governance/upgrade authority actually
    enforced at runtime, or only declared in genesis? An unenforced upgrade
    authority is a MainNet-critical gap.
- **Exit gate:** duplicate-signer and threshold correctness proven by test;
  the genesis-authority consumption gap is characterized and tracked. Track:
  **CARRY-FORWARD**.

### B8 — Panic-surface triage (breadth sweep)

Raw counts (`~3,900 .unwrap()`, `~2,500 .expect()`, `~393 panic!`) are inflated
by inline `#[cfg(test)]` modules.

- **Technique:** mechanically isolate **non-test** occurrences (AST, or
  `rg` with a "before first `#[cfg(test)]`" filter, or `cargo-geiger`-style
  tooling) in the attacker-reachable paths first: `dag_mempool.rs`,
  `consensus_net*.rs`, `p2p_inbound.rs`, the wire/serde decoders, and
  `received_vote_evidence.rs`.
- **Exit gate:** a census of non-test panics on attacker-reachable input exists;
  each is either proven unreachable, guarded, or converted to a propagated
  error. Track: **CARRY-FORWARD (liveness)**; DEVNET-BLOCK for any proven
  remote-crash.

**Gate B (deep audit complete):** every sub-area has a verdict with evidence;
no open Critical; carry-forward items recorded against the §6 matrix.

---

## §3 — Workstream C: Dynamic & adversarial validation

Static reading finds *some* bugs; the rest need the code running against hostile
input and hostile peers. QBIND currently has fuzzing = 0 and property testing on
only the VM/gas path.

| ID | Task | How | Exit gate | Track |
|---|---|---|---|---|
| **C1** | Fuzzing | `cargo-fuzz` targets for: wire/serde decoders, handshake/frame parser (`qbind-net`), tx decode + mempool admission, QC/vote-evidence parse. Seed corpus from existing test vectors; run short in PR CI, long nightly. | Targets exist, run clean; corpus + any crash repros committed. | CARRY-FORWARD |
| **C2** | Property tests (expand) | Beyond `t177/t179`: consensus safety invariants (B2), ledger **conservation of value** (B6), serde round-trip (`decode(encode(x)) == x`). `proptest` already a dev-dep in `qbind-ledger`/`qbind-node`. | New proptest suites green in CI. | CARRY-FORWARD |
| **C3** | Adversarial simulation | Reuse `crates/qbind-consensus/src/{sim.rs,multi_sim.rs,adversarial_multi_sim.rs}`: equivocation, vote-withholding, network partition, leader failure. Assert **safety** (no conflicting commits) and **liveness** (eventual progress). | Byzantine scenarios run in CI with safety/liveness assertions; any violation is a Critical finding. | CARRY-FORWARD |
| **C4** | Multi-node soak + chaos | Drive the real `qbind-node` binary via the `scripts/devnet/run_*` harnesses, multi-validator, under latency/packet-loss/restart/clock-skew. Assert crash-recovery and **cross-node state-root agreement** each epoch. | A reproducible N-node soak passes; crash-at-commit recovers to a consistent root. | DEVNET-BLOCK |
| **C5** | Sanitizers | Miri on unsafe-bearing crates (B2); ASAN/TSAN over consensus+net tests; `loom` for the `unsafe impl Send/Sync` types. | Sanitizer runs clean or residuals documented. | CARRY-FORWARD |

**Gate C:** fuzzing + property + adversarial-sim + multi-node soak all run in
CI (nightly where long), and the crash/repro corpus is committed.

---

## §4 — Workstream D: Release engineering & operational readiness (DevNet)

| ID | Task | Detail | Exit gate | Track |
|---|---|---|---|---|
| **D1** | Reproducible build + provenance | Verify `scripts/build-mainnet-release.sh` is bit-reproducible on a clean host; confirm the release-artifact manifest + Sigstore attestation workflow; pin genesis via `--expect-genesis-hash` against `docs/release/public-devnet/genesis/devnet-genesis.json` (`0x48b3a862…`). | Two independent builds hash-match; genesis hash pin verified. | DEVNET-BLOCK |
| **D2** | Operator attack surface | Metrics HTTP (`crates/qbind-node/src/metrics_http.rs`) must **not** bind `0.0.0.0` by default and must expose nothing sensitive unauthenticated; keystore file perms (B1); `node_config.rs` profile-invariant validation. Close tracked **M-series launch blockers**, notably **M4 live seeds** (currently Yellow) in `docs/release/public-devnet/network/`. | Metrics bind + config invariants confirmed; M-gates Green per the blocker register. | DEVNET-BLOCK |
| **D3** | Ops drills | Dry-run monitoring/alerting baseline; execute a backup/restore drill; walk the incident-response and PQC-trust-lifecycle runbooks in `docs/ops/`. | Each runbook executed once end-to-end with captured output. | DEVNET-BLOCK (restore) / DEFERRABLE (scale) |
| **D4** | Missing policy artifacts | Add `SECURITY.md` (+ coordinated-disclosure contact/policy), a `LICENSE`, `CHANGELOG.md`, `CODEOWNERS`, and a standalone **threat-model** document (data-flow + trust boundaries: P2P ingress, signer channel, governance envelope, genesis authority). | All five artifacts committed; threat model reviewed against §2 findings. | DEVNET-BLOCK (`SECURITY.md`, `LICENSE`, threat model) |

**Gate D:** a public operator can obtain a provenance-verified binary, run a
node safely with sane defaults, recover from a crash, and report a
vulnerability through a documented channel.

---

## §5 — Workstream E: Evidence-vs-reality reconciliation

Produce `docs/security/evidence/E-drift/README.md`: a drift report that takes
each major readiness claim and records **claim → reality → verdict**. Minimum
set (add any found during §1–§4):

| Claimed | Check against reality | Expected finding |
|---|---|---|
| CodeQL is the security gate | No CodeQL workflow exists; "did not run" | Drift → A4 |
| Test suite enforces quality | No CI runs `cargo test` | Drift → A2 |
| Slashing present | Live-wired engine may be Noop (B3) | Drift → B3 |
| Timeout/view-change works | Whitepaper §8.10 marks it incomplete (B2) | Drift → B2 |
| Genesis authority governs | "Not consumed by any live verifier" (B7) | Drift → B7 |
| DoS protections on | Inbound rate limiter default-disabled (B4) | Drift → B4 |

**Exit gate:** every row has a verdict and links to its tracker item; no claim
in the readiness corpus is left unchecked. This is where "no gaps" is proven:
the gap between the paper trail and the running code is closed or explicitly
owned.

---

## §6 — Carry-forward matrix (TestNet / MainNet)

The forward-looking guarantee. "DevNet has no value" never excuses a
`CORRECT-NOW` item.

| Area | Item | DevNet | TestNet/MainNet | Classification |
|---|---|---|---|---|
| Crypto | Toy-suite rejection on prod profiles (B1) | must refuse on devnet profile | Critical | **CORRECT-NOW** |
| Crypto | Min-security-bits + no cross-epoch downgrade (B1) | — | Critical | **CORRECT-NOW** |
| Consensus | `unsafe` memory safety (B2) | — | Critical | **CORRECT-NOW** |
| Consensus | QC duplicate-vote / equivocation (B2) | — | Critical | **CORRECT-NOW** |
| Consensus | Safety under timeout/view-change (B2) | if reachable | Critical | **CORRECT-NOW** |
| Value | Conservation of value, no silent saturation, T201 (B6) | — | Critical | **CORRECT-NOW** |
| Value | Cross-chain-id replay protection (B6) | — | High | **CORRECT-NOW** |
| State | Decoder robustness / durability / Merkle (B5) | — | High | **CORRECT-NOW** |
| Net | Decoder panic/alloc DoS (B4, B8) | — | High | **CORRECT-NOW** |
| Net | Public DoS default posture (B4) | public port open | — | **DEVNET-BLOCK** |
| Governance | `verify_envelope` duplicate-signer (B7) | — | High | **CORRECT-NOW** |
| Slashing | Real penalty enforcement (B3) | Noop acceptable | required | **DEFERRABLE→TestNet gate** |
| Governance | Genesis-authority runtime consumption (B7) | declared | required | **DEFERRABLE→TestNet gate** |
| Ops | Live seed topology / scale (D2, D3) | minimal | required | **DEFERRABLE** |

**Rule:** every **CORRECT-NOW** row is audited to MainNet standard during the
DevNet cycle and must have no open Critical before DevNet opens, even though it
is not, strictly, a DevNet functional blocker.

---

## §7 — Sequencing, DevNet Go/No-Go, tracker

### 7.1 Order of execution

1. **A** (baseline) — freeze a reproducible, enforced target. *Nothing below is
   trustworthy until A2/A4 run.*
2. **B** (deep) in priority order **B1 → B2 → B6 → B4 → B5 → B3 → B7 → B8**,
   running **C** (dynamic) in parallel as each area's harness lands (B2↔C3/C5,
   B4/B5↔C1, B6↔C2, C4 once multi-node is stable).
3. **E** (reconciliation) — continuous; finalized after B/C.
4. **D** (release engineering) — last, as the Go/No-Go gate.

### 7.2 DevNet Go/No-Go checklist (feeds the existing `LAUNCH_GO_NO_GO.md`)

- [ ] Gate A green: CI builds + runs all tests + clippy + fmt + deny + CodeQL + coverage.
- [ ] Gate B: no open **Critical**; every **CORRECT-NOW** row (§6) audited, no open Critical.
- [ ] B1: suite-0/weak-suite rejection proven on all non-DevNet profiles **and** devnet startup refusal (regression test committed).
- [ ] B2: Miri/ASAN clean (or residuals justified) on `received_vote_evidence.rs` + HotStuff engine; QC duplicate/equivocation tests green.
- [ ] B6: conservation-of-value property test green; T201 resolved; cross-chain-id replay proven.
- [ ] B4: public DoS default posture decided; cookie-before-decap + nonce-monotonicity re-confirmed.
- [ ] Gate C: fuzz + proptest + adversarial sim + multi-node soak in CI; crash-recovery → consistent state root.
- [ ] Gate D: reproducible build hash-match; genesis hash pinned; metrics bind safe; `SECURITY.md` + `LICENSE` + threat model committed; M-series blockers Green (incl. M4 seeds).
- [ ] Gate E: drift report complete; every readiness claim has a verdict.
- [ ] Each checked box has a reproducible evidence bundle under `docs/security/evidence/<id>/`.

Any unchecked box ⇒ **NO-GO**.

### 7.3 Tracker

Use [`QBIND_DEEP_AUDIT_TRACKER.md`](./QBIND_DEEP_AUDIT_TRACKER.md). Keep the
tracker, the evidence dirs, and this playbook in sync; the tracker is the single
source of truth for status.

---

## §8 — Appendices

### 8.1 Tooling cheat-sheet

```bash
# Baseline (run from repo root, pinned toolchain)
cargo build --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check

# Supply chain
cargo install cargo-deny cargo-audit cargo-cyclonedx
cargo deny check
cargo audit
cargo cyclonedx --format json            # SBOM

# Coverage
cargo install cargo-llvm-cov
cargo llvm-cov --workspace --lcov --output-path lcov.info

# unsafe inventory + memory safety
cargo install cargo-geiger
cargo geiger
rustup toolchain install nightly --component miri
cargo +nightly miri test -p qbind-consensus
RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -p qbind-consensus --target x86_64-unknown-linux-gnu

# Fuzzing
cargo install cargo-fuzz
cargo fuzz add wire_decode && cargo fuzz run wire_decode

# Pin the audited commit in every evidence bundle
git rev-parse HEAD && git rev-parse HEAD^{tree}
```

### 8.2 Prioritized file-target index

1. `crates/qbind-crypto/src/consensus_sig.rs` · `crates/qbind-consensus/src/crypto_verifier.rs` · `crates/qbind-node/src/startup_validation.rs` — **toy-suite gate** (B1)
2. `crates/qbind-consensus/src/received_vote_evidence.rs` — **49 unsafe** (B2)
3. `crates/qbind-consensus/src/basic_hotstuff_engine.rs` — unsafe allocator (B2)
4. `crates/qbind-consensus/src/{qc.rs,vote_accumulator.rs,timeout.rs,pacemaker.rs,driver.rs}` — QC + view-change (B2)
5. `crates/qbind-ledger/src/{monetary_state.rs,monetary_engine.rs,account.rs}` — value math, T201 (B6)
6. `crates/qbind-node/src/{mempool.rs,dag_mempool.rs}` — replay/nonce/fees (B6)
7. `crates/qbind-net/src/{handshake.rs,cookie.rs,session.rs}` + `crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs` — transport + DoS (B4)
8. `crates/qbind-wire/`, `crates/qbind-serde/`, `crates/qbind-runtime/src/block.rs` — decoders + Merkle (B5)
9. `crates/qbind-consensus/src/slashing/` + `crates/qbind-ledger/src/slashing_ledger.rs` — slashing reality (B3)
10. `crates/qbind-gov/src/verify.rs` + genesis-authority files — governance (B7)
11. `crates/qbind-node/src/{keystore.rs,metrics_http.rs}` + `crates/qbind-crypto/src/kdf.rs` — keys + operator surface (B1/D2)

### 8.3 Severity & gate definitions — see §0.2 and §0.3.

### 8.4 Inputs to reconcile (claims, not evidence)

- [`Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`](../../Audit/QBIND_SECURITY_FINDINGS_REGISTER.md)
- [`docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md`](./QBIND_AUDIT_REMEDIATION_PLAN.md)
- [`docs/whitepaper/QBIND_WHITEPAPER.md`](../whitepaper/QBIND_WHITEPAPER.md) (§8.10) + [`contradiction.md`](../whitepaper/contradiction.md)
- [`docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`](../release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md) · [`BLOCKER_REGISTER.md`](../release/public-devnet/BLOCKER_REGISTER.md) · [`LAUNCH_GO_NO_GO.md`](../release/public-devnet/LAUNCH_GO_NO_GO.md)
- `docs/protocol/` audits (slashing invariants, state, validator economics, proposal-vote signing domain, trust-anchor authority model)
