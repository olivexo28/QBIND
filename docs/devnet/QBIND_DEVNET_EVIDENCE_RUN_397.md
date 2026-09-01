# QBIND DevNet Evidence — Run 397

Public DevNet **M4 external-seed reachability closure — preflight blocker note**.
Run 397 pursued the real launch blocker **M4** (deploy or verify a genuine
externally reachable public DevNet seed/bootnode, prove external TCP + strict
KEMTLS/static-root reachability from an independent off-host vantage, publish a
schema-valid live seed list, and — only if criteria permit — close the M4-gated
live-registration half of M6). It **stopped early at the hard preflight** because
the mandatory Route A infrastructure is not available in this environment.

**Decision gate:** **NEGATIVE-FOR-EXTERNAL / stop-early.** The task's hard preflight
requires that a durable operator-controlled seed host with a real public
IP/DNS, an inbound-openable P2P port, and an **independent off-host vantage point**
all exist before any files are changed. Prerequisites **1, 2, 3, 7, 8** fail here,
so Run 397 explicitly does **not** repeat a sandbox loopback Route C probe (already
captured by Runs 377/378/388/391/393) and records only a minimal blocker note.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.
Run 397 starts no node, opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status service, adds no CLI flag, changes no
Rust/`build.rs`/runtime behavior, changes no P2P wire format, weakens no peer
admission, enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker state.

## 1. Exact verdict

**NEGATIVE-FOR-EXTERNAL / public-DevNet M4 external seed reachability NOT proven.**
Real public seed infrastructure and an independent off-host vantage point are
unavailable in this sandboxed environment, so no external TCP or KEMTLS/static-root
evidence could be captured and no schema-valid live seed list could be published.
**M4 stays Yellow / launch-blocking**, **M6 stays Yellow / Partial**, **S5 stays
Yellow**, **S7 stays Yellow**; M1–M3, M5, M7–M20 and S1–S4, S6 remain Green; public
DevNet remains **NOT launch-ready**; **C4/C5 remain OPEN**. TestNet/MainNet
untouched.

## 2. Files changed

- `docs/release/public-devnet/network/reachability/RUN_397_qbind-devnet-seed-1.md`
  — minimal Route A preflight blocker record (no loopback probe, no live claim).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_397.md` — this evidence record.

No harness script, archive directory, `devnet-seeds.live.json`, or readiness-matrix
edit was created, because there is no external evidence to justify them and no
readiness status changes.

## 3. Route A hard-preflight result

| # | Prerequisite | Present? |
|---|--------------|----------|
| 1 | Durable operator-controlled DevNet seed host | **NO** |
| 2 | Real public IP / DNS name | **NO** |
| 3 | Inbound-openable public P2P port | **NO** |
| 4 | Durable DevNet seed identity | identity path exists; not provisioned live |
| 5 | Strict KEMTLS / static-root material | path exists; no durable operator material |
| 6 | Runnable release `qbind-node` on seed host | buildable locally; no seed host |
| 7 | Independent off-host vantage | **NO** |
| 8 | Vantage can run TCP + KEMTLS checks | **NO** |
| 9 | Publish-safe evidence capturable | N/A (no external endpoint) |

Prerequisites 1, 2, 3, 7, 8 fail; an outbound public-host connectivity check also
did not complete, confirming no public egress-to-ingress path. Per the task, the run
stops early.

## 4. Readiness delta

None. M4 Yellow, M6 Yellow/Partial, S5 Yellow, S7 Yellow, C4/C5 OPEN — all
unchanged. `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` was intentionally
**not** edited (no status moved).

## 5. Tests / checks run

- Route A hard-preflight verification (host / public IP / inbound port / off-host
  vantage / egress) — all external prerequisites absent.
- **No Rust source / `build.rs` change** in this run, so `cargo test` is not
  applicable; recorded honestly as no-Rust-delta.
- Secret scan over the two changed docs — no secrets/raw material/absolute paths.

## 6. CodeQL

Docs only; no Rust or `build.rs` change. CodeQL is **not meaningful / trivial** for
this change set (no compiled code paths added or modified). Recorded honestly — not
a skipped/timed-out clean claim.

## 7. Honest limitations

- Run 397 advances no readiness item; it only records that the M4 external step
  cannot be executed here and stops early instead of re-proving loopback.
- M4 Green still requires a real, externally reachable KEMTLS static-root seed and
  an independent off-host vantage. The infrastructure prerequisites are unchanged
  from `docs/release/public-devnet/network/reachability/RUN_393_qbind-devnet-seed-1.md`
  §15 and `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`.

## 8. Suggested Run 398

Execute the Route A objective on **real operator infrastructure** (durable public
seed host + independent off-host vantage), capture external TCP + KEMTLS/static-root
evidence, publish `devnet-seeds.live.json` (`status: live`), and only then move M4
Yellow → Green and evaluate the M4-gated M6 live-registration half.