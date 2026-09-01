# QBIND DevNet Evidence — Run 390

Public DevNet **ops** evidence for the M15 reset-policy and M16 incident-response documentation
blockers. Run 390 publishes a consolidated, operator-facing **ops** package
(`docs/release/public-devnet/ops/` — `README.md`, `RESET_POLICY.md`, `INCIDENT_RESPONSE.md`,
`SAFETY.md`, `VERIFY.md`) and verifies it against the **real** `qbind-node` CLI/help + source surfaces
and the existing ops runbooks, via the harness
`scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh` (`RESULT=POSITIVE`).

**Decision gate = Route B** (docs + a docs/verification harness; **no** production Rust source change,
**no** `build.rs` change, **no** new CLI flag). The only reset-related CLI surface referenced is the
pre-existing, **hidden**, offline operator-ceremony flag `--authority-state-reset` (Run 127).

**Safety label:** DevNet · experimental · resettable · no value · NOT public-DevNet launch-ready · no
M4 Green · no M6 fully-Green · no TestNet readiness · no MainNet readiness · no uptime SLA · **C4/C5
OPEN**. This evidence does not imply launch, TestNet, MainNet, C4, or C5 readiness. Run 390 starts no
node, opens no externally reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status page,
changes no P2P wire format, weakens no peer admission, enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker/LivePqcTrustState.

## 1. Exact verdict

**PASS / public-DevNet ops reset + incident-response guidance POSITIVE.** M15 (reset policy) and M16
(incident-response process) documentation is published and verified against real CLI/source surfaces
with no overclaim. **M15 moves Yellow → Green**; **M16 is reconciled to Green** with a public-DevNet
scoped incident-response artifact (its prior Green rested only on the internal, Beta-scoped
`docs/ops/QBIND_INCIDENT_RESPONSE.md`). M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial,
M12/M13/M14 remain Green, public DevNet remains **NOT launch-ready**, and **C4/C5 remain OPEN**.

## 2. Files changed

No production Rust source or `build.rs` change (docs + harness/archive only).

New:

- `docs/release/public-devnet/ops/README.md`
- `docs/release/public-devnet/ops/RESET_POLICY.md`
- `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`
- `docs/release/public-devnet/ops/SAFETY.md`
- `docs/release/public-devnet/ops/VERIFY.md`
- `scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh`
- `docs/devnet/run_390_public_devnet_ops_reset_incident_response/README.md`
- `docs/devnet/run_390_public_devnet_ops_reset_incident_response/summary.txt`
- `docs/devnet/run_390_public_devnet_ops_reset_incident_response/.gitignore`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_390.md` (this record)

Narrowly updated (cross-links + M15/M16 delta/reconciliation only):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/operator/README.md`
- `docs/release/public-devnet/operator/QUICKSTART.md`
- `docs/release/public-devnet/operator/SAFETY.md`
- `docs/release/public-devnet/observability/RUNBOOK.md`
- `docs/release/public-devnet/security/README.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

## 3. Decision gate route

**Route B** — existing CLI/source surfaces and ops runbooks are sufficient; publish docs plus a small
docs/verification harness that validates the documented commands, doc structure, and cross-links. No
production source change was required.

## 4. Ops package contents

`docs/release/public-devnet/ops/`: `README.md` (index/scope/cross-links/readiness), `RESET_POLICY.md`
(M15), `INCIDENT_RESPONSE.md` (M16), `SAFETY.md` (DevNet-only safety label + publish/never-publish
rules), and `VERIFY.md` (copy-paste operator checks). Every file carries the
experimental/resettable/no-value/no-C4-C5-closure safety header.

## 5. Reset policy guidance (M15)

`RESET_POLICY.md` covers: (1) DevNet-only safety label (experimental / resettable / no value / no
MainNet readiness / no C4-C5 closure); (2) what a reset means (state may be wiped; genesis pinned or
successor published; prior balances/state have no value / no persistence guarantee); (3) reset
triggers (safety incident, data corruption, trust-root/key compromise, protocol-breaking upgrade,
unrecoverable fork, planned maintenance); (4) notice policy (pre-announce when possible; emergency
reset without notice allowed for safety; UTC-timestamped record required after the fact); (5) operator
action (stop node; back up private keys only if still trusted; delete/reset data dir; verify genesis
hash; restart using published package); (6) what never changes silently (no hidden genesis, no silent
seed promotion, no implicit trust-root replacement, no MainNet/TestNet reuse); (7) the reset evidence
record shape; (8) the `--authority-state-reset` posture; and (9) no legal/financial/value guarantees.

## 6. Incident-response guidance (M16)

`INCIDENT_RESPONSE.md` covers: (1) DevNet incident severity levels (DS-0…DS-3, mapped to internal
Sev-0…Sev-3); (2) incident classes (seed unreachable; trust-bundle/root/signing-key mismatch;
suspected key compromise; peer flood/DoS; chain halt/no progress; bad release artifact/provenance
issue; reset event); (3) first-response steps per class; (4) evidence to capture (timestamps; binary
SHA/BuildID/manifest; metrics summaries only, not raw dumps; relevant node IDs; redacted config); (5)
escalation and rollback/reset decision points; (6) cross-links to observability alerts/runbook,
security package, P2P posture, reset policy, and the existing internal incident-response document; (7)
publication policy (publish a minimal incident summary; avoid secrets/private endpoints/raw logs); and
(8) explicit non-claims (no uptime SLA, no value protection, no MainNet readiness, no C4/C5 closure).
It references and defers to the **internal** `docs/ops/QBIND_INCIDENT_RESPONSE.md` for internal roles,
escalation, and the Beta evidence packet — this is the M16 reconciliation.

## 7. Reset evidence record shape

`reset_id`, `reason`, `utc_timestamp`, `old_genesis_hash`, `new_genesis_hash` (or "unchanged / genesis
pinned"), `operator_action`, `safety_statement`, `no_value_reminder`. Publish-safe values only — never
private keys, credentials, tokens, raw logs, raw metrics dumps, private endpoints/hostnames, or
absolute build paths.

## 8. Incident evidence / redaction rules

Capture UTC timestamps, release-artifact SHA-256/BuildID/manifest identifiers, **summarized** metric
counters (not raw scrapes), public node IDs, and **redacted** config. Never capture into a committed
record: private keys, KEM secrets, mnemonics, credentials, tokens, raw logs, raw metrics dumps, data
dirs, private endpoints, private hostnames, absolute build paths, or branch dirty-state strings.

## 9. CLI / help verification

`--authority-state-reset` (with companions `--authority-state-reset-output-audit`,
`--authority-state-reset-operator-note`) is a pre-existing Run 127 flag defined in
`crates/qbind-node/src/cli.rs` (`hide = true`) and dispatched offline in `crates/qbind-node/src/main.rs`
before any networking/consensus/metrics/SIGHUP/reload/peer-candidate machinery is installed. The
harness asserts it is **defined** in `cli.rs`, **dispatched** in `main.rs`, and **hidden** from
`qbind-node --help`, and that the ops docs reference **no** invented reset/incident CLI flag. No new
CLI flag is added.

## 10. Cross-link verification

The harness confirms the ops docs cross-link `docs/release/public-devnet/operator/`,
`docs/release/public-devnet/observability/`, `docs/release/public-devnet/security/`,
`docs/release/public-devnet/network/`, `docs/ops/QBIND_INCIDENT_RESPONSE.md`, and
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`. The observability `RUNBOOK.md`, operator
`README.md`/`QUICKSTART.md`/`SAFETY.md`, and security `README.md` cross-link back to the ops package.

## 11. Non-claim checks

Non-claim grep over `docs/release/public-devnet/ops/` finds no forbidden `launch-ready` / `M4 Green` /
`C4 closed` / `C5 closed` / `TestNet ready` / `MainNet ready` / `uptime SLA` claim (negations and
"remains OPEN/Yellow" statements excluded). `non_claim_grep=OK`.

## 12. Default compatibility

No default behaviour change. No CLI flag added or altered. `--authority-state-reset` remains a hidden,
offline, opt-in operator ceremony (unchanged). The node's normal startup path, wire format, peer
admission, and trust/validator/epoch/sequence/marker state are untouched.

## 13. CLI surface

Unchanged. The only reset-related surface is the pre-existing hidden offline `--authority-state-reset`
(+ its two companion flags). No new public or hidden flag is introduced.

## 14. Runtime mutation check

None. Run 390 starts no node and mutates no runtime state. `--authority-state-reset` is documented as
an offline marker-persistence ceremony that derives a new authority marker only from a verified genesis
authority block + verified ratification sidecar (DevNet/TestNet allowed, MainNet refused); it performs
no live/peer-driven apply, mutates no running `LivePqcTrustState`/validator-set/epoch/sequence, and
implies no live governance / authority-lifecycle activation / C4-C5 closure.

## 15. Readiness delta — M15

**Yellow → Green.** DevNet reset policy published (`docs/release/public-devnet/ops/RESET_POLICY.md`)
and verified (all required sections present; `--authority-state-reset` posture documented; non-claim
grep clean). The readiness matrix checklist, §10 status row, §11 next-run row, §16 gap-matrix row, and
§8/§9 evidence tables are updated to Green.

## 16. Readiness delta / reconciliation — M16

**Green (reconciled).** The prior Green rested only on the internal, Beta/MainNet-readiness-scoped
`docs/ops/QBIND_INCIDENT_RESPONSE.md` (explicitly not a public status page and not written for the
public DevNet audience), while the checklist showed `- [ ] M16` and top-of-file run summaries listed
M16 inconsistently. Run 390 resolves this by publishing a **public-DevNet-scoped** operator
incident-response process (`docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`) that references and
defers to the internal procedure. M16 is preserved as Green on the basis of this public-DevNet scoped
evidence; the checklist and matrix rows are updated consistently (no pretend "new Green move").

## 17. Public DevNet status

**NOT launch-ready.** M4 remains Yellow/launch-blocking; because at least one must-have is not Green,
public DevNet is not launch-ready.

## 18. Remaining DevNet blockers

- **M4** (seed/bootnodes) — Yellow; no externally reachable seed / no independent external reachability
  evidence (Run 378/388 Route C). Launch blocker.
- **M6** (validator identity) — Yellow/Partial; generation/verification + register-check are
  Green-for-scope (Run 375/376), but a live registration path is M4-gated and operator-root
  reuse/rotation/revocation is C4/C5-OPEN.

## 19. TestNet blockers

Untouched: faucet (T1), public RPC gateway + rate limiting (T2/T3), explorer (T4), governance-proof
surface hardening at scale (T5), live validator-set rotation (T6), data-retention SLAs (T7),
soak/chaos/multi-region (T8), and the TestNet Alpha/Beta exit gates.

## 20. MainNet blockers

Untouched: MainNet custody (N1), MainNet authority rotation/revocation (N2 — Red), runtime
authority-lifecycle wiring (N3), SLSA-grade signed provenance (N4), C4 closure (N5), C5 closure (N6),
production economic finalization (N7).

## 21. C4/C5

**OPEN.** Run 390 makes no C4 or C5 closure claim. `--authority-state-reset` is an offline ceremony and
implies no live governance / authority-lifecycle activation / C4-C5 closure.

## 22. Tests run

- `scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh` → `RESULT=POSITIVE`
  (build; reset-flag defined/offline-dispatched/hidden; ops files present; safety labels; reset-policy
  sections; incident-response sections + classes; cross-links; non-claim grep; no private/raw
  artifacts; readiness reconciliation).
- `cargo build -p qbind-node --release --locked --bin qbind-node` → builds
  (SHA-256 `5d6ae6210c06acc086b7eedf4b234e57e1525103e2fa69b1633e9418c8c2179f`, BuildID
  `ca7da940e6c1453340d8ee85eb637f908501d90d`, toolchain rustc/cargo 1.98.0).
- `cargo test -p qbind-node --lib` — **not run: no Rust source changed** (docs + harness only; honest
  no-Rust-delta baseline).

## 23. Security scans

Secret scanning run over all changed files — no secrets. No private keys, credentials, tokens, raw
logs, raw metrics dumps, data dirs, private endpoints, private hostnames, absolute build paths, or
branch dirty-state strings are committed. The archive directory tracks only `README.md`, `summary.txt`
(publish-safe hashes + status lines), and `.gitignore`.

## 24. CodeQL

**Trivial / not meaningful for this change.** Run 390 is docs + a Bash verification harness only, with
no Rust / `build.rs` change, so CodeQL code analysis has no compiled surface to analyze for this delta.

## 25. Provenance

- Release binary SHA-256: `5d6ae6210c06acc086b7eedf4b234e57e1525103e2fa69b1633e9418c8c2179f`
- ELF BuildID: `ca7da940e6c1453340d8ee85eb637f908501d90d`
- Toolchain: `rustc 1.98.0 (88d9e12ae 2026-08-18)` / `cargo 1.98.0 (797e8a9bc 2026-08-05)`
- Harness: `scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh` (`RESULT=POSITIVE`)
- Archive: `docs/devnet/run_390_public_devnet_ops_reset_incident_response/` (README + summary +
  .gitignore only)

## 26. Honest limitations

- This is documentation + verification only; it does not create live infrastructure, does not prove
  external reachability, and does not exercise a real reset on a live network.
- `RESET_POLICY.md` describes a **network-wide operational** reset (state wipe) as an operator/coordinator
  action; it is not automated by any single CLI flag. `--authority-state-reset` is a narrower offline
  marker-persistence ceremony, documented as such.
- M16 remains scoped to public DevNet operator needs; production incident-response depth (internal
  roles, evidence packet, MainNet-readiness exercises) stays in the internal document.

## 27. Suggested Run 391

Pursue the remaining launch blockers directly: attempt **M4** real external seed reachability from an
independent external vantage point (Route A) or record the Route C blocker again with any new
infrastructure options, and — if M4 advances — stage the M4-gated **M6** live registration path. No
new public CLI flag; no C4/C5 closure.