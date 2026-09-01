# QBIND DevNet Evidence — Run 392

Public DevNet **seed-node operations** evidence for the S7 should-have (seed-node operational runbook)
and the M4 Route-A deployment path. Run 392 publishes a consolidated, operator-facing seed-node
operations package under `docs/release/public-devnet/network/` — `SEED_NODE_OPERATIONS.md`,
`M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`, `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` — and verifies it
against the **real** `qbind-node` CLI/help + seed-list schema surfaces via the harness
`scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh` (`RESULT=POSITIVE`).

**Decision gate = Route B** (docs + a docs/verification harness; **no** production Rust source change,
**no** `build.rs` change, **no** new CLI flag). Route A (a real externally reachable seed proven from
an independent off-host vantage point) is **not** available in this sandbox — the same Route C finding
as Run 378/388/391 — so Run 392 **prepares** but does not execute the real M4 external reachability
run, and fakes no endpoint or reachability.

**Safety label:** DevNet · experimental · resettable · no value · NOT public-DevNet launch-ready · no
M4 Green · no M6 fully-Green · no TestNet readiness · no MainNet readiness · no uptime SLA · **C4/C5
OPEN**. Run 392 starts no node, opens no externally reachable port, deploys no
seed/bootnode/faucet/RPC/explorer/status page, changes no P2P wire format, weakens no peer admission,
enables no peer-driven apply, and mutates no trust/validator/epoch/sequence/marker/LivePqcTrustState.

## 1. Exact verdict

**PASS / public-DevNet seed-node operations + M4 Route-A checklist POSITIVE.** The seed-node operations
runbook, the M4 Route-A deployment checklist, and the reachability evidence template are published and
verified against real CLI/schema surfaces with no overclaim. **S7 moves Red → Yellow** (should-have
runbook published + verified; operating a live seed remains M4-gated). **M4 stays Yellow/launch-blocking**,
**M6 stays Yellow/Partial**, **M12/M13/M14/M15/M16 remain Green**, public DevNet remains **NOT
launch-ready**, and **C4/C5 remain OPEN**.

## 2. Files changed

No production Rust source or `build.rs` change (docs + harness/archive only).

New:

- `docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md`
- `docs/release/public-devnet/network/M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`
- `docs/release/public-devnet/network/SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`
- `scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh`
- `docs/devnet/run_392_public_devnet_seed_ops_route_a_checklist/README.md`
- `docs/devnet/run_392_public_devnet_seed_ops_route_a_checklist/summary.txt`
- `docs/devnet/run_392_public_devnet_seed_ops_route_a_checklist/.gitignore`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_392.md` (this record)

Narrowly updated (cross-links + S7 delta only):

- `docs/release/public-devnet/network/README.md`
- `docs/release/public-devnet/network/VERIFY.md`
- `docs/release/public-devnet/operator/QUICKSTART.md`
- `docs/release/public-devnet/security/README.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

## 3. Decision gate route

**Route B** — real external seed infrastructure and an independent off-host vantage point are not
available (Route A cannot run; the sandbox reaches the same Route C finding as Run 378/388/391), and
existing docs did not yet fully cover seed-node operation (Route C rejected). Publish the seed-ops
docs plus a small docs/verification harness that validates the documented commands, doc structure, and
cross-links. No production source change was required.

## 4. Seed-ops package contents

`docs/release/public-devnet/network/`: `SEED_NODE_OPERATIONS.md` (S7 runbook),
`M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md` (the exact Route-A checklist to move M4 Green),
`SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` (canonical reachability evidence record format). Every file
carries the experimental/resettable/no-value/no-C4-C5-closure DevNet safety label.

## 5. Seed-node operations guidance

`SEED_NODE_OPERATIONS.md` covers: (1) DevNet-only safety label; (2) seed operator role and
responsibilities; (3) durable seed identity generation + custody (`qbind-node identity generate devnet
seed`; ML-KEM leaf secret private/`0600`; root/signing secrets never committed; replace preflight
illustrative identities before live publication; non-mutating `register-check` before publishing);
(4) the real public-seed startup command (`--env devnet`, `--network-mode p2p`, `--enable-p2p`,
public bind/advertised posture, `--p2p-mutual-auth required`, `--p2p-pqc-root-mode pqc-static-root`,
`--p2p-trusted-root`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--genesis-path`,
`--expect-genesis-hash`); (5) firewall/NAT/security-group requirements; (6) metrics exposure
(loopback-only `QBIND_METRICS_HTTP_ADDR`; never expose unauthenticated metrics publicly); (7)
operational checks (process running; P2P port listening; genesis hash pinned; build provenance known;
NodeId/cert matches public identity); (8) failure handling (keep `status: planned`; do not publish
`devnet-seeds.live.json`; document Route C/Route B honestly); (9) retirement/removal of a bad seed
(`status: retired`; no silent replacement; publish reachability/incident note).

## 6. Route-A deployment checklist

`M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md` covers: (1) preflight prerequisites; (2) exact seed identity
material checklist; (3) exact public endpoint checklist; (4) exact strict KEMTLS/static-root checklist;
(5) independent vantage requirements (outside seed host/NAT; same-host/same-NAT/private-VPN/loopback/
RFC 5737 are insufficient); (6) required external TCP evidence; (7) required external KEMTLS/static-root
evidence; (8) seed-list promotion (`devnet-seeds.live.json`, `status: live`, non-null
`last_reachability_evidence`, schema-valid, genesis matching Run 356); (9) `register-check --status live
--reachability-evidence` acceptance (and fail-closed without it); (10) M4 Green rules and non-claims.

## 7. Reachability evidence template

`SEED_REACHABILITY_EVIDENCE_TEMPLATE.md` defines: run id; UTC timestamp; seed id; node_id; peer_id;
environment; expected genesis hash; binary SHA-256; ELF BuildID; toolchain; public host/port; vantage
identity + independence statement; TCP dial result; KEMTLS/static-root handshake result; observed
remote NodeId/cert-derived identity; firewall/NAT/security-group summary; redaction statement; and the
conclusion fields `external_tcp_reachability`, `external_kemtls_reachability`, `live_reachability_claim`,
`m4_green_claim`, `c4_c5_closure_claim`.

## 8. CLI / help verification

Every documented seed P2P/genesis flag is **pre-existing** and defined in
`crates/qbind-node/src/cli.rs` and advertised in the top-level `--help`: `--network-mode`,
`--enable-p2p`, `--p2p-listen-addr`, `--p2p-advertised-addr`, `--p2p-peer`, `--p2p-mutual-auth`,
`--p2p-pqc-root-mode`, `--p2p-trusted-root`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`,
`--expect-genesis-hash`. The `qbind-node identity generate` and `qbind-node identity register-check`
subcommands are present. **No new CLI flag is introduced.**

## 9. Seed-list schema verification

`docs/release/public-devnet/network/devnet-seeds.live-candidate.json` still validates against
`devnet-seed-list.schema.json` (jsonschema draft-07).

## 10. Candidate / live status verification

The committed candidate's single entry remains `status: "planned"` with `last_reachability_evidence:
null` (non-live). No `devnet-seeds.live.json` is created; no entry is marked `status: live`.

## 11. Cross-link verification

The new docs cross-link the identity package (`docs/release/public-devnet/identity/`), the security
root/bootstrap docs (`PQC_ROOT_AND_SIGNING_KEYS.md`, `PQC_TRUST_BOOTSTRAP.md`), the observability
package, the ops incident-response and reset-policy docs, the readiness matrix, the Run 356 genesis
package, and the PQC trust lifecycle runbook. Reverse cross-links were added in
`network/README.md`, `network/VERIFY.md`, `operator/QUICKSTART.md`, `security/README.md`,
`p2p/VERIFY.md`, and `ops/INCIDENT_RESPONSE.md`.

## 12. Non-claim checks

The harness non-claim grep over the three new docs passes: no `launch-ready`, `M4 Green`, `C4 closed`,
`C5 closed`, `TestNet ready`, `MainNet ready`, or `uptime SLA` claim is asserted (only explicitly
negated / conditional forms remain).

## 13. Default compatibility

`--enable-p2p` / `--network-mode p2p` are opt-in and off by default; the DevNet freeze is preserved for
every other operator. No default network behaviour is changed.

## 14. CLI surface

Pre-existing only. No CLI flag added, renamed, hidden, or unhidden. `identity generate` /
`register-check` are the pre-existing Run 375/376 subcommands (read-only / non-mutating).

## 15. Runtime mutation check

None. Run 392 opens no externally reachable port, changes no P2P wire format, weakens no peer
admission, performs no live/peer-driven apply, and mutates no validator set / `LivePqcTrustState` /
epoch / sequence / marker. The harness starts no node.

## 16. Readiness delta — S7

**Red → Yellow.** The seed-node operational runbook (plus Route-A checklist and evidence template) is
published and verified. It stays Yellow (not Green) because operating a **live** seed depends on M4,
and no externally reachable seed exists.

## 17. Readiness delta — M4

**Unchanged: Yellow / launch-blocking.** No externally reachable seed and no independent off-host
vantage exist; the run publishes the path to Green but does not achieve it. No M4 Green is claimed.

## 18. Readiness delta — M6

**Unchanged: Yellow / Partial.** Live registration is M4-gated. No M6 Green is claimed.

## 19. Public DevNet status

**NOT launch-ready.** At least one must-have (M4) is not Green.

## 20. Remaining DevNet blockers

M4 (no externally reachable seed) is the primary launch blocker; M6 (live registration) is M4-gated.
Should-haves S1–S6 remain per the readiness matrix; S7 is now Yellow.

## 21. TestNet blockers

Untouched. Public TestNet readiness is out of scope and not claimed.

## 22. MainNet blockers

Untouched. MainNet authority rotation/revocation and custody remain Red; MainNet readiness is not
claimed.

## 23. C4 / C5

**Both remain OPEN.** Seed-node operations documentation makes no governance/authority-lifecycle
change and closes neither C4 nor C5 (`c4_c5_closure_claim=false`).

## 24. Tests run

- `bash scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh` → `RESULT=POSITIVE`.
- `cargo build -p qbind-node --release --locked --bin qbind-node` → builds (driven by the harness).
- Seed-list schema validation (jsonschema draft-07) → OK.
- Non-claim grep over the new docs → OK.
- Secret scan over all changed files → clean (see §25).
- `cargo test --lib`: **not run** — there is **no Rust source change** in this run (docs + harness
  only), recorded honestly as no-Rust-delta.

## 25. Security scans

No secret, private key, KEM secret, signing secret, token, raw log, raw metrics dump, data dir,
private endpoint, private hostname, or absolute build path is committed. The evidence archive tracks
only `README.md`, `summary.txt`, and `.gitignore`; `summary.txt` contains only publish-safe hashes and
OK/POSITIVE status lines. The harness removes any temporary `--help` captures under its OUTDIR.

## 26. CodeQL

**Trivial / not meaningful for CodeQL.** This run is docs + a bash verification harness only, with no
Rust/`build.rs`/production source change, so CodeQL analysis is not meaningful. No skipped/timed-out/
DB-too-large analysis is claimed clean.

## 27. Provenance

- Release binary SHA-256: `80d83b0472b7382ec4ccf2ea6d627bfbf9b9375ab22d6d598d129eb88f4357be`.
- ELF BuildID: `430c1348ea20cd8f88d84bbfd2a4ab7bd94e4733`.
- Toolchain: `rustc 1.98.0 (88d9e12ae 2026-08-18) / cargo 1.98.0 (797e8a9bc 2026-08-05)`.
- Run 356 genesis: `genesis_hash 0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`,
  genesis-file SHA-256 `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`.
- Harness summary archived at
  `docs/devnet/run_392_public_devnet_seed_ops_route_a_checklist/summary.txt`.

(Binary SHA-256 / BuildID are environment-specific and regenerated on every run.)

## 28. Honest limitations

Run 392 documents but does not execute the real M4 external-seed reachability run: no real externally
reachable seed is deployed and no independent off-host vantage exists in this sandbox (Route C for the
external step). Following the runbook prepares — but does not by itself achieve — M4 Green. The
committed live-candidate identity remains illustrative and must be replaced by the operator's durable
seed identity before any live publication.

## 29. Suggested Run 393

Execute the real **M4 Route-A** run on genuine external infrastructure: deploy a real KEMTLS
static-root seed with a routable public endpoint, prove reachability from an independent off-host
vantage (external TCP + KEMTLS handshake), fill in `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`, promote a
new `devnet-seeds.live.json` entry to `status: live` with non-null `last_reachability_evidence`, confirm
`register-check --status live --reachability-evidence` acceptance, and only then move **M4** Yellow →
Green (which in turn unblocks the live-registration half of **M6**).
