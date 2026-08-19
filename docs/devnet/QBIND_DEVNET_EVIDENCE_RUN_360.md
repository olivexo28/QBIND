# QBIND DevNet Evidence — Run 360

Public DevNet P2P exposure, peer-admission, and abuse/DoS posture publication.

Run 360 is **docs / artifact / verification only**. It publishes the canonical public DevNet
**P2P posture package** (`docs/release/public-devnet/p2p/`) — README, public P2P port posture, peer
admission policy, abuse/DoS posture, and a verification doc — for the `qbind-node` P2P, peer-admission,
and abuse/DoS surfaces, validated against the real CLI (`qbind-node --help`) and source. It also
applies a narrow Run 359 hygiene correction to the operator quickstart/README. It launches **no**
public DevNet; deploys **no** seed node / bootnode / faucet / RPC gateway / explorer / status page;
adds **no** public CLI flag; changes **no** P2P wire format / peer-admission logic / peer
rate-limiter implementation / default network behaviour; enables **no** MainNet; performs **no**
runtime authority-lifecycle wiring; and performs **no** validator-set mutation / epoch transition /
execution-sink write. It publishes **no** live endpoint and **no** secret. Full **C4 remains OPEN**,
**C5 remains OPEN**, and MainNet authority rotation/revocation remains **Red**. The Run 353/354
boundary remains **Green-for-scope only**.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim.

## 1. Exact verdict

**PASS (public-DevNet-P2P-posture positive; docs/artifact/verification-only; public DevNet NOT
launch-ready; M10 and M11 moved Yellow → Green for the public DevNet readiness track only; M12 stays
Yellow/Partial with the recorded gap; M4 remains Yellow/launch-blocking; M6–M9/M13–M15 unchanged;
Run 353/354 Green-for-scope only; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

The P2P posture package (README, P2P_PORT_POSTURE, PEER_ADMISSION_POLICY, ABUSE_DOS_POSTURE, VERIFY),
this evidence file, the readiness-matrix updates, the narrow protocol/ops/whitepaper-doc updates, the
Run 359 operator quickstart/README hygiene correction, the required test, the secret scan, and
provenance all landed. Every `qbind-node` CLI flag referenced by the P2P docs was validated to appear
in `qbind-node --help`. No public DevNet, TestNet, or MainNet readiness is claimed. Because M12 could
not honestly move to Green (rate-limiter thresholds are hardcoded and not operator-configurable, and
no per-connection-rate limiter is exposed), this is a **PASS with M12 Partial** — a partial-positive
on the M10/M11/M12 objective, full-positive on the run's publish-and-verify scope.

## 2. Files changed

New (P2P posture package):

- `docs/release/public-devnet/p2p/README.md`
- `docs/release/public-devnet/p2p/P2P_PORT_POSTURE.md`
- `docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`

New (evidence):

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_360.md` — this file.

Narrow updates:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — M10/M11 Yellow → Green; M12 stays
  Yellow/Partial; status header, checklist, status matrix, next-run table, owner table, blocker
  summary, and §17 summary updated. M4/M6–M9/M13–M15 unchanged.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status header (Run 360) + run log Run 360 entry;
  C4/C5 stay OPEN.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 360 no-change-to-model entry.
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — Run 360 no-change-to-surface
  entry.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 360 trust-lifecycle-inert note.
- `docs/whitepaper/contradiction.md` — Run 360 "No contradiction found" entry.
- `docs/release/public-devnet/operator/QUICKSTART.md`, `docs/release/public-devnet/operator/README.md`
  — narrow Run 359 hygiene correction only (remove stale "M3 is Red"; state M3 Green same-host scope;
  keep NOT launch-ready; cross-link Run 359 binary package).

No source code changed. No Run 356 / Run 357 / Run 358 / Run 359 artifact was modified (the operator
README/QUICKSTART changes are the intended Run 359 hygiene fix only).

## 3. Canonical location decision

The canonical location is `docs/release/public-devnet/p2p/`, a new sibling of the Run 356 genesis
package (`docs/release/public-devnet/genesis/`), the Run 357 seed-list package
(`docs/release/public-devnet/network/`), the Run 358 operator package
(`docs/release/public-devnet/operator/`), and the Run 359 binary package
(`docs/release/public-devnet/binary/`) under the shared `docs/release/public-devnet/` tree. This
matches the exact directory specified by the Run 360 task; no better pre-existing canonical location
existed for a published public-DevNet P2P posture package.

## 4. P2P posture package contents

| File | Purpose |
|------|---------|
| `README.md` | Scope, what it is / is not, NOT-launch-ready statement, DevNet-only safety posture, relationship to Runs 356–359, M10/M11/M12 targeting, what remains before M4 Green. |
| `P2P_PORT_POSTURE.md` | P2P disabled by default; listen/advertise/peer flags; safe local dry-run; future live-seed posture (bind/advertise/port/NAT/static peers/no-discovery); mandatory genesis-hash pinning; Run 357 seed-list→CLI mapping; operator "must not" list; later M4 evidence requirements. |
| `PEER_ADMISSION_POLICY.md` | Admission via existing KEMTLS mutual-auth + PQC trust-root/trust-bundle; suite/trust-bundle/genesis/identity expectations; fail-closed failure matrix; peer claims advisory-only; peer-driven apply out of scope; MainNet rotation/revocation Red. |
| `ABUSE_DOS_POSTURE.md` | Existing `peer_rate_limiter` (default 1000 msg/s + 100 burst, on by default, hardcoded); connection/handshake surfaces; metrics to watch; minimum recommended posture; recorded M12 gap; future work before TestNet. |
| `VERIFY.md` | Exact operator/reviewer verification commands (flag existence, placeholder no-live, no forbidden readiness/closure claims, safety-label presence, quickstart hygiene, unmodified prior artifacts, secret hygiene). |

## 5. Public P2P port posture summary

Grounded in `crates/qbind-node/src/cli.rs` and `p2p_tcp.rs`: public DevNet P2P is **disabled by
default** — `--enable-p2p` defaults to `false` and `--network-mode` defaults to `local-mesh`, so a
default node binds no public port. The listen default `--p2p-listen-addr 127.0.0.1:0` is loopback-only
on an ephemeral port; public exposure requires an explicit routable bind and (behind NAT/LB)
`--p2p-advertised-addr`. Peers are supplied **statically** via repeatable `--p2p-peer`; no
operator-facing discovery CLI is exposed, so no discovery capability is claimed. Every public node
must pin the Run 356 canonical genesis hash with `--expect-genesis-hash`. Run 357 seed-list fields map
onto the pre-existing flags; only `status: "live"` entries are dialable and the placeholder
(`192.0.2.1`) must not be dialed.

## 6. Peer-admission policy summary

Admission uses the existing KEMTLS handshake path. Under `--p2p-mutual-auth required` the listener
requires a verified `NetworkDelegationCert` and derives session identity from its `validator_id`.
Trust is anchored by `--p2p-trust-bundle` (+ `--p2p-trust-bundle-signing-key`) and/or
`--p2p-trusted-root`, using PQC suite ID 100 (ML-DSA-44); root material via `--p2p-pqc-root-mode`,
`--p2p-leaf-cert`/`--p2p-leaf-cert-key`, `--p2p-peer-leaf-cert`. Environment/genesis/chain binding is
enforced (`--expect-genesis-hash`, bundle `TrustBundleEnvironment` vs `--env`). Failure is
**fail-closed** for wrong genesis/chain/environment, wrong/revoked trust root, revoked leaf, malformed
bundle, untrusted peer, and placeholder/non-live seeds. Peer claims are advisory-only and do not
bypass ratification; peer-driven trust-bundle apply is out of scope; MainNet authority
rotation/revocation remains Red.

## 7. Abuse/DoS posture summary

Grounded in `crates/qbind-node/src/peer_rate_limiter.rs` and `metrics.rs`: a per-peer inbound-message
token-bucket rate limiter is **enabled by default** with hardcoded defaults
`DEFAULT_MAX_MESSAGES_PER_SECOND = 1000`, `DEFAULT_BURST_ALLOWANCE = 100`, `NUM_SHARDS = 16`; over-budget
messages are dropped (connection not torn down); it fails **open** on lock poisoning. P2P is off by
default (strongest DoS default); admission is fail-closed. Operators watch per-peer `rate_limit_drop` /
`total_rate_limit_drops()`, `consensus_net_peer_disconnect_total{reason}`,
`consensus_net_peer_inbound_total{kind}`, outbound-drop counters, and the
`qbind_p2p_pqc_trust_bundle_*` gauges/counters (including `signature_rejected_total` and
`sequence_rollback_rejected_total`). **Recorded gap:** the thresholds are hardcoded with **no**
operator-facing CLI/config surface, and there is **no** per-connection / global inbound-connection-rate
limiter in `qbind-node`; therefore **M12 stays Yellow/Partial**.

## 8. Run 359 quickstart hygiene correction

The Run 358 operator quickstart/README contained stale pre-Run359 wording stating M3 is **Red**. Run
360 narrowly corrected it:

- `QUICKSTART.md` §0 and §11: "M3 is Red" / "M3 — … Red" replaced with M3 **Green (same-host scope,
  Run 359)** and a cross-link to `docs/release/public-devnet/binary/`; public DevNet kept **NOT
  launch-ready** because M4 and M6–M15 remain unresolved. (The §3 build note already cross-linked the
  Run 359 binary package.)
- `README.md` §5 and §6: "remains Red" wording replaced with M3 Green same-host after Run 359; kept
  NOT launch-ready.

No Run 359 evidence, hashes, or binary artifacts were changed.

## 9. Verification commands and results

All commands run from the repository root with `BIN=./target/release/qbind-node`.

1. **CLI-flag existence** — every flag referenced by the P2P docs is present in `qbind-node --help`:

   ```
   OK   --enable-p2p, --p2p-listen-addr, --p2p-advertised-addr, --p2p-peer, --p2p-mutual-auth,
        --p2p-trust-bundle, --p2p-trust-bundle-signing-key, --p2p-pqc-root-mode, --p2p-trusted-root,
        --p2p-leaf-cert, --p2p-leaf-cert-key, --p2p-peer-leaf-cert, --expect-genesis-hash,
        --print-genesis-hash, --env, --genesis-path, --data-dir   (17/17 OK)
   ```

   (The internal `P2pDiscoveryConfig` is explicitly documented as **not** an operator CLI surface; no
   discovery capability is claimed.)

2. **Placeholder no-live** — `statuses: ['placeholder']`; `OK: no status==live entry`.

3–7. **No forbidden readiness/closure claim** (markdown-tolerant, per `VERIFY.md`): each of the
   launch-ready, TestNet-readiness, MainNet-readiness, C4/C5-closure, and M4-Green checks printed
   `OK` with no offending line.

8. **Safety label present** in all five P2P docs — `OK README.md / P2P_PORT_POSTURE.md /
   PEER_ADMISSION_POLICY.md / ABUSE_DOS_POSTURE.md / VERIFY.md`.

9. **Quickstart hygiene** — `OK: no 'M3 is Red' wording`; `OK: references Run 359 binary package`.

10. **Prior artifacts unmodified** — `git status --short` shows no change to
    `docs/release/public-devnet/genesis/`, `.../network/`, or `.../binary/`; only the operator
    `README.md`/`QUICKSTART.md` changed (Run 359 hygiene fix).

11. **Secret hygiene** — no private key / mnemonic / seed phrase / api-key / password value in the
    P2P docs (only references to operator-held `--p2p-leaf-cert-key` files and negation statements).

## 10. Tests run

- `cargo build -p qbind-node --release` — success (used to validate `--help` CLI surface).
- `cargo test -p qbind-node --lib` — **1377 passed; 0 failed; 0 ignored** (finished in ~64s).
  Docs-only diff; no source changed, so this is a regression sanity check on the unchanged crate.
- Documentation validation commands in §9 (all `OK`).

## 11. Security scans

- **Secret scan** over all changed files: no secret introduced (see §9.11). The P2P docs contain no
  private key, mnemonic, seed phrase, credential, token, API key, private infrastructure, or real
  production hostname; the only sample host is the RFC 5737 documentation address `192.0.2.1`
  (referenced from the Run 357 placeholder, not published anew as live).
- **CodeQL:** not meaningful for the Run 360 diff — this is a **docs/artifact-only** change with **no**
  source modification. No CodeQL coverage is claimed for this diff.

## 12. Provenance

- **Repository:** `olivexo28/QBIND`.
- **Branch:** `copilot/fix-typo-in-documentation`.
- **Commit:** the Run 360 commit on the branch (this evidence lands with the P2P package and doc
  updates; the working tree is committed clean — no unexplained `git_status: dirty`).
- **Artifact paths:** `docs/release/public-devnet/p2p/{README,P2P_PORT_POSTURE,PEER_ADMISSION_POLICY,
  ABUSE_DOS_POSTURE,VERIFY}.md`; `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_360.md`.
- **P2P doc file SHA-256 (LF):**
  - `README.md` — `32b20351a764b066c88977990a4bdd9d225d9e15dbbb6cdd3d9c1fa9c2f72649`
  - `P2P_PORT_POSTURE.md` — `202b4cb930a2699096e5249279260f10ef20b6d4e8229750ff3ff53e91e70e1e`
  - `PEER_ADMISSION_POLICY.md` — `e013d2fec855d18a0e7fcae664208d7340a0941b2eb71cadf44109928313bac3`
  - `ABUSE_DOS_POSTURE.md` — `87a8a190f518d8b50b2f060a872b3f70cd13678cda0961c511c3d985aff8a22d`
  - `VERIFY.md` — `9fcd46dc4ee98cce8060c3eeac8385e47c163500a23e8bebb9e30cd3312d05c8`
- **Run 356 genesis:** canonical hash
  `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`; file SHA-256
  `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`.
- **Run 357:** schema `devnet-seed-list.schema.json` SHA-256
  `b6630547afe4b37481256e73185704756d3450ed51eb18914ea27153723a3f75`; placeholder
  `devnet-seeds.placeholder.json` SHA-256
  `0b11c2c77de2550144f85af12e327b38216a7272be3c944760a1395e516942d0` (single entry, `status:
  "placeholder"`, no live entry).
- **Run 358:** operator package `docs/release/public-devnet/operator/` (referenced; quickstart/README
  updated for Run 359 hygiene only).
- **Run 359:** `qbind-node` SHA-256
  `f916af6db4cd1d8575b02f750ad4759c3470c2a2027d532cde50ca06e5b22990`; ELF BuildID
  `274fdaf3ded72362e87e11ccffce6912bde5208b` (referenced, not modified).
- **Readiness matrix deltas:** M10 Yellow → Green; M11 Yellow → Green; M12 stays Yellow/Partial (gap
  recorded); M4 unchanged Yellow/launch-blocking; M6–M9/M13–M15 unchanged.

## 13. Honest limitations

- **M12 not Green:** the abuse/DoS surface is real and documented, but its thresholds are hardcoded
  (`1000` msg/s + `100` burst) with no operator-facing config surface, and no per-connection /
  inbound-connection-rate limiter is exposed. Per the task rule, M12 stays **Yellow/Partial**.
- **No discovery capability:** static `--p2p-peer` dialing is the supported operator surface; the
  internal `P2pDiscoveryConfig` is not an operator CLI surface and is not relied upon or claimed.
- **No live infrastructure:** no seed/bootnode is deployed and no reachability evidence is produced,
  so **M4 remains Yellow/launch-blocking** and public DevNet is **NOT launch-ready**.
- **Docs-only diff:** CodeQL is not meaningful and not claimed clean; no source was changed.

## 14. Suggested Run 361 next step

Either (a) begin the **M4 live-seed** track: stand up a real externally reachable DevNet seed/bootnode
against this published posture, capture inbound-KEMTLS + genesis-pinned reachability evidence from an
independent host, and replace the Run 357 placeholder with a committed `status: "live"` seed list; or
(b) close the **M12** gap by exposing operator-configurable rate-limiter thresholds and adding a
per-connection/global inbound-connection-rate limiter, then validate under load. (a) is the launch
blocker; (b) hardens the posture ahead of it.