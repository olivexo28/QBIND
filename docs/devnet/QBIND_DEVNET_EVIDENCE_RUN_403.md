# QBIND DevNet Evidence — Run 403

Public DevNet **release package index + operator verification map** — navigation
index + operator/reviewer verification map + verification harness.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
NOT public-DevNet launch-ready · no M4 Green · no M6 fully-Green · no S5 Green ·
no S7 Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**.
Run 403 adds **no** production Rust source change, **no** `build.rs` change,
**no** new CLI flag; it starts no externally reachable listener, opens no
externally reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status
service, changes no P2P wire format, weakens no peer admission, enables no
peer-driven apply, and mutates no trust/validator/epoch/sequence/marker/
`LivePqcTrustState` state.

## 1. Exact verdict

**PASS / public-DevNet artifact index + operator verification map POSITIVE.** The
artifact index and operator verification map land cleanly and are verified against
the **on-disk package tree** and the **canonical** readiness matrix. No readiness
overclaim is introduced; no readiness item moves Green.

## 2. Files changed

New:
- `docs/release/public-devnet/ARTIFACT_INDEX.md`
- `docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md`
- `scripts/devnet/run_403_public_devnet_artifact_index_verification_map.sh`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_403.md` (this file)
- `docs/devnet/run_403_public_devnet_artifact_index_verification_map/{README.md,summary.txt,.gitignore}`

Narrowly updated (docs only):
- `docs/release/public-devnet/LAUNCH_GO_NO_GO.md` (companion-doc pointer to the
  artifact index + verification map; no status change)
- `docs/release/public-devnet/BLOCKER_REGISTER.md` (cross-reference to the artifact
  index + verification map; no status change)
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (Run 403 narrative; item
  statuses unchanged — M4 🟡, M6 🟡, S5 🟡, S7 🟡, C4/C5 OPEN)
- `docs/whitepaper/contradiction.md` (Run 403 — No contradiction found)

No production source, `build.rs`, `Cargo.toml`, or CLI file is changed.

## 3. Decision gate route

**Route B (expected).** Publishing a navigation index + verification map over the
already-recorded package tree and readiness state is purely operator-facing
documentation — **docs + verification harness only**, no new CLI surface and no
source change. Route A (deploy anything to change status) was not taken because the
run's scope is docs + verification only and moves no item Green; Route C (defer /
publish nothing) was not taken because the current package tree **can** be indexed
and mapped honestly without overclaiming, which is precisely the clarity this run
adds.

## 4. Artifact index contents

`ARTIFACT_INDEX.md` carries the DevNet safety label and indexes thirteen artifact
groups, each with **path / purpose / readiness item / verify / status /
non-claims**: (1) genesis; (2) binary provenance / reproducibility / manifest;
(3) operator quickstart; (4) identity; (5) P2P / peer admission; (6) network /
seed-list / M4 checklist; (7) security / PQC trust bootstrap; (8) observability /
alerting; (9) ops / reset / incident response; (10) recovery / backup / upgrade /
rollback; (11) status decision; (12) launch go/no-go; (13) blocker register. It
closes with a package-coverage table, a C4/C5 + contradiction-ledger statement,
and a TestNet/MainNet non-claim.

## 5. Operator verification map contents

`OPERATOR_VERIFICATION_MAP.md` carries the DevNet safety label and provides:
recommended read orders for an **external operator**, a **security reviewer**, and
a **release manager**; an **exact verification map** covering genesis, binary
provenance, identity, P2P posture, observability, recovery, and go/no-go
verification (each with how / reference / item-status); and a four-part **launch
stop rule**.

## 6. Package coverage

The harness confirms every present public DevNet package directory
(`genesis/`, `binary/`, `operator/`, `identity/`, `p2p/`, `network/`, `security/`,
`observability/`, `ops/`, `recovery/`, `status/`) is referenced by the index, and
that the two top-level launch docs (`LAUNCH_GO_NO_GO.md`, `BLOCKER_REGISTER.md`)
are referenced. No package path is absent; any future removal must be marked
explicitly **absent** in the index.

## 7. Read-order guidance

Three audience-specific read orders are published (operator / security reviewer /
release manager), each starting from the artifact index and ending at the launch
decision gate / C4/C5 + contradiction ledger.

## 8. Verification-command mapping

The verification map ties each artifact group to a `VERIFY.md` document and, where
one exists, a `scripts/devnet/run_NNN_*.sh` harness (e.g. genesis → `genesis/VERIFY.md`
+ `--expect-genesis-hash`; binary → `run_383/384/385`; identity → `run_375/376/401`;
P2P → `run_367/368`; observability → `run_379/381`; recovery → `run_394`; go/no-go →
`run_402`). The harness verifies all cross-linked docs resolve on disk.

## 9. Launch stop rule

The map's stop rule states plainly: (1) do not attempt launch while M4/M6 are
Yellow (decision is NO-GO); (2) do not create `devnet-seeds.live.json` without real
off-host M4 evidence; (3) do not claim TestNet/MainNet readiness; (4) do not claim
C4/C5 closure.

## 10. Cross-link verification

```
launch_docs_referenced=OK (LAUNCH_GO_NO_GO.md + BLOCKER_REGISTER.md referenced)
m4_refs=OK (M4 Route-A checklist + seed reachability evidence template referenced)
identity_refs=OK (identity continuity + rotation/revocation deferral referenced)
c4_c5_refs=OK (C4/C5 closure criteria + contradiction ledger referenced)
link_targets_resolve=OK (all cross-linked docs resolve on disk)
```

## 11. Non-claim checks

```
non_claim_grep=OK (no launch-ready / M4-M6-S5-S7-Green / C4-C5-closure / TestNet-MainNet-ready / deployment claim)
```

The normalized non-claim grep over both new docs finds no forbidden
readiness/closure/launch/deployment claim.

## 12. Security scans

- **Secret scan:** the changed files were scanned; **no** secret / API key / token
  / credential is present. The package is docs + shell only; the harness
  `.gitignore` excludes keys, certs, logs, metrics, and data dirs.
  `committed_private_material=NONE`.
- The harness additionally verifies the two new docs contain **no** absolute
  filesystem path (`/home`, `/root`, `/tmp`, `/var`, `/etc`, `/Users`), **no**
  private endpoint, and **no** embedded private/signing material.

## 13. Runtime mutation check

None. Run 403 applies **no** trust bundle, performs **no** live/peer-driven apply,
and mutates **no** validator set / `LivePqcTrustState` / epoch / sequence / marker.
It opens no externally reachable port and starts no node listener.

## 14. Readiness delta

**None.** No readiness item moves Green. M4 🟡, M6 🟡, S5 🟡, S7 🟡, and the
Green items are unchanged. C4/C5 remain OPEN. Public DevNet remains **NOT
launch-ready**. This run adds navigation + clarity only.

## 15. M4 status

**Yellow / launch-blocking (unchanged).** No real, externally reachable public
DevNet seed with independent off-host reachability evidence exists.

## 16. M6 status

**Yellow / Partial (unchanged).** Generation + verification + non-mutating
`register-check` are Green-for-scope; the live-registration half is M4-gated and
durable-root reuse/rotation/revocation is C4/C5-deferred.

## 17. S5/S7 status

**Both Yellow (unchanged).** S5's live status view and S7's live seed operation are
deferred until M4 / a live network.

## 18. Public DevNet status

**NOT launch-ready (unchanged).** The launch decision remains **NO-GO**.

## 19. C4/C5

**C4 OPEN; C5 OPEN (unchanged).** MainNet authority rotation/revocation remains
**Red**. Nothing here closes, advances, or reinterprets C4 or C5.

## 20. TestNet/MainNet non-claims

TestNet and MainNet remain **untouched**; N1–N7 remain **Red**. `identity generate`
refuses `mainnet`/`testnet`. **No TestNet readiness and no MainNet readiness is
claimed.**

## 21. Tests run

- `bash scripts/devnet/run_403_public_devnet_artifact_index_verification_map.sh` →
  `RESULT=POSITIVE` (all OK lines; see
  `run_403_public_devnet_artifact_index_verification_map/summary.txt`).
- Non-claim grep → OK. Secret / absolute-path / private-endpoint scan → clean.
  Markdown cross-link targets resolve on disk → OK.
- **No Rust source changed → no `cargo test` / `cargo build` is required or run**
  (recorded honestly; this is a docs + shell run).

## 22. CodeQL

**Docs + shell only; no production Rust/`build.rs`/source change** → trivial / not
meaningful for CodeQL. No skipped/timed-out/DB-too-large analysis is presented as
clean.

## 23. Honest limitations

- This run publishes a **navigation index and verification map**; it does not
  change the underlying facts. M4 is still Yellow because no real off-host external
  reachability exists in this environment. The index documents that blocker rather
  than resolving it.
- The index/map are verified against the **committed package tree and readiness
  matrix**, not against a live network (there is none). Correctness of each group's
  status rests on the prior runs' recorded status, not a fresh re-proof of each item.
- The verification map lists verification commands but does not execute the
  per-package harnesses; it points operators at them.

## 24. Suggested Run 404

Pursue the real launch blocker: **M4** — deploy or validate a genuinely externally
reachable public DevNet seed/bootnode under strict KEMTLS static-root, capture
independent off-host reachability evidence, publish a schema-valid
`devnet-seeds.live.json`, and only then flip M4 Green and revisit the go/no-go gate
and this index. Do not attempt operator-root reuse/rotation/revocation until C4/C5
work is scoped, to avoid overclaiming closure.
