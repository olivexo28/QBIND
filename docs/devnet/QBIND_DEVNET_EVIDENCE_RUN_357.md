# QBIND DevNet Evidence — Run 357

Public DevNet seed/bootnode list format + placeholder seed-list publication.

Run 357 is **docs / artifact / verification only**. It publishes the canonical public DevNet seed/bootnode list
**format** (a JSON Schema) and a **placeholder** DevNet seed-list artifact, with verification evidence. It does
**not** launch a public DevNet, deploys **no** seed nodes / bootnodes / faucet / RPC gateway / explorer / status
page, adds **no** public CLI flag, changes **no** P2P wire format or peer-admission logic, changes **no** default
network behaviour, enables **no** MainNet, performs **no** runtime authority-lifecycle wiring, performs **no**
validator-set mutation, and performs **no** epoch transition or execution-sink write. Full **C4 remains OPEN**,
**C5 remains OPEN**, and MainNet authority rotation/revocation remains **Red**. The Run 353/354 boundary remains
**Green-for-scope only**.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5 closure claim.

## 1. Exact verdict

**PASS (public-DevNet-seed-list-format positive; docs/artifact/verification-only; public DevNet NOT launch-ready;
M4 moved Red → Yellow for the public DevNet readiness track only and REMAINS a launch blocker; M3 remains Red;
Run 353/354 Green-for-scope only; MainNet authority rotation/revocation Red; Full C4 OPEN; C5 OPEN).**

The canonical seed-list schema, placeholder seed-list, verification doc, README, this evidence file, the
readiness-matrix update, the required tests, the secret scan, and provenance all landed. Validation succeeded with
repo-available Python `json` + `jsonschema` (no new dependency, no new CLI flag). No public DevNet, TestNet, or
MainNet readiness is claimed. **No real seed nodes are deployed; M4 remains launch-blocking.**

## 2. Files changed

New (network / seed-list package):

- `docs/release/public-devnet/network/README.md`
- `docs/release/public-devnet/network/devnet-seed-list.schema.json`
- `docs/release/public-devnet/network/devnet-seeds.placeholder.json`
- `docs/release/public-devnet/network/VERIFY.md`

New (evidence):

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_357.md` — this file.

Narrow updates:

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` — M4 Red → Yellow (still a launch blocker); status,
  matrix, next-run, blocker summary, and §17 summary updated.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — status header + run log: Run 357 entry; C4/C5 stay OPEN.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 357 no-change-to-model entry.
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` — Run 357 no-change-to-surface entry.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 357 trust-lifecycle note (trust-bundle-required field only).
- `docs/whitepaper/contradiction.md` — Run 357 "No contradiction found" entry.

## 3. Canonical location decision

The canonical location is `docs/release/public-devnet/network/`, a new sibling of the Run 356 genesis package
`docs/release/public-devnet/genesis/` under the shared `docs/release/public-devnet/` tree. No better pre-existing
canonical location existed for a published public-DevNet seed list, so the `network/` subdirectory was created.

## 4. Seed-list package contents

| File | SHA-256 | Purpose |
|------|---------|---------|
| `README.md` | (tracked) | Purpose / non-purpose / Run 356 relation / operator usage / CLI flags / launch-readiness / M4 Green criteria. |
| `devnet-seed-list.schema.json` | `25aaee879c417cdca8ddcc0a459175aa311dd1c2a60b19f300fdbe7867dcd7ce` | Canonical JSON Schema (draft-07). |
| `devnet-seeds.placeholder.json` | `70e497df5a441e0d355f7070e1424185c47e431379c0c78862db8727e31fd357` | Placeholder seed list (non-live). |
| `VERIFY.md` | (tracked) | Exact verification commands + expected outputs. |

## 5. Seed-list schema summary

`devnet-seed-list.schema.json` is a JSON Schema draft-07 (`additionalProperties: false`). Required top-level fields:
`schema_version`, `network_name`, `environment` (`enum: ["devnet"]`), `runtime_chain_id`, `genesis_hash`
(`^0x[0-9a-f]{64}$`), `genesis_file_sha256` (`^[0-9a-f]{64}$`), `safety_label` (all of `experimental`, `resettable`,
`no_value`, `no_mainnet_readiness_claim`, `no_c4_c5_closure_claim` pinned `true`), `placeholder_statement`, and
`seed_nodes` (array). Each `seed_node` requires: `node_id`, `peer_id`, `validator_address` (each string **or** null
for documented absence), `p2p_host`, `p2p_port` (0–65535), `p2p_multiaddr` (string or null), `transport_security_mode`,
`pqc_suite`, `trust_bundle_required` (boolean), `expected_genesis_hash` (`^0x[0-9a-f]{64}$`), `operator`, `status`
(`enum: placeholder | planned | live | retired`), `last_reachability_evidence` (string or null), `notes`. Conditional
rules: a `live` entry **must** carry non-empty `last_reachability_evidence`; a `placeholder` / `planned` / `retired`
entry **must** have `last_reachability_evidence: null`. This makes it structurally impossible to mark a non-live entry
as reachable, or to publish a live entry without evidence.

## 6. Placeholder seed-list contents

`devnet-seeds.placeholder.json`: `schema_version 1.0.0`, `network_name "QBIND Public DevNet (experimental)"`,
`environment "devnet"`, `runtime_chain_id "0x51424E4444455600"`,
`genesis_hash "0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f"`,
`genesis_file_sha256 "d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c"`, full `safety_label`
(all true), an explicit `placeholder_statement` asserting NOT launch-ready, and **one** `seed_nodes` entry:

- `node_id: null`, `peer_id: null`, `validator_address: null` (documented absence — no real identity generated),
- `p2p_host: "192.0.2.1"` (RFC 5737 TEST-NET-1, non-routable), `p2p_port: 19000`, `p2p_multiaddr: "192.0.2.1:19000"`,
- `transport_security_mode: "kemtls-mutual-auth-required"`, `pqc_suite: "ml-dsa-44"`, `trust_bundle_required: true`,
- `expected_genesis_hash:` (matches top-level genesis hash), `operator: "example-operator-placeholder"`,
- `status: "placeholder"`, `last_reachability_evidence: null`, `notes:` explicit "NOT A LIVE SEED".

No fake externally reachable IP/DNS/peer-id/key is published as live.

## 7. Verification commands and results

All run from repo root; only pre-existing tooling (Python 3.12 + repo-available `jsonschema` 4.10.3):

1. **Schema valid JSON** — `python3 -c "import json; json.load(open('.../devnet-seed-list.schema.json')); print('schema valid json')"` → `schema valid json`. **PASS**
2. **Placeholder valid JSON** — `python3 -c "import json; json.load(open('.../devnet-seeds.placeholder.json')); print('placeholder valid json')"` → `placeholder valid json`. **PASS**
3. **Placeholder validates vs schema** — `jsonschema.validate(instance=placeholder, schema=schema)` → `placeholder validates against schema`. **PASS**
4. **Genesis hash cross-check** — placeholder `genesis_hash` (and every `expected_genesis_hash`) equals `0x48b3a862…af18145f` and appears in Run 356 `devnet-network-parameters.md`. **PASS**
5. **Genesis file SHA-256 cross-check** — placeholder `genesis_file_sha256` equals the value in Run 356 `devnet-genesis.sha256` (`d1db07fe…5c86c`). **PASS**
6. **No entry falsely marked live** — no `status: "live"` present; all non-live entries have `last_reachability_evidence: null`. **PASS**
7. **No public DevNet launch claim** — `safety_label` all true and `placeholder_statement` contains "NOT launch-ready". **PASS**
8. **MainNet/TestNet unaffected** — `environment` is `devnet` only; no TestNet/MainNet artifact created or modified. **PASS**

Exact commands and expected outputs are recorded in `docs/release/public-devnet/network/VERIFY.md`.

## 8. Tests run

- `cargo test -p qbind-node --lib` — see §12 for result (docs/artifact-only diff; no source changed).

The Run 357 diff is docs/artifact-only (no Rust source changed), so no broader source-regression suite is required
by repository policy; the `qbind-node --lib` suite is run as the task-required baseline.

## 9. Security scans

- **Secret scanning** over all changed files: **no secrets detected**. The seed-list files contain no private keys,
  private IPs intended to remain private, credentials, tokens, API keys, mnemonics, seed phrases, production
  hostnames, or real operator secrets. The only host value is `192.0.2.1` (RFC 5737 documentation range).
- **CodeQL:** not meaningful for the Run 357 diff — this is docs/artifact-only with **no source-code change**. No
  CodeQL coverage is claimed for this run. (If CodeQL were invoked and skipped/unavailable, that exact result would
  be recorded here rather than being called clean.)

## 10. Readiness matrix delta for M4

- **Before (Run 356):** M4 seed/bootnodes = 🔴 Red — static `--p2p-peer` only; no published seed list; no discovery.
- **After (Run 357):** M4 = 🟡 Yellow — canonical seed-list **format** (`devnet-seed-list.schema.json`) + **placeholder**
  artifact (`devnet-seeds.placeholder.json`) published under `docs/release/public-devnet/network/`, verified and
  genesis-pinned. **M4 remains a public DevNet launch blocker.** It moves to Green **only** with a committed live
  seed/bootnode list plus reachability evidence from real externally reachable seed nodes.
- No other must-have status changed. M3 remains Red. M1/M16/M19/M20 remain Green.

## 11. Provenance

- **git commit (pre-run tip):** `467203651189e2d8dafd4949c069747f66700e69` (Run 357 artifacts are added in this run's commit).
- **branch:** `copilot/run-357-task`.
- **clean/dirty state:** working tree was clean before this run; after this run it contains only the Run 357
  additions/updates listed in §2, which are committed (no unexplained `git_status: dirty`).
- **artifact paths:** see §2 / §4.
- **schema hash (`devnet-seed-list.schema.json`):** `25aaee879c417cdca8ddcc0a459175aa311dd1c2a60b19f300fdbe7867dcd7ce`.
- **placeholder seed-list hash (`devnet-seeds.placeholder.json`):** `70e497df5a441e0d355f7070e1424185c47e431379c0c78862db8727e31fd357`.
- **Run 356 genesis hash (referenced, not modified):** `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`.
- **Run 356 genesis file SHA-256 (referenced, not modified):** `d1db07febcf76267f9d3e277a0ff99d06bbe5dffd59d0607799521562ec5c86c`.
- **commands run:** §7 verification commands; `cargo test -p qbind-node --lib`; secret scan; hash computations.
- **test results:** §12.
- **security scan result:** §9 (no secrets; CodeQL N/A for docs-only diff).
- **readiness matrix deltas:** §10 (M4 Red → Yellow, still launch-blocking).

## 12. Test results

`cargo test -p qbind-node --lib`:

```
test result: ok. 1377 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 68.42s
```

Result: **PASS** (1377 passed, 0 failed). No Rust source was changed by Run 357; this confirms no regression.

## 13. Honest limitations

- This run publishes **only** the seed-list format and a placeholder artifact. **No real seed/bootnode nodes are
  deployed and no external reachability evidence exists**, so **M4 remains a launch blocker** and public DevNet
  remains **NOT launch-ready**.
- The placeholder host is a non-routable RFC 5737 documentation address; it must never be dialed.
- The seed-list schema/artifact are **not** consumed by any runtime discovery, peer-admission, or authority path;
  they are operator-facing documentation/artifacts only.
- The `transport_security_mode` / `pqc_suite` / `trust_bundle_required` fields *describe* the pre-existing join
  surface; Run 357 changes none of that behaviour and adds no CLI flag.

## 14. Suggested Run 358 next step

Author the external validator/full-node **onboarding quickstart** (must-have M5, foldable with M6 node-identity and
M17 how-to-run-a-node), validated against the real `qbind-node` startup path, referencing the Run 356 genesis package
and the Run 357 seed-list format. (The actual **live seed/bootnode deployment + external reachability evidence**
needed to move M4 to Green requires real infrastructure and remains a separate, deployment run.)
