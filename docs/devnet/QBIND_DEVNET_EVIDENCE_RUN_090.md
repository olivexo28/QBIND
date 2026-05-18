# QBIND DevNet Evidence — Run 090

**Objective:** docs-only operator-playbook update. Update
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` so operators
understand the distinction between (1) validation-only receive/send
of peer-candidate `0x05` frames (Runs 076–085), (2) propagation-only
rebroadcast after validation (Runs 087–089), (3) local operator
SIGHUP live apply (§6.F.4 / Run 074), and (4) peer-driven live apply,
which is **still not implemented**. Fold Run 087 safety spec, Run 088
disabled-by-default propagation prototype, and Run 089 release-binary
N=3 DevNet propagation evidence into a single, internally-consistent
operator surface, with explicit unsafe-guidance scrubs.

**Verdict:** **strongest positive**. The runbook is updated accurately
for the propagation-only lifecycle; the Run 090 evidence doc (this
document) is created; `docs/whitepaper/contradiction.md` is updated;
unsafe guidance is absent; `cargo check -p qbind-node --bin qbind-node`
passes; no source changes were required.

## Files changed

- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (header / intro /
  §6.G title / §6.G.9 / §6.G.10 / §6.G.11 / §6.G.12 / §6.G.13 / §10
  / §11 / §12 — see "Runbook sections changed" below).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_090.md` (new — this document).
- `docs/whitepaper/contradiction.md` (Run 090 docs-consistency note;
  no C4/C5 closure claim).

No changes were made to `crates/**/src/**`. No tests were modified.
No new dependencies were added.

## Required investigation findings

- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`: previously framed
  for Run 088 only (header said "Run: 088 (disabled propagation-only
  peer-candidate prototype)"). It already mentioned Run 087 / Run 088
  in the §1 prologue and the §6.G.8 future-design-gate subsection,
  but it did **not** yet (a) frame Run 089 as the strongest current
  release-binary propagation evidence, (b) carry an explicit
  propagation-only operator MAY / MUST NOT split, (c) carry a
  propagation-only evidence checklist matched to the Run 089
  harness, or (d) extend §10 / §11 / §12 with Runs 088/089/090. Run
  090 closes these documentation gaps.
- `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`:
  defines the future-work design gate (bounded payload, validation
  before rebroadcast, duplicate suppression, rate limiting, loop
  prevention, no apply, no sequence commit, no session eviction,
  clear metrics). Run 088 satisfies the propagation subset on
  prototype and unit/integration tests; Run 089 satisfies the
  propagation subset on release binaries (N=3 DevNet). Run 087's
  peer-driven-apply / `activation_epoch` / KMS-HSM / signing-key
  ratification / fast-sync subsets remain explicitly open. Run 090
  re-states this boundary in §6.G.13 and in this evidence doc.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_087.md`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_088.md`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_089.md`: read in full;
  every Run 087/088/089 claim is preserved verbatim in §6.G.12 and
  §6.G.11. No Run 089 invariant was weakened, dropped, or
  reinterpreted.
- `docs/whitepaper/contradiction.md`: already carries Run 088 and
  Run 089 sub-notes under C4. Run 090 adds a docs-consistency note
  that does not change the C4 / C5 state.
- Code reference inspection (no source changes made):
  - `crates/qbind-node/src/cli.rs`: confirms hidden flag
    `--p2p-trust-bundle-peer-candidate-propagation-enabled` exists
    (`cli.rs:652`).
  - `crates/qbind-node/src/metrics.rs`: confirms the five
    propagation counters exist with the names cited in the runbook
    (`peer_candidate_propagation_{attempt,sent,suppressed_duplicate,suppressed_invalid,rate_limited}_total`,
    exposed as `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_*`).
  - `crates/qbind-node/src/pqc_peer_candidate_wire.rs` and
    `crates/qbind-node/src/pqc_trust_peer_candidate.rs`: confirm
    the propagation dispatcher gates rebroadcast on
    `PeerCandidateWireOutcome::Validated` and that the validator
    library has no apply / sequence-commit / session-evict / live-
    trust-mutation handle.
  - `crates/qbind-node/src/p2p_tcp.rs`: confirms source-aware
    read-loop dispatch and selected-peer raw `0x05` send queue.
  - `crates/qbind-node/src/main.rs`: confirms the propagation
    sender is installed after transport build only when both the
    propagation flag and a validated `--p2p-trust-bundle` baseline
    are present; no peer-driven apply context is wired.
- **No runtime contradictions were found.** The runtime behaviour
  described by Runs 087/088/089 matches the source surfaces above.
  No `crates/**/src/**` change was required.

## Runbook sections changed

| §section | Change |
|---|---|
| Front matter (Run / Status / Scope owner / Date) | `Run: 088 …` → `Run: 090 (operator-playbook prose update for the propagation-only peer-candidate lifecycle from Runs 087–089)`. Status updated to "Operator playbook landed and updated for Runs 050–089". Scope owner extended to "… + peer-candidate validation-only and propagation-only lifecycle". |
| §1 prologue | Extended to name Run 089 (release-binary N=3 DevNet propagation evidence) and Run 090 (this docs update) explicitly; restates the four-mode distinction (validation-only / propagation-only / local SIGHUP apply / peer-driven apply still not implemented). |
| §6.G title | "Peer-candidate validation-only lifecycle (Runs 076–085)" → "Peer-candidate validation-only and propagation-only lifecycle (Runs 076–089)". |
| §6.G.9 (new) | "Propagation-only behavior (Runs 087–089)" — flag name; disabled by default; validation-before-rebroadcast; invalid / oversize / duplicate / rate-limited do not rebroadcast; source-peer exclusion; loop prevention via seen-cache / duplicate suppression / bounded fanout / fixed-window rate limit / bounded queue; no sequence write; no `LivePqcTrustState` mutation; no session eviction; no apply; no consensus ratification; no trust-bundle synchronization claim; lists the five propagation counters; explicitly notes the `peer_candidate_applied_total` family is absent. |
| §6.G.10 (new) | "What operators MAY and MUST NOT use propagation-only mode for" — MAY: spread observation evidence; observe validation results across nodes; collect metrics/logs for manual operational decision-making. MUST NOT: automatic root rotation; automatic revocation distribution; peer-driven live apply; replacement for local SIGHUP live reload; consensus approval; bundle-signing-key ratification; trust-bundle synchronization. |
| §6.G.11 (new) | "Propagation-only evidence checklist (per scenario)" — receive-side counters move; propagation counters move only after validation; `propagation_suppressed_invalid_total` moves for rejected candidates; duplicate counters move for repeated candidates; source node `received_total` stays zero in source-exclusion test; sequence hashes unchanged; `live_reload_apply_*` zero; `session_eviction_*` zero; `peer_candidate_applied_total` family absent; no Dummy crypto; no `--p2p-trusted-root` fallback. |
| §6.G.12 (new) | Mapping for Runs 087 (safety spec) / 088 (propagation prototype) / 089 (release-binary N=3 DevNet propagation evidence). |
| §6.G.13 (new) | Residual open items after Runs 087–089: peer-driven live apply; `activation_epoch` runtime source; KMS/HSM custody; signing-key ratification; fast-sync / restore parity; per-environment production trust-anchor operation; full C4/C5 closure. |
| §10 (residual risks) | Sub-piece 2 "Peer-supplied / gossiped trust-bundle acceptance" extended to reference Runs 088 and 089 and to re-state that peer-driven apply is **not** implemented and propagation today is opt-in / does not synchronize trust / does not ratify consensus / does not substitute for §6.F.4 SIGHUP. |
| §11 (Mapping to Runs 050–087) | Header bumped to "Mapping to Runs 050–090". New rows added for Runs 088 / 089 / 090. |
| §12 (Glossary) | New entry `--p2p-trust-bundle-peer-candidate-propagation-enabled` (Run 088); new sub-section listing the five `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_*` counters and what each moves on. |

## How Runs 087–089 are represented

- **Run 087** is represented as the **safety specification** that
  every future propagation / apply work MUST satisfy. The runbook
  retains §6.G.8 (already present from Run 087) as the formal
  reference, and §6.G.12 lists Run 087 as the design-gate artefact.
- **Run 088** is represented as the **propagation prototype**: the
  flag, the five counters, the validation-before-rebroadcast contract,
  source-peer exclusion, loop-prevention primitives, and the
  explicit absence of the `peer_candidate_applied_total` family.
  Surfaced in §6.G.9 (behaviour), §6.G.10 (MAY / MUST NOT), §6.G.11
  (per-scenario evidence checklist), §6.G.12 (run-mapping), and §12
  (glossary).
- **Run 089** is represented as the **release-binary N=3 DevNet
  propagation evidence** that lifts the Run 088 prototype from
  unit/integration to real binaries. Surfaced in §1 prologue, §6.G.9
  (named as the evidence harness), §6.G.11 (the harness is the
  canonical regression for the propagation-only checklist), §6.G.12
  (mapping), §10 (residual-risks paragraph).

The runbook does **not** elevate Run 088 or Run 089 into anything they
do not claim. Specifically, the runbook does not:

- claim peer-driven live apply,
- claim consensus ratification of propagated candidates,
- claim trust-bundle synchronization,
- recommend treating propagation as a substitute for §6.F.4 SIGHUP,
- recommend `--p2p-trusted-root` as a propagation fallback,
- recommend Dummy crypto,
- recommend unsigned TestNet/MainNet bundles,
- recommend reusing the transport root key as a bundle-signing key.

## Commands run

Unsafe-guidance grep checks against the updated runbook (each pattern
intentionally matches "fallback / live apply / consensus / sync /
Dummy / unsigned / key-reuse" *recommendations*, not the existing
"MUST NOT" / negation prose):

- `rg -n 'recommend.*--p2p-trusted-root' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — **no matches**.
- `rg -n '--p2p-trusted-root.*fallback|fallback.*--p2p-trusted-root' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md | rg -v 'MUST NOT|no fallback|not.*reintroduced|MUST NOT be re-introduced'` — only negation/MUST NOT lines remain (no positive recommendation).
- `rg -n 'recommend.*DummySig|recommend.*DummyKem|recommend.*DummyAead|use.*DummySig|use.*DummyKem|use.*DummyAead' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — **no matches**.
- `rg -n 'recommend.*unsigned.*(testnet|mainnet|bundle)' -i docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — **no matches**.
- `rg -n 'propagat.*(is|as).*(live apply|apply)' -i docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md | rg -v 'NOT|never|not '` — **no matches** (all matches are explicit negations).
- `rg -n 'propagat.*(consensus|ratification|ratifie)' -i docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md | rg -v 'NOT|never|not '` — **no matches**.
- `rg -n 'propagat.*(synchron|sync.*trust|trust.*sync)' -i docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md | rg -v 'NOT|never|not '` — **no matches**.
- `rg -n 'reuse.*(transport root|signing key|kem|leaf)' -i docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md | rg -v 'MUST NOT|do not|never'` — **no matches**.

Build sanity:

- `cargo check -p qbind-node --bin qbind-node` — **PASS**.

No source files were touched, so no affected-test reruns were
required by the task's conditional source-change rule.

## Checks pass/fail status

| check | result |
|---|---|
| `cargo check -p qbind-node --bin qbind-node` | **PASS** |
| No recommendation to use `--p2p-trusted-root` as fallback | **PASS** (no positive recommendation; only MUST NOT / "no fallback" prose remains) |
| No recommendation to use `DummySig` / `DummyKem` / `DummyAead` | **PASS** |
| No recommendation to accept unsigned TestNet/MainNet bundles | **PASS** |
| No recommendation to treat propagation as live apply | **PASS** |
| No recommendation to treat propagation as consensus ratification | **PASS** |
| No recommendation to treat propagation as automatic trust-bundle synchronization | **PASS** |
| No recommendation to reuse transport root key as bundle-signing key | **PASS** |

## What was documented

- The propagation-only behavior added by Run 088 and proven on
  release binaries by Run 089: the flag, the five counters, the
  source-peer exclusion, the loop-prevention primitives, and the
  explicit "no apply / no sequence write / no `LivePqcTrustState`
  mutation / no session eviction / no consensus ratification / no
  trust-bundle synchronization" invariants.
- An explicit, operator-facing MAY / MUST NOT split for the
  propagation-only mode (§6.G.10).
- A per-scenario evidence checklist (§6.G.11) that matches what the
  Run 089 N=3 DevNet harness asserts on release binaries.
- A run-mapping table (§6.G.12) that names Runs 087 / 088 / 089 with
  the role each plays and the artefact each produced.
- A consolidated residual-risk list (§6.G.13) that re-states every
  C4 / C5 sub-piece that remains open after Runs 087–089.
- Glossary entry for the propagation flag and a glossary section
  for the five propagation counters (§12).

## What was proven

- The runbook is now internally consistent with Runs 087, 088, and
  089 and with the live source (`cli.rs`, `metrics.rs`,
  `pqc_peer_candidate_wire.rs`, `pqc_trust_peer_candidate.rs`,
  `p2p_tcp.rs`, `main.rs`).
- The runbook contains no unsafe guidance against the eight task-
  required unsafe-guidance categories.
- `cargo check -p qbind-node --bin qbind-node` passes against the
  current tree, confirming the docs change did not collaterally
  break the binary path (no source was modified).

## What remains not solved

All C4 / C5 items already enumerated in §10 of the runbook remain
**OPEN** after Run 090 (this is a docs-only run that does not close
runtime work):

- Peer-driven live apply (validated propagated candidates still do
  not mutate live trust on any node).
- `activation_epoch` runtime source.
- KMS / HSM custody.
- In-binary / on-chain bundle-signing-key ratification.
- Production fast-sync / consensus-storage restore parity.
- Per-environment production trust-anchor operation.
- Two-node / N-node MainNet release-binary peer-connection smoke
  (separately tracked C4 piece, unrelated to propagation).
- Full C4 remains OPEN.
- C5 remains OPEN / NARROWED — Run 090 does not narrow C5 further.

## Contradictions found or not found

**None.** The investigation phase confirmed the runbook (after this
update) is internally consistent and matches the source surfaces
referenced for Runs 087–089. No `crates/**/src/**` changes were
required.

## Was `contradiction.md` updated, and why

**Yes.** A short Run 090 docs-consistency note is appended under C4.
It explicitly does **not** claim any new closure — it records that
the operator-lifecycle runbook now folds the Run 087 safety spec,
the Run 088 propagation prototype, and the Run 089 release-binary
N=3 DevNet propagation evidence into a single operator surface, with
explicit MAY / MUST NOT operator guidance and a per-scenario evidence
checklist. Every C4 sub-piece and C5 itself remain OPEN; Run 090
narrows neither.

## Remaining C4 / C5 items after Run 090

- C4 remains **OPEN** for all sub-pieces enumerated in §10 of the
  runbook, including peer-driven live apply, `activation_epoch`
  runtime source, KMS / HSM custody, in-binary / on-chain signing-
  key ratification, production fast-sync / consensus-storage
  restore parity, per-environment production trust-anchor
  operation, selective per-peer session retention, admin-API /
  filesystem-watcher trigger surface, and the two-node / N-node
  MainNet release-binary peer-connection smoke.
- C5 remains **OPEN / NARROWED** by prior Runs 038 / 039 only.
  Run 090 is docs-only and does not narrow C5.

## Immediate next action

Land the peer-driven **apply** path behind a hidden, disabled-by-
default flag with the same Run 070 safety contract
(`validate → snapshot → swap → evict → commit_sequence`), gated on
consensus-ratified bundle-signing keys and an `activation_epoch`
runtime source. Until then, propagation-only mode (Run 088 / Run 089)
remains the strongest peer-driven motion on the `0x05` path, and
§6.F.4 SIGHUP remains the only running-node apply surface for
trust-bundle mutation.