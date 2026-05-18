# QBIND DevNet Evidence — Run 086

## Exact objective

Update the operator lifecycle runbook
(`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`) to document the
peer-candidate `0x05` validation-only lifecycle landed by Runs
076–085, so that operators understand exactly what
peer-candidate exchange does and does **not** do. Strict
docs-first scope: no `crates/**/src/**` change unless a real
contradiction is found; no implementation of peer-driven live
apply, propagation/rebroadcast, `activation_epoch`, KMS/HSM,
signing-key ratification, fast-sync restore, or any redesign of
KEMTLS / consensus; no claim of full C4 or C5 closure.

## Exact verdict

**Strongest positive for the scoped Run 086 documentation
objective.**

- The runbook (`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`)
  is updated with a new §6.G "Peer-candidate validation-only
  lifecycle (Runs 076–085)" that covers strict behaviour,
  feature evolution (Run 076 → Run 085), allowed operator use,
  forbidden operator interpretations, safety invariants (per-
  scenario checklist), and Run 085 MainNet evidence summary.
- §10 residual risks is updated to reflect that Runs 076–085
  added an **observation-only** peer-candidate `0x05` exchange
  while explicitly preserving "peer-driven live apply /
  propagation remains OPEN".
- §11 mapping table gains rows for Runs 076–086.
- §12 glossary gains entries for the six hidden Run 077 / Run
  079 / Run 080 peer-candidate CLI flags.
- Run 086 evidence file (`this file`) created.
- `docs/whitepaper/contradiction.md` updated with a C4 Run 086
  evidence note.
- Forbidden-guidance grep checks all clean.
- `cargo check -p qbind-node --bin qbind-node` passes.
- **No source changes were required and none were made.** The
  implementation observed in
  `crates/qbind-node/src/pqc_trust_peer_candidate.rs`,
  `crates/qbind-node/src/pqc_peer_candidate_binary.rs`,
  `crates/qbind-node/src/pqc_peer_candidate_wire.rs`,
  `crates/qbind-node/src/p2p_tcp.rs`,
  `crates/qbind-node/src/p2p_node_builder.rs`,
  `crates/qbind-node/src/main.rs`,
  `crates/qbind-node/src/cli.rs`, and
  `crates/qbind-node/src/metrics.rs` agrees with the runbook
  prose; no contradictions were found.

Full C4 and C5 are **not** claimed closed. C4 peer-driven live
apply / propagation, `activation_epoch` runtime sourcing,
KMS/HSM custody, in-binary/on-chain signing-key ratification,
production fast-sync / consensus-storage restore, and
per-environment production trust-anchor operation remain open.

## Exact files changed

- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 086
  documentation update: front matter; introduction; new §6.G
  peer-candidate validation-only lifecycle; §10 residual risks
  re-worded for the peer-candidate boundary; §11 mapping table
  extended with Runs 076–086; §12 glossary extended with the
  six hidden peer-candidate CLI flags).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_086.md` (this file).
- `docs/whitepaper/contradiction.md` (C4 Run 086 evidence
  update — narrows operator-doc coverage; does not narrow C4 or
  C5 closure status).

**No `crates/**/src/**` source file was changed.** Run 086 is
documentation-only.

## Exact commands run

### Forbidden-guidance grep checks (must return no matches)

```text
# 1. No recommendation to use --p2p-trusted-root as fallback in the runbook.
grep -nE 'recommend|use|fallback' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md | grep -E '--p2p-trusted-root'

# 2. No recommendation to use DummySig / DummyKem / DummyAead in the runbook.
grep -nE 'recommend|use' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md | grep -E 'Dummy(Sig|Kem|Aead)'

# 3. No recommendation to accept unsigned TestNet/MainNet bundles.
grep -nE 'unsigned.*(testnet|mainnet)|(testnet|mainnet).*unsigned' -i docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md \
  | grep -viE 'refuse|reject|MUST NOT|NOT.* accepted|fail closed'

# 4. No recommendation to treat peer-candidate exchange as automatic propagation.
grep -nE 'peer-candidate.*propagat|propagat.*peer-candidate' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md \
  | grep -viE 'NOT |never|no propag|not propagated|remains OPEN|C4-OPEN|MUST NOT'

# 5. No recommendation to treat peer-candidate exchange as peer-driven live apply.
grep -nE 'peer-candidate.*(live apply|apply)|apply.*peer-candidate' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md \
  | grep -viE 'NOT |never|MUST NOT|not applied|remains OPEN|C4-OPEN|Not peer-driven'

# 6. No recommendation to reuse transport root key as bundle-signing key.
grep -nE 'reuse|same.*key' docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md \
  | grep -iE 'transport.*root.*(signing|sign).*key|signing.*key.*transport.*root'
```

### Build / type-check

```text
cargo check -p qbind-node --bin qbind-node
```

## Tests / checks run and pass/fail status

| Check | Result |
|---|---|
| `grep` 1 — no `recommend/use/fallback` line mentioning `--p2p-trusted-root` | **pass** (no match — all `--p2p-trusted-root` mentions are negative/forbidden, e.g. "MUST NOT", "no `--p2p-trusted-root` fallback") |
| `grep` 2 — no `recommend/use` line mentioning `DummySig`/`DummyKem`/`DummyAead` | **pass** (no match — all references are negative/forbidden) |
| `grep` 3 — no recommendation to accept unsigned TestNet/MainNet bundles | **pass** (no match — runbook explicitly refuses unsigned production bundles) |
| `grep` 4 — no recommendation that peer-candidate exchange = automatic propagation | **pass** (every peer-candidate × propagation mention is negative: "not propagated", "MUST NOT", "remains OPEN") |
| `grep` 5 — no recommendation that peer-candidate exchange = peer-driven live apply | **pass** (every peer-candidate × apply mention is negative: "NOT applied", "MUST NOT", "Not peer-driven") |
| `grep` 6 — no recommendation to reuse transport-root key as bundle-signing key | **pass** (§2.1 / §4 enforce strict key separation; no reuse recommendation present) |
| `cargo check -p qbind-node --bin qbind-node` | **pass** |

No `crates/**/src/**` change was made, so no additional test
suite needed to be rerun. The Run 084 / Run 085 harnesses
remain the canonical regression evidence for the peer-candidate
runtime behaviour the runbook now documents.

## Investigation findings

- **Code observed (read-only).**
  `crates/qbind-node/src/pqc_trust_peer_candidate.rs` exposes
  `PeerCandidateValidator::try_accept` and is the library boundary
  for Run 076. `crates/qbind-node/src/pqc_peer_candidate_binary.rs`
  is the Run 077 binary check-mode entry point and exits 0/1
  without starting the node. `crates/qbind-node/src/pqc_peer_candidate_wire.rs`
  is the Run 078 typed/versioned/bounded wire envelope. `p2p_tcp.rs`
  + `p2p_node_builder.rs` carry the Run 079 receive-loop dispatch
  + the Run 080 send-side publisher. `main.rs` + `cli.rs` expose
  exactly the six hidden flags documented in §12. `metrics.rs`
  exposes the `qbind_p2p_pqc_trust_bundle_peer_candidate_*`
  counter family.
- **Disabled-by-default.** All five operator flags
  (`--p2p-trust-bundle-peer-candidate-validation-enabled`,
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`,
  `--p2p-trust-bundle-peer-candidate-wire-publish-enabled`,
  paired with their `-path` / `-once` partners) default to off.
- **No apply / no propagation path.** No symbol referenced by the
  peer-candidate modules calls
  `pqc_trust_reload::apply_validated_candidate{,_with_previous}`,
  `LivePqcTrustState::swap_snapshot`, `P2pSessionEvictor::*`, or
  `pqc_trust_sequence::commit_sequence`. The peer-candidate
  receive path does not re-emit; the sender path is one-shot
  (`-once`) under operator control.
- **Evidence path consistent.** Run 084 / Run 085 harnesses and
  evidence docs explicitly assert sequence-hash invariance, live
  reload apply metrics = 0, session eviction metrics = 0, and
  `sent_total = 0` on non-senders. Run 085 additionally asserts
  no `--p2p-trusted-root`, no active `DummySig` / `DummyKem` /
  `DummyAead`, real ML-KEM-768 + ChaCha20-Poly1305.

## Runbook sections changed

- **Front matter** — Run number / status / scope owner / date
  updated to reflect Run 086.
- **Introduction** — extended to list Runs 076–085 inline and
  to state Run 086's docs-only stance.
- **§6.G (new)** — "Peer-candidate validation-only lifecycle
  (Runs 076–085)" with six sub-sections:
  - §6.G.1 Strict behaviour (does / does-not list).
  - §6.G.2 Feature evolution (Run 076 → Run 085 mapping table).
  - §6.G.3 What operators may use this path for.
  - §6.G.4 What operators MUST NOT treat this path as.
  - §6.G.5 Safety invariants checklist.
  - §6.G.6 MainNet evidence (Run 085 — strongest current).
  - §6.G.7 What the peer-candidate path does NOT close.
- **§10 residual risks** — item 2 (peer-supplied / gossiped
  acceptance) now explicitly notes that Runs 076–085 added an
  observation-only `0x05` exchange while preserving "peer-driven
  live apply / propagation remains OPEN". No other §10 items
  changed.
- **§11 mapping table** — eleven new rows for Runs 076, 077,
  078, 079, 080, 081, 082/083, 084, 085, 086.
- **§12 glossary** — six new entries for
  `--p2p-trust-bundle-peer-candidate-validation-enabled`,
  `--p2p-trust-bundle-peer-candidate-check`,
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`,
  `--p2p-trust-bundle-peer-candidate-wire-publish-enabled`,
  `--p2p-trust-bundle-peer-candidate-wire-publish-path`, and
  `--p2p-trust-bundle-peer-candidate-wire-publish-once`.

## How Runs 076–085 are represented in the runbook

| Run | Where it is anchored | Claim represented |
|---|---|---|
| 076 | §6.G.1, §6.G.2, §11 | Library-level `PeerCandidateValidator`; disabled-by-default; non-mutating. |
| 077 | §6.G.1, §6.G.2, §11, §12 | Local check mode; node does not start; exits 0/1; reuses Run 076 validator. |
| 078 | §6.G.1, §6.G.2, §11 | Bounded typed/versioned wire envelope (`0x05`). |
| 079 | §6.G.1, §6.G.2, §6.G.5, §11, §12 | Disabled-by-default receive-loop dispatch; receiver-side counters move only when on. |
| 080 | §6.G.1, §6.G.2, §11, §12 | Disabled-by-default send-side publisher; one-shot publish. |
| 081 | §6.G.2, §11 | First N=2 real `0x05` evidence; partial only (DummySig ambiguity). |
| 082 / 083 | §6.G.2, §11 | DummySig boundary isolated as non-active / probe-log-only with respect to the matrix. |
| 084 | §6.G.5, §6.G.6, §11, §10 | Committed N=2 DevNet harness; closed N=2 evidence gap. |
| 085 | §6.G.1, §6.G.5, §6.G.6, §11, §10 | Committed N=4 MainNet harness; strongest current evidence; sequence hashes unchanged; no apply/eviction/propagation; no Dummy crypto; no fallback. |

## Contradictions found or not found

**None.** The runbook prose and §6.G strict-behaviour list are
exactly the behaviour observed in
`pqc_trust_peer_candidate.rs`,
`pqc_peer_candidate_binary.rs`,
`pqc_peer_candidate_wire.rs`, `p2p_tcp.rs`,
`p2p_node_builder.rs`, `main.rs`, `cli.rs`, and `metrics.rs`.
No `crates/**/src/**` change was required and none was made.

## Remaining open C4 / C5 items

- **C4-OPEN**: peer-driven live apply / propagation.
- **C4-OPEN**: `activation_epoch` runtime source (height-only
  remains the only supported axis).
- **C4-OPEN**: KMS / HSM custody integration.
- **C4-OPEN**: in-binary / on-chain signing-key ratification.
- **C4-OPEN**: production fast-sync / consensus-storage restore
  parity for trust-bundle records on a partially-restored node.
- **C4-OPEN**: per-environment production trust-anchor operation
  (depends on operator custody / HSM).
- **C5 remains OPEN / NARROWED.** Run 086 does not close any
  C5 boundary. Production AEAD on the binary path remains
  test-grade (`DummyAead`) under §C5 tracking; production
  KEMTLS lifecycle, signed root-distribution channel, and
  production CA / cert rotation / revocation remain
  operator-out-of-band.
- **C4-OPEN**: full C4 closure.

## contradiction.md update

Updated. A short Run 086 evidence note was appended under §C4
recording that the operator lifecycle runbook now documents the
peer-candidate validation-only lifecycle for Runs 076–085, that
the update is docs-only with no source change, and that the
update narrows operator-documentation coverage **without**
narrowing C4 closure (peer-driven live apply / propagation
remain explicitly OPEN). The note explicitly preserves the
Run 085 C4 evidence note above it.

## Exact immediate next action

Use `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` §6.G as the
canonical operator description of the peer-candidate `0x05`
validation-only lifecycle. The next scoped task should address
**peer-driven live apply / propagation** only if explicitly
requested as a separate run, and MUST thread the same Run 065
activation-margin policy, the same Run 050/051/053 validator
pipeline, and the same Run 070
`validate → swap → evict → commit` ordering through any new
peer-input apply path. Until such a run lands, operators MUST
continue to treat peer-candidate `0x05` exchange as a signal
source only and continue to use the §6.F.4 SIGHUP live
reload-apply path as the sole operator surface that applies a
candidate to a running node.