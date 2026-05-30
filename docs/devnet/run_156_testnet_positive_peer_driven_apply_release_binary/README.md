# Run 156 — Positive TestNet Release-Binary End-to-End Peer-Driven Apply Closure

## Scope

Run 156 closes the gap left open by Run 155: it produces **real
release-binary process-log evidence** for the **positive** TestNet
end-to-end peer-driven apply path (A1), rather than mapping that path to
Run 154/152/150/148 source/test coverage as Run 153 and Run 155 did.

Run 156 introduces **no new production source delta**. It reuses the
Run 153 wiring in `crates/qbind-node/src/main.rs` verbatim — the hidden,
disabled-by-default `--p2p-trust-bundle-peer-candidate-drain-once` hook
that drives:

```
live inbound 0x05 candidate (TestNet domain)
  → v2 validation-only acceptance
  → staging queue
  → hidden explicit drain-once hook (Run 153 wiring)
  → ProductionDrainInvocationBuilder
  → ProductionV2MarkerCoordinator
  → Run 150 PeerDrivenApplyDrain::try_drain_once
  → Run 148 try_apply_staged_peer_candidate
  → Run 070 apply_validated_candidate_with_previous
  → LivePqcTrustState swap
  → session eviction (Run 070/072 semantics)
  → Run 055 sequence commit
  → v2 authority marker persist after commit
```

## Architecture (real TestNet N=3 topology)

- **V0**: publisher of the live `0x05` v2 TestNet peer-candidate (real
  release `qbind-node`, `--p2p-trust-bundle-peer-candidate-wire-publish-*`).
- **V1**: TestNet receiver with wire validation **+ staging + apply-enabled
  + drain-once enabled** (real release `qbind-node`). After
  `QBIND_DRAIN_ONCE_DELAY_SECS` the hidden drain-once hook fires exactly
  once.
- **V2**: observer / propagation-invariant node (real release `qbind-node`).

## Harness

`scripts/devnet/run_156_testnet_positive_peer_driven_apply_release_binary.sh`

The harness mints the real signed-TestNet P2P transport material
(`devnet_pqc_trust_bundle_helper`), the consensus signer keystores
(`devnet_consensus_signer_keystore_helper`), and the Run 132/133/154
TestNet fixtures (`run_133_v2_validation_only_fixture_helper`); brings up
the real N=3 live PQC P2P cluster; publishes exactly one live `0x05`
candidate from V0; and fires V1's explicit drain-once. It then **reports
the actual drain outcome** and asserts the appropriate invariants:

- If the drain-once returns **`Applied`**, the harness asserts the full
  Run 070 ordering (sequence commit precedes the v2 authority-marker
  persist) and the sequence advance, and writes `a1_apply_proof.txt`.
  A1 is then **PROVEN** by the release-binary process log.
- Otherwise the harness writes `a1_blocker.txt` documenting the **exact
  blocker**, and does **not** substitute source/test coverage for the
  positive verdict (per `task/RUN_156_TASK.txt`).

## Result of the in-tree fixture run

With the fixtures that ship in this repository, the real release binaries
execute the live path end-to-end **up to V1's wire-validation gate**:

1. V0/V1/V2 bring up the live authenticated PQC P2P transport (TestNet).
2. V0 publishes exactly one live `0x05` v2 TestNet candidate (publish-once).
3. V1 **observes** the live `0x05` frame on the wire (Run 078 receive path).
4. V1's live wire-validation / ratification gate **rejects** the candidate
   before staging, so the staging queue stays empty.
5. The explicit drain-once fires exactly once and returns **`NoCandidate`**;
   there is no autonomous repeat drain and **no live trust mutation**
   (only the `first-load persisted_sequence=1` baseline appears in V1's
   Run 055 log; there is no `persisted_sequence=2` commit).

### Exact blocker

A peer-driven apply requires the published candidate to be a valid
**Run-070 successor** of V1's live baseline `LivePqcTrustState`, which is
initialised from V1's live P2P trust bundle (`--p2p-trust-bundle`). That
transport bundle — and the V0/V1/V2 leaf certs/KEM keys that bring up the
live handshake — are minted by `devnet_pqc_trust_bundle_helper`
(`signed-testnet`) under **root authority A**. The only available TestNet
*apply* candidate (Run 154 / `run_133` helper
`testnet/peer-candidate.valid.json`, `declared_sequence=2`) is signed
under a **disjoint standalone root authority B** with **no matching P2P
leaf credentials**. Universe B is not a successor of universe A, so the
live `0x05` wire-validation gate rejects it and it never stages.

No existing fixture tool mints a single **unified universe** that
simultaneously provides (a) N=3 P2P leaf certs/KEM keys for the live
transport and (b) a self-consistent `baseline(seq1) → candidate(seq2)`
apply pair signed by that same transport root, plus the matching v2
ratification sidecar. `devnet_pqc_trust_bundle_helper` provides (a) but
not (b); `run_133_v2_validation_only_fixture_helper` provides (b) but not
(a). This is the same structural reason Run 153 and Run 155 mapped the
positive A1 path to source/test coverage.

### Driving the positive `Applied` outcome (when a unified fixture exists)

The harness is a **complete driver**, not a stub. Once a unified fixture
universe is available it can be supplied via environment overrides and the
harness will exercise the real apply and assert the Applied ordering
automatically:

```
QBIND_RUN156_TRANSPORT_DIR=<unified-material-dir> \
QBIND_RUN156_CANDIDATE_ENVELOPE=<unified-seq2-envelope> \
QBIND_RUN156_SIDECAR=<unified-v2-ratification> \
QBIND_RUN156_GENESIS=<unified-genesis> \
QBIND_RUN156_GENESIS_HASH=<unified-genesis-hash> \
bash scripts/devnet/run_156_testnet_positive_peer_driven_apply_release_binary.sh
```

Building that unified fixture tooling is out of Run 156's strict scope (it
introduces no new lifecycle/governance/KMS/rotation behaviour) and is the
subject of a dedicated future fixture-tooling run.

## Invariants held in this run

- MainNet drain-once **refused unconditionally** (`Run 151: FATAL`,
  exit code 1) — see `exit_codes/A6_mainnet_refused.exit_code`.
- No autonomous background drain (a single explicit, delayed drain-once).
- No automatic apply on receipt.
- No peer-majority authority.
- No live trust **sequence mutation** when the candidate did not apply.
- Denylist grep clean — see `grep_summaries/out_of_scope.txt`.

## Out-of-scope deferrals (unchanged)

- Governance / KMS / HSM: unimplemented.
- Signing-key rotation / revocation lifecycle: open.
- Validator-set rotation: open.
- Full C4: open. C5: open.
- MainNet: refused unconditionally.

## Tracked vs generated artifacts

Only `README.md` and `summary.txt` are tracked (mirroring Run 153 /
Run 155). All per-run artifacts (`logs/`, `exit_codes/`,
`grep_summaries/`, `fixtures/`, `material/`, `signers/`, `data/`,
`metrics/`, `sequence/`, `marker_hashes/`, `provenance.txt`,
`fixture_manifest.txt`, `a1_apply_proof.txt`, `a1_blocker.txt`) are
reproduced by the harness and are `.gitignore`d (they contain absolute
paths, ephemeral key fingerprints, and timestamps).

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_156.md` for the canonical
evidence report.