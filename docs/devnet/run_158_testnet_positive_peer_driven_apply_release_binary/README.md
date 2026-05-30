# Run 158 — Positive TestNet Release-Binary End-to-End Peer-Driven Apply Evidence (Unified Fixture Universe)

## Scope

Run 158 closes the **Run 156 disjoint-universe blocker** by driving the
real `target/release/qbind-node` TestNet receiver through the **complete
positive peer-driven apply path** over **live P2P**, using the
**Run 157 unified TestNet fixture universe** (a single self-consistent
universe binding live transport, baseline seq=1 trust bundle, candidate
seq=2 trust bundle, v2 ratification sidecar, seeded v2 marker, V0/V1/V2
leaf certs/KEM keys, and the valid `0x05` peer-candidate envelope).

Run 158 introduces **no new production runtime source delta**. It reuses
the Run 153 wiring in `crates/qbind-node/src/main.rs` verbatim — the
hidden, disabled-by-default
`--p2p-trust-bundle-peer-candidate-drain-once` hook that drives:

```
live inbound 0x05 candidate (TestNet domain)
  → v2 validation-only acceptance
  → staging queue
  → hidden explicit drain-once hook (Run 153 wiring)
  → ProductionDrainInvocationBuilder (Run 152)
  → ProductionV2MarkerCoordinator (Run 152)
  → Run 150 PeerDrivenApplyDrain::try_drain_once
  → Run 148 try_apply_staged_peer_candidate
  → Run 070 apply_validated_candidate_with_previous
  → LivePqcTrustState swap
  → session eviction (Run 070/072 semantics)
  → Run 055 sequence commit
  → v2 authority marker persist after commit
```

Per `task/RUN_158_TASK.txt`, Run 158 **must not** substitute source/test
coverage for the positive A1 verdict. The harness drives the real
release binaries against the unified universe and writes
`a1_apply_proof.txt` only when V1's stderr log shows the canonical
Run 070 ordering markers and the Run 055 `persisted_sequence` advance;
otherwise it writes `a1_blocker.txt` documenting the exact failure mode
(without source/test substitution).

## Architecture (real TestNet N=3 topology)

- **V0** — publisher of the live `0x05` v2 TestNet peer-candidate
  envelope from the unified manifest
  (`--p2p-trust-bundle-peer-candidate-wire-publish-enabled` +
  `--p2p-trust-bundle-peer-candidate-wire-publish-path` +
  `--p2p-trust-bundle-peer-candidate-wire-publish-once`).
- **V1** — TestNet receiver, full apply pipeline armed:
  `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`,
  `--p2p-trust-bundle-peer-candidate-staging-enabled`,
  `--p2p-trust-bundle-peer-candidate-apply-enabled`,
  `--p2p-trust-bundle-peer-candidate-drain-once`. After
  `QBIND_DRAIN_ONCE_DELAY_SECS` the hidden drain-once hook fires
  exactly once.
- **V2** — observer / propagation-invariant node.

All three nodes use the unified universe's V0/V1/V2 leaf
certs/KEM keys, the unified seq=1 baseline trust bundle (under the same
transport root that signs the seq=2 candidate), the unified v2 seq=1
sidecar, the unified TestNet genesis (and its expected canonical
genesis hash), and the same TestNet chain id / TestNet authority root.
This makes the candidate a **valid Run-070 successor** of V1's live
baseline `LivePqcTrustState`, which is the precise condition Run 156's
disjoint universes failed to satisfy.

## Harness

`scripts/devnet/run_158_testnet_positive_peer_driven_apply_release_binary.sh`

The harness:

1. Captures provenance (git commit, rustc/cargo versions, binary +
   helper SHA-256 and ELF Build IDs).
2. Mints the unified TestNet fixture universe with the real release
   `run_157_unified_testnet_peer_apply_fixture_helper`.
3. Mints per-validator consensus signer keystores with the real
   release `devnet_consensus_signer_keystore_helper` (validator
   identity only — out of scope for this run's apply claim).
4. Runs the TestNet single-node fail-closed refusal matrix:
   `R2_mainnet_refused`, `C1_testnet_drain_without_apply`,
   `C3_testnet_drain_without_staging`,
   `C4_testnet_drain_without_wire_validation` (all expected to exit 1
   with `Run 151: FATAL` / `FATAL`).
5. Drives the live N=3 cluster for the positive scenario
   `A1_testnet_unified_apply` (V0 publishes the unified valid
   envelope; V1 wire-validates, stages, and explicitly drains once)
   and asserts the apply outcome.
6. Drives the live N=3 cluster for the rejection scenario
   `R3_wrong_environment` (V0 publishes the unified
   wrong-environment / DevNet-domain envelope to a TestNet receiver;
   V1 must reject before staging and the drain-once must return
   `NoCandidate`).
7. Captures before/after sequence and v2 marker JSON + SHA-256 for V1
   (so Run 055 sequence commit and v2 marker persist after commit are
   verifiable).
8. Writes `a1_apply_proof.txt` (positive) or `a1_blocker.txt`
   (blocker), grep summaries (in-scope ordering proof + denylist),
   and `summary.txt`.

The harness does **not** substitute source/test coverage for the A1
positive verdict.

## Required ordering proof (the harness checks for this in V1's stderr)

1. P2P connection established (`P2P transport up`).
2. live `0x05` candidate received (`peer-candidate wire frame observed`).
3. v2 validation-only accepted under TestNet domain (`[run-142]`).
4. candidate staged (`[run-146]` / `[run-147]`).
5. explicit drain-once triggered (`[run-153] drain-once`).
6. `ProductionDrainInvocationBuilder` built invocation (`[run-152]`).
7. `ProductionV2MarkerCoordinator` accepted marker decision (`[run-152]`).
8. Run 150 drain invoked (`[run-150]`).
9. Run 148 controller invoked (`[run-148]`).
10. Run 070 ordering: `validate → snapshot previous → swap →
    evict_sessions → commit_sequence` (`[run-070]`).
11. sequence commit succeeds (`persisted_sequence=2`).
12. v2 marker persists strictly **after** sequence commit
    (`v2 authority marker` after the `persisted_sequence=2` line).
13. Applied outcome emitted
    (`VERDICT=applied` / `trust-bundle candidate APPLIED live`).

## Required mutation proof

V1 captures, into the (gitignored) `sequence/` and `marker_hashes/`
sub-directories, the **before** and **after** state of:

- the v2 authority marker JSON and SHA-256;
- the sequence file JSON and SHA-256;
- the TestNet genesis hash (from the unified manifest);
- the TestNet chain id (from the unified manifest);
- the live trust fingerprint / active-root evidence visible in V1's
  stderr;
- session-eviction counters from V1's stderr (`session_evictions=`);
- applied / drain outcome lines (`[run-070]` / `[run-150]` /
  `[run-153]`);
- node stdout/stderr for V0/V1/V2.

The expected mutation is: `persisted_sequence` advances from `1` to
`2`; the v2 authority marker advances from the seeded seq=1 record
(matching `seed-marker.v2.seq1.json`) to a seq=2 record digest equal
to the unified manifest's `expected_candidate_digest`; session
evictions fire per Run 070/072 semantics; and the live trust
fingerprint matches the unified manifest's
`expected_candidate_fingerprint`.

## Required denylist (the harness's `out_of_scope.txt` must be empty)

- no autonomous background drain;
- no apply on receipt without explicit drain;
- no peer-majority authority;
- no governance claim;
- no KMS / HSM claim;
- no signing-key rotation/revocation claim;
- no validator-set rotation claim;
- no MainNet apply;
- no fallback to `--p2p-trusted-root`;
- no active `DummySig` / `DummyKem` / `DummyAead`;
- no `SIGHUP` / `reload-apply` / `startup-mutation` /
  `snapshot-restore` apply outcome;
- no schema/wire/metric drift.

The expected MainNet-refusal banner — which names `governance` /
`KMS` / `HSM` only to say they are NOT implemented — is excluded from
the denylist match (same precedent as Run 153 / 155 / 156).

## Invariants held in this run

- MainNet drain-once **refused unconditionally** (`Run 151: FATAL`,
  exit code 1) — see `exit_codes/R2_mainnet_refused.exit_code`.
- TestNet drain-once without apply / without staging / without
  wire-validation each exit 1 with `FATAL` —
  see `exit_codes/C{1,3,4}_*.exit_code`.
- No autonomous background drain (a single explicit, delayed drain-once).
- No automatic apply on receipt.
- No peer-majority authority.
- No fallback to `--p2p-trusted-root`.
- No `DummySig` / `DummyKem` / `DummyAead`.
- No `SIGHUP` / `reload-apply` / startup-mutation /
  snapshot-restore apply outcome.

## Out-of-scope deferrals (unchanged)

- Governance / KMS / HSM: unimplemented.
- Signing-key rotation / revocation lifecycle: open.
- Validator-set rotation: open.
- Full C4: open. C5: open.
- MainNet: refused unconditionally.

## Tracked vs generated artifacts

Only `README.md` and `summary.txt` are tracked (mirroring Run 153 /
Run 155 / Run 156). All per-run artifacts (`logs/`, `exit_codes/`,
`grep_summaries/`, `fixtures/`, `material/`, `signers/`, `data/`,
`metrics/`, `sequence/`, `marker_hashes/`, `provenance.txt`,
`fixture_manifest.txt`, `a1_apply_proof.txt`, `a1_blocker.txt`) are
reproduced by the harness and are `.gitignore`d (they contain
absolute paths, ephemeral key fingerprints, and timestamps).

See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_158.md` for the canonical
evidence report.