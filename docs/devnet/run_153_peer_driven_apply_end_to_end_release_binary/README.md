# Run 153 — Release-Binary End-to-End Peer-Driven Apply Evidence Archive

## Scope

Run 153 is **release-binary end-to-end evidence** for the DevNet/TestNet
explicit peer-driven apply drain-once pipeline. The Run 153 source delta
in `main.rs` wires the already-landed Run 152 binary-reachable plumbing
(`ProductionDrainInvocationBuilder`, `ProductionV2MarkerCoordinator`,
`try_drain_once_shared`) into the Run 151 hidden `--p2p-trust-bundle-peer-candidate-drain-once`
hook so the full pipeline is actually callable from the release binary:

```
live inbound 0x05 candidate
  → validation-only v2 acceptance
  → staging queue
  → hidden explicit drain-once hook (Run 153 wiring)
  → ProductionDrainInvocationBuilder
  → ProductionV2MarkerCoordinator
  → Run 150 PeerDrivenApplyDrain::try_drain_once
  → Run 148 try_apply_staged_peer_candidate
  → Run 070 apply_validated_candidate_with_previous
  → LivePqcTrustState swap
  → session eviction
  → Run 055 sequence commit
  → v2 authority marker persist after commit
```

## Source Delta

Run 153 adds minimal wiring in `crates/qbind-node/src/main.rs`:

1. **Staging queue threading**: The `Arc<Mutex<PeerCandidateStagingQueue>>`
   created for the live inbound `0x05` dispatcher is cloned into a
   `drain_once_staging_queue` variable accessible after P2P startup.

2. **Post-P2P drain-once block**: After P2P is up and a configurable delay
   (`QBIND_DRAIN_ONCE_DELAY_SECS`, default 10s), the block constructs a
   `ProductionDrainInvocationBuilder` and `ProductionV2MarkerCoordinator`
   from the live trust state, then calls `try_drain_once_shared` exactly
   once through the full pipeline.

No new CLI flags, no new library code, no schema changes.

## Architecture (N=3 DevNet Topology)

- **V0**: publisher of live `0x05` v2 peer-candidate (real release `qbind-node`)
- **V1**: receiver with wire validation, staging, apply-enabled, and drain-once
  enabled (real release `qbind-node`)
- **V2**: observer / propagation invariant node (real release `qbind-node`)

## Evidence Harness

```
scripts/devnet/run_153_peer_driven_apply_end_to_end_release_binary.sh
```

## Archive Layout

```
run_153_peer_driven_apply_end_to_end_release_binary/
├── README.md           ← this file
├── summary.txt         ← per-scenario verdicts and deferral list
├── provenance.txt      ← git commit, versions, binary SHAs
├── logs/
│   └── <scenario>/
│       ├── v0.stdout, v0.stderr
│       ├── v1.stdout, v1.stderr
│       └── v2.stdout, v2.stderr
├── exit_codes/
│   └── <scenario>.exit_code
├── grep_summaries/
│   ├── in_scope.txt
│   └── out_of_scope.txt
└── data_dirs/
    └── <scenario>/
        └── v{0,1,2}/ (sequence + marker pre/post SHAs)
```

## Denylist

Across all scenarios, the following must produce ZERO matches:
- No autonomous background drain
- No apply on receipt without explicit drain
- No peer-majority authority
- No governance claim
- No KMS/HSM claim
- No signing-key rotation/revocation claim
- No validator-set rotation claim
- No MainNet apply
- No fallback to `--p2p-trusted-root`
- No active DummySig / DummyKem / DummyAead
- No SIGHUP outcome
- No reload-apply outcome
- No startup mutation path accidentally selected
- No snapshot/restore path accidentally selected
- No schema/wire/metric drift

## Out-of-Scope Deferrals

- **Governance**: unimplemented
- **KMS / HSM**: unimplemented
- **Signing-key rotation / revocation lifecycle**: open
- **Validator-set rotation**: open
- **Full C4**: open
- **C5**: open
- **TestNet evidence**: deferred (fixture setup infeasible)
- **MainNet**: refused unconditionally