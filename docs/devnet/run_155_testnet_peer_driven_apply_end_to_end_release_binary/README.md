# Run 155 — Release-Binary TestNet End-to-End Peer-Driven Apply Evidence Archive

## Scope

Run 155 is **release-binary TestNet end-to-end evidence** for the explicit
peer-driven apply drain-once pipeline. It mirrors Run 153's DevNet
end-to-end evidence but binds the whole exercise to the **TestNet runtime
domain** using the **Run 154 TestNet fixtures**.

Run 155 introduces **no new production source delta**: it reuses the Run 153
wiring in `main.rs` verbatim. That wiring is environment-agnostic for
DevNet/TestNet (the Run 150 `PeerDrivenDrainPolicy` /
`PeerDrivenApplyPolicy` are selected by environment via
`testnet_enabled()`), so the same hidden, disabled-by-default
`--p2p-trust-bundle-peer-candidate-drain-once` hook drives the full
pipeline under `--env testnet`:

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

## Architecture (N=3 TestNet Topology)

- **V0**: publisher of live `0x05` v2 TestNet peer-candidate (real release `qbind-node`)
- **V1**: TestNet receiver with wire validation, staging, apply-enabled, and
  drain-once enabled (real release `qbind-node`)
- **V2**: observer / propagation invariant node (real release `qbind-node`)

## Evidence Harness

```
scripts/devnet/run_155_testnet_peer_driven_apply_end_to_end_release_binary.sh
```

The harness, on a real `target/release/qbind-node`:

1. Captures provenance (git commit, rustc/cargo, `qbind-node` + Run 133
   helper SHA-256 and ELF Build IDs).
2. Mints the Run 154 TestNet fixtures with the **real release helper**
   (`run_133_v2_validation_only_fixture_helper`) and records their TestNet
   domain binding (environment, chain id, genesis hash) and SHA-256s.
3. Runs the TestNet release-binary refusal/fail-closed matrix
   (A6/C2 MainNet refused, C1/C3/C4 co-requisite refusals).
4. Emits in-scope and out-of-scope (denylist) grep summaries.

## Archive Layout

```
run_155_testnet_peer_driven_apply_end_to_end_release_binary/
├── README.md           ← this file
├── summary.txt         ← per-scenario verdicts and deferral list
├── provenance.txt      ← git commit, versions, binary + helper SHAs/Build IDs
├── fixtures/
│   ├── mint.log
│   ├── testnet_manifest.txt   ← TestNet fixture SHA-256s + genesis hash
│   ├── testnet/        ← Run 154 TestNet fixtures (real helper output)
│   ├── devnet/         ← DevNet fixtures (unchanged Run 133 output)
│   └── mainnet/        ← MainNet fixture-only material (never authoritative)
├── logs/
│   └── <scenario>/v1.{stdout,stderr}
├── exit_codes/
│   └── <scenario>.exit_code
└── grep_summaries/
    ├── in_scope.txt
    └── out_of_scope.txt
```

## Release-Binary Scenarios (this harness)

| Scenario | Expectation |
|----------|-------------|
| `A6_mainnet_refused` | exit=1, `Run 151: FATAL` (MainNet refused unconditionally) |
| `C1_testnet_drain_without_apply` | exit=1, `Run 151: FATAL` (apply co-requisite) |
| `C3_testnet_drain_without_staging` | exit=1, `FATAL` (staging co-requisite) |
| `C4_testnet_drain_without_wire_validation` | exit=1, `FATAL` (wire-validation co-requisite) |

The full positive TestNet apply path (A1) and the deterministic
selection / duplicate / reject matrix (A2–A5, R1–R11) are exercised by the
Run 154 TestNet fixture suite and the Run 152/150/148 source/test
matrices; the canonical mapping is in
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_155.md`.

## Denylist

Across all scenarios the denylist grep
(`grep_summaries/out_of_scope.txt`) must produce ZERO matches (the
expected MainNet-refusal banner, which names governance / KMS-HSM only to
state they are NOT implemented, is excluded):

- No autonomous background drain
- No apply on receipt without explicit drain
- No peer-majority authority
- No governance / KMS / HSM claim
- No signing-key rotation/revocation claim
- No validator-set rotation claim
- No MainNet apply
- No fallback to `--p2p-trusted-root`
- No active DummySig / DummyKem / DummyAead
- No SIGHUP / reload-apply / startup-mutation / snapshot-restore apply outcome
- No schema/wire/metric drift

## Out-of-Scope Deferrals

- **Governance**: unimplemented
- **KMS / HSM**: unimplemented
- **Signing-key rotation / revocation lifecycle**: open
- **Validator-set rotation**: open
- **Full C4**: open
- **C5**: open
- **MainNet**: refused unconditionally

DevNet evidence from Run 153 remains valid and untouched.
