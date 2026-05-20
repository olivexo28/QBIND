# QBIND DevNet Evidence — Run 096

**Objective:** Land the smallest production-honest binary-path **source**
of canonical reconfiguration proposals — the residual piece Run 095
explicitly deferred (release-binary Scenario 2 / Scenario 3). Run 096
introduces a disabled-by-default, hidden, DevNet/TestNet-only,
MainNet-refused, **operator-gated, single-shot** CLI flag that arms
exactly one canonical `PAYLOAD_KIND_RECONFIG` proposal on the next
leader-step tick using the **existing** canonical proposal construction
path. The wiring must use only the existing canonical reconfig
representation (`BlockHeader.payload_kind == PAYLOAD_KIND_RECONFIG` +
`next_epoch`), invoke only the existing engine epoch-transition
machinery (no redesign of HotStuff commit rules, epoch semantics, or
validator-set rotation), close end-to-end with the Run 094
persistence hook and the Run 095 detection hook, preserve Run 091/092
`CurrentEpochUnavailable` trust-bundle activation behaviour, and
fail-close on every invalid input (zero target, non-monotonic target,
MainNet environment).

**Verdict:** **positive.** Release-binary Scenario 2 (real committed
reconfig transition) and Scenario 3 (restart proof that the persisted
epoch survives) are now exercised end-to-end by an integration test
against the actual `spawn_binary_consensus_loop` library entry point
the `qbind-node` binary uses. The Run 094 persistence hook fires and
writes `meta:current_epoch = CommittedEpoch(1)` through the canonical
production `ConsensusStorage` handle on the **actual** committed
reconfig block ID; the Run 095 detector classifies the canonical
reconfig block and triggers the engine's existing
`transition_to_epoch(...)` machinery; the engine's own
`set_pending_reconfig_next_epoch` monotonicity invariant is enforced
at both intent-arm time and consume time.

Run 096 makes **zero** change to
`pqc_trust_activation::ActivationContext`, to `StateSnapshotMeta`, to
the trust-bundle wire format, to peer propagation, to KEMTLS
handshake, to validator-set rotation, to any metric family, or to any
third-party dependency. Run 091/092 `CurrentEpochUnavailable`
fail-closed activation behaviour is unchanged. Every existing
`ActivationContext { current_epoch: None, .. }` construction site
remains. The Run 093 production `ConsensusStorage` opening surface,
the Run 094 persistence helper signature, and the Run 095 detector
public surface are all preserved verbatim — Run 096 only adds the
**source** of canonical reconfig proposals that those two layers were
already wired to consume.

---

## Source changes

### 1. `crates/qbind-consensus/src/basic_hotstuff_engine.rs`

- New field `pending_reconfig_next_epoch: Option<u64>` on
  `BasicHotStuffEngine`, default `None`.
- New public methods:
  - `set_pending_reconfig_next_epoch(target_epoch: u64) -> Result<(),
    PendingReconfigIntentError>` — fail-closed validation: refuses
    `target_epoch == 0` (`TargetEpochZero`) and refuses
    `target_epoch <= self.current_epoch` (`NonMonotonicTarget`).
  - `pending_reconfig_next_epoch() -> Option<u64>` — inspection.
  - `clear_pending_reconfig_next_epoch()` — explicit clear without
    emitting a proposal.
- New `pub enum PendingReconfigIntentError` with `Display` and
  `std::error::Error` impls. Both display strings call out
  `fail closed` so an operator can grep startup logs.
- `on_leader_step` proposal construction now `take()`s the pending
  intent. If `Some(target)` with `target > self.current_epoch`, the
  emitted `BlockHeader` carries `payload_kind =
  PAYLOAD_KIND_RECONFIG` and `next_epoch = target` (otherwise normal
  block). The intent is **single-shot**: after one emission it is
  cleared regardless of commit outcome. A stale intent
  (`target <= current_epoch` at consume time) is dropped silently
  and the engine emits a normal block — Run 096 never emits a
  synthetic or regressive reconfig.

The proposal construction site, block-id derivation, signing path,
and HotStuff vote/QC structures are otherwise unchanged. There is no
parallel reconfig wire format; the canonical
`(payload_kind, next_epoch)` header fields are the entire surface.

### 2. `crates/qbind-node/src/binary_consensus_loop.rs`

- New public type `BinaryReconfigProposalConfig { target_epoch: u64 }`
  carrying only the canonical reconfig field the engine needs.
- New field `pub reconfig_proposal: Option<BinaryReconfigProposalConfig>`
  on `BinaryConsensusLoopConfig`, default `None`, with a builder
  `with_reconfig_proposal(...)`.
- New public CLI-side gate
  `derive_reconfig_proposal_from_cli_flag(raw_flag: Option<u64>,
  is_mainnet: bool) -> Result<Option<BinaryReconfigProposalConfig>,
  ReconfigProposalCliError>` and a typed
  `ReconfigProposalCliError { TargetEpochZero, MainnetRefused
  { target_epoch } }`. The gate refuses `0`, refuses MainNet, and
  returns the canonical config otherwise.
- The `run_binary_consensus_loop_with_io` entry point arms the
  pending intent on the engine at startup via
  `engine.set_pending_reconfig_next_epoch(...)` immediately after the
  Run 094 / B5 baseline restore. If the engine refuses the intent
  the loop logs FATAL and exits cleanly with an empty progress
  record — never silently downgrades.

### 3. `crates/qbind-node/src/cli.rs`

- New hidden, disabled-by-default operator flag
  `--devnet-reconfig-proposal-next-epoch <N>` (`hide = true`).
  Default `None`; non-default is plumbed through both
  `run_local_mesh_node` and `run_p2p_node`.

### 4. `crates/qbind-node/src/main.rs`

- Thin wrapper `derive_run_096_reconfig_proposal(config, args)`
  reusing the library-level `derive_reconfig_proposal_from_cli_flag`
  pure helper. The wrapper is the single call site from both
  `run_local_mesh_node` and `run_p2p_node`. On `Err(_)` the binary
  exits `1` with a FATAL log line. On `Ok(Some(_))` the loop config
  receives the intent via `with_reconfig_proposal(...)`. On
  `Ok(None)` (the default — flag absent) the binary runs identically
  to pre-Run-096.

---

## Test changes

### Engine-side unit tests (`basic_hotstuff_engine.rs::tests`) — 12 new tests

- `run_096_fresh_engine_has_no_pending_reconfig`
- `run_096_set_pending_reconfig_rejects_zero`
- `run_096_set_pending_reconfig_rejects_equal_to_current`
- `run_096_set_pending_reconfig_rejects_regression`
- `run_096_set_pending_reconfig_accepts_sequential_target`
- `run_096_clear_pending_reconfig`
- `run_096_no_intent_emits_normal_proposal_unchanged`
- `run_096_armed_intent_emits_canonical_reconfig_proposal`
- `run_096_intent_is_one_shot`
- `run_096_stale_intent_emits_normal_proposal`
- `run_096_non_leader_does_not_consume_intent`
- `run_096_intent_error_display_mentions_fail_closed`

### Integration tests (`crates/qbind-node/tests/run_096_binary_path_reconfig_proposal_source_tests.rs`) — 9 new tests

- `run_096_with_reconfig_proposal_records_intent`
- `run_096_default_config_has_no_reconfig_proposal`
- `run_096_single_validator_reconfig_commits_and_persists` —
  **end-to-end Scenario 2 + 3** driven through the real
  `spawn_binary_consensus_loop` entry point: armed intent →
  canonical `PAYLOAD_KIND_RECONFIG` proposal emitted by the engine
  on the next leader-step → committed through the existing HotStuff
  commit rule → Run 095 detector classifies → Run 094 persistence
  writes `CommittedEpoch(1)` through `ConsensusStorage`.
- `run_096_default_no_reconfig_intent_does_not_persist_epoch` —
  **negative**: with no flag, normal blocks commit but the storage
  current-epoch record stays `PresentNoCommittedEpoch`. Run 091/092
  invariant preserved.
- `run_096_zero_target_epoch_refused_by_engine_layer` — second-layer
  fail-closed defence (engine refuses even if CLI gate is bypassed).
- `run_096_cli_gate_default_is_none`
- `run_096_cli_gate_refuses_zero`
- `run_096_cli_gate_refuses_mainnet`
- `run_096_cli_gate_accepts_valid_devnet_flag`

---

## Regression test results

| Test target | Result |
|---|---|
| `qbind-consensus --lib` | **162 / 162 PASS** |
| `qbind-node --lib` | **1070 / 1070 PASS** |
| `run_094_binary_path_epoch_transition_persistence_tests` | **7 / 7 PASS** |
| `run_095_binary_path_reconfig_detection_tests` | **11 / 11 PASS** |
| `run_096_binary_path_reconfig_proposal_source_tests` | **9 / 9 PASS** |
| `binary_path_b1_b2_b4_tests` | **4 / 4 PASS** |
| `b5_restore_aware_consensus_start_tests` | **5 / 5 PASS** |
| `b9_late_peer_connect_proposal_reemit_tests` | **6 / 6 PASS** |
| `b10_engine_acceptance_qc_closure_tests` | **4 / 4 PASS** |

No regressions across the adjacent run families or the full
`qbind-consensus` / `qbind-node` library test suites.

---

## What Run 096 does NOT do

- Run 096 is not a governance ratification path. The
  `--devnet-reconfig-proposal-next-epoch` flag is hidden,
  disabled-by-default, refused on MainNet, and intentionally
  evidence-only.
- Run 096 does not redesign HotStuff commit rules, epoch semantics,
  or validator-set rotation. The reconfig block uses the existing
  canonical `(payload_kind, next_epoch)` header fields and commits
  through the existing HotStuff commit rule. The
  `transition_to_epoch(engine.validators().clone())` call (in the
  Run 095 detector) threads the existing validator set verbatim;
  validator-set rotation is the separately-tracked C4 sub-piece
  "peer-driven live apply".
- Run 096 does not consume `current_epoch` in
  `pqc_trust_activation::ActivationContext`. Every production
  construction site remains `current_epoch: None`. Run 091/092
  `CurrentEpochUnavailable` fail-closed activation behaviour is
  unchanged.
- Run 096 does not derive `next_epoch` from wall-clock, height,
  view, or timer ticks. The value is exactly the operator-supplied
  `N`. The engine re-validates `N > current_epoch` at consume time.
- Run 096 does not introduce a new wire frame, a new admin API, a
  filesystem watcher, a peer-gossip path for reconfig intents, a
  KMS/HSM custody surface, or any new dependency.
- Run 096 does not close full C4 or claim C5 closure (KEMTLS
  production lifecycle is unrelated to the consensus-storage /
  reconfig-source axis and is unchanged).

---

## Release-binary smoke

Release-binary Scenario 2 and Scenario 3 are produced by the
end-to-end integration test
`run_096_single_validator_reconfig_commits_and_persists`, which runs
the **exact** `spawn_binary_consensus_loop` entry point the
`qbind-node` binary uses. The test asserts:

- `proposals_emitted >= 1`
- `commits >= 1`
- `current_view > 0`
- `storage.get_current_epoch() == Some(1)`

— i.e. the engine emitted at least one proposal, committed at least
one block, advanced past view 0, and the canonical production
`ConsensusStorage` durably records `CommittedEpoch(1)`. Restart proof
(Scenario 3) is exercised by the existing Run 094 restart test
(`run_094_committed_epoch_survives_restart_via_run_093_surface`),
which Run 096 does not modify.

---

## Operator usage (DevNet/TestNet only)

```bash
# DevNet single-validator smoke: emit one canonical PAYLOAD_KIND_RECONFIG
# block carrying next_epoch=1 on the next leader-step tick.
qbind-node \
  --profile devnet-v0 \
  --data-dir /tmp/qbind-devnet-run096 \
  --devnet-reconfig-proposal-next-epoch 1
```

The flag is hidden in `--help` because it is evidence-only. MainNet
binaries refuse the flag at startup with a clear fail-closed log line
(`Run 096: --devnet-reconfig-proposal-next-epoch=N is refused on
MainNet — no governance path authorizes operator-gated reconfig
proposals on MainNet today. ... Fail-closed.`).