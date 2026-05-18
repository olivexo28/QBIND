# QBIND DevNet Evidence — Run 088

**Objective:** disabled-by-default validation-before-rebroadcast propagation prototype for peer-candidate `0x05`, with no apply side effects.

**Verdict:** partial positive. Library and binary wiring landed; unit/integration evidence proves valid frames rebroadcast only after validation, invalid/oversize/duplicate/rate-limited frames do not rebroadcast, source peer is excluded, and apply/sequence/session metrics remain untouched. Release-binary N=3 propagation evidence is not completed in this run.

## Files changed

- `crates/qbind-node/src/cli.rs`
- `crates/qbind-node/src/main.rs`
- `crates/qbind-node/src/metrics.rs`
- `crates/qbind-node/src/p2p_tcp.rs`
- `crates/qbind-node/src/pqc_peer_candidate_wire.rs`
- `crates/qbind-node/tests/run_079_pqc_peer_candidate_wire_live_dispatch_tests.rs`
- `crates/qbind-node/tests/run_088_pqc_peer_candidate_propagation_tests.rs`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_088.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

## Required investigation findings

- `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`: Run 087 requires bounded payloads, validation before rebroadcast, duplicate suppression, rate limiting, loop prevention, no apply, no sequence commit, no session eviction, and clear metrics. Run 088 implements only the propagation subset and leaves peer-driven apply gates open.
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`: previous text said `0x05` remained validation-only / no propagation. This is now updated to distinguish non-applying validation-before-rebroadcast propagation from peer-driven apply.
- Runs 076–087 evidence docs: prior lifecycle had library validation, local binary check, bounded wire envelope, live receive path, send-side publisher, N=2/N=4 evidence, runbook coverage, and Run 087 safety gates. Run 088 does not weaken the no-Dummy/no-fallback evidence from Runs 084/085.
- `crates/qbind-node/src/pqc_trust_peer_candidate.rs`: `PeerCandidateValidator` already provides bounds checks, duplicate suppression, rate limiting, and non-mutating validation through the Run 069 loader.
- `crates/qbind-node/src/pqc_peer_candidate_wire.rs`: Run 078/079 receiver and dispatcher existed; Run 088 adds optional propagation after `PeerCandidateWireOutcome::Validated` only.
- `crates/qbind-node/src/p2p_tcp.rs`: raw `0x05` frame send queues existed from Run 080; Run 088 adds selected-peer raw send and source-aware read-loop dispatch.
- `crates/qbind-node/src/p2p_node_builder.rs`: builder installs the wire sink before transport start; no redesign was required.
- `crates/qbind-node/src/main.rs`: hidden flag wiring now arms propagation only with a validated trust-bundle baseline and installs the propagation sender after transport build.
- `crates/qbind-node/src/cli.rs`: hidden flag added: `--p2p-trust-bundle-peer-candidate-propagation-enabled`.
- `crates/qbind-node/src/metrics.rs`: new propagation counters added without adding any `_applied_total` family.

## Propagation design

- Receive `0x05` frame through the existing read-loop discriminator path.
- Decode and validate through `PeerCandidateWireReceiver` / `PeerCandidateValidator`.
- If validation fails, oversize drops, duplicate suppression fires, receiver is disabled, or rate limiting fires: no rebroadcast.
- If validation succeeds and propagation is enabled:
  - record propagation attempt;
  - enforce local propagation fixed-window rate limit;
  - suppress already-seen candidate id (`sequence:fingerprint_prefix`);
  - select connected peers excluding the source peer;
  - bound fanout by `max_rebroadcast_targets`;
  - enqueue over existing bounded raw-frame channels.

No TTL field was added because the wire envelope was intentionally left compatible. Loop prevention is therefore local seen-cache + source exclusion + bounded fanout/rate/queue limits.

## Metrics and logging

Added counters:

- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_attempt_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_duplicate_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_suppressed_invalid_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_rate_limited_total`

No `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` exists. Logs state validation-before-propagation, not applied, sequence not persisted, live trust unchanged, sessions untouched, rebroadcast count, and source peer exclusion.

## Proof mapping

- Valid candidate propagated only after validation: `run088_enabled_valid_candidate_rebroadcasts_once_to_non_source_only`.
- Invalid candidate not propagated: `run088_invalid_and_oversize_candidates_do_not_rebroadcast`.
- Oversize candidate not propagated: `run088_invalid_and_oversize_candidates_do_not_rebroadcast`.
- Duplicate not repeatedly propagated: `run088_duplicate_candidate_is_suppressed_after_first_rebroadcast`.
- Rate-limited candidate not propagated: `run088_propagation_rate_limit_blocks_rebroadcast_after_validation`.
- Source peer excluded: `run088_enabled_valid_candidate_rebroadcasts_once_to_non_source_only`.
- No apply / no sequence burn / no session eviction: Run 088 tests assert sequence unchanged and live-reload/session-eviction metrics remain zero; the propagation dispatcher has no `LivePqcTrustState`, `ProductionLiveTrustApplyContext`, `LiveReloadController`, or session-evictor handle.
- No Dummy crypto / no fallback: no fallback path was added; validation still reuses the existing bundle-signing-key and trust-bundle loader path.

## Commands run

Baseline before edits:

- `cargo test -p qbind-node --lib pqc_peer_candidate_wire`
- `cargo test -p qbind-node --lib pqc_trust_peer_candidate`
- `cargo test -p qbind-node --test run_080_pqc_peer_candidate_wire_send_tests`
- `cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests`
- `cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests`
- `cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests`
- `cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests`
- `cargo test -p qbind-node --lib metrics`
- `cargo test -p qbind-node --lib p2p`
- `cargo test -p qbind-node --lib`
- `cargo test -p qbind-net --lib`
- `cargo test -p qbind-crypto --lib`
- `cargo build --release -p qbind-node --bin qbind-node`
- `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper`
- `cargo build --release -p qbind-node --example devnet_pqc_root_helper`

Post-change:

- `cargo test -p qbind-node --lib pqc_peer_candidate_wire` — PASS
- `cargo test -p qbind-node --lib pqc_trust_peer_candidate` — PASS
- `cargo test -p qbind-node --test run_080_pqc_peer_candidate_wire_send_tests` — PASS
- `cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests` — PASS
- `cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests` — PASS
- `cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests` — PASS
- `cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests` — PASS
- `cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests` — PASS
- `cargo test -p qbind-node --lib metrics` — PASS
- `cargo test -p qbind-node --lib p2p` — PASS
- `cargo test -p qbind-node --lib` — PASS
- `cargo test -p qbind-net --lib` — PASS
- `cargo test -p qbind-crypto --lib` — PASS
- `cargo build --release -p qbind-node --bin qbind-node` — PASS
- `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper` — PASS
- `cargo build --release -p qbind-node --example devnet_pqc_root_helper` — PASS

Note: repository-wide `cargo fmt --check` was also tried and failed on pre-existing formatting diffs outside the Run 088 scope, so it was not used as a Run 088 pass/fail signal.

## Release-binary evidence

N=3 release-binary propagation evidence was not completed in Run 088
itself. It was completed in **Run 089** — see
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_089.md` and
`scripts/devnet/run_089_peer_candidate_propagation_n3.sh`. Run 089 runs
three release `qbind-node` processes (V0/V1/V2) over loopback on
DevNet, has V0 publish a valid Run 080 0x05 envelope, asserts V1
validates and rebroadcasts to V2 only (source-peer exclusion),
asserts V2 validates the propagated frame, asserts the invalid /
duplicate / settle-window scenarios match the Run 088 contract, and
hashes every node's `pqc_trust_bundle_sequence.json` before/after each
scenario to prove byte-identical equality. No wire-format change was
made, so Run 084/085 matrix reruns were not required by the task's
conditional wire-format rule.

## Remaining C4/C5 items

- Peer-driven live apply.
- `activation_epoch` runtime source.
- KMS/HSM custody.
- In-binary/on-chain signing-key ratification.
- Production fast-sync / consensus-storage restore.
- Per-environment production trust-anchor operation.
- Full C4 remains OPEN; C5 remains OPEN / narrowed.

## Immediate next action

Run an N=3 release-binary DevNet propagation harness that proves V0→V1→V2 propagation, source exclusion, duplicate suppression, no apply, no sequence burn, no session eviction, and no loop.