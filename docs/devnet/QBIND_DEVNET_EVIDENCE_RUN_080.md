# QBIND DevNet Evidence — Run 080

## Exact objective

Land a disabled-by-default production send-side counterpart for peer-candidate wire frame discriminator `0x05`, then prove bounded publish-once frame exchange semantics remain validation-only (no apply, no sequence write, no live trust mutation, no session eviction, no propagation).

## Exact verdict

**Partial positive.**  
Run 080 send-side publisher plumbing landed on the production binary and transport path with bounded publish-once semantics and fail-closed outcomes. Unit/integration evidence proves send-side encode/queue/no-peer/failure accounting and preserves validation-only boundaries.  
**Boundary still present:** this run does not yet include release-binary N=2 proof artifacts in this document for real two-process exchange logs/metrics.

## Exact files changed

- `crates/qbind-node/src/metrics.rs`
- `crates/qbind-node/src/p2p_tcp.rs`
- `crates/qbind-node/src/pqc_peer_candidate_wire.rs`
- `crates/qbind-node/src/cli.rs`
- `crates/qbind-node/src/main.rs`
- `crates/qbind-node/tests/run_080_pqc_peer_candidate_wire_send_tests.rs`

## Investigation findings (file/function references)

- Run 079 receive routing is in `p2p_tcp.rs::read_loop` and `pqc_peer_candidate_wire.rs::read_loop_dispatch_peer_candidate_wire_frame`.
- Existing transport write path only handled structured `P2pMessage` (`p2p_tcp.rs::write_loop` + `encode_frame`), so `0x05` raw-frame send required a bounded side channel.
- Peer registry ownership is in `TcpKemTlsP2pService.peers` (`HashMap<NodeId, PeerConnection>`), which allows snapshot-based bounded fanout.

## Send-side design landed

- Added Run 080 publisher API in `pqc_peer_candidate_wire.rs`:
  - `PeerCandidateWireFrameSender` trait
  - `LivePeerCandidateWirePublisher`
  - `PeerCandidateWirePublishConfig`
  - `PeerCandidateWirePublishReport`
  - `RawFrameSendReport` and per-peer outcomes
- Publisher path:
  1. load local operator envelope file (`PeerCandidateEnvelope`)
  2. bridge to wire envelope (`PeerCandidateWireEnvelopeV1`)
  3. encode with existing Run 078 encoder (`encode_peer_candidate_wire_frame`)
  4. bounded wait for peers
  5. single fanout send attempt to currently connected peers
  6. record send-side counters

## Transport send-side plumbing

- `TcpKemTlsP2pService` now has bounded raw-frame queue per peer (`RAW_FRAME_CHANNEL_CAPACITY=8`).
- Write loop multiplexes structured messages and raw framed bytes.
- Added `send_raw_frame_to_all_peers` snapshot fanout with non-blocking `try_send` per peer.
- Implemented publisher sender trait on `TcpKemTlsP2pService`.

## Enablement flags (hidden, disabled by default)

- `--p2p-trust-bundle-peer-candidate-wire-publish-enabled`
- `--p2p-trust-bundle-peer-candidate-wire-publish-path <PATH>`
- `--p2p-trust-bundle-peer-candidate-wire-publish-once`

Partial-config fail-closed checks were added in `main.rs`.

## Metrics/logging

Added send-side counters:

- `qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_send_failure_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_send_no_peer_total`
- `qbind_p2p_pqc_trust_bundle_peer_candidate_send_oversize_total`

No `_applied_total` and no `peer_candidate_wire_*` family were introduced.

## Validation-only / no-propagation boundaries preserved

Publisher and transport send path do **not**:

- apply trust bundle
- write sequence
- mutate `LivePqcTrustState`
- evict sessions
- auto-rebroadcast/propagate

## Exact commands run

- `cargo check -p qbind-node --lib`
- `cargo check -p qbind-node --bin qbind-node`
- `cargo test -p qbind-node --lib pqc_peer_candidate_wire -- --nocapture`
- `cargo test -p qbind-node --lib metrics::tests::peer_candidate_send_metrics -- --nocapture`
- `cargo test -p qbind-node --test run_080_pqc_peer_candidate_wire_send_tests -- --nocapture`
- `cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests`
- `cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests`
- `cargo test -p qbind-node --lib pqc_trust_peer_candidate`
- `cargo test -p qbind-node --lib pqc_peer_candidate_binary`

## Tests/evidence status

- Run 080 unit/integration tests: **pass**
- Run 078/079 regressions: **pass**
- Run 076/077 library regressions: **pass**
- Remaining required full matrix from task file: **not fully executed in this run**

## Proof points

- Valid publish path enqueues bounded frame and records sent metrics.
- No-peer timeout fails closed and records `send_no_peer_total`.
- Queue-full outcome records `send_failure_total`.
- Log line includes validation-only/not-applied boundary.

## Not solved in this run

- Release-binary N=2 two-process artifact proof for real `0x05` exchange (sender/receiver logs + metrics + sequence invariants captured in this doc).
- Full command matrix from the Run 080 task file.

## Exact immediate next action

Run a two-process release-binary DevNet capture with sender publish-once + receiver wire-validation enabled, collect sender/receiver logs + `/metrics` + sequence file checks, and append those artifacts here to upgrade verdict from partial positive to strongest positive.

## Run 081 follow-up evidence (2026-05-15)

Run 081 (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_081.md`) completed the requested release-binary N=2 live `0x05` exchange artifact capture:

- valid sender publish-once + receiver wire-validation-enabled exchange proven on release `qbind-node` with sender `qbind_p2p_pqc_trust_bundle_peer_candidate_sent_total=1`, receiver `received_total=1`, `validated_total=1`;
- receiver-disabled cheap-ignore case captured (sender sends; receiver peer-candidate validation counters remain zero);
- invalid wrong-chain candidate captured (receiver `rejected_total=1`);
- duplicate case captured (receiver `duplicate_total=1`);
- receiver sequence-file hash remained unchanged across all wire scenarios;
- session-eviction and live-reload-apply metrics remained unchanged (all zero).

Run 081 remains **partial positive** (not strongest positive) because the captured logs still include the existing Run 033 timeout-verification probe line containing `TrustedClientRoots/DummySig`, so the strict “no DummySig” claim is not yet closed. Run 081 does, however, narrow the Run 080 boundary from “send plumbing landed without release N=2 exchange proof” to “release-binary N=2 validation-only wire exchange proven with non-mutation invariants preserved.”