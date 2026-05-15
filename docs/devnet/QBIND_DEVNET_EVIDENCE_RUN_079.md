# QBIND DevNet Evidence — Run 079

**Title.** Run 079 — Live P2P receive-loop dispatch wiring for the
disabled-by-default peer-candidate wire path (validation-only).

**Date.** 2026-05-15.

**Verdict.** Partial positive. Disabled-by-default live P2P
receive-loop integration lands: the previously library-level-only
Run 078 `PeerCandidateWireReceiver` is now reachable from every
production `qbind-node` per-peer KEMTLS `read_loop` via a
`PeerCandidateWireFrameSink` trait + `LivePeerCandidateWireDispatcher`
adapter, gated on the existing Run 078 hidden
`--p2p-trust-bundle-peer-candidate-wire-validation-enabled` flag.
The release binary compiles in release mode with the dispatch wired
end-to-end (`spawn_peer_handlers` for the accept loop, `dial_peer`
for the legacy single-shot outbound path, and `DialerHandle::dial_once`
for the B8 retry path). Valid peer-supplied `0x05` frames validate
through the **same** Run 078 → Run 076 → Run 069 chain and bump the
**same** seven Run 076
`qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters; invalid /
oversize / duplicate / rate-limited / tampered frames fail closed at
the appropriate boundary; **no** `LivePqcTrustState` mutation, **no**
sequence persistence, **no** `P2pSessionEvictor` call, **no**
propagation, **no** session disconnection for an honest peer that
happens to send a malformed `0x05` frame. **No production publisher
of `0x05` frames lands in this run** — the discriminator is only
routed *inbound*; the partial-positive boundary is that two N=2
release-binary nodes that opt into the flag will not see a real
wire frame unless one of them is patched to *send* one (or unless a
future Run integrates a publisher). C4 remains OPEN.

---

## 1. Objective

A running `qbind-node` should be able to receive a bounded
peer-candidate wire frame (discriminator `0x05`) over the live P2P
KEMTLS-protected transport and validate it through the Run 078
`PeerCandidateWireReceiver`, without applying it, propagating it,
persisting sequence, mutating `LivePqcTrustState`, or evicting
sessions.

Strict scope (per `task/RUN_079_TASK.txt`):
- Add live receive-loop dispatch for the reserved peer-candidate
  frame discriminator `0x05`.
- Gate the handler behind the existing hidden Run 078 wire-validation
  flag.
- Default behavior unchanged when the flag is absent.
- Decode and size-bound the frame before expensive validation.
- Call `PeerCandidateWireReceiver` / `PeerCandidateValidator` only
  after cheap pre-checks.
- Do NOT call `ProductionLiveTrustApplyContext` / `LiveReloadController`
  / `LivePqcTrustState::swap_snapshot` / `P2pSessionEvictor` /
  `check_and_update_sequence`.
- Do NOT rebroadcast or forward peer candidate frames.
- Do NOT disconnect honest peers for invalid candidates.

---

## 2. Files changed

### 2.1 Library (`crates/qbind-node/src/`)
- **`pqc_peer_candidate_wire.rs`** — pre-existing Run 078 module
  extended with the Run 079 live-dispatch surface:
  - `pub trait PeerCandidateWireFrameSink: Send + Sync + 'static`
    with one method `handle_frame(&self, frame_bytes: &[u8])`.
  - `pub struct LivePeerCandidateWireDispatcher` — wraps the Run 078
    `PeerCandidateWireReceiver` one-to-one, holds owned runtime
    context fields (`expected_environment`, `expected_chain_id`,
    `scratch_dir`, `signing_keys`, `activation_ctx`,
    `sequence_persistence_path`, `local_leaf_cert_bytes`,
    `validation_time_secs`) plus an `Arc<P2pMetrics>` handle and a
    pluggable monotonic-millis clock. `impl PeerCandidateWireFrameSink
    for LivePeerCandidateWireDispatcher` routes every frame through
    `PeerCandidateWireReceiver::try_handle_frame` against a fresh
    `PeerCandidateWireRuntimeContext` reconstructed from the owned
    fields. Also exposes `dispatch_frame_for_test` for unit tests.
  - `pub struct LivePeerCandidateWireDispatcherConfig` — owned-fields
    builder for the dispatcher.
  - `pub struct DiscardPeerCandidateWireSink` — fail-safe
    cheap-discard sink installed when the operator opts in but no
    `--p2p-trust-bundle` baseline is loaded. Bumps only
    `received_total + disabled_total` per frame; never decodes, never
    allocates beyond the frame slice the caller already has.
  - `pub enum ReadLoopFrameDecision { PassThrough |
    ConsumedPeerCandidateWire }` — the return type of the read-loop
    helper, used as a discriminated tag so the caller in
    `p2p_tcp.rs` can decide whether to fall through to
    `decode_frame` or continue the read loop.
  - `pub fn read_loop_dispatch_peer_candidate_wire_frame(frame_bytes:
    &[u8], sink: Option<&Arc<dyn PeerCandidateWireFrameSink>>) ->
    ReadLoopFrameDecision` — pure-function helper that peeks the
    first byte and dispatches to the sink (or cheap-drops) iff the
    byte equals `DISCRIMINATOR_PEER_CANDIDATE_WIRE`. Returns
    `PassThrough` for every other first byte so the existing
    `decode_frame` demuxer for `0x00 / 0x01 / 0x02 / 0x03` runs
    bit-for-bit unchanged.
  - 8 new module unit tests under `#[cfg(test)] mod tests` (the
    existing Run 078 unit-test count grows from 16 to 24, all green).

- **`p2p_tcp.rs`** — production P2P transport service:
  - New `peer_candidate_wire_sink: Arc<RwLock<Option<Arc<dyn
    PeerCandidateWireFrameSink>>>>` field on
    `TcpKemTlsP2pService`.
  - New `set_peer_candidate_wire_frame_sink(&self, Arc<dyn ...>)`
    public installer + `has_peer_candidate_wire_frame_sink(&self) ->
    bool` public read accessor (used by tests / observability;
    avoids leaking the trait object on the read path).
  - New mirror field on `DialerHandle` so the B8 retry path
    (`DialerHandle::dial_once`) sees the same sink as the accept
    loop. Threaded through `dialer_handle()`.
  - `spawn_peer_handlers` gains an `Arc<RwLock<...>>` parameter so
    the call sites in `dial_peer`, `handle_inbound_connection`, and
    `DialerHandle::dial_once` all pass the SAME slot.
  - Inside `TcpKemTlsP2pService::read_loop`: exactly one new branch
    added BEFORE the existing `decode_frame(...)` call —

    ```rust
    let sink_snapshot = peer_candidate_wire_sink.read().clone();
    let decision = read_loop_dispatch_peer_candidate_wire_frame(
        &payload, sink_snapshot.as_ref(),
    );
    match decision {
        ReadLoopFrameDecision::ConsumedPeerCandidateWire => continue,
        ReadLoopFrameDecision::PassThrough => {} // fall through
    }
    ```

    The `continue` keeps the read loop alive on every `0x05` frame
    (whether decoded successfully or rejected at the
    discriminator-layer) so a peer-supplied wire frame can NEVER
    poison the connection for honest `0x00 / 0x01 / 0x02 / 0x03`
    traffic.

- **`p2p_node_builder.rs`** — production builder:
  - New `peer_candidate_wire_sink: Option<Arc<dyn ...>>` field on
    `P2pNodeBuilder` with `Default::None` semantics.
  - New `with_peer_candidate_wire_sink(self, Arc<dyn ...>) -> Self`
    builder setter.
  - In `build()`, after `TcpKemTlsP2pService::new(...)` and before
    `start()`, the configured sink (if any) is installed via
    `set_peer_candidate_wire_frame_sink` so the very first accepted
    / dialed peer's read loop already sees it.

### 2.2 Binary (`crates/qbind-node/src/main.rs`)
- `run_p2p_node` gains a Run 079 install block positioned AFTER
  the existing Run 070/073 `live_for_reload_apply`
  `with_live_pqc_trust` builder hook and BEFORE `builder.build(...)`.
  - When `args.p2p_trust_bundle_peer_candidate_wire_validation_enabled
    == true` AND `trust_bundle_loaded.is_some()`: construct a full
    `LivePeerCandidateWireDispatcher` using
    - `config.environment` (the same environment value the existing
      startup loader uses);
    - `config.environment.chain_id()` (same canonical chain-id
      source);
    - `bundle_signing_keys` parsed earlier in `run_p2p_node` from
      `--p2p-trust-bundle-signing-key`;
    - `ActivationContext::height_only(0)` (matches the Run 069
      reload-check baseline; the receive-side path is strictly
      validation-only so a height-only context is the truthful
      default);
    - `pqc_trust_sequence::sequence_file_path(data_dir)` from
      `config.data_dir` (read-only cross-check; the dispatcher never
      writes the sequence file);
    - `node_metrics.p2p_arc()` — the SAME `Arc<P2pMetrics>` the
      service uses via `with_p2p_metrics`.
    The scratch directory is `std::env::temp_dir() /
    "qbind-run079-wire-scratch-<pid>"`; if it cannot be created the
    install block falls back to `DiscardPeerCandidateWireSink` with
    an operator-visible error line.
  - When the flag is set but `trust_bundle_loaded.is_none()`:
    install `DiscardPeerCandidateWireSink` so the operator opt-in is
    honoured truthfully (frames recognised at the discriminator
    layer, counted via `received_total + disabled_total`, dropped
    without decode).
  - When the flag is unset: the entire Run 079 install block is
    bit-for-bit silent. Every existing `qbind-node` startup
    invocation is unchanged.

### 2.3 Tests
- **`crates/qbind-node/tests/run_079_pqc_peer_candidate_wire_live_dispatch_tests.rs`** — NEW. 11 integration tests, all pass.

### 2.4 Docs
- **`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_079.md`** — THIS file.
- **`docs/whitepaper/contradiction.md`** — Run 079 C4 sub-piece entry
  (POSITIVE NARROW; full C4 remains OPEN).

---

## 3. Commands run

### 3.1 New Run 079 tests (PASS)
```
$ cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests
test result: ok. 11 passed; 0 failed; 0 ignored
```
Tests:
1. `run079_default_service_has_no_wire_sink_installed`
2. `run079_read_loop_helper_routes_only_0x05_to_sink`
3. `run079_read_loop_helper_drops_0x05_without_sink`
4. `run079_discard_sink_only_bumps_received_and_disabled`
5. `run079_live_dispatcher_validates_without_applying_or_persisting`
6. `run079_live_dispatcher_rejects_tampered_signature`
7. `run079_live_dispatcher_drops_oversize_before_decode`
8. `run079_live_dispatcher_rate_limit_kicks_in`
9. `run079_dispatcher_composes_with_reload_check_no_cross_mutation`
10. `run079_sink_trait_object_is_send_sync_across_threads`
11. `run079_format_metrics_does_not_introduce_new_family`

### 3.2 Regression — Run 069 / 073 / 074 / 076 / 077 / 078 (PASS)
```
$ cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests
test result: ok. 12 passed; 0 failed

$ cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests
test result: ok. 10 passed; 0 failed

$ cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests
test result: ok. 10 passed; 0 failed

$ cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests
test result: ok. 16 passed; 0 failed

$ cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests
test result: ok. 12 passed; 0 failed

$ cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests
test result: ok. 19 passed; 0 failed
```

### 3.3 Regression — wire-touching transports / mutual-auth (PASS)
```
$ cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
test result: ok. 10 passed; 0 failed

$ cargo test -p qbind-net --test run_052_leaf_revocation_handshake_tests
test result: ok. 9 passed; 0 failed
```

### 3.4 Regression — full library suites (PASS)
```
$ cargo test -p qbind-node --lib
test result: ok. 1057 passed; 0 failed; 0 ignored

$ cargo test -p qbind-net --lib
test result: ok. 17 passed; 0 failed

$ cargo test -p qbind-crypto --lib
test result: ok. 68 passed; 0 failed
```

The `qbind-node` lib suite includes the previously-passing Run 078
unit tests (16) plus 8 new Run 079 unit tests in the same module
(`pqc_peer_candidate_wire::tests::*`), all green. All Run
074-related counters (`peer_candidate_*`, `live_reload_*`,
`session_eviction_*`) remain rendered correctly by
`metrics::format_metrics()`.

### 3.5 Release binary + helpers (PASS)
```
$ cargo build --release -p qbind-node --bin qbind-node \
                                      --example devnet_pqc_trust_bundle_helper \
                                      --example devnet_pqc_root_helper
Finished `release` profile [optimized] target(s) in 6m 35s
```
Single pre-existing warning (`unused variable: worker_id`) is
unrelated to Run 079.

---

## 4. Investigation findings

### 4.1 Live read-loop insertion point
- File: `crates/qbind-node/src/p2p_tcp.rs`.
- Function: `TcpKemTlsP2pService::read_loop` (the per-peer
  `tokio::spawn`ed task that drives every accepted / dialed KEMTLS
  session via `SecureChannel::recv_frame_async` → `decode_frame`).
- Existing discriminator handling: `decode_frame` returns a
  `P2pMessage::{Consensus, Dag, Control}` based on the first byte of
  the frame payload (`0x00 / 0x01 / 0x02 / 0x03`). Unknown
  discriminators error at `decode_frame` and the peer is recorded as
  receiving an unknown frame (with bytes counted on
  `bytes_received`).
- Insertion: a single peek-and-route call to
  `read_loop_dispatch_peer_candidate_wire_frame` is added BEFORE
  the existing `decode_frame` call. The new helper returns
  `ConsumedPeerCandidateWire` if and only if the first byte equals
  `DISCRIMINATOR_PEER_CANDIDATE_WIRE = 0x05`; in that case the read
  loop `continue`s. Otherwise the helper returns `PassThrough` and
  the existing `decode_frame` path runs unchanged.
- Honest-peer policy: peer-supplied `0x05` frames that fail at any
  Run 078 / 076 / 069 boundary DO NOT close the KEMTLS session — the
  read loop continues on the `ConsumedPeerCandidateWire` arm so a
  hostile or buggy peer sending malformed `0x05` frames cannot poison
  the consensus / DAG / control inbound paths for honest peers.

### 4.2 Frame `0x05` non-collision
- `p2p_tcp.rs` uses `0x00 / 0x01 / 0x02 / 0x03` for the existing
  consensus / DAG / control frame types (the exact mapping is
  documented at `decode_frame`'s call sites and in the Run 078
  evidence doc §"What is narrowed").
- Run 078 reserved `DISCRIMINATOR_PEER_CANDIDATE_WIRE = 0x05` and
  the Run 078 module unit test
  `frame_discriminator_does_not_collide_with_existing_p2p_tcp_frames`
  asserts the non-collision invariant. Run 079 only routes inbound
  on that already-reserved discriminator; the invariant is
  unchanged.

### 4.3 Frame size pre-bound
- `MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES` (Run 078) is enforced inside
  `decode_peer_candidate_wire_frame` BEFORE any allocation /
  deserialization. The Run 079 dispatcher reuses
  `PeerCandidateWireReceiver::try_handle_frame` verbatim, so the
  pre-allocation bound is preserved bit-for-bit.
- At the transport layer, `SecureChannel::recv_frame_async` already
  caps the on-the-wire frame size via the existing KEMTLS framing
  layer (no Run 079 change there).
- Run 079 integration test
  `run079_live_dispatcher_drops_oversize_before_decode` proves
  `dropped_oversize_total +1` and `rejected_total` unchanged for a
  declared-oversize frame, without scratch-file allocation.

### 4.4 Peer identity / source metadata
- Today the per-peer read loop passes a `NodeId` (the local
  registration handle for the remote peer) but the operator-visible
  `peer_id` field on `PeerCandidateWireEnvelopeV1` is the
  peer-supplied string the *frame* carries, not the validator-cert
  identity from the KEMTLS handshake. Run 079 does NOT bind the
  KEMTLS-derived identity into the dispatcher's runtime context —
  that binding (e.g. per-peer rate-limiting keyed on validator id)
  is part of the still-open peer/gossip propagation surface and is
  explicitly deferred. The current global Run 076 rate-limiter
  remains the operative DoS bound (proven by
  `run079_live_dispatcher_rate_limit_kicks_in`).

### 4.5 Metrics / logging
- Reuses the seven Run 076
  `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters verbatim.
- No `_applied_total` family, no `peer_candidate_wire_*` family —
  both asserted by `run079_format_metrics_does_not_introduce_new_family`.
- The operator-visible installation log line is
  `[binary] Run 079: installing live peer-candidate wire dispatcher
  (env=<env> sequence_baseline=<n> signing_keys=<count>).` and
  `[binary] Run 079: --p2p-trust-bundle-peer-candidate-wire-validation-enabled
  was supplied without a --p2p-trust-bundle baseline; installing
  cheap-discard sink ...` for the no-baseline path. Neither line
  references any private material or bundle bytes.
- The per-frame `wire_observed_log_line(...)` from Run 078 is
  unchanged and still contains the stable disclaimer substrings
  `Run 078`, `NOT applied`, `not propagated`, `sequence not
  persisted`, `live trust state unchanged`, `sessions untouched`.

---

## 5. Live-receive semantics (proof matrix)

| Boundary | Test |
|---|---|
| Disabled (no sink installed) → no decode, no validator call | `run079_read_loop_helper_drops_0x05_without_sink` |
| Disabled (discard sink installed) → only `received_total + disabled_total` bumped | `run079_discard_sink_only_bumps_received_and_disabled` |
| Enabled + valid candidate → validates, NOT applied, NOT propagated | `run079_live_dispatcher_validates_without_applying_or_persisting` |
| Enabled + tampered-signature candidate → rejected at Run 069 loader | `run079_live_dispatcher_rejects_tampered_signature` |
| Enabled + oversize declared payload → dropped before decode | `run079_live_dispatcher_drops_oversize_before_decode` |
| Enabled + rate-limit kicks in → `rate_limited_total` bumps | `run079_live_dispatcher_rate_limit_kicks_in` |
| `0x00 / 0x01 / 0x02 / 0x03 / 0x04 / 0x06 / 0xff` frames → `PassThrough` (existing demuxer runs unchanged) | `run079_read_loop_helper_routes_only_0x05_to_sink` |
| Run 069 reload-check unaffected on the same bundle bytes | `run079_dispatcher_composes_with_reload_check_no_cross_mutation` |
| `Arc<dyn PeerCandidateWireFrameSink>` `Send + Sync` across threads | `run079_sink_trait_object_is_send_sync_across_threads` |
| No new metric family in `format_metrics()` | `run079_format_metrics_does_not_introduce_new_family` |

All outcomes (validated / rejected / oversize / rate-limited /
duplicate / disabled): **no** `LivePqcTrustState` mutation, **no**
sequence mutation, **no** session eviction, **no** propagation, **no**
`_applied_total` movement, **no** Run 074 trigger counter movement,
**no** `Dummy*` fallback path.

---

## 6. Safety / DoS controls

- **Max declared frame size** enforced by
  `decode_peer_candidate_wire_frame` BEFORE allocation (Run 078,
  unchanged).
- **No unbounded task spawn per frame** — the read loop dispatches
  *synchronously* via the `PeerCandidateWireFrameSink::handle_frame`
  trait method; no `tokio::spawn` per frame.
- **No unbounded buffering** — the helper takes the existing payload
  slice the read loop already has.
- **Rate-limit** — inherited from Run 076 (global fixed-window
  budget on `max_in_window` per `rate_limit_window_ms`). Per-peer
  rate-limiting keyed on KEMTLS identity is deferred (see §4.4).
- **Duplicate suppression** — inherited from Run 076 (LRU keyed on
  the 8-hex-char bundle fingerprint prefix). A duplicate frame
  short-circuits the LRU without paying ML-DSA verification cost
  twice.
- **Malformed frames** — never panic; rejected at the frame layer
  with `rejected_total`, and the read loop continues so honest
  traffic is unaffected.

---

## 7. Proofs of non-regression

### 7.1 Local check mode (Run 077) unchanged
`cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests` →
12/12 pass after Run 079 lands. The Run 077 binary path constructs no
`P2pNodeBuilder` and exits before any Run 079 install block could
fire; bit-for-bit unchanged.

### 7.2 Local reload paths unchanged
- Run 069 reload-check: 12/12 pass.
- Run 073 process-start reload-apply: 10/10 pass.
- Run 074 SIGHUP live reload-apply: 10/10 pass.
- The Run 079 dispatcher holds **no** handle to
  `LivePqcTrustState`, **no** handle to `LiveReloadController`, **no**
  handle to `LiveTrustApplyContext`, and **no** handle to
  `P2pSessionEvictor`. By construction it cannot trigger any of
  those paths.

### 7.3 P2P wire / mutual-auth unchanged
- `run_037_pqc_static_root_mutual_auth_tests`: 10/10 pass.
- `qbind-net::run_052_leaf_revocation_handshake_tests`: 9/9 pass.
- The KEMTLS handshake is untouched; only the inner
  application-frame demuxer gains a single peek-and-route call.

### 7.4 Full lib suites unchanged
- `qbind-node --lib`: 1057/1057 pass.
- `qbind-net --lib`: 17/17 pass.
- `qbind-crypto --lib`: 68/68 pass.

---

## 8. Release-binary evidence (boundary statement)

**Boundary.** The release binary `target/release/qbind-node` builds
cleanly with Run 079 wired end-to-end (`cargo build --release -p
qbind-node --bin qbind-node` succeeds). The disabled-by-default N=2
baseline path is exercised by every Run 037 / Run 040 / Run 052
release-binary smoke that already ships, because the install block
is silent when the flag is unset.

However, **no production `qbind-node` code path publishes `0x05`
frames on the wire today** — the receive-side dispatch lands, but
the send-side publisher is part of the still-open peer/gossip
propagation surface and is intentionally NOT in this run's scope.
The Run 079 integration tests exercise the dispatcher directly via
the `PeerCandidateWireFrameSink::handle_frame` trait method (the
same entry point the read loop's helper calls), proving the
end-to-end Run 069/076/078 chain bit-for-bit; but they do NOT spawn
two `qbind-node` release binaries and have one *send* a
`0x05` frame to the other, because no such *send* path exists in the
binary in this run.

**This is the partial-positive verdict.** The narrowed boundary is:
"live receive-loop dispatch wired into production-binary read loop;
when an opted-in peer happens to *send* a `0x05` frame (e.g. via a
test harness or a future publisher), the receive path validates it
through the Run 078 → Run 076 → Run 069 chain truthfully". The
release-binary smoke for an actual two-node frame exchange is
deferred to the Run that introduces the production publisher.

### 8.1 Disabled-by-default N=2 baseline
- Default startup: no flag → bit-for-bit-unchanged from Run 078.
  Inherits every existing N=2 release-binary smoke
  (`run_037_pqc_static_root_mutual_auth_tests`,
  `run_052_leaf_revocation_handshake_tests`). No fallback, no Dummy
  crypto.

### 8.2 Enabled valid peer-candidate frame
- Proven by `run079_live_dispatcher_validates_without_applying_or_persisting`
  driving the trait method on the same byte stream the read loop
  would pass through. Counter movement: `received_total +1`,
  `validated_total +1`, every other Run 076 counter unchanged. No
  `_applied_total` family in `format_metrics()` output. No
  `LivePqcTrustState` mutation (asserted by construction — the
  dispatcher holds no live-state handle). No session eviction
  (asserted by construction — the dispatcher holds no evictor
  handle).

### 8.3 Invalid peer-candidate frame
- `run079_live_dispatcher_rejects_tampered_signature`: tampered
  signature → rejected at Run 069 loader, `rejected_total +1`, no
  sequence / live-trust / session mutation.

### 8.4 Oversize frame
- `run079_live_dispatcher_drops_oversize_before_decode`: declared
  oversize → `dropped_oversize_total +1` before any allocation,
  `rejected_total` unchanged, no panic.

### 8.5 Duplicate / rate-limit
- `run079_live_dispatcher_rate_limit_kicks_in`: with
  `max_in_window = 1`, a second unique-fingerprint frame is
  rate-limited; truthful invariant `validated + rate_limited +
  rejected + dropped_oversize + duplicate + disabled == received`
  holds.

---

## 9. Exact boundaries (still OPEN)

Run 079 does **not** close:
- peer-driven live apply
- propagation / rebroadcast (peer/gossip publisher)
- consensus ratification of bundle-signing-key changes
- `activation_epoch` runtime sourcing (unchanged from Run 057)
- KMS / HSM custody
- in-binary / on-chain bundle-signing-key ratification
- production fast-sync / consensus-storage restore
- per-environment production trust-anchor operation
- admin-API / filesystem-watcher triggers
- selective per-peer session retention

C4 remains OPEN. C5 remains OPEN / narrowed.

---

## 10. contradiction.md update

Updated. See `docs/whitepaper/contradiction.md` §"C4 Run 079
evidence update (2026-05-15)". Records validation-only live receive
narrowed acceptance; full C4 stays OPEN; no peer-driven live apply
clause is closed; no `Dummy*` fallback introduced; the absence of an
`_applied_total` family is anchored verbatim;
release-binary-publisher boundary is recorded explicitly.

---

## 11. Exact immediate next action recommended

Implement a production peer-candidate wire **publisher** (the
send-side counterpart to the Run 079 receive-side dispatch) under
the same disabled-by-default boundary, so that an N=2 release-binary
peer-connection smoke can be authored where one node *sends* a real
`0x05` frame over the live KEMTLS-protected transport and the
receiving node validates it through the Run 079 dispatcher. The
publisher MUST remain disabled by default, MUST require a separate
hidden CLI flag, and MUST NOT introduce a re-broadcast path
(end-of-line at the directly-targeted peer). Counter-bump expectation
on the publisher side: a new "sent" counter family (one counter, no
`_applied_total`); operator log line MUST contain the stable
disclaimer substrings already used by Run 079. After that publisher
lands, the Run 079 partial-positive boundary in §8 collapses to a
strongest-positive release-binary evidence run.