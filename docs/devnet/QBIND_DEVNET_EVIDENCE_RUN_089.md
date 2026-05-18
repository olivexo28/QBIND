# QBIND DevNet Evidence — Run 089

**Objective:** prove on release `qbind-node` binaries that the Run 088
validation-before-rebroadcast propagation prototype for peer-candidate
`0x05` frames works end-to-end on an N=3 DevNet:

- V0 sends a valid `0x05` peer-candidate frame to V1,
- V1 validates it,
- V1 rebroadcasts it to V2 only,
- V1 does **not** rebroadcast back to V0/source,
- V2 validates it,
- and no apply / sequence write / session eviction / `LivePqcTrustState`
  mutation / `--p2p-trusted-root` fallback / Dummy crypto occurs.

**Verdict:** **strongest positive**. The N=3 DevNet release-binary
propagation harness (`scripts/devnet/run_089_peer_candidate_propagation_n3.sh`)
passes end-to-end. Across baseline + 4 propagation scenarios (valid
V0→V1→V2, invalid wrong-chain, duplicate, source-exclusion settle-window)
every required assertion holds:

- valid candidates rebroadcast only after validation,
- the source peer is excluded from V1's rebroadcast target set,
- invalid/duplicate candidates do not rebroadcast,
- no loop forms,
- no apply, no sequence write, no session eviction, no LivePqcTrustState
  mutation,
- no `--p2p-trusted-root` fallback,
- no active `DummySig` / `DummyKem` / `DummyAead`.

The harness is committed and repeatable; the only source change required
to produce evidence was the harness itself plus the evidence/contradiction
doc updates listed below.

## Files changed

- `scripts/devnet/run_089_peer_candidate_propagation_n3.sh` (new — N=3 DevNet harness).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_089.md` (new — this document).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_088.md` (Run 089 follow-up note appended).
- `docs/whitepaper/contradiction.md` (Run 089 narrowing of the C4 peer-candidate sub-piece).

No source changes were required to `crates/qbind-node/src/**`, the
`pqc_peer_candidate_wire` / `pqc_trust_peer_candidate` modules, or any
metrics / CLI wiring. Run 088 already provided every counter, log line,
flag, and rebroadcast/source-exclusion gate the harness needed to
observe.

## Harness design

`scripts/devnet/run_089_peer_candidate_propagation_n3.sh` (`run089`):

1. Builds (or reuses pre-built) release `qbind-node` and the three
   DevNet helpers
   (`devnet_pqc_trust_bundle_helper`, `devnet_pqc_root_helper`,
   `devnet_consensus_signer_keystore_helper`).
2. Records `sha256` and ELF `Build ID` for each release artifact (in
   `${OUTDIR}/artifact_sha256.txt` and `${OUTDIR}/artifact_build_id.txt`).
3. Mints a signed DevNet trust bundle for `N=3` validators via
   `devnet_pqc_trust_bundle_helper ${OUTDIR}/material 3 signed-devnet 1`.
4. Mints `N=3` DevNet consensus signer keystores via
   `devnet_consensus_signer_keystore_helper ${OUTDIR}/signers 3` so
   Run 033's `timeout-verification probe: active=true reason=n/a` fires
   on every node (no `DummySig` fallback).
5. Generates three Run 080 envelope JSON fixtures (`candidate_valid.json`,
   `candidate_invalid_wrong_chain.json`, `candidate_duplicate.json`)
   wrapping the same signed baseline bundle.
6. Per scenario, launches three release `qbind-node` processes
   (`v0`, `v1`, `v2`) on loopback with disjoint port slots per scenario:
   - shared baseline flags: `--env devnet`, `--network-mode p2p`,
     `--enable-p2p`, mutual-auth required, pqc-static-root,
     signed trust bundle path + signing key, per-validator leaf cert/key,
     consensus signer keystore, consensus-key trio (V0/V1/V2 each at
     stake 100), `--data-dir` per validator.
   - per-validator flags vary by scenario (publish-once on V0,
     `--p2p-trust-bundle-peer-candidate-propagation-enabled` on V1, etc.).
7. Scrapes `/metrics` from every node, polls until target metrics
   reach expected values, then fetches a final snapshot.
8. Captures `stdout` / `stderr` for every node and greps `[Run040]`,
   `Run 033`, and `peer-candidate` / `propagation_enabled` / `not-applied`
   lines into `run033_run040_lines.txt` and `peer_candidate_lines.txt`.
9. Hashes `pqc_trust_bundle_sequence.json` on every node before and
   after each scenario; asserts byte-for-byte equality.
10. Asserts the propagation / source-exclusion / no-apply / no-eviction /
    no-fallback / no-Dummy invariants for every scenario, and asserts
    the absence of the `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total`
    family (Run 088 contract).
11. Copies `summary.txt`, metrics, sequence hashes, envelopes, logs,
    and identity files into
    `docs/devnet/run_089_peer_candidate_propagation_n3/` for review.

Cluster start order (`v2 → v1 → v0` with 0.5 s spacing) gives V0 time
to dial both peers before its `publish_once` fires. Because Run 080's
`publish_once_from_config` uses `send_raw_frame_to_all_peers`, the
publish broadcast reaches **all** of V0's currently-connected peers,
i.e. typically both V1 and V2 — so V2's receive count is `1` or `2`
depending on race timing (the direct V0→V2 copy plus the V1→V2
propagation copy, the second of which is deduplicated by the receiver's
LRU). The harness asserts `V2.received_total >= 1`, `V2.validated_total ==
1`, and `V2.duplicate_total == received - 1`, while still asserting the
hard propagation evidence on V1 exactly: `propagation_attempt_total == 1`
and `propagation_sent_total == 1`. Because V2 is V1's only non-source
peer, `propagation_sent_total == 1` on V1 cryptographically proves the
V1→V2 propagation edge.

The harness deliberately does **not** wire any peer-driven live apply,
sequence write, session eviction, `activation_epoch`, fast-sync restore,
or KMS/HSM custody. It does not introduce any wire-format change.

## Run 087 safety-spec compliance mapping

| `docs/protocol/QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md` requirement | Run 089 evidence |
|---|---|
| Bounded payload | `MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES` enforced at wire decode; Run 078 tests already prove this; release binary uses the same code path. |
| Validation before rebroadcast | V1 logs `Run 088: peer-candidate validated before propagation; NOT applied; … rebroadcast_count=1; source_peer_excluded=true` (see `logs/valid_v1.stderr.log`). Invalid wrong-chain scenario shows `V1.validated_total=0`, `V1.rejected_total=1`, `V1.propagation_sent_total=0`. |
| Source-peer exclusion | `V0.received_total == 0` on every propagation scenario (`valid`, `duplicate`, `source_exclusion`). V1 only rebroadcasts to its single non-source peer (V2). |
| Duplicate suppression | Duplicate scenario shows `V1.duplicate_total=1`, `V1.propagation_sent_total=1` (only the first publish rebroadcast). |
| Rate limiting | Default `PeerCandidatePropagationConfig` rate limit holds (Run 088 unit test `run088_propagation_rate_limit_blocks_rebroadcast_after_validation` exercises the boundary; release binary reuses the same `LivePeerCandidateWireDispatcher`). |
| No loop | Source-exclusion settle scenario waits 5 s after V1 propagates; `V0.received_total` stays at `0`, `V1.propagation_sent_total` stays at `1`, `V2.propagation_sent_total` stays at `0`. |
| No apply | `qbind_p2p_pqc_trust_bundle_live_reload_apply_success_total == 0` and `qbind_p2p_pqc_trust_bundle_live_reload_apply_failure_total == 0` on every node, every scenario. The `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` family is absent from `/metrics` text (asserted by `assert_common_invariants`). |
| No sequence commit | `pqc_trust_bundle_sequence.json` byte-for-byte identical before/after each scenario on every node (`sequence/<scenario>.v{0,1,2}.{before,after}.sha256`). |
| No session eviction | `qbind_p2p_session_eviction_*` and `qbind_p2p_trust_bundle_live_reload_sessions_evicted_total` all zero on every node, every scenario. |
| Clear metrics | Run 088 counters present and incrementing as designed (see § Metrics snapshots). |

## Required release-binary scenarios

### 1. Baseline N=3 DevNet startup

Asserted on each of V0/V1/V2:

- `qbind_p2p_pqc_cert_verify_accepted_total >= 1`,
  `qbind_p2p_pqc_cert_verify_rejected_total == 0`.
- `qbind_consensus_committed_height >= 1` (consensus progresses).
- `pqc_trust_bundle_sequence.json` written by the loader (per-validator
  baseline sequence file present).
- All Run 088 propagation counters and Run 076 peer-candidate counters
  at zero (no traffic yet).
- All apply / session-eviction families at zero.
- No `--p2p-trusted-root` fallback in logs.
- No `DummySig` / `DummyKem` / `DummyAead` active in logs.

Run 033 `timeout-verification probe: active=true reason=n/a` and Run 040
`pqc_root_mode=pqc-static-root … dummy_kem_registered=false
dummy_aead_registered=false … transport_kem_suite_name=ml-kem-768
transport_aead_suite_name=chacha20-poly1305` lines emitted by every
node confirm real PQC mutual auth with no Dummy fallback (extracted into
`run033_run040_lines.txt`).

### 2. Valid V0 → V1 → V2 propagation

V0 runs `--p2p-trust-bundle-peer-candidate-wire-publish-enabled
--p2p-trust-bundle-peer-candidate-wire-publish-path candidate_valid.json
--p2p-trust-bundle-peer-candidate-wire-publish-once`. V1 runs
`--p2p-trust-bundle-peer-candidate-propagation-enabled` plus the wire
validation flag. V2 runs only the wire validation flag.

Observed metrics (`metrics/valid_*.metrics`):

| node | received | validated | rejected | duplicate | propagation_attempt | propagation_sent | sent |
|---|---|---|---|---|---|---|---|
| V0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 |
| V1 | 1 | 1 | 0 | 0 | 1 | 1 | 0 |
| V2 | 2 | 1 | 0 | 1 | 0 | 0 | 0 |

V1's log line:

> `[binary] Run 088: peer-candidate validated before propagation; NOT applied; sequence not persisted; live trust unchanged; sessions untouched; rebroadcast_count=1; source_peer_excluded=true; candidate_fp=d28da147.. sequence=1`

Sequence files byte-identical before/after on every node
(see `sequence/valid.v{0,1,2}.{before,after}.sha256`); all
`live_reload_apply_*` and `session_eviction_*` zero on every node.

### 3. Invalid wrong-chain candidate

V0 publishes `candidate_invalid_wrong_chain.json` (chain_id forced to
`0000000000000000`).

Observed metrics (`metrics/invalid_wrong_chain_*.metrics`):

| node | received | validated | rejected | propagation_sent |
|---|---|---|---|---|
| V0 | 0 | 0 | 0 | 0 |
| V1 | 1 | 0 | 1 | 0 |
| V2 | 1 | 0 | 1 | 0 |

V1's `propagation_suppressed_invalid_total == 1` confirms the propagation
gate fired closed on the validator rejection. V2 also rejected the
direct broadcast copy (received via the publish-once fan-out) and did
not rebroadcast. V1 did **not** propagate the invalid frame to V2.

### 4. Duplicate suppression

V0 publishes once, is killed, then a second V0 process is started on a
new port slot and publishes the same envelope. V1 receives both, the
validator-side LRU dedup fires on the second arrival, and V1 does not
rebroadcast a second time.

Observed metrics (`metrics/duplicate_*.metrics`):

| node | received | validated | rejected | duplicate | propagation_attempt | propagation_sent |
|---|---|---|---|---|---|---|
| V0_second | 0 | 0 | 0 | 0 | 0 | 0 |
| V1 | 2 | 1 | 0 | 1 | 1 | 1 |
| V2 | 3 | 1 | 0 | 2 | 0 | 0 |

The second V0 process never receives an echo; V1 propagated exactly
once; V2 validated exactly once and dedup-suppressed the rest.

### 5. Source exclusion (no loop, settle window)

After V1 propagates the valid candidate to V2, the harness sleeps 5 s
and re-scrapes metrics on every node. `V0.received_total` stays at `0`,
`V1.propagation_sent_total` stays at `1`, and `V2.propagation_sent_total`
stays at `0`. No loop forms, even allowing significant settle time.

Observed metrics (`metrics/source_exclusion_*.metrics`):

| node | received | validated | propagation_attempt | propagation_sent |
|---|---|---|---|---|
| V0 | 0 | 0 | 0 | 0 |
| V1 | 1 | 1 | 1 | 1 |
| V2 | 2 | 1 | 0 | 0 |

## Sequence before/after hashes

Every per-validator `pqc_trust_bundle_sequence.json` hash is byte-for-byte
identical before and after each of the four propagation scenarios:

```
valid v0 OK 0f53d951cbcfe2a7…
valid v1 OK 0f53d951cbcfe2a7…
valid v2 OK c2459de5d2a4d0e4…
invalid_wrong_chain v0 OK 0f53d951cbcfe2a7…
invalid_wrong_chain v1 OK 0f53d951cbcfe2a7…
invalid_wrong_chain v2 OK c2459de5d2a4d0e4…
duplicate v0 OK 0f53d951cbcfe2a7…
duplicate v1 OK 0f53d951cbcfe2a7…
duplicate v2 OK c2459de5d2a4d0e4…
source_exclusion v0 OK 0f53d951cbcfe2a7…
source_exclusion v1 OK 0f53d951cbcfe2a7…
source_exclusion v2 OK c2459de5d2a4d0e4…
```

(Full `.sha256` files archived under
`docs/devnet/run_089_peer_candidate_propagation_n3/sequence/`.)

## Proof live reload apply metrics remain zero

For each node in each scenario the `assert_common_invariants` shell helper
asserts that the entire live-reload apply family stays at zero:

- `qbind_p2p_trust_bundle_live_reload_trigger_total == 0`
- `qbind_p2p_trust_bundle_live_reload_apply_success_total == 0`
- `qbind_p2p_trust_bundle_live_reload_apply_failure_total == 0`
- `qbind_p2p_trust_bundle_live_reload_already_in_progress_total == 0`
- `qbind_p2p_trust_bundle_live_reload_sessions_evicted_total == 0`

Independent post-run sweep (`grep -rE … metrics/`) confirmed no
non-zero match across all 13 metric scrapes (4 scenarios × 3 nodes +
duplicate's `v0_second`).

## Proof session eviction metrics remain zero

The same `assert_common_invariants` block asserts:

- `qbind_p2p_session_eviction_attempt_total == 0`
- `qbind_p2p_session_eviction_success_total == 0`
- `qbind_p2p_session_eviction_failure_total == 0`
- `qbind_p2p_session_eviction_sessions_evicted_total == 0`

All zero across every scenario × node.

## Proof LivePqcTrustState is not mutated

Run 088 does not provide a public `swap_snapshot` metric counter, but
the indirect observables are all zero:

- No `live_reload_apply_success_total` event (mutation would route
  through `pqc_trust_reload::apply_validated_candidate` and bump that
  counter).
- No `live_reload_sessions_evicted_total` event (a successful apply
  would trigger session eviction).
- Sequence file unchanged on every node (Run 070's apply contract
  commits sequence on success).
- No `Run 070` apply log line in any node's stderr (greppable in
  `peer_candidate_lines.txt`).

The dispatcher object configured at startup has `propagation_sender =
Some(p2p_service.clone())` but **no** `LivePqcTrustState`,
`ProductionLiveTrustApplyContext`, `LiveReloadController`, or
session-evictor handle (verified by reading `crates/qbind-node/src/main.rs`
lines 2511–2654; the `set_propagation_sender` call is the only mutation
hook on the dispatcher).

## Proof no propagation loop

Across the source-exclusion settle scenario the harness waits **5 s**
after the V1→V2 propagation completes and re-scrapes every node's
metrics. The invariants that would catch a loop are:

- `V0.received_total == 0` (source exclusion holding under wall time).
- `V1.propagation_sent_total == 1` (V1 did not re-propagate the echo).
- `V2.propagation_sent_total == 0` (V2 has propagation disabled, can
  never echo).
- Receiver-side LRU dedup counters on V1 and V2 do not climb beyond
  their expected per-scenario values.

All four hold. The Run 088 design — local seen-cache (`sequence:fingerprint_prefix`),
source-peer exclusion in the target-set builder, bounded per-window rate
limit, bounded fanout, bounded raw-frame queue depth — collectively
prevents loops without requiring a TTL field on the envelope.

## Proof no active DummySig / DummyKem / DummyAead

Every node's stderr emits:

> `[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true`

And Run 033 reports `active=true reason=n/a … local_signer=loaded(backend=local-keystore-plain,…)`,
confirming the consensus signer is a real ML-DSA keystore (not a
`DummySig`). The harness greps for `DummySig|DummyKem|DummyAead|dummy_kem_registered=true|dummy_aead_registered=true`
in every node's stderr and fails closed on any hit; no hit occurred.

## Proof no --p2p-trusted-root fallback

The harness greps for
`--p2p-trusted-root.*fallback|fallback.*--p2p-trusted-root` in every
node's stderr and fails closed on any hit; no hit occurred. The
`--p2p-trusted-root` flag is **never** passed in `common_args`; only the
signed-bundle path + signing-key spec are configured.

## Binary / helper identities

| artifact | sha256 | build_id |
|---|---|---|
| `target/release/qbind-node` | `6950d3076913f8ca5492d3f7d1ed3a05202b2f6ad943fcf004adf731307c20ef` | `34221cdb03f0ebac889893c368962cf23dc16b79` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `03aabde22cfd25ad1b92de3cd22861b9a3baccb0df85e50b6a9b8f7dd5f96593` | `fbeb1490ab534e207fc212655067a66d38829b8a` |
| `target/release/examples/devnet_pqc_root_helper` | `7e8bc00c4174dfb5d5e9f82b8f5ace09b75b0b8613f64eb54410af151d62f386` | `e5e29a053fa5e3c2230b4330aab2fadb2fdcad41` |
| `target/release/examples/devnet_consensus_signer_keystore_helper` | `18f455bd0e8891381ee00dd31472beade2409d843ddae25fcf327843620d8b4c` | `ebb61100054d043ad0e0d2dc4272968641233f38` |

git commit at run time: `f8e66209522d34117a40ea56b6cca8dcbb7ede9b`.
chain_id: `51424e4444455600` (DevNet).

## Commands run

Pre-existing baseline (Run 088 already proved these green; re-run as Run
089 required-tests):

- `cargo build --release -p qbind-node --bin qbind-node` — PASS (6m52s, reused).
- `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper` — PASS (reused).
- `cargo build --release -p qbind-node --example devnet_pqc_root_helper` — PASS (reused).
- `cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper` — PASS (reused).
- `cargo test --release -p qbind-node --test run_076_pqc_peer_candidate_validation_tests` — PASS.
- `cargo test --release -p qbind-node --test run_077_binary_peer_candidate_check_tests` — PASS.
- `cargo test --release -p qbind-node --test run_078_pqc_peer_candidate_wire_tests` — PASS (19/19).
- `cargo test --release -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests` — PASS (11/11).
- `cargo test --release -p qbind-node --test run_080_pqc_peer_candidate_wire_send_tests` — PASS (3/3).
- `cargo test --release -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests` — PASS (5/5).
- `cargo test --release -p qbind-node --lib` — PASS (1063/1063).
- `cargo test --release -p qbind-net --lib` — PASS (17/17).
- `cargo test --release -p qbind-crypto --lib` — PASS (68/68).

New for Run 089:

- `scripts/devnet/run_089_peer_candidate_propagation_n3.sh` — PASS (5/5 scenarios).

The `--lib pqc_peer_candidate_wire`, `--lib pqc_trust_peer_candidate`,
`--lib metrics`, and `--lib p2p` filters from the task list are subsets
of the `--lib` full run that passed.

## Tests / evidence pass-fail status

| item | status |
|---|---|
| Run 076 validation tests | PASS |
| Run 077 binary check tests | PASS |
| Run 078 wire frame tests | PASS (19/19) |
| Run 079 live dispatch tests | PASS (11/11) |
| Run 080 wire send tests | PASS (3/3) |
| Run 088 propagation tests | PASS (5/5) |
| qbind-node lib tests | PASS (1063/1063) |
| qbind-net lib tests | PASS (17/17) |
| qbind-crypto lib tests | PASS (68/68) |
| Run 089 N=3 DevNet harness (baseline) | PASS |
| Run 089 valid V0 → V1 → V2 propagation | PASS |
| Run 089 invalid wrong-chain non-propagation | PASS |
| Run 089 duplicate suppression | PASS |
| Run 089 source-exclusion settle (no loop) | PASS |

## What was proven

On real release `qbind-node` binaries, running an N=3 DevNet over
loopback with mutual-auth PQC KEMTLS (ML-KEM-768 + ChaCha20-Poly1305 +
ML-DSA-44), real consensus signer keystores, and a signed DevNet trust
bundle:

1. The Run 088 propagation gate is honored end-to-end: a valid
   peer-candidate frame is **validated before** it is rebroadcast.
2. V1 rebroadcasts exactly once to its single non-source peer (V2):
   `propagation_attempt_total == 1`, `propagation_sent_total == 1`,
   `rebroadcast_count=1 source_peer_excluded=true` in the V1 log.
3. The source peer (V0) **never** receives its own candidate back from
   V1: `V0.received_total == 0` across `valid`, `duplicate`, and
   `source_exclusion` scenarios; no loop forms under a 5 s settle window.
4. Invalid (wrong-chain) candidates are rejected on V1 and **not**
   rebroadcast: `propagation_sent_total == 0`,
   `propagation_suppressed_invalid_total >= 1`.
5. Duplicate candidates are suppressed (validator-side LRU) and **not**
   rebroadcast a second time: `propagation_sent_total` stays at `1` even
   after two valid V0 publishers send the same envelope.
6. No node mutates `pqc_trust_bundle_sequence.json` (byte-identical
   before/after on every node in every scenario).
7. All live-reload apply, session-eviction, and `peer_candidate_applied_total`
   counters/families remain zero / absent across every node in every
   scenario.
8. No `--p2p-trusted-root` fallback fires anywhere.
9. No active `DummySig`/`DummyKem`/`DummyAead`: Run 040 reports
   `dummy_kem_registered=false`, `dummy_aead_registered=false`; Run 033
   reports `active=true reason=n/a … backend=local-keystore-plain`.
10. The N=3 cluster progresses consensus (`qbind_consensus_committed_height
    >= 1` on every node) under the propagation-enabled topology, so the
    propagation prototype does not regress C4 binary-path multi-validator
    consensus.

## What remains not solved

Run 089 is propagation-only. The following C4 / C5 items remain **OPEN**
and were intentionally **NOT** addressed:

- Peer-driven live apply (a received & validated candidate still does
  not become the live PQC trust state on any node).
- `activation_epoch` runtime source.
- KMS / HSM custody.
- In-binary / on-chain signing-key ratification.
- Production fast-sync / consensus-storage restore.
- Per-environment production trust-anchor operation.
- Timeout-verification activation, forged-traffic rejection, and
  transport-root dependency (C5).

## contradiction.md update

Yes. Run 089 narrows the C4 peer-candidate sub-piece **from "tested
propagation prototype" to "live release-binary propagation-only
evidence"**. The update preserves every previously-open C4/C5 item; it
does **not** claim full C4 or C5 closure. If a future run observes
propagation causing apply, sequence burn, session eviction,
`LivePqcTrustState` mutation, `--p2p-trusted-root` fallback, or active
Dummy crypto, that must be recorded as a contradiction/regression per
Run 087's safety contract.

## Immediate next action

Land the peer-driven **apply** path behind a hidden, disabled-by-default
flag with the same safety contract (validate → swap snapshot →
evict sessions → commit sequence), gated on consensus-ratified signing
keys and an `activation_epoch` runtime source. Until then, V2 / V1 still
discard validated candidates without mutating live trust — which is the
correct posture, but it leaves Run 087's full peer-driven trust-bundle
lifecycle open.
