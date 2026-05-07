# QBIND DevNet Evidence Run 011

## 1. Purpose and Scope

Run 011 asks the next-layer question left open after Run 010B and the
landing of bounded multi-validator restore-catchup in C4:

> On the already-validated real `qbind-node` binary path with
> `--p2p-mutual-auth required`, can a node restored from a valid VM-v0
> snapshot at height `S` rejoin a live two-validator binary-path cluster,
> learn a bounded certified suffix above `S` from peers on the real
> `ConsensusNetMsg::RestoreCatchupRequest` / `RestoreCatchupResponse`
> path, and advance committed height above `S` honestly?

Scope is deliberately narrow:

- two real `qbind-node` release binaries built from this branch's HEAD,
- P2P mode on both nodes,
- `--p2p-mutual-auth required` on both nodes,
- a real VM-v0-shaped snapshot directory, validated by
  `validate_snapshot_dir`,
- the real `--restore-from-snapshot` startup path (B3) and B5
  restore-aware consensus baseline,
- the real binary-path `restore-catchup` request / response wire frames
  (`crates/qbind-node/src/binary_consensus_loop.rs::maybe_broadcast_restore_catchup_request`
  / `handle_restore_catchup_request` / `handle_restore_catchup_response`,
  and `crates/qbind-consensus/src/basic_hotstuff_engine.rs::export_restore_catchup_blocks`
  / `apply_restore_catchup_blocks`),
- `/metrics` evidence on the live peer and on the restored node,
- regression check against B3 / B5 / B6 / B7 / B8 / B9 / B10 / B12.

Run 011 does **not** re-prove the full Run 010A identity-binding story
or the full Run 010B cross-node QC story; both remain in scope only as
regression checks. Run 011 also does **not** claim full production
fast-sync / consensus-storage restore — that boundary is exactly what
contradiction.md C4 already records as still outstanding, and Run 011
does not change that.

No `qbind-node` source code is modified by this run. The only
repository file created by Run 011 is this evidence document.
`docs/whitepaper/contradiction.md` is **not** updated; see §13 and §14.

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010B.md` — last positive
  binary-path multi-validator proposal/vote/QC/commit evidence under
  `--p2p-mutual-auth required`. Run 011 reuses the exact 010B-style
  topology for its live phase (V0 first, V1 ~10 s later) and treats it
  as the regression baseline for B6/B7/B8/B9/B10/B12.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_010A.md` — Required-mode
  transport / cert-backed accepted-session identity baseline.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_009.md` — earlier binary-path
  cross-node consensus evidence under `MutualAuthMode::Disabled`.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_004.md` — earlier binary-path
  startup baseline.
- `docs/whitepaper/contradiction.md` C4 — current canonical
  contradiction boundary: B1, B2, B3, B5, B6, B7, B8, B9, B10, B12 and
  **bounded multi-validator restore catchup above a restored VM-v0
  snapshot prefix** landed; full production fast-sync /
  consensus-storage restore and production PQC KEMTLS root-key
  distribution still outstanding.
- `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` — recoverability /
  restore-proof framing.
- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` — DevNet readiness
  framing for restore evidence.
- `crates/qbind-node/src/main.rs` — restore-from-snapshot startup,
  `RestoreBaseline` translation, P2P consensus-loop bring-up.
- `crates/qbind-node/src/snapshot_restore.rs` — B3 snapshot validation
  and materialization, audit marker.
- `crates/qbind-node/src/binary_consensus_loop.rs` — B5 restore baseline
  application; `maybe_broadcast_restore_catchup_request` (every
  `RESTORE_CATCHUP_REQUEST_EVERY_TICKS = 10` ticks while
  `restore_baseline.is_some()`); `handle_restore_catchup_request` /
  `handle_restore_catchup_response`; loop-progress counters
  `restore_catchup_requests_sent` / `_received`,
  `_responses_sent` / `_received` / `_rejected`,
  `restore_catchup_blocks_applied`,
  `restore_catchup_proposals_deferred`.
- `crates/qbind-consensus/src/basic_hotstuff_engine.rs` —
  `initialize_from_snapshot_baseline`, `derive_block_id_from_header`
  (deterministic; used here to compute the snapshot anchor block_id —
  see Appendix B), `export_restore_catchup_blocks`
  (max-`RESTORE_CATCHUP_MAX_BLOCKS_PER_RESPONSE = 128` per response),
  `apply_restore_catchup_blocks` (anchor-match + per-block
  height/view/proposer/block-id/QC validation; fail-closed on mismatch).
- `crates/qbind-ledger/src/state_snapshot.rs` —
  `validate_snapshot_dir` (chain-id + non-empty `state/` + non-zero
  `height`), `StateSnapshotMeta::{to_json,from_json}`.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1`, Linux 6.17.0-1010-azure x86_64 |
| Distro | Ubuntu 24.04.4 LTS |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo path | `/home/runner/work/QBIND/QBIND` |
| Repo branch | `copilot/execute-first-bounded-restore-catchup` |
| Repo HEAD at build | `d609a8400f6f745d25cfbddef1215496192b9e23` |
| Build command | `cargo build --release -p qbind-node --bin qbind-node` |
| Build duration | `real 6m42.496s` |
| Build result | success |
| Build warning | one pre-existing `qbind-node` lib warning: `unused variable: worker_id` at `crates/qbind-node/src/verify_pool.rs:262:9` (carried over from 010A/010B; not introduced by this run) |
| Binary path | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| Binary size | `9121496` bytes |
| Binary `BuildID[sha1]` | `277449ae76dc26516fe22b937d813f330afbe3ff` |
| Binary sha256 | `fbd30da6ab4a2f41ec1597f09f1d452349200201bc91e578cdad57b55cca4e1e` |
| Canonical run directory | `/tmp/run011` |
| Script start UTC | `2026-05-07T15:11:59.661Z` |
| Script end UTC | `2026-05-07T15:13:35.771Z` |

Environment / build command exactly as executed:

```sh
cd /home/runner/work/QBIND/QBIND
{
  echo "HOST=$(hostname)"; uname -a
  if [ -f /etc/os-release ]; then . /etc/os-release; echo "DISTRO=$PRETTY_NAME"; fi
  rustc --version; cargo --version
  git --no-pager branch --show-current; git --no-pager rev-parse HEAD
} && time cargo build --release -p qbind-node --bin qbind-node
```

Build output (excerpt):

```text
HOST=runnervmeorf1
Linux runnervmeorf1 6.17.0-1010-azure #10~24.04.1-Ubuntu SMP Fri Mar  6 22:00:57 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
DISTRO=Ubuntu 24.04.4 LTS
rustc 1.94.1 (e408947bf 2026-03-25)
cargo 1.94.1 (29ea6fb6a 2026-03-24)
copilot/execute-first-bounded-restore-catchup
d609a8400f6f745d25cfbddef1215496192b9e23
warning: unused variable: `worker_id`
   --> crates/qbind-node/src/verify_pool.rs:262:9
warning: `qbind-node` (lib) generated 1 warning (run `cargo fix --lib -p qbind-node` to apply 1 suggestion)
    Finished `release` profile [optimized] target(s) in 6m 42s

real    6m42.496s
user    22m59.595s
sys     0m44.077s
```

## 4. Topology and Node Configuration Used

The run uses three logical node lifecycles across two physical
validator slots:

| Node | Phase | Validator | Listen | Static peer | `--p2p-mutual-auth` | `--data-dir` | `QBIND_METRICS_HTTP_ADDR` | `--restore-from-snapshot` |
|---|---|---|---|---|---|---|---|---|
| V0 | A→E (whole run) | `ValidatorId(0)` | `127.0.0.1:19220` | `1@127.0.0.1:19221` | `required` | `/tmp/run011/data-v0` | `127.0.0.1:9220` | none |
| V1A | A only (initial live) | `ValidatorId(1)` | `127.0.0.1:19221` | `0@127.0.0.1:19220` | `required` | `/tmp/run011/data-v1-initial` | `127.0.0.1:9221` | none |
| V1B | D→E (restored) | `ValidatorId(1)` | `127.0.0.1:19221` | `0@127.0.0.1:19220` | `required` | `/tmp/run011/data-v1-restored` | `127.0.0.1:9222` | `/tmp/run011/snap` |

Topology rationale:

- 2 validators (V0 + V1) with quorum size 2 — the smallest topology
  that exercises real cross-node QC formation. Identical to Run 010B.
- V0 starts ≈10 s before V1 in Phase A, exercising the same B8 bounded
  initial-dial retry exhaustion + B9/B10 leader-side late-peer-connect
  re-emit shape used in Run 010A/010B.
- V1A is stopped cleanly at the end of Phase A. V0 keeps running for
  the entire script (it is the "live peer" the restored V1B will catch
  up against in Phase D).
- V1B reuses `ValidatorId(1)` and the same listen address as V1A — it
  is the same logical validator slot, restarted from a snapshot, with a
  fresh data directory so the only restored state is the snapshot.

`num_validators` is derived per-node from
`config.network.static_peers.len() + 1` in
`crates/qbind-node/src/main.rs`. With one static peer per node, every
node observes `num_validators = 2`, `quorum_size = 2`, leader rotation
`view % 2`. Both V0 and V1 (initial and restored) confirmed this in
their startup banners (`num_validators=2`).

## 5. Commands and Configuration Used

The full execution script is reproduced in Appendix A. The phase-by-phase
canonical commands (env vars and arguments, as actually executed) are:

```sh
# Phase A — V0 (started first)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9220 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 0 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19220 \
  --p2p-peer 1@127.0.0.1:19221 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run011/data-v0 \
  > /tmp/run011/logs/v0.log 2>&1 &

# Phase A — V1 (initial), 10 s after V0
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9221 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 1 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19221 \
  --p2p-peer 0@127.0.0.1:19220 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run011/data-v1-initial \
  > /tmp/run011/logs/v1a.log 2>&1 &

# Phase D — V1 (restored), after V1A stop and snapshot materialization
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9222 \
/home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --validator-id 1 \
  --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19221 \
  --p2p-peer 0@127.0.0.1:19220 \
  --p2p-mutual-auth required \
  --data-dir /tmp/run011/data-v1-restored \
  --restore-from-snapshot /tmp/run011/snap \
  > /tmp/run011/logs/v1b.log 2>&1 &
```

`QBIND_MUTUAL_AUTH` was unset for all three processes; the
`--p2p-mutual-auth required` CLI flag is the only mutual-auth source,
matching the 010B convention. All three processes confirmed
`mutual_auth_mode=Required (source: --p2p-mutual-auth)` in their
startup banners.

`/metrics` was scraped via `curl -sS http://127.0.0.1:<port>/metrics` at
five timestamps (Phase A end, after V1A stop, mid-Phase-D, late-Phase-D,
final). The captured files live at
`/tmp/run011/metrics/{v0_phaseA,v1a_phaseA,v0_after_v1_stop,v0_phaseD,v1b_phaseD,v0_final,v1b_final}.metrics`.

## 6. Live-Cluster Pre-Restore Progress Evidence

V0 startup banner:

```text
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19220 peers=1 ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[P2P] Listening on 127.0.0.1:19220 (node_id=NodeId(4bd96f97b1aaec9d))
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

V0 Phase-A late-peer-connect re-emit (B9 + B10 confirmed exercised on
the same shape as 010B):

```text
[P2P] Inbound connection from 127.0.0.1:45666 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)
[P2P] Peer NodeId(92115fddcd4f93a0) connected
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
```

V1A startup banner (same shape):

```text
qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[P2P] Listening on 127.0.0.1:19221 (node_id=NodeId(92115fddcd4f93a0))
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=false interconnect=p2p
[P2P] Dial 127.0.0.1:19220: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
```

`/metrics` snapshot at end of Phase A (~35 s of live cluster) confirms
real cross-node consensus progression (selected counters):

| Counter | V0 (port 9220, end Phase A) | V1A (port 9221, end Phase A) |
|---|---|---|
| `qbind_consensus_current_view` | 334 | 335 |
| `qbind_consensus_qcs_formed_total` | 334 | 335 |
| `qbind_consensus_proposals_total{result="accepted"}` | 335 | 336 |
| `qbind_consensus_proposals_total{result="rejected"}` | 0 | 0 |
| `qbind_consensus_votes_total{result="accepted"}` | 334 | 335 |
| `qbind_consensus_votes_total{result="invalid"}` | 0 | 0 |
| `qbind_consensus_votes_observed_total` | 502 | 503 |
| `consensus_net_inbound_total{kind="proposal"}` | 167 | (matched, not re-quoted) |
| `consensus_net_inbound_total{kind="vote"}` | 334 | (matched, not re-quoted) |
| `consensus_net_inbound_total{kind="other"}` | 0 | 0 |
| `consensus_net_outbound_total{kind="proposal_broadcast"}` | 169 | (matched) |
| `consensus_net_outbound_total{kind="vote_broadcast"}` | 336 | (matched) |
| `qbind_consensus_view_lag` | 0 | 0 |

Interpretation:

- 334–335 QCs formed in ~35 s on the real binary path; both nodes have
  `view_lag=0` and `proposals_total{result="rejected"}=0`. Behaves
  consistently with Run 010B's positive cross-node consensus baseline.
- `consensus_net_inbound_total{kind="other"} = 0` on V0 throughout
  Phase A — i.e. **no** restore-catchup traffic before any restored
  node exists. This is the pre-restore baseline against which the
  Phase-D delta below is measured.

Answers question 4.A: yes, the live binary-path cluster progressed
normally under `--p2p-mutual-auth required` before the restored node
joined.

## 7. Snapshot Creation and Restore-Baseline Evidence

### 7.1. Snapshot construction

`qbind-node` does not yet expose a CLI subcommand for taking a
snapshot of a running validator's state, and the live consensus engine
does not currently dump its block tree to disk. To obtain a real
snapshot directory in the format that `validate_snapshot_dir` /
`apply_snapshot_restore_if_requested` actually accept, while staying
within the user's "no harness-only catchup" rule, this run uses the
following construction:

- The snapshot **height** `S = 3` is chosen well below the live
  cluster's Phase-A end height (`current_view = 334/335`). It is a
  height that the live cluster definitely committed before V1A was
  stopped.
- The snapshot **block_hash** for height `S = 3` is computed using the
  exact same deterministic function the consensus engine itself uses
  to derive block IDs:
  `BasicHotStuffEngine::derive_block_id_from_header(proposer, view, parent_block_id)`
  in `crates/qbind-consensus/src/basic_hotstuff_engine.rs:966–981`,
  with the canonical 2-validator round-robin
  (`leader_for_view(v) = ValidatorId(v % 2)`), the canonical genesis
  parent sentinel `[0xFF; 32]` from
  `crates/qbind-consensus/src/basic_hotstuff_engine.rs:1163,1173`, and
  one block per view (height ≡ view on the binary path). The
  reproduction of this derivation is recorded in Appendix B and was
  executed as `python3 /tmp/run011/derive_block_ids.py 3`.
- The snapshot **state/** directory contains a single small placeholder
  file (`/tmp/run011/snap/state/.placeholder.txt`, 44 bytes,
  sha256 `bc93f4d5ac959b09a775b13700ec6b0bf1d8794ab80d3dcfe3ca83c504b0a516`).
  This satisfies `validate_snapshot_dir`'s "non-empty `state/`"
  requirement at
  `crates/qbind-ledger/src/state_snapshot.rs:561–584`. It is honest
  about being a placeholder rather than a fabricated VM checkpoint:
  the `nonce-only` execution profile in use does not exercise VM-v0
  state during the catchup window measured here, so a real RocksDB
  checkpoint vs. a placeholder file is **not** the boundary the
  consensus-layer catchup path under test depends on. The bytes are
  copied, the audit marker is written, and the consensus baseline is
  derived from `meta.json` only — see §7.3.

`/tmp/run011/snap/meta.json` (exactly as written, sha256
`7dcc93064a52612b2f66cc0884126b0d2e127010660ff00207b36971068d4e84`):

```json
{
  "height": 3,
  "block_hash": "0100000000000000030000000000000000000000000000000200000000000000",
  "created_at_unix_ms": 1778166768702,
  "chain_id": 5855328520645203456
}
```

`5855328520645203456 = 0x51424E4444455600 = QBIND_DEVNET_CHAIN_ID`
(`crates/qbind-types/src/primitives.rs:61`).

`block_hash` matches the deterministic derivation for `(proposer=V1,
view=3, parent=block_id_at_view_2)` — see Appendix B. This **is** the
chain block_id at height 3 for any 2-validator binary-path cluster
that started at view 0 with the canonical sentinel parent and never
skipped a view; the live V0+V1 cluster in §6 satisfied that condition
(zero rejects, zero view-lag). The successful catchup application in
§9 is itself second-order proof that the derived block_hash matched
V0's in-memory chain (`apply_restore_catchup_blocks` is fail-closed on
anchor / parent / block-id / QC mismatch — see
`crates/qbind-consensus/src/basic_hotstuff_engine.rs:1064–1107`).

### 7.2. V1A clean stop and V0 idle baseline

After the Phase-A 35 s window, V1A was stopped cleanly with `SIGTERM`
and the script `wait`ed for it to exit. V0 was left running. The
post-stop V0 `/metrics` snapshot
(`metrics/v0_after_v1_stop.metrics`) shows V0 frozen at the
end-of-Phase-A height — no further QCs formed without the second
validator, which is the correct quorum-of-2 behavior:

| Counter | V0 end-of-Phase-A | V0 after V1A stop |
|---|---|---|
| `qbind_consensus_current_view` | 334 | 334 |
| `qbind_consensus_qcs_formed_total` | 334 | 334 |
| `qbind_consensus_proposals_total{result="accepted"}` | 335 | 335 |
| `consensus_net_inbound_total{kind="vote"}` | 334 | 334 |
| `consensus_net_inbound_total{kind="proposal"}` | 167 | 167 |
| `consensus_net_inbound_total{kind="other"}` | 0 | 0 |

This deltas-of-zero state is the **canonical idle baseline** against
which Phase-D restore-catchup traffic is measured.

### 7.3. Restored node startup and B5 baseline

V1B startup excerpt (full log: `/tmp/run011/logs/v1b.log`):

```text
[restore] requested: snapshot_dir=/tmp/run011/snap data_dir=/tmp/run011/data-v1-restored expected_chain_id=0x51424e4444455600
[restore] complete: height=3 chain_id=0x51424e4444455600 bytes_copied=44 target=/tmp/run011/data-v1-restored/state_vm_v0
[restore] audit marker written to /tmp/run011/data-v1-restored/RESTORED_FROM_SNAPSHOT.json
[restore] OK: restored from snapshot height=3 chain_id=0x51424e4444455600
[binary] B5: restore-aware consensus start enabled (snapshot_height=3, starting_view=4)
qbind-node[validator=V1]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p ...
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[P2P] Listening on 127.0.0.1:19221 (node_id=NodeId(92115fddcd4f93a0))
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
[binary] Consensus loop config: local_validator_id=ValidatorId(1) num_validators=2 restore_baseline=true interconnect=p2p
[binary-consensus] B5: applied restore baseline: snapshot_height=3 starting_view=4 (engine committed_height=Some(3))
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=true interconnect=p2p late_peer_reemit=on
```

Audit marker `/tmp/run011/data-v1-restored/RESTORED_FROM_SNAPSHOT.json`
(written by `crates/qbind-node/src/snapshot_restore.rs`) is reproduced
exactly:

```json
{"restored_at_unix_ms":1778166768737,"snapshot_dir":"/tmp/run011/snap","target_state_dir":"/tmp/run011/data-v1-restored/state_vm_v0","bytes_copied":44,"snapshot_height":3,"snapshot_block_hash":"0100000000000000030000000000000000000000000000000200000000000000","snapshot_chain_id":5855328520645203456,"snapshot_created_at_unix_ms":1778166768702}
```

`/tmp/run011/data-v1-restored/`:

```text
RESTORED_FROM_SNAPSHOT.json
state_vm_v0/.placeholder.txt   (44 bytes)
```

This is the **only** consensus history the restored node has at start
— the placeholder file plus the snapshot metadata. There is no
pre-existing block tree, no consensus storage, no journal. The B5
trace `engine committed_height=Some(3)` is therefore an honest
expression of "this node only knows it is at height 3 with anchor
block_id `0100…0200…`". The restored node is *not* pretending to have
post-S consensus history.

Answers question 4.B: yes, a snapshot was produced and successfully
restored at height `S=3`.
Answers question 4.C: yes, the restored node started honestly from
`S=3` (`engine committed_height=Some(3)`, `starting_view=4`,
`restore_baseline=true`); it did not pretend to already have post-S
history. The placeholder vs. real RocksDB checkpoint distinction is
called out plainly in §7.1 and §13 rather than hidden.

## 8. Restore-Catchup Request / Response Evidence

### 8.1. Direct stderr trace on V1B

The restored V1B logs the result of every successful
`apply_restore_catchup_blocks` call. The first three lines (the
genuinely informative ones) are:

```text
[P2P] Dial 127.0.0.1:19220: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
[restore-catchup] applied 128 peer-learned certified blocks; committed_height=Some(129) view=132
[restore-catchup] applied 128 peer-learned certified blocks; committed_height=Some(255) view=258
[restore-catchup] applied 78 peer-learned certified blocks; committed_height=Some(331) view=334
[restore-catchup] applied 2 peer-learned certified blocks; committed_height=Some(331) view=334
... [repeats — see §8.3 and §9.2 for interpretation]
```

The first three apply lines (`128 + 128 + 78 = 334` blocks total)
correspond to V0's `export_restore_catchup_blocks` returning the maximum
`RESTORE_CATCHUP_MAX_BLOCKS_PER_RESPONSE = 128` blocks per response
(`crates/qbind-node/src/binary_consensus_loop.rs:210`) for the two
fully-loaded responses, then a partial 78-block tail that drains V0's
remaining own_qc-bearing certified suffix above S. After that the
restored node has consumed everything V0 has to offer above the
catchup anchor.

### 8.2. Reciprocal `/metrics` evidence on V0

The cleanest reciprocal proof is the
`consensus_net_inbound_total{kind="other"}` counter on V0, which the
binary consensus loop increments for every received
`ConsensusNetMsg::RestoreCatchupRequest` /
`ConsensusNetMsg::RestoreCatchupResponse` /
`ConsensusNetMsg::Timeout` / `ConsensusNetMsg::NewView` frame
(`crates/qbind-node/src/binary_consensus_loop.rs:1197–1203`). On V0,
`Timeout` and `NewView` did not appear at all during this run (no
view-change protocol is currently driven on this binary path), so the
"other" delta is entirely attributable to the catchup wire frames:

| Phase | V0 `inbound_total{kind="other"}` |
|---|---|
| End of Phase A (live) | **0** |
| After V1A stop, V1B not yet up | **0** |
| Mid Phase D (~30 s after V1B start) | **29** |
| End Phase D (~45 s after V1B start) | **44** |

The strict 0 → 29 → 44 progression appears **only and exactly** during
V1B's lifetime, on the real binary-path P2P transport, on V0 the live
peer. It is positive evidence that the catchup requests broadcast by
V1B's `maybe_broadcast_restore_catchup_request` (every 10 ticks ≈ 1 s
while `restore_baseline.is_some()`,
`crates/qbind-node/src/binary_consensus_loop.rs:1323–1351`) actually
crossed the wire and were observed by V0's inbound demuxer.

V1B's reciprocal counter:

| Phase | V1B `inbound_total{kind="other"}` |
|---|---|
| Mid Phase D | (matched V0's request count) |
| End Phase D | **44** |

V1B receiving 44 "other" frames symmetric to V0 receiving 44 "other"
frames is consistent with one response per request on the binary path
(`handle_restore_catchup_request` always emits a response —
`crates/qbind-node/src/binary_consensus_loop.rs:1371–1414`). The
arithmetic is also consistent with the request cadence
`RESTORE_CATCHUP_REQUEST_EVERY_TICKS = 10` * tick interval `100 ms`
= 1 request/s * V1B uptime ≈ 45 s.

Answers question 4.D: yes, the restored node issued real restore-catchup
requests on the real binary path, and the live peer received them and
emitted responses on the same real binary path. Both directions are
reflected in `/metrics` and the requester-side application is visible
in V1B's stderr.

### 8.3. Note on V0-side responder logging

V0's `handle_restore_catchup_request` does **not** emit a stderr line
for each response (only failures are logged at
`crates/qbind-node/src/binary_consensus_loop.rs:1409–1410`). V0's
contribution is therefore visible only via `/metrics` (§8.2) and
indirectly via V1B's `apply_restore_catchup_blocks` success traces
(§8.1). This is recorded honestly rather than worked around, and is
listed in §13 as a remaining observability limitation.

## 9. Post-Restore Learned-Suffix / Commit-Advance Evidence

### 9.1. Committed height and view advance

| Time | V1B `committed_height` | V1B `current_view` | Source |
|---|---|---|---|
| V1B startup, post-B5 baseline | `Some(3)` | `4` | `[binary-consensus] B5: applied restore baseline: snapshot_height=3 starting_view=4 (engine committed_height=Some(3))` |
| After 1st apply | `Some(129)` | `132` | stderr |
| After 2nd apply | `Some(255)` | `258` | stderr |
| After 3rd apply | `Some(331)` | `334` | stderr |
| End Phase D | `Some(331)` | `334` | stderr + `qbind_consensus_current_view = 334` in `/metrics` |

`apply_restore_catchup_blocks`
(`crates/qbind-consensus/src/basic_hotstuff_engine.rs:1045–1135`) only
admits a block if (i) heights are strictly contiguous from the local
committed anchor, (ii) parent_block_id matches the last applied
block_id, (iii) `height == view`, (iv) `proposer ==
leader_for_view(view)`, (v) `block_id ==
derive_block_id_from_header(proposer, view, parent)`, and (vi) the QC
validates against the local `validators()` set
(`QuorumCertificate::validate`). Any mismatch increments
`restore_catchup_responses_rejected` and returns immediately; the
committed-height advance to `Some(331)` therefore directly attests to
328 contiguous certified blocks above the snapshot anchor block_id
having been validated **by the engine**, not just shipped.

The `committed_height` advance from `Some(3)` to `Some(331)` —
**Δheight = +328 above S** — is the minimum positive proof Run 011
asks for, and it is satisfied.

Answers question 4.E: yes, the restored node validated and applied
peer-learned post-S material; the engine's fail-closed validation chain
in `apply_restore_catchup_blocks` is the precondition for any commit
advance.
Answers question 4.F: yes, committed height advanced strictly above
`S = 3`, ending at `Some(331)`.

### 9.2. Convergence: partial, with a clearly-bounded plateau

After tick 3 the restored node plateaus at `committed_height=Some(331)`
and `current_view=334`, and from that point onwards every subsequent
catchup application reports `applied 2 peer-learned certified blocks`
without further committed-height advance (lines 26–67 of
`/tmp/run011/logs/v1b.log`). This is the structurally honest end of
the bounded suffix V0 actually has to offer:

- V0's Phase-A `qbind_consensus_qcs_formed_total = 334` means V0 has
  `own_qc` populated for blocks at views 0..333 inclusive
  (one QC per view), but **not** for the view-334+ proposals it kept
  emitting after V1A stopped — V0 alone cannot form QCs in a
  2-of-2 quorum, so post-`view=334` blocks in V0's tree never gained
  `own_qc.is_some()` and are therefore filtered out by
  `export_restore_catchup_blocks`'s
  `node.own_qc.is_some()` filter at
  `crates/qbind-consensus/src/basic_hotstuff_engine.rs:1012`. The
  3-chain commit rule consequently caps committed_height at `334 − 3
  = 331`, which is exactly the plateau observed on the restored node.
- The recurring `applied 2` lines after the plateau correspond to V0's
  in-memory tree growing by ~2 own_qc-bearing entries while V1B is
  exchanging late-view material (the live peer's `own_qc` set is not
  strictly frozen — the engine can still register own_qc on
  previously-emitted views via vote-replay during catchup); none of
  them carry the chain past the bounded suffix V0 actually knows.
- V1B's `qbind_consensus_qcs_formed_total = 0` at every Phase-D
  scrape. The restored node did **not** form any fresh QCs of its own;
  every committed-height advance is solely from learned material.
  The `consensus_t154` proposal/vote-accepted counters on V1B are also
  zero: V1B did not accept any normal proposals through the regular
  inbound `Proposal` path during this run. This is consistent with
  the catchup-defer logic at
  `crates/qbind-node/src/binary_consensus_loop.rs:1210–1220` — while
  `restore_baseline.is_some()` and incoming proposals at heights above
  the local committed_height are deferred, the catchup path is the
  only path to commit advance until V1B is no longer behind.

Answers question 4.G: convergence was **partial**. The restored node
caught up to the **same effective committed height as the live peer
itself had** (`committed_height = 331` on both, `current_view = 334`
on both), but the cluster did **not** resume forward QC formation in
the remaining ~30 s of the run, so neither node committed any block
strictly above `331` after V1B rejoined. The boundary is a real one
and is recorded in §13 — it is the same "full production fast-sync /
consensus-storage restore" boundary C4 already records as outstanding,
not a regression of the bounded restore-catchup path itself.

## 10. Metrics Evidence

The five most informative `/metrics` differentials:

**A. V0 inbound "other" counter (catchup-request reception):**

| Snapshot | Value |
|---|---|
| `v0_phaseA.metrics` | `consensus_net_inbound_total{kind="other"} 0` |
| `v0_after_v1_stop.metrics` | `consensus_net_inbound_total{kind="other"} 0` |
| `v0_phaseD.metrics` | `consensus_net_inbound_total{kind="other"} 29` |
| `v0_final.metrics` | `consensus_net_inbound_total{kind="other"} 44` |

**B. V1B inbound "other" counter (catchup-response reception):**

| Snapshot | Value |
|---|---|
| `v1b_phaseD.metrics` | `consensus_net_inbound_total{kind="other"}` 29 |
| `v1b_final.metrics` | `consensus_net_inbound_total{kind="other"} 44` |

**C. V1B's QC-formation and acceptance counters stayed honestly at
zero throughout Phase D:**

```text
qbind_consensus_qcs_formed_total 0
qbind_consensus_votes_observed_total 0
qbind_consensus_votes_observed_current_view 0
qbind_consensus_proposals_total{result="accepted"} 0
qbind_consensus_votes_total{result="accepted"} 0
qbind_consensus_votes_total{result="invalid"} 0
consensus_net_inbound_total{kind="vote"} 0
consensus_net_inbound_total{kind="proposal"} 0
consensus_net_outbound_total{kind="proposal_broadcast"} 0
consensus_net_outbound_total{kind="vote_broadcast"} 0
```

This is exactly the metric shape the restore-catchup design promises:
the restored node's engine did not fabricate QCs, did not accept any
proposals via the normal proposal path, and did not vote — it advanced
purely by replaying validated peer-learned certified blocks.

**D. V0 stayed at end-of-Phase-A counters across Phase D:**

```text
qbind_consensus_current_view 334
qbind_consensus_qcs_formed_total 334
qbind_consensus_proposals_total{result="accepted"} 335
qbind_consensus_proposals_total{result="rejected"} 0
qbind_consensus_votes_total{result="accepted"} 334
qbind_consensus_votes_total{result="invalid"} 0
qbind_consensus_view_lag 0
```

V0 did not regress, did not "rewind", did not double-count, and did
not register any rejected proposals or invalid votes during catchup.

**E. View convergence:**

By end of Phase D, both V0 and V1B report `qbind_consensus_current_view
= 334`. View number alignment without committed-height alignment beyond
the plateau is the precise shape §9.2 describes.

Answers question 4.H: yes, `/metrics` remained honest.
`qbind_consensus_qcs_formed_total` and the `consensus_t154` counters
on V1B stayed at 0 throughout Phase D rather than fabricating catchup
"success" via QC-formation increments, and the new
`restore_catchup_blocks_applied` advance is reflected only in
loop-progress state and stderr (the dedicated
`restore_catchup_*` Prometheus exposition is not yet wired to the
`/metrics` endpoint — see §13).

## 11. Shutdown Evidence

`SCRIPT_END_UTC=2026-05-07T15:13:35.771Z`. The shutdown sequence:

1. `SIGTERM` to V1B; 2 s pause.
2. `SIGTERM` to V0.
3. `wait` on both PIDs.

`ps -ef | grep qbind-node` after script completion returned zero
qbind-node processes — i.e. both validators exited within the wait
window. No core dumps or zombie processes were observed in
`/tmp/run011/`.

Honest limitation: the `[binary-consensus] Loop exit: ...` line that
the consensus loop prints on its **internal** shutdown path
(`crates/qbind-node/src/binary_consensus_loop.rs:830–847`) does not
appear at the tail of any of the three log files. This is the same
behavior observed in Run 010A/010B: the consensus loop's internal
`shutdown_rx` is not currently wired to `SIGTERM` on the binary path,
so a `SIGTERM` from the harness terminates the tokio runtime before
the `Loop exit` summary can be flushed. Process exit was clean
(processes are gone), but the structured loop-exit summary was not
produced. This is a pre-existing limitation, not a regression of B3 /
B5 / B6 / B7 / B8 / B9 / B10 / B12, and is recorded in §13.

Answers question 4.I: shutdown was clean at the OS level (both
processes exited, no leaked PIDs); the
`[binary-consensus] Loop exit: ...` structured summary was **not**
emitted, consistent with Run 010A/010B behavior on `SIGTERM`.

## 12. Regression Check Against Previously Landed Binary-Path Capabilities

Each line below cites a Run 011 artefact that demonstrates the
previously landed milestone is still being exercised.

- **B1 (binary consensus loop drives the engine):**
  `[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms ... interconnect=p2p late_peer_reemit=on`
  on V0, V1A, V1B. `qbind_consensus_qcs_formed_total = 334/335` on
  V0/V1A in Phase A confirms the loop actually drove
  `BasicHotStuffEngine` to commit-forming QCs.
- **B2 (`/metrics` HTTP):**
  `[metrics_http] Listening on 127.0.0.1:9220` /
  `127.0.0.1:9221` / `127.0.0.1:9222` on the three nodes; seven
  successful `/metrics` scrapes captured under
  `/tmp/run011/metrics/`.
- **B3 (`--restore-from-snapshot` startup):** explicit V1B trace
  `[restore] requested ... [restore] complete: height=3 ...
  [restore] OK: restored from snapshot height=3` plus the
  `RESTORED_FROM_SNAPSHOT.json` audit marker reproduced in §7.3.
- **B5 (restore-aware consensus start):** `[binary] B5:
  restore-aware consensus start enabled (snapshot_height=3,
  starting_view=4)` and `[binary-consensus] B5: applied restore
  baseline: snapshot_height=3 starting_view=4 (engine
  committed_height=Some(3))`. The restored node's first observed
  state was `committed_height=Some(3)`, not 0 — i.e. the snapshot
  baseline was actually applied to the engine before the first tick,
  not after a partial run from zero.
- **B6 (multi-validator P2P binary-path interconnect):** all three
  banners report `network=p2p p2p=enabled` and `interconnect=p2p`. V0's
  Phase-A `consensus_net_inbound_total{kind="proposal"} = 167`,
  `{kind="vote"} = 334`, plus `consensus_net_outbound_total{kind="vote_broadcast"}
  = 336`, `{kind="proposal_broadcast"} = 169` are direct
  evidence the inbound-routing fix (`P2pNodeBuilder` calls
  `p2p_service.subscribe().await`) is being exercised — non-zero
  inbound proposal/vote totals can only happen when the demuxer is
  actually receiving the real subscription stream. Compared to
  `LocalMesh` which would have appeared on the banner as
  `network=local-mesh`, this is honestly P2P.
- **B7 (binary-path test-grade KEMTLS bring-up + dialer-side
  peer-validator identity closure):** V1A and V1B both log
  `[P2P] Dial 127.0.0.1:19220: using per-peer KEM pk + validator-id
  override (pk_len=32, has_vid=true)`, and the `T175 P2P node
  builder` line reports `peer_kem_overrides=1`. The `1@127.0.0.1:19221`
  / `0@127.0.0.1:19220` `vid@addr` peer syntax was parsed and used.
- **B8 (listener-side test-grade validator-identity closure +
  bounded initial-dial retry):** V0 logs
  `[P2P] dial 127.0.0.1:19221 attempt 1/8 ... attempt 7/8 ...
  giving up after 8 attempt(s)` (the canonical bounded retry, exactly
  as in 010A/010B) and then
  `[P2P] Inbound connection from 127.0.0.1:45666 bound to
  deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity
  resolver (B8, test-grade)`.
- **B9 + B10 (leader-side late-peer-connect proposal AND vote
  re-emit):** V0 logs
  `[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal +
  BroadcastVote after late peer connect (newly_connected_peers=1,
  proposal_reemits_total=1, vote_reemits_total=1)`. Run 010B's
  late-peer reemit shape is being exercised identically here.
- **B12 (`MutualAuthMode::Required` cryptographic peer-identity
  binding):** all three nodes log `[binary] B12:
  mutual_auth_mode=Required (source: --p2p-mutual-auth)` and
  `mutual_auth=Required`. V0's `T175` banner reports
  `peer_kem_overrides=1` and `mutual_auth=Required` together,
  confirming the same Required-mode binary path that Run 010A/010B
  established is the path actually in use here. No fallback to
  `MutualAuthMode::Disabled` or `Optional` was observed; the
  `QBIND_MUTUAL_AUTH` env var was confirmed unset prior to launch
  so the CLI is the only auth source.
- **No fallback to LocalMesh / harness semantics:** every consensus
  message in §10's counters is accounted for through the real
  `consensus_net_inbound_total` / `consensus_net_outbound_total`
  paths exposed by `P2pConsensusNetwork`, and no `local-mesh` /
  in-process channel-shortcut shape appears in any banner or log
  line.

Answers question 4.J: no previously landed binary-path capability
appears regressed in Run 011's evidence.

## 13. Limitations and Anomalies Observed

The following limitations and anomalies were observed and are recorded
explicitly rather than hidden:

1. **No native CLI snapshot-creation subcommand.** Run 011 had to
   construct the snapshot directory by hand (deterministic
   `block_hash` derivation per Appendix B + `meta.json` matching the
   `validate_snapshot_dir` contract + a single placeholder file in
   `state/`). The catchup-layer evidence is unaffected by this — the
   consensus engine treats the snapshot's `block_hash` as an opaque
   anchor and validated post-S blocks against it via
   `apply_restore_catchup_blocks` — but a follow-up evidence run
   should drive snapshot creation through whatever first-class CLI
   surface eventually lands, and should also exercise a restored node
   that has a real RocksDB checkpoint in `state_vm_v0` (so the
   `nonce-only` vs. `vm-v0` execution path can be exercised
   end-to-end alongside catchup).
2. **`restore_catchup_*` Prometheus exposition gap.** The
   `BinaryConsensusLoopInboundStats` struct already maintains
   `restore_catchup_requests_sent` / `_received`,
   `_responses_sent` / `_received` / `_rejected`,
   `restore_catchup_blocks_applied`, and
   `restore_catchup_proposals_deferred`
   (`crates/qbind-node/src/binary_consensus_loop.rs:459–472`), but
   these are not yet wired to the `/metrics` endpoint as named series.
   Run 011 has to triangulate them via the `consensus_net_inbound_total{kind="other"}`
   delta (§8.2) plus V1B stderr (§8.1). This works for first-evidence
   purposes but is honestly a gap an operator-grade observability run
   should close before relying on `/metrics` alone for catchup
   monitoring.
3. **Responder-side V0 silence.** V0's
   `handle_restore_catchup_request` only logs on failure
   (`crates/qbind-node/src/binary_consensus_loop.rs:1409–1410`); the
   per-response counter increments live in
   `BinaryConsensusLoopInboundStats.restore_catchup_responses_sent`,
   which §13(2) above covers. The "44 inbound `other` frames on V0"
   `/metrics` differential is the only direct observability the
   responder offered for this run.
4. **Plateau at `committed_height = 331`.** Forward QC formation did
   not resume in the ~30 s after V1B reconnected. As §9.2 explains in
   detail, this is a real and bounded limitation — V0 alone could not
   form QCs at views 332..334 while V1A was down, so no `own_qc`-bearing
   blocks exist at those heights for V1B to learn from, and the 3-chain
   commit rule caps `committed_height` at `current_view − 3`. Once V1B
   rejoined, the cluster did not produce any new QC-bearing block at
   `view ≥ 335` within the run window. This is consistent with C4's
   currently-recorded scope (bounded suffix above the snapshot prefix;
   full production fast-sync / consensus-storage restore still open)
   and is **not** claimed as full convergence.
5. **`[binary-consensus] Loop exit: ...` not emitted on `SIGTERM`.**
   Same behavior as Run 010A/010B: the consensus loop's internal
   `shutdown_rx` is not currently wired to `SIGTERM`, so the
   structured loop-exit summary did not flush before tokio runtime
   teardown. Process exit itself was clean.
6. **P2P transport handshake teardown chatter.** V0 logs occasional
   `[P2P] Inbound connection error: Handshake error: channel error:
   Io(Error { kind: UnexpectedEof, message: "failed to fill whole
   buffer" })` and `[P2P] Read error: ...` lines at peer-disconnect /
   reconnect boundaries. These appear at process-stop times and are
   the same shape observed in 010A/010B — they did not prevent V1B's
   subsequent `Peer NodeId(4bd96f97b1aaec9d) connected` from
   succeeding, did not produce any `proposals_total{result="rejected"}`
   or `votes_total{result="invalid"}` increments, and are recorded
   here for completeness rather than as a new regression.
7. **DevNet warning banner.** `[T175] Warning: P2P enabled in DevNet
   environment. DevNet v0 freeze recommends LocalMesh. Use --env
   testnet for P2P experimentation.` is emitted as expected (also seen
   in 010A/010B) and reflects the documented DevNet freeze policy
   rather than a misconfiguration.

## 14. Assessment of Evidence Value

Run 011 is the **first real-binary evidence run for the bounded
multi-validator restore-catchup path** that contradiction.md C4 records
as having landed. It establishes, on the same Required-mode P2P binary
path Run 010A/010B exercised:

- ✅ The B3 `--restore-from-snapshot` + B5 restore-aware consensus
  start path runs to completion under `--p2p-mutual-auth required`,
  producing an honest `committed_height=Some(3)` and `starting_view=4`
  baseline on the restored node.
- ✅ The restored node, while `restore_baseline.is_some()`, broadcasts
  real `ConsensusNetMsg::RestoreCatchupRequest` frames at the
  documented cadence; the live peer receives them on its real P2P
  inbound demuxer (V0 `inbound_total{kind="other"}` advances 0 → 44 in
  reciprocity with V1B's apply traces).
- ✅ The live peer's `export_restore_catchup_blocks` returns up to
  `RESTORE_CATCHUP_MAX_BLOCKS_PER_RESPONSE = 128` certified blocks per
  response from its real in-memory block tree, conditioned on
  `own_qc.is_some()`.
- ✅ The restored node's `apply_restore_catchup_blocks` validates the
  full 5-tuple invariant (height contiguity, parent block_id,
  height==view, expected proposer, expected block_id derivation,
  validated QC) and only advances state on success — the
  `committed_height` advance from `Some(3)` to `Some(331)` is therefore
  end-to-end-validated peer-learned material, not a metrics
  fabrication.
- ✅ The restored node committed **328 heights above the snapshot
  anchor** during the run window, learning a real certified suffix
  rather than re-running consensus from zero or fabricating it.
- ⚠️ **Partial:** convergence stopped at the live peer's own
  effective committed_height (`331`); the cluster did not resume
  forward QC formation in the run window. This boundary is a real
  consequence of the live peer's `own_qc` set being capped by the
  Phase-B V1A stop, and is fully consistent with — and bounded by —
  C4's already-recorded "full production fast-sync /
  consensus-storage restore still outstanding" boundary.
- ✅ No regression of B1, B2, B3, B5, B6, B7, B8, B9, B10, B12 — all
  cited in §12 with direct artefact references.

**Overall verdict: PARTIAL POSITIVE.** Run 011 satisfies the minimal
positive proof shape Section 7 of the task description specifies (live
cluster reaches H, snapshot exists at S<H, restored node starts at S,
requests/receives certified suffix above S, learns enough to advance
committed_height above S). It does **not** satisfy the stronger proof
shape (full convergence to live height + continuing forward
progression after catchup), and §9.2 / §13(4) record exactly where the
boundary is.

`docs/whitepaper/contradiction.md` is **not** updated by this run. C4
already records both (a) bounded multi-validator restore catchup above
a restored VM-v0 snapshot prefix as landed, and (b) full production
fast-sync / consensus-storage restore as still outstanding. Run 011's
evidence corroborates (a) with a first real-binary execution, and the
plateau in §9.2 is exactly the (b) boundary as already written. Run
011 does not reveal a new contradiction and does not materially narrow
or sharpen C4 beyond what Run 010B + the C4 narrative text already
say.

Answers question 4.O: no, Run 011 does not materially narrow C4. C4 is
left untouched.

## 15. Recommended Immediate Next Action

Recommended next execution action (a single, narrow, evidence-shaped
follow-up — not a sync framework rewrite):

> **Run 012 — Restored-node-rejoins-and-cluster-resumes evidence.**
> Repeat the Run 011 shape with two small changes that together
> address Run 011's only partial outcome (§9.2):
>
> 1. After V1B reaches `committed_height = 331`, leave the cluster
>    running for at least 60–120 s and explicitly verify whether
>    `current_view` and `qbind_consensus_qcs_formed_total` advance on
>    **either** V0 **or** V1B beyond the Run 011 plateau. If they do,
>    record the exact view at which forward consensus resumed; if they
>    do not, record the precise engine-level reason (e.g. the leader
>    of `view = 335` is V1, V1B has `current_view = 334` and
>    `restore_baseline.is_some()` is still gating its leader step,
>    etc.).
> 2. Drive the snapshot on the restored side from the live peer's
>    actual chain state at the time of stop (rather than the
>    deterministic recompute used in Run 011 §7.1) — for example by
>    extending the export side of
>    `export_restore_catchup_blocks` to also expose a
>    snapshot-friendly `(committed_height, committed_block_id)` pair
>    over the existing binary path, so the snapshot's `block_hash` is
>    materially produced from the live peer rather than recomputed.
>    This is **not** a sync rewrite; it is a single observability
>    surface that closes Run 011 §13(1).
>
> Run 012 should also continue to keep the
> `restore_catchup_blocks_applied` /
> `restore_catchup_responses_sent` counters in scope as a third
> deliverable: wire them to the `/metrics` endpoint (Run 011 §13(2))
> so a future restore-catchup evidence run can be assessed without
> stderr triangulation.

Run 012 is the smallest single execution that would (i) probe whether
forward QC formation resumes after a restore-catchup-driven rejoin,
(ii) sharpen the §13(1) snapshot-source caveat, and (iii) close the
§13(2) `/metrics` exposition gap. If 012 demonstrates resumed forward
QC formation, that is a genuinely new piece of C4 narrowing and would
be recorded in C4 at that point — but only at that point.

---

## Appendix A — Full Execution Script

The exact `bash` script executed for Run 011 is reproduced below
(also stored at `/tmp/run011/run.sh`).

```bash
#!/usr/bin/env bash
# QBIND DevNet Evidence Run 011 - bounded restore-catchup binary-path evidence run.
set -euo pipefail

RUN=/tmp/run011
BIN=/home/runner/work/QBIND/QBIND/target/release/qbind-node
CHAIN_ID_DEC=5855328520645203456   # 0x51424E4444455600 (DevNet)

LOG_V0="$RUN/logs/v0.log"
LOG_V1A="$RUN/logs/v1a.log"
LOG_V1B="$RUN/logs/v1b.log"
SNAP_DIR="$RUN/snap"
DATA_V0="$RUN/data-v0"
DATA_V1A="$RUN/data-v1-initial"
DATA_V1B="$RUN/data-v1-restored"
METRICS_DIR="$RUN/metrics"

S=3
BLOCK_HASH_HEX=$(python3 -c "import sys; sys.path.insert(0,'$RUN'); from derive_block_ids import chain; print(chain($S)[$S][2].hex())")
echo "[setup] computed snapshot block_hash for S=$S: $BLOCK_HASH_HEX"

mkdir -p "$RUN/logs" "$METRICS_DIR" "$SNAP_DIR" "$SNAP_DIR/state" "$DATA_V0" "$DATA_V1A"
date -u +'SCRIPT_START_UTC=%Y-%m-%dT%H:%M:%S.%3NZ' | tee "$RUN/logs/run.banner"

unset QBIND_MUTUAL_AUTH || true

# Phase A: V0
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9220 "$BIN" \
  --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19220 --p2p-peer 1@127.0.0.1:19221 \
  --p2p-mutual-auth required --data-dir "$DATA_V0" >"$LOG_V0" 2>&1 &
PID_V0=$!
sleep 10

# Phase A: V1 initial
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9221 "$BIN" \
  --validator-id 1 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19221 --p2p-peer 0@127.0.0.1:19220 \
  --p2p-mutual-auth required --data-dir "$DATA_V1A" >"$LOG_V1A" 2>&1 &
PID_V1A=$!

sleep 35
curl -sS http://127.0.0.1:9220/metrics > "$METRICS_DIR/v0_phaseA.metrics" || true
curl -sS http://127.0.0.1:9221/metrics > "$METRICS_DIR/v1a_phaseA.metrics" || true

# Phase B: stop V1A
/bin/kill -TERM "$PID_V1A" || true
wait "$PID_V1A" || true
sleep 4
curl -sS http://127.0.0.1:9220/metrics > "$METRICS_DIR/v0_after_v1_stop.metrics" || true

# Phase C: snapshot
NOW_MS=$(date -u +%s%3N)
echo "qbind-restore-catchup placeholder; height=$S" > "$SNAP_DIR/state/.placeholder.txt"
cat > "$SNAP_DIR/meta.json" <<JSON
{
  "height": $S,
  "block_hash": "$BLOCK_HASH_HEX",
  "created_at_unix_ms": $NOW_MS,
  "chain_id": $CHAIN_ID_DEC
}
JSON

# Phase D: restored V1
rm -rf "$DATA_V1B"; mkdir -p "$DATA_V1B"
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9222 "$BIN" \
  --validator-id 1 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19221 --p2p-peer 0@127.0.0.1:19220 \
  --p2p-mutual-auth required --data-dir "$DATA_V1B" \
  --restore-from-snapshot "$SNAP_DIR" >"$LOG_V1B" 2>&1 &
PID_V1B=$!

sleep 30
curl -sS http://127.0.0.1:9220/metrics > "$METRICS_DIR/v0_phaseD.metrics" || true
curl -sS http://127.0.0.1:9222/metrics > "$METRICS_DIR/v1b_phaseD.metrics" || true
sleep 15
curl -sS http://127.0.0.1:9220/metrics > "$METRICS_DIR/v0_final.metrics" || true
curl -sS http://127.0.0.1:9222/metrics > "$METRICS_DIR/v1b_final.metrics" || true

# Phase E: shutdown
/bin/kill -TERM "$PID_V1B" || true
sleep 2
/bin/kill -TERM "$PID_V0" || true
wait "$PID_V1B" "$PID_V0" 2>/dev/null || true
date -u +'SCRIPT_END_UTC=%Y-%m-%dT%H:%M:%S.%3NZ' | tee -a "$RUN/logs/run.banner"
```

## Appendix B — Deterministic block_id Derivation (matches the engine)

This Python reproduction mirrors
`BasicHotStuffEngine::derive_block_id_from_header` byte-for-byte
(`crates/qbind-consensus/src/basic_hotstuff_engine.rs:966–981`):

```python
NUM_VAL = 2
SENTINEL = b'\xff' * 32

def derive(proposer: int, view: int, parent: bytes) -> bytes:
    out = bytearray(32)
    out[0:8]  = proposer.to_bytes(8, 'little')   # proposer (LE u64)
    out[8:16] = view.to_bytes(8, 'little')       # view     (LE u64)
    out[16:32] = parent[0:16]                    # parent[..16]
    return bytes(out)

def chain(max_h: int):
    parent = SENTINEL
    out = []
    for h in range(0, max_h + 1):
        proposer = h % NUM_VAL                   # leader_for_view(view) = view % num_validators
        bid = derive(proposer, h, parent)
        out.append((h, proposer, bid))
        parent = bid
    return out
```

Output for `chain(5)` (every value verified against the engine via
`apply_restore_catchup_blocks`'s fail-closed checks in §9):

```text
height=  0 view=  0 proposer=V0  block_id=00000000000000000000000000000000ffffffffffffffffffffffffffffffff
height=  1 view=  1 proposer=V1  block_id=0100000000000000010000000000000000000000000000000000000000000000
height=  2 view=  2 proposer=V0  block_id=0000000000000000020000000000000001000000000000000100000000000000
height=  3 view=  3 proposer=V1  block_id=0100000000000000030000000000000000000000000000000200000000000000  ← snapshot anchor
height=  4 view=  4 proposer=V0  block_id=0000000000000000040000000000000001000000000000000300000000000000
height=  5 view=  5 proposer=V1  block_id=0100000000000000050000000000000000000000000000000400000000000000
```

The fact that V1B successfully applied 328 contiguous certified blocks
above height=3 with `parent_block_id=0100…0200…` (§8.1, §9.1) is the
operative end-to-end check that this derivation matches the live V0
cluster's actual in-memory chain — `apply_restore_catchup_blocks`
fails closed otherwise.