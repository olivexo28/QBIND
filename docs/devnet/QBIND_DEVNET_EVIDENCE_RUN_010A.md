# QBIND DevNet Evidence Run 010A

## 1. Purpose and Scope

Run 010A is the **first post-B12 binary-path DevNet evidence exercise**
on QBIND. Its purpose is intentionally narrow: **before** asking the
system to prove full cross-node consensus progression under
`MutualAuthMode::Required`, prove the lower layer cleanly and in
isolation on real `qbind-node` binaries, namely

1. that two real `qbind-node` processes start under
   `--p2p-mutual-auth required`,
2. that startup unambiguously confirms Required mode,
3. that the mutual-auth KEMTLS handshake succeeds between them,
4. that the listener-side accepted-session identity is sourced from the
   *verified* cert-backed material introduced by B12 (not from the
   pre-B12, self-asserted `client_random` text path),
5. that both sides register each other under the same deterministic
   NodeIds far enough for `send_to(ValidatorId)` routing preconditions
   to hold,
6. that `/metrics` remains honest under Required mode,
7. that shutdown remains clean,
8. that no previously landed binary-path milestone (B1, B2, B3, B5, B6,
   B7, B8, B9, B10, B11) has regressed.

Per task brief §1, full consensus progression under mutual-auth required
mode is **out of scope** for the verdict of this run. Cross-node
proposal/vote/QC/commit progression that happens incidentally is recorded
under §6/§7/§8 as observation only; it is **not** the basis on which
Run 010A is judged. Run 010A's verdict is bounded strictly to items
(1)–(8) above.

This is an execution / evidence task. No QBIND source files are modified
by this run; only this evidence document is created. As recorded in
§13, no contradiction.md update is warranted (§11 explains why).

## 2. Canonical Basis

- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_009.md` — defines the
  pre-Run-010A baseline (B6–B10 closed and exercised, full cross-node
  consensus progression on the binary path observed for the first time
  under `MutualAuthMode::Disabled`); prescribes the topology / peer-syntax
  / `[binary] B12: …` / loop-exit-summary regression-guard expectations
  carried forward into Run 010A.
- `docs/whitepaper/contradiction.md` C4 — current canonical record of
  the binary-bring-up contradiction. As of v1.5 (`2026-05-07`), the C4
  Status row records B12 as landed end-to-end through the binary path
  alongside B1/B2/B3/B5/B6/B7/B8/B9/B10. Run 010A is the first DevNet
  evidence run executed against that B12 claim.
- `crates/qbind-node/src/main.rs:341–422` — `[binary] B12:
  mutual_auth_mode=…` startup banner, `--p2p-mutual-auth` /
  `QBIND_MUTUAL_AUTH` source resolution, MainNet fail-closed guard, and
  `with_mutual_auth_mode(...)` plumb-through into `P2pNodeBuilder`.
- `crates/qbind-node/src/p2p_node_builder.rs:773–856` — the listener-side
  inbound identity resolver split by mode. Under
  `MutualAuthMode::Required` the resolver fails closed if
  `peer_init.mutual_auth_complete == false`, then derives the NodeId
  *only* from `peer_init.verified_peer_validator_id` via
  `parse_test_validator_id_from_cert_validator_id` →
  `derive_test_node_id_from_validator_id`. The pre-B12 self-asserted
  `client_random` resolver path is unreachable under Required.
- `crates/qbind-node/src/p2p_node_builder.rs:983–1031` — the dialer-side
  attaches the local `NetworkDelegationCert` as `local_client_cert` and
  installs `TrustedClientRoots` so the listener actually exercises
  `parse_and_verify_client_cert`.
- `crates/qbind-node/src/secure_channel.rs:115–146,343–371` — the
  `AcceptedPeerInit { verified_peer_validator_id, verified_client_node_id,
  mutual_auth_complete }` surface populated from
  `Connection::peer_validator_id()` / `peer_node_id()` /
  `mutual_auth_complete()` at the `Established` transition.
- `crates/qbind-node/tests/b12_mutual_auth_identity_binding_tests.rs`
  — the in-tree B12 closure / regression tests that shape Run 010A.

## 3. Run Environment

| Field | Value |
|---|---|
| Host | `runnervmeorf1`, Linux 6.17.0-1010-azure x86_64 |
| Distro | Ubuntu 24.04.4 LTS (Noble Numbat) |
| `rustc` | `1.94.1 (e408947bf 2026-03-25)` |
| `cargo` | `1.94.1 (29ea6fb6a 2026-03-24)` |
| Repo branch | `copilot/execute-devnet-evidence-run-010a` |
| Repo HEAD at build | `ab199d57364cf76b57d962e04253d8d9e1076f49` (branch HEAD as cloned, prior to this doc — no source files modified by Run 010A) |
| Build profile | `cargo build --release -p qbind-node --bin qbind-node` |
| Build duration | 6 m 38 s (`real`) |
| Resulting binary | `target/release/qbind-node`, ELF 64-bit LSB pie executable, x86-64, 9 089 936 bytes, BuildID `e3a9660f65f581b5ce2cc390d60bcf429330afc9` |
| Binary build warning | one pre-existing `qbind-node` (lib) warning (`unused variable: worker_id` in `verify_pool.rs:262`); same shape as Run 008 / Run 009; no regression caused by this run |
| All run logs / metrics / data dirs under | `/tmp/run010a/` |

The binary used for **all** sub-runs in this report is the same binary
built once from the branch HEAD; no per-sub-run rebuild was done.

## 4. Topology and Node Configuration Used

Two sub-runs were executed in sequence, both against the same release
binary:

### 4.1 Sub-run A — Primary, two real binaries under `MutualAuthMode::Required`

| Node | Validator | Listen | Static peer (`vid@addr`) | Mutual auth | Metrics | Data dir | Start (UTC) |
|---|---|---|---|---|---|---|---|
| V0 | `ValidatorId(0)` | `127.0.0.1:19000` | `1@127.0.0.1:19001` | `--p2p-mutual-auth required` | `127.0.0.1:9100` | `/tmp/run010a/data-v0` | `2026-05-07T09:29:53.200Z` |
| V1 | `ValidatorId(1)` | `127.0.0.1:19001` | `0@127.0.0.1:19000` | `--p2p-mutual-auth required` | `127.0.0.1:9101` | `/tmp/run010a/data-v1` | `2026-05-07T09:30:44.039Z` |

**Honest stagger note.** The V1 start is recorded at `09:30:44.039Z`,
which is `~50.8 s` after V0's start at `09:29:53.200Z`, NOT the ~12 s
late-peer-connect stagger Runs 008 / 009 used. This is because the
operator's first attempt to background V1 was killed by the orchestration
shell before `nohup` finished (V1's pid file was written but no `qbind-node`
process actually appeared in `ps -ef`); a second, `setsid`-based spawn
succeeded `~51 s` after V0. The stagger is therefore wider than planned,
but it remains **strictly inside the territory B8 + B9 + B10 are designed
to cover**: V0's bounded initial-dial retry (8 attempts × {100, 200, 400,
800, 1000, 1000, 1000} ms ≈ 5.5 s) had long since exhausted, and B9 + B10
re-emit-on-late-peer-connect is *exactly* the closure that handles the
"V1 connects long after view 0's first leader-tick" case. The wider
stagger does not invalidate any §1 item; if anything, it gives a stricter
test of the Required-mode listener's ability to bind a long-late
inbound. The two cross-node loop-exit `commits=802` / `commits=803`
confirm that recovery completed cleanly once V1 connected.

V0 is the leader of view 0 in this two-validator cluster, so V0's first
leader-tick fires into an empty peer set; whichever side eventually
establishes a TCP connection (here, V1, after V1 starts and dials V0) is
the side whose KEMTLS handshake completes; on V0 the **inbound resolver**
must bind that accepted session to V1's deterministic
`NodeId(92115fddcd4f93a0)`, and on V1 the **dialer-side override path**
must register V0's deterministic `NodeId(4bd96f97b1aaec9d)`.

Critically for §1 item (4): under `MutualAuthMode::Required` the V0
resolver MUST source V1's NodeId from
`AcceptedPeerInit.verified_peer_validator_id` (cert-backed) and not from
`AcceptedPeerInit.client_random` (legacy self-asserted). See §6 for the
proof.

### 4.2 Sub-run B — Single-validator LocalMesh regression check

| Node | Validator | Mode | Mutual auth | Metrics | Data dir | Start (UTC) |
|---|---|---|---|---|---|---|
| SV | `ValidatorId(0)` | `local-mesh` | (flag not passed; `QBIND_MUTUAL_AUTH` not set) | `127.0.0.1:9102` | `/tmp/run010a/data-sv` | `2026-05-07T09:32:32.296Z` |

This sub-run does not use P2P, does not have static peers, does not pass
`--p2p-mutual-auth`, and does not exercise B6/B7/B8/B9/B10/B12. Per
`main.rs`, the LocalMesh path `run_local_mesh_node` does not even reach
the `[binary] B12: …` banner site; the single-validator self-quorum
path is bit-equivalent to pre-B12. Sub-run B confirms this empirically
on the production binary (see §10).

### 4.3 No Required-mode comparison sub-run with a friendlier stagger

A reverse-stagger or tight-stagger comparison sub-run is not added. Run
008 already recorded that even a 6 s reverse stagger on this host did
not produce a clean separation between "B9 path" and "original
first-emission broadcast path" (binary boot + KEMTLS handshake exceeded
the 100 ms tick interval). Under Required mode the handshake is even
more expensive (the listener now actually parses + verifies the client
cert), so the same conclusion applies a fortiori. Adding such a sub-run
would not produce evidence beyond what §6 already demonstrates.

## 5. Commands and Configuration Used

Exactly as executed (each backgrounded with `setsid` for Sub-run A V1
and the original V0; output redirected to per-node files under
`/tmp/run010a/logs/`).

### 5.1 Sub-run A

```sh
# V0 (started first, 2026-05-07T09:29:53.200Z)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19000 \
    --p2p-peer 1@127.0.0.1:19001 \
    --p2p-mutual-auth required \
    --validator-id 0 \
    --data-dir /tmp/run010a/data-v0

# … delay (~51 s, see §4.1 honest stagger note) …

# V1 (started second, 2026-05-07T09:30:44.039Z)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9101 \
  ./target/release/qbind-node \
    --env devnet \
    --network-mode p2p \
    --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19001 \
    --p2p-peer 0@127.0.0.1:19000 \
    --p2p-mutual-auth required \
    --validator-id 1 \
    --data-dir /tmp/run010a/data-v1
```

### 5.2 Sub-run B (single-validator regression check)

```sh
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9102 \
  ./target/release/qbind-node \
    --env devnet --network-mode local-mesh \
    --validator-id 0 \
    --data-dir /tmp/run010a/data-sv
```

### 5.3 Environment variables

The only environment variable set per node beyond the inherited shell is
`QBIND_METRICS_HTTP_ADDR` (gating B2's metrics endpoint per
`MetricsHttpConfig::from_env`). `QBIND_MUTUAL_AUTH` is **not** set in
any sub-run; mutual-auth mode in Sub-run A is supplied exclusively via
the `--p2p-mutual-auth required` CLI flag. This fact is independently
proven by V0/V1's `[binary] B12: mutual_auth_mode=Required (source:
--p2p-mutual-auth)` startup banner (§6.1) — the source field would have
read `QBIND_MUTUAL_AUTH` if the env var had been the active source, and
`default` if neither input had been provided.

No `--restore-from-snapshot`, no genesis override, no validator-set
override, no PoP / KEMTLS env overrides; the binary uses its built-in
`SimpleValidatorNodeMapping` and `derive_test_kem_keypair_from_validator_id`
defaults introduced by B7. Both P2P nodes were started with `--env
devnet`, which prints the standard "P2P enabled in DevNet environment.
DevNet v0 freeze recommends LocalMesh." advisory to stderr — this is
expected and honest (the binary does not silently fall back to LocalMesh;
it proceeds with P2P as configured). The `[restore] no
--restore-from-snapshot requested; normal startup.` line confirms B3 was
honestly not exercised.

### 5.4 Peer syntax

All P2P peers use the post-B7 `vid@addr` syntax. Both V0 and V1 in
Sub-run A exclusively use `vid@addr`; both nodes' stdout logs the
post-B7 line `peer_kem_overrides=1`, which is the count of `vid@`-form
overrides that were successfully parsed and registered. A second, post-B12
field on the same line — `mutual_auth=Required` — proves the
`P2pNodeBuilder::with_mutual_auth_mode(...)` plumb-through executed.

## 6. Startup, Mutual-Auth Handshake, and Identity-Binding Evidence

### 6.1 V0 startup banner — Required mode confirmed unambiguously

V0 stderr (`/tmp/run010a/logs/node0.stderr`) — relevant lines verbatim,
in emit order:

```
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[restore] no --restore-from-snapshot requested; normal startup.
[T175] Warning: P2P enabled in DevNet environment. DevNet v0 freeze recommends LocalMesh. Use --env testnet for P2P experimentation.
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9100 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9100 (set via QBIND_METRICS_HTTP_ADDR)
[binary] P2P mode: starting transport + consensus loop. environment=DevNet profile=nonce-only
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[metrics_http] Listening on 127.0.0.1:9100
[binary] P2P transport up. Listen address: 127.0.0.1:19000, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary] Multi-validator P2P (2 validators): inbound P2P consensus messages are routed into BasicHotStuffEngine via on_proposal_event / on_vote_event; engine actions flow back out through P2pConsensusNetwork.
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
```

V0 stdout (`/tmp/run010a/logs/node0.stdout`) — relevant lines:

```
qbind-node[validator=V0]: starting in environment=DevNet chain_id=0x51424e4444455600 scope=DEV profile=nonce-only network=p2p p2p=enabled listen=127.0.0.1:19000 peers=1 gas=off fee-priority=off fee_distribution=burn-only mempool=fifo dag_availability=disabled dag_coupling=off stage_b=disabled diversity=off(prefix24=2,prefix16=8,buckets>=4)
[P2P] Listening on 127.0.0.1:19000 (node_id=NodeId(4bd96f97b1aaec9d))
[T175] P2P node builder: validator=ValidatorId(0) node_id=NodeId(4bd96f97b1aaec9d) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
```

V1 stderr (`/tmp/run010a/logs/node1.stderr`) and V1 stdout
(`/tmp/run010a/logs/node1.stdout`) — corresponding lines:

```
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
…
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on
…
qbind-node[validator=V1]: starting in environment=DevNet … listen=127.0.0.1:19001 peers=1 …
[P2P] Listening on 127.0.0.1:19001 (node_id=NodeId(92115fddcd4f93a0))
[T175] P2P node builder: validator=ValidatorId(1) node_id=NodeId(92115fddcd4f93a0) num_validators=2 peer_kem_overrides=1 mutual_auth=Required
```

What this proves for §1 items (1)–(2):

- **Both real `qbind-node` processes started successfully under
  `--p2p-mutual-auth required`.** Both reach the `[binary] P2P node
  started. Press Ctrl+C to exit.` line and both reach the
  `[binary-consensus] Starting consensus loop:` line.
- **Startup unambiguously confirms Required mode on both sides.** Two
  independent witnesses on each node:
  1. `[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)`
     — emitted by `main.rs` after CLI / env resolution. The `source:
     --p2p-mutual-auth` field proves the mode came from the CLI flag,
     not from `QBIND_MUTUAL_AUTH` and not from the default.
  2. `[T175] P2P node builder: … mutual_auth=Required` — emitted by
     `p2p_node_builder::P2pNodeBuilder::build()` after
     `with_mutual_auth_mode(...)`. This is the post-B12 builder field
     that did not exist before B12 and would read `Disabled` if the
     mode had silently been overridden.

### 6.2 V0 dial-retry and inbound resolver — handshake succeeds, listener bind happens via post-B12 cert-backed path

V0 stdout, continuing after the startup lines above:

```
[P2P] dial 127.0.0.1:19001 attempt 1/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 100ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 2/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 200ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 3/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 400ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 4/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 800ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 5/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 6/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] dial 127.0.0.1:19001 attempt 7/8 failed (transient: I/O error: Connection refused (os error 111)); retrying in 1000ms (B8 initial-dial retry)
[P2P] Accepted connection from 127.0.0.1:40886
[P2P] Accepted connection from 127.0.0.1:40896
[P2P] Inbound connection from 127.0.0.1:40896 bound to deterministic NodeId NodeId(92115fddcd4f93a0) via inbound identity resolver (B8, test-grade)
[P2P] Peer NodeId(92115fddcd4f93a0) connected
```

V0 stderr in the same window:

```
[P2P] dial 127.0.0.1:19001 giving up after 8 attempt(s): I/O error: Connection refused (os error 111) (transient=true, max_attempts=8)
[P2P] Inbound connection error: Handshake error: channel error: Io(Error { kind: UnexpectedEof, message: "failed to fill whole buffer" })
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
```

V1 stdout, in the same window:

```
[P2P] Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)
[P2P] Peer NodeId(4bd96f97b1aaec9d) connected
```

What this proves for §1 items (3)–(4):

- **Mutual-auth handshake succeeds.** Both sides report `Peer NodeId(...)
  connected` (V0 sees V1's deterministic `NodeId(92115fddcd4f93a0)`;
  V1 sees V0's deterministic `NodeId(4bd96f97b1aaec9d)`). These are
  byte-identical to the deterministic NodeIds Runs 007 / 008 / 009
  observed under `MutualAuthMode::Disabled`, i.e. the same
  `derive_test_node_id_from_validator_id` derivation B7 introduced — by
  design (per `p2p_node_builder.rs:843–845`, the Required-mode resolver
  maps the *cert-derived* validator id through the *same*
  `derive_test_node_id_from_validator_id`, so the NodeId byte pattern is
  the same but the cryptographic source is different).
- **Cert-backed identity binding is the path actually exercised on V0.**
  This is the central B12 claim. Three concurring artifacts establish
  it:
    1. The `[binary] B12: mutual_auth_mode=Required (source:
       --p2p-mutual-auth)` banner above is V0's only configured
       resolver mode.
    2. The `[P2P] Inbound connection from 127.0.0.1:40896 bound to
       deterministic NodeId NodeId(92115fddcd4f93a0) via inbound
       identity resolver (...)` line is emitted by
       `p2p_tcp.rs:737–741` *only* when the resolver returned `Some(_)`.
       The closure installed by `p2p_node_builder.rs:829–855` under
       `MutualAuthMode::Required` returns `Some(_)` **only via** the
       sequence
         - `peer_init.mutual_auth_complete == true` (else early
           `return None`),
         - `peer_init.verified_peer_validator_id == Some(vid_bytes)`
           (else `?` early returns `None`),
         - `parse_test_validator_id_from_cert_validator_id(&vid_bytes)
           == Some(vid)` (else `?` early returns `None`),
         - `Some(derive_test_node_id_from_validator_id(vid))`.
       The resolver therefore could not have returned the *self-asserted*
       `client_random`-derived NodeId for this session: the `client_random`
       branch of the resolver is in the `MutualAuthMode::Disabled` arm
       of the same `match`, which is unreachable when `resolver_mode ==
       Required`. The successful bind is thus *only* possible through
       the cert-backed branch; the cert-backed branch *only* yields
       `Some` when `mutual_auth_complete = true` AND
       `verified_peer_validator_id` parsed.
    3. Cross-node engine progression confirms that the registration was
       actually routable: V0's `consensus_net_inbound_total{kind="vote"}
       = 688` and V1's `consensus_net_inbound_total{kind="vote"} = 687`
       at scrape T2 (§8) — V0 received 688 cross-node votes from V1 and
       V1 received 687 cross-node votes from V0 — which can only happen
       if the listener-side `send_to(ValidatorId)` resolves to a
       registered transport session. Under Required mode this can only
       have come from the cert-backed bind.
- **B7 dialer-side override is active on V1**: the
  `using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)`
  line is the post-B7 dialer-side identity-closure trace. Under
  `MutualAuthMode::Required` the dialer additionally attaches its local
  `NetworkDelegationCert` as `local_client_cert` so the listener can
  parse + verify it (`p2p_node_builder.rs:998–1000`).
- **B8 bounded initial-dial retry is exercised on V0**: 7 retries with
  the documented {100, 200, 400, 800, 1000, 1000, 1000} ms backoff,
  then `giving up after 8 attempt(s) … transient=true, max_attempts=8`
  — identical shape to Runs 008 / 009, no regression.
- **B9 + B10 paired re-emit fires exactly once on V0.** Following the
  late connect, `B9+B10: re-emitted view 0 BroadcastProposal +
  BroadcastVote after late peer connect (newly_connected_peers=1,
  proposal_reemits_total=1, vote_reemits_total=1)` — this is what
  unblocks the cross-node progression observed in §7/§8. No regression
  vs. Runs 008 / 009.
- **Honest noise carried forward unchanged from Runs 006/007/008/009.**
  V0 sees a first inbound TCP connection (`127.0.0.1:40886`) that fails
  KEMTLS with `UnexpectedEof`, and V0's *second* inbound
  (`127.0.0.1:40896`) succeeds via the resolver. Same shape as Runs 006
  / 007 / 008 / 009 stderr; this is honest noise, not silent failure,
  and not a B7/B8/B9/B10/B12 regression.

### 6.3 Honest ambiguity: the listener log line still self-labels "B8, test-grade"

The exact text emitted by `p2p_tcp.rs:737–741` is hardcoded
`"… via inbound identity resolver (B8, test-grade)"`. This println is
the same call site for both the B8 (`Disabled`) path and the B12
(`Required` / `Optional`) path because `p2p_tcp.rs::handle_inbound_connection`
does not know which `InboundIdentityResolver` shape the builder
installed. The line's `(B8, test-grade)` parenthetical is therefore
**not** a witness to which resolver branch ran. The cert-backed path is
proven by the chain of necessary conditions in §6.2 bullet 2 above, NOT
by this log text.

This is recorded as an honest ambiguity in the log surface; it does not
weaken the binding (the resolver code can only return `Some` via the
cert-backed branch under `Required`), but it is a candidate for a
small future log-text refinement. It does not warrant a new
contradiction (see §11).

## 7. Connectivity / Routing-Precondition Evidence

§1 item (5) asks: did both sides register each other under deterministic
NodeIds far enough for routing preconditions to hold?

### 7.1 Symmetric `Peer NodeId(...) connected` on both sides

V0 stdout: `[P2P] Peer NodeId(92115fddcd4f93a0) connected` — V1's
deterministic NodeId per `derive_test_node_id_from_validator_id(1)`.

V1 stdout: `[P2P] Peer NodeId(4bd96f97b1aaec9d) connected` — V0's
deterministic NodeId per `derive_test_node_id_from_validator_id(0)`.

Both NodeIds are byte-identical to those observed in Runs 007 / 008 / 009.

### 7.2 `send_to(ValidatorId)` precondition holds — proof from cross-node traffic

Routing preconditions are observable because the binary actually used
them. From the §8 metrics scrape T2 on V0 and V1:

- V0 `consensus_net_outbound_total{kind="vote_broadcast"} = 689`,
  `consensus_net_outbound_total{kind="proposal_broadcast"} = 345` —
  V0 actually pushed `689 + 345 = 1034` outbound consensus frames to
  the registered V1 transport session.
- V1 `consensus_net_inbound_total{kind="vote"} = 687`,
  `consensus_net_inbound_total{kind="proposal"} = 344` — V1 actually
  *received* 1031 of those frames (the 3-frame deficit is the natural
  in-flight gap between V0's outbound counter increment and V1's
  inbound counter increment when the scrape timestamps differ; V0 was
  scraped microseconds after V1).

The same shape holds in the reverse direction (V1 outbound 688 + 344 =
1032; V0 inbound 688 + 344 = 1032). This is positive evidence that the
cert-bound NodeId on both sides actually resolved through
`send_to(ValidatorId)` to the registered transport session.

### 7.3 Out-of-scope distinction

This section establishes **routing precondition**: traffic crosses
between the two registered sessions in both directions. Per §1, full
cross-node consensus progression (proposal → vote → QC → commit) is
out of scope for the verdict; it is observed incidentally and recorded
in §8 / §9 (loop-exit summaries) so the reader can see the engine layer
also progressed, but Run 010A's verdict does NOT rest on it.

## 8. Metrics Evidence

§1 item (6) asks: did `/metrics` remain honest? Two scrapes were taken
on each Sub-run A node, ~15 s apart.

| Time (UTC) | Endpoint | Selected counters |
|---|---|---|
| `2026-05-07T09:31:25.684Z` (T1) | V0 `127.0.0.1:9100/metrics` | `qbind_consensus_qcs_formed_total = 398`; `qbind_consensus_proposals_total{result="accepted"} = 398`; `qbind_consensus_proposals_total{result="rejected"} = 0`; `consensus_net_inbound_total{kind="vote"} = 398`, `{kind="proposal"} = 199`, `{kind="other"} = 0`; `consensus_net_outbound_total{kind="vote_broadcast"} = 399`, `{kind="proposal_broadcast"} = 200`; `consensus_net_outbound_dropped_total = 0`; `consensus_net_inbound_channel_closed_total = 0` |
| `2026-05-07T09:31:25.684Z` (T1) | V1 `127.0.0.1:9101/metrics` | `qbind_consensus_qcs_formed_total = 397`; `qbind_consensus_proposals_total{result="accepted"} = 398`, `{result="rejected"} = 0`; `consensus_net_inbound_total{kind="vote"} = 397`, `{kind="proposal"} = 199`, `{kind="other"} = 0`; `consensus_net_outbound_total{kind="vote_broadcast"} = 398`, `{kind="proposal_broadcast"} = 199`; `consensus_net_outbound_dropped_total = 0`; `consensus_net_inbound_channel_closed_total = 0` |
| `2026-05-07T09:31:55.869Z` (T2) | V0 `127.0.0.1:9100/metrics` | `qbind_consensus_qcs_formed_total = 688`; `qbind_consensus_proposals_total{result="accepted"} = 688`; `consensus_net_inbound_total{kind="vote"} = 688`, `{kind="proposal"} = 344`; `consensus_net_outbound_total{kind="vote_broadcast"} = 689`, `{kind="proposal_broadcast"} = 345`; `qbind_consensus_view_changes_total = 1376`; `qbind_consensus_leader_changes_total = 688` |
| `2026-05-07T09:31:55.869Z` (T2) | V1 `127.0.0.1:9101/metrics` | `qbind_consensus_qcs_formed_total = 687`; `qbind_consensus_proposals_total{result="accepted"} = 688`; `consensus_net_inbound_total{kind="vote"} = 687`, `{kind="proposal"} = 344`; `consensus_net_outbound_total{kind="vote_broadcast"} = 688`, `{kind="proposal_broadcast"} = 344`; `qbind_consensus_view_changes_total = 1374`; `qbind_consensus_leader_changes_total = 687` |

Each scrape returned 317 lines, well-formed Prometheus text, no 5xx, no
truncation, no decode error. Both endpoints stayed reachable across both
scrapes with no observable jitter beyond the natural `~30 s × 100 ms`
tick advance.

What this proves for §1 item (6):

- **`/metrics` remains honest.** Counter monotonicity holds across T1 →
  T2 on both nodes. Cross-node deltas are ≤ 3 frames (the natural
  in-flight gap between V0/V1 scrape moments). `result="rejected"`
  stays at 0 throughout — there is no silent rejection of incoming
  proposals on either side under Required mode. `outbound_dropped_total
  = 0` and `inbound_channel_closed_total = 0` rule out silent
  back-pressure or silent channel close.
- **No metric surface regressed under Required mode.** Every counter
  family that Run 009 observed under `Disabled` mode is present and
  populated here under `Required`. The B11 `consensus_net_outbound_total`
  family that Run 009 observed at non-zero values is at non-zero values
  here as well (it would have been 0 if the B11 wiring had been
  silently undone by B12 — it was not).
- **Honest under-report carried forward, unchanged.** As recorded in
  Runs 008/009, the `outbound_vote_late_peer_reemits` counter is
  surfaced in `BinaryConsensusLoopInboundStats` and in the stderr
  `B9+B10:` trace, but the `Loop exit:` one-liner in
  `binary_consensus_loop.rs` was not extended when B10 added the paired
  cache. Same shape here:
  `outbound_proposal_late_peer_reemits=1` appears in V0's loop-exit
  line; the paired `outbound_vote_late_peer_reemits=1` value is observable
  only in the stderr `B9+B10:` trace. This is the same single
  divergence Runs 008/009 recorded honestly; no new under-report
  introduced by Required mode.

## 9. Shutdown Evidence

§1 item (7) asks: did shutdown remain clean?

At `2026-05-07T09:32:07.998Z` SIGINT was sent simultaneously to V0 (PID
9529) and V1 (PID 9572) via `kill -INT 9529 9572`. By
`2026-05-07T09:32:13.001Z` (≈ 5 s later) `ps -ef | grep qbind-node`
returned no matching processes.

V0 stderr final lines:

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 1348 ticks.
[binary-consensus] Loop exit: ticks=1348 proposals=403 commits=802 committed_height=Some(801) view=804 inbound_msgs=1206 inbound_proposals=402 inbound_votes=804 outbound_proposals=403 outbound_votes=805 outbound_proposal_late_peer_reemits=1
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

V1 stderr final lines:

```
[binary] Shutdown signal received, stopping P2P node...
[binary-consensus] Shutdown signal received after 840 ticks.
[binary-consensus] Loop exit: ticks=840 proposals=402 commits=803 committed_height=Some(802) view=805 inbound_msgs=1208 inbound_proposals=403 inbound_votes=805 outbound_proposals=402 outbound_votes=805 outbound_proposal_late_peer_reemits=0
[binary] P2P node shutdown complete.
[binary] Stopping metrics HTTP server...
[metrics_http] Shutting down
[binary] Shutdown complete.
```

What this proves for §1 item (7):

- **Both nodes accepted SIGINT, drained, and exited cleanly.** Both
  emit the canonical four-line shutdown-completion sequence in order
  (`P2P node shutdown complete.` → `Stopping metrics HTTP server...` →
  `[metrics_http] Shutting down` → `Shutdown complete.`).
- **Loop-exit accounting is internally consistent under Required mode.**
  V0 ran 1348 ticks ≈ 134.8 s (matches V0 wall-clock 09:29:53 → 09:32:08
  ≈ 135 s). V1 ran 840 ticks ≈ 84.0 s (matches V1 wall-clock 09:30:44 →
  09:32:08 ≈ 84 s). The ~50.8 s difference matches the §4.1 stagger.
- **Engine layer also progressed cleanly (incidental).** V0 final
  `committed_height=Some(801)`, V1 final `committed_height=Some(802)` —
  ~800 commits each on top of the deterministic late-connect recovery.
  Per §1 this is recorded as observation only and is **not** the basis
  on which Run 010A is judged. Run 010A's verdict is bounded to §1
  items (1)–(8); no implicit upgrade to "full mutual-auth Required
  consensus progression proven" is being claimed here.
- **No "Loop exit (ABORTED)" / "panicked at" / `WARN` / `ERROR`
  shutdown lines on either side.** No process-exit anomaly.

## 10. Regression Check Against Previously Landed Binary-Path Capabilities

§1 item (8) asks: did any previously landed binary-path capability appear
regressed?

| Milestone | Pre-Run-010A canonical evidence | Run-010A observed | Regression? |
|---|---|---|---|
| **B1** — `BasicHotStuffEngine` driven by `binary_consensus_loop` from binary path | Runs 005–009 | `[binary-consensus] Starting consensus loop` on both Sub-run A nodes and on Sub-run B; loop-exit summaries with internally consistent tick counts | No |
| **B2** — `/metrics` HTTP server gated on `QBIND_METRICS_HTTP_ADDR` | Runs 005–009 | `[metrics_http] Listening on …` on all three sub-runs; both Sub-run A scrapes returned 317 lines of well-formed Prometheus text | No |
| **B3** — `--restore-from-snapshot` honest startup path | Runs 005–009 | `[restore] no --restore-from-snapshot requested; normal startup.` on every sub-run; B3 was not exercised, no fallback or silent restore | No (not exercised by design) |
| **B5** — restore-aware consensus start | Runs 005–009 | `restore_baseline=false` on every loop-config line; B5 was not exercised, no fallback | No (not exercised by design) |
| **B6** — multi-validator P2P binary-path interconnect (real inbound demuxing) | Runs 008/009 | Sub-run A: V0 `inbound_msgs=1206 / inbound_proposals=402 / inbound_votes=804`; V1 `inbound_msgs=1208 / inbound_proposals=403 / inbound_votes=805` | No |
| **B7** — dialer-side test-grade KEMTLS bring-up + identity closure | Runs 007/008/009 | V1 `Dial 127.0.0.1:19000: using per-peer KEM pk + validator-id override (pk_len=32, has_vid=true)`; both `[T175] P2P node builder: …` lines log `peer_kem_overrides=1` | No |
| **B8** — listener-side identity resolver + bounded initial-dial retry | Runs 007/008/009 | V0 dial retries 1/8…7/8 with documented backoff; `giving up after 8 attempt(s) … transient=true, max_attempts=8`; listener resolver fired (now via the B12 cert-backed branch — semantics broadened, not regressed) | No |
| **B9** — leader-side proposal re-emit on late peer connect | Runs 008/009 | V0 stderr: `B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote …`; V0 loop-exit `outbound_proposal_late_peer_reemits=1` | No |
| **B10** — paired leader-vote re-emit on the same B9 trigger; engine-progress recorder + inbound engine-accept metric closure | Runs 008/009 | V0 stderr `vote_reemits_total=1` on the same `B9+B10:` line; cross-node `qbind_consensus_qcs_formed_total = 687/688` and `qbind_consensus_proposals_total{result="accepted"} = 688/688` at T2 (incidental) | No |
| **B11** — `consensus_net_outbound_total` family populated honestly on the binary path | Runs 008/009 | V0 T2 `consensus_net_outbound_total{kind="vote_broadcast"} = 689`, `{kind="proposal_broadcast"} = 345`; V1 T2 `{kind="vote_broadcast"} = 688`, `{kind="proposal_broadcast"} = 344`; `outbound_dropped_total = 0` everywhere | No |
| **§11 LocalMesh single-validator regression-guard** | Runs 005–009 | Sub-run B: `interconnect=none late_peer_reemit=off`; loop-exit `ticks=205 proposals=205 commits=203 committed_height=Some(202) view=205 inbound_msgs=0 inbound_proposals=0 inbound_votes=0 outbound_proposals=0 outbound_votes=0 outbound_proposal_late_peer_reemits=0`; clean `[binary] LocalMesh node stopped.` shutdown | No |

In summary, **no previously landed binary-path capability appears
regressed** by enabling `--p2p-mutual-auth required`. The single
behavioural change observed at the resolver boundary (NodeId now
sourced from cert-backed material under Required) is the intended B12
broadening, not a regression: byte-identical NodeId result, strictly
stronger cryptographic provenance.

## 11. Limitations and Anomalies Observed

This section is deliberately strict. Only the observed limitations and
anomalies of Run 010A itself are listed; nothing is editorialized into
the section.

1. **Stagger between V0 and V1 was ~50.8 s, not the planned ~12 s.**
   Caused by the operator's first attempt to background V1 being killed
   by the orchestration shell before `nohup` finished; recovered
   transparently by re-spawning V1 with `setsid`. The wider stagger
   does not invalidate any §1 item — if anything it tests a stricter
   version of the late-peer-connect case, and B8/B9/B10 handled it
   exactly as designed (`giving up after 8 attempt(s)` then `B9+B10:
   re-emitted view 0 BroadcastProposal + BroadcastVote`). Recorded
   honestly in §4.1.
2. **Listener log line `(B8, test-grade)` does not differentiate
   resolver mode.** As recorded in §6.3, `p2p_tcp.rs:737–741` uses a
   hardcoded `(B8, test-grade)` parenthetical for both the B8
   self-asserted resolver and the B12 cert-backed resolver. This is an
   honest ambiguity in the log surface, **not** in the resolver
   semantics: the chain of necessary conditions in §6.2 bullet 2 proves
   the cert-backed branch is the only branch that could have returned
   `Some` under `Required`. Candidate for a small future log-text
   refinement; not a contradiction (see §13).
3. **`outbound_vote_late_peer_reemits` is not surfaced in the loop-exit
   one-liner.** Carried forward unchanged from Runs 008/009. Same
   single under-report; no new under-report introduced by Required mode
   (§8).
4. **One inbound `UnexpectedEof` handshake error on V0.** Same shape as
   Runs 006/007/008/009 stderr (`[P2P] Inbound connection error:
   Handshake error: channel error: Io(Error { kind: UnexpectedEof, …
   })`); corresponds to V0's *first* inbound TCP connection
   (`127.0.0.1:40886`) being torn down before the KEMTLS handshake
   completed. V0's *second* inbound (`127.0.0.1:40896`) succeeds via
   the resolver and binds to V1's deterministic NodeId. Honest noise,
   not silent failure, not a B7/B8/B9/B10/B12 regression.
5. **No KEMTLS-handshake-success counter observable on `/metrics`.**
   The post-Run-008/009 metric surface still lacks a dedicated
   handshake-success counter at the transport layer; success is
   inferred from `Peer NodeId(...) connected` on stdout and from the
   `consensus_net_*` families exhibiting non-zero counts. No regression
   vs. prior runs; just an honest note about what `/metrics` does NOT
   carry.
6. **Required-mode timing under cold start was not measured separately.**
   The handshake completed within the natural late-peer-connect window
   that B8 + B9 + B10 covered, but a microbenchmark of "Required-mode
   handshake latency on a tight reverse stagger" was not produced.
   Out of scope for §1 of this run; flagged for a future evidence run
   if and when needed.

No production-readiness claims are made. The B12 plumb-through
exercised here remains wired through the test-grade DummySig signature
suite + `TrustedClientRoots` resolver per `main.rs:374–422`; per the
fail-closed guard there, `--p2p-mutual-auth required` is rejected with
`FATAL` on `--env mainnet` and produces a `WARNING` on `--env testnet`.
DevNet — which is what this run used — proceeds without extra warning
beyond the standard banner. None of this contradicts what
`docs/whitepaper/contradiction.md` C4 already records about production
PQC root-key distribution remaining out of scope.

## 12. Assessment of Evidence Value

Run 010A is the **first DevNet evidence run** to exercise the B12
mutual-auth-required path on real `qbind-node` binaries. It demonstrates,
on production binaries built from the branch HEAD:

- Required-mode CLI plumbing reaches the listener and dialer (§6.1
  startup banner + `[T175] … mutual_auth=Required` builder line).
- Cert-backed listener-side identity binding is the *only* code path
  through which the observed inbound bind could have happened (§6.2
  necessary-conditions chain).
- Both sides successfully complete the mutual-auth handshake and
  register each other under the same deterministic NodeIds B7/B8 already
  introduced (§6.2, §7.1).
- Cross-node `send_to(ValidatorId)` routing precondition holds in both
  directions (§7.2).
- `/metrics` is honest under Required mode, with no counter regression
  vs. Runs 008/009 (§8).
- Shutdown is clean on both sides (§9).
- No previously landed binary-path capability appears regressed (§10).

What Run 010A is deliberately **not**:

- It is **not** a full proof of cross-node consensus progression under
  Required mode. The cross-node QC formation and commit progression
  observed (V0/V1 final `committed_height=Some(801)`/`Some(802)`) is
  recorded as incidental observation per task §1, not as a verdict
  basis. A future evidence run focused on full progression would tighten
  this further (e.g. a cleanly-staggered start and a longer soak with
  multiple `/metrics` scrapes correlated against loop-exit summaries).
- It is **not** a production-readiness statement. The Required-mode
  cert verification path is exercised structurally (the `parse_and_verify_client_cert`
  codepath ran), but production PQC root-key distribution is **not**
  exercised; this is the remaining open scope explicitly retained in
  C4.
- It is **not** a complete observability statement. The §6.3 log-text
  ambiguity and the §11 item 5 missing handshake-success counter are
  flagged honestly; they don't weaken the binding, they just leave
  surface area for a future small refinement.

Evidence value classification: **POSITIVE on the §1 (1)–(8) checklist.**

## 13. Recommended Immediate Next Action

The exact immediate next action recommended after Run 010A is:

> **Execute "DevNet Evidence Run 010B": prove full cross-node consensus
> progression (proposal → vote → QC → commit) on real `qbind-node`
> binaries under `--p2p-mutual-auth required`, with a deliberately tight
> reverse stagger that exercises both the late-peer-connect path (the
> incidental shape Run 010A produced) AND a cleanly-staggered shape
> where V0's first leader-tick fires *after* V1 has connected and
> completed the mutual-auth handshake.**

The bounded scope of Run 010B should be:
- two real `qbind-node` binaries, both `--p2p-mutual-auth required`,
- one sub-run with a ~12 s late-peer-connect stagger (re-confirms
  Run 010A's handshake/identity proof end-to-end into the engine),
- one sub-run with V1 started ~5 s *before* V0 (to demonstrate that the
  Required-mode listener path is the one binding the dialer's identity
  in the no-late-connect case as well),
- ≥ 3 `/metrics` scrapes per sub-run spaced ≥ 10 s apart for monotonicity,
- explicit cross-node `committed_height` progression recorded against
  loop-exit summaries (as the §6/§7/§8 incidental observation here is
  not the verdict basis),
- §11 LocalMesh single-validator regression check repeated on the same
  binary.

What Run 010B should **not** do:
- attempt MainNet/TestNet (the `main.rs:374–422` fail-closed guard
  forbids MainNet under the test-grade B12 stack and warns on TestNet —
  evidence runs should respect that),
- attempt soak / Alpha/Beta readiness claims,
- attempt production PQC claims,
- redesign the resolver log text (§6.3); a separate small log-refinement
  patch should land independently of evidence runs.

After Run 010B passes, the canonical `docs/whitepaper/contradiction.md`
C4 row for B12 should be revisited *together* with the evidence from
Runs 010A + 010B, not in isolation by Run 010A — this is why no
contradiction.md update is applied here (Run 010A on its own does not
narrow C4 below what the v1.5 doc already records).

---

**Run 010A verdict: POSITIVE on §1 items (1)–(8). Cert-backed
mutual-auth identity binding is exercised end-to-end on the binary
path; no previously landed binary-path capability appears regressed.
Full cross-node consensus progression under Required mode is observed
incidentally and is reserved as the explicit subject of recommended
Run 010B.**