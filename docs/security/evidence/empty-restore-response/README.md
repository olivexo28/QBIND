# Empty RestoreCatchupResponse and restore-mode exit investigation

**EMPTY-RESPONSE INVESTIGATION — INDEPENDENT REVIEW PENDING.**
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**.
Activation remains **DISABLED**; public DevNet remains **NO-GO**.
This is new bounded source analysis, not an implemented containment,
independent acceptance, executed exploit or observed production behavior.
All prior bounded acceptances retain their recorded scope.

## Identity, scope and evidence provenance

On 2026-11-07, before changes, `origin` was
`https://github.com/olivexo28/QBIND` for fetch and push. Direct
`git ls-remote origin refs/heads/main`, local `main` and HEAD all identified
`2d3b2f7a4c4055882525e3af1814d57e87c01c76`, tree
`0b0e597a29dc8f2d95d93f9bd04364cc140a9db1`. The starting branch was
`main`; worktree and staging were empty. No identity mismatch occurred.
`git switch -c investigation/empty-restore-response-20261107
2d3b2f7a4c4055882525e3af1814d57e87c01c76` succeeded without resetting,
discarding or cherry-picking work. The repository has no tracked `AGENTS.md`.

All source references below are pinned to that exact base, not a moving main.
`B` means `crates/qbind-node/src/binary_consensus_loop.rs`, `M` means
`crates/qbind-node/src/main.rs`, `E` means
`crates/qbind-consensus/src/basic_hotstuff_engine.rs`, and `S` means
`crates/qbind-consensus/src/hotstuff_state_engine.rs`. The linked ranges
are the actual source evidence; tables distinguish binary wiring from
callable helpers and fixture-established states.

Existing accepted evidence is reused, not rerun:
[integration preparation](../a17-f1-integration/README.md) records
user-supplied **PASS WITH LIMITATIONS**, exact correspondence, and author-run
9 A17 controls / 9 restore regressions plus production compilation at
`fb27c7e7d864bbea8b91fb6c109872ca15aa6d77`. Its test logs are evidence
of those executions, not new runs at this task's base or hosted CI.
[corrected controls](../a17-f1-test-controls/README.md) describe the admitted
synthetic snapshot, shared protected-state/outbound checker and limitations.
No unavailable reviewer identity or raw independent review is inferred.
Historical rustfmt exit 1 and full/raw-log whitespace exit 2 remain
unsuccessful checks in those packages; their bytes are not repaired.

The existing actual-dispatch empty controls are
[B:10410-10431](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L10410-L10431)
(initially inactive) and
[B:10841-10930](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L10841-L10930)
(direct-import progressed exit, baseline no-exit and self). Pure state
controls at B:10935-11015 characterize single-shot/strict-progress/maximum
rules. The older helper-only `restore_mode_exits_on_empty_response_from_caught_up_peer`
at B:11079-11179 imports just one block and conditionally asserts **no exit**
when the 3-chain has not committed; its name is not proof of a successful
production exit. All are existing source/tests, not newly executed cases.

No production/test code, dependencies, configuration or operational keys are
changed. No node, signing experiment, network experiment, test suite, build,
release artifact or PR is produced. Git ref inspection/push is repository
publication, not a consensus-network experiment. This task executes only
source reads and documentation/integrity checks.

## 1. Actual ingress and prerequisites

The source-supported chain is transport session -> decoded P2P envelope ->
demux -> bounded consensus channel -> binary receive arm -> actual handler.
It is not evidence that any deployed peer used this chain:

| Boundary | Pinned evidence and prerequisites |
|---|---|
| Binary startup | [M:5665-5820](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/main.rs#L5665-L5820), [M:6100-6165](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/main.rs#L6100-L6165): P2P preflight is RequireOrFail; usable local timeout signer, membership/key provider, suites/backends and verification context must pass before network construction. Legacy peer-key or genesis-authority routes are configuration-dependent. This does not activate PV authority. |
| Binding configuration | [builder:1565-1690](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p_node_builder.rs#L1565-L1690): production always installs `Some(gate)`. Nonempty certificate mapping requires Required/Optional mutual auth and active `pqc-static-root`. Other modes install an empty map/no usable origin, not a binding bypass. [builder:702-754](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p_node_builder.rs#L702-L754) validates index range, certificate shape/suite, root signature/time window, canonical validator identity and configured revocation. Map construction rejects duplicate/conflicting identities. |
| Session origin | Inbound resolver requires `mutual_auth_complete`, verified full cert-derived NodeId and verified validator ID matching the map. [TCP:1469-1489](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p_tcp.rs#L1469-L1489) consumes that resolver. [TCP:1567-1628](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p_tcp.rs#L1567-L1628), also :2883-2937 for dial workers, requires actual authenticated server certificate identity to match the configured expected pair; address alone cannot mint origin. |
| Frame delivery | [TCP:181-205](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p_tcp.rs#L181-L205) checks frame length/discriminator and deserializes the structured message. [TCP:2230-2297](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p_tcp.rs#L2230-L2297) requires successful secure-channel receipt/decode and, when installed, per-peer rate admission before forwarding with the session origin. Decode/read error, receiver closure, or a rate drop prevents handler receipt. This investigation does not accept deserialization allocation bounds. |
| Demux/channel | [inbound:370-392](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p_inbound.rs#L370-L392), [inbound:501-520](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p_inbound.rs#L501-L520), [M:6192-6205](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/main.rs#L6192-L6205): origin is preserved; full/closed `try_send` fails with a log. Capacity is 256. [B:3127-3148](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L3127-L3148) supplies the actual envelope, binding gate and restore state to the handler. |
| Claimed responder | [gate:388-447](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/peer_consensus_binding.rs#L388-L447), [B:7393-7421](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L7393-L7421): the `u16 responder_validator_index` is widened to ValidatorId; origin must exist, full NodeId must be known, mapped/authenticated validator must agree, claimed validator must be known and equal origin validator. `binding_gate=None` permits claimed identity only in callable/test arrangements; production does not use that configuration. |

[Wire structure:213-220](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/p2p.rs#L213-L220)
contains responder index, request height/ID, optional responder height and
blocks, not a signed committed-height proof. The empty response is
deserializable even though the current honest request handler
[B:8403-8422](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L8403-L8422)
returns without sending when export is empty. Therefore regular request
servicing by this pinned implementation does **not** generate an empty
response. Its arrival needs another implementation, a deliberately sent
frame by a mapped peer, or a fixture; none was observed here.

Receipt ordering is exact: [B:6160-6188](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L6160-L6188)
increments saturating `inbound_msgs_received` and inbound `other` metric
before binding. A binding rejection increments
`inbound_sender_binding_rejected_total` and gate rejection metric, but not
response receipt/rejection. Successful binding increments gate acceptance
and `restore_catchup_responses_received`. Every non-empty bound response
then increments `restore_catchup_responses_rejected` once and returns:
**A17-F1 remains unchanged**, including bound self-labelled nonempty frames.
Only empties reach the helper. [B:8458-8477](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L8458-L8477)
first ignores self responses, already counted as received, without peer
tracking or transition. Claiming self from a non-self session fails binding.

Restore activity requires a configured baseline. [M:2883-2900](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/main.rs#L2883-L2900)
maps successful snapshot restore metadata height/hash into a baseline;
failed requested restore terminates startup. [B:2839-2851](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L2839-L2851)
seeds the fresh engine once; [B:3062-3073](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L3062-L3073)
starts mode/gauge active iff the baseline exists. Neither this initialization
nor transport authentication reconstructs QC/vote/signing history.

## 2. Exact empty-response state machine

The empty branch calls `evaluate_restore_mode_transition` and returns
**before** request-anchor checks or any import. Neither
`request_from_height` nor `request_from_block_id` is consulted. No outstanding
request, nonce, intended recipient, response freshness, quorum of responders,
or peer-height proof is checked. Request emission does not maintain an
outstanding-request ledger. Empty receipt itself does not change engine,
votes, QC, lock or commit height and performs no signing or outbound call.

Let `A` be active, `B0` snapshot baseline height, `L` optional local committed
height, `P` optional stored peer maximum, and `H` optional reported height.
The authoritative code is
[B:2368-2423](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L2368-L2423):

1. If inactive, return immediately: no maximum update, no rearm, no new exit.
2. While active, `Some(H)` sets `P = Some(max(previous P, H))`; `None`
   preserves `P`. This happens **before** missing-local-height refusal.
3. Exit iff `L` and resulting `P` both exist, `L >= P` and `L > B0`.
   Active state constructed from config always has `Some(B0)`. The
   conditional baseline check in the method does not create a reachable
   active-without-baseline production state.
4. Exit records `active=false`, `exited_at_height=Some(L)`. There is no
   timer/commit-only exit; a qualifying non-self response triggers evaluation.

| Empty response / prior state | Exact result while initially active |
|---|---|
| `H=None`, `P=None` | No target; cannot exit even with strict local progress. |
| `H=None`, existing `P` | Reevaluate against old maximum; can exit if local has since reached it and is above baseline. |
| `H<L` or `H=L`, no greater prior maximum | Exit only if `L>B0`; a lower claim need not even be above baseline. |
| `H>L` | Maximum rises to at least H; no exit at current L. |
| Lower/equal H after a previously higher P | P never decreases; no exit until L reaches the stored higher target. |
| `L=None` | Store a present H first, then remain active; no invented local height. Fresh restored binary starts with Some(B0), so missing L is a method boundary/fixture case, not normal restore initialization. |
| `L<=B0` | No exit for any report, including zero/lower/equal heights. |
| Repeated active responses | Receipt counters repeat; maximum is monotone. Repeated same/lower reports cannot lower target, but can trigger exit after independent local progress. |
| Initially inactive or post-exit responses | Receipt counters still repeat; non-self empty evaluation refreshes gauge to 0 but leaves P/exit record unchanged. Self early return does not run gauge refresh. No later inflated report rearms mode. |

[B:8558-8589](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L8558-L8589)
publishes active gauge and exit height on the single flip, with an exit log.
The loop refreshes metrics/progress after receipt. Counters/gauges are
observability, not authenticated recovery receipts. Comments calling this
"safe-exit" or requiring "peer-learned material" do not add a proof or origin
check: executable logic reads scalar committed height only. Likewise the
struct's "every received response" description is qualified by binding,
self, nonempty-guard and inactive early returns.

## 3. Where strict local progress can originate

The nonempty guard removes network suffix import at **this dispatch**, not
all engine progress. The loop creates a fresh uniform-validator engine and
seeds only the snapshot floor; it does not load an already progressed engine
or uncommitted suffix into that instance.
[E:2665-2693](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L2665-L2693),
[S:2055-2083](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-consensus/src/hotstuff_state_engine.rs#L2055-L2083)
seed `Some(B0)`, a parentless block without own QC, next view and fresh
latches; the restored anchor alone is not a new commit.

| Potential origin | Current integrated reachability and limits |
|---|---|
| Local leader ticks | **Source-established, not hypothetical:** [B:3224-3243](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L3224-L3243), and :3379-3397, call `do_leader_tick` regardless of mode. [B:3683-3766](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L3683-L3766) calls `try_propose` before forwarding authorization. [E:4060-4213](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L4060-L4213) checks leader, one-proposal-per-view and successor representability, registers a block, inserts a logical local self-vote, forms a QC/advances view if quorum is reached, and only then returns unsigned actions. Outbound suppression does not roll back these mutations. |
| Single-validator progression | With local validator 0, uniform set size 1, usable height/view headroom and enough ticks, local self-votes alone reach quorum; three certified descendants can commit the first block above B0. No outbound signer or nonempty import is needed for that local engine progression. The source has existing engine B5 controls at E:10979-11035 and loop control [B:9871-9914](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L9871-L9914); they are not newly executed evidence. This proves a progress origin, **not** the combined bound-nonself exit scenario. |
| Multi-validator ordinary Proposal/Vote | The engine has proposal ingestion/self-vote and received-vote -> QC -> commit routes. The deferral gate does not suppress every near-anchor proposal. But [M:8680-8710](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/main.rs#L8680-L8710), [B:3138-3146](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L3138-L3146) wire Required, no PV authority/current snapshot and no journal. Actual Proposal/Vote admission at [B:6245-6325](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L6245-L6325), :6735-6835 refuses before engine effects; presence of Timeout authority does not substitute. A single local vote in a uniform set of size >=2 is insufficient QC power. Canonically activated PV progress is a future wiring obligation, not current deployed reachability. |
| Timeout/NewView | Active mode blocks only local timeout emission, not inbound processing. Verified no-high-QC TCs can advance view and clear per-view latches, permitting another local leader step. [E:5184-5238](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L5184-L5238) applies view/possibly lock, **not committed height or own QCs**. It cannot replace the multi-validator vote quorum or certify three descendants. Present high-QC handling has the retained-proof/current-authority boundary below. A sequence of TC view jumps alone is not strict committed-height progress. |
| Direct suffix import / seeded engines | [E:3954-4047](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3954-L4047) remains callable and nontransactional. A17's progressed actual-handler empty fixture explicitly imports three logical-QC blocks **directly before dispatch**, bypassing no production rule because this is test setup. Helper stale/import/error branches remain callable characterization, but all nonempty actual network dispatches stop before them. No current binary caller of that import outside the guarded helper is established. |
| Restart APIs, snapshots, epoch transitions | Public restart/state APIs can establish other heights for library callers; this loop invokes only startup snapshot-baseline initialization. Periodic/signal snapshots export state, not increment this engine's floor. [B:9029-9129](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L9029-L9129) consumes already committed reconfig entries and retains the same validator set for epoch transition; it is not a second source of votes or height. `S.committed_height` assignments are in commit and restart/baseline initialization (:1922, :1999, :2063), not TC handling. |

Commit itself is not "height moved with time": [S:1784-1806](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-consensus/src/hotstuff_state_engine.rs#L1784-L1806)
attaches an own QC then invokes
[S:1830-1938](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-consensus/src/hotstuff_state_engine.rs#L1830-L1938).
The child, parent and grandparent must exist and have own QCs, views must
strictly increase, and grandparent height/view must advance the committed
anchor. Received logical vote processing and view advance are at
[E:4861-4940](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L4861-L4940).

**Do not combine incompatible configurations.** In production
[M:6192-6194](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/main.rs#L6192-L6194)
sets validator count to static peers + self and the builder enforces
certificate validator indices < that count. For size 1 the only in-range
identity is 0; a successfully bound response is self and ignored by the
local-0 helper. For size >=2 a bound nonself is possible, but the current
fresh-engine/Required/no-PV wiring supplies no source-established
multi-validator strict progress route in this trace. The no-IO path can
progress locally but has no receiver/facade
[B:2908-2934](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L2908-L2934).
An actual progressed multi-validator deployment needs separately evidenced
wiring/state history; the fixture is not that evidence. None of these limits
licenses the broader assertion that the A17 guard prevents all local progress.
The exact absent-effective-PV refusals used by current production are
[B:6422-6440](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L6422-L6440)
and
[B:6883-6903](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L6883-L6903);
the earlier current-snapshot checks independently refuse a supplied PV
context without an admitted snapshot under Required.

## 4. Active versus inactive: effect and remaining gates

Only the three mode-dependent control decisions below change; mode exit
does not grant authority or run a signer. Other decisions continue in both
states. The actual loop calls are [B:3224-3345](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L3224-L3345)
and :3379-3500.

| Decision/path | Active / inactive effect | Remaining checks and current binary limits |
|---|---|---|
| Catch-up request emission | Active permits cadence; inactive stops fresh requests. | [B:8353-8387](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L8353-L8387): ticks % 10 == 1, local committed height and block ID, outbound facade and successful broadcast; sent count only on success. No PV snapshot or consensus signer gate here. Mode change does not cancel already sent requests. |
| Proposal deferral | Active defers height > committed+1, or height == committed+1 with wrong committed parent. Inactive removes **only this** deferral. Missing local height does not defer. | [B:6571-6583](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L6571-L6583), :8390-8401: decode, origin binding, admitted current PV snapshot/epoch, domain/signature/suite/key/membership and applicable embedded-QC evidence/correspondence/budget plus pre-effect freshness precede deferral. Engine leader/view/epoch/safety/latch checks and outbound controls still follow. Current production rejects PV earlier, in either mode. |
| Local view timeout | Active suppresses timeout eligibility. Inactive removes that single suppression, not the other gates; the next tick need not emit. | [B:7550-7838](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L7550-L7838): progress observation first; view/commit progress returns early, committed progress resets backoff. Configured valid threshold, outbound facade, unconsumed per-view timeout latch, inclusive elapsed tick window and valid successor needed. Defaults: base 50 ticks, capped backoff 800; invalid backoff disables with warning. No automatic timer reset merely on mode exit. |
| Timeout signing/consumption/publication | Not invoked by empty handler; potentially reachable later after timeout eligibility. | Context/signer presence, local signer==engine ID, governed key/suite/backend and u8 suite representability; engine-created timeout identity; F7 high-QC admission and confirmation; chain-aware signer success; local signature verification; serialization; second F7 confirmation; then mark latch, ingest, broadcast. Sign/verify/encode refusal precedes latch/ingestion. Broadcast failure can occur **after** local ingestion; success count/backoff increase only on broadcast success. PV journal guards must not be incorrectly attributed to this distinct timeout signer route. |
| F7 retained high-QC, all Timeout/TC consumers | Same checks in either mode. | [B:1537-1622](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L1537-L1622), :1490-1511: **absent QC** admits NoQc, including without current PV authority. **Present QC** requires current coherent snapshot/ticket, matching engine/timeout membership, epoch/chain, unambiguous retained proof within scan/working-set/retention bounds, domain re-verification and pre-effect confirmation. Production passes no current snapshot, so present QC is refused. Empty mode exit changes none of this. |
| Inbound Timeout and NewView | Active does not defer/suppress; inactive same. | [B:6962-7148](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L6962-L7148), :7150-7350: frame cap/limited decode; Timeout sender binding, NewView origin-only binding; required context, signed Timeout/TC evidence verification (chain/suite/key/member/quorum/correspondence); F7 admission/confirmation; engine accumulator/TC validation. No mode condition here. Inbound Timeout quorum can form/apply/broadcast NewView even while restoring. |
| Local TC/NewView publication | Same in both modes, reached after verified timeout ingestion forms TC. | [B:7898-8006](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L7898-L8006): signed-evidence TC verification, F7 admission/confirmation, engine TC validation/application, facade, encoding and successful broadcast. No additional NewView signer invocation; it carries constituent signed timeouts. Engine apply precedes publication, so missing facade/encode/send failure does not undo it. Direct inbound NewView applies without this rebroadcast helper. |
| Leader step and PV forwarding | Leader construction/self-vote/cache updates continue in both modes. | Leader/view/latch/successor and local engine quorum/commit checks above. [B:5818-6047](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L5818-L6047): forwarding requires facade, current admission/epoch, exact bound signer and original ticket, guarded signing, final freshness confirmation and broadcast/directed-send success. Production no-current-snapshot refusal occurs before signing, but after leader engine effects. |
| Guarded Proposal/Vote signing | Same in both modes; not authorized by exit. | [B:4371-4474](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L4371-L4474), :4598-4950 (Proposal), :4951-5300 (Vote): context/signer and wire-chain; mandatory journal/Required admission; supported wire version, original view/round/step, signer identity/membership, governed suite/key/backend, exact decision/domain binding; exclusive durable reservation or validated retained resend; conflict/uncertain/exhausted/error refusals; frozen-context/original-ticket revalidation after journal; signer success and result publication, then pre-facade freshness. These local guards do not prove global signer exclusivity or authenticated recovery. |
| Late-peer PV re-emission | No mode gate: considered on both active/inactive ticks. | [B:3850-4129](https://github.com/olivexo28/QBIND/blob/2d3b2f7a4c4055882525e3af1814d57e87c01c76/crates/qbind-node/src/binary_consensus_loop.rs#L3850-L4129): wired connectivity, newly connected transition, cached matching-view proposal, local current leader, commit below cached view, per-view latch, facade; original cache provenance/current admission/epoch; guarded journal/signing and pre-facade confirmation, paired vote coherence. Production caches no authorization provenance and supplies no snapshot/journal; Required refuses publication. |
| Request servicing and response import | Mode does not control servicing; inactive still receives stragglers. | Request origin/claimed requester, receipt count, nonself, facade, export above matching requested anchor and nonempty export, send success. Empty incoming responses remain scalar mode observations; every nonempty incoming response stays refused in both modes before helper, independent of authority/self/anchor/configuration. |
| Metrics, snapshots, reconfiguration, shutdown | Continue in both modes; exit is not a loop shutdown or resume token. | Post-receipt/tick state metrics/progress and configured periodic snapshots still run; snapshot enabled/directory/interval/runtime/anchor and per-height duplicate checks remain. Committed reconfig validation, sequential epoch engine checks and storage persistence failures can terminate loop. Shutdown signal, max_ticks cap and inbound-channel closure handling are unchanged. Mode exit does not mutate epoch/storage/keys/authority, repair signing history, or persist/clear quarantine. |

## 5. Consequences of lower, equal and inflated bound claims

Authentication at ingress establishes the session sender as a configured
one-to-one certificate-bound validator, subject to the actual transport and
configuration checks above. It does **not** prove responder honesty,
committed-height accuracy, chain agreement at that height, quorum endorsement,
snapshot currentness, a response to our request, recovered anti-equivocation
history, exclusive signer ownership, or authority to clear/resume.

**Lower/equal:** a bound nonself empty report can cause the scalar flip if
mode is active, local L exists and is strictly above B0, and the resulting
global maximum is <=L. A lower/equal response does not erase a greater
previous maximum. The first such response can make the node stop requests,
remove proposal deferral and allow the timeout eligibility check, even if
an unobserved honest peer/network is further ahead or local progress was
not authenticated recovery. "Premature" here is relative to that separately
established recovery/currentness obligation, not a violated predicate of
the implemented scalar rule. Without strict progress, or without a bound
nonself session, this exit consequence is unsupported. The current
production configuration coexistence limits in section 3 must not be
discarded when making an exploit claim.

**Inflated:** a bound nonself empty `Some(H)` above local height raises the
single global target while active, even at baseline and without any
outstanding request. No strictly progressed local state is needed to
establish this target poisoning. Other responders' lower/equal reports
and `None` cannot reduce it. Mode stays active until local height reaches
that maximum and exceeds baseline; there is no expiry, peer removal,
quorum aggregation, per-peer correction or manual clear in this state
machine. An unreachable target, e.g. a very high u64 with insufficient
engine headroom, can prevent mode exit for that loop lifetime. Already
inactive responses cannot poison/rearm it.

This supports a **mode-exit/availability risk conditional on bound receipt**,
not proof of newly stalled authenticated consensus: at baseline in the
current multi-validator binary, PV authority already prevents ordinary
quorum progression, and nonempty suffix imports are already contained.
If an independently evidenced progressed instance would otherwise exit,
inflation preserves request emission/deferral/local-timeout suppression.
It does not suppress leader ticks, inbound TC/NewView handling, or grant
finality to an arbitrary block. Removing that scalar mode barrier would
still not bypass Required PV or present-high-QC refusal.

Repeated active claims have no extra engine/signing effect but do repeat
receipt accounting and transition evaluation. A later lower claim cannot
repair earlier inflation. No live peer, deployed config, revision, timing
trace, signer run, network disagreement or arbitrary-finality consequence
was exercised in this task.

## 6. Narrow next review boundary, not implementation

**Review additional containment at the actual bound-empty dispatch before
any peer-height tracking/mode transition.** A conservative candidate is
refusing empty responses as recovery/mode-clear inputs while positive
recovery and explicit resume authority remain absent. Review rather than
activate it: keeping restore active would retain request attempts and
proposal deferral and suppress local timeout eligibility indefinitely;
it would remove the existing scalar exit/liveness behavior (including
fixtures/other integrations that relied on it). Honest empty reports are
not generated by the pinned request responder, but compatibility with
other implementations is unresolved. Merely validating request anchor or
adding an outstanding request would not authenticate reported height or
authorize recovery; caps/expiry/quorum hints are not positive proofs either.

Minimum future assessment controls, **FUTURE / NOT EXECUTED here**:

| Control | Evidence needed, beyond the retained unchanged A17 tests |
|---|---|
| Actual-handler matrix | Real `handle_inbound_consensus_msg`, present production-equivalent binding gate/origin, supplied recording facade and shared protected-state checker. Bound nonself empty with H None/0/lower/equal/higher/u64::MAX; old P None/lower/higher; L missing/baseline/above; self; initially inactive and repeated pre/post-exit responses. Explicitly mismatched request anchors and no outstanding request. Check receipt/binding/rejection counts separately from engine/mode/max/outbound effects. |
| Non-vacuous controls | Preserve nonempty unconditional refusal including self/stale/authority/configuration variants; mismatched/missing/unknown origins fail binding. Old behavior must show mode-only exit and inflation where predicates are satisfied, so a future no-effect assertion is sensitive. Seeded progress/direct-import fixtures must remain labelled test-only; also use local leader progression to characterize a real source progress route without pretending size-1 has an admissible nonself peer. |
| Downstream tick controls | Compare active versus exited states for request cadence/anchor/facade, proposal authority before deferral, near/far/wrong-parent proposals, leader engine mutations versus suppressed PV publication, late-peer cache/provenance/latches, timeout elapsed boundary and progress reset/backoff. Assert absent signer/context/authority/journal and wrong chain/epoch/suite/backend failures, plus recording-facade send failure. |
| Separate Timeout/F7 controls | No-high-QC versus present high-QC; Required missing current snapshot, retained-proof/currentness/working-set refusal; verified TC view-only effects while restore active; local timeout sign/verify/encode/latch/ingest/send ordering and TC apply-before-publication. A signer-eligible control requires separately authorized bounded test fixtures, not operational keys or live-node activation. |
| Positive recovery/resume obligations | Positive chain/QC/committed-prefix recovery; authenticated currentness/freshness; recovered signing-history continuity; signer exclusivity; durable quarantine ownership/lifecycle; independently authorized clear/resume. Each needs its own actual caller, authority, durable state/effect and refusal evidence. Transport identity, scalar height, a local journal, mode flip or one successful signing operation cannot stand in for these separate obligations. |

**Unresolved from source alone:** deployed session/configuration eligibility;
whether an actual progressed multi-validator node at this revision has a
non-fixture progress history; external implementations' empty-response usage;
real availability improvement/regression; global currentness and signer
exclusivity; durable quarantine/clear authority. Resolution needs pinned
runtime/configuration and provenance evidence, independently authorized
actual-handler/downstream acceptance controls and distinct recovery/security
contracts, not speculation or a network experiment in this task.

## Integrity and publication

`CHANGED_PATHS.txt` enumerates the complete five-path documentation-only
delivery, including the append-only plan and the manifest itself.
`SHA256SUMS` hashes the other four changed paths (plan included), deliberately
excluding its own bytes. `documentation-checks.log` records the exact base,
source/audit hashes, byte-prefix and unchanged-baseline scope checks,
historical-manifest verification, pinned-reference/local-link checks,
UTF-8/LF/EOF checks for new prose, staging inventory and whitespace check
commands/outcomes. Historical paths, the audit register and prior plan bytes
remain unchanged; raw earlier logs are not normalized.

Unsuccessful attempt in this task: an explanatory follow-up `apply_patch`
included a nonexistent trailing context line (`documentation checks.`) and
was rejected before applying any change. The corrected patch succeeded.
Initial guessed builder/transport filename searches returned no matches;
the subsequent actual paths were located and read. An unset
`core.autocrlf` query returned exit 1 (no value), not a validation failure.
The first documentation-validator command used `python`, which is not
installed under that name; it exited 127 before any assertions ran. Its
diagnostic is retained in `documentation-checks.log`; the retry uses
`python3`. These are not test failures or successful security acceptance cases.

Final commit/tree/parent, manifest hash, direct remote task/main refs and
worktree/staging state are reported after publication rather than embedded
self-referentially here. Only this investigation branch is committed/pushed;
no merge, main push, PR, force push or activation is authorized.

## Frozen-main continuation

The initial task correctly stopped when direct remote `main` moved. On
continuation the frozen direct ref was verified twice as
`541d9a6c9a43fe10410260d9c2494a5fc4416c7a`, tree
`0b0e597a29dc8f2d95d93f9bd04364cc140a9db1`. Its parent is the original
expected base `2d3b2f7a4c4055882525e3af1814d57e87c01c76`, with merge parent
`9ef29e2432b9b84fca63e59440d64d085631e9a3` (PR #8 containment history).
The old commit is an ancestor; both trees are exactly
`0b0e597a29dc8f2d95d93f9bd04364cc140a9db1`; `git diff --quiet` on the two
trees returned 0. Pinned source links above use the old commit because the
new merge has the exact same full tree; the current branch was fast-forwarded
to the new frozen commit before further edits, preserving the unstaged drafts.
Prior A17 implementation and acceptance-control review dispositions are
user-supplied PASSED/CLOSED within their scopes, not a new independent
review disposition for this investigation.

Draft-byte verification was done before modification. The plan
(`c43010529615ab74f1b073c93ffe0db159b7604fb9350c118958ec29f882c799`),
README (`5b1d33ede4d90db19840fa305dfec14dd9dfdbe4ea3c9b6ec6dd4a17adc5e455`)
and changed-path list
(`2d5f2bbbbfde48758afb6bb4bcb049142655388400ee271bd74ebd75d1f980ec`)
matched the stopped-task report. The initial diagnostics log also matched its
reported SHA-256
(`110925ee8e20e418fc288d64bee7a2dfbd1a2739b84214bb84da6fed319c8863`)
before this continuation appended further checks. These hashes identify the
prior draft version, not the final committed bytes. All added diagnostics
preserve the earlier log as a byte prefix. Exact continuation identities,
commands, success/failure status and any command transcription correction
are recorded in `documentation-checks.log`; no historical evidence file was
rewritten.
