# Catch-up ingress resource boundary

**CATCH-UP INGRESS RESOURCE BOUNDARY — INDEPENDENT REVIEW PENDING.**

This is a documentation-only source investigation pinned to protected main
`9bf0eb43e4e3c601d02d3886d220b0abeb3a103e`
(tree `56509b20084ee1cbe2c42fda9d73d87e4c82c33f`). The inspected transport,
wire-type, inbound-dispatch and builder files at the task base were byte-for-
byte identical to that pinned main. All source links below use the pinned
main revision, not this task branch. No source or test code was changed, and
no Rust tests, builds, node, or network were run.

Pinned source map:

- [Transport ciphertext cap](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-net/src/framed_io.rs#L17-L22) and [frame size check/allocation](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-net/src/framed_io.rs#L113-L139)
- [Secure-channel counted frame read, decryption, and reader queue](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/secure_channel.rs#L219-L230) and [recv_app](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/secure_channel.rs#L547-L575), [queue capacity](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/secure_channel.rs#L825-L840)
- [Application-frame deserialization](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L181-L205), [inbound queue](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L848-L854), [listener and connection-rate check](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L1229-L1335), [handshake/origin resolution](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L1372-L1490), [per-peer worker queues](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L1827-L1870), and [read/decode/limiter/origin enqueue ordering](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L2213-L2285)
- [Catch-up response schema](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p.rs#L183-L218), [origin-carrying demux](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_inbound.rs#L367-L390), and [caller-sized consensus queue](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_inbound.rs#L467-L515)
- [Builder origin resolver and deployed limiter installation](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_node_builder.rs#L1580-L1675) and [limiter-before-start setup](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_node_builder.rs#L1720-L1755); [default peer message thresholds](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/peer_rate_limiter.rs#L63-L100)
- [Binary inbound accounting and sender binding](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L6102-L6170), [actual catch-up response guard](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L7398-L7438), [outbound-only 128-block limit](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L248-L248) and [its use](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L8420-L8458)

The accepted three P1 composition resource-ordering controls at task-base
commit `ad72aae3b0be5c3c5279463e5ceaf5e0e23d4702` remain accepted within
their test-only scope. They observe provider/evidence operations after the
test caller has allocated inputs and assembled borrowed references; they do
not model or bound transport-frame allocation, deserialization, concurrent
sessions, or deployed ingress. This investigation neither repeats nor
supersedes those controls. It also does not repeat the accepted A33-F1/E27
owner/lease review: those records are historical design evidence only, not a
production catch-up gate.

## 1. Actual ingress ordering

The network path is:

1. `TcpListener::accept` admits a socket and starts a handler task. The
   optional connection-rate limiter is consulted here, before KEMTLS. There
   is no source-visible maximum active inbound-connection count on the
   accept loop; it continuously spawns into a `JoinSet`.
2. The handler completes `SecureChannel::from_accepted_with_peer_init`,
   resolves the listener-side session identity, and (where configured)
   derives `AuthenticatedConsensusOrigin` from the handshake's verified
   identity. It then starts peer workers. These operations establish
   transport/session context before application messages arrive, but do not
   inspect a response's variable-length fields.
3. `SecureChannel::recv_app` reads one encrypted transport frame. The
   five-byte transport header declares ciphertext length. The reader rejects
   lengths greater than 16 MiB before allocating the ciphertext-frame `Vec`;
   it then reads and decrypts the frame, producing a plaintext application
   `Vec`. No separate application-plaintext or `P2pMessage` byte budget is
   visible at this point.
4. `read_loop_inner` receives that plaintext `Vec`, updates byte accounting,
   routes the peer-candidate discriminator if applicable, then calls
   `decode_frame`. That function checks the application framing header and
   declared payload extent, takes the payload slice and calls
   `bincode::deserialize::<P2pMessage>`. This is where the response's
   `blocks: Vec<_>` and each block's `qc_signer_indices: Vec<u16>` are
   materialized. `RestoreCatchupResponse` has no serializer-level count or
   per-field length cap in its type definition or this call site.
5. Only after successful full `P2pMessage` decoding does the optional
   deployed per-peer message-rate limiter run. It is a message-count limiter,
   not a byte, nested-count, or allocation bound. The decoded message and the
   connection's in-process origin are then enqueued in the transport-wide
   inbound channel. The origin is not read from or replaceable by payload
   fields.
6. `P2pInboundDemuxer` routes the decoded consensus message and origin to the
   consensus handler. The handler uses `try_send` into a caller-sized
   consensus channel; if that queue is full or closed, it logs and drops the
   already-decoded message.
7. `handle_inbound_consensus_msg` increments its general inbound-message
   statistic and inbound-other network metric before dispatch. For a catch-up
   response, it then binds the payload's `responder_validator_index` to the
   authenticated origin when a binding gate is installed. A binding refusal
   increments the binding-rejected counter and returns. Only an admitted
   response increments `restore_catchup_responses_received`.
8. The actual dispatch refuses every admitted non-empty response and returns
   before the import helper, peer-height tracking, restore-mode transition,
   or engine application. An admitted empty response increments the
   empty-ignored counter and returns before those same effects. It does not
   call `handle_restore_catchup_response`; that separate helper's empty
   response transition behavior is not the actual dispatch behavior.

Thus sender binding is later than transport receipt, decryption, application
frame parsing, full bincode deserialization, decoded-message rate limiting,
and queueing. It is before catch-up response receipt accounting and either
containment guard. A transport-authenticated responder and individually
authenticated endorsements are distinct notions: this wire response carries
logical signer indices, not QC signature bytes, and the catch-up dispatch
currently refuses non-empty responses regardless.

The transport origin is configuration-dependent. The inbound origin resolver
is optional at the transport API; the builder installs it only with the
binding gate, and it returns no origin unless mutual authentication completed,
verified client identity fields exist, and the authoritative node/validator
map accepts that pair. The source trace does not establish a particular live
deployment's mutual-auth, trust-root, network-reachability, or adversary
configuration. It therefore does not claim that arbitrary unauthenticated
Internet senders can reach this decoded path. Kernel socket buffers and
allocator/OS accounting are also outside the source-level byte bounds
identified here.

### Effects while restore mode is active

The response-specific effects before return are bounded to transport byte
accounting, limiter accounting if a decoded frame is rate-limited, general
inbound-message/network metrics, binding-rejection accounting when binding
fails, and—after successful binding—response received plus either rejected
non-empty or ignored-empty accounting. An admitted non-empty response does
not reach peer-height/mode effects or engine import. An admitted empty
response does not establish that the node is caught up and does not change
restore mode. Restore mode can therefore remain active indefinitely if no
other code changes its state. This is not a complete engine, worker, or
signer fence; it describes only this response dispatch.

## 2. Bounds and enforcement stages

| Resource / condition | Source-backed control | What it does not bound |
|---|---|---|
| Encrypted transport frame | `MAX_TRANSPORT_CIPHERTEXT = 16 * 1024 * 1024`; length checked before the transport frame buffer allocation | Aggregate bytes across sessions, application deserialization allocations, or an independently configured smaller catch-up budget |
| Application P2P frame | `decode_frame` checks minimum header and that declared payload extent is present, then deserializes | No explicit `P2pMessage` byte/count limit before deserialization; it is reached only after ciphertext read/decryption |
| Catch-up nested data | `Vec<RestoreCatchupBlock>` and each `Vec<u16>` are deserialized from payload | No source-visible inbound max block count, signer count, or per-field count |
| Transport inbound queue | Capacity 256 decoded envelopes | Item count only, not retained byte capacity; messages are already fully decoded |
| Secure-channel reader queue | Capacity 32 plaintext results per secure channel | Item count only; no aggregate bound across sessions |
| Consensus forwarding queue | `ChannelConsensusHandler::new(capacity)` receives a caller-supplied capacity and uses `try_send` | No single fixed production capacity is established by this API; no byte budget |
| Per-peer inbound rate | Builder installs the deployed limiter before service start; defaults are 1,000 messages/s plus burst 100, with validated override support | It runs after full decode and limits messages, not bytes or concurrent connections |
| Connection-rate limiter | Optional, if runtime abuse/DoS config enables it; consulted on accept before handshake | It is not a maximum-active-connections semaphore or resource bound; configuration/reachability is deployment-dependent |
| Outbound catch-up response | `RESTORE_CATCHUP_MAX_BLOCKS_PER_RESPONSE = 128` is passed to outbound export | It is not an inbound response cap and must not be used as evidence of one |

The 16 MiB transport cap limits the length of one ciphertext frame before
that frame's buffer allocation. The plaintext is derived only after reading
and decrypting that frame. No separate application-level size limit is
visible. The exact allocation behavior of bincode for hostile vector
lengths, allocator failure behavior, and aggregate memory under concurrent
sessions were not measured here; this report makes no exploitability or
remote-denial-of-service claim. The secure-channel worker uses socket read
timeouts and invalidates a session if a framing read fails after consuming
bytes, but source inspection does not establish a total wall-clock deadline
for a peer that continues making read progress.

The fixed channel capacities bound queued *items*, not the bytes retained by
those items. The accept loop has no fixed concurrent-session cap in the
inspected source. A connection-rate bucket may reject connection bursts when
enabled, but a rate threshold is not an active-connection ceiling.

## 3. One bounded next correction (proposal only)

**Proposed boundary:** a reviewed bounded decoder at the existing
`read_loop_inner` application-frame handoff, immediately before
`decode_frame` invokes bincode. The input is the actual borrowed decrypted
application-frame byte slice and the connection/origin context already held
by the read loop. At this boundary, encrypted ciphertext framing, ciphertext
allocation, decryption, and allocation of the plaintext application `Vec`
have already happened. A guard here cannot prevent any of those allocations.

The design review should establish a deployment-supported byte budget before
selecting numeric thresholds. The decoder should first validate actual
available frame bytes with checked arithmetic and reject a frame exceeding
the reviewed application-byte budget. If the review also requires specific
catch-up block or signer-index limits before vector materialization, the
same pre-deserialization boundary must parse those encoded lengths without
allocating response vectors, using an encoding-accurate bounded decoder or
scanner. A claimed count/length is not a substitute for checking remaining
actual bytes. Do not add a scanner that silently disagrees with bincode's
encoding or report a standalone scanner test as deployed ingress
enforcement.

Malformed, truncated, overflowed, structurally inconsistent, or over-budget
input should be refused before bincode materializes response vectors. A
source-compatible rollout can preserve the existing close-on-decode-error
policy; it should use a bounded reason counter and bounded diagnostic (no
peer-controlled full payload/length formatting). Keep rate-limit drops
distinct from malformed/size refusals. Honest empty responses remain
admitted to the existing empty-ignore behavior when within budget. Honest
non-empty responses remain unconditionally refused by consensus dispatch;
this proposal does not authorize applying them. Oversized honest messages
would be disconnected, so threshold selection carries a liveness and
compatibility cost and must be justified by measured valid traffic.

This per-frame boundary would not cap concurrent sockets, handshake work,
total bytes retained by the 32/256-item queues, caller-sized consensus
queues, total decoder CPU, or aggregate cross-peer memory. Those need
separate measured budgets and controls; do not imply this correction closes
them. The existing optional connection-rate limiter and post-decode
per-peer message limiter remain distinct layers.

## 4. Future acceptance matrix

All rows below are **FUTURE / NOT EXECUTED**. This task ran documentation
and source-integrity checks only; it did not run Rust tests or builds.

| Stage | Required future evidence | Status |
|---|---|---|
| Scanner/decoder unit controls | At-limit and one-beyond actual byte inputs; count and nested-length caps; malformed/truncated encodings; checked-add overflow; no response-vector allocation before refusal; restored valid decode | FUTURE / NOT EXECUTED |
| Sensitivity at the proposed real boundary | Exercise the actual pre-bincode entrypoint; prove over-limit and malformed fixtures are refused there, and a bypass/mutant that proceeds to bincode is detected by the same oracle | FUTURE / NOT EXECUTED |
| Dispatch regression | Valid empty response still reaches existing ignored outcome; valid non-empty response still reaches unconditional refusal; neither changes peer progress, mode, engine, or outbound actions | FUTURE / NOT EXECUTED |
| Transport integration | Drive a bounded encrypted frame through actual `SecureChannel` and `read_loop_inner`; demonstrate framing/decrypt limits are earlier than the proposed application guard and count actual-stage outcomes | FUTURE / NOT EXECUTED |
| Restart/crash and ownership | Not applicable to a pre-deserialization guard alone; any future recovery/application/resume proposal needs separately reviewed crash, durability, and owner/fencing evidence | FUTURE / NOT EXECUTED |
| Multi-peer/resource sensitivity | Concurrent sessions, bounded and saturated downstream queues, memory/CPU budget, cancellation, and slow-progress behavior under the proposed operational limits | FUTURE / NOT EXECUTED |
| Release binary/configuration | Show the guard is wired on every deployed inbound route and that release configuration cannot silently disable or bypass it | FUTURE / NOT EXECUTED |

The only retained executions pertinent here are earlier, specifically
attributed test-only P1 composition/resource-ordering controls. They do not
exercise the production ingress boundary and are not counted as evidence for
any row above.

## 5. Open scope and disposition

No inbound threshold is selected. No scanner, decoder, network gate, response
format, catch-up application, cryptographic authority, currentness mechanism,
signer fence, or resume authority is implemented or selected. B/C and
production P1/P2 remain unselected. The source path's current non-empty
refusal and empty-response ignore are unchanged.

A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
