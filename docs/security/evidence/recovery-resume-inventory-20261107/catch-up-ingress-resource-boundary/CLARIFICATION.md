# Catch-up ingress inventory clarification

**CATCH-UP INGRESS INVENTORY CLARIFICATION — INDEPENDENT REVIEW PENDING.**

This append-only clarification incorporates the user-supplied review of
commit `2cafa1b21365e99d95aa0c759dd2dd90fa1e43af` (tree
`cfd10f254f1205070deb2c377336670ea660e305`, parent
`ad72aae3b0be5c3c5279463e5ceaf5e0e23d4702`). The central ingress ordering
and proposed review boundary remain **PASS WITH LIMITATIONS**; these
documentation clarifications were OPEN. Earlier bounded acceptances remain
unchanged. This is source/arithmetic reasoning, not a reproduced panic,
exploitable condition, or production reachability finding.

The prior source/hash/preservation checks and results recorded in the
original `COMMANDS.txt` and `integrity.txt` are historical author evidence.
They were not independently rerun for this clarification. No Rust tests or
builds, node, or network activity were run. All proposed ingress controls
remain FUTURE / NOT EXECUTED.

## 1. Declared-length arithmetic and reachability

The pinned-main application decoder at
[`p2p_tcp.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L181-L201)
reads an inner `u32` payload length, converts it to `usize`, checks
`frame.len() < 5 + len`, then slices `frame[5..5 + len]`. Those additions are
unchecked. The raw transport decoder at
[`transport.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-net/src/transport.rs#L49-L66)
has the analogous `buf.len() < 5 + len` and `buf[5..5 + len]` operations.
The receive helper's separate header parser is at
[`framed_io.rs`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-net/src/framed_io.rs#L113-L139).

These are different boundaries:

- The normal socket receive path reads an outer transport header and rejects
  ciphertext lengths above `MAX_TRANSPORT_CIPHERTEXT` (16 MiB) before
  allocating its transport-frame read buffer. It subsequently decodes the
  just-read buffer as a `TransportFrame`; the frame is bounded by that cap.
  `SecureChannel::recv_app` then re-encodes the actual `TransportFrame`
  ciphertext length to pass it to `Connection::decrypt_app`. The outer
  receive cap therefore constrains those outer transport-frame lengths.
- The decrypted plaintext is itself a P2P application frame with its own
  discriminator, `u32` declared payload length, and actual byte slice.
  `decode_frame` performs its unchecked `5 + len` expression on that inner
  declaration. The outer ciphertext cap does not validate the inner
  declaration against the available plaintext bytes before this expression
  is evaluated.
- `TransportFrame::decode` is also a public raw-buffer helper. Direct callers
  to it, and other call paths into raw transport decoding, are separate
  boundaries. This investigation did not exhaustively assess them or claim
  that every such caller receives a length already checked by
  `read_transport_frame`.

On a 32-bit target, a `u32` length can convert to the full `usize` range.
When the value exceeds `usize::MAX - 5`, `5 + len` overflows. With integer
overflow checks enabled, this addition panics. With checks disabled, Rust
integer addition wraps modulo the integer width. For the overflowing
`u32`-to-`usize` values on a 32-bit target, `len + 5` then wraps to an end
offset below the five-byte header; the length comparison may pass for an
already-header-sized buffer, after which the `5..end` slice range is invalid
and panics. These are conditional consequences of the source expressions,
not observed runtime behavior. No such input was executed.
Supported 32-bit targets, target-specific compilation, deployed
`overflow-checks` settings, and actual attacker/reachability conditions are
**UNKNOWN / NOT ESTABLISHED** by this source investigation. The 16 MiB outer
cap does not eliminate the separate inner-header condition.

A future guard must inspect the actual borrowed decrypted application frame
and safely establish the payload endpoint **before** the current
`decode_frame` evaluates either unchecked endpoint expression, or replace
that parsing path with an equivalent reviewed bounded parser. A check placed
after `decode_frame`'s endpoint arithmetic but before bincode is too late.
The same principle applies if raw `TransportFrame::decode` callers are
included in a future scope: validate actual buffer extent with safe
arithmetic before using its endpoint, or replace the parsing path. No
threshold or guard is selected here.

## 2. Source-visible transport copies

The normal receive path creates these source-visible buffers, in order:

1. `read_transport_frame` allocates a `Vec` for the five-byte header plus
   ciphertext after checking the 16 MiB ciphertext limit.
2. `TransportFrame::decode(&buf)` copies the ciphertext slice into the
   returned `TransportFrame`'s `Vec`. The input read buffer is local to
   `read_transport_frame`; it is not the returned ciphertext vector.
3. `SecureChannel::recv_app` calls `frame.encode()`, producing another
   length-prefixed `Vec` from the actual decoded ciphertext length.
4. `Connection::decrypt_app` calls `TransportFrame::decode(frame_bytes)`,
   which copies ciphertext a second time into a new `TransportFrame` before
   checking the application message type and opening the AEAD frame.
5. AEAD opening returns the plaintext application `Vec`, which then passes
   to `read_loop_inner` and the P2P application decoder.

The re-encoding in step 3 uses the actual `TransportFrame.ciphertext.len()`
already admitted by the outer receive cap; it is not the hostile inner P2P
application length. The inner header is inspected only after AEAD opening.

Pinned links: [`read_transport_frame`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-net/src/framed_io.rs#L113-L139),
[`TransportFrame::decode` and its ciphertext copy](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-net/src/transport.rs#L49-L66),
[`SecureChannel::recv_app`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/secure_channel.rs#L547-L575),
and [`Connection::decrypt_app`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-net/src/connection.rs#L396-L428).

These are code-visible buffer creations/copies, not a measured peak-memory
profile. The call structure shows the encoded-frame argument remains present
while `decrypt_app` parses it; allocator capacity/over-allocation, exact
allocator reuse, backend scratch space, plaintext lifetime overlap,
subsequent queue retention, concurrent sessions, and aggregate process
memory were not measured. The 16 MiB limit is a per-ciphertext-frame length
limit, not a peak-memory or cross-session memory bound.

## 3. Superseding effects wording

The original inventory's sentence that response effects are “bounded to” a
listed set of counters was too exhaustive. Read that list as examples, not
as a complete effect inventory. Before the actual response guard, the source
also records demultiplexing consensus-message metrics, binary inbound
message/network metrics, transport byte accounting, and can emit diagnostic
logs for decode errors, sender-binding rejection, and response refusal.
Limiter outcomes can add their own drop accounting. See the pinned
[`P2pInboundDemuxer::handle_envelope`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_inbound.rs#L367-L390),
[`read_loop_inner`](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L2213-L2290),
and [binary ingress accounting and response dispatch](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L6102-L6170).
The prior central containment claim remains: actual dispatch refuses
admitted non-empty responses and ignores admitted empty responses before
peer-height, engine-application, and restore-mode effects. This statement
does not claim those are the only observable effects. The response-specific
guard is at [binary dispatch](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L7398-L7438).

## 4. Source-count correction and retained status

The original command note said “seven ingress source paths” although the
checker enumerates and compares nine source files. The superseding command
correction in `COMMANDS.txt` is **nine inspected source paths**. The original
record remains untouched as historical evidence.

The user-supplied **PASS WITH LIMITATIONS** remains scoped to the central
ordering and proposed review boundary. Arithmetic, copy-sequence, effect
wording, and path-count clarifications are now documented; no production
resource guard or test-only ingress scanner was run. Existing source/hash/
preservation check results remain attributed to the original author
execution, not to independent execution. Every proposed scanner, actual
ingress, transport, multi-peer/resource, and release-binary acceptance case
remains **FUTURE / NOT EXECUTED**.

A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
