# Application-frame checked endpoint

**APPLICATION-FRAME CHECKED ENDPOINT — INDEPENDENT REVIEW PENDING.**

This narrow correction changes the real application decoder at
`crates/qbind-node/src/p2p_tcp.rs::decode_frame`. It computes the declared
payload endpoint with `usize::checked_add(5)` before comparing frame length
or slicing. An unrepresentable endpoint returns
`P2pTransportError::Encoding("frame payload length overflow")`; a
representable endpoint beyond the actual frame retains the
`P2pTransportError::Encoding("frame truncated")` refusal. The existing
five-byte header check, bincode decoder, and discriminator/type match remain
in place.

The tests call `decode_frame` itself for short and truncated frames, a tiny
frame declaring `u32::MAX`, representative consensus/DAG/control messages,
discriminator mismatch, and appended bytes after the declared frame payload.
The latter remain ignored because the decoder slices only the declared
payload and does not require the frame slice to end there. A separate
`usize::MAX` test exercises the same checked-endpoint helper's overflow
branch. On the available x86_64 host, this is a helper-level arithmetic
control: the production decoder's u32 length plus five is representable, so
the tiny `u32::MAX` production-decoder test reaches the ordinary truncated
frame error. No native 32-bit target is installed; production 32-bit
execution was NOT RUN.

The source-level motivating application expression was pinned at protected
main [`p2p_tcp.rs` (9bf0eb43, decode_frame)](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/p2p_tcp.rs#L181-L201).
The independent raw transport helper remains out of scope and unchanged:
[`TransportFrame::decode` at protected main](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-net/src/transport.rs#L49-L66).
This correction adds no bincode or nested-count limit, no pre-ingress,
peak-memory, or concurrent-session bound, and no authority or resume
behavior. Existing catch-up non-empty refusal and empty-response ignore
controls are unchanged.

The prior ingress investigation README
(`catch-up-ingress-resource-boundary/README.md`) was inspected and preserved
unchanged. Its earlier actual documentation diff remains ten paths; listing
it as inspected here does not add it to that diff.

Exact commands, toolchain/target, test outputs and exits, failed attempts,
formatting/scope/preservation checks, and hashes are recorded in
[`COMMANDS.txt`](COMMANDS.txt), [`CHECKS.txt`](CHECKS.txt), and
[`SHA256SUMS`](SHA256SUMS). Existing historical evidence and
`Audit/QBIND_SECURITY_FINDINGS_REGISTER.md` are preserved.

The separate raw helper, nested decoding/resource limits, production
currentness, durable application, signer fencing and resume remain
unresolved. A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
