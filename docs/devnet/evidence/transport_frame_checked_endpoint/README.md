# TransportFrame checked endpoint correction

## Scope and identities

Disposition: **TRANSPORT-FRAME CHECKED ENDPOINT — IMPLEMENTED; INDEPENDENT
REVIEW PENDING.** The concern remains OPEN pending independent review. This
evidence does not claim integration approval, hosted CI success, deployed
impact, or running-node assurance.

- Repository: `olivexo28/QBIND`
- Base branch and commit: `test/transport-frame-decoder-baseline` at
  `4de10794eccefcf0a50e148ae15de07fd6dc461c`
- Base tree: `4fa85138199fb223e6f39444bcb03c0efd898517`
- Accepted baseline parent: `9458e0dcb26c33dbb27be0a96005400b8eed473a`
- Live `origin/main` at preflight: `9458e0dcb26c33dbb27be0a96005400b8eed473a`,
  tree `f010c0f9cec8de7ea31e621c6b58800957227d85`
- Task branch: `fix/transport-frame-checked-endpoint`
- Initial source/test tree for the debug and release runs:
  `c5769df7bf916852293bbff1306aa15e27414dde`
- Final formatted source/test tree for the repeated debug and release runs:
  `edf5ce643279daf0680b3068cfb7336d9b00a23c`
- Both are the base tree plus only
  `crates/qbind-net/src/transport.rs` and
  `crates/qbind-net/tests/transport_frame_decoder_baseline_tests.rs`; the
  latter tree differs only by rustfmt formatting from the initial tree.

Preflight found the expected accepted branch and remote refs, a clean worktree
and staging area, no untracked files, and no `AGENTS.md`.

## Implementation behavior

Only `TransportFrame::decode` in `crates/qbind-net/src/transport.rs` changed
in production. It still rejects headers shorter than five bytes with
`Protocol("transport frame too short")`. It parses the wire length as `u32`,
uses `usize::try_from` and returns
`Protocol("transport frame payload length not representable")` if conversion
fails, then computes `5usize.checked_add(len)` and returns
`Protocol("transport frame payload length overflow")` if the endpoint
overflows. The validated endpoint is used for both the available-buffer
comparison and payload slice. Representable but incomplete payloads continue
to return `Protocol("transport frame payload truncated")`; valid payloads
decode as before, and trailing bytes remain ignored.

The test file preserves the five baseline actual-decoder characterization
cases. Its cfg-32 actual-decoder test is no longer ignored and asserts exact
results for header-only inputs of `u32::MAX - 5` (truncation) and
`u32::MAX - 4`, `u32::MAX` (endpoint overflow). On 64-bit, the boundary test
continues to require truncation for those declared lengths because their
endpoints are representable. No declared-size payload allocations are used.
The host can represent every `u32` as `usize`, so conversion failure cannot be
exercised on this host. This does not claim general support for targets
narrower than 32 bits.

## Test execution and results

Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, Cargo `1.99.1
(5f94df478 2026-08-27)`, stable. Host and test target:
`x86_64-unknown-linux-gnu` on Linux. Only that target was installed.
Working directory for both commands:
`/workspaces/QBIND/olivexo28/QBIND`.

Complete stdout/stderr and actual exit codes are preserved in `debug.log` and
`release.log` (initial runs), and `debug-repeat.log` and `release-repeat.log`
(final formatted tree).

- Debug command: `cargo test -p qbind-net --test transport_frame_decoder_baseline_tests --test transport_frame_tests --test framed_io_tests` — exit 0.
- Release command: `cargo test --release -p qbind-net --test transport_frame_decoder_baseline_tests --test transport_frame_tests --test framed_io_tests` — exit 0.

Each of the four runs passed the same 37 executed bodies: 5 decoder-baseline
cases, 10 transport-frame cases, and 22 framed-I/O cases. There are 37
distinct executed test bodies and 148 total body executions across the four
runs. Test names are in the adjacent logs. No tests failed or were ignored in
the x86-64 selections.

Native 32-bit execution: **NOT RUN** (no 32-bit target installed). The
cfg-32 test exercises the actual decoder if run natively, but it was not
compiled or executed here. The x86-64 boundary test is not a substitute for
native 32-bit checked-add overflow behavior. No helper/model, cross-compilation
or panic-mode inference is claimed as native execution.

## Scope verification

No changes were made to the wire format, public decoder size policy,
framed-reader 16 MiB limit, encryption, callers, application-frame decoder,
catch-up behavior, recovery policy, Cargo manifests, dependencies, lockfile,
or authoritative audit register. The accepted test-only baseline commit and
its evidence files remain unchanged. Its historical test-source hash remains
in the accepted baseline checksum manifest and corresponds to the source blob
at the accepted baseline commit; the updated test source is checksummed
separately here. No production source outside `transport.rs` changed. The
adjacent `SHA256SUMS` records checksums for this README, all four raw logs,
and the two changed source/test files.

Activation remains DISABLED; public DevNet remains NO-GO. Broader resource,
recovery/resume and other recorded obligations remain OPEN.
