# Application-frame test/evidence correction

**APPLICATION-FRAME TEST/EVIDENCE CORRECTION — INDEPENDENT REVIEW PENDING.**

The user-supplied CHANGES REQUIRED review applies to the test/validation
package at `be0e83749233143ff0b713ea353600c922fdbaab`; the production checked
endpoint calculation remains supported by source inspection. This correction
changes only the maximum-declared-length test oracle in
`crates/qbind-node/src/p2p_tcp.rs`. The test now evaluates
`checked_frame_payload_end(u32::MAX as usize)` on the active target and then
requires the real `decode_frame` call to return the matching specific
encoding error: `frame truncated` when the endpoint is representable, or
`frame payload length overflow` when it is not. Both arms assert a returned
error, so a panic fails the test. The production calculation and other
decoder test bodies are unchanged.

## Corrected execution evidence

The corrected affected runs were executed on
`x86_64-unknown-linux-gnu` with Rust `1.99.1
(58cf8f9c3 2026-10-13)`. All three commands exited 0:

- Debug focused: 5 passed, 0 failed.
- Release focused: 5 passed, 0 failed.
- Debug P2P regression selection: 39 passed, 0 failed.

The three selections overlap: all five `decode_frame_tests` test bodies are
also selected by `p2p_tcp::`. There are **39 distinct test bodies** across
the selection union (five decoder tests plus 34 peer-retirement tests), but
**49 test-body executions** in the three runs (5 + 5 + 39). This separates
distinct tests from profile/regression repetitions.

Complete stdout, stderr, and a separately recorded exit code for each run
are retained under [`raw/`](raw/). The capture invokes each Cargo command
with stdout and stderr redirected to separate files, immediately saves `$?`
to its `.exit` file, and only then evaluates that status; the status is not
replaced by a later logging command. The toolchain and installed-target
outputs are also retained in full. Exact shell commands, result summaries,
test names, capture semantics, and counts are in [`COMMANDS.txt`](COMMANDS.txt).

Only `x86_64-unknown-linux-gnu` was installed. Native 32-bit test execution
is **NOT RUN**; the corrected oracle's 32-bit arm is source/test logic, not
evidence of a 32-bit run. The older `application-frame-checked-endpoint`
command file keeps its author summaries as historical summaries; they are
not raw logs and are not represented as a reviewer rerun. Earlier failed
build attempts noted there likewise remain historical summaries. No failed
or intermediate attempt occurred in the three corrected runs recorded here.

No production behavior, other decoder test body, raw transport helper,
nested decoding limit, recovery/resume obligation, or catch-up refusal/ignore
behavior changed. The prior ingress investigation and its closed
clarifications, prior accepted tests/evidence, and audit register are
preserved. The separate raw transport helper, nested decoding/resource
limits, and recovery/resume obligations remain unresolved.

`CHECKS.txt` records formatting, whitespace, scope, prefix, and preservation
checks. `SHA256SUMS` records hashes for changed source/docs and every raw
artifact. A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
