# Application-frame scoped integration candidate

**APPLICATION-FRAME SCOPED CANDIDATE — INDEPENDENT REVIEW PENDING.**

This branch is a narrow integration candidate, not an integration into main.
It is based on protected main commit
`9bf0eb43e4e3c601d02d3886d220b0abeb3a103e` (tree
`56509b20084ee1cbe2c42fda9d73d87e4c82c33f`). The source/test-only candidate
commit is `c002a90e71d63747f0bb92246da78154c02c9e4a` (tree
`b7f120eb64cd0134a641cbe43aa3fd069f2ae784`, parent is the protected main
commit). The final packaged branch tip additionally includes this evidence
record. Its sole non-evidence file is
`crates/qbind-node/src/p2p_tcp.rs`, whose blob is
`ff9e99d8e77f51f3b7d118d198fa549c49d67870`. That blob exactly matches the
accepted producer endpoint's file blob at commit
`7fcb3b96dd4263dc60f1d81871c541ddb4210631` (tree
`e8881066b2b45e23b6c6d1b0368b8c632daecb16`). The accepted producer parent is
`be0e83749233143ff0b713ea353600c922fdbaab`; its task-branch history and
unrelated inventory changes are not included here.

The source/test delta is precisely the accepted application-frame checked
endpoint correction: replace unchecked endpoint use in the real
`decode_frame` with checked `5 + payload_len`, returning
`P2pTransportError::Encoding` for overflow/truncation, and its five focused
decoder test bodies, including the target-aware maximum-length oracle. The
candidate source/test diff has 111 insertions and two deletions relative to
main and was applied from the accepted producer commit's `p2p_tcp.rs` diff.
No other source or test file is changed. Valid-message round trips,
discriminator rejection and existing trailing-frame-byte behavior remain
covered. No nested bincode limit or catch-up containment behavior is
changed.

The accepted producer's retained author-run summaries record debug focused
5/5, release focused 5/5, and P2P regression 39/39: 39 distinct test bodies
across 49 run instances because the five decoder tests are included in both
focused runs and the regression selection. These are historical author
results, not independent review or candidate reruns. They are documented at
the producer commit's
[author evidence record](https://github.com/olivexo28/QBIND/blob/7fcb3b96dd4263dc60f1d81871c541ddb4210631/docs/security/evidence/recovery-resume-inventory-20261107/application-frame-test-evidence-correction/README.md)
and complete [raw output manifest](https://github.com/olivexo28/QBIND/blob/7fcb3b96dd4263dc60f1d81871c541ddb4210631/docs/security/evidence/recovery-resume-inventory-20261107/application-frame-test-evidence-correction/SHA256SUMS).
This candidate's own new validation runs and full raw outputs are under
[`raw/`](raw/) and separately counted in [`COMMANDS.txt`](COMMANDS.txt).

Only x86_64 is available; native 32-bit execution is NOT RUN. The raw
`TransportFrame::decode` helper, broader resource bounds and all
recovery/resume obligations remain unresolved. Main's existing audit and
evidence bytes are preserved. Scope, candidate/source blob correspondence,
commands, complete raw output hashes, and verification results are recorded
in [`CHECKS.txt`](CHECKS.txt) and [`SHA256SUMS`](SHA256SUMS).

A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
