# Quarantine read interface return-type correction

**NON-WIRED INTERFACE CORRECTION — INDEPENDENT REVIEW PENDING.**

## Entry and correction scope

Before editing, repository `olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`, local/remote task tip
`f853ad7c301f9b5f0311792a8d85baae44c49960`, tree
`cd4cacd4f0f4684c3ea09fcb24f48873e05c5cdb`, clean worktree/staging and
local/remote protected main `c9aaef40b045e896ddfa8b01bad230f6b680715e`
matched.

The change is limited to the public return type and tests plus append-only
plan/evidence/checksum entries and two new test logs. Earlier evidence files
and previous plan/manifest bytes are preserved. The interface remains
disconnected from CLI, reset orchestration, catch-up, storage, signer and
network paths.

## Correction

Previously `classify_for_reset` returned `Result<(), ResetRefusal>`. Its
branches returned only `Err`, but callers could still represent `Ok(())` as
an allow result. The public function now returns `ResetRefusal` directly.
Every decision is a refusal value; there is no success type or `Ok(())`
variant to construct.

The fake-reader interface test asserts the direct result for each existing
classification and includes a function-pointer type assertion:

```rust
fn(&StoreIdentity, usize, &mut FakeReader, &FakeDecoder) -> ResetRefusal
```

The distinct refusal outcomes remain: supported `Applying` and recorded
state, absent, malformed/corrupt, unsupported version, foreign or mismatched
identity, unavailable, oversized, read failure with byte count and error
kind, uncertain, Clean-looking without separate authority, invalid expected
identity and invalid read limit. No allow, clear, resume or currentness
authority was added.

The `read_bounded` implementation and behavior were not changed. Its byte
limit is supplied by the caller; this work selects no production maximum.
The helper bounds its own read to the supplied limit plus a probe byte and
reports oversized input or read failure. A `QuarantineReader` backend must
enforce bounded allocation while reading. The classifier's post-read
`Vec::len()` check is defense in depth only and cannot prevent a backend
from allocating excessively before returning its vector.

## Tests and checks

Exact test commands:

```sh
rustfmt --edition 2021 crates/qbind-node/src/pqc_reset_quarantine.rs crates/qbind-node/tests/a33_f1_quarantine_read_interface_tests.rs
rustfmt --edition 2021 --check crates/qbind-node/src/pqc_reset_quarantine.rs crates/qbind-node/tests/a33_f1_quarantine_read_interface_tests.rs
cargo test -p qbind-node --lib pqc_reset_quarantine::tests::bounded_read_detects_oversize_and_preserves_partial_failure -- --exact --nocapture
cargo test -p qbind-node --test a33_f1_quarantine_read_interface_tests -- --nocapture --test-threads=1
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --check
```

Results: targeted rustfmt and whitespace checks passed; bounded-reader unit
test **1 passed**; fake-reader/fake-decoder interface tests **6 passed**,
including the selected public return type and direct refusal assertions. Raw
Cargo output is captured in
`quarantine-read-interface-return-type-bounded-read.log` and
`quarantine-read-interface-return-type-focused.log`.

The tests exercise the Rust interface and `read_bounded` only. They do not
exercise a persistent backend, production allow decision, CLI/reset caller,
filesystem durability, startup coverage, crash behavior, signer fencing or
network behavior.

## Historical-aware integrity and ordinary checksum result

No existing manifest entry was rewritten. The historical-aware check
verifies each preserved hash against its producing revision and each
appended current hash against the current file. It also checks that the
remediation plan and `SHA256SUMS` retain their exact starting-tip bytes as
prefixes. The ordinary `sha256sum --check SHA256SUMS` result, including the
number and paths of expected failures, is recorded with final verification
after this append-only record and its hash are added.

A33-F1 / E27 and all other unresolved obligations remain **OPEN**. The
interface remains non-wired; activation **DISABLED**; public DevNet
**NO-GO**.
