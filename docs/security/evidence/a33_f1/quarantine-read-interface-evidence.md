# Non-wired reset quarantine read interface

**NON-WIRED QUARANTINE INTERFACE — INDEPENDENT REVIEW PENDING.**

## Entry and scope

Before editing, repository `olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`, local/remote task tip
`7069ab7a2202ce2eb1a1f1422f831d283455e08d`, tree
`50dc2d62e7fb537c50c85dafd4d669c5bc4a9247`, clean worktree/staging and
local/remote protected main `c9aaef40b045e896ddfa8b01bad230f6b680715e`
matched.

The new public module `pqc_reset_quarantine` has no production caller. Its
fake-reader integration tests and bounded-read unit test do not invoke the
real reset, CLI, startup, filesystem, signer, consensus or network. The
audit register, earlier evidence, and all prior plan and manifest bytes
are preserved.

## Selected interface

The module exposes `QuarantineReader`, `RecordDecoder`,
`classify_for_reset`, `read_bounded`, and typed records/errors:

* `StoreIdentity` carries opaque, non-empty `store_id` and `chain_id`
  strings as expected input and decoded record identity. The reader/decoder
  must bind the same intended store and chain. String representation,
  derivation, canonicalization, and persistent encoding are deliberately
  unselected. A matching local identity is not proof of freshness,
  anti-rollback, complete reconciliation, or exclusive signer ownership.
* `QuarantinedState::{Applying, RecordedOutcome}` maps to a typed
  `ResetRefusal::Quarantined`. `ObservedState::CleanLooking` maps to
  `CleanLookingRequiresSeparateAuthority`; this component defines no
  production allow, clear or resume operation.
* `Ok(None)` maps to `Absent`, which refuses. Malformed/corrupt and
  unsupported-version decoder results remain distinct refusals. Either
  store or chain mismatch maps to `ForeignOrMismatchedIdentity`.
* Reader unavailable, oversized, partial, uncertain, and invalid-limit
  outcomes are distinct typed refusals. Decoder uncertainty also refuses.
  `classify_for_reset` returns only `Result<(), ResetRefusal>`; no local
  observation yields a reset authorization.
* The caller supplies `max_bytes`; there is no selected protocol maximum.
  `read_bounded` reads at most the bound plus one probe byte, reports
  oversized input, and reports every read error with `bytes_read` and
  `ErrorKind` as `ReadError::ReadFailed` (zero bytes means failed before
  progress; nonzero bytes means a partial read), never as absence. The
  classifier also checks that a reader does not return more than its
  supplied limit. A clean EOF after a short payload reaches the decoder,
  which must classify truncation as malformed/corrupt or uncertain; it must
  not turn it into absence or Clean-looking. Backends must use a reviewed
  bound and must not mutate quarantine data during classification.

The `RecordDecoder` is an explicit seam because no marker codec or version
has been approved. The interface does not select a 324- or 340-byte record,
initialization ceremony, currentness authority, anti-rollback source,
signer-exclusivity mechanism or reset-eligible state.

## Refusal mapping and component guarantees

| Reader / decoder observation | Component result | Reset effects authorized? |
|---|---|---|
| Supported `Applying` / recorded outcome | `Quarantined(state)` | No |
| No record | `Absent` | No |
| Malformed or corrupt | `MalformedOrCorrupt` | No |
| Unsupported version | `UnsupportedVersion { version }` | No |
| Foreign store or chain identity | `ForeignOrMismatchedIdentity` | No |
| Open/read unavailable | `Unavailable` | No |
| Input above caller bound | `Oversized { limit }` | No |
| Read error, including after partial bytes | `ReadFailure { bytes_read, kind }` | No |
| Other uncertain read/decode result | `Uncertain` | No |
| Matching local `CleanLooking` | `CleanLookingRequiresSeparateAuthority` | No |
| Invalid expected identity/limit | typed invalid-input refusal | No |

This is a typed classification contract only. The reader implementation
still has to establish a safe read boundary, bounded allocation and accurate
absence semantics. A trait, matching identity or checksum cannot establish
durability, publication ordering, failure-after-publication behavior,
path identity, concurrent-writer safety, first-use initialization, schema
migration, copied-store protection or a current/anti-rollback authority.
Those are backend and protocol obligations and remain unresolved.

The production wiring check was:

```sh
rg -n "classify_for_reset" crates/qbind-node/src --glob "*.rs"
```

It found only the generic function definition in the new module. An initial
narrower `classify_for_reset\(` search returned no matches because generic
type parameters occur between the function name and opening parenthesis;
the corrected symbol search confirms no production caller.

## Future integration boundary against current source

Source was inspected at task tip `7069ab7a2202ce2eb1a1f1422f831d283455e08d`.
The component is not wired into any source below.

| Current source | Current behavior and future required control |
|---|---|
| `crates/qbind-node/src/main.rs:2222-2275` | `--authority-state-reset` is an early-exit route before `--print-genesis-hash` (`main.rs:2305`), profile validation and normal startup. It requires explicit `--data-dir` and Linux, creates the directory, acquires `restore.lock`, then assembles inputs and calls reset. A future reader gate can only occur after lock acquisition succeeds and before the call/input path can produce a reset effect. The directory and lock file may have been created before classification; neither is quarantine evidence. |
| `crates/qbind-node/src/restore_completion.rs:858-899` | `acquire_destination_lock` opens/creates the stable lock file and uses nonblocking exclusive `flock`; even contention can leave the file. The held lock protects cooperating users only. Failure must stop before classification and reset writes. |
| `crates/qbind-node/src/pqc_authority_state_reset.rs:1130-1188` | Public `execute_authority_state_reset` checks separation and verifies; verification refusal may publish a refusal audit. Direct callers do not acquire ownership or classify quarantine. |
| `pqc_authority_state_reset.rs:982-1078,1082-1128` | Audit path guard examines final and temporary audit/marker/lock identities. Audit writer can create parent directories, write the `.json.tmp`, and rename. A future classification must precede every refusal, pending and final audit write, including temporary-file writes. |
| `pqc_authority_state_reset.rs:1192-1252` | Verified orchestration writes pending audit, persists marker, then final audit; marker persistence error may emit refusal audit. Classification must happen before entering this entire sequence. |
| `crates/qbind-node/src/pqc_authority_state.rs:1308-1395` | Marker persistence creates parent directories, writes/syncs a temporary marker, renames it and syncs the parent on Unix; errors can occur after publication. This interface does not alter those effects. |
| `crates/qbind-node/src/main.rs:2503-2544,2552-2555` | Ordinary and restore startup acquire the shared destination lock before restore/startup decisions and hold it for process lifetime when a data-dir exists. A future startup gate must be ordered before participating startup work, not just reset. |
| `main.rs:2663-2700,2781-2844` | Restore attempt setup checks the existing restore record before mutation, later publishes INTENT and proceeds through materialization/COMPLETE. The quarantine gate is not present and cannot be inferred from restore-completion state. |
| `main.rs:5034-5118` | Ordinary startup evaluates the separate restore-completion guard. It is not a quarantine gate. A future quarantine startup refusal must cover this and restore startup paths before listener, signer, consensus, storage or other participating work. |
| `main.rs:2292-2325` | `--print-genesis-hash` exits after the reset route and before normal startup. It is a read-only operator route; this task did not add quarantine classification there or claim it participates in node operation. |

Future work must also inventory CLI subcommands and early exits that open
or mutate state, alternate binaries, library callers, ordinary and restore
startup, and test/maintenance routes. A CLI-only gate cannot cover arbitrary
direct calls to the public reset function or other processes.

## Tests and evidence boundary

The new interface integration tests use fake `QuarantineReader` and
`RecordDecoder` implementations with synthetic store/chain identities.
They cover Applying, recorded outcome, absent, malformed/corrupt,
unsupported version, both identity mismatches, unavailable, oversized
reader output, partial and uncertain read errors, decoder uncertainty,
Clean-looking refusal, and invalid identity/limit. The module unit test
exercises the actual generic `read_bounded` helper with synthetic oversized
input and a reader that fails after returning a prefix.

Commands and results:

```sh
rustfmt --edition 2021 crates/qbind-node/src/pqc_reset_quarantine.rs crates/qbind-node/tests/a33_f1_quarantine_read_interface_tests.rs
rustfmt --edition 2021 --check crates/qbind-node/src/pqc_reset_quarantine.rs crates/qbind-node/tests/a33_f1_quarantine_read_interface_tests.rs
cargo test -p qbind-node --lib pqc_reset_quarantine::tests::bounded_read_detects_oversize_and_preserves_partial_failure -- --exact --nocapture
cargo test -p qbind-node --test a33_f1_quarantine_read_interface_tests -- --nocapture --test-threads=1
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --check
```

Results: targeted formatting and whitespace checks passed; bounded-reader
unit test **1 passed**; fake-reader typed-classification tests **6 passed**.
Raw Cargo outputs are retained as
`quarantine-read-interface-bounded-read.log` and
`quarantine-read-interface-focused.log`.
Trailing blank lines at the ends of those captured logs were removed to meet
the repository whitespace check; command output and reported results are
otherwise unchanged.

An additional `rustfmt --edition 2021 --check --config skip_children=true
crates/qbind-node/src/lib.rs` attempt failed on existing unrelated formatting
in the crate root (including pre-existing module ordering/comment formatting
and EOF layout). It made no changes. The new interface source and integration
test both pass their targeted rustfmt check; the crate-root registration is
the only change in `lib.rs`.

The ordinary checksum command is expected to exit 1 because the preserved
manifest contains two historical hashes for the unchanged A33 model source:

| Preserved hash | Revision whose source bytes it covers |
|---|---|
| `772cc9df58bdeb052c56be30540c4db333e0ba1dc63f9bb0110e2501b7b60423` | `ce2fa5f2c6239df60497ecb811fc5e38bc5f9f5a` |
| `f13f88f6162695acf3c3aba1a98897d26c67b600e9ecedd50e28bd4507bf831b` | `9fc107c9717e6b71ac7f694a0c3472d7d2f2608d` |
| `bb89f8b9fd0d340b66129361fffbca335ebe6a3064af9fb9d4ba528968e09489` | Starting/current task tip `7069ab7a2202ce2eb1a1f1422f831d283455e08d` |

The first two are historical relative to the unchanged current model file;
the third matches the current model source. Each appended interface source,
test, plan, evidence, and output-log digest is checked against its file. The
historical-aware verifier checks the first two source entries against their
respective Git revisions, the third against the starting tip, and current
appended entries against current bytes. It also checks that the plan and
manifest retain their exact starting-tip bytes as prefixes. Ordinary
`sha256sum --check SHA256SUMS` is thus reported as **two expected historical
source mismatches**, not a full manifest pass.

These are component unit/integration tests only. They are not models of the
real filesystem and do not prove filesystem durability, actual CLI ordering,
production quarantine enforcement, ordinary/restore startup coverage,
concurrent writer safety, process or power-loss crash safety, signer
fencing, currentness, recovery, or network delivery.

## Remaining acceptance dependencies

Before a real backend or gate can be accepted, separately select/review the
persistent schema and codec/version policy; stable store/chain identity
derivation; maximum record size and bounded-open semantics; initialization
and migration; freshness/anti-rollback/currentness authority; publication,
sync, readback and failure-after-publication behavior; path and alias
identity; concurrency/exclusive writer and signer ownership; complete reset,
direct-library, ordinary-startup, restore-startup and CLI-exit coverage; and
any separate clear/resume authority. No such decision or wiring was made.
A33-F1 / E27 and all other unresolved obligations remain **OPEN**; activation
**DISABLED**; public DevNet **NO-GO**.
