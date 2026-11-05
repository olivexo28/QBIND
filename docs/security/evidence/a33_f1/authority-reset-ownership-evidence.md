# Authority-reset CLI destination ownership

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.**

## Producer and entry checks

Repository `olivexo28/QBIND`, existing branch
`copilot/a33-f1-bounded-eviction`. Before editing, origin URL, branch,
HEAD/local and remote task tip, local/remote main, clean worktree/staging
all matched. Starting commit `f30cae3f502020101edf5e447bdf26aea9c9f0e1`,
tree `9392002ff7bed9b824d92f0eb4a8426890e01442`,
parent `11bb930e005abd082a1dbb296f0b8fe90dcf4fc0`.
Protected local/remote main `c9aaef40b045e896ddfa8b01bad230f6b680715e`
is not updated. Entry command:

```sh
git remote get-url origin && git branch --show-current &&
git rev-parse HEAD HEAD^{tree} HEAD^ refs/heads/main &&
git status --porcelain=v1 --untracked-files=all &&
git ls-remote origin refs/heads/copilot/a33-f1-bounded-eviction refs/heads/main
```

Baseline production sources are exactly the starting commit; new test
harness was compiled against them before editing production. Corrected
producer is the commit carrying this record (parent = starting commit).
Source SHA-256 identities are in `authority-reset-ownership-checks.log`;
final commit/tree identity is reported after commit, avoiding a self-hash.
Linux x86_64; Cargo/Rust 1.99.1; local temporary synthetic data only.

## Source review and effect boundaries

Starting source anchors:

| Surface | Starting source | Finding |
|---|---|---|
| Reset dispatch | `crates/qbind-node/src/main.rs:2222-2258` | Calls public reset before normal destination lock. |
| Normal ownership | `crates/qbind-node/src/main.rs:2480-2528` | Explicit data directory creation and real nonblocking exclusive lock; not reached by reset. |
| Lock | `crates/qbind-node/src/restore_completion.rs:810-905` | Descriptor-held advisory `flock(LOCK_EX | LOCK_NB)` at `restore.lock`, stable file, no unlink. |
| Guard and audit writer | `crates/qbind-node/src/pqc_authority_state_reset.rs:976-1104` | Guard, possible audit-parent creation, temporary audit write and rename, including refusal. |
| Orchestrator | `crates/qbind-node/src/pqc_authority_state_reset.rs:1131-1248` | Guard before verification; verification refusal audit, or pending audit, marker persistence, success audit; typed compound failure context. |
| Marker writer | `crates/qbind-node/src/pqc_authority_state.rs:1308-1395` | Possible parent creation, marker `.tmp` create/truncate/write/sync, rename, directory open/sync; attempted temp removal on rename failure. |

Archive/verification read existing marker and public fixtures; they do not
write an archive side file. No other reset-related writer was added.
Audits can be outside the data directory: ownership coordinates cooperating
reset/startup processes for this destination, not arbitrary writers to a
shared external audit path.

Corrected CLI `main.rs:2222-2282` requires explicit `--data-dir`, refuses
non-Linux before directory creation, creates that explicit directory if
necessary, and acquires the existing lock before invoking the orchestrator.
Failure exits 1 with a destination-ownership diagnostic and **no reset audit
or marker write**. The descriptor binding remains live through all reset
effects and result reporting; process exit closes it in the kernel
(`process::exit` does not run Rust destructors). No default directory is
invented. Directory creation can itself partly succeed before an error;
opening the lock may create an empty `restore.lock` even if later flock
fails. These ownership artifacts are effects, not a no-filesystem-effect
guarantee. They are never automatically unlinked or treated as stale locks.

The guard now inspects the lock pathname and compares all four reset write
paths (audit final/temp, marker final/temp) against it using the same parent,
canonical-path and existing-inode comparisons. This is necessary because
renaming an audit over a held lock would otherwise leave the descriptor
locking an obsolete inode. Existing exact/alias/uncertain paths fail
`UnsafeAuditPath` before verification and before any audit write. A
nonregular/symlink lock leaf also refuses. Direct writer/orchestrator callers
observe this additional bounded path refusal; signatures/error types and
verification rules do not change. CLI missing-destination/lock refusals now
precede verification rather than producing verification/refusal-audit results.

The previous typed operation/audit failures remain unchanged. An error after
marker rename/directory sync can still mean changed marker bytes; persistence
acknowledgment is not audit acknowledgment, rollback, or power-loss durability.

## Observed baseline, not a security pass

`authority-reset-ownership-baseline.log`: a separate owned test process
acquired the **actual** lock helper, signaled readiness after acquisition,
and blocked on owned stdin. The actual `qbind-node` binary then ran reset
under a 30-second child deadline. The supplied hash is syntactically valid
but synthetic genesis file absent, producing real `GenesisLoadFailed`.
Observed exit 1, marker unchanged, **audit changed to a refusal record while
the other process still owned the lock**. After explicit holder release,
the same invocation again reached verification/refusal audit. One baseline
control passed its reproduction assertions; this is defective behavior,
not a correction or security pass. Production source remained the starting
revision during this run.

```sh
QBIND_A33_BASELINE=1 cargo test -p qbind-node \
  --test a33_f1_authority_reset_destination_lock_tests \
  contender_refuses_then_release_allows_normal_verification \
  -- --nocapture --test-threads=1
```

The transient baseline arm required `GenesisLoadFailed`, exit 1, unchanged
marker, and changed audit; it has been replaced by corrected assertions.
The log preserves the actual observations. Final tests do not expose an
environment switch that accepts the defective result.

## Corrected tests and exact commands

`authority-reset-ownership-integration.log`:

```sh
rustfmt --edition 2021 \
  crates/qbind-node/tests/a33_f1_authority_reset_destination_lock_tests.rs \
  crates/qbind-node/tests/support/authority_reset_cli.rs \
  crates/qbind-node/tests/a33_f1_authority_reset_verified_success_tests.rs
cargo test -p qbind-node \
  --test a33_f1_authority_reset_destination_lock_tests \
  --test a33_f1_authority_reset_verified_success_tests \
  --test a33_f1_authority_reset_audit_collision_tests \
  -- --nocapture --test-threads=1
```

Exit 0: **4 initial ownership tests**, **1 verified fixture test / 7
scenarios** and **6 path tests / 18 scenarios** passed (7.01s, 30.57s,
48.66s respectively). One ownership test is the subprocess-holder entry,
which is a no-op in the parent suite; the contention test actually launches
it in a separate process. These are not four independent contention cases.

The existing fully verified fixture uses in-memory synthetic ML-DSA test
credentials and signed public genesis/trust bundle/v1 ratification inputs.
CLI uses real current time, permitted by the fixture validity window,
actual verifier/Strict enforcement, guarded writer and marker loader.
CLI success returns 0; all derived fields except expected current-time
timestamp equal the verified plan, final success audit record and marker
digest agree. A valid-input equal audit/marker CLI destination acquires
ownership, then refuses at the pre-verification path guard with marker and
previous audit bytes unchanged. Function-level fresh/repeated success and
real tampered bundle/ratification controls remain covered. Private key
material is never written to logs or evidence.

`authority-reset-ownership-final-controls.log` adds the explicit absent
directory control and records final **5 ownership tests** (13.88s), then
**1 existing lock regression**, all passed, exit 0:

```sh
cargo test -p qbind-node \
  --test a33_f1_authority_reset_destination_lock_tests \
  -- --nocapture --test-threads=1
cargo test -p qbind-node --lib \
  restore_completion::tests::second_lock_acquisition_is_contended \
  -- --exact --nocapture
```

Final ownership controls: held real lock => bounded refusal, existing
marker/audit byte-identical; release => normal `GenesisLoadFailed`, separate
parsed refusal audit, marker unchanged; missing data-dir, directory at lock
path and regular file at data-dir => no reset marker/audit output; explicit
absent directory => directory/empty stable lock created, separate refusal
audit, no marker. Seven reset-write/lock alias cases (equal, dot spelling,
parent symlink, audit hard link, audit-temp hard link, marker hard link,
marker-temp hard link) refuse before verifier, preserve lock inode/bytes
and marker bytes, then allow lock reacquisition on CLI exit.

Harness `tests/support/authority_reset_cli.rs` owns each child in an RAII
kill/reap guard. CLI stdout/stderr use owned temporary regular files (no
pipe-fill deadlock); CLI deadline 30s, holder readiness/release 10s each.
Holder stdin EOF releases ownership. Panic/timeout drops children before
temporary directories, including failed attempts. Only early-exit reset
CLI is invoked, never normal node startup.

`authority-reset-ownership-reset-regressions.log`:

```sh
cargo test -p qbind-node --lib pqc_authority_state_reset:: \
  -- --nocapture --test-threads=1
```

Exit 0: **22 passed**, 110.28s: verification and typed failure-stage controls,
including not-attempted, uncertain persistence and acknowledged persistence
with separate audit error. Fault seams remain private tests, not CLI fault
injection or new end-to-end post-rename failure evidence.

## Retained unsuccessful attempts and formatting

1. Baseline command above initially failed compilation (exit 101):
   assumed `wait_timeout` dev dependency was not linked by this crate.
   Raw output: `authority-reset-ownership-build-attempt-1.log`.
   Replaced with standard-library bounded `try_wait` polling; no dependency
   manifest/install change.
2. Same baseline command exited 101 when CLI exited 2 for unsupported
   `--environment`; corrected to actual `--env`.
   `authority-reset-ownership-cli-attempt-2.log`.
3. Same baseline command exited 101 when malformed hash was refused by
   `to_node_config` before reset, rather than actual reset verifier.
   Corrected to 64 synthetic hex characters and absent genesis.
   `authority-reset-ownership-cli-attempt-3.log`.
4. The integration command's preceding rustfmt exited 1 before Cargo ran:
   newly added test accidentally inserted inside a match arm; diagnostic
   `expected identifier, found keyword fn` at line 106. Moved test to
   module scope; no production test failure or Cargo result from that attempt.
5. Whole-source `rustfmt --edition 2021 --config newline_style=Windows
   --check crates/qbind-node/src/pqc_authority_state_reset.rs` exited 1
   for legacy formatting and new tuple layout. Raw output:
   `authority-reset-ownership-format-attempt.log`. New lines were formatted;
   unrelated legacy layout and CRLF bytes were not rewritten.
   `rustfmt --edition 2021 --config skip_children=true --emit stdout
   crates/qbind-node/src/main.rs` similarly identified new binding layout
   and existing unrelated formatting differences; only touched-region
   formatting was applied.
6. First staged `git -c core.whitespace=cr-at-eol,-blank-at-eof diff
   --cached --check` exited 2 before commit: eight literal single-space
   context lines in the retained formatter diff output were diagnosed as
   trailing whitespace (`authority-reset-ownership-format-attempt.log`,
   lines 44, 71, 76, 84, 93, 98, 131, 153). Preserve that raw output;
   final whitespace checks exclude raw task `.log` files, not code/docs.

Final `python3 docs/security/evidence/a33_f1/authority-reset-ownership-checks.py`
checks scope, historical checksum integrity, prior plan/manifest byte
prefixes, complete new/changed test formatting and changed production-line
formatting while excluding existing legacy differences, and code/docs whitespace.
`authority-reset-ownership-checks.log` records success. Full-workspace
formatting is not claimed. Raw formatter diff context whitespace and Cargo
trailing blank lines are retained under the task-log whitespace exception;
source CRLF is allowed, not rewritten.

## Early-exit inventory, direct calls and residuals

At starting source `main.rs:2017-2205`, `identity` is a separate local
key/certificate utility dispatched before parsing, outside destination
ownership. Clap help/version, config parsing and governance-policy/MainNet
refusals precede reset; they do not invoke reset writers. Policy selector
capture/banner has no reset effect. `--print-genesis-hash` at 2282-2328 is
read/hash/print only, still before normal lock, unchanged. MainNet and
boot-genesis validation refusals also precede normal lock and are unchanged.
Reload-check, peer-candidate validation and reload-apply CLI exit modes
(`main.rs:2532-2593`, subsequent dispatches) are already downstream of normal
ownership when configured with a destination; no expanded guarantee for
stateless invocations. Snapshot restore/storage/startup ordering was not
redesigned. New coverage is the reset route, not every early-exit utility.

The public library reset function and audit writer do **not** acquire or
require an ownership token. Direct callers must acquire/retain the real
lock themselves; CLI ownership cannot protect arbitrary library invocations.
This contract is explicit in the orchestrator documentation.

Supported assumptions: Linux case-sensitive local filesystem with working
advisory flock; cooperating processes use the same stable destination/lock
inode and never unlink/replace it; operator-controlled stable directories,
no concurrent namespace, hard-link, mount or path replacement. Existing
parent symlinks are resolved by the guard; symlink/special leaves refuse.
The new alias checks prevent this reset's own writes from replacing the
lock under that profile, not hostile races. Unavailable metadata/parents
fail closed. Other platforms explicitly refuse before directory creation;
non-Linux execution, other filesystems/hosts, hostile replacement and
crash/power-loss cases are **UNTESTED**. No complete alias coverage,
copied-store/cross-host signing protection, signer fencing, durability,
recovery or startup-safety assurance is inferred.

Future stay-closed quarantine classification must occur **after destination
ownership and before any reset audit/marker effects** (including refusal
audits), as well as at other protected startup paths. This insertion-point
comment is not enforcement. Production quarantine marker/startup gate,
recovery authority, automatic clear/resume and signer fencing remain
unimplemented and **OPEN**. Baseline evidence is preserved, not relabeled;
no audit-register/history edits, live node/network, operational signing,
deployment, activation, PR, main update or force-push.

A33-F1 / E27 and all other unresolved obligations remain **OPEN**.
Activation **DISABLED**; public DevNet **NO-GO**.
