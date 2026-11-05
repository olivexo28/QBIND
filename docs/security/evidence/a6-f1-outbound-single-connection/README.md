# A6-F1 outbound single-connection correction

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.** This fixes a separately
identified pre-existing outbound double connection, not a new canonical
finding or closure of A6-F1. A6-F1 / OBL-AVL-4a / E14 and all remaining
obligations stay **OPEN**. Activation **DISABLED**; public DevNet **NO-GO**.

## Verified entry and producer

Repository `olivexo28/QBIND`, branch
`copilot/audit-a6-f1-displaced-peer-cleanup`, clean worktree and exact local
and remote starting tip `7268cbd047b559291cb5472f9c702543c6397f09`
(tree `8fec7fc6d5f5243a345c53ce1b6975fcd7cd1e58`); protected remote main
`64ce7131340a861d8b33063f430dfc0beab531b3`. No `AGENTS.md` was found.

Producer **`4b055bd529ba6f19cec9619addeb08dc02e19347`**, tree
`2922d66a7f96dd6f12190fb5561fb532793226fc`, sole parent the starting tip.
Only `crates/qbind-node/src/p2p_tcp.rs` changes: mode `100644`, blob
`0dd88492a6576b1184d8f7473fd0953043ea614e`. Positive verification below
runs on this exact committed source, with only this new evidence directory
untracked. Documentation/evidence is committed separately, not amended
into the producer.

[Producer source and six new controls](https://github.com/olivexo28/QBIND/blob/4b055bd529ba6f19cec9619addeb08dc02e19347/crates/qbind-node/src/p2p_tcp.rs)
are commit-pinned.

## Mechanism and bounded fix

Both `TcpKemTlsP2pService::dial_peer` and `DialerHandle::dial_once` opened
a Tokio TCP connection and converted it into an unused `_std_stream`.
They then called `tracked_dial`, which opened a second TCP connection
carrying KEMTLS. The unused connection stayed alive across the handshake.
This was present before the earlier retirement correction.

The production change removes only those two preliminary connect blocks.
Each entry point now uses the single existing `tracked_dial` connection:
Tokio owns cancellable TCP establishment; after establishment,
`tracked_handshake` retains the independent socket-shutdown clone and
blocking join in the registry. Terminal-fence checks, retained task
outcomes, registration publication, verified-server origin matching,
per-peer config overrides, retry policy and eviction snapshot semantics
are unchanged. No authentication or cryptographic configuration is
weakened. One *attempt* uses one connection; later configured retries
remain separate attempts.

## Baseline reproduction

`baseline-probes.patch` adds six test functions/helpers to the unchanged
starting production file in a detached isolated worktree. No production
connect block was removed there. Four selected baseline tests exercise
both actual outbound entry points with permissive and one-connection
server admission. The loopback server counts each accepted TCP socket;
the first slot runs the actual KEMTLS server. Extra slots either run
KEMTLS (permissive) or are immediately closed (budget one).

```sh
CARGO_TARGET_DIR=/workspaces/QBIND/olivexo28/QBIND/target timeout 240s cargo test --locked --offline -p qbind-node --lib single_connection -- --test-threads=1
```

`baseline.log`: **0 passed, 4 failed, exit 101**. All four observed
**2 accepted sockets instead of 1**. Permissive runs connected through
the second socket; budget-one runs rejected that socket and failed the
dial. Baseline cancellation variants were not run. Server workers are
owned by a `JoinSet`, with a two-second read timeout and six-second
overall test deadline; the service cleanup runs before failure assertions.
No platform timing guarantee is inferred from these fixture deadlines.
The isolated worktree was removed after retaining the test patch/log.

The retained baseline patch predates producer-only result diagnostics,
removal of an unnecessary server-side identity assertion, and formatting.
Its dial/count mechanism and assertions are the same. The shell wrapper's
post-run relative `tail` command failed after changing into the isolated
worktree (exit 1); the correctly located raw Cargo log was then read from
the repository root. That wrapper failure is not a test exit: the raw
baseline explicitly records Cargo exit 101.

`precursor-outbound.log` retains a pre-commit smoke run:
`timeout 240s cargo test --locked --offline -p qbind-node --lib outbound_ -- --test-threads=1`,
**27 passed, exit 0**. This overly broad selector included unrelated
existing local signing unit fixtures, not operational signing; it is
not counted as producer-pinned required verification. No compile
failure occurred in this task.

## Producer-pinned commands and results

Each positive log records exact producer, tree, parent, shell-escaped
command, raw combined output, and actual exit status.

| Log | Exact command | Result |
|---|---|---|
| `lifecycle.log` | `timeout 240s cargo test --locked --offline -p qbind-node --lib peer_retirement_tests -- --test-threads=1 --nocapture` | 21 passed |
| `secure-channel.log` | `timeout 240s cargo test --locked --offline -p qbind-node --lib secure_channel:: -- --test-threads=1` | 16 passed |
| `compatibility.log` | `timeout 360s cargo test --locked --offline -p qbind-node --test b8_listener_identity_closure_and_dial_retry_tests --test run_072_p2p_session_eviction_tests --test run_074_pqc_trust_bundle_live_reload_tests --test run_418_authenticated_peer_consensus_sender_binding_tests -- --test-threads=1` | B8: 6; Run 072: 8; Run 074: 10; Run 418: 18 passed |
| `production-check.log` | `timeout 300s cargo check --locked --offline -p qbind-node --lib` | Passed, existing warnings retained |
| `format-whitespace.log` | `bash -c 'rustfmt --edition 2021 --check --config skip_children=true crates/qbind-node/src/p2p_tcp.rs && git diff --check 7268cbd047b559291cb5472f9c702543c6397f09 HEAD'` | Passed at producer |

**79 selected tests passed**, none failed/ignored; all five producer
commands exit **0**. No full-workspace execution or independent
post-correction acceptance is claimed.

Four successful actual-entry tests observe `accepted=1 rejected=0
dial_ok=true handshake_ok=true`, including the restrictive budget in
both entry points. The sole socket completes real KEMTLS and produces
the server channel; cleanup observes peer-loop/blocking-worker completion,
empty handshake registry, zero active count and remote EOF.

Two more actual-entry controls await the first handshake byte while the
server deliberately withholds its reply. They drop the pinned
`dial_peer`/`dial_once` future, observe the blocking worker still retained
in the registry, call shutdown, observe its join handle consumed and
registry removal, and read remote EOF. A later dial is refused by the
terminal fence without any newly accepted socket (bounded local check).
These tests supplement, rather than replace, the earlier direct
`tracked_dial` cancellation control and all 15 prior lifecycle controls.
Existing A5-F1/A11-F2, B8 retries, Run 072 eviction, Run 074 reload and
Run 418 origin gates remain covered.

The shared fixture uses real ML-KEM-768 and ChaCha20-Poly1305, with
test-only certificate signature verification, mutual auth disabled in
the fixture and synthetic identities. This is not evidence of production
certificate trust or deployment identity. Production crypto settings
and origin gates remain unchanged. All traffic is isolated loopback;
no external peer, live DevNet, deployment, operational signing or
activation was used.

## Integrity and residual scope

`verify.py` validates the starting plan's exact byte prefix, both earlier
A6-F1 evidence directories byte-for-byte, producer ancestry/source,
actual log counts and `SHA256SUMS`. Run it from the repository root:

```sh
python3 docs/security/evidence/a6-f1-outbound-single-connection/verify.py
```

`documentation-integrity.log` retains the verification and staged
whitespace checks: both the full staged and source/prose checks pass,
with no new raw-evidence whitespace exception. It also records toolchain
and protected remote identities at this pre-publication stage.
Historical evidence, audit register and earlier plan text are not changed.
Earlier author/reviewer qualifications remain as recorded: the original
4 + 15 + 8 + 10 and subsequent 73-test author results are not rewritten;
the earlier bounded A5-F1 review verified 19 checksums and reported 69
author tests, without reviewer Cargo execution, retaining its raw-log
whitespace limitation.

The existing terminal shutdown/new-service restart policy is preserved.
Cancellation, shutdown request, join completion and socket observation
remain distinct. Permanent or timed-out cleanup stays tracked and
reported; this task does not establish global admission bounds,
platform-wide shutdown timing, key erasure, registered-session fatal-read
cleanup, full eviction/trust-reload reclamation, or deployment assurance.
Already-progressed writes/delivery cannot be retracted; no replay or
acknowledgement is added. A6-F1 / OBL-AVL-4a / E14, A5-F1 / E11,
A11-F2 / E19, E07 and OBL-GOV-2 remain **OPEN** to their remaining extent.
**IMPLEMENTED — INDEPENDENT REVIEW PENDING**; activation **DISABLED**,
public DevNet **NO-GO**.
