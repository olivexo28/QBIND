# QBIND DevNet Evidence — Run 364

Release-binary evidence for the public DevNet abuse/DoS **M12** controls — the runtime-owned
**connection-rate limiter** (Run 362) and the **per-peer message-rate override** (Run 363) — proven
together on the real `target/release/qbind-node` binary plus a release-built helper that links the
production Run 361/362/363 library symbols.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready · release-binary evidence only (no source behavior
> change, no new CLI flag, no live deployment).

## 1. Exact verdict

**Partial-positive / public-DevNet-abuse-DoS-M12 release-binary positive (M12 stays Yellow/Partial,
strengthened — NOT Green).**

The release helper, harness, production-binary CLI scenarios, tests, docs, secret scan, and matrix
updates all landed. **M12 does not move Green.** The connection-rate limiter is wired end-to-end into
the production accept path and is release-binary proven. The per-peer message-rate override reaches
the live `AsyncPeerManagerImpl` limiter construction path (release-binary proven), **but** production
`main.rs` / `p2p_node_builder` do not yet thread the CLI-derived `peer_rate_limiter_config` into the
deployed node's live peer manager, so end-to-end operator effect on a running node is not yet
delivered. Per the readiness rules, because the per-peer message-rate evidence is incomplete for the
deployed binary, M12 stays `Yellow/Partial` (strengthened). M4 remains Yellow/launch-blocking; M6
remains Yellow; public DevNet remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/examples/run_364_public_devnet_abuse_dos_m12_release_binary_helper.rs` — release
  helper (7 scenarios) linking the real Run 361/362/363 symbols for both limiters.
- `scripts/devnet/run_364_public_devnet_abuse_dos_m12_release_binary.sh` — release harness.
- `docs/devnet/run_364_public_devnet_abuse_dos_m12_release_binary/{README.md,summary.txt,.gitignore}`
  — evidence archive (only these three files tracked).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md` — this file.

Modified (narrow, docs only):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

**No source change.** The helper/harness rely only on existing public library symbols.

## 3. Release artifacts and hashes

| artifact | value |
| --- | --- |
| toolchain | `rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)` |
| `target/release/qbind-node` SHA-256 | `5912445d58fad6991f478c1f2316d081c18b2d8d018f89f5ee5a9be44c4bb2fb` |
| `qbind-node` Build ID | `72a7c9e358aa0cda432f89b0a4a7b3bce4fca6ad` |
| release helper SHA-256 | `ed3cc61f77b9f2cb1b537dcce218d47c7090ac86cb347f71072930a4f2048d4d` |
| helper Build ID | `dfcacc08b51428cbcacba85d9ba91f99ddc3ab56` |

SHA-256 / Build ID values are environment-specific (toolchain + absolute build path + dependency
versions) and are reproducibility anchors for this build only. Re-running in a different environment
legitimately yields different hashes.

## 4. Helper / harness corpus

Helper scenarios (all `match=true`, verdict PASS):

1. `01_default_preserves_behavior` — no flags: connection limiter disabled; per-peer defaults
   `1000`/`100`; the production peer-manager builds `PeerRateLimiter::with_defaults()`; drop metric 0.
2. `02_connection_rate_enabled_allows_then_refuses` — small bucket (4): 4 admitted, 5th
   `ConnectionRateLimited`, `qbind_p2p_connection_rate_drop_total` increments exactly once.
3. `03_per_peer_message_rate_enabled_allows_then_drops` — custom `--p2p-max-messages-per-second 5
   --p2p-burst-allowance 0` reaches the live `AsyncPeerManagerImpl` limiter (capacity 5): 5 allowed,
   6th dropped, connection-rate metric untouched.
4. `04_combined_connection_and_message_rate_independent` — both configured from one validated posture:
   a connection-rate refusal never admits a peer; a per-peer message-rate drop occurs only on the
   admitted message path; counters remain distinct.
5. `05_invalid_config_fails_closed` — zero connection-rate window, zero per-peer max, zero
   connection-rate max, unbounded per-peer max, and inconsistent per-address config are all rejected.
6. `06_mainnet_refused` — enabled MainNet abuse/DoS config refused (direct + via CLI).
7. `07_cli_surface_hidden_and_parse_checked` — all 8 hidden flags absent from `--help`; real hidden
   flags parse; invented flags rejected by clap.

Harness (`scripts/devnet/run_364_public_devnet_abuse_dos_m12_release_binary.sh`): builds the release
binary + helper, captures SHA-256 / Build ID / toolchain, runs the helper, and exercises the
production-binary CLI surface.

## 5. Production-binary scenarios

1. `--help` succeeds and hides all Run 362/363 abuse/DoS flags — `help_hidden_flags_absent: true`.
2. Real hidden flags parse (connection-rate + per-peer, via `--version` short-circuit) —
   `real_hidden_flags_parse: true (rc=0)`.
3. Invalid abuse/DoS config fails closed — proven via release helper scenario 05, which calls the
   exact production validation function `CliArgs::abuse_dos_runtime_config()`.
4. MainNet abuse/DoS enablement refused — proven via release helper scenario 06 (same production
   validation function).
5. Invented abuse/DoS flag exits with a clap error — `invented_flag_rejected: true (rc=2)`.
6. Default DevNet surface unchanged — `--help` lists no new public flag; hidden flags stay hidden.
7. No new public CLI flag exposed accidentally — verified against `--help`.

> Scenarios 3 and 4 are proven through the release helper rather than a full node launch because every
> `qbind-node` invocation reachable in this environment enters its blocking LocalMesh consensus loop
> before the abuse/DoS validation branch in `main.rs` executes; a full-node run would hang rather than
> exit. The helper drives the identical validation code path deterministically.

## 6. Connection-rate runtime evidence

Helper scenario 02: an enabled connection-rate limiter (global capacity 4) admits exactly 4 inbound
connections at `t0` and refuses the 5th with `ConnectionDecision::ConnectionRateLimited`, incrementing
`qbind_p2p_connection_rate_drop_total` from 0 → 1 and `drop_count` to 1. This is wired end-to-end into
the production accept path (`main.rs` → `p2p_node_builder::with_abuse_dos_runtime_config` →
`TcpKemTlsP2pService::set_abuse_dos_runtime_state` → `should_admit`).

## 7. Per-peer message-rate runtime evidence

Helper scenario 03: `--p2p-max-messages-per-second 5 --p2p-burst-allowance 0` flows through
`CliArgs::abuse_dos_runtime_config()` → `PublicDevnetAbuseDosRuntimeConfig::peer_rate_limiter_config()`
→ `AsyncPeerManagerConfig::with_peer_rate_limiter_config(Some(cfg))` → `AsyncPeerManagerImpl::new`,
producing a live `PeerRateLimiter` whose config is `max=5, burst=0`. It allows 5 messages then drops
the 6th, without touching the connection-rate metric. This proves the override reaches the **live
peer-manager limiter construction path** in release mode.

## 8. Combined limiter independence evidence

Helper scenario 04: from one validated `AbuseDosConfig` (connection capacity 1, per-peer capacity 3),
the first inbound is admitted and the second refused by the connection-rate limiter (metric 0 → 1);
the per-peer limiter on the admitted peer allows 3 messages then drops the 4th, leaving the
connection-rate metric at 1. The controls are independent and their counters distinct.

## 9. Rejection / fail-closed evidence

Helper scenario 05 rejects: zero connection-rate window (`from_config`), zero per-peer max (CLI), zero
connection-rate max (CLI), unbounded per-peer max `2_000_000` (CLI, exceeds `MAX_MESSAGES_PER_SECOND`),
and an inconsistent per-address connection-rate config (window without max). Helper scenario 06 refuses
MainNet directly and via `--env mainnet`.

## 10. Default compatibility

Helper scenario 01: with no flags the connection limiter is disabled, 1000 disabled-limiter admissions
never refuse, the drop metric stays 0, and the production peer-manager's limiter equals
`PeerRateLimiter::with_defaults()` (`1000` msg/s + `100` burst). Bit-for-bit unchanged.

## 11. CLI / config surface

No new public CLI flags. The hidden/devnet-only Run 362/363 flags
(`--p2p-connection-rate-limit-enabled`, `--p2p-connection-rate-window-ms`, `--p2p-connection-rate-max`,
`--p2p-connection-burst`, `--p2p-max-messages-per-second`, `--p2p-burst-allowance`,
`--p2p-per-address-connection-rate-window-ms`, `--p2p-per-address-connection-max`) remain absent from
`--help` (helper 07 + harness), parse when supplied, and reject invented variants.

## 12. Metric evidence

`qbind_p2p_connection_rate_drop_total` renders exactly once (`registered_once: true`), carries no
endpoint labels (`endpoint_label_leak: false`), increments only on connection-rate refusal (helper 02),
and is never touched by per-peer message-rate drops (helper 03/04).

## 13. Non-mutation evidence

The helper opens no P2P socket, launches no DevNet, deploys no seed/bootnode/faucet/RPC/explorer/status
page, changes no P2P wire format, weakens no peer admission or trust-bundle behavior, and mutates no
`LivePqcTrustState` / sequence / marker / validator set / epoch. Connection-rate refusals close the
inbound socket early without admitting a peer; per-peer drops act only on the admitted message path.
No Run 070 path is touched.

## 14. Readiness matrix delta for M12

M12: `Yellow/Partial (stronger, Run 363)` → `Yellow/Partial (stronger, Run 364 — release-binary
evidence for both controls)`. **Not Green.** Exact reason: the connection-rate limiter is
production-wired and release-proven, but the per-peer message-rate override reaches only the live
peer-manager *construction path* — the deployed `qbind-node` (`main.rs` / `p2p_node_builder`) does not
yet build its live `AsyncPeerManagerImpl` from the CLI-derived `peer_rate_limiter_config`, so per-peer
operator effect on a running node is not yet delivered. The readiness rule requires **both** controls
proven runtime/operator-configurable with defaults preserved before Green; per-peer end-to-end
production threading is the remaining gap.

## 15. Current public DevNet readiness status

**NOT launch-ready.** Green: M1, M2, M3 (same-host scope), M5, M10, M11, M16–M20. Yellow/Partial: M4,
M6, M7–M9, M12 (strengthened), M13–M15. M4 remains launch-blocking.

## 16. Remaining public DevNet blockers

M4 (live seed/bootnode reachability) launch-blocking; M6 (stable identity generation); M7–M9, M13–M15;
and M12 per-peer message-rate end-to-end production threading (thread `peer_rate_limiter_config` into
the deployed `AsyncPeerManagerImpl`) plus load evidence.

## 17. Public TestNet blockers

All public-DevNet blockers above, plus TestNet-scope reachability, identity, and abuse/DoS end-to-end
release evidence. **No TestNet readiness is claimed.**

## 18. MainNet blockers

MainNet authority rotation/revocation Red; no production abuse/DoS policy (MainNet refused by this
surface); Full C4/C5 OPEN. **No MainNet enablement.**

## 19. C4/C5 status

Full **C4 OPEN**; **C5 OPEN**. Unchanged by Run 364.

## 20. Tests run

- `cargo build -p qbind-node --release` — ok.
- `cargo build -p qbind-node --release --example run_364_public_devnet_abuse_dos_m12_release_binary_helper` — ok.
- `scripts/devnet/run_364_public_devnet_abuse_dos_m12_release_binary.sh` — PASS (7/7 helper scenarios).
- `cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests` — **21 passed; 0 failed**.
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests` — **38 passed; 0 failed**.
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests` — **30 passed; 0 failed**.
- `cargo test -p qbind-node --lib` — **1385 passed; 0 failed**.

> Run 361 reconciliation: the Run 361 target reports **30** tests here. Some prior run logs recorded
> "38" for Run 361; the authoritative count for
> `run_361_public_devnet_abuse_dos_hardening_tests` in this tree is **30 passed**.

## 21. Security scans

Secret scanning run over all changed files — no secrets, keys, mnemonics, credentials, tokens, private
infrastructure, or live endpoints. All addresses are RFC 5737 (`192.0.2.0/24`) documentation ranges or
localhost.

## 22. CodeQL

The diff is a new Rust example (helper), a shell harness, and docs — no production/library source
change. `codeql_checker` was invoked (declared non-trivial because a new analyzable Rust example file
was added). **Exact result: CodeQL analysis was SKIPPED — the Rust database was too large.** This is
recorded verbatim and is **not** asserted as a clean scan. Because no production source symbol was
modified, the analyzable delta over production code is nil; the skip does not mask an unreviewed
production change.

## 23. Provenance

- git commit: `02663e8f69b66f14e4795a255347f6a1caed0d7e` (helper + harness in the preceding commit on
  this branch; evidence + docs follow).
- branch: `copilot/run-364-update-documentation`.
- working state at build: helper + harness committed; docs pending in the same series.
- files changed: see §2.
- helper: `crates/qbind-node/examples/run_364_public_devnet_abuse_dos_m12_release_binary_helper.rs`.
- harness: `scripts/devnet/run_364_public_devnet_abuse_dos_m12_release_binary.sh`.
- release binary SHA-256 / helper SHA-256 / Build IDs / toolchain: see §3.
- helper scenarios: §4. production-binary scenarios: §5. test counts: §20. secret scan: §21. CodeQL:
  §22. readiness delta: §14.

## 24. Honest limitations

- **Release-binary evidence only.** No source behavior change; no new CLI flag; no live deployment.
- **Per-peer message-rate is construction-path-proven, not end-to-end production-threaded.** The
  deployed `qbind-node` still does not construct its live `AsyncPeerManagerImpl` from the CLI override;
  the release helper exercises the exact production construction API but not the deployed wiring.
- **Semantic fail-closed proven via the release helper, not a full node launch**, because reachable
  `qbind-node` invocations block in the LocalMesh consensus loop before the abuse/DoS validation
  branch. The helper calls the identical `CliArgs::abuse_dos_runtime_config()` validation function.
- M12 stays Yellow; no Green, no launch-ready, no TestNet/MainNet readiness, no C4/C5 closure claim.

## 25. Suggested Run 365 next step

Thread the CLI-derived `peer_rate_limiter_config` into the deployed node's live `AsyncPeerManagerImpl`
in `main.rs` / `p2p_node_builder` (a bounded, default-preserving source change), then produce
release-binary evidence that a running `qbind-node` honors a custom per-peer message-rate override
end-to-end. With connection-rate already production-wired, that would close the remaining M12 gap and
justify evaluating the M12 Green gate.