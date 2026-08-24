# QBIND DevNet Evidence — Run 366

Release-binary **end-to-end** evidence for the public DevNet abuse/DoS **M12** controls — the
runtime-owned **connection-rate limiter** (Run 362) and the **per-peer message-rate override threaded
through the deployed `P2pNodeBuilder`** (Run 365) — proven together on the real
`target/release/qbind-node` plus a release-built helper.

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready · **release-binary evidence** (no new CLI flag, no live
> deployment, no P2P wire-format change). The evidence is **deployed-builder-path release-binary**, not
> live-socket (see §21).

## 1. Exact verdict

**Partial-positive / public-DevNet-abuse-DoS-M12 end-to-end release-binary positive on the
deployed-builder path (M12 stays Yellow/Partial, strengthened — NOT Green).**

The release helper, harness, production-binary CLI scenarios, deployed-builder-path evidence, tests,
docs, secret scan, and CodeQL provenance all landed. The release-built helper links the real
Run 361/362/363/365 symbols and drives the per-peer scenarios through the **deployed** `P2pNodeBuilder`
methods (`with_abuse_dos_runtime_config` → `deployed_peer_rate_limiter_config` →
`deployed_async_peer_manager_config` → `build_deployed_peer_manager`), proving both controls in release
mode with defaults preserved. **M12 does not move Green** because a running `qbind-node` cannot be
driven over its live P2P inbound/message socket path in this environment: DevNet runs in LocalMesh mode
(`--enable-p2p` is ignored) and the node blocks in the consensus loop. M4 remains Yellow/launch-blocking;
M6 remains Yellow; public DevNet remains **NOT launch-ready**; Full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper.rs` —
  release-built helper (8 scenarios) that drives the per-peer scenarios through the deployed builder
  path.
- `scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh` — release-binary
  harness (build + hashes + helper + CLI surface + bounded node launch).
- `docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/README.md`
- `docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/summary.txt`
- `docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/.gitignore`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_366.md` — this file.

Modified (docs, narrow):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

**No production/library source changed.** No new public CLI flags. No P2P wire-format change. No default
change. Only the tracked archive files (`README.md`, `summary.txt`, `.gitignore`) are committed; all raw
logs/artifacts are `.gitignore`d.

## 3. Release artifacts and hashes

- `node_bin`: `target/release/qbind-node`
- `node_bin_sha256`: `1c4e546f3a766c006d2bd9601a3a404e9983c0e32d52fd8691b367ded667e381`
- `node_build_id`: `147246663749c27398299ae69a57140bf7d2b2f1`
- `helper_bin`: `target/release/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper`
- `helper_sha256`: `9cd59f7caa48705922d8fb7a77881d6175f80cf2e54e099290c336ff9dad9d47`
- `helper_build_id`: `511214803e24c9fc585ac6d78af9f443a5c5b8a6`
- toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)`

> SHA-256 / Build ID values are environment-specific (toolchain, absolute build path, dependency
> versions) and are recorded as reproducibility anchors for this build only.

## 4. Runtime evidence shape

Bounded loopback release-binary harness (task approaches B + C):

- **Deployed-builder path (release helper, approach C strengthened):** the release-built helper links
  the real Run 361/362/363/365 symbols and instantiates the **deployed** `P2pNodeBuilder` and its live
  `AsyncPeerManagerImpl` from the same release-built symbols, driving the per-peer scenarios through the
  Run 365 deployed methods rather than the direct `AsyncPeerManagerConfig` seam Run 364 used.
- **Bounded real-node launch (approach B):** a timeout-supervised real `target/release/qbind-node`
  starts on an explicit temporary `--data-dir` with `--enable-p2p` and the hidden abuse/DoS flags; it is
  reaped by the timeout (rc=124) after entering the consensus loop. On DevNet the node logs
  `enable_p2p=true ignored because network_mode=local-mesh`, so the live P2P accept/message socket path
  is **not** driven here — this is the documented blocker keeping M12 Yellow/Partial.

Only localhost / RFC 5737 (`192.0.2.0/24`) addresses are used. No live seed or external endpoint.

## 5. Helper / harness corpus

- Helper: `crates/qbind-node/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper.rs`
  (8 scenarios, all PASS).
- Harness: `scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh`
  (verdict PARTIAL-POSITIVE).
- Archive: `docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/` (only
  `README.md`, `summary.txt`, `.gitignore` tracked).

Helper scenarios:

1. `01_default_preserves_behavior` — deployed builder derives `None`; conn limiter disabled; per-peer
   `1000`/`100`; drop metric 0.
2. `02_connection_rate_end_to_end` — 4 admitted; over-budget `ConnectionRateLimited`; no peer admitted
   on refusal; metric increments per refusal.
3. `03_per_peer_message_rate_end_to_end` — deployed builder installs custom `5`/`0`; deployed peer
   manager honors it; 5 allowed; 6th dropped; connection-rate metric untouched.
4. `04_combined_independence` — connection refusal doesn't admit; message drop on admitted deployed
   path; counters distinct.
5. `05_invalid_configs_fail_closed` — zero-window / zero-msg / zero-conn / unbounded / inconsistent all
   rejected.
6. `06_mainnet_refused` — MainNet abuse/DoS config refused (direct + CLI).
7. `07_cli_surface_hidden_and_parse_checked` — hidden flags absent from `--help`; real parse; invented
   rejected.
8. `08_deployed_builder_matches_direct_default` — deployed default equals direct default (no drift).

## 6. Production-binary scenarios

1. `qbind-node --help` hides all 8 hidden Run 362/363 abuse/DoS flags — **true**.
2. Real hidden flags parse successfully on DevNet (`--version` short-circuit, rc=0) — **true**.
3. Invalid abuse/DoS config fail-closed — proven via release helper scenario 05 through the exact
   production validation fn `CliArgs::abuse_dos_runtime_config()` (a full-node run hangs in LocalMesh
   before the validation branch, so it is not re-run as a launch).
4. MainNet abuse/DoS enablement refused — proven via release helper scenario 06 through the same fn.
5. Invented abuse/DoS flag rejected with clap error (rc=2) — **true**.
6. Default DevNet/TestNet/MainNet surfaces unchanged — **true** (no new public flag).
7. No accidental public CLI flag exposure — **true**.

## 7. Connection-rate end-to-end evidence

Helper scenario 02: a tightened bucket (4 tokens, no burst) admits exactly 4 inbound attempts; the
over-budget attempt returns `ConnectionDecision::ConnectionRateLimited`, admits no peer, and increments
`qbind_p2p_connection_rate_drop_total` on each refusal. The connection-rate limiter is runtime-wired
into the live `p2p_tcp` accept loop (Run 362) and disabled by default.

## 8. Per-peer message-rate end-to-end evidence

Helper scenario 03: `--p2p-max-messages-per-second 5 --p2p-burst-allowance 0` flows
`CliArgs::abuse_dos_runtime_config()` → `P2pNodeBuilder::with_abuse_dos_runtime_config` →
`deployed_peer_rate_limiter_config` (installs `Some(5/0)`) → `build_deployed_peer_manager` →
`AsyncPeerManagerImpl` → live `PeerRateLimiter`. The deployed peer manager honors the custom values: 5
messages allowed, the 6th dropped, and the connection-rate metric stays 0. This exercises the Run 365
deployed-builder threading in release mode.

## 9. Combined limiter independence evidence

Helper scenario 04: with a 1-token connection bucket and a 3-token per-peer bucket derived from the same
validated posture (per-peer via the deployed builder), the first inbound is admitted and the second is
refused (connection metric → 1), while the admitted peer path allows 3 messages then drops the 4th
without touching the connection-rate counter. The two counters remain distinct.

## 10. Rejection / fail-closed evidence

Helper scenario 05 rejects zero connection-rate window, zero per-peer message max, zero connection-rate
max, unbounded per-peer message-rate, and inconsistent per-address config — all before any runtime state
or deployed peer manager is built. Scenario 06 refuses an enabled MainNet abuse/DoS config both directly
and via `--env mainnet`. Scenario 07 rejects invented flags via clap.

## 11. Default compatibility

Scenario 01 + 08: with no abuse/DoS flags the deployed builder derives `None`,
`deployed_async_peer_manager_config()` equals the default `AsyncPeerManagerConfig`, and the deployed
peer manager's limiter equals `PeerRateLimiter::with_defaults()` (`1000` msg/s + `100` burst) — bit-for-
bit identical to a directly-built default peer manager. The connection limiter stays disabled and the
drop metric stays 0.

## 12. CLI / config surface

No new public CLI flags. The hidden/devnet-only Run 362/363 flags remain absent from `--help`, parse on
the real binary when supplied, and reject invented variants. All 8 hidden flags are confirmed absent
from `--help` on `target/release/qbind-node`.

## 13. Metric evidence

`qbind_p2p_connection_rate_drop_total` renders exactly once (`registered_once: true`), with no endpoint
label leak (`endpoint_label_leak: false`); rendered line `qbind_p2p_connection_rate_drop_total 1`. The
metric increments only on connection-rate refusals and never on per-peer message drops.

## 14. Non-mutation evidence

Run 366 changes no production/library source. It performs no P2P wire-format change, no peer-admission
weakening, no trust-bundle behavior weakening, no `LivePqcTrustState` mutation, no sequence/marker
write, no validator-set mutation, no epoch transition, and no Run 070 path. It opens no P2P socket in
the helper and drives no live traffic; the bounded node launch is read-only startup reaped by timeout.

## 15. Readiness matrix delta for M12

M12: `Yellow/Partial (stronger, Run 365 — deployed-node per-peer threading landed at source/test level)`
→ `Yellow/Partial (stronger, Run 366 — deployed-builder-path release-binary end-to-end evidence for both
controls)`. **Not Green.** The deployed-builder path is now release-binary proven for both the
connection-rate limiter and the per-peer message-rate override, with defaults preserved. M12 remains
Yellow/Partial because a running `qbind-node` cannot be driven over its live P2P inbound/message socket
path here (DevNet LocalMesh ignores `--enable-p2p`), so live-socket end-to-end operator effect is not
demonstrated.

## 16. Current public DevNet readiness status

**NOT launch-ready.** Green: M1, M2, M3 (same-host scope), M5, M10, M11, M16–M20. Yellow/Partial: M4,
M6, M7–M9, M12 (strengthened), M13–M15. M4 remains launch-blocking.

## 17. Remaining public DevNet blockers

M4 (live seed/bootnode reachability) launch-blocking; M6 (stable identity generation); M7–M9, M13–M15;
and M12 live-socket end-to-end evidence (a running node driven over the real inbound/message path) plus
load evidence.

## 18. Public TestNet blockers

All public-DevNet blockers above, plus TestNet-scope reachability, identity, and abuse/DoS live-socket
end-to-end release evidence. **No TestNet readiness is claimed.**

## 19. MainNet blockers

MainNet authority rotation/revocation Red; no production abuse/DoS policy (MainNet refused by this
surface); Full C4/C5 OPEN. **No MainNet enablement.**

## 20. C4/C5 status

Full **C4 OPEN**; **C5 OPEN**. Unchanged by Run 366.

## 21. Tests run

- `cargo build -p qbind-node --release` — ok.
- `cargo build -p qbind-node --release --example run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper`
  — ok.
- `scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh` — PARTIAL-POSITIVE
  (helper PASS 8/8; CLI surface checks pass; bounded node launch reaped by timeout under LocalMesh).
- `cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests` —
  **20 passed; 0 failed**.
- `cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests` —
  **21 passed; 0 failed**.
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests` —
  **38 passed; 0 failed**.
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests` —
  **30 passed; 0 failed**.
- `cargo test -p qbind-node --lib` — **1385 passed; 0 failed**.

> Run 361 reconciliation: the authoritative count for
> `run_361_public_devnet_abuse_dos_hardening_tests` in this tree is **30 passed** (preserved from
> Run 364/365).

## 22. Security scans

Secret scanning run over all changed files — no secrets, keys, mnemonics, credentials, tokens, private
infrastructure, or live endpoints. All addresses in the helper/harness are RFC 5737 (`192.0.2.0/24`)
documentation ranges or localhost.

## 23. CodeQL

Run 366 adds a new Rust **example** (`run_366_..._release_helper.rs`) plus a shell harness and docs; it
changes **no** production/library source. Because a new Rust source file (the example) is added,
`codeql_checker` was invoked (declared non-trivial for the example). **Exact result: CodeQL analysis for
`rust` was SKIPPED — "Analysis was skipped because the database size is too large" (0 alerts returned
because the analysis did not run).** This is recorded verbatim and is **not** asserted as a clean scan.
The example contains no unsafe code, no I/O beyond writing evidence files under a caller-supplied output
dir, no network sockets, and no untrusted-input parsing beyond clap arg parsing already covered by the
production CLI.

## 24. Provenance

- branch: `copilot/run-366-update-application-logs`.
- base git commit: `12714a8a2c35ecf46fdcf95dc35714bc92336369`.
- clean/dirty: clean before this run; this run adds the helper/harness/archive/docs listed in §2.
- toolchain: `rustc 1.97.1 (8bab26f4f 2026-07-14)` / `cargo 1.97.1 (c980f4866 2026-06-30)`.
- helper path: `crates/qbind-node/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper.rs`.
- harness path: `scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh`.
- archive path: `docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/`.
- release binary SHA-256 / helper SHA-256 / Build IDs / toolchain: §3.
- helper scenarios: §5. production-binary scenarios: §6. runtime evidence shape: §4.
- test counts: §21. secret scan: §22. CodeQL: §23. readiness delta: §15.

## 25. Honest limitations

- **Deployed-builder-path release-binary, not live-socket.** The per-peer override is release-binary
  proven through the deployed `P2pNodeBuilder` construction path, but a running `qbind-node` is not
  driven over a real P2P inbound/message socket because DevNet runs in LocalMesh mode (`--enable-p2p`
  ignored) and blocks in the consensus loop.
- The two production-binary semantic-fail-closed scenarios are proven through the release helper (exact
  production validation fn), not a full-node launch, for the same LocalMesh-blocking reason.
- M12 stays Yellow; no Green, no launch-ready, no TestNet/MainNet readiness, no C4/C5 closure claim.
- M4 remains launch-blocking; M6 remains Yellow.

## 26. Suggested Run 367 next step

Provide live-socket end-to-end evidence: bring up a bounded real `qbind-node` in a P2P-capable network
mode (not LocalMesh) on loopback, drive real inbound connection attempts and per-peer message traffic
through the deployed `build_deployed_peer_manager` path, and observe `qbind_p2p_connection_rate_drop_total`
plus per-peer drops over the wire. If that live-socket evidence holds with defaults preserved, it would
justify evaluating the M12 Green gate.