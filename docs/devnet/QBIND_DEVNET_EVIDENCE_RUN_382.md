# QBIND DevNet Evidence - Run 382

Release-provenance injection for `qbind_node_build_info` on top of the accepted
Run 381 gauge hardening. Run 382 makes release-binary provenance visible through
the Run 381 `qbind_node_build_info` info metric by adding a safe, build-time
provenance path (decision gate Route B) for the `git_commit` and `build_id`
labels, while preserving every Run 381 metric-safety constraint. It is an
observability/provenance-only run.

Safety label: DevNet, experimental, no value, resettable, metrics loopback-only
by default, NOT public-DevNet launch-ready, no M4 Green, no M6 Green, no TestNet
readiness, no MainNet readiness, C4/C5 OPEN. This provenance hardening does not
imply launch, TestNet, MainNet, C4, or C5 readiness. The only source addition is a
build script that populates two compile-time metric label strings; no runtime
behaviour change, no new public endpoint, no CLI flag, no P2P wire-format change,
no peer-admission weakening, and no trust/validator/epoch/sequence/marker/
LivePqcTrustState mutation.

## 1. Exact verdict

PASS / public-DevNet build-info provenance hardening POSITIVE. A minimal build
script (`crates/qbind-node/build.rs`) bridges release provenance into the Run 381
`qbind_node_build_info` labels without any runtime change. On the release binary:

- default (no injection): `git_commit` is auto-derived to a short git commit hash
  and `build_id` renders `unknown`
  (`qbind_node_build_info{version="0.1.0",build_id="unknown",git_commit="4d2e13402562",env="devnet",chain_id="51424e4444455600"} 1`);
- injected (`QBIND_GIT_COMMIT` / `QBIND_BUILD_ID` set at build time): both labels
  are populated and honour the injected values
  (`build_id="run382-buildid-abc123"`, `git_commit="deadbeefcafe0382"`).

All labels are sanitized to `[A-Za-z0-9._-]`; no path/host/endpoint/secret label
leaks; missing provenance renders `unknown` (never a panic). The ELF
`.note.gnu.build-id` is captured separately from the metric `build_id` label and
the harness asserts they are distinct. The Run 381 `qbind_node_data_dir_free_bytes`
gauge remains intact; metrics stay disabled-by-default and loopback-only; scrape +
alert YAML parse; enabled alert expressions reference present metrics. M12, M13,
M14 remain Green; M4 remains Yellow; M6 remains Yellow/Partial; the public DevNet
remains NOT launch-ready; C4/C5 remain OPEN; TestNet/MainNet untouched.

## 2. Files changed

Production source (minimal; build-time provenance only, no runtime change):

- crates/qbind-node/build.rs (new): sanitizes and injects `QBIND_GIT_COMMIT`
  (explicit env override, else a short `git rev-parse --short=12 HEAD` derivation)
  and passes through a harness/CI-injected `QBIND_BUILD_ID` via
  `cargo:rustc-env`, which the existing `option_env!` labels in metrics.rs read.
- crates/qbind-node/Cargo.toml (`build = "build.rs"`).

Tests:

- crates/qbind-node/tests/run_382_public_devnet_build_info_provenance_tests.rs
  (new; 6 tests).

Observability package (provenance documentation only; no metric/alert change):

- docs/release/public-devnet/observability/METRICS.md
- docs/release/public-devnet/observability/VERIFY.md
- docs/release/public-devnet/observability/README.md

Binary provenance package (ELF BuildID vs metric build_id distinction):

- docs/release/public-devnet/binary/BUILDINFO.md
- docs/release/public-devnet/binary/README.md

Harness + archive + evidence:

- scripts/devnet/run_382_public_devnet_build_info_provenance.sh (new harness).
- docs/devnet/run_382_public_devnet_build_info_provenance/ (README.md, summary.txt,
  .gitignore) (new archive).
- docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_382.md (this evidence record).

Narrow run-log updates:

- docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
- docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md
- docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md
- docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md
- docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
- docs/whitepaper/contradiction.md

## 3. Decision gate route

Route B. Run 381 already exposed `qbind_node_build_info` with `build_id` /
`git_commit` read from `option_env!(QBIND_BUILD_ID)` / `option_env!(QBIND_GIT_COMMIT)`,
which rendered `unknown` unless the operator manually injected those env vars
(Route A would have required manual env at every build). A minimal, dependency-free
build script bridges provenance into those exact compile-time labels: it prefers an
explicit env value (CI / release harness), else derives a short git commit hash at
build time, and passes through a harness-injected build id. This keeps the label
set and the disabled-by-default loopback exposure exactly as Run 381 while making
release provenance visible automatically. No new dependency, CLI flag, endpoint, or
runtime code path is added.

## 4. Provenance injection design

- `build.rs` runs only at build time (it is not linked into the node) and emits
  `cargo:rustc-env=QBIND_GIT_COMMIT=<value>` / `cargo:rustc-env=QBIND_BUILD_ID=<value>`
  only when it has a value; the existing `option_env!` calls in `metrics.rs` read
  those at compile time, so no runtime shelling-out ever occurs in the node.
- `git_commit`: `QBIND_GIT_COMMIT` env wins (sanitized); otherwise
  `git rev-parse --short=12 HEAD` is run best-effort. On any failure (no git, not a
  work tree, non-UTF-8) the label is left unset → renders `unknown`.
- `build_id`: taken from a `QBIND_BUILD_ID` env value only. It is NEVER derived from
  git or the ELF. Missing → `unknown`.
- Both values are sanitized to `[A-Za-z0-9._-]`, length-capped at 64, and an
  all-placeholder result is dropped. `metrics.rs` sanitizes them a second time via
  `sanitize_info_label`. Only a commit hash is ever exposed — never a branch, tag,
  remote, dirty-state string, path, hostname, or username.
- `cargo:rerun-if-env-changed` (both vars) and a best-effort
  `cargo:rerun-if-changed` on the resolved git `HEAD` keep the label fresh across
  checkouts without forcing rebuilds.

## 5. qbind_node_build_info evidence

Observed on the release binary (summary.txt):

Default (no injection):

    qbind_node_build_info{version="0.1.0",build_id="unknown",git_commit="4d2e13402562",env="devnet",chain_id="51424e4444455600"} 1

Injected (`QBIND_GIT_COMMIT=deadbeefcafe0382 QBIND_BUILD_ID=run382-buildid-abc123`):

    qbind_node_build_info{version="0.1.0",build_id="run382-buildid-abc123",git_commit="deadbeefcafe0382",env="devnet",chain_id="51424e4444455600"} 1

- Value is always 1 (info metric); the label set is unchanged from Run 381
  (`version,build_id,git_commit,env,chain_id`).
- `version` is present (`0.1.0`, from `CARGO_PKG_VERSION`).
- `git_commit` is populated in both builds (auto-derived by default; overridden by
  the injected value).
- `build_id` is populated only when injected.

## 6. Missing-provenance fallback

- `build_id_default=OK build_id=unknown`: with no `QBIND_BUILD_ID` injection the
  build_id label renders exactly `unknown`, proving the fallback. It is never
  silently set to the git commit (unit test
  `build_id_is_never_derived_from_git_commit` asserts `build_id != git_commit`).
- `git_commit` likewise renders `unknown` when neither an env override nor a git
  derivation is available (build script degrades safely; the harness records the
  degraded outcome honestly if git is unavailable).
- The build never panics on provenance: every git/env read is `.ok()`-guarded.

## 7. Label safety

- All label values are sanitized to `[A-Za-z0-9._-]` in `build.rs` and again in
  `metrics.rs`. The harness asserts the label section contains no `/`, `@`, space,
  `\`, and no `:` inside any label value, and no secret-ish token
  (`secret|token|password|apikey|api_key|BEGIN`).
- No path, hostname, username, private endpoint, branch name, dirty-status string,
  or absolute build path can appear (only a commit hash / injected build id is ever
  emitted).

## 8. ELF BuildID vs metric build_id distinction

These are distinct provenance planes and the harness captures them separately:

- ELF `.note.gnu.build-id` (from `readelf -n`): a linker-computed binary identity,
  e.g. default `5cd3d4ce164ade109a67ed848cfad193e4aed7e4`, injected
  `55f049894c79168e84b88019ded073f300450c1a`. Recorded in
  `docs/release/public-devnet/binary/BUILDINFO.md`.
- `qbind_node_build_info` `build_id` label: an operator-facing, harness/CI-injected
  release identity (`run382-buildid-abc123` in the injected build).

`elf_vs_metric_build_id=OK`: the harness asserts the injected metric `build_id`
does not equal the ELF BuildID. The two are never conflated.

## 9. Disk metric regression

`disk_free_bytes_present=OK qbind_node_data_dir_free_bytes=86265159680` (value only,
no path/mount/host label). The Run 381 free-space gauge is unchanged and still
present when `--data-dir` is set.

## 10. Metrics endpoint/default compatibility

`metrics_disabled_by_default=OK`: a node started without `QBIND_METRICS_HTTP_ADDR`
logs no `/metrics` bind. `no_new_cli_flag=OK`: `qbind-node --help` exposes no
metrics/observability/build-info/provenance flag; provenance is build-time only.
The metrics transport (metrics_http.rs) is unchanged and binds loopback
(127.0.0.1) with HTTP 200 in the harness.

## 11. Alert/scrape config evidence

`scrape_config_yaml=OK` and `alert_rules_yaml=OK` (both example files parse).
`enabled_exprs_present=OK`: every enabled alert expression references a metric
present in the fresh scrape, the Prometheus `up` series, or the Run-380-proven
absent-until-drop per-peer series. No alert/scrape change was required this run.

## 12. Non-claim checks

`non_claim_check=OK`: no launch-ready / M4-Green / TestNet / MainNet / C4 / C5
closure claim in the observability docs. The evidence, README, and doc run-logs all
restate NOT launch-ready / M4 Yellow / M6 Yellow / C4-C5 OPEN.

## 13. Readiness matrix delta for M13

M13 remains Green. Operator telemetry is unchanged in shape; the `build_info` labels
now carry real release provenance (git commit + injected build id) instead of
`unknown`, widening auditability while preserving every prior Run 379/380/381
required family and the loopback-only, disabled-by-default exposure.

## 14. Readiness matrix delta for M14

M14 remains Green. Alert + scrape YAML still parse; no alert references a
non-existent series; the enabled/future split is unchanged from Run 381.

## 15. Current public DevNet readiness status

NOT launch-ready. Build-info provenance is an operator-facing auditability
improvement on a valueless, resettable DevNet; it does not launch a network.

## 16. Remaining public DevNet blockers

M4 (external seed reachability) remains Yellow / launch-blocking; M6 remains
Yellow/Partial (M4-gated). No live seed/bootnode, faucet, RPC gateway, explorer, or
status page. All out of scope for Run 382.

## 17. Public TestNet blockers

All public DevNet blockers above, plus TestNet-grade validator set / economics /
upgrade governance and sustained multi-operator soak - untouched by Run 382.

## 18. MainNet blockers

MainNet custody and MainNet authority rotation/revocation remain Red; C4/C5 must
close first. Untouched by Run 382.

## 19. C4/C5 status

C4 OPEN. C5 OPEN. Run 382 makes no closure claim and touches no
authority-lifecycle / validator-set / epoch / sequence / marker /
LivePqcTrustState surface.

## 20. Tests run

- cargo build -p qbind-node --release --bin qbind-node: OK (default sha256
  f4c58e74c482dadd7c0ed781c4a4ae42f7028b649d3bb47bb52762bb46fb0fdb, ELF BuildID
  5cd3d4ce164ade109a67ed848cfad193e4aed7e4).
- scripts/devnet/run_382_public_devnet_build_info_provenance.sh: RESULT=POSITIVE
  (default + injected release builds; all checks OK; see summary.txt).
- cargo test -p qbind-node --test run_382_public_devnet_build_info_provenance_tests:
  6 passed, 0 failed.
- cargo test -p qbind-node --lib: 1394 passed, 0 failed.
- YAML parse (scrape + alerts): pyyaml_ok for both example files.
- non-claim grep over the observability package: OK.

## 21. Security scans

secret_scanning over all changed files: no secrets. The injected provenance tokens
in the harness (`deadbeefcafe0382`, `run382-buildid-abc123`) are non-secret,
low-cardinality placeholders. The harness commits no private key, credential,
private hostname, raw log, data dir, git branch, dirty-state string, or raw
`/metrics` dump; only publish-safe hashes and status lines appear in the tracked
summary. Only loopback (127.0.0.1) is used.

## 22. CodeQL

CodeQL (rust) was invoked on the change set and returned: analysis **SKIPPED
because the database size is too large** (0 alerts, but the analysis did not run
to completion). Per policy this is **NOT** recorded as "clean". Manual review of
the only source addition (`build.rs`): every `git`/env read is `.ok()`-guarded so
the build never panics on provenance; values are sanitized to `[A-Za-z0-9._-]`
with a length cap before being emitted as `cargo:rustc-env`, and `metrics.rs`
sanitizes them again at render time, so no exposition-format injection is possible.
The build script never executes at node runtime and adds no runtime code path.

## 23. Provenance

Default release binary sha256
f4c58e74c482dadd7c0ed781c4a4ae42f7028b649d3bb47bb52762bb46fb0fdb, ELF BuildID
5cd3d4ce164ade109a67ed848cfad193e4aed7e4; injected build ELF BuildID
55f049894c79168e84b88019ded073f300450c1a; toolchain rustc 1.98.0 / cargo 1.98.0.
The metric `build_id` label (harness-injected `run382-buildid-abc123`) is distinct
from both ELF BuildIDs. Metrics observed by live loopback scrape of each binary.

## 24. Honest limitations

- Auto-derived `git_commit` requires `git` and a work tree at build time; a
  source-tarball or git-less build renders `git_commit="unknown"` unless
  `QBIND_GIT_COMMIT` is injected.
- `build_id` is only populated when the harness/CI injects `QBIND_BUILD_ID`; it is
  intentionally never derived, so a build with no injection keeps `build_id="unknown"`.
- Injecting `QBIND_GIT_COMMIT` / `QBIND_BUILD_ID` changes the compiled label
  strings and therefore the binary hash / ELF BuildID; reproducibility is per-input
  (same source + same injected provenance ⇒ same output).
- The metrics endpoint remains loopback-only with no auth/TLS and must stay
  loopback.

## 25. Suggested Run 383 next step

Wire the release-build harness (`docs/release/public-devnet/binary/`) to inject a
canonical `QBIND_BUILD_ID` (e.g. the ELF BuildID or a release tag) and the release
`QBIND_GIT_COMMIT` so published artifacts ship populated provenance by default,
and/or begin M4 external seed reachability work (out of scope here), which remains
the top launch blocker.