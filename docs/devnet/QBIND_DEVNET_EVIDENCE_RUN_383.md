# QBIND DevNet Evidence - Run 383

Canonical injected release provenance + same-input reproducibility on top of the
accepted Run 382 build-info provenance bridge. Run 382 added
`crates/qbind-node/build.rs`, which bridges `QBIND_GIT_COMMIT` / `QBIND_BUILD_ID`
into the compile-time `qbind_node_build_info` labels but proved only a single
injected build. Run 383 wires the bridge to **canonical injected** values for a
published release artifact (so `git_commit` / `build_id` ship populated by default)
and proves the injected build is **same-input reproducible**. It is a
**docs/harness-only** run (decision gate Route A): it adds **no** production source
change and **no** CLI flag.

Safety label: DevNet, experimental, no value, resettable, metrics loopback-only by
default, NOT public-DevNet launch-ready, no M4 Green, no M6 Green, no TestNet
readiness, no MainNet readiness, C4/C5 OPEN. This provenance/reproducibility
evidence does not imply launch, TestNet, MainNet, C4, or C5 readiness. There is no
source or `build.rs` change; the run only chooses canonical injected provenance
values, builds with them, scrapes the resulting metric on loopback, and proves
reproducibility. No new public endpoint, no CLI flag, no P2P wire-format change, no
peer-admission weakening, and no trust/validator/epoch/sequence/marker/
LivePqcTrustState mutation.

## 1. Exact verdict

PASS / public-DevNet injected release provenance reproducibility POSITIVE. The
release harness injects canonical provenance
(`QBIND_GIT_COMMIT=e7934da3c8bc`, `QBIND_BUILD_ID=qbind-devnet-0.1.0-e7934da3c8bc`)
and a live loopback scrape shows both labels populated:

    qbind_node_build_info{version="0.1.0",build_id="qbind-devnet-0.1.0-e7934da3c8bc",git_commit="e7934da3c8bc",env="devnet",chain_id="51424e4444455600"} 1

The injected `git_commit` equals the expected short commit; the injected `build_id`
equals the canonical release id. Two clean `--locked` builds with the same source,
lockfile, toolchain, and injected provenance are **byte-identical**
(`cdf8bfb815bb25057b1d6716028bd6083206a1efb1c05d59b7c3811c7999b004`, `cmp -s` exit
0), matched by the default-target build; a **changed** injected `build_id` changes
the hash (`ba2fb14de9be262f687c0c21739c8d7b2387043440ef20a547b6795ef0299102`, as
expected). The ELF `.note.gnu.build-id`
(`924ddf144fac4f5f0705496f185b06fa892205c8`) is captured separately and is distinct
from the metric `build_id`. The Run 382 missing-injection fallback
(`build_id="unknown"`) is preserved; metrics stay disabled-by-default and
loopback-only; scrape + alert YAML parse; the non-claim grep passes. M12, M13, M14
remain Green; M4 remains Yellow; M6 remains Yellow/Partial; the public DevNet
remains NOT launch-ready; C4/C5 remain OPEN; TestNet/MainNet untouched.

## 2. Files changed

No production source or `build.rs` change (docs/harness only).

Harness + archive + evidence:

- scripts/devnet/run_383_public_devnet_release_provenance_injected_repro.sh (new harness).
- docs/devnet/run_383_public_devnet_release_provenance_injected_repro/ (README.md,
  summary.txt, .gitignore) (new archive).
- docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md (this evidence record).

Binary provenance package (canonical injected build command + reproducibility):

- docs/release/public-devnet/binary/README.md
- docs/release/public-devnet/binary/BUILDINFO.md
- docs/release/public-devnet/binary/REPRODUCIBILITY.md
- docs/release/public-devnet/binary/VERIFY.md

Observability package (canonical injected provenance documentation only; no
metric/alert change):

- docs/release/public-devnet/observability/METRICS.md
- docs/release/public-devnet/observability/VERIFY.md

Narrow run-log updates:

- docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
- docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md
- docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md
- docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md
- docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
- docs/whitepaper/contradiction.md

## 3. Decision gate route

Route A (docs/harness only). Run 382 already added the `build.rs` provenance bridge
(that was its Route B source change). Run 383 needs no further source change: it
picks canonical injected values, drives the existing bridge via the standard
`QBIND_GIT_COMMIT` / `QBIND_BUILD_ID` env, and proves reproducibility with a shell
harness plus documentation. No new dependency, CLI flag, endpoint, or runtime code
path is added.

## 4. Canonical injected provenance values

- `QBIND_GIT_COMMIT=e7934da3c8bc` — the expected short commit,
  `git rev-parse --short=12 HEAD` at build time.
- `QBIND_BUILD_ID=qbind-devnet-0.1.0-e7934da3c8bc` — a canonical, low-cardinality,
  non-secret release id derived deterministically from the package version
  (`0.1.0`) + short commit. It is **injected** (never derived inside `build.rs`
  from git or the ELF) and is intentionally **not** the ELF BuildID.

Both are non-secret, low-cardinality tokens sanitized to `[A-Za-z0-9._-]` by
`build.rs` and again by `metrics.rs`.

## 5. Build command

    QBIND_GIT_COMMIT=e7934da3c8bc \
    QBIND_BUILD_ID=qbind-devnet-0.1.0-e7934da3c8bc \
      cargo build -p qbind-node --release --locked --bin qbind-node

The two same-input reproducibility builds run the identical command with isolated
`CARGO_TARGET_DIR`s; the changed-input build uses `…-e7934da3c8bc-alt` as the
`QBIND_BUILD_ID`.

## 6. qbind_node_build_info evidence

Observed on the canonical release binary via a live loopback `/metrics` scrape
(HTTP 200, `127.0.0.1`):

    qbind_node_build_info{version="0.1.0",build_id="qbind-devnet-0.1.0-e7934da3c8bc",git_commit="e7934da3c8bc",env="devnet",chain_id="51424e4444455600"} 1

- value always 1 (info metric); label set unchanged from Run 381/382.
- `version=0.1.0` present.
- `git_commit=e7934da3c8bc` equals the expected short commit.
- `build_id=qbind-devnet-0.1.0-e7934da3c8bc` equals the canonical release id.

## 7. Same-input reproducibility evidence

Two clean `--locked` builds in isolated `CARGO_TARGET_DIR`s with the same source,
lockfile, toolchain, and canonical injected provenance:

    repro_build1_sha256=cdf8bfb815bb25057b1d6716028bd6083206a1efb1c05d59b7c3811c7999b004
    repro_build2_sha256=cdf8bfb815bb25057b1d6716028bd6083206a1efb1c05d59b7c3811c7999b004
    same_input_reproducible=OK (build1 == build2, byte-identical, cmp -s exit 0)
    repro_elf_build_id_stable=OK elf_build_id=924ddf144fac4f5f0705496f185b06fa892205c8

The default-target canonical artifact matches both isolated builds
(`canonical_matches_repro=OK`), i.e. all three builds hash to
`cdf8bfb815bb25057b1d6716028bd6083206a1efb1c05d59b7c3811c7999b004` with ELF BuildID
`924ddf144fac4f5f0705496f185b06fa892205c8`. This is a same-host, per-input result
(see §24).

## 8. Changed-input hash-difference evidence

Rebuilding the same source with a **different** injected `build_id`
(`qbind-devnet-0.1.0-e7934da3c8bc-alt`) changes the binary:

    changed_input_sha256=ba2fb14de9be262f687c0c21739c8d7b2387043440ef20a547b6795ef0299102
    changed_input_changes_hash=OK (different injected build_id => different SHA-256, as expected)

`ba2fb14d…` != `cdf8bfb8…`, confirming the injected provenance is compiled into the
binary and reproducibility is per-input.

## 9. ELF BuildID vs metric build_id

Distinct provenance planes, captured separately:

- ELF `.note.gnu.build-id` (from `readelf -n`):
  `924ddf144fac4f5f0705496f185b06fa892205c8` — a linker-computed binary identity,
  recorded in `docs/release/public-devnet/binary/BUILDINFO.md`.
- `qbind_node_build_info` `build_id` label:
  `qbind-devnet-0.1.0-e7934da3c8bc` — an operator-facing, harness-injected canonical
  release identity.

`elf_vs_metric_build_id=OK`: the harness asserts the metric `build_id` does not
equal the ELF BuildID. They are never conflated (metric `build_id` preferred
distinct).

## 10. Metrics endpoint/default compatibility

`metrics_disabled_by_default=OK`: a node started without `QBIND_METRICS_HTTP_ADDR`
logs no `/metrics` bind. `no_new_cli_flag=OK`: `qbind-node --help` exposes no
metrics/observability/build-info/provenance flag; provenance is build-time only.
The metrics transport (metrics_http.rs) is unchanged and binds loopback
(127.0.0.1) with HTTP 200 in the harness. Missing-injection fallback
(`missing_injection_fallback=OK`): a build with no `QBIND_BUILD_ID` does not embed
the canonical id and the metric renders `build_id="unknown"` (Run 382 regression).

## 11. Label safety

All label values are sanitized to `[A-Za-z0-9._-]` in `build.rs` and again in
`metrics.rs`. The harness asserts the label section contains no `/`, `@`, space,
`\`, no `:` inside any label value, and no secret-ish token
(`secret|token|password|apikey|api_key|BEGIN`). Only a commit hash and the
canonical injected release id are ever emitted — no path, hostname, username,
private endpoint, branch name, dirty-status string, or absolute build path.

## 12. Alert/scrape config evidence

`scrape_config_yaml=OK` and `alert_rules_yaml=OK` (both example files parse). No
alert/scrape change was required this run; the Run 381 disk gauge / alert and the
enabled/future split are unchanged.

## 13. Non-claim checks

`non_claim_check=OK`: no launch-ready / M4-Green / TestNet / MainNet / C4 / C5
closure claim in the release-binary + observability docs (verification-command and
negation lines are excluded from the forbidden-claim match). The evidence, README,
and doc run-logs all restate NOT launch-ready / M4 Yellow / M6 Yellow / C4-C5 OPEN.

## 14. Readiness M13

M13 remains Green. Operator telemetry is unchanged in shape; the published release
artifact now ships **canonical** release provenance (`git_commit` + canonical
`build_id`) by default rather than `unknown`, widening auditability while preserving
every Run 379/380/381/382 required family and the loopback-only, disabled-by-default
exposure.

## 15. Readiness M14

M14 remains Green. Alert + scrape YAML still parse; no alert references a
non-existent series; the enabled/future split is unchanged from Run 381/382.

## 16. Public DevNet status

NOT launch-ready. Canonical injected release provenance + reproducibility is an
operator-facing auditability improvement on a valueless, resettable DevNet; it does
not launch a network.

## 17. Remaining DevNet blockers

M4 (external seed reachability) remains Yellow / launch-blocking; M6 remains
Yellow/Partial (M4-gated). No live seed/bootnode, faucet, RPC gateway, explorer, or
status page. All out of scope for Run 383.

## 18. TestNet blockers

All public DevNet blockers above, plus TestNet-grade validator set / economics /
upgrade governance and sustained multi-operator soak — untouched by Run 383.

## 19. MainNet blockers

MainNet custody and MainNet authority rotation/revocation remain Red; C4/C5 must
close first. Untouched by Run 383.

## 20. C4/C5

C4 OPEN. C5 OPEN. Run 383 makes no closure claim and touches no
authority-lifecycle / validator-set / epoch / sequence / marker / LivePqcTrustState
surface.

## 21. Tests run

- Canonical injected release build:
  `QBIND_GIT_COMMIT=e7934da3c8bc QBIND_BUILD_ID=qbind-devnet-0.1.0-e7934da3c8bc cargo build -p qbind-node --release --locked --bin qbind-node`:
  OK (sha256 `cdf8bfb815bb25057b1d6716028bd6083206a1efb1c05d59b7c3811c7999b004`,
  ELF BuildID `924ddf144fac4f5f0705496f185b06fa892205c8`).
- Same-input reproducibility build 1 and build 2 (isolated `CARGO_TARGET_DIR`s):
  both `cdf8bfb8…`, byte-identical (`cmp -s` exit 0).
- Changed-input build (`build_id …-alt`): sha256
  `ba2fb14de9be262f687c0c21739c8d7b2387043440ef20a547b6795ef0299102` (differs, as
  expected).
- scripts/devnet/run_383_public_devnet_release_provenance_injected_repro.sh:
  RESULT=POSITIVE (all checks OK; see summary.txt).
- cargo test -p qbind-node --test run_382_public_devnet_build_info_provenance_tests:
  6 passed, 0 failed.
- cargo test -p qbind-node --lib: 1394 passed, 0 failed.
- YAML parse (scrape + alerts): pyyaml_ok for both example files.
- non-claim grep over the release-binary + observability packages: OK.

## 22. Security scans

secret_scanning over all changed files: no secrets. The canonical injected
provenance tokens (`e7934da3c8bc`, `qbind-devnet-0.1.0-e7934da3c8bc`) are non-secret,
low-cardinality identifiers. The harness commits no private key, credential, private
hostname, raw log, data dir, git branch, dirty-state string, or raw `/metrics` dump;
node data dirs, scrape dumps, and the isolated reproducibility `CARGO_TARGET_DIR`s
are removed on exit; only publish-safe hashes and status lines appear in the tracked
summary. Only loopback (127.0.0.1) is used.

## 23. CodeQL

No production Rust / `build.rs` change in this run (docs + shell harness only), so
CodeQL is **trivial / not meaningful** for Run 383: there is no compiled-code delta
to analyze. The only source change that introduced the provenance bridge
(`build.rs`) was already analyzed/manually reviewed under Run 382 and is unchanged
here.

## 24. Provenance

Canonical release binary sha256
`cdf8bfb815bb25057b1d6716028bd6083206a1efb1c05d59b7c3811c7999b004`, ELF BuildID
`924ddf144fac4f5f0705496f185b06fa892205c8`; both same-input reproducibility builds
hash identically; changed-input build sha256
`ba2fb14de9be262f687c0c21739c8d7b2387043440ef20a547b6795ef0299102`; toolchain
`rustc 1.98.0 (88d9e12ae 2026-08-18)` / `cargo 1.98.0 (797e8a9bc 2026-08-05)`;
target `x86_64-unknown-linux-gnu`; git commit `e7934da3c8bc`; canonical injected
metric `build_id=qbind-devnet-0.1.0-e7934da3c8bc` (distinct from the ELF BuildID).
Metrics observed by live loopback scrape of the canonical binary.

## 25. Honest limitations

- **Same-host, per-input only.** Reproducibility holds for the same host,
  toolchain, lockfile, and injected provenance. A different host/toolchain/target,
  or a different injected `git_commit` / `build_id`, legitimately changes the
  SHA-256 / ELF BuildID (the injected values are compiled in). Cross-host
  reproducibility, SLSA-grade provenance, and signed-release attestation are **not**
  claimed.
- **git-dependent commit.** The canonical `QBIND_GIT_COMMIT` is derived from
  `git rev-parse` at build time; a source-tarball / git-less build must inject it
  explicitly or `git_commit` renders `unknown`.
- **No launch impact.** This is auditability/reproducibility evidence only; M4/M6
  remain the launch blockers and are untouched.
- The metrics endpoint remains loopback-only with no auth/TLS and must stay
  loopback.

## 26. Suggested Run 384

Adopt the canonical injected release build in CI so published DevNet artifacts are
built with `QBIND_GIT_COMMIT` / `QBIND_BUILD_ID` and the SHA-256 / ELF BuildID /
canonical `build_id` are recorded per release, and/or begin M4 external seed
reachability work (out of scope here), which remains the top launch blocker.
