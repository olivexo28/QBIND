# QBIND DevNet Evidence — Run 043

**Date:** 2026-05-11
**Branch:** `copilot/continue-qbind-development-0ef11146-5396-4b0f-a1f7-a9cd29614a41`
**Scope:** Observability-only.
**Verdict:** **PARTIAL POSITIVE** (see §13 for exact boundary).

---

## 1. Exact objective

Close the inherited Run 038/039/040/041/042 observability gap recorded in
`docs/whitepaper/contradiction.md` Run 041 C4 update:

> `qbind_p2p_pqc_*` live `/metrics` exposure (Run 038/039/040/041 inherited
> OPEN gap — declared in `P2pMetrics::format_metrics` but not wired through
> `NodeMetrics::format_metrics`)

by wiring the existing `P2pMetrics::format_metrics()` output through
`NodeMetrics::format_metrics` / `NodeMetrics::format_metrics_with_crypto`,
**without** changing protocol behaviour, KEMTLS behaviour, cert/root
lifecycle, consensus behaviour, or cryptographic behaviour, and **without**
fabricating metric values.

The fix has **two surgically-paired layers** — both needed for the live
`/metrics` endpoint to actually emit `qbind_p2p_pqc_*` lines from the real
binary:

1. **Formatter wiring.** `NodeMetrics::format_metrics` did not call
   `self.p2p.format_metrics()`, so the family was structurally absent from
   the live HTTP body served by `metrics_http::format_metrics_output`.
2. **Instance sharing.** `P2pNodeBuilder::build()` minted a *fresh local*
   `Arc<P2pMetrics>` instead of using the one owned by `NodeMetrics`, so
   even after (1), the family lines would print but every counter would
   stay at 0 because every live transport increment landed on a separate,
   never-scraped `P2pMetrics` instance.

Both layers are addressed; layer (2) was discovered during real-binary
verification of layer (1) and is the truly-missing link beyond what the
problem statement's preferred minimal edit captured. See §6 for honest
record.

---

## 2. Exact files changed

| File | Change |
|---|---|
| `crates/qbind-node/src/metrics.rs` | (a) Insert `self.p2p.format_metrics()` into `NodeMetrics::format_metrics` (after `peer_network`, before `connection_limit`), exactly once. (b) Change `NodeMetrics::p2p` field type from `P2pMetrics` to `Arc<P2pMetrics>` and initialize as `Arc::new(P2pMetrics::new())`. (c) Add `NodeMetrics::p2p_arc(&self) -> Arc<P2pMetrics>` accessor. (d) Add 8 new `#[test]` cases under `mod tests` proving the wiring (see §5). Existing `pub fn p2p(&self) -> &P2pMetrics` API unchanged at the call-site level (deref coercion of `&Arc<P2pMetrics>` to `&P2pMetrics`). |
| `crates/qbind-node/src/p2p_node_builder.rs` | (a) Add `p2p_metrics: Option<Arc<P2pMetrics>>` field on `P2pNodeBuilder` (defaults `None` in `P2pNodeBuilder::new`). (b) Add builder method `P2pNodeBuilder::with_p2p_metrics(mut self, metrics: Arc<P2pMetrics>) -> Self`. (c) In `build()`, replace `let metrics = Arc::new(P2pMetrics::new());` with `let metrics = self.p2p_metrics.clone().unwrap_or_else(|| Arc::new(P2pMetrics::new()));`. No changes to any cert-verify, KEM, AEAD, or handshake logic. |
| `crates/qbind-node/src/main.rs` | In `run_p2p_node`, append `.with_p2p_metrics(node_metrics.p2p_arc())` to the existing `P2pNodeBuilder::new()` chain. This is the only call-site that wires the shared metrics instance into the live binary path. No other production code path needs adjustment. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_043.md` | NEW — this document. |
| `docs/whitepaper/contradiction.md` | Run 043 C4 update row appended (see §10). |

**Files NOT changed (explicit non-scope, preserved bit-for-bit):**

- `crates/qbind-crypto/**` — no crypto behaviour changes.
- `crates/qbind-net/**` — no KEMTLS, cert-verify, KEM, or AEAD changes.
- Any `binary_consensus_loop.rs`, `verify_*`, `pqc_root_config.rs`,
  `pqc_devnet_helper.rs`, `forged_injection.rs`, or `signer_loader.rs`
  protocol surface.
- Existing `qbind_p2p_pqc_*` metric **names** (kept stable; no rename).
- Existing aggregate-of-per-reason rejection counter contract (Run 037
  contract: each per-reason `inc_*` also bumps
  `cert_verify_rejected_total`).

---

## 3. Investigation findings (exact file/function references)

### 3.1 Metric definitions

| Symbol | Location |
|---|---|
| `P2pMetrics` struct | `crates/qbind-node/src/metrics.rs:5416` |
| `impl P2pMetrics` | `crates/qbind-node/src/metrics.rs:5549` |
| `P2pMetrics::format_metrics` | `crates/qbind-node/src/metrics.rs:6039` (header `# P2P transport metrics (T172)` at 6042; `qbind_p2p_pqc_*` family emitted from this same function, the 10 names at lines 6280–6362 are the field accessors / setters wired to those output lines) |
| `P2pMetrics::set_pqc_root_mode` | `crates/qbind-node/src/metrics.rs:6283` |
| `P2pMetrics::set_pqc_roots_configured` | `crates/qbind-node/src/metrics.rs:6290` |
| `P2pMetrics::inc_pqc_cert_verify_accepted` | `crates/qbind-node/src/metrics.rs:6297` |
| `P2pMetrics::inc_pqc_cert_verify_rejected_*` (6 reasons) | `crates/qbind-node/src/metrics.rs:6305–6335` |
| `NodeMetrics` struct | `crates/qbind-node/src/metrics.rs:7754` (field `p2p` was `P2pMetrics`, now `Arc<P2pMetrics>`) |
| `NodeMetrics::p2p()` accessor | `crates/qbind-node/src/metrics.rs:7952` |
| `NodeMetrics::p2p_arc()` (Run 043 NEW) | `crates/qbind-node/src/metrics.rs:7965` |
| `NodeMetrics::format_metrics` | `crates/qbind-node/src/metrics.rs` (`self.p2p.format_metrics()` inserted after `peer_network`, before `connection_limit`, exactly once) |
| `NodeMetrics::format_metrics_with_crypto` | composes its output on top of `format_metrics`, so the Run 043 insertion in `format_metrics` covers both live paths automatically (verified by §5 test `run_043_node_metrics_format_metrics_with_crypto_includes_pqc_family`) |
| `metrics_http::format_metrics_output` | `crates/qbind-node/src/metrics_http.rs:468–484` (dispatches to either `format_metrics` or `format_metrics_with_crypto`) |
| HTTP `/metrics` body builder | `crates/qbind-node/src/metrics_http.rs:450` (`let body = format_metrics_output(metrics, crypto_refs);`) |

### 3.2 Why `qbind_p2p_pqc_*` was missing from live `/metrics` before Run 043

Two stacked reasons:

**(a) Formatter never delegated.** `metrics_http::format_metrics_output`
(line 468 of `metrics_http.rs`) calls either
`metrics.format_metrics_with_crypto(...)` or `metrics.format_metrics()`.
Before Run 043, `NodeMetrics::format_metrics` walked through `network`,
`runtime`, `spawn_blocking`, `peer_network`, `connection_limit`, KEM,
storage, consensus, timeout-verification, dag_coupling, monetary, etc.,
but did **not** call `self.p2p.format_metrics()`. The
`# P2P transport metrics (T172)` block and all `qbind_p2p_pqc_*` lines
were therefore structurally absent from the live HTTP response body.
This is the "missing link" the problem statement preferred-edit
identifies.

**(b) Instance divergence (discovered during §6 real-binary verification
of (a)).** Even after fixing (a), real-binary scrape under
`pqc-static-root` mode showed `qbind_p2p_pqc_root_mode 0` and
`qbind_p2p_pqc_roots_configured 0` — because `P2pNodeBuilder::build()`
constructs its **own** `let metrics = Arc::new(P2pMetrics::new());` at
`p2p_node_builder.rs:1091` (pre-Run-043), and that fresh instance —
populated by `metrics.set_pqc_root_mode(pqc_mode_n)` at line 1107 and
later by every live cert-verify path — is a *different* `Arc<P2pMetrics>`
from `NodeMetrics::p2p`, which is what `format_metrics_output` actually
scrapes. Fix (a) without fix (b) would honestly emit the names but with
every value pinned at 0, which the strict scope policy
("do not add placeholder counters that always report success") would
violate.

### 3.3 Counter source map (honest)

| Counter / gauge | Live binary call site (besides `mod tests`) | Status |
|---|---|---|
| `qbind_p2p_pqc_root_mode` | `p2p_node_builder.rs:1107` (`metrics.set_pqc_root_mode(pqc_mode_n)`) | **Wired** — now correctly reflects `pqc-static-root` (=1) on live `/metrics` after the Run 043 instance-sharing fix. |
| `qbind_p2p_pqc_roots_configured` | `p2p_node_builder.rs:1108` (`metrics.set_pqc_roots_configured(pqc_roots_n)`) | **Wired** — same. |
| `qbind_p2p_pqc_cert_verify_accepted_total` | _(no live call site — declared but never incremented from production code)_ | **Declared, not yet incremented** — `grep -rn 'inc_pqc_cert_verify_accepted' crates/` returns only the metrics-module definition and Run 043's own deterministic tests. Documented honestly; **not** fabricated by Run 043. |
| `qbind_p2p_pqc_cert_verify_rejected_total` | _(aggregate; bumped by every per-reason `inc_*`)_ | Will increment when any per-reason inc is wired. |
| `qbind_p2p_pqc_cert_rejected_unknown_root_total` | _(no live call site)_ | Same as above. |
| `qbind_p2p_pqc_cert_rejected_wrong_suite_total` | _(no live call site)_ | Same. |
| `qbind_p2p_pqc_cert_rejected_bad_signature_total` | _(no live call site)_ | Same. |
| `qbind_p2p_pqc_cert_rejected_validator_mismatch_total` | _(no live call site)_ | Same. |
| `qbind_p2p_pqc_cert_rejected_malformed_total` | _(no live call site)_ | Same. |
| `qbind_p2p_pqc_cert_rejected_expired_total` | _(no live call site)_ | Same. |

Per the problem statement: *"If some `qbind_p2p_pqc_*` metrics are declared
but not incremented anywhere, document honestly; do not fake increments."*
Run 043 honours this by **not** adding placeholder increment call sites in
`qbind-net::verify_delegation_cert` or anywhere else. Wiring the increments
into the live cert-verify path is a separate, well-scoped follow-up
(suggested as Run 044 in §15).

---

## 4. Exact implementation change

### 4.1 `crates/qbind-node/src/metrics.rs`

- Insertion in `NodeMetrics::format_metrics()`:

  ```rust
  // Per-peer metrics (T90.4)
  output.push_str(&self.peer_network.format_metrics());

  // P2P transport / PQC root metrics (T172, T205, T206, T226, Run 037 PQC).
  //
  // Run 043: wire `P2pMetrics::format_metrics()` (...) into the live
  // `/metrics` output (...). Emitted exactly once.
  output.push('\n');
  output.push_str(&self.p2p.format_metrics());

  // Connection limit metrics (T105)
  output.push_str(&self.connection_limit.format_metrics());
  ```

- Field & accessor:

  ```rust
  // BEFORE: p2p: P2pMetrics,
  // AFTER:
  p2p: Arc<P2pMetrics>,
  // ...
  // ctor: p2p: Arc::new(P2pMetrics::new()),
  // ...
  pub fn p2p(&self) -> &P2pMetrics { &self.p2p }
  pub fn p2p_arc(&self) -> Arc<P2pMetrics> { Arc::clone(&self.p2p) }
  ```

### 4.2 `crates/qbind-node/src/p2p_node_builder.rs`

- New `Option<Arc<P2pMetrics>>` field, `with_p2p_metrics` setter, and one
  line in `build()`:

  ```rust
  let metrics = self
      .p2p_metrics
      .clone()
      .unwrap_or_else(|| Arc::new(P2pMetrics::new()));
  ```

### 4.3 `crates/qbind-node/src/main.rs`

- One line appended to the existing builder chain in `run_p2p_node`:

  ```rust
  let builder = P2pNodeBuilder::new()
      .with_num_validators(num_validators as usize)
      .with_consensus_handler(Arc::new(consensus_handler))
      .with_mutual_auth_mode(mutual_auth_mode)
      .with_p2p_metrics(node_metrics.p2p_arc()); // Run 043
  ```

**Proof emitted exactly once:** §5 test
`run_043_pqc_family_emitted_exactly_once_in_format_metrics` and
`run_043_pqc_family_emitted_exactly_once_in_format_metrics_with_crypto`
assert `count == 1` for every member of the 10-element family on both
formatter paths. §5 test `run_043_pqc_section_header_emitted_once`
additionally pins the section header
`# P2P transport metrics (T172)` to exactly 1 occurrence. Confirmed live
on the real binary (§7) with `grep -c "^# P2P transport metrics (T172)" =
1` on both V0 and V1 metrics dumps.

---

## 5. Tests run and pass/fail status

| Command | Result | Notes |
|---|---|---|
| `cargo test -p qbind-node --lib metrics` | **100 / 100 PASS** | Includes 8 new `run_043_*` tests listed below + all existing metrics tests. |
| `cargo test -p qbind-node --lib p2p` | **138 / 138 PASS** | Builder, demuxer, p2p_diversity, p2p_node_builder tests all green; `with_p2p_metrics` does not break any builder-only test (the `unwrap_or_else` fallback preserves pre-Run-043 path bit-for-bit). |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **14 / 14 PASS** | Run 040 contract preserved. |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **12 / 12 PASS** | Run 037 contract preserved. |
| `cargo test -p qbind-node --lib` | **775 / 775 PASS** | = 767 (pre-Run-043, per Run 041) + 8 new `run_043_*` tests. Zero regressions. |
| `cargo test -p qbind-crypto --lib` | **68 / 68 PASS** | Crypto unchanged. |
| `cargo test -p qbind-net --lib` | **15 / 15 PASS** | Net unchanged. |
| `cargo build --release -p qbind-node --bin qbind-node` | **OK** | sha256 = `9ecfb8a4d61cb51457f533a903c80d51dbc5da92f6c1e05816284e48b8a1e63f`. Only the same 3 pre-existing warnings as Run 041. |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | **OK** | sha256 = `43ab13016bba36dc3db4e43df1fbc177456a8a4075ddcf01968ee3aef8d463c8`. |

### 5.1 New `run_043_*` tests (all PASS)

1. `run_043_node_metrics_format_metrics_includes_pqc_family` — every name in the 10-element family present in `NodeMetrics::format_metrics()`.
2. `run_043_node_metrics_format_metrics_with_crypto_includes_pqc_family` — every name present in `NodeMetrics::format_metrics_with_crypto(None, None)`.
3. `run_043_pqc_family_emitted_exactly_once_in_format_metrics` — each name occurs at line-start exactly once.
4. `run_043_pqc_family_emitted_exactly_once_in_format_metrics_with_crypto` — same, on the wrapper path.
5. `run_043_zero_valued_pqc_rejection_counters_visible_by_default` — `cert_rejected_*_total 0` lines visible at zero (existing P2pMetrics style emits zero counters; operators can alarm on `== 0`).
6. `run_043_non_zero_pqc_counters_propagate_through_node_formatter` — `set_pqc_root_mode(1)`, `set_pqc_roots_configured(2)`, 3× `inc_pqc_cert_verify_accepted`, one of each per-reason `inc_pqc_cert_verify_rejected_*` ⇒ `accepted_total 3`, `rejected_total 6`, each per-reason `_total 1`. Asserts on both `format_metrics()` and `format_metrics_with_crypto(...)`.
7. `run_043_pqc_wiring_does_not_regress_existing_metric_surfaces` — `consensus_net_inbound_total{kind="vote"}`, `consensus_events_total{kind="tick"}`, `consensus_net_spawn_blocking_total`, `qbind_timeout_verification_active|signer_loaded|key_provider_loaded|validator_count`, `qbind_net_kem_encaps_total|decaps_total` all still present.
8. `run_043_pqc_section_header_emitted_once` — `# P2P transport metrics (T172)` appears exactly once in both formatter outputs.

---

## 6. Real-binary positive smoke (two-node `pqc-static-root` Required)

### 6.1 Topology

- Same Run 040/041/042 binary recipe; release-binary sha256s in §5.
- DevNet-ephemeral materials from
  `target/release/examples/devnet_pqc_root_helper /tmp/run043/mat 2`
  (one shared root `4abf0794...`, sig suite 100, KEM suite 100, root pk
  fingerprint `fp=b52fcdbb`; helper's root signing key never written to
  disk; only `root.id.hex`/`root.pk.hex`/`trusted-root.spec`/2×
  `v{N}.cert.bin`/2× `v{N}.kem.sk.bin` produced).
- V0 on `127.0.0.1:19450`, `/metrics` on `127.0.0.1:43050`.
- V1 on `127.0.0.1:19451`, `/metrics` on `127.0.0.1:43051`.
- Both: `--env devnet --network-mode p2p --enable-p2p --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root --p2p-trusted-root <SAME_SPEC>`,
  per-validator real ML-DSA-44-signed leaf cert + ML-KEM-768 leaf secret,
  one `--p2p-peer-leaf-cert PEER_VID:PATH`.

### 6.2 Startup logs prove pqc-static-root + ML-DSA-44 + ML-KEM-768 + ChaCha20-Poly1305

Both nodes (`/tmp/run043/v0-pqc.stderr.log`, `/tmp/run043/v1-pqc.stderr.log`):

```
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 \
  configured_roots=1 leaf_credentials_present=true peer_leaf_certs=1 \
  (root fingerprints: [id=4abf0794.. suite=100 fp=b52fcdbb])
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 \
  transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 \
  dummy_kem_registered=false transport_aead_suite_id=101 \
  transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false \
  configured_roots=1 leaf_credentials_present=true
```

V0 additionally logs:

```
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote \
  after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, \
  vote_reemits_total=1)
```

`newly_connected_peers=1` is the binary-loop signal that mutual-auth
completed under `MutualAuthMode::Required` with a verified cert-derived
NodeId — i.e. the dialer's listener-cert ML-DSA-44 verify against the
configured root pk succeeded.

### 6.3 Live `/metrics` excerpts proving `qbind_p2p_pqc_*` visibility

V0 (`curl http://127.0.0.1:43050/metrics | grep '^qbind_p2p_pqc_'`):

```
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 0
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0
```

V1 (`curl http://127.0.0.1:43051/metrics | grep '^qbind_p2p_pqc_'`): identical 10-line block.

Section header on both nodes:

```
$ grep -c "^# P2P transport metrics (T172)" /tmp/run043/v0-pqc-metrics.txt
1
$ grep -c "^# P2P transport metrics (T172)" /tmp/run043/v1-pqc-metrics.txt
1
```

Sanity (pre-existing surfaces preserved):

```
qbind_timeout_verification_active 0
qbind_timeout_verification_signer_loaded 0
qbind_timeout_verification_key_provider_loaded 0
qbind_timeout_verification_validator_count 0
```

(Run 033 timeout-verification surface still present and not regressed.
`active=0` here is expected — the Run 043 positive smoke is the smallest
shape sufficient to prove metrics wiring; it deliberately omits the
consensus signer keystore + `--validator-consensus-key` entries that Run
034/038 needed to turn `active=1`. This is the same boundary recorded
honestly in Run 038's negative smoke.)

Full live `/metrics` bodies saved to:

- `/tmp/run043/v0-pqc-metrics.txt` (446 lines)
- `/tmp/run043/v1-pqc-metrics.txt` (446 lines)

### 6.4 Default-mode single-node sanity (`local-mesh`, no PQC config)

To prove the wiring is harmless when `pqc-static-root` is not configured
(test-grade default), a single-node `--network-mode local-mesh
--data-dir /tmp/run043/v0-data` startup with
`QBIND_METRICS_HTTP_ADDR=127.0.0.1:43043` yields:

```
qbind_p2p_pqc_root_mode 0
qbind_p2p_pqc_roots_configured 0
qbind_p2p_pqc_cert_verify_accepted_total 0
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0
```

(`root_mode=0` correctly reports `test-grade-dummy-sig` when no PQC
config is set; zero-valued rejection counters are visible per existing
style.) Saved to `/tmp/run043/v0-default-metrics.txt`.

---

## 7. Real-binary negative smoke (tampered cert)

Two-node setup as §6, except `v1.cert.bin` has its trailing signature
byte flipped (`/tmp/run043/mat/v1.cert.bin.tampered`, `bytes[-1] ^= 0x01`).
V1 carries the tampered cert as both its own `--p2p-leaf-cert` and V0's
`--p2p-peer-leaf-cert`.

**Boundary explicitly recorded.** V1 fails closed *at startup* in
`P2pNodeBuilder::build()` with:

```
[binary] ERROR: Failed to build P2P node: Config("delegation cert \
verification failed: KeySchedule(\"signature verify error\")")
```

— i.e. the dialer's own cert self-verification under the configured
trusted root failed before the metrics HTTP server could record any
live cert-verify rejection. This is honest fail-closed behaviour: V1
never reached a state where `/metrics` would have anything meaningful
to add about the bad cert; the boundary is recorded.

V0 stays alive throughout (`ps -p $V0_PID` returns `yes`), its
`/metrics` remains scrapeable, no `newly_connected_peers` line appears
(no peer ever reached mutual-auth completion), and the
`qbind_p2p_pqc_*` family is still present on V0:

```
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 0
qbind_p2p_pqc_cert_verify_rejected_total 0
... (all 10 lines visible, all zero)
```

Logs preserved at `/tmp/run043/v0n.stderr.log` and `/tmp/run043/v1n.stderr.log`;
metrics body at `/tmp/run043/v0n-metrics.txt`.

**Why no live rejection counter motion?** §3.3 records honestly: the
`inc_pqc_cert_verify_rejected_*` setters are declared but have no live
call site in `qbind-net::verify_delegation_cert`. Wiring those
increments into the live cert-verify path is a separate Run 044 task
(see §15). Run 043 deliberately did **not** fabricate increments.

---

## 8. Optional N=4 smoke

**Not run.** The CI sandbox is the same shape that Run 035 / Run 041 §19
identified — multi-process N=4 orchestration with reliable
network-namespace isolation is not available here. Re-executing the
Run 038/039/040/042 N=4 multi-process B14 absent-leader recovery
orchestration under the Run 043 binary to capture
`qbind_p2p_pqc_root_mode=1` + `qbind_p2p_pqc_roots_configured=1` on all
four nodes is recorded as the recommended next operator action in §15.
The two-node positive smoke in §6 already proves the same wiring on the
same release binary on every reachable node.

---

## 9. Proof metrics are emitted exactly once

| Layer | Mechanism |
|---|---|
| Source-level | `metrics_http::format_metrics_output` dispatches to either `format_metrics` OR `format_metrics_with_crypto` — never both. `format_metrics_with_crypto` composes `format_metrics` exactly once at its top. The Run 043 insertion is inside `format_metrics` (not inside `format_metrics_with_crypto`), so the family is emitted **once per HTTP response**. |
| Unit tests | §5 tests #3 and #4 explicitly assert `count == 1` for each of the 10 PQC metric names on **both** formatter paths. |
| Section header | §5 test #8 asserts `# P2P transport metrics (T172)` appears exactly once on both paths. |
| Live binary | §6.3 confirms `grep -c "^# P2P transport metrics (T172)" /tmp/run043/v{0,1}-pqc-metrics.txt = 1` on every captured scrape. |

---

## 10. `docs/whitepaper/contradiction.md` update

A new C4 update row is appended:

> **#### C4 Run 043 evidence update (2026-05-11) — `qbind_p2p_pqc_*`
> live `/metrics` exposure NARROWED**

The row states honestly:

- The Run 038/039/040/041/042 inherited gap "declared in
  `P2pMetrics::format_metrics` but not wired through
  `NodeMetrics::format_metrics`" is **closed at the formatter path level**:
  `qbind_p2p_pqc_*` family is now structurally present on the live
  `/metrics` endpoint, emitted exactly once, on the same release binary
  byte-identified in §5.
- The instance-divergence sub-gap (§3.2(b)) is also closed at the binary
  path level: gauges (`root_mode`, `roots_configured`) now reflect live
  binary state (`1`, `1` under `pqc-static-root` on the two-node
  positive smoke).
- The per-reason cert-verify increment call sites in
  `qbind-net::verify_delegation_cert` (and any accept-path
  increment) **remain unwired**; this is a separate, well-scoped
  follow-up explicitly recorded in §3.3 and §15 — Run 043 honoured the
  strict "do not fake increments" policy and did **not** add placeholder
  call sites.
- C4 remains OPEN for: CA / cert rotation / cert revocation / signed
  root distribution lifecycle, production fast-sync / consensus-storage
  restore, exponential-backoff timeout pacing, per-environment trust
  anchors, cert validity-window enforcement, and the `qbind-net`
  cert-verify-counter increment wiring.
- C5 is **NOT** marked closed by Run 043.

---

## 11. Exact commands run

```bash
# Build + unit tests (in repo root /home/runner/work/QBIND/QBIND)
cargo test -p qbind-node --lib metrics
cargo test -p qbind-node --lib p2p
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test -p qbind-node --lib
cargo test -p qbind-crypto --lib
cargo test -p qbind-net --lib
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper

# Real-binary positive smoke (two-node Required + pqc-static-root)
mkdir -p /tmp/run043
target/release/examples/devnet_pqc_root_helper /tmp/run043/mat 2
SPEC=$(cat /tmp/run043/mat/trusted-root.spec)
mkdir -p /tmp/run043/v0-pqc /tmp/run043/v1-pqc

QBIND_METRICS_HTTP_ADDR=127.0.0.1:43050 target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19450 --p2p-peer 127.0.0.1:19451 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$SPEC" \
  --p2p-leaf-cert /tmp/run043/mat/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run043/mat/v0.kem.sk.bin \
  --p2p-peer-leaf-cert "1:/tmp/run043/mat/v1.cert.bin" \
  --validator-id 0 --data-dir /tmp/run043/v0-pqc &

QBIND_METRICS_HTTP_ADDR=127.0.0.1:43051 target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19451 --p2p-peer 127.0.0.1:19450 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$SPEC" \
  --p2p-leaf-cert /tmp/run043/mat/v1.cert.bin \
  --p2p-leaf-cert-key /tmp/run043/mat/v1.kem.sk.bin \
  --p2p-peer-leaf-cert "0:/tmp/run043/mat/v0.cert.bin" \
  --validator-id 1 --data-dir /tmp/run043/v1-pqc &

sleep 10
curl -s http://127.0.0.1:43050/metrics | grep "^qbind_p2p_pqc_"
curl -s http://127.0.0.1:43051/metrics | grep "^qbind_p2p_pqc_"

# Negative smoke
python3 -c "p='/tmp/run043/mat/v1.cert.bin.tampered'; \
  import shutil; shutil.copy('/tmp/run043/mat/v1.cert.bin', p); \
  d=bytearray(open(p,'rb').read()); d[-1]^=1; open(p,'wb').write(bytes(d))"
# ...two-node smoke with v1.cert.bin.tampered as both V1's own leaf and V0's peer cert...
```

---

## 12. What was fixed (exact)

1. `NodeMetrics::format_metrics` now delegates to
   `self.p2p.format_metrics()` exactly once, between the `peer_network`
   and `connection_limit` blocks, so the live `/metrics` HTTP endpoint
   served by `metrics_http::format_metrics_output` now includes the
   complete `qbind_p2p_pqc_*` family. `NodeMetrics::format_metrics_with_crypto`
   inherits this via composition without any second call.
2. `NodeMetrics::p2p` is now `Arc<P2pMetrics>` with a new `p2p_arc()`
   accessor, so the same instance can be shared into the live transport
   build path.
3. `P2pNodeBuilder` gains a `with_p2p_metrics(Arc<P2pMetrics>)` setter;
   `main.rs::run_p2p_node` passes `node_metrics.p2p_arc()` so the live
   transport and the live HTTP scrape see one identical instance.
4. The Run 037 `set_pqc_root_mode` and `set_pqc_roots_configured` calls
   at `p2p_node_builder.rs:1107–1108` (unchanged) now populate the
   instance that is actually scraped, so live `/metrics` correctly
   reports `qbind_p2p_pqc_root_mode 1` and
   `qbind_p2p_pqc_roots_configured 1` under `pqc-static-root` mode.

## 13. What was proven (exact)

- Unit-test level: 8 new deterministic `run_043_*` tests + 767 pre-existing `qbind-node --lib` tests + 12 `run_037` + 14 `run_040` + 68 `qbind-crypto --lib` + 15 `qbind-net --lib` all PASS.
- Real-binary level (release `qbind-node` sha256 `9ecfb8a4...`): two-node
  `pqc-static-root` Required-mode mutual-auth smoke (`newly_connected_peers=1`
  on V0) shows live `/metrics` includes the entire `qbind_p2p_pqc_*`
  family, emitted exactly once (header count = 1), with `root_mode=1`
  and `roots_configured=1` correctly reflecting the active production-honest
  configuration. Negative tampered-cert smoke fails closed at builder
  time; V0 stays alive with the family still scrape-visible.
- No protocol, KEMTLS, cert, KEM, AEAD, consensus, or signer behaviour
  changed. Run 037/038/039/040/041/042 tests preserved bit-for-bit.

## 14. What remains not solved (exact)

- **Per-reason cert-verify increment call sites** are still missing in
  `qbind-net::verify_delegation_cert` and the listener/dialer error
  paths. The 8 counters
  (`cert_verify_accepted_total`, `cert_verify_rejected_total`,
  `cert_rejected_unknown_root_total`, `_wrong_suite_total`,
  `_bad_signature_total`, `_validator_mismatch_total`,
  `_malformed_total`, `_expired_total`) are scrape-visible but stay at 0
  on live binary because no production code path calls their `inc_*`
  setters. **Documented honestly per problem-statement policy; not
  fabricated.** Recommended as Run 044.
- All other C4 OPEN items as recorded in the Run 041/042 evidence and
  this Run 043 update row: CA / cert rotation / cert revocation / signed
  root distribution lifecycle, production fast-sync /
  consensus-storage restore, exponential-backoff timeout pacing,
  per-environment trust anchors, cert validity-window enforcement.
- C5 is **not** closed.
- Full C4 is **not** closed.
- Live N=4 multi-process B14 capture under the Run 043 binary not run
  in this evidence pass (sandbox limitation; recommended in §15).

## 15. Recommended immediate next action

Wire the `inc_pqc_cert_verify_accepted` call into the success path of
`qbind_net::verify_delegation_cert` (or its caller in `qbind-net`'s
listener/dialer handshake) and each `inc_pqc_cert_verify_rejected_*`
call into the matching `NetError::ClientCertInvalid("...")` /
`KeySchedule("signature verify error")` branches, so the live counters
move under positive and negative cert-verify events on the live binary.
Verify with a fresh two-node positive + negative smoke and a fresh N=4
multi-process B14 absent-leader recovery capture under the Run 040 real-AEAD
recipe. This is the natural completion of the observability work begun
in Run 043 and is bounded entirely to `qbind-net` + a thin `P2pMetrics`
handle injection — no protocol behaviour changes required.

---

## 16. Exact verdict

**PARTIAL POSITIVE.**

- Formatter wiring landed; `qbind_p2p_pqc_*` family is visible on live
  `/metrics` exactly once, on the release binary, under
  `pqc-static-root` Required mode, with `root_mode=1` and
  `roots_configured=1` correctly reflecting the active configuration.
- All required tests pass; no protocol, crypto, or consensus behaviour
  changed; no metric renamed, no metric duplicated, no metric fabricated.
- The per-reason cert-verify increment call sites remain unwired in the
  live cert-verify path — documented honestly per the strict
  "do not fake increments" policy, and recorded as the recommended
  Run 044 follow-up.
- Live N=4 multi-process B14 capture under the Run 043 binary not
  executed (sandbox limitation; two-node positive smoke is the
  authoritative live-binary proof in this evidence pass).