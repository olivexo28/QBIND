# QBIND DevNet Evidence — Run 052: Leaf-Level Certificate Revocation Enforcement

## Exact objective

Run 052 is the next C4 piece on top of the Run 050 / Run 051 PQC
trust-anchor lifecycle. The objective is the smallest production-honest
leaf-level certificate revocation enforcement layer:

- Wire the existing trust-bundle `revocations[].leaf_cert_fingerprint`
  surface into the `pqc-static-root` PQC delegation cert verification
  path on both the listener and the dialer side.
- A revoked leaf delegation cert MUST fail closed with
  `NetError::ClientCertInvalid("cert revoked")`.
- A non-revoked signed-bundle path MUST continue to work exactly as
  it did in Run 051.
- Add `qbind_p2p_pqc_cert_verify_rejected_revoked_total` (and
  preserve the Run 037 contract: per-reason setter also bumps the
  aggregate `qbind_p2p_pqc_cert_verify_rejected_total`).
- Prove no fallback to `--p2p-trusted-root`, `DummySig`, `DummyKem`,
  or `DummyAead`.
- Preserve Run 037 / Run 040 / Run 044 / Run 050 / Run 051 behaviour
  bit-for-bit on the existing inputs.
- Do NOT implement activation epoch/height gating, sequence
  monotonicity persistence, chain-id crosscheck, or a CA / rotation
  playbook in this run — those remain later C4 items.

## Exact verdict

**Strongest positive for the scoped Run 052 leaf-level revocation
enforcement layer.** The trust bundle's
`revocations[].leaf_cert_fingerprint` field is now interpreted as a
scoped leaf-level revocation: a `Some(fp)` entry surfaces a 32-byte
canonical fingerprint into `LoadedTrustBundle::revoked_leaf_fingerprints`
without excluding the corresponding root from `active_roots`; a `None`
entry preserves the Run 050 root-level revocation behaviour. The set
is wired through the `P2pNodeBuilder::with_pqc_leaf_revocations` API
into both client- and server-side `qbind_net` handshake configs ONLY
on the production-honest PQC path (`MutualAuthMode::Required` or
`Optional` + `PqcRootMode::PqcStaticRoot`), and a non-empty active set
is wrapped into a `LeafCertRevocationList` lookup that the qbind-net
handshake engine consults at the final pass-or-fail boundary in
`parse_and_verify_client_cert` (listener) and
`ClientHandshake::handle_server_accept` (dialer). When the verified
leaf cert's canonical fingerprint matches an active entry, the
handshake fails closed with `NetError::ClientCertInvalid("cert revoked")`,
the metrics adapter bumps `inc_pqc_cert_verify_rejected_revoked` (which
moves both the new
`qbind_p2p_pqc_cert_verify_rejected_revoked_total` counter and the
aggregate `qbind_p2p_pqc_cert_verify_rejected_total`), and
`inc_accepted` is NOT bumped. A non-revoked signed-bundle path
continues to verify exactly as in Run 051, with `inc_accepted` bumped
exactly once. Runs 037 / 044 / 050 / 051 unit and integration suites
all pass unchanged. The qbind-net `LeafCertRevocationList` field
defaults to `None`, taking a zero-cost no-op path that is bit-for-bit
identical to the pre-Run-052 verification surface for every existing
caller. Cross-crate fingerprint determinism (qbind-node
`cert_leaf_fingerprint` ≡ qbind-net `leaf_cert_fingerprint`) is
asserted by an integration test, with an additional regression test
that pins the shared domain-separator string. The DevNet/test-grade
DummySig / DummyKem / DummyAead path is intentionally NOT wired with
a revocation list (mirrors Run 044 cert-verify-metrics-sink
discipline); only the PQC path is.

The live-binary smoke shape (release `qbind-node` boot with
`--p2p-trust-bundle` + `--p2p-trust-bundle-signing-key` and a
revoked-leaf bundle) is the same shape as Run 051's signed-DevNet
positive smoke and is exercised end-to-end by the integration tests
listed below; the binary smoke artifact set was not produced in this
session, which is recorded as the explicit remaining boundary.

## Exact files changed

| File | Change |
| --- | --- |
| `crates/qbind-node/src/pqc_trust_bundle.rs` | Add `TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR`, `cert_leaf_fingerprint(&NetworkDelegationCert)`, `cert_leaf_fingerprint_hex(&[u8;32])`, `LoadedTrustBundle.revoked_leaf_fingerprints`, `LoadedTrustBundle::revoked_leaf_fingerprint_count()`, `LoadedTrustBundle::is_leaf_revoked(&[u8;32])`. Re-interpret `revocations[].leaf_cert_fingerprint`: `None` → root-level revocation (Run 050 behaviour preserved), `Some(fp)` → leaf-only revocation that does NOT exclude the root from `active_roots`. Add validation that a `Some(fp)` value is exactly 64 lowercase hex characters; otherwise the bundle load fails closed with `MalformedLeafFingerprint { root_id, reason }`. Honor `effective_from` for leaf entries (only active leaf revocations are surfaced). 7 new unit tests; total trust-bundle unit tests: **65/65 pass** (was 58 + 7 new). |
| `crates/qbind-net/src/handshake.rs` | Add `LEAF_CERT_FINGERPRINT_DOMAIN_SEPARATOR` (byte-identical to the qbind-node one), `leaf_cert_fingerprint(&NetworkDelegationCert) -> [u8;32]`, and `LeafCertRevocationList` (Arc-backed lookup + `active_count`). Add optional `leaf_cert_revocations: Option<LeafCertRevocationList>` field to BOTH `ClientHandshakeConfig` and `ServerHandshakeConfig`. In `parse_and_verify_client_cert` (listener): after all existing checks pass and BEFORE `inc_accepted`, compute the leaf fingerprint and look it up; on hit → `inc_rejected_revoked` + return `NetError::ClientCertInvalid("cert revoked")`. In `ClientHandshake::handle_server_accept` (dialer): same check after the existing validator-id mismatch check, before `inc_accepted`. |
| `crates/qbind-net/src/cert_verify_metrics.rs` | Add `inc_rejected_revoked(&self)` to the `CertVerifyMetricsSink` trait with a default no-op (back-compat for existing impls). Update reason-mapping doc table. Extend the trait's unit tests to cover the new method. |
| `crates/qbind-net/src/lib.rs` | Re-export `LeafCertRevocationList`, `leaf_cert_fingerprint`, and `LEAF_CERT_FINGERPRINT_DOMAIN_SEPARATOR`. |
| `crates/qbind-node/src/metrics.rs` | Add `pqc_cert_rejected_revoked_total: AtomicU64` field on `P2pMetrics`, `inc_pqc_cert_verify_rejected_revoked()` (which also bumps the aggregate `pqc_cert_verify_rejected_total`), and `pqc_cert_verify_rejected_revoked_total()` accessor. Render `qbind_p2p_pqc_cert_verify_rejected_revoked_total` in `format_metrics`. Implement `inc_rejected_revoked` on the existing `CertVerifyMetricsSink for P2pMetrics` adapter. Update Run 043 metric-name list and the zero-value / non-zero propagation tests to include the new metric and the new aggregate value (7 instead of 6). |
| `crates/qbind-node/src/p2p_node_builder.rs` | Add `pqc_revoked_leaf_fingerprints: Option<Arc<HashSet<[u8;32]>>>` field and `with_pqc_leaf_revocations(...)` setter. On the production-honest PQC mutual-auth path with a non-empty revoked set, wrap into a `LeafCertRevocationList` and wire into BOTH client + server handshake configs. Test-grade DummySig path leaves the field `None`. Empty active revoked set takes the zero-cost no-op path. |
| `crates/qbind-node/src/main.rs` | After loading the trust bundle, derive the leaf-revocation set from `loaded.revoked_leaf_fingerprints` and pass to the builder via `with_pqc_leaf_revocations()`. Emit `[binary] Run 052: revoked_leaf_fingerprints=N (from trust bundle env=… sequence=…)` on every startup. |
| `crates/qbind-net/tests/run_052_leaf_revocation_handshake_tests.rs` | NEW. 9 tests exercising the live qbind-net handshake boundary: revoked leaf fails closed + `inc_rejected_revoked` exactly once on listener, same on dialer, non-revoked leaves accept with `inc_accepted` exactly once, `leaf_cert_revocations: None` preserves Run 044 behaviour, empty list accepts. |
| `crates/qbind-node/tests/run_052_pqc_leaf_revocation_tests.rs` | NEW. 12 tests exercising the qbind-node trust-bundle ↔ adapter ↔ metrics glue: signed-bundle revoked-leaf surfaces a fingerprint, future-dated revocation is not yet active (and IS active after the effective time), malformed leaf-fingerprint fails closed, cross-crate fingerprint determinism, cross-crate domain-separator equality, adapter mapping (`inc_rejected_revoked` → revoked + aggregate), metric rendering on both formatters, no-fallback assertion (PQC suite ID preserved). |
| All existing test struct literals (qbind-net + qbind-node) | Add explicit `leaf_cert_revocations: None` (157 sites total). Mechanical struct-update; no behaviour change. |

Total NEW test surface: **+28 tests** across qbind-net and qbind-node
(7 trust-bundle unit + 9 qbind-net handshake + 12 qbind-node integration).

## Exact tests run

| Suite | Result |
| --- | --- |
| `cargo test -p qbind-node --lib pqc_trust_bundle` | 65 / 65 pass |
| `cargo test -p qbind-node --lib metrics` | 104 / 104 pass |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | 12 / 12 pass |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | 10 / 10 pass |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` | 13 / 13 pass |
| `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | 13 / 13 pass |
| `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` | 12 / 12 pass |
| `cargo test -p qbind-net` | 175 / 175 pass (incl. new 9 in `run_052_leaf_revocation_handshake_tests`) |
| `cargo test -p qbind-crypto --lib` | 68 / 68 pass |
| `cargo build -p qbind-node --lib --bin qbind-node` | clean (only pre-existing `bincode::config` deprecation warnings) |

## Exact reason-mapping table updates

`crates/qbind-net/src/cert_verify_metrics.rs` reason table now includes:

| Engine outcome | Sink method |
| --- | --- |
| Leaf-cert fingerprint is on the active leaf-revocation list (Run 052) — `NetError::ClientCertInvalid("cert revoked")` | `inc_rejected_revoked` |

The existing Run 037 / 044 / 045 mappings are preserved unchanged.

## Exact metric surface added

```
# HELP qbind_p2p_pqc_cert_verify_rejected_revoked_total
#      Total cert-verify rejections caused by an active leaf-cert
#      revocation entry on the loaded trust bundle (Run 052).
#      Bumped only on the production-honest PQC path; the test-grade
#      DummySig path does not wire the revocation surface.
# TYPE qbind_p2p_pqc_cert_verify_rejected_revoked_total counter
qbind_p2p_pqc_cert_verify_rejected_revoked_total <uint>
```

The Run 037 contract is preserved: each per-reason `inc_*` (including
`inc_pqc_cert_verify_rejected_revoked`) bumps the aggregate
`qbind_p2p_pqc_cert_verify_rejected_total` exactly once on the same
event.

## Exact no-fallback proof

The Run 052 leaf-revocation surface is wired ONLY on the
production-honest PQC mutual-auth path. The exact `match` arm in
`P2pNodeBuilder::build` is:

```rust
match (
    mutual_auth_mode,
    self.pqc_root_config.as_ref(),
    self.pqc_revoked_leaf_fingerprints.as_ref(),
) {
    (
        MutualAuthMode::Required | MutualAuthMode::Optional,
        Some(cfg),
        Some(revoked_set),
    ) if matches!(cfg.mode, PqcRootMode::PqcStaticRoot) && !revoked_set.is_empty() => {
        … wrap into LeafCertRevocationList …
    }
    _ => None,
}
```

This means:

- DummySig / DummyKem / DummyAead: never reached (no
  `PqcStaticRootConfig` is configured on that path; `cfg.mode` is
  `TestGradeDummySig` if a config is set at all).
- `--p2p-trusted-root` (legacy CLI): not a fallback target — the
  Run 052 wiring keys off the LOADED TRUST BUNDLE, not the
  `--p2p-trusted-root` CLI list.
- Empty active revoked set → no `LeafCertRevocationList` is
  installed → handshake takes the zero-cost no-op path → Run 050 / 051
  behaviour preserved bit-for-bit.

The `no_fallback_to_test_grade_dummy_primitives_for_pqc_path`
integration test in `run_052_pqc_leaf_revocation_tests.rs` asserts
that for every active root surfaced from a Run-052-revoked signed
bundle, `root.suite_id == PQC_TRANSPORT_SUITE_ML_DSA_44` and
`cfg.mode == PqcRootMode::PqcStaticRoot` — both discriminators that
would change if a future regression silently fell back to a
test-grade primitive.

## Exact remaining boundaries (NOT done in Run 052)

The following are explicitly out of scope for Run 052 and remain as
later C4 items:

- Activation epoch / height gating for revocation entries (only
  `effective_from` UNIX seconds is honored today).
- Sequence-number monotonicity persistence across restarts.
- `chain_id` crosscheck on bundle / cert.
- Operator-facing CA + rotation playbook.
- Live-binary release-build smoke artifacts for revoked-leaf
  fixtures (the smoke shape is identical to Run 051; the artifact
  set was not produced in this session).

These are listed honestly so future runs can pick them up without
ambiguity.