# QBIND DevNet Evidence — Run 071

**Title:** Mutable live PQC trust-context handle (initialize-only) — shared `LivePqcTrustState` snapshot replaces closure-captured `PqcStaticRootConfig` / `Arc<HashSet<[u8;32]>>` clones on the production-honest PQC handshake path, with no live mutation in this run.
**Date:** 2026-05-14
**C-row narrowed:** C4 — "on-the-fly trust-bundle hot reload" (NARROW sub-piece — mutable handle landed; live apply still gated on production session-eviction hook)

---

## 1. Exact objective

Land the **smallest safe** mutable-capable shared live trust-context
handle defined by `task/RUN_071_TASK.txt`. Run 071 builds **on top
of** Run 070's `validate → swap → evict_sessions → commit_sequence`
apply contract; it must NEVER weaken Run 070's apply ordering or
rollback semantics, must NEVER weaken Run 069's non-mutation
validation/staging boundary, must NEVER accept peer-supplied or
gossiped bundles, must NEVER add an automatic filesystem-watcher
hot-reload path, must NEVER advertise hot reload to operators, and
must NEVER mutate the live trust context after startup in Run 071.

Before Run 071 the active PQC trust material — `active_roots`,
`revoked_root_ids`, the `LeafCertRevocationList` revocation set, and
the configured root / leaf certs — was cloned into immutable
`ClientHandshakeConfig` / `ServerHandshakeConfig` closures inside
`crates/qbind-node/src/p2p_node_builder.rs::build_p2p_node`. There
was no process-wide shared "live" trust handle at all, so Run 070's
apply contract had no runtime swap point to wire into and the
production binary surfaced
`ReloadApplyError::UnsupportedRuntimeContext` honestly.

Run 071 introduces exactly that handle:

- a new `qbind_node::pqc_live_trust::LivePqcTrustState`
  (`Arc<RwLock<Arc<LivePqcTrustSnapshot>>>`) initialized once at
  startup from the already-validated `LoadedTrustBundle`;
- a `P2pNodeBuilder::with_live_pqc_trust(...)` builder method that
  routes the listener-side `TrustedClientRoots` resolver and the
  bidirectional `LeafCertRevocationList` revocation closure
  through `LivePqcTrustState::snapshot()` instead of through
  closure-captured config clones;
- `qbind-node`'s `main.rs` calls `with_live_pqc_trust(...)` after
  Run 052's `with_pqc_leaf_revocations(...)` so the verification
  surface is **byte-identical** to pre-Run-071 at startup.

Run 071 deliberately stops there. It does NOT call `swap_snapshot`
on any production path, does NOT connect the handle to
`pqc_trust_reload::apply_validated_candidate`, and does NOT change
Run 070's production surface (which still returns
`UnsupportedRuntimeContext` because no session-eviction hook
exists yet on the honest PQC path).

---

## 2. Exact verdict

**POSITIVE — narrow.** The Run 071 mutable-capable handle lands in
the library, is wired through `P2pNodeBuilder` to both client- and
server-side handshake configs, and is exercised end-to-end by 11
in-module unit tests plus 13 dedicated integration tests. The
existing Run 037 / 050 / 052 / 055 / 062 / 063 / 069 / 070
regressions all pass byte-for-byte unchanged, the release binary
builds, and `cargo test -p qbind-node --lib pqc_` reports 211/211
green (200 prior + 11 new). No production code path mutates the
handle after startup in Run 071; the `swap_snapshot` capability is
covered by a unit test only so that a future Run 072+ wiring
cannot regress its ordering contract silently.

The remaining C4 sub-piece — live application of a validated
candidate bundle on a running binary — stays OPEN behind the
production session-eviction hook. Run 070's
`ReloadApplyError::UnsupportedRuntimeContext` surface continues to
be the honest answer on `--p2p-trust-bundle-reload-apply-enabled`
until that hook lands.

---

## 3. Required regressions

All commands run from the repository root in this session.

| Command | Result |
|---|---|
| `cargo test -p qbind-node --lib pqc_live_trust` | **11/11 pass** (initial from-loaded round-trip; pending vs. active revocation enforcement; cheap-clone Arc semantics; concurrent reads; swap-snapshot future capability; lock poisoning → `LivePqcTrustError::LockPoisoned`) |
| `cargo test -p qbind-node --lib pqc_` | **211/211 pass** (`pqc_live_trust` 11/11, `pqc_trust_reload` 5/5, `pqc_trust_bundle` 100/100, `pqc_trust_sequence` 27/27, `pqc_trust_activation` 34/34, others — superset) |
| `cargo test -p qbind-node --test run_071_pqc_live_trust_tests` | **13/13 pass** |
| `cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests` | **13/13 pass** (Run 070 contract unchanged) |
| `cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests` | **12/12 pass** (Run 069 unchanged) |
| `cargo test -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests` | **all pass** (Run 063 unchanged) |
| `cargo test -p qbind-node --test run_062_pqc_revocation_activation_tests` | **all pass** (Run 062 unchanged) |
| `cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | **all pass** (Run 055 unchanged) |
| `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` | **all pass** (Run 052 unchanged) |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` | **all pass** (Run 050 unchanged) |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **all pass** (Run 037 unchanged) |
| `cargo build --release -p qbind-node --bin qbind-node` | **succeeds** (preserved warning-only diff) |

---

## 4. What landed (production code)

### 4.1 New module: `crates/qbind-node/src/pqc_live_trust.rs`

- `LivePqcTrustError::LockPoisoned` — fail-closed signal for
  callers in the handshake-verification path.
- `LivePqcTrustSnapshot` — immutable, `Arc`-cheaply-clonable
  snapshot of the public post-validation trust material:
  - `environment` (`TrustBundleEnvironment`),
  - `chain_id: Option<String>` (preserved bit-for-bit),
  - 32-byte canonical `fingerprint`,
  - `sequence`,
  - `signature_status` (`BundleSignatureStatus`),
  - `active_roots: Vec<PqcTrustedRoot>` (public ML-DSA-44 keys
    only),
  - `revoked_root_ids: HashSet<[u8;32]>` (active set),
  - `revoked_leaf_fingerprints: HashSet<[u8;32]>` (active set),
  - `pending_revoked_root_ids` /
    `pending_revoked_leaf_fingerprints` (observability-only;
    verification NEVER reads pending sets).
- `LivePqcTrustState` — the shared handle
  (`Arc<RwLock<Arc<LivePqcTrustSnapshot>>>`):
  - `initialize_from_loaded_bundle(&LoadedTrustBundle)` — the
    sole production constructor;
  - `snapshot() -> Result<Arc<LivePqcTrustSnapshot>,
    LivePqcTrustError>` — short read lock + Arc clone, no I/O
    under the lock;
  - `lookup_active_root_pk(&[u8;32])` and
    `is_leaf_revoked(&[u8;32])` — handshake-side helpers;
  - `active_leaf_revocation_count()` — for the
    `LeafCertRevocationList` construction-time `active_count`;
  - `swap_snapshot(new)` — present but **unused** by any Run 071
    production path; future capability for Run 072+;
  - `Clone` is cheap (`Arc::clone` of the inner lock).
- 11 in-module unit tests cover:
  1. initialize from a loaded DevNet bundle,
  2. signature-status round-trip,
  3. `chain_id: None` round-trip on DevNet,
  4. `lookup_active_root_pk` returns the expected public key,
  5. lookup returns `None` for an actively revoked root id
     (defence in depth),
  6. leaf-revocation lookup consults the active set only,
  7. concurrent `snapshot()` reads from clones produce the same
     fingerprint / counts,
  8. repeated `snapshot()` reads return Arcs pointing at the same
     allocation (Run 071 never mutates),
  9. `swap_snapshot` swaps the inner Arc and returns the previous
     one (pinned-down ordering contract for Run 072+),
  10. no private material is reachable from the public surface
      (root public-key bytes only),
  11. a poisoned `RwLock` → `LivePqcTrustError::LockPoisoned`
      on `snapshot()`, `is_leaf_revoked`, and
      `lookup_active_root_pk`.

### 4.2 `P2pNodeBuilder` wiring (`crates/qbind-node/src/p2p_node_builder.rs`)

- New field `pqc_live_trust: Option<LivePqcTrustState>` (default
  `None`, preserving pre-Run-071 behaviour for tests).
- New builder method `with_live_pqc_trust(LivePqcTrustState)`.
- `trusted_client_roots` resolver on the production-honest PQC
  mutual-auth path: when `pqc_live_trust` is `Some(live)`, reads
  through `live.lookup_active_root_pk(...)` per lookup and
  fails closed (returns `None` → "untrusted root") if the
  underlying `RwLock` is poisoned.
- `leaf_cert_revocations` (the `LeafCertRevocationList`): when
  `pqc_live_trust` is `Some(live)`, reads through
  `live.is_leaf_revoked(...)` per lookup and fails closed
  (returns `true` → "cert revoked") if the lock is poisoned. The
  construction-time `active_count` comes from
  `live.active_leaf_revocation_count()`. The zero-cost no-op
  path is preserved when the active set is empty (matches the
  pre-Run-052 / pre-Run-071 empty-set behaviour bit-for-bit).
- Both code paths fall through cleanly to the pre-Run-071
  `pqc_root_config` / `pqc_revoked_leaf_fingerprints` closures
  when no live handle is installed — every existing builder
  caller (tests, harnesses, non-binary integration code) keeps
  behaving identically.

### 4.3 Binary wiring (`crates/qbind-node/src/main.rs`)

A new block, immediately after Run 052's leaf-revocation wiring
and immediately before `builder.build(...)`, constructs
`LivePqcTrustState::initialize_from_loaded_bundle(loaded)` whenever
`trust_bundle_loaded.is_some()` and threads the handle through
`with_live_pqc_trust(live)`. It emits an unambiguous operator log
line:

```
[binary] Run 071: live PQC trust-state initialized \
 (env=Devnet sequence=N fingerprint=<sha3-hex> active_roots=N \
  revoked_roots_active=N revoked_leaves_active=N)
```

The byte-level verification surface is unchanged: the live snapshot
is built from the exact same `LoadedTrustBundle` that already drives
`with_pqc_root_config(...)` and `with_pqc_leaf_revocations(...)`,
so the listener-side root resolver and the leaf-revocation closure
yield identical results to the pre-Run-071 path on every
fingerprint / root id.

---

## 5. What is **explicitly excluded** by Run 071

- No production call to `swap_snapshot`. The live handle stays at
  its initial snapshot for the lifetime of the binary.
- No connection between the new handle and
  `pqc_trust_reload::apply_validated_candidate`. The Run 070 CLI
  hook (`--p2p-trust-bundle-reload-apply-enabled`) continues to
  return `ReloadApplyError::UnsupportedRuntimeContext` and exit 1
  because no `LiveTrustApplyContext` is wired against the runtime
  (no session-eviction hook exists yet on the honest PQC path).
- No filesystem watcher, no gossip, no peer-supplied bundles, no
  KMS / HSM integration, no `activation_epoch` runtime sourcing,
  no KEMTLS / consensus / B14 redesign, no rotation of the
  bundle-signing key, no new `/metrics` counters in this run (the
  existing Run 050/051/062 trust-bundle gauges already surface
  the same fields the live snapshot mirrors).
- No new CLI flags. The handle is automatically used whenever a
  trust bundle is loaded; on the test-grade DummySig path and on
  the `Disabled` mutual-auth path the handle is constructed but
  never consulted (the existing test-grade `TrustedClientRoots`
  fallback runs unchanged).
- No change to Run 069 (validation/staging boundary) or Run 070
  (apply contract). The corresponding integration tests pass
  byte-for-byte unchanged.

---

## 6. Concurrency & fail-closed contract

- **Reader path:** `LivePqcTrustState::snapshot()` takes a short
  `RwLock::read()`, clones the inner `Arc<LivePqcTrustSnapshot>`
  (single Arc bump), and drops the read lock. All subsequent
  lookups read the cloned snapshot with no lock held — no network
  I/O, no expensive crypto, and no hashing happens while the
  lock is held.
- **Writer path:** `swap_snapshot` (unused in Run 071) takes a
  single write lock, replaces the inner Arc, and returns the
  previous one. Readers either see the entire old snapshot or
  the entire new snapshot — never a half-applied state. Because
  Run 071 never calls `swap_snapshot`, the unit test
  `swap_snapshot_replaces_inner_arc_and_returns_previous` is the
  only test that exercises the contract; it asserts the
  ordering (previous returned, new installed, Arc pointer
  changed).
- **Lock poisoning:** if a future writer panics while holding the
  write lock, the underlying `RwLock` is poisoned. The reader
  returns `LivePqcTrustError::LockPoisoned`. The two
  handshake-side closures wired in `p2p_node_builder.rs`
  translate this into a fail-closed result:
  - `TrustedClientRoots` resolver → `None` → "untrusted root";
  - `LeafCertRevocationList` → `true` → "cert revoked".
  A poisoned trust state therefore degrades availability without
  leaking past trust state into a new handshake.

---

## 7. Trust separation (unchanged from Run 050+)

- The transport leaf-cert ML-DSA-44 root key is the *transport*
  trust anchor (mirrored on `LivePqcTrustSnapshot.active_roots`).
- The bundle-signing ML-DSA-44 key id is the *bundle-signing*
  trust anchor (mirrored on
  `LivePqcTrustSnapshot.signature_status`).
- The two id-spaces are domain-separated by SHA3 prefix at
  derivation time (`derive_signing_key_id` vs.
  `derive_root_key_id`). No Run 071 surface re-uses one as the
  other.
- No private material crosses the live-trust boundary. The
  `lookup_active_root_pk` helper returns the **public** ML-DSA-44
  root public key bytes — the same value the loaded bundle
  already exposed pre-Run-071 to the `TrustedClientRoots`
  closure.

---

## 8. Documentation

- `docs/whitepaper/contradiction.md` C4 entry is narrowed with a
  note that the production binary now installs a mutable-capable
  shared live trust-state handle initialized once at startup
  from the validated `LoadedTrustBundle`. The remaining open
  C4 sub-piece is the production session-eviction hook plus the
  `LiveTrustApplyContext` adapter that closes the loop with
  Run 070's apply contract.

---

## 9. Reproducible commands

```bash
# Run 071 unit + integration tests
cargo test -p qbind-node --lib pqc_live_trust
cargo test -p qbind-node --test run_071_pqc_live_trust_tests

# Full PQC trust regression set
cargo test -p qbind-node --lib pqc_

# Prior run integration regressions (must all pass)
cargo test -p qbind-node \
  --test run_037_pqc_static_root_mutual_auth_tests \
  --test run_050_pqc_trust_bundle_tests \
  --test run_052_pqc_leaf_revocation_tests \
  --test run_055_pqc_trust_bundle_sequence_tests \
  --test run_062_pqc_revocation_activation_tests \
  --test run_063_pqc_local_issuer_root_self_check_tests \
  --test run_069_pqc_trust_bundle_reload_check_tests \
  --test run_070_pqc_trust_bundle_reload_apply_tests

# Release binary build
cargo build --release -p qbind-node --bin qbind-node
```

---

## 10. Open items (carried forward to a future run)

1. **Session-eviction hook on the honest PQC path.** Without a
   way to eagerly close in-flight KEMTLS sessions verified
   against the *previous* trust snapshot, a `swap_snapshot`
   call could leave already-completed handshakes alive
   indefinitely. Run 070's `LiveTrustApplyContext::evict_sessions`
   contract pins the call-site; the runtime hook is still
   missing.
2. **`LiveTrustApplyContext` adapter from the running binary.**
   Once (1) lands, a small adapter that:
   - calls `LivePqcTrustState::snapshot()` for `snapshot_active`,
   - calls `LivePqcTrustState::swap_snapshot(new)` for `swap_state`,
   - calls the session-eviction hook for `evict_sessions`,
   - calls the existing `pqc_trust_sequence::commit_sequence`
     for `commit_sequence`,
   - rolls back via `swap_snapshot(previous)` on
     post-swap failure,

   closes the loop with Run 070 without redesigning Run 069 / 070.
3. **`activation_epoch` runtime sourcing.** Still open under
   the C4 umbrella; unaffected by Run 071.
4. **KEMTLS AEAD / DummyAead replacement** and **production
   fast-sync/consensus-storage restore.** Unaffected by Run 071.