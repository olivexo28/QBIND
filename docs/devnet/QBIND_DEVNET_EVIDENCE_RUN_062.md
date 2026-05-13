# QBIND DevNet Evidence — Run 062: Per-entry Revocation Activation Gates on the PQC Trust Bundle (NARROW C4 sub-piece)

## Exact objective

Run 062 introduces, exercises on the live release binary, and proves
the smallest production-honest **per-entry activation gate** on the
PQC trust-bundle revocation surface introduced by Run 050/052/054 and
extended by Runs 055–061. Before Run 062, every revocation entry on
`TrustBundle.revocations` (root-scope or leaf-scope) became fully
active the moment the bundle parsed (subject only to the wall-clock
`effective_from` field that has been on the schema since Run 050).
Operators who wanted to publish a *scheduled* revocation that took
effect at a known future block height had no way to do so. After
Run 062, every revocation entry carries an optional, ML-DSA-44-signature-
covered, canonical-fingerprint-covered `activation_height: Option<u64>`
field with the same inclusive `current_height >= activation_height`
semantics as the Run 057 bundle-level activation gate. Entries whose
height gate is unsatisfied (or whose runtime height source is
unavailable) are surfaced as **PENDING** on the new
`pending_revoked_root_ids` / `pending_revoked_leaf_fingerprints`
accessors and gauges, and are NOT enforced anywhere — they do not
appear in `active_roots` filtering, the Run 061 local-leaf startup
self-check, or the qbind-net peer-handshake `with_pqc_leaf_revocations(...)`
context.

The scope is intentionally narrow (per the task):

- add `#[serde(default)] activation_height: Option<u64>` to
  `TrustBundleRevocation`; participate in `canonical_signing_bytes` and
  `canonical_fingerprint` so the ML-DSA-44 bundle signature covers the
  field bit-for-bit;
- split `LoadedTrustBundle.revoked_*` into ACTIVE and PENDING root/leaf
  sets, threaded from a single `current_height: Option<u64>` on a new
  `validate_at_with_signing_keys_chain_id_and_revocation_activation`
  entrypoint;
- emit one `[binary] Run 062: trust-bundle revocation activation
  (configured=N active=A pending=P root_active=Ra root_pending=Rp
  leaf_active=La leaf_pending=Lp)` log line on startup;
- expose seven gauges under the existing
  `qbind_p2p_pqc_trust_bundle_*` family:
  `_revocations_configured_total`, `_revocations_active_total`,
  `_revocations_pending_total`, `_revocations_root_active`,
  `_revocations_root_pending`, `_revocations_leaf_active`,
  `_revocations_leaf_pending`;
- preserve `revoked_leaf_fingerprints` semantics on the local-leaf
  self-check (Run 061) and on the qbind-net peer-handshake
  enforcement context (Run 052) bit-for-bit (both surfaces continue
  to receive the ACTIVE set only);
- preserve `qbind_p2p_pqc_trust_bundle_revoked_roots` (Run 050)
  semantics bit-for-bit (it equals `_revocations_root_active` by
  construction; no rename, no widening);
- helper-mint four signed DevNet fixtures:
  `signed-devnet-leaf-revocation-pending-v0`,
  `signed-devnet-leaf-revocation-active-v0`,
  `signed-devnet-root-revocation-pending`,
  `signed-devnet-root-revocation-active`;
- NEVER relax any pre-existing fail-closed boundary (every Run
  050/051/052/053/054/055/057/061 negative path is preserved);
- NEVER widen the helper signature to accept private-key material;
- NEVER introduce `Dummy*` / classical-signature fallbacks.

Explicitly out of scope for Run 062 (and listed below in
"Explicitly NOT done in Run 062"):

- root-level local revocation self-check
  (Run 061 §10 item (a) — still open);
- per-entry `activation_epoch` field on revocation entries (the
  Run 057 bundle-level `CurrentEpochUnavailable` boundary is
  unchanged; no production runtime epoch source exists);
- per-environment minimum activation-margin policy on revocation
  entries (operator policy, not binary policy);
- on-the-fly trust-bundle hot-reload (the bundle is loaded exactly
  once per process lifetime; the new gauges are sticky-at-startup
  snapshots);
- the Run 060 operator playbook (`QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`)
  is intentionally NOT updated in Run 062.

## Anchoring

| component | file | role |
| --- | --- | --- |
| schema field | `crates/qbind-node/src/pqc_trust_bundle.rs` `TrustBundleRevocation.activation_height` | optional `u64`, `#[serde(default)]`, signature-covered |
| canonical preimage | `pqc_trust_bundle::canonical_signing_bytes` / `canonical_fingerprint` | each entry's `activation_height` is mixed in (proven by `run062_canonical_fingerprint_covers_revocation_activation_height` and by the integration tamper test) |
| validate entrypoint | `pqc_trust_bundle::TrustBundle::validate_at_with_signing_keys_chain_id_and_revocation_activation` | accepts `current_height: Option<u64>`; computes the active/pending split deterministically |
| legacy shim | `validate_at_with_signing_keys_and_chain_id` | unchanged callers see height-gated entries as PENDING (fail-safe) |
| loaded view | `LoadedTrustBundle.{revoked_root_ids,revoked_leaf_fingerprints,pending_revoked_root_ids,pending_revoked_leaf_fingerprints}` + accessors | the only authoritative source of "active vs. pending" downstream |
| binary log line | `crates/qbind-node/src/main.rs` (after the existing Run 050/051 trust-bundle-loaded line) | `[binary] Run 062: trust-bundle revocation activation (...)` |
| metrics gauges | `crates/qbind-node/src/metrics.rs` | seven gauges under the existing `qbind_p2p_pqc_trust_bundle_*` family |
| local-leaf self-check (Run 061) | `crates/qbind-node/src/main.rs` Run 061 block | reads `loaded.revoked_leaf_fingerprints` (active set) only — pending entries cannot reach it |
| peer-handshake enforcement (Run 052) | `crates/qbind-node/src/main.rs` `P2pNodeBuilder::with_pqc_leaf_revocations(loaded.revoked_leaf_fingerprints.clone())` | receives the active set only |
| helper modes | `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` | four new modes + 7th positional arg `[revocation_activation_height_for_target_override]` |
| lib unit tests | `crates/qbind-node/src/pqc_trust_bundle.rs::tests::run062_*` | 11 tests |
| integration tests | `crates/qbind-node/tests/run_062_pqc_revocation_activation_tests.rs` | 11 tests |

## Resolution rule (single source of truth)

Given a revocation entry with `effective_from = e_from` and
`activation_height = ah_opt`, validated at wall-clock `now` with
optional runtime `current_height = ch_opt`:

```
configured = (e_from <= now)             // existing Run 050 wall-clock filter (legacy)
height_satisfied =
    match (ah_opt, ch_opt) {
        (None, _)        => true,        // legacy entry: no height gate
        (Some(_), None)  => false,       // height gated, no runtime source ⇒ fail-safe PENDING
        (Some(ah), Some(ch)) => ch >= ah, // inclusive boundary (Run 057-style)
    }
active  = configured && height_satisfied
pending = configured && !height_satisfied
```

A revocation is in EXACTLY ONE of `{active, pending, neither}`. The
`neither` case is reached only when the wall-clock `effective_from`
is in the future (legacy Run 050/052 scheduled-by-wall-clock entries
that haven't activated yet) — these entries continue to appear
NOWHERE in the loaded view's enforcement sets, exactly as before
Run 062.

## Test results

```
$ cargo test -p qbind-node --lib pqc_trust_bundle
test result: ok. 91 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --lib pqc_trust_sequence
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --lib pqc_trust_activation
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --lib metrics
test result: ok. 78 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_062_pqc_revocation_activation_tests
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_061_pqc_local_leaf_self_check_tests
test result: ok.  9 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests
test result: ok. 14 passed; 0 failed; 0 ignored; 0 measured

$ cargo test -p qbind-net --test run_052_leaf_revocation_handshake_tests
test result: ok.  9 passed; 0 failed; 0 ignored; 0 measured

$ cargo check -p qbind-node --bin qbind-node
    Finished `dev` profile (only pre-existing bincode::config + verify_pool::worker_id warnings)
```

The lib `pqc_trust_bundle` test count moved from the Run 061 baseline
80 → 91 (+11 new Run 062 unit tests). The Run 062 integration test
file is new (+11 tests). No pre-existing test was modified or
removed; literal `TrustBundleRevocation { ... }` constructions in
existing test files (`tests/run_052_pqc_leaf_revocation_tests.rs`,
`tests/run_061_pqc_local_leaf_self_check_tests.rs`) gained the
strictly-mechanical `activation_height: None` field so they
continue to compile under the new struct shape.

The 11 Run 062 unit tests pin:
- `run062_legacy_no_activation_height_is_immediately_active` — None ⇒ active immediately (Run 050/052 parity)
- `run062_height_satisfied_is_active` — `current_height >= activation_height` ⇒ active
- `run062_height_future_is_pending` — `current_height <  activation_height` ⇒ pending
- `run062_height_unavailable_keeps_entry_pending` — `current_height = None` ⇒ pending (fail-safe)
- `run062_legacy_validate_shim_treats_height_gated_as_pending` — `validate_at_with_signing_keys_and_chain_id` shim is fail-safe
- `run062_root_revocation_pending_keeps_root_active` — pending root revocation does NOT silently exclude the root
- `run062_root_revocation_active_excludes_root` — satisfied root revocation excludes the root (Run 050 parity)
- `run062_effective_from_future_legacy_entry_neither_active_nor_pending` — wall-clock-future legacy entries appear NOWHERE
- `run062_tampered_revocation_activation_height_fails_signature` — post-signing tampering of `activation_height` invalidates the ML-DSA-44 signature
- `run062_canonical_fingerprint_covers_revocation_activation_height` — `canonical_fingerprint` and `canonical_signing_bytes` both incorporate the field
- `run062_serde_default_for_missing_activation_height` — pre-Run-062 producer's bundle JSON (no `activation_height` key) parses cleanly with the field defaulting to `None`

The 11 Run 062 integration tests pin:
- `future_height_leaf_revocation_is_pending_not_active`
- `satisfied_height_leaf_revocation_is_active`
- `legacy_no_activation_height_leaf_revocation_is_active`
- `future_height_root_revocation_keeps_root_active`
- `satisfied_height_root_revocation_excludes_root`
- `tampering_revocation_activation_height_after_signing_fails_signature`
- `missing_runtime_height_keeps_revocation_pending`
- `inclusive_boundary_current_equals_required_activates`
- `legacy_json_without_activation_height_field_parses`
- `mixed_revocations_active_and_pending_counters`
- `no_revocations_unchanged_baseline`

## Binary identity (release smoke harness)

| binary | sha256 | sha1 |
| --- | --- | --- |
| `target/release/qbind-node` | `a14e36d2fbb603531fa6ca0eca8268173b474985c3e543e9b6f493581c90880c` | `215186095d224f018999a06f55036abe8898af62` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `ff6c276763934f239bc2cd652086abaa29dce7d0a4e859982b3a67499e67eea2` | `28bd441b1c148557623f13f2ed59052d5b292f82` |
| `target/release/examples/devnet_pqc_root_helper` | `9332b228e86aa1c65a3270a2bd3ad471f9797e6ae54c00db7526e1a80b28008d` | `0ed1958ad43dc2e13370fd35c1bf00fa9d645f43` |

Toolchain: `rustc 1.94.1 (e408947bf 2026-03-25)`; host: Ubuntu 24.04.4 LTS.

## Release-binary smoke harness

```bash
# 1) Build release binaries (qbind-node, two helpers).
cargo build --release -p qbind-node \
  --bin qbind-node \
  --example devnet_pqc_trust_bundle_helper \
  --example devnet_pqc_root_helper

# 2) Mint four signed DevNet bundle fixtures (one per smoke).
mkdir -p /tmp/qbind_run062
for mode in \
    signed-devnet-leaf-revocation-pending-v0 \
    signed-devnet-leaf-revocation-active-v0 \
    signed-devnet-root-revocation-pending \
    signed-devnet-root-revocation-active; do
  outdir="/tmp/qbind_run062/${mode}"
  mkdir -p "$outdir"
  ./target/release/examples/devnet_pqc_trust_bundle_helper \
    "$outdir" 2 "$mode" > "$outdir/helper.stdout.log" 2>&1
done

# 3) Smoke 1 — leaf-revocation PENDING.
#    Bundle revokes v0's leaf cert with activation_height = u64::MAX.
#    Run 062 reports pending=1 leaf_pending=1; the Run 061 local-leaf
#    self-check correctly skips this pending entry; the node starts.
BD=/tmp/qbind_run062/signed-devnet-leaf-revocation-pending-v0
SIGN_SPEC="$(cat $BD/signing-key.spec)"
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19710 timeout 6 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19510 --p2p-peer 1@127.0.0.1:19511 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v0.cert.bin" \
  --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
  --p2p-peer-leaf-cert "1:$BD/v1.cert.bin" \
  --validator-id 0 --data-dir /tmp/qbind_run062/data/leaf-pending
# Expected: exit 124 (timeout after clean startup); no FATAL.

# 4) Smoke 2 — leaf-revocation ACTIVE.
#    Bundle revokes v0's leaf cert with activation_height = 0.
#    Run 062 reports active=1 leaf_active=1; the Run 061 local-leaf
#    self-check fails closed.
BD=/tmp/qbind_run062/signed-devnet-leaf-revocation-active-v0
SIGN_SPEC="$(cat $BD/signing-key.spec)"
timeout 15 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19520 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v0.cert.bin" \
  --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
  --validator-id 0 --data-dir /tmp/qbind_run062/data/leaf-active
# Expected: exit 1; stderr contains exactly one
# "FATAL: Run 061 local leaf certificate revoked" line.

# 5) Smoke 3 — root-revocation PENDING.
#    Bundle root-revokes the only root with activation_height = u64::MAX.
#    Run 062 reports pending=1 root_pending=1; active_roots=1; the
#    node starts.
BD=/tmp/qbind_run062/signed-devnet-root-revocation-pending
SIGN_SPEC="$(cat $BD/signing-key.spec)"
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19730 timeout 6 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19530 --p2p-peer 1@127.0.0.1:19531 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v0.cert.bin" \
  --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
  --p2p-peer-leaf-cert "1:$BD/v1.cert.bin" \
  --validator-id 0 --data-dir /tmp/qbind_run062/data/root-pending
# Expected: exit 124; no FATAL; active_roots=1; root_pending=1.

# 6) Smoke 4 — root-revocation ACTIVE.
#    Bundle root-revokes the only root with activation_height = 0.
#    Run 062 reports active=1 (root); active_roots=0; the binary
#    fails closed exactly as in Run 050.
BD=/tmp/qbind_run062/signed-devnet-root-revocation-active
SIGN_SPEC="$(cat $BD/signing-key.spec)"
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19740 timeout 6 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19540 --p2p-peer 1@127.0.0.1:19541 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v0.cert.bin" \
  --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
  --p2p-peer-leaf-cert "1:$BD/v1.cert.bin" \
  --validator-id 0 --data-dir /tmp/qbind_run062/data/root-active
# Expected: exit 1; stderr contains exactly one
# "FATAL: --p2p-mutual-auth required + --p2p-pqc-root-mode
#  pqc-static-root requires at least one configured trusted root"
# line; active_roots=0; revoked_roots=1.
```

## Observed stderr (key excerpts)

### Smoke 1 (leaf-revocation PENDING)

```
[binary] Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) required_epoch=None current_epoch=None)
[binary] Run 050/051: trust bundle loaded path=/tmp/qbind_run062/signed-devnet-leaf-revocation-pending-v0/trust-bundle.json env=devnet fp=41db70333c7b8a19b8a3d832ff28d3fc495f106271c86bdf3590864f64fce6b2 active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=30f42f0b..) signing_keys_configured=1. Bundle root IDs: [9a0a2d3b..]
[binary] Run 062: trust-bundle revocation activation (configured=1 active=0 pending=1 root_active=0 root_pending=0 leaf_active=0 leaf_pending=1)
[binary] P2P node started. Press Ctrl+C to exit.
```

Exit code: 124 (timeout-after-clean-startup). Cross-check counts on
Smoke 1 stderr:

| substring | count | meaning |
| --- | --- | --- |
| `FATAL` | 0 | Run 061 self-check correctly skipped the pending entry |
| `Failed to build P2P node` | 0 | builder succeeded |
| `Run 062: ... pending=1 leaf_pending=1` | 1 | gauge values mirror loaded view |
| `active_roots=1 revoked_roots=0` | 1 | root surface untouched |
| `Dummy` | 0 | no `Dummy*` fallback registered |

### Smoke 2 (leaf-revocation ACTIVE — fail-closed)

```
[binary] Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) required_epoch=None current_epoch=None)
[binary] Run 055: trust-bundle sequence persistence env=devnet chain_id=51424e4444455600 path=/tmp/qbind_run062/data/leaf-active/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=c2051f1c
[binary] Run 050/051: trust bundle loaded path=/tmp/qbind_run062/signed-devnet-leaf-revocation-active-v0/trust-bundle.json env=devnet fp=c2051f1cffa932eff3ce6c0e33dc6f31b64b0785129d60d4877941aca381fffe active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=070cc083..) signing_keys_configured=1. Bundle root IDs: [ad1a0663..]
[binary] Run 062: trust-bundle revocation activation (configured=1 active=1 pending=0 root_active=0 root_pending=0 leaf_active=1 leaf_pending=0)
[binary] FATAL: Run 061 local leaf certificate revoked: the local --p2p-leaf-cert fingerprint (47756d46..) appears in the active revoked_leaf_fingerprints set of the loaded trust bundle (bundle fp c2051f1c..). Refusing to start P2P. No fallback to --p2p-trusted-root on bundle-revoked local leaf. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_061.md and docs/whitepaper/contradiction.md C4 (signed root distribution).
```

Exit code: 1. Cross-check counts on Smoke 2 stderr:

| substring | count | meaning |
| --- | --- | --- |
| `FATAL: Run 061` | 1 | the existing Run 061 self-check fires on the now-active leaf revocation |
| `Failed to build P2P node` | 0 | `builder.build(...)` never entered |
| `[binary] Run 052: revoked_leaf_fingerprints=` | 0 | Run 052 builder wiring never reached |
| `Run 062: ... active=1 leaf_active=1` | 1 | gauge values mirror loaded view |
| `newly_connected_peers` | 0 | no peer-handshake counter could move |
| `Dummy` | 0 | no `Dummy*` fallback registered |

### Smoke 3 (root-revocation PENDING)

```
[binary] Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) required_epoch=None current_epoch=None)
[binary] Run 050/051: trust bundle loaded path=/tmp/qbind_run062/signed-devnet-root-revocation-pending/trust-bundle.json env=devnet fp=1f2e92983bd45af129336b9cf46569c93e2c08a55b58ac27306778b8f7fd8a20 active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=a9e4ae8d..) signing_keys_configured=1. Bundle root IDs: [81cd3400..]
[binary] Run 062: trust-bundle revocation activation (configured=1 active=0 pending=1 root_active=0 root_pending=1 leaf_active=0 leaf_pending=0)
[binary] P2P node started. Press Ctrl+C to exit.
```

Exit code: 124 (timeout-after-clean-startup). Cross-check counts:

| substring | count | meaning |
| --- | --- | --- |
| `FATAL` | 0 | pending root revocation does NOT exclude the root |
| `active_roots=1 revoked_roots=0` | 1 | root surface untouched (legacy `_revoked_roots` semantics preserved) |
| `Run 062: ... pending=1 root_pending=1` | 1 | new gauges mirror loaded view |
| `Dummy` | 0 | no `Dummy*` fallback registered |

### Smoke 4 (root-revocation ACTIVE — fail-closed)

```
[binary] Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) required_epoch=None current_epoch=None)
[binary] Run 055: trust-bundle sequence persistence env=devnet chain_id=51424e4444455600 path=/tmp/qbind_run062/data/root-active/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=200ffbd4
[binary] Run 050/051: trust bundle loaded path=/tmp/qbind_run062/signed-devnet-root-revocation-active/trust-bundle.json env=devnet fp=200ffbd4170fb49111713fd63cbffa473360b9d995a2a6bdfbdf29c599e6928f active_roots=0 revoked_roots=1 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=87a7050b..) signing_keys_configured=1. Bundle root IDs: []
[binary] FATAL: --p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root requires at least one configured trusted root. The supplied trust bundle (if any) contained zero active, in-window, non-revoked roots. See docs/whitepaper/contradiction.md C4 (signed root distribution).
```

Exit code: 1. Cross-check counts:

| substring | count | meaning |
| --- | --- | --- |
| `active_roots=0 revoked_roots=1` | 1 | satisfied root revocation excluded the root immediately (Run 050 parity) |
| `FATAL: --p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root requires at least one configured trusted root` | 1 | identical to legacy Run 050 root-revocation FATAL |
| `Dummy` | 0 | no `Dummy*` fallback registered |

(The Run 062 log line is intentionally NOT emitted on Smoke 4
because the no-active-roots FATAL fires earlier in the startup
order; the new gauges remain unset for that run, which is correct
behaviour because the binary exits before metrics are observable.
Smoke 3 above proves the gauges DO emit for the same root-revocation
shape when the entry is pending.)

## `/metrics` scrape (Smoke 1 dwell)

During Smoke 1 the metrics HTTP server was bound on
`127.0.0.1:19711`; while the node was alive (sleep 3 between launch
and curl), `curl -s http://127.0.0.1:19711/metrics` returned the
seven new gauges:

```
qbind_p2p_pqc_trust_bundle_revocations_active_total 0
qbind_p2p_pqc_trust_bundle_revocations_configured_total 1
qbind_p2p_pqc_trust_bundle_revocations_leaf_active 0
qbind_p2p_pqc_trust_bundle_revocations_leaf_pending 1
qbind_p2p_pqc_trust_bundle_revocations_pending_total 1
qbind_p2p_pqc_trust_bundle_revocations_root_active 0
qbind_p2p_pqc_trust_bundle_revocations_root_pending 0
```

The gauge values byte-match the `[binary] Run 062: ...` log line
emitted on the same run. Identity:
- `_revocations_configured_total = _revocations_active_total + _revocations_pending_total + (legacy effective_from-future entries)`
- `_revocations_root_active + _revocations_leaf_active = _revocations_active_total`
- `_revocations_root_pending + _revocations_leaf_pending = _revocations_pending_total`
- `_revocations_root_active = qbind_p2p_pqc_trust_bundle_revoked_roots` (legacy gauge, preserved bit-for-bit)

## No private-key leak proof

After every smoke, the helper output directory under
`/tmp/qbind_run062/<mode>/` contains exactly:
- `root.id.hex`, `root.pk.hex` (root **public** material only — root
  signing key minted ephemerally in memory and never written);
- `signing-key.id.hex`, `signing-key.pk.hex`, `signing-key.spec`
  (bundle-signing **public** material only);
- `v<N>.cert.bin`, `v<N>.leaf-fp.hex` (leaf cert + canonical
  fingerprint — both public);
- `v<N>.kem.sk.bin` (the validator KEM secret — required for the
  validator's own use, written `0o600` per the existing helper
  policy carried over from Run 037/050; never read by Run 062 logic);
- `trust-bundle.json` (signed bundle — public);
- `trusted-root.spec` (one-line CLI spec — public);
- `helper.stdout.log` (helper informational lines — never any
  private key).

No `root.sk.*`, `signing-key.sk.*`, or `bundle-signing.sk.*` file is
ever created (verified by `find /tmp/qbind_run062 -name '*.sk.*' -not
-name 'v*.kem.sk.bin'`). The Run 062 code path itself never touches
any `*.sk.*` artifact and never widens the helper API surface to
accept private-key material — the new modes only set additional
fields on `TrustBundleRevocation`, which is purely public schema.

## Explicitly NOT done in Run 062

(Mirrored verbatim into `docs/whitepaper/contradiction.md` C4 Run 062
remaining boundaries.)

(a) **Root-level local revocation self-check.** Unchanged from the
Run 061 §10 item (a) boundary — the binary still does NOT fail
closed at startup when the operator's local leaf was issued by a
root that is itself on `revoked_root_ids` (active set), without
the leaf's own fingerprint being on `revoked_leaf_fingerprints`.
Run 062 does NOT introduce that check. With Run 062, an operator
can now SCHEDULE a root revocation via `activation_height`, but the
local-leaf-issuance-from-revoked-root startup check itself is still
open.

(b) **`activation_epoch` runtime source on per-entry revocations.**
Run 062 only adds per-entry `activation_height` (block-height); an
analogous `activation_epoch` field is intentionally NOT added. The
bundle-level Run 057 boundary (`CurrentEpochUnavailable` fail-closed)
is unchanged, and there is currently no production runtime epoch
source.

(c) **Per-environment minimum activation-margin policy on revocation
entries.** Unchanged from the Run 057 bundle-level boundary — the
binary does NOT enforce a minimum margin between a revocation's
`activation_height` and the current finalised height. Operator
policy.

(d) **In-binary bundle-signing-key ratification.** Unchanged from
the Run 060 boundary; out-of-band CLI overlap remains the supported
rotation path.

(e) **External KMS / HSM integration.** Unchanged.

(f) **Multi-validator MainNet release-binary peer-connection
smoke.** Unchanged from the Run 059/060/061 boundary.

(g) **Production fast-sync / consensus-storage restore.** Unchanged.

(h) **Operator playbook prose update.** Run 060's
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` does not yet describe
how to use `activation_height` on revocation entries. The runbook is
intentionally NOT updated in Run 062 (Run 062 is source-and-evidence,
not operator-doc).

(i) **`/metrics` `_pending_total` does not bump a counter on
activation.** The seven Run 062 gauges are sticky-at-startup
snapshots (the trust bundle is loaded exactly once per process
lifetime); a future run may add an "activation transition observed
at runtime" counter family if/when on-the-fly trust-bundle
hot-reload is supported.

**C5 remains NOT closed** by Run 062; Run 062 does not touch
timeout/NewView wire formats, forged-traffic policy, KEMTLS wire
formats, consensus message wire formats, or any
signature/verification semantics outside the trust-bundle
revocation-entry activation-gate surface. **Full C4 remains OPEN.**