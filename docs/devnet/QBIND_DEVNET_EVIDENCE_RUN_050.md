# QBIND DevNet Evidence — Run 050

**Date**: 2026-05-12
**Branch**: `copilot/continue-qbind-development-8fcba092-6a4c-4e63-ac5e-ef8473658f65`
**Commit (before this Run's last commit)**: `eabcf187b5e1a8f3728046b54f7a3dbc86119133`
**Git status (during evidence capture)**: dirty (new module + helper + test files staged for the next commit)
**`qbind-node` (release) sha256**: `d05c28e4c069117a74293b163f0d63f12d3460de4e50ae47769068473392bdb5`
**`qbind-node` (release) ELF BuildID (GNU, sha1)**: `3a42b69feba597ecbf8b0c0ed139ce80e0f05ecf`
**`devnet_pqc_trust_bundle_helper` (release) sha256**: `61e6c29dd1d83c0f7650efca05ee5b1daec86ce7e183955363912b091eaa4536`

## Exact objective

Land the **smallest production-honest foundation layer** for PQC transport trust-anchor lifecycle on top of the Run 037 / 039 / 040 / 045 / 049 stack:

1. structured, environment-bound, canonically-hashable PQC trust-anchor bundle (DevNet / TestNet / MainNet binding);
2. per-root validity windows and `active | retired | revoked` status, evaluated at load time;
3. explicit revocation entries that fail closed regardless of `status` (defence in depth);
4. signed-bundle envelope **parsed but not verified** (Run 050 boundary) so that unsigned bundles are allowed only on DevNet; TestNet and MainNet refuse to load an unsigned bundle;
5. CLI flag `--p2p-trust-bundle <PATH>` wired into `qbind-node`'s `pqc-static-root` startup with a documented static-roots-vs-bundle conflict policy and **NO** silent fallback;
6. `qbind_p2p_pqc_trust_bundle_*` observability on the live `/metrics` endpoint;
7. DevNet-only bundle issuance helper (`devnet_pqc_trust_bundle_helper`) capable of producing positive *and* every documented negative fixture so future runs can re-prove fail-closed behaviour deterministically.

No KEMTLS, B14, consensus, timeout/NewView, or transport-crypto wire-format changes. No fallback to `DummySig` / `DummyKem` / `DummyAead`.

## Exact verdict

**Strongest positive for the scoped layer; explicitly partial for the full C4 piece.**

- DevNet root-level trust-anchor lifecycle (load, validate, environment-bind, status-filter, validity-window-filter, root-revocation-list, deterministic fingerprint, fail-closed startup) **lands and is proven** on a real `qbind-node` release binary with real ML-DSA-44 transport signing keys, real ML-KEM-768, real ChaCha20-Poly1305, and no `DummySig` / `DummyKem` / `DummyAead` registration.
- TestNet / MainNet refusal of unsigned bundles **lands and is proven** by unit and integration tests; live-binary TestNet/MainNet startup proof is intentionally deferred — Run 050 does not run a TestNet or MainNet `qbind-node` invocation.
- **Signed-bundle verification itself is NOT implemented in Run 050.** It is recorded as remaining under C4. Any bundle carrying a `signature` field is rejected at load time with `SignedBundleVerificationNotImplemented` so there is no path on which an unverified signature is silently accepted.
- **Leaf-level cert revocation is NOT implemented in Run 050.** The bundle schema records a `leaf_cert_fingerprint` field for future use, and the schema-level test exercises the field, but the live transport-cert-verify path does not consult it. Recorded as remaining.

## Exact files changed

```
crates/qbind-node/src/cli.rs                                            (+24 lines: --p2p-trust-bundle flag)
crates/qbind-node/src/lib.rs                                            (+5  lines: pub mod pqc_trust_bundle)
crates/qbind-node/src/main.rs                                           (+ 95 lines, -2 lines: bundle load + merge + metrics + fail-closed invariants)
crates/qbind-node/src/metrics.rs                                        (+ 70 lines: 5 trust-bundle gauges + accessors + format_metrics emission)
crates/qbind-node/src/pqc_trust_bundle.rs                               (NEW, ~1300 lines: data model + parser + validator + canonical fingerprint + helper-mode builder + 27 unit tests)
crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs            (NEW: DevNet-only bundle issuance helper supporting 8 modes)
crates/qbind-node/tests/run_050_pqc_trust_bundle_tests.rs               (NEW, 13 integration tests)
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_050.md                            (NEW, this document)
docs/devnet/run_050_smoke_*.{stdout,stderr}.log                         (NEW: captured live qbind-node smoke output)
docs/devnet/run_050_metrics_valid.txt                                   (NEW: captured `/metrics` scrape under valid bundle)
docs/whitepaper/contradiction.md                                        (+ Run 050 narrowing section under C4)
```

## Trust-bundle format

The on-disk artefact is a UTF-8 JSON file. The Rust-side `serde` shape is in `crates/qbind-node/src/pqc_trust_bundle.rs`. Annotated structural example (real bytes from `/tmp/run050/valid/trust-bundle.json`):

```json
{
  "bundle_version": 1,
  "environment": "devnet",           // devnet | testnet | mainnet
  "chain_id": null,                  // optional, not yet enforced (Run 050 boundary)
  "generated_at": 1778563931,        // Unix seconds, informational
  "valid_from": 0,                   // Unix seconds, enforced at load
  "valid_until": 18446744073709551615, // Unix seconds, enforced at load
  "sequence": 1,                     // monotonic; recorded, not yet enforced
  "roots": [
    {
      "root_id":     "65a3a23a…dbf7",  // 32-byte stable id, 64 lowercase hex chars
      "suite_id":    100,              // ML-DSA-44 only; anything else fails closed
      "root_pk":     "b76fc826…20bf",  // full ML-DSA-44 public key
      "status":      "active",         // active | retired | revoked
      "not_before":  0,                // per-root window start, enforced at load
      "not_after":   18446744073709551615, // per-root window end, enforced at load
      "activation_epoch":  null,       // recorded only; not yet enforced
      "activation_height": null        // recorded only; not yet enforced
    }
  ],
  "revocations": [
    // {
    //   "root_id": "…",               // MUST reference a roots[i].root_id
    //   "leaf_cert_fingerprint": null, // schema field; not yet enforced (Run 050 boundary)
    //   "reason": "compromise",       // free-form, logged on rejection
    //   "effective_from": 1700000000  // Unix seconds; future-dated revocations recorded but not yet active
    // }
  ],
  "signature": null                   // Run 050: parsed only. If non-null, load fails with SignedBundleVerificationNotImplemented
}
```

## Validation semantics

Implemented in `TrustBundle::validate_at`. Errors are deterministic and exhaustive:

| Failure                                                                  | Error variant                              | Live-binary log    |
| ------------------------------------------------------------------------ | ------------------------------------------ | ------------------ |
| `bundle_version != 1`                                                    | `UnsupportedSchemaVersion(v)`              | FATAL              |
| `bundle.environment` mismatches runtime environment                      | `WrongEnvironment { expected, found }`     | FATAL              |
| Unsigned bundle on TestNet/MainNet                                        | `UnsignedBundleNotAllowed(env)`            | FATAL              |
| Any non-null `signature`                                                  | `SignedBundleVerificationNotImplemented`   | FATAL              |
| `valid_from > valid_until`                                                | `InvalidBundleValidityWindow`              | FATAL              |
| `now < valid_from`                                                        | `BundleNotYetValid`                        | FATAL              |
| `now > valid_until`                                                       | `BundleExpired`                            | FATAL              |
| Any root with `not_before > not_after`                                    | `InvalidRootValidityWindow(id)`            | FATAL              |
| Active root with `now < not_before`                                       | `RootNotYetValid(id)`                      | FATAL              |
| Active root with `now > not_after`                                        | `RootExpired(id)`                          | FATAL              |
| Two roots with the same `root_id`                                         | `DuplicateRootId(id)`                      | FATAL              |
| Any root using suite_id ≠ 100 (ML-DSA-44)                                | `UnsupportedSuite { root_id, suite_id }`   | FATAL              |
| Malformed hex (root_id / root_pk / signing_key_id)                       | `MalformedHex(detail)`                     | FATAL              |
| `root_pk` length ≠ `ML_DSA_44_PUBLIC_KEY_SIZE`                          | `MalformedRootPublicKey {…}`               | FATAL              |
| Revocation references unknown root                                       | `RevocationReferencesUnknownRoot(id)`      | FATAL              |
| Duplicate revocation entry                                               | `DuplicateRevocation(id)`                  | FATAL              |
| `signing_key_id` collides with any `root_id` (trust-separation policy)   | `SigningKeyCollidesWithRootId(id)`         | FATAL              |
| Empty active set in `--p2p-mutual-auth required` + bundle-only           | (FATAL guard in `main.rs`)                 | FATAL              |
| Both `--p2p-trust-bundle` and `--p2p-trusted-root` on TestNet/MainNet    | (FATAL guard in `main.rs`)                 | FATAL              |

A successful load produces a `LoadedTrustBundle` with:
- `bundle: TrustBundle`,
- `fingerprint: [u8; 32]` — SHA3-256 of `serde_json::to_vec(bundle_with_signature_stripped)` prefixed by the domain string `b"QBIND:pqc-trust-bundle-fp:v1"` (deterministic; verified by `canonical_fingerprint_is_deterministic`, `canonical_fingerprint_strips_signature`, `canonical_fingerprint_changes_with_root_content`),
- `active_roots: Vec<PqcTrustedRoot>` — only entries with `status == Active`, in their own window, AND not on the revocation list,
- `revoked_root_ids: HashSet<[u8; 32]>` — for future leaf-aware lookups and metrics.

## Signature model and boundaries (Run 050)

- **DevNet**: unsigned bundle accepted. (Matches the existing DevNet ephemeral-root helper convention from Run 037.)
- **TestNet / MainNet**: unsigned bundle **REFUSED** at load time with `UnsignedBundleNotAllowed(env)`.
- **Any environment, signed bundle**: **REFUSED** at load time with `SignedBundleVerificationNotImplemented`. Run 050 does not introduce a verification code path, so there is zero risk of an unverified signature being silently treated as verified.
- **Trust separation**: even when signed-bundle verification lands, `signing_key_id` MUST NOT equal any `roots[i].root_id`. The schema validator enforces this (`SigningKeyCollidesWithRootId`) so that a compromised transport root cannot retroactively be used as a bundle-distribution authority.

This is the documented Option-B + future-Option-C boundary from the task description.

## Environment-binding semantics

- `bundle.environment` is matched against `NodeConfig.environment` (the same field that drives chain-id selection at `crates/qbind-types/src/primitives.rs:112`).
- A DevNet runtime refuses TestNet and MainNet bundles. A TestNet runtime refuses DevNet and MainNet bundles. A MainNet runtime refuses DevNet and TestNet bundles. Verified in unit tests (`wrong_environment_fails_closed`, `unsigned_bundle_rejected_on_testnet`, `unsigned_bundle_rejected_on_mainnet`) and in integration test `wrong_environment_bundle_is_rejected_fail_closed`.
- Stable metric encoding: `qbind_p2p_pqc_trust_bundle_environment = 0` for DevNet, `1` for TestNet, `2` for MainNet; only meaningful when `qbind_p2p_pqc_trust_bundle_loaded == 1`.

## Revocation semantics

- **Root-level revocation: enforced.** Either of the two pathways excludes the root from `active_roots`:
  1. `roots[i].status = "revoked"` (or `"retired"`), OR
  2. an entry in `revocations[]` whose `root_id` matches.
- Defence in depth: even if a root somehow appears in both `roots[]` with `status: active` AND in `revocations[]`, the revocation wins; the root is excluded from `active_roots`.
- `revocations[i].effective_from` is honoured: a revocation whose effective time is in the future is recorded in the bundle (and stays in the source-of-truth JSON), but the root is NOT yet excluded from the live trust set at the current `validation_time_secs`. This lets operators schedule rotations.
- **Leaf-level revocation: NOT enforced in Run 050.** `revocations[i].leaf_cert_fingerprint` is parsed by the schema but the live `verify_delegation_cert` path does not consult it. Recorded as remaining.

## Static-root migration / conflict behaviour

- `--p2p-trusted-root ROOTID:SUITE:ROOTPK` is preserved bit-for-bit on DevNet.
- When **only** `--p2p-trust-bundle` is supplied, the bundle's `active_roots` populate the trust set.
- When **both** are supplied:
  - DevNet: allowed; the bundle roots are merged into the CLI roots, deduplicated by `root_key_id`.
  - TestNet / MainNet: **FATAL** at startup. The operator must choose one of the two. Captured in main.rs explicitly:
    > `--p2p-trust-bundle and --p2p-trusted-root cannot be combined on environment={} (only DevNet allows the operator override). Use the bundle alone, or omit --p2p-trusted-root.`
- The Run 037 invariant "Required + pqc-static-root demands ≥ 1 trusted root" is preserved end-to-end: when the CLI roots are empty but a bundle is supplied, the bundle's `active_roots` must be ≥ 1 or main.rs fails closed (`zero active, in-window, non-revoked roots`). Proven by the `root-status-revoked` and `root-revocation-listed` smokes below.

## Startup log examples

Positive load (from `run_050_smoke_valid.stderr.log`):
```
[binary] Run 050: trust bundle loaded path=/tmp/run050/valid/trust-bundle.json env=devnet fp=c3d6eda5d0df26baed1a26719d83404a7db34b03ce55d88e3857318e451757ac active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signed=false (DevNet-unsigned scaffolding; signed-bundle verification remains C4-open). Bundle root IDs: [65a3a23a..]
```

Negative-load examples (one line each):
```
[binary] FATAL: --p2p-trust-bundle load/validate failed for path=/tmp/run050/wrong-environment/trust-bundle.json: trust bundle environment mismatch (expected devnet, bundle declares testnet). No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade). See docs/whitepaper/contradiction.md C4 (signed root distribution).
[binary] FATAL: --p2p-trust-bundle load/validate failed for path=/tmp/run050/expired-bundle/trust-bundle.json: trust bundle is expired. …
[binary] FATAL: --p2p-trust-bundle load/validate failed for path=/tmp/run050/expired-root/trust-bundle.json: trust bundle root 426188cf…7074 is expired. …
[binary] FATAL: --p2p-trust-bundle load/validate failed for path=/tmp/run050/duplicate-root/trust-bundle.json: trust bundle has duplicate root_id e05b0681…429d. …
[binary] FATAL: --p2p-trust-bundle load/validate failed for path=/tmp/run050/unsupported-suite/trust-bundle.json: trust bundle root f8358170…44dc uses unsupported suite_id 99 (only 100 = ML-DSA-44 accepted). …
[binary] FATAL: --p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root requires at least one configured trusted root. The supplied trust bundle (if any) contained zero active, in-window, non-revoked roots. …
```

None of these logs contains a private key, a KEM secret, or any byte of `root_sk`. The helper enforces the same property: `root_sk was held in memory only; never written to disk.`

## Metrics added

Five new gauges on `P2pMetrics`, all surfaced on `/metrics` from the shared `node_metrics.p2p_arc()` instance:

```
qbind_p2p_pqc_trust_bundle_loaded         (0 / 1)
qbind_p2p_pqc_trust_bundle_environment    (0=devnet, 1=testnet, 2=mainnet; meaningful only when _loaded == 1)
qbind_p2p_pqc_trust_bundle_active_roots   (count)
qbind_p2p_pqc_trust_bundle_revoked_roots  (count — only counts entries in the bundle's revocations[] list, not status=Retired/Revoked roots)
qbind_p2p_pqc_trust_bundle_sequence       (the bundle's monotonic sequence number)
```

Live scrape from the positive smoke (captured in `docs/devnet/run_050_metrics_valid.txt`):
```
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 0
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_trust_bundle_loaded 1
qbind_p2p_pqc_trust_bundle_environment 0
qbind_p2p_pqc_trust_bundle_active_roots 1
qbind_p2p_pqc_trust_bundle_revoked_roots 0
qbind_p2p_pqc_trust_bundle_sequence 1
```

No counters were fabricated; the Run 044 `qbind_p2p_pqc_cert_*` family is unchanged (all sub-counter zeros preserved on this scrape because no peer connected in the single-node smoke).

## Tests run and pass/fail status

| Suite                                                                                     | Result        |
| ----------------------------------------------------------------------------------------- | ------------- |
| `cargo test -p qbind-node --lib pqc_trust_bundle` (27 new tests in this module)            | **27/27 pass** |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` (13 new integration tests) | **13/13 pass** |
| `cargo test -p qbind-node --lib metrics` (existing P2pMetrics + adapters)                  | **102/102 pass** |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests`                | **12/12 pass** |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests`                  | **14/14 pass** |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests`            | **10/10 pass** |
| `cargo test -p qbind-node --lib` (full library, includes the new module's 27)              | **818/818 pass** (was 791 before Run 050; +27 from the new module) |
| `cargo test -p qbind-net --lib`                                                            | **17/17 pass** |
| `cargo test -p qbind-crypto --lib`                                                         | **68/68 pass** |
| `cargo build --release -p qbind-node --bin qbind-node`                                     | **clean** (3 pre-existing warnings, none from this Run) |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper`                     | **clean**      |
| `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper`             | **clean**      |

## Exact commands run

```bash
# unit tests
cargo test -p qbind-node --lib pqc_trust_bundle
cargo test -p qbind-node --lib metrics
cargo test -p qbind-node --lib
cargo test -p qbind-net --lib
cargo test -p qbind-crypto --lib

# integration tests
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests
cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests

# release builds
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper

# real-binary smokes (eight fixtures: 1 positive + 7 negative)
for mode in valid wrong-environment expired-bundle expired-root duplicate-root \
            unsupported-suite root-status-revoked root-revocation-listed; do
  ./target/release/examples/devnet_pqc_trust_bundle_helper "/tmp/run050/$mode" 2 "$mode"
  ./target/release/qbind-node --env devnet --validator-id 0 \
    --network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:0 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle "/tmp/run050/$mode/trust-bundle.json" \
    --p2p-leaf-cert "/tmp/run050/$mode/v0.cert.bin" \
    --p2p-leaf-cert-key "/tmp/run050/$mode/v0.kem.sk.bin" \
    --p2p-peer-leaf-cert "1:/tmp/run050/$mode/v1.cert.bin"
done

# /metrics scrape under valid bundle
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9051 ./target/release/qbind-node \
  --env devnet --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle /tmp/run050/valid/trust-bundle.json \
  --p2p-leaf-cert /tmp/run050/valid/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run050/valid/v0.kem.sk.bin \
  --p2p-peer-leaf-cert 1:/tmp/run050/valid/v1.cert.bin &
curl -s http://127.0.0.1:9051/metrics | grep -E 'qbind_p2p_pqc_'
```

## Positive two-node trust-bundle smoke summary

`mode=valid` smoke (exit code 124 = timeout, i.e. the binary stayed up healthily for the 8-second window):
- Binary loaded the bundle (`Run 050: trust bundle loaded path=… env=devnet fp=c3d6eda5… active_roots=1 revoked_roots=0 sequence=1 …`).
- `pqc_root_mode = pqc-static-root` registered the real `MlDsa44SignatureSuite` under suite_id 100 (no `DummySig` fallback).
- ML-KEM-768 + ChaCha20-Poly1305 selected (unchanged from Run 040).
- `qbind_p2p_pqc_root_mode = 1`, `qbind_p2p_pqc_roots_configured = 1`, `qbind_p2p_pqc_trust_bundle_loaded = 1`, `qbind_p2p_pqc_trust_bundle_active_roots = 1`, `qbind_p2p_pqc_trust_bundle_revoked_roots = 0` all observable on the live `/metrics` endpoint.
- No private-key material in any of `docs/devnet/run_050_smoke_*.{stdout,stderr}.log` (verified by inspection — only public IDs, public keys, lengths, and fingerprints).

A live **two-binary** smoke was not attempted in Run 050 (the same binary identity satisfies the trust-bundle layer's invariants regardless of node count; the Run 037 / 039 / 040 / 042 / 049 evidence already cover the multi-node pqc-static-root handshake on the byte-identical `MlDsa44SignatureSuite` path). Two-binary trust-bundle smoke is a candidate for a future "Run 050.1" optional run.

## Negative smokes summary

All seven recorded negative fixtures exited with `1` (FATAL), with precise reasons, and **no fallback to `--p2p-trusted-root`** was taken on bundle failure:

| Mode                       | FATAL reason (truncated)                                                                                       |
| -------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `wrong-environment`        | `trust bundle environment mismatch (expected devnet, bundle declares testnet)`                                |
| `expired-bundle`           | `trust bundle is expired`                                                                                     |
| `expired-root`             | `trust bundle root 426188cf…7074 is expired`                                                                  |
| `duplicate-root`           | `trust bundle has duplicate root_id e05b0681…429d`                                                            |
| `unsupported-suite`        | `trust bundle root f8358170…44dc uses unsupported suite_id 99 (only 100 = ML-DSA-44 accepted)`                |
| `root-status-revoked`      | (bundle parses; `active_roots=0`) → FATAL `requires at least one configured trusted root`                     |
| `root-revocation-listed`   | (bundle parses; `active_roots=0 revoked_roots=1`) → FATAL `requires at least one configured trusted root`    |

Full captures in `docs/devnet/run_050_smoke_*.stderr.log`.

## Investigation findings (exact file/function references)

Investigated, no inconsistencies that warranted source changes outside the documented scope:

- `crates/qbind-node/src/pqc_root_config.rs:432` `PqcStaticRootConfig` — unchanged. Bundle-derived roots are merged into `trusted_roots: Vec<PqcTrustedRoot>` so the existing `lookup_root_pk` (line 463) continues to be the single source of truth at verify time. Revoked roots simply do not appear in `trusted_roots` after merge, so the existing fail-closed `ClientCertInvalid("untrusted root")` path enforces revocation without any change to the resolver itself.
- `crates/qbind-node/src/p2p_node_builder.rs:773` `with_pqc_root_config` — unchanged. Trust bundle wiring lives entirely in `main.rs`, which builds the same `PqcStaticRootConfig` shape.
- `crates/qbind-net/src/handshake.rs` — unchanged. KEMTLS / `NetworkDelegationCert` / `TrustedClientRoots` semantics not touched.
- `crates/qbind-node/src/pqc_devnet_helper.rs` — unchanged. The new `devnet_pqc_trust_bundle_helper.rs` example wraps `mint_devnet_root` and `issue_leaf_delegation_cert`, preserving Run 037/045 semantics for cert issuance.
- `crates/qbind-node/src/cli.rs` — only the one new `--p2p-trust-bundle <PATH>` flag added; pre-existing `--p2p-trusted-root` / `--p2p-leaf-cert*` flags untouched.
- `crates/qbind-node/src/main.rs` — adds a single bundle-loading block before `PqcStaticRootConfig { … }`, plus two FATAL guards (static-roots+bundle conflict on TestNet/MainNet; empty-active-set under Required), plus the five `set_pqc_trust_bundle_*` metric calls on the shared `node_metrics.p2p_arc()` Arc; the existing Run 037–049 log lines and behaviour are untouched.
- `crates/qbind-types/src/primitives.rs:102` `NetworkEnvironment` — used unchanged via `TrustBundleEnvironment::matches_runtime`.
- `qbind_p2p_pqc_*` metrics — five gauges added in `metrics.rs`; the Run 044 `qbind_p2p_pqc_cert_*` family and its sub-counters are untouched.

## Remaining open items (kept open under C4)

1. **Signed-bundle (ML-DSA-44) verification.** Schema is in place; verification code path is not. Loader rejects any non-null `signature` with `SignedBundleVerificationNotImplemented` — no silent acceptance possible.
2. **TestNet / MainNet bundle distribution.** Unsigned bundles are refused on TestNet/MainNet today; until signed-bundle verification lands, neither TestNet nor MainNet can run with the bundle layer alive. This is the documented Run 050 boundary, not a regression.
3. **Leaf-level revocation enforcement.** Bundle schema records `leaf_cert_fingerprint`; live cert-verify path does not yet consult it.
4. **Activation epoch / height enforcement.** Bundle schema records `activation_epoch` and `activation_height`; runtime does not yet gate root activation on consensus epoch or height.
5. **Sequence-number persistence / monotonicity enforcement across reloads.** Recorded in metric; not yet persisted.
6. **chain_id crosscheck.** Bundle schema records `chain_id`; runtime does not yet enforce it against `NodeConfig.chain_id`.
7. **Production CA / certificate-rotation operator playbook / signed-root-distribution lifecycle.** None of these are claimed closed.
8. **Production fast-sync / consensus-storage restore.** Untouched by Run 050.
9. **Per-environment trust anchors for TestNet / MainNet specifically.** DevNet binding is proven end-to-end; TestNet / MainNet binding is proven by unit + integration tests but not by a live-binary TestNet/MainNet startup.
10. **`backoff` live cap-hit at 800 ticks** under a TestNet/MainNet trust-bundle run — Run 049 already proved this on DevNet, but the bundle layer was not yet present then.

`docs/whitepaper/contradiction.md` is updated to record the narrowing on items 1–9 (root-level lifecycle layer narrowed) while keeping C4 OPEN.

## Was `contradiction.md` updated and why?

**Yes.** A new section was appended under C4: "Run 050 evidence update — production-honest PQC trust-anchor bundle foundation; C4 narrowed on the root-level lifecycle layer; signed-bundle verification and leaf-level revocation remain open". The section records:
- the narrowing: DevNet root-level lifecycle (load / validate / env-bind / status / window / revocation list / fingerprint / fail-closed) is now proven on a real binary;
- the explicit non-claim: signed-bundle verification, leaf-level revocation enforcement, activation epoch/height gating, sequence-number monotonicity, and chain_id crosscheck remain open;
- the explicit non-claim: full C4 remains OPEN; C5 untouched.

## Exact immediate next action recommended

**Run 051**: land **signed bundle (ML-DSA-44) verification** with a dedicated bundle-signing key list configured via a new CLI flag (`--p2p-trust-bundle-signing-key ROOTID:SUITE:PK`, repeatable) that is **separate** from `--p2p-trusted-root` (trust-separation policy), wire `qbind_p2p_pqc_trust_bundle_signature_verified_total` and `_rejected_total` counters, and enable TestNet/MainNet bundle operation end-to-end. Re-prove a positive two-binary TestNet smoke and tampered-signature negative smoke.

Alternative parallel: **Run 050.1** — two-binary live trust-bundle handshake smoke on DevNet (cheap; uses the same fixtures from this Run with two `qbind-node` processes wired by `--p2p-peer`). Useful only as an extra-belt-and-braces continuity check; the trust-bundle layer itself is already proven by the unit / integration / single-binary smoke evidence in this Run.