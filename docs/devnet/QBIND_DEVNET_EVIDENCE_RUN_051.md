# QBIND DevNet Evidence — Run 051: Signed PQC Trust-Bundle ML-DSA-44 Verification

## Exact objective

Run 051 implements the smallest production-honest signed PQC trust-bundle
verification layer on top of the Run 050 structured-trust-bundle
foundation. The objective is:

- Replace the Run 050 `SignedBundleVerificationNotImplemented` boundary
  with real ML-DSA-44 signed-bundle verification.
- Add a trust-separated `--p2p-trust-bundle-signing-key` CLI flag whose
  KEYID may not collide with any transport root id.
- Refuse unsigned TestNet/MainNet bundles and refuse any
  bad/wrong-key/unsupported-suite/malformed-bytes/missing-key signature
  fail-closed, with no fallback to `--p2p-trusted-root` and no
  fallback to `DummySig`/`DummyKem`/`DummyAead`.
- Add truthful signed-bundle metrics
  (`qbind_p2p_pqc_trust_bundle_signature_verified_total`,
  `qbind_p2p_pqc_trust_bundle_signature_rejected_total`,
  `qbind_p2p_pqc_trust_bundle_signing_keys_configured`).
- Prove the positive DevNet and TestNet paths AND the
  tampered/wrong-key/unsupported-suite/malformed-sig/key-root-collision/
  unsigned-testnet/unsigned-mainnet negative paths against the real
  release `qbind-node` binary.

## Exact verdict

**Strongest positive for the scoped Run 051 signed-root-distribution
layer.** ML-DSA-44 signed-bundle verification lands behind
`--p2p-trust-bundle-signing-key`; the trust-separated bundle-signing
key list is enforced against both bundle-internal `roots[]` and the
external `--p2p-trusted-root` CLI set; DevNet and TestNet signed
bundles verify on the live release `qbind-node` binary; unsigned
TestNet/MainNet, tampered, wrong-key, unsupported-suite, malformed-sig,
and key/root-collision fixtures all fail closed with precise FATAL
reasons; signed-bundle metrics are truthful (verified counter moves to
1 on a real verification, rejected counter stays at 0); no
`DummySig`/`DummyKem`/`DummyAead` registered; no fallback to
`--p2p-trusted-root` on any bundle failure. MainNet live signed-bundle
startup is proven by unit + integration tests + the same
`validate_at_with_signing_keys` codepath that powers DevNet/TestNet,
but a real-binary MainNet smoke with a production-grade signing key
was deliberately not performed and is recorded as the explicit
remaining boundary.

## Exact files changed

| File | Change |
| --- | --- |
| `crates/qbind-node/src/pqc_trust_bundle.rs` | Add `BundleSigningKey`, `BundleSigningKeySet`, `BundleSigningKeySpecError`, `parse_bundle_signing_key_spec`, `derive_signing_key_id`, `sign_bundle_devnet_helper`, `canonical_signing_bytes`, `TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR`, `BundleSignatureStatus`, `LoadedTrustBundle.signature_status`; add `validate_at_with_signing_keys` / `load_from_bytes_with_signing_keys` / `load_from_path_with_signing_keys` and keep the 3-arg shims for Run 050 back-compat; replace the `SignedBundleVerificationNotImplemented` rejection with the real ML-DSA-44 verify path; add `MissingSigningKey` / `UnsupportedSignatureSuite` / `SignatureSuiteMismatch` / `MalformedSignatureBytes` / `BadSignature` error variants; mark legacy `SignedBundleVerificationNotImplemented` `#[doc(hidden)]`; add 29 new unit tests for the parser, canonical signing bytes, and end-to-end signature verification. |
| `crates/qbind-node/src/cli.rs` | Add repeatable `--p2p-trust-bundle-signing-key KEYID:SUITE:PK` flag with full Run 051 doc. |
| `crates/qbind-node/src/main.rs` | Parse the signing-key flag up front; enforce trust-separation between the parsed signing-key list and the configured `--p2p-trusted-root` set (both directions); enforce TestNet/MainNet+bundle requires signing-key; warn-only no-op when signing-key is supplied without a bundle; thread `BundleSigningKeySet` into `TrustBundle::load_from_path_with_signing_keys`; bump the new `signature_verified_total` counter exactly once on success, bump the new `signature_rejected_total` counter exactly once on signature-envelope rejection before `exit(1)`; surface `signature=verified(signing_key_id=…)` or `signature=unsigned` in the trust-bundle log line; set the new `signing_keys_configured` gauge. |
| `crates/qbind-node/src/metrics.rs` | Add `pqc_trust_bundle_signature_verified_total`, `pqc_trust_bundle_signature_rejected_total`, `pqc_trust_bundle_signing_keys_configured` `AtomicU64`s; expose `pqc_trust_bundle_signature_verified_total()` / `inc_pqc_trust_bundle_signature_verified()` / `pqc_trust_bundle_signature_rejected_total()` / `inc_pqc_trust_bundle_signature_rejected()` / `pqc_trust_bundle_signing_keys_configured()` / `set_pqc_trust_bundle_signing_keys_configured()` accessors; render the three lines in `format_metrics_with_crypto`; add 2 new metrics unit tests. |
| `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` | Extend with 9 new signed-bundle helper modes (`signed-devnet`, `signed-testnet`, `signed-mainnet`, `signed-tampered`, `signed-wrong-key`, `signed-unsupported-suite`, `signed-malformed`, `signed-key-root-collision`, plus retained Run 050 modes and the new `unsigned-testnet`/`unsigned-mainnet` fixtures); generate ephemeral ML-DSA-44 bundle-signing keys in memory only; write `signing-key.{id.hex,pk.hex,spec}` for operator capture; never write `signing_sk` or `root_sk` to disk. |
| `crates/qbind-node/tests/run_051_pqc_trust_bundle_signing_tests.rs` | New integration-test file: 13 tests covering signed DevNet/TestNet/MainNet positive load, unsigned DevNet still loads, unsigned TestNet/MainNet fail closed, tampered/wrong-key/unsupported-suite/missing-key signed-bundle fail-closed paths, signing-key-vs-bundle-root-id collision, signature metadata changes do not affect signing preimage, and the 3-arg back-compat shim still routes through the new verify path. |
| `docs/whitepaper/contradiction.md` | Append "C4 Run 051 evidence update" recording signed-root-distribution narrowed for DevNet + TestNet (live binary) + MainNet (test surface), and the explicit list of remaining-open C4 pieces (leaf-level revocation, activation gating, sequence persistence, chain_id crosscheck, production CA/rotation playbook, MainNet live smoke). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_051.md` | New evidence document (this file). |
| `docs/devnet/run_051_smoke_*.{stdout,stderr}.log`, `docs/devnet/run_051_metrics_signed-devnet.txt` | Smoke logs (positive DevNet, positive TestNet, 5 signed-bundle negatives, 2 unsigned TestNet/MainNet negatives, /metrics scrape). |

## Exact commands run

```bash
# build
cargo build -p qbind-node --lib
cargo build --release -p qbind-node --bin qbind-node \
  --example devnet_pqc_root_helper --example devnet_pqc_trust_bundle_helper

# unit + integration tests
cargo test -p qbind-node --lib pqc_trust_bundle
cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests
cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests
cargo test -p qbind-node --lib pqc_root_config
cargo test -p qbind-node --lib metrics
cargo test -p qbind-node --lib p2p
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests
cargo test -p qbind-node --lib
cargo test -p qbind-net --lib
cargo test -p qbind-crypto --lib

# generate signed fixtures
for mode in signed-devnet signed-testnet signed-mainnet \
            signed-tampered signed-wrong-key signed-unsupported-suite \
            signed-malformed signed-key-root-collision \
            unsigned-testnet unsigned-mainnet; do
  ./target/release/examples/devnet_pqc_trust_bundle_helper "/tmp/run051/$mode" 1 "$mode"
done

# positive DevNet signed-bundle smoke (release binary)
SIGN_SPEC="$(cat /tmp/run051/signed-devnet/signing-key.spec)"
timeout 6 ./target/release/qbind-node \
  --env devnet --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle /tmp/run051/signed-devnet/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert /tmp/run051/signed-devnet/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run051/signed-devnet/v0.kem.sk.bin

# /metrics scrape under verified signed bundle
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9151 ./target/release/qbind-node \
  ... (same flags as above) &
curl -s http://127.0.0.1:9151/metrics | grep -E 'qbind_p2p_pqc_trust_bundle'

# positive TestNet signed-bundle smoke
SIGN_SPEC="$(cat /tmp/run051/signed-testnet/signing-key.spec)"
timeout 6 ./target/release/qbind-node --env testnet ... \
  --p2p-trust-bundle /tmp/run051/signed-testnet/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" ...

# negative smokes (each exits 1)
for mode in signed-tampered signed-wrong-key signed-unsupported-suite \
            signed-malformed signed-key-root-collision; do
  timeout 6 ./target/release/qbind-node --env devnet ... \
    --p2p-trust-bundle /tmp/run051/$mode/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$(cat /tmp/run051/$mode/signing-key.spec)" \
    --p2p-leaf-cert ... --p2p-leaf-cert-key ...
done
timeout 6 ./target/release/qbind-node --env testnet ... \
  --p2p-trust-bundle /tmp/run051/unsigned-testnet/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$(cat /tmp/run051/unsigned-testnet-with-key/signing-key.spec)" ...
timeout 6 ./target/release/qbind-node --env mainnet ... \
  --p2p-trust-bundle /tmp/run051/unsigned-mainnet/trust-bundle.json ...
```

## Tests run and pass/fail status

| Suite | Result |
| --- | --- |
| `cargo test -p qbind-node --lib pqc_trust_bundle` | **56 / 56 pass** (Run 050's 27 + Run 051's 29 new tests) |
| `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | **13 / 13 pass** |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` | **13 / 13 pass** (unchanged; 3-arg `load_from_bytes` shim routes through the new verify path with an empty signing-key set) |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **12 / 12 pass** |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **14 / 14 pass** |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | **10 / 10 pass** |
| `cargo test -p qbind-node --lib pqc_root_config` | **14 / 14 pass** |
| `cargo test -p qbind-node --lib p2p` | **138 / 138 pass** |
| `cargo test -p qbind-node --lib metrics` (incl. 2 new Run 051 tests) | **104 / 104 pass** |
| `cargo test -p qbind-node --lib` (full) | **847 / 847 pass** (was 818 / 818 in Run 050; +29) |
| `cargo test -p qbind-net --lib` | **17 / 17 pass** |
| `cargo test -p qbind-crypto --lib` | **68 / 68 pass** |
| `cargo build --release -p qbind-node --bin qbind-node` | Clean |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | Clean |
| `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper` | Clean |

## Investigation findings

### Run 050 trust-bundle layer baseline

- `crates/qbind-node/src/pqc_trust_bundle.rs` already defined
  `TrustBundle`, `TrustBundleSignature { signing_key_id, suite_id,
  sig_bytes }`, environment binding (`devnet|testnet|mainnet`),
  validity windows, per-root status, revocation list, and the
  deterministic `canonical_fingerprint()` over the bundle with the
  signature stripped. The signature field was structurally there but
  any non-null `signature` was rejected with
  `TrustBundleError::SignedBundleVerificationNotImplemented`.
- `crates/qbind-node/src/cli.rs` already had `--p2p-trust-bundle`
  (Run 050).
- `crates/qbind-node/src/main.rs` already had the
  `load_from_path` → `LoadedTrustBundle` → `trusted_roots`-merge path
  with fail-closed exit-1 on any error and no fallback to
  `--p2p-trusted-root` on bundle failure (Run 050 invariant).
- `crates/qbind-node/src/metrics.rs` already exposed
  `qbind_p2p_pqc_trust_bundle_{loaded,environment,active_roots,
  revoked_roots,sequence}`.
- The existing trust-separation check (`SigningKeyCollidesWithRootId`)
  was already in place but unreachable on Run 050 because all signed
  bundles were rejected before that check ran.

### Signed-bundle envelope semantics

- `signing_key_id`: 64-char lowercase hex (32-byte canonical id).
- `suite_id`: `100` (ML-DSA-44) only. Any other value fails closed
  with `UnsupportedSignatureSuite`.
- `sig_bytes`: lowercase hex of an ML-DSA-44 detached signature; must
  decode to exactly `qbind_crypto::ML_DSA_44_SIGNATURE_SIZE` bytes
  (2420). Anything else fails closed with `MalformedSignatureBytes`.
- Signing preimage:
  `preimage = b"QBIND:pqc-trust-bundle-signature:v1" || serde_json::to_vec(bundle { signature: None })`.
  The domain separator is intentionally distinct from
  `b"QBIND:pqc-trust-bundle-fp:v1"` (used by `canonical_fingerprint`),
  so a fingerprint hash can never collide with a signature preimage.
- The `signature` envelope is stripped from the preimage, so adding,
  removing, or replacing the signature does NOT change what was signed.
  This also preserves the Run 050 fingerprint semantics — the
  fingerprint of an unsigned bundle equals the fingerprint of the
  same bundle re-signed.
- Verification order: structural checks (schema, environment,
  validity window, root status, root window, revocation consistency,
  trust-separation) all run first; only then is the ML-DSA-44
  verifier invoked. The verifier is never called on a malformed
  envelope.

### Signing-key CLI/config semantics

- `--p2p-trust-bundle-signing-key KEYID:SUITE:PK`, repeatable.
- Strict parser (`parse_bundle_signing_key_spec`): exactly 3
  colon-separated fields; KEYID is 64 lowercase hex chars; SUITE is
  decimal `100`; PK is lowercase hex of exactly
  `ML_DSA_44_PUBLIC_KEY_SIZE` bytes. Empty/missing/trailing fields
  fail closed. `BundleSigningKeySet::parse_specs` then rejects
  duplicate KEYIDs.
- `BundleSigningKey { key_id_bytes: [u8;32], suite_id: u8, pk_bytes:
  Vec<u8> }`. The set looks up entries by canonical 32-byte id, never
  by string compare.

### Trust-separation rules

- Bundle-internal (Run 050 invariant, preserved):
  `signature.signing_key_id` MUST NOT collide with any
  `roots[i].root_id`. Enforced inside
  `TrustBundle::validate_at_with_signing_keys` →
  `TrustBundleError::SigningKeyCollidesWithRootId`.
- CLI-external (Run 051 invariant, new): a
  `--p2p-trust-bundle-signing-key KEYID:…` MUST NOT collide with any
  `--p2p-trusted-root` KEYID configured on the same CLI invocation.
  Enforced inside `main.rs` before bundle load; FATAL with
  `--p2p-trust-bundle-signing-key <id> collides with a configured --p2p-trusted-root id`.

### Environment policy

| Env | Unsigned bundle | Signed bundle | Bundle without signing-key |
| --- | --- | --- | --- |
| DevNet | Accepted (Run 050 scaffolding preserved) | Verified or fails closed | Accepted (DevNet may load unsigned bundles even with signing keys configured) |
| TestNet | Refused (`UnsignedBundleNotAllowed`) | Verified or fails closed | Refused at the binary boundary (`main.rs` pre-check) |
| MainNet | Refused (`UnsignedBundleNotAllowed`) | Verified or fails closed | Refused at the binary boundary |

- `--p2p-trust-bundle-signing-key` without `--p2p-trust-bundle` is a
  documented warning-only no-op (does not fail closed). This is the
  only intentional non-fail-closed branch on the Run 051 surface.

### Static-root conflict / fallback policy

- DevNet bundle + CLI static roots: both allowed (Run 050 invariant,
  preserved); deduplicated by `root_key_id`.
- TestNet/MainNet bundle + CLI static roots: refused (Run 050
  invariant, preserved).
- On bundle-signature failure: never fall back to CLI static roots
  in any environment. Live FATAL output ends with
  `No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade)`.

### Metrics added/changed

| Metric | Type | Semantics |
| --- | --- | --- |
| `qbind_p2p_pqc_trust_bundle_signature_verified_total` | Counter | Incremented exactly once per process when an ML-DSA-44 signed trust bundle verified at startup. Stays at 0 for unsigned (DevNet) bundles and processes without `--p2p-trust-bundle`. |
| `qbind_p2p_pqc_trust_bundle_signature_rejected_total` | Counter | Incremented exactly once per signed-bundle envelope rejection (missing key, bad signature, malformed bytes, unsupported suite, suite mismatch). Note: the binary fails closed before `/metrics` is reachable on the rejected-at-startup path; the counter is also driven by tests, and is exposed so a future hot-reload of the bundle (out of scope for Run 051) can report rejected reloads. |
| `qbind_p2p_pqc_trust_bundle_signing_keys_configured` | Gauge | Number of `--p2p-trust-bundle-signing-key` entries successfully parsed at startup (0 when not supplied). |

No Run 050 metric was renamed or removed. The render path emits each
of the three new lines exactly once (verified by
`pqc_trust_bundle_signature_metrics_render_once_in_format_metrics`).

## Binary identity

- Branch: `copilot/continue-qbind-development-c396ead2-0dd3-487f-a138-9752ddd14029`
- Commit: `d9e76a80074bf58957e9d8576f1421f2fbc59c60` (clean working
  tree as of `release` build; subsequent doc commits are non-binary).
- Repo state at build: dirty for code changes; rebuilt cleanly under
  this state.
- `target/release/qbind-node` sha256: `5f081df0f97db1ceb99e5461a61af273fb12484fc2da2091f29fb88a77c89533`
- `target/release/qbind-node` ELF BuildID: `8206eade49aa80f0dcd22aa21dd52c4e8933e1c7`

## Helper identity

- `target/release/examples/devnet_pqc_trust_bundle_helper` sha256: `da2f476ded67f41d926f4af8a389bea8b53431b973c79e35aad61c3bdbda3ebf`
- `target/release/examples/devnet_pqc_trust_bundle_helper` ELF BuildID: `4c87d078d9f78bee7af5594abca4386541225cbc`
- `target/release/examples/devnet_pqc_root_helper` sha256 (unchanged surface; rebuilt under the same toolchain): `5fa74e76c4cf301a53088960b79db24dc8ca2ad39da303556cf4abf95d87095a`

## Positive DevNet signed-bundle smoke

`mode=signed-devnet` smoke (exit code 124 = `timeout 6` reached, i.e.
the binary stayed up healthily for the smoke window):

- Bundle log: `[binary] Run 050/051: trust bundle loaded path=/tmp/run051/signed-devnet/trust-bundle.json env=devnet fp=49d2800639f004b3de0ea13eaf6fb441faa0169725e15459557abc917d310908 active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=53453d8f..) signing_keys_configured=1. Bundle root IDs: [419e4269..]`
- Transport line: `[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=0`
- Suite registration: `[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true`
- Binary-consensus committed-anchor heights advanced 28→57 over the
  smoke window.
- `/metrics` (under signed bundle):

```text
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 0
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_trust_bundle_loaded 1
qbind_p2p_pqc_trust_bundle_environment 0
qbind_p2p_pqc_trust_bundle_active_roots 1
qbind_p2p_pqc_trust_bundle_revoked_roots 0
qbind_p2p_pqc_trust_bundle_sequence 1
qbind_p2p_pqc_trust_bundle_signature_verified_total 1
qbind_p2p_pqc_trust_bundle_signature_rejected_total 0
qbind_p2p_pqc_trust_bundle_signing_keys_configured 1
```

- No `DummySig`/`DummyKem`/`DummyAead` registered; no fallback to
  `--p2p-trusted-root`; no private-key bytes in any log
  (`signing_sk`/`root_sk` held in memory only by the helper, never
  written to disk).

## Positive TestNet signed-bundle smoke or exact boundary

`mode=signed-testnet` smoke (`--env testnet`, exit 124 — process
stayed up healthily for the smoke window):

- Bundle log: `[binary] Run 050/051: trust bundle loaded path=/tmp/run051/signed-testnet/trust-bundle.json env=testnet fp=81b21565ce896f5da6a3be3efdb046ee859afb90b46c6ba3ebb7213c327a57aa active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=560a2082..) signing_keys_configured=1. Bundle root IDs: [2b20c9cd..]`
- Same `pqc_root_mode=pqc-static-root` + `dummy_*=false` shape as
  the DevNet smoke.
- The TestNet smoke reaches the same `pqc-static-root` provider
  setup as DevNet; the bundle layer's environment binding, signature
  policy, and trust-separation invariants are honoured on a live
  release binary with `--env testnet`.

## Tampered-signature negative smoke

`mode=signed-tampered` (helper signs honestly, then mutates
`roots[0].not_after` post-signing):

- Exit: `1`.
- FATAL: `--p2p-trust-bundle load/validate failed for path=/tmp/run051/signed-tampered/trust-bundle.json: trust bundle ML-DSA-44 signature verification failed for signing_key_id b3398073127c02fa9401cc8ff0935f70d980ed3782fdb1f0ba2515e19fc5d778 (tampered bundle or forged envelope — fail closed). No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade).`
- No `--p2p-trusted-root` fallback; no `DummySig`/`DummyKem`/`DummyAead`
  fallback.

## Wrong-signing-key negative smoke

`mode=signed-wrong-key` (helper signs with key A, but publishes key
B's KEYID:SUITE:PK as the signing-key spec):

- Exit: `1`.
- FATAL: `--p2p-trust-bundle load/validate failed for path=/tmp/run051/signed-wrong-key/trust-bundle.json: trust bundle signature references signing_key_id f203bf76084c8d32675a7cfd67559e01a759bbc5c9cb447ceaf666cee5060015 but no matching --p2p-trust-bundle-signing-key was configured (fail closed). No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade).`

This is the `MissingSigningKey` path — the bundle was signed under
KEY A whose KEYID is not present in the operator's configured set
(only KEY B is published). Same fail-closed outcome as a malicious
signer; no fallback.

A second wrong-key variant (correct KEYID, wrong PK bytes) is
covered by the `wrong_signing_key_fails_closed` unit test and the
`wrong_signing_key_fails_closed` integration test; both produce
`TrustBundleError::BadSignature`, which would surface as the same
`trust bundle ML-DSA-44 signature verification failed for signing_key_id …`
FATAL message as the `signed-tampered` smoke.

## Unsigned TestNet/MainNet negative smokes

`mode=unsigned-testnet` (`--env testnet`, unsigned bundle, signing-key
supplied so the binary pre-check passes through to the loader):

- Exit: `1`.
- FATAL: `--p2p-trust-bundle load/validate failed for path=/tmp/run051/unsigned-testnet/trust-bundle.json: trust bundle is unsigned but environment testnet requires a signed bundle. … No fallback to --p2p-trusted-root on bundle failure (production-honest lifecycle must not silently downgrade).`

`mode=unsigned-mainnet` (`--env mainnet`, unsigned bundle, no
signing-key supplied — hits the binary pre-check):

- Exit: `1`.
- FATAL: `--p2p-trust-bundle /tmp/run051/unsigned-mainnet/trust-bundle.json on environment=MainNet requires at least one --p2p-trust-bundle-signing-key (TestNet/MainNet refuse unsigned bundles, and cannot verify a signed bundle without a configured signing key).`

Both paths fail closed; DevNet unsigned remains intentionally
preserved as the only environment that accepts unsigned bundles.

## Additional Run 051 negative smokes (extra coverage)

`mode=signed-unsupported-suite`:
- Exit: `1`.
- FATAL: `… trust bundle signature for signing_key_id 720ceede… uses unsupported suite_id 99 (only 100 = ML-DSA-44 accepted) …`

`mode=signed-malformed`:
- Exit: `1`.
- FATAL: `… trust bundle signature for signing_key_id 9a5f55d3… has malformed sig_bytes: expected 2420 bytes, got 1 …`

`mode=signed-key-root-collision`:
- Exit: `1`.
- FATAL: `… trust bundle signing_key_id fe4ef9b8… collides with a transport root_id (trust-separation policy fails closed) …`

## Optional two-binary smoke

Not attempted in Run 051. The same binary identity satisfies the
trust-bundle signed-verification layer's invariants regardless of
node count; the Run 037 / 039 / 040 / 042 / 049 evidence already
covers the multi-node `pqc-static-root` handshake on the byte-identical
`MlDsa44SignatureSuite` path. A two-binary signed-bundle smoke is a
candidate for a future "Run 051.1" optional run.

## Remaining open items

- Live MainNet signed-bundle real-binary smoke (`--env mainnet` with
  a production-grade signing key). Proven by unit + integration tests
  on the same `validate_at_with_signing_keys` codepath, but not by
  a live-binary smoke.
- Leaf-level certificate revocation enforcement (bundle-level
  `revocations[]` still only revokes whole roots; per-leaf-cert
  revocation is not implemented).
- Activation `epoch`/`height` gating (recorded but not enforced).
- Sequence-number monotonicity persistence across reboots (recorded
  but not persisted/cross-checked).
- `chain_id` crosscheck against the runtime chain id (recorded but
  not crosschecked).
- Production CA / certificate rotation / signing-key rotation
  operator playbook (the helper generates ephemeral DevNet
  bundle-signing keys in memory; production signing remains an
  out-of-process KMS task).
- Production fast-sync / consensus-storage restore (unchanged from
  prior runs).
- C5 closure (not touched by Run 051: no change to timeout/NewView
  wire formats, forged-traffic policy, KEMTLS wire formats, or
  consensus message wire formats).

## Exact immediate next action recommended

**Run 052: leaf-level certificate revocation enforcement.** Extend the
trust-bundle `revocations[]` shape with leaf-level entries
(`leaf_cert_fingerprint` is already in the schema but currently only
checked for whole-root revocation), wire `verify_delegation_cert` to
consult the bundle's leaf-fingerprint revocation set under
`pqc-static-root` mode, add `qbind_p2p_pqc_cert_verify_rejected_revoked_total`
to the existing per-reason counter family, prove a live-binary
fixture where a leaf certificate appearing on the revocation list
fails cert-verify with the `revoked` reason, and prove the Run 037 /
040 / 044 / 050 / 051 stack is unaffected. Keep the surface small:
do not introduce activation gating, sequence persistence, or
chain_id crosscheck in the same run.