# QBIND DevNet Evidence — Run 389

Public DevNet **security operator** evidence for the M7/M8/M9 key-management and PQC trust-root
bootstrap documentation blockers. Run 389 publishes a consolidated, operator-facing **security**
package (`docs/release/public-devnet/security/` — `README.md`, `KEY_MANAGEMENT.md`,
`PQC_TRUST_BOOTSTRAP.md`, `PQC_ROOT_AND_SIGNING_KEYS.md`, `SAFETY.md`, `VERIFY.md`) and verifies it
against the **real** `qbind-node` CLI/help surfaces and the existing DevNet
`devnet_pqc_trust_bundle_helper` example, via the harness
`scripts/devnet/run_389_public_devnet_security_key_trust_bootstrap.sh` (`RESULT=POSITIVE`).

**Decision gate = Route B** (docs + a docs/verification harness; **no** production Rust source change,
**no** new CLI flag). Every flag documented is a **pre-existing** surface validated to appear in
`qbind-node --help`.

**Safety label:** DevNet · experimental · resettable · no value · NOT public-DevNet launch-ready · no
M4 Green · no M6 fully-Green · no TestNet readiness · no MainNet readiness · **C4/C5 OPEN**. This
evidence does not imply launch, TestNet, MainNet, C4, or C5 readiness. Run 389 opens no externally
reachable port, deploys no seed/bootnode/faucet/RPC/explorer/status page, changes no P2P wire format,
weakens no peer admission (the `identity` command and `--p2p-trust-bundle-reload-check` are read-only /
validation-only), enables no peer-driven apply, and mutates no
trust/validator/epoch/sequence/marker/LivePqcTrustState.

## 1. Exact verdict

**PASS / public-DevNet security key/trust bootstrap guidance POSITIVE.** M7, M8, and M9 documentation
is published and verified against real CLI/helper surfaces with no overclaim. All three move
**Yellow → Green (Green-for-scope, DevNet operator documentation)**. M4 stays Yellow/launch-blocking,
M6 stays Yellow/Partial, M12/M13/M14 remain Green, public DevNet remains **NOT launch-ready**, and
**C4/C5 remain OPEN**.

## 2. Files changed

No production Rust source or `build.rs` change (docs + harness/archive only).

New:

- `docs/release/public-devnet/security/README.md`
- `docs/release/public-devnet/security/KEY_MANAGEMENT.md`
- `docs/release/public-devnet/security/PQC_TRUST_BOOTSTRAP.md`
- `docs/release/public-devnet/security/PQC_ROOT_AND_SIGNING_KEYS.md`
- `docs/release/public-devnet/security/SAFETY.md`
- `docs/release/public-devnet/security/VERIFY.md`
- `scripts/devnet/run_389_public_devnet_security_key_trust_bootstrap.sh`
- `docs/devnet/run_389_public_devnet_security_key_trust_bootstrap/README.md`
- `docs/devnet/run_389_public_devnet_security_key_trust_bootstrap/summary.txt`
- `docs/devnet/run_389_public_devnet_security_key_trust_bootstrap/.gitignore`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_389.md` (this record)

Narrowly updated (cross-links + M7/M8/M9 delta only):

- `docs/release/public-devnet/operator/README.md`
- `docs/release/public-devnet/operator/QUICKSTART.md`
- `docs/release/public-devnet/operator/IDENTITY.md`
- `docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

## 3. Decision gate route

**Route B** — existing CLI/helper surfaces are sufficient; publish docs plus a small docs/verification
harness that validates the documented commands and generated example shapes. No production source
change was required.

## 4. Security package contents

`docs/release/public-devnet/security/`: `README.md` (index/scope/cross-links/readiness),
`KEY_MANAGEMENT.md` (M7), `PQC_TRUST_BOOTSTRAP.md` (M8), `PQC_ROOT_AND_SIGNING_KEYS.md` (M9),
`SAFETY.md` (DevNet-only safety label + public/private rules), and `VERIFY.md` (copy-paste operator
checks). Every file carries the experimental/resettable/no-value/no-C4-C5-closure safety header.

## 5. Key-management guidance (M7)

`KEY_MANAGEMENT.md` covers: DevNet-only label; the full key inventory (node/KEMTLS leaf key; transport
trust root; consensus/block signer key; trust-bundle signing key; operator identity JSON) with
public-vs-private marking; local signer modes using existing CLI only (`--signer-mode`
loopback-testing / encrypted-fs / remote-signer / hsm-pkcs11 with `--signer-keystore-path` /
`--remote-signer-url` / `--hsm-config-path`); remote-signer/HSM/KMS posture with an honest
"posture/integration surface, not production custody" note; file-permission requirements (private key
`0600`, keystore `0700`); rotation/revocation status (DevNet operational only; no MainNet custody;
C4/C5 OPEN); backup guidance (what to back up, what never to commit, how to recover lost DevNet keys by
regeneration); and an explicit refusal of value-bearing/MainNet custody claims.

## 6. Trust-bundle bootstrap guidance (M8)

`PQC_TRUST_BOOTSTRAP.md` covers: the DevNet trust-bundle bootstrap flow; genesis-hash pinning
(`--expect-genesis-hash 0x48b3a862…145f`); the separation of transport roots (`--p2p-trusted-root`)
from bundle-signing keys (`--p2p-trust-bundle-signing-key`); `--p2p-trust-bundle` loading and its
strict validation (env binding, validity windows, root status, revocation list, suite `100`,
signature); signed-bundle verification-key usage; `--p2p-trusted-root` / static-root posture and DevNet
limitations (DummySig + unsigned bundles are DevNet-only conveniences); reload-check (validation-only)
vs the hidden/advanced reload-apply/SIGHUP mutating surfaces (out of scope for DevNet bootstrap);
peer-candidate validation/propagation is advisory/non-mutating; **no** peer-driven live apply; **no**
fallback roots or hidden default anchors; and MainNet/TestNet stricter policy with no DevNet shortcut
leakage.

## 7. PQC root/signing-key guidance (M9)

`PQC_ROOT_AND_SIGNING_KEYS.md` covers: generating DevNet root/leaf material with the first-class
`qbind-node identity` command and the `devnet_pqc_trust_bundle_helper` / `devnet_pqc_root_helper`
examples; which generated files are public (`public-identity.json`, `leaf.cert.bin`, `root.id.hex`,
`root.pk.hex`, `trusted-root.spec`, `signing-key.{id,pk}.hex`, `signing-key.spec`, `trust-bundle.json`)
vs private (`*.kem.sk.bin` `0600`; root + bundle signing secrets held in memory only, never on disk);
NodeId derivation (`sha3_256("QBIND:nodeid:v1" || leaf_kem_pk)`) and `identity verify` re-derivation;
pinning a trusted root for strict KEMTLS; verifying a trust-bundle signature via reload-check; a
wrong-chain/wrong-env/wrong-genesis detection table backed by the helper's negative fixtures; what is
**not** production custody; and what remains C4/C5-open.

## 8. Public/private material rules

Public: validator/node addresses, node/peer ids, fingerprints, root **public** keys/ids,
bundle-signing **verification** keys, leaf certs, trust-bundle document, and the whole
`public-identity.json` (records private-file **paths** only, never contents). Private (never publish or
commit): `*.kem.sk.bin` (`0600`), the transport root ML-DSA-44 signing key (in memory only), the
trust-bundle ML-DSA-44 signing secret (in memory only), validator consensus signing keys, keystore
contents/passwords, HSM secrets, mnemonics, seed phrases, credentials, tokens, and private
endpoints/hostnames. Harness check `public_identity_no_private=OK` confirms no secret-key bytes appear
in the public JSON.

## 9. CLI/help verification

`qbind-node --help` was captured and all 13 documented flags are present with **no** invented flag:
`--signer-mode`, `--signer-keystore-path`, `--remote-signer-url`, `--hsm-config-path`,
`--p2p-trust-bundle`, `--p2p-trust-bundle-signing-key`, `--p2p-trusted-root`, `--p2p-pqc-root-mode`,
`--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-peer-leaf-cert`, `--p2p-mutual-auth`,
`--expect-genesis-hash` (`help_documented_flags=OK`). `qbind-node identity --help` surfaces
generate/verify/print-public/seed-candidate/register-check (`identity_help=OK`). The
`--p2p-trust-bundle-reload-check` / `--p2p-trust-bundle-reload-apply-*` flags are intentionally
`hide = true` (advanced/long-running-node) and are documented as such rather than claimed to appear in
`--help`.

## 10. Identity generation / verification evidence

`qbind-node identity generate devnet full-node` produced a real public identity
(`identity_generate=OK`, e.g. `node_id=5ddbab2f…1849`), the leaf KEM secret key is mode `0600`, and no
root signing key is written to disk. `qbind-node identity verify <leaf.cert.bin>` deterministically
re-derives the same NodeId (`identity_verify=OK`).

## 11. Trust-bundle helper / bootstrap evidence

`devnet_pqc_trust_bundle_helper <out> 1 signed-devnet` mints a valid signed DevNet bundle;
`root.*`/`signing-key.*` files are emitted, the bundle-signing **secret** is never written to disk, and
`v0.kem.sk.bin` is `0600` (`trust_bundle_mint=OK`). `qbind-node --env devnet
--p2p-trust-bundle-reload-check <bundle> --p2p-trust-bundle-signing-key <spec> --p2p-leaf-cert …
--p2p-leaf-cert-key …` reports `signature_verified=true`, `VERDICT=valid`, and "no live trust apply"
(`trust_bundle_reload_check_valid=OK`).

## 12. Rejection / fail-closed evidence

- `signed-tampered` bundle → reload-check `VERDICT=invalid` (signature verification failed);
  `trust_bundle_reload_check_tampered=REFUSED`.
- `qbind-node identity generate mainnet …` and `… testnet …` both refused, no material written
  (`mainnet_testnet_generation=REFUSED`).
- Documented (from the helper's fixtures and the loader) fail-closed cases: wrong-environment,
  expired/not-yet-valid root, revoked root/leaf, unsupported suite, wrong signing key, malformed
  bundle, and genesis-hash mismatch (`--expect-genesis-hash`).

## 13. Default compatibility

No default behaviour change. `identity` and `--p2p-trust-bundle-reload-check` are opt-in, read-only /
validation-only paths. `--p2p-mutual-auth` still defaults to `disabled`; strict admission
(`required` + `pqc-static-root`) only **tightens** admission. No metrics/endpoint change; no data
written outside the operator's temp dir.

## 14. CLI surface

No CLI flag added, renamed, hidden, or unhidden. All documented flags pre-exist in
`crates/qbind-node/src/cli.rs` / `identity_cli.rs`.

## 15. Runtime mutation check

No runtime mutation. Harness `committed_private_material=NONE`; no socket opened for admission; no
trust/validator/epoch/sequence/marker/LivePqcTrustState change; reload-check is validation-only.

## 16. Readiness delta M7

**Yellow → Green (Green-for-scope).** Consolidated operator-facing key-management guidance
(`KEY_MANAGEMENT.md`) is published and verified against the real `--signer-mode` local/remote/HSM
surfaces and the `0600` private-key permission requirement. No MainNet custody is claimed.

## 17. Readiness delta M8

**Yellow → Green (Green-for-scope).** DevNet PQC trust-bundle bootstrap procedure
(`PQC_TRUST_BOOTSTRAP.md`) is published and verified against the real `--p2p-trust-bundle` /
`--p2p-trust-bundle-signing-key` loader via `--p2p-trust-bundle-reload-check`
(`signature_verified=true`, tampered fails closed). No live trust apply; no peer-driven apply.

## 18. Readiness delta M9

**Yellow → Green (Green-for-scope).** DevNet PQC root/signing-key guidance
(`PQC_ROOT_AND_SIGNING_KEYS.md`) is published and verified against the real root/leaf/signing-key
helpers and `--p2p-trusted-root` / `identity verify` derivation, with public-vs-private file rules and
wrong-chain/env/genesis detection.

## 19. Public DevNet status

**NOT launch-ready.** At least one must-have (M4) is not Green.

## 20. Remaining DevNet blockers

M4 (external seed reachability — Yellow), M6 (live registration path — Yellow/Partial), and the
should/other must-haves M15 (reset policy) / M16 (incident response) not yet Green.

## 21. TestNet blockers

TestNet readiness is untouched and unclaimed; the stricter TestNet trust/signer policy (signed bundles
required, no DummySig, no loopback-testing signer, ratification gates) is unchanged.

## 22. MainNet blockers

MainNet readiness is untouched and unclaimed; MainNet custody and MainNet authority rotation/revocation
remain **Red**.

## 23. C4/C5

**C4 remains OPEN** (operator-supplied root reuse/rotation/revocation as a full production CA
lifecycle). **C5 remains OPEN** (governance-executed authority lifecycle runtime wiring). No closure
claimed.

## 24. Tests run

- `scripts/devnet/run_389_public_devnet_security_key_trust_bootstrap.sh` → `RESULT=POSITIVE`.
- `cargo build -p qbind-node --release --locked --bin qbind-node` → OK (SHA-256
  `6c43154415b630645217bbdb618f80dfb719b24d58799c3dcfd3df505b0a6ccd`, BuildID
  `c61071905d4f3497b5ee845a12ecd434bac642f5`, toolchain `rustc 1.98.0` / `cargo 1.98.0`).
- `cargo build -p qbind-node --release --example devnet_pqc_trust_bundle_helper` → OK.
- `cargo test -p qbind-node --test run_375_public_devnet_identity_cli_tests` → 13 passed.
- `cargo test -p qbind-node --test run_376_public_devnet_identity_registration_tests` → 14 passed.
- `cargo test -p qbind-node --lib`: **not run — no Rust source change (docs/harness only)**; baseline
  unchanged, honestly recorded (no Rust delta).
- Non-claim grep over `docs/release/public-devnet/security/` → clean (`non_claim_grep=OK`).

## 25. Security scans

Secret scanning was run over all changed files; no private key, root/bundle signing secret, KEM
secret, mnemonic, seed phrase, credential, token, raw log, raw metrics dump, data dir, private
endpoint, private hostname, absolute build path, or branch dirty-state string is committed. The
archive `.gitignore` and the repository `.gitignore` (`*.kem.sk.bin`, `*.cert.bin`) backstop the
temporary `material/` output, which is removed on exit (`committed_private_material=NONE`).

## 26. CodeQL

Docs + harness only, **no** production Rust or `build.rs` change → CodeQL is **trivial / not
meaningful** for this change (recorded honestly, not claimed clean-by-analysis).

## 27. Provenance

Branch `copilot/run-389-task`; base commit `a8bc2ad9a6f9795614747ddbe6c1d4ba9e1d8b4b`. Release binary
SHA-256 `6c43154415b630645217bbdb618f80dfb719b24d58799c3dcfd3df505b0a6ccd`, ELF BuildID
`c61071905d4f3497b5ee845a12ecd434bac642f5`, toolchain `rustc 1.98.0 (88d9e12ae 2026-08-18)` /
`cargo 1.98.0 (797e8a9bc 2026-08-05)`. Harness summary archived at
`docs/devnet/run_389_public_devnet_security_key_trust_bootstrap/summary.txt`. Generated identity/bundle
material is temporary and not committed; the recorded `node_id` is intentionally public.

## 28. Honest limitations

- M7/M8/M9 move Green **for the operator-documentation scope only** — the guidance is verified against
  real CLI/helper surfaces, but this does not deploy production custody, a KMS/HSM backend, or a live
  trust-apply flow.
- Remote-signer/HSM/KMS are documented as **posture/integration surfaces**, not proven end-to-end
  production custody.
- The `--p2p-trust-bundle-reload-apply-*` / SIGHUP mutating surfaces are documented but intentionally
  **not exercised** (out of scope; would mutate live trust state).
- M4 (external reachability) and M6 (live registration) are unaffected; C4/C5 stay OPEN; TestNet/MainNet
  are untouched. Public DevNet remains NOT launch-ready.

## 29. Suggested Run 390

Publish the remaining public DevNet operator must-haves **M15** (DevNet reset policy — when/how state
is wiped) and **M16** (incident-response process), as a docs + verification run in the same
`docs/release/public-devnet/` tree, keeping M4/M6 Yellow and C4/C5 OPEN.
