# Separate Bootstrap-Anchor Synthetic Test Evidence

Status: synthetic test-only evidence; no production implementation or authority.

## Tested source

- Branch: `test/separate-bootstrap-anchor-synthetic`
- Source commit: `3cf05468bd753d279433904eeaa0cbdc73550706`
- Source tree: `33157f8936410775657d85932498231fa5414a87`
- Parent: `091f3a3436f3b4d28d12a7e091f2192be4ba9b9b`
- Reviewed specification parent: `15bd45ce8e42fb71c4bb98a550eb2c5d6f14e1cc`
- Source changed path: `crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs`
- No production source, dependency manifest, or lockfile changed.

## Fixtures and controls

The test generates disposable bootstrap ML-DSA-44 keypairs with the existing
`qbind_crypto` implementation. The independently established expected anchor,
its provenance flag, deployment binding (`synthetic-initial-devnet-A`), and
permitted association suite (`100`) are constructed before the signed
association and are not read from it. The fixture uses synthetic purpose
`qbind.synthetic.validator-association`, version `1`, and a separate validator
suite (`700`) and 64-byte public-key placeholder; there is no validator private
key, live signer, operational key, startup hook, or authority-bearing callback.
The synthetic identity also includes environment `Devnet`, chain ID `0xD301`,
32-byte genesis identity, destination `synthetic-destination-A`, and validator
ID `41`.

Seven tests cover positive verification/comparison, acquisition failures
(missing, unreadable, malformed, truncated, ambiguous, unsupported schema)
without verifier invocation, anchor provenance/substitution, deployment and
anchor-suite binding, invalid signature, purpose/version/suite policy, signed
suite-metadata binding, each of the seven identity fields, per-field shared
signing/verification encoding omission, separate comparison sensitivity, and
valid/equal input with currentness unresolved. The scenario previously
mislabeled “wrong-suite signing key” changes association suite metadata while
signing with a non-anchor key that still uses ML-DSA-44; an incompatible-suite
key case was not tested. Each checked result is limited to authentication,
equality, refusal, or unresolved currentness and conveys no permission or
startup authority. This earlier seven-test evidence is supplemented by the
coverage-correction evidence in
`a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-20261108.md`.

## Commands and retained output

Commands were run at source commit
`3cf05468bd753d279433904eeaa0cbdc73550706`, tree
`33157f8936410775657d85932498231fa5414a87`.

Focused suite (exit 0; 7 passed, 0 failed):

```sh
set -o pipefail; cargo test -p qbind-node --test separate_bootstrap_anchor_synthetic_tests 2>&1 | tee docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-focused-output-20261108.txt; status=$?; printf 'command_exit_code=%s\n' "$status" | tee -a docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-focused-output-20261108.txt; exit "$status"
```

Complete output: [focused test log](a33-f1-separate-bootstrap-anchor-synthetic-focused-output-20261108.txt).

Compile-only check (exit 0):

```sh
set -o pipefail; cargo test -p qbind-node --test separate_bootstrap_anchor_synthetic_tests --no-run 2>&1 | tee docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-compile-output-20261108.txt; status=$?; printf 'command_exit_code=%s\n' "$status" | tee -a docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-compile-output-20261108.txt; exit "$status"
```

Complete output: [compile-only log](a33-f1-separate-bootstrap-anchor-synthetic-compile-output-20261108.txt).

Formatting check: `rustfmt --check crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs` (exit 0; terminal output was empty).

Focused result: 7 passed, 0 failed, 0 ignored. The outputs retain the compiler
warnings emitted by the existing workspace code.

## Limits

This synthetic harness does not establish real bootstrap-anchor provisioning,
trust-root integrity, a production signature suite or encoding, currentness,
signing-history completeness, signer exclusivity, durable intent, startup
ordering, recovery, or restart safety. It does not authorize deployment or
signing. A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED and
public DevNet remains NO-GO.
