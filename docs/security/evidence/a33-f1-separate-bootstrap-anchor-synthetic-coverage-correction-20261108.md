# Synthetic Bootstrap-Anchor Coverage Correction Evidence

Status: isolated synthetic test-model correction only; no production wiring or
authority.

## Tested source and branch

- Branch: `test/separate-bootstrap-anchor-synthetic`
- Source commit: `b841fa4e8fb5718b5f74d60363d7d1ad8e50cea5`
- Source tree: `398f4b8648748e7769482ed94d98f4374e089653`
- Parent: `28e1dc0ccd68c94691ecc85e9a62079203122735`
- Parent tree: `5eb4dae0f356b969d5513de641fd0c2ca5c18810`
- Reviewed specification ancestor: `15bd45ce8e42fb71c4bb98a550eb2c5d6f14e1cc`
- Source changed path: `crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs`
- No production source, dependency, manifest, or lockfile changed.

## Coverage corrections

The checker now receives a fixed `ExpectedDomain` independently of the signed
association and observation. It binds environment `Devnet`, numeric chain ID
`0xD301`, genesis identity `[0x31; 32]`, and destination
`synthetic-destination-A`; the fixed expected anchor and deployment label
remain independent inputs. For each domain field, the authorized synthetic
bootstrap key signs a foreign tuple, observations match that tuple, and the
same pipeline refuses with the specific field mismatch. A matching positive
pipeline result remains covered, and bypassing that field's domain guard makes
the foreign tuple pass the pipeline's non-authorizing
`Verified`/`Equal`/`Unresolved` result, proving sensitivity.

Missing anchor, missing association, and missing signature now have distinct
acquisition refusals. Each has an explicit assertion that the verifier was not
called. Existing missing and unavailable observation controls remain. The
valid synthetic positive remains `Verified`, `Equal`, and `Unresolved`.

The earlier evidence phrase “wrong-suite signing key” was inaccurate: that
scenario changes association suite metadata while signing with a non-anchor
key that still uses the ML-DSA-44 primitive. An actually incompatible-suite
signing key was not tested. This test remains synthetic and does not choose
production domain semantics, provisioning, a signature suite, currentness
mechanism, or any authority.

## Commands and results

Commands were run against source commit
`b841fa4e8fb5718b5f74d60363d7d1ad8e50cea5`, tree
`398f4b8648748e7769482ed94d98f4374e089653`.

Focused suite (exit 0; 9 passed, 0 failed):

```sh
set -o pipefail; cargo test -p qbind-node --test separate_bootstrap_anchor_synthetic_tests 2>&1 | tee docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-focused-output-20261108.txt; status=$?; printf 'command_exit_code=%s\n' "$status" | tee -a docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-focused-output-20261108.txt; exit "$status"
```

Complete output: [focused test log](a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-focused-output-20261108.txt).

Compile-only check (exit 0):

```sh
set -o pipefail; cargo test -p qbind-node --test separate_bootstrap_anchor_synthetic_tests --no-run 2>&1 | tee docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-compile-output-20261108.txt; status=$?; printf 'command_exit_code=%s\n' "$status" | tee -a docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-compile-output-20261108.txt; exit "$status"
```

Complete output: [compile-only log](a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-compile-output-20261108.txt).

Formatting check: `rustfmt --check crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs` (exit 0; no output).

The previously retained focused and compile-only output files were not edited.
Their SHA-256 values before this correction were respectively
`8634610ee02df1c0edcdf12485226c7b98330820185bceaad64b1a9b303d2b11` and
`2c33825bb133b9ecd69039c54d35c8ba354d165fb82b1f3d281b745034a05460`.

## Scope and limits

Relative to parent commit `28e1dc0ccd68c94691ecc85e9a62079203122735`, the
source commit changes only the test file. Relative to main
`810a6759ef1e3ddb42c9a0f09f78502dc4655276`, this branch also contains its
inherited reviewed specification, identity-comparison test, and prior
evidence. The new correction does not establish production provisioning,
currentness, startup enforcement, signer exclusivity, durable intent,
recovery, or restart safety. A23-F1 and A33-F1 / E27 remain OPEN; activation
remains DISABLED; public DevNet remains NO-GO.
