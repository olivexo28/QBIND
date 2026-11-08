# Candidate B independence-refusal synthetic fixture evidence

**TEST-ONLY SYNTHETIC EVIDENCE. NOT OPERATIONAL PROVISIONING, RUNTIME
ENFORCEMENT, OR AUTHORITY.**

## Revisions and scope

The test branch was created from the verified reviewed specification:

| Item | Revision |
|---|---|
| Reviewed spec branch | `docs/candidate-b-anchor-commitment` |
| Reviewed spec commit/tree | `af55d73be9b3eb043a1997f7b0e6061121494fa7` / `f6e8c6a773b719c0c633f1ae4cd761792e87b835` |
| Expected main commit | `aa382fa28b2d3e97e6203d47fa8231b5f2269741` |
| Test branch | `test/candidate-b-independence-refusal` |
| Test source commit/tree | `e612f47c14d79472e4823a83443697c4cfc90f9e` / `0ed57a91971beee8df8d4968f0c2fedb55b4a266` |
| Test source parent | `af55d73be9b3eb043a1997f7b0e6061121494fa7` |
| Test-source changed path relative to reviewed specification | `crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs` |

Relative to the reviewed specification, the test-source commit changes only
the test file above. The later evidence commit adds only this evidence note
and its two retained command-output files. The reviewed assessment and
Candidate B specification inherited from the parent branch remain unchanged.
No production source, test manifests, workspace manifests, lockfile,
dependencies, or historical evidence were changed.

The source revision/tree above produced the focused test and compile-only
outputs below. The test source and build inputs were committed before the
runs. Evidence is committed separately; its commit must be checked to ensure
the test/build input paths still match this producing revision.

## Fixture and result model

Two tests extend the existing isolated synthetic bootstrap-anchor integration
suite (nine inherited tests plus these two, eleven total). Synthetic anchor,
expected commitment, signed association, identity observations, expected
domain, verifier policy and deployment scope remain fixed while the
independence-review evidence varies.

The fixed synthetic commitment comparison covers the full generated public
key bytes, its suite, association purpose and deployment binding. It is a
test fixture value, not a selected production digest or commitment format.
The separately supplied synthetic review input models a trusted review
authority, continued applicability, distinct commitment/anchor channel
identities, verifier recipient, deployment scope, authority/credential/
administrator/failure-domain separation, and no common control under the
fixture threat model. These fixed trust labels model assumptions only.

The positive control asserts a raw match only as diagnostic information,
expected-anchor authentication, verified association authenticity, tuple
equality, and `Currentness::Unresolved`. Independence-review applicability
is a different fixture input from association currentness; the test does not
give the evaluator knowledge that the association is current.

The same `run_candidate_b_check` checker receives identical anchor,
commitment, association, observations, domain and policy in each negative
case, varying only independence evidence:

| Case | Synthetic evidence variation | Expected result |
|---|---|---|
| Missing | No review attestation. | Expected anchor and dependent association authenticity/equality unavailable; raw match diagnostic only. |
| Conflicting | Two otherwise trusted reviews disagree on the anchor-channel scope. | Same refusal/unavailable results. |
| Insufficient | Review lacks administrator separation and records common control under the stated threat model. | Same refusal/unavailable results. |
| Inapplicable | Review says it no longer remains applicable. | Same refusal/unavailable results. |

For each case, the test also calls that same checker with a test-only
`bypass_independence_gate` mutant. It holds every other fixture input fixed.
The bypass yields an authenticated expected anchor and verified/equal
dependent association result, so the exact negative assertion expecting
unavailability fails. The positive control prevents a reject-everything
checker from passing. The association verifier call counter remains zero on
each correctly refused case.

No authority-bearing callback, live signer, operational key, startup hook,
node, or production verifier is used. The existing suite's ML-DSA-44
implementation creates disposable synthetic test keys; this fixture detail
does not select an operational algorithm.

## Commands and retained outputs

Both Cargo commands ran against source commit
`e612f47c14d79472e4823a83443697c4cfc90f9e`, tree
`0ed57a91971beee8df8d4968f0c2fedb55b4a266`, using a fresh isolated Cargo
target directory so no binary from another worktree was reused:

| Command | Result | Complete output |
|---|---|---|
| `CARGO_TARGET_DIR=/tmp/candidate-b-independence-refusal-target cargo test -p qbind-node --test separate_bootstrap_anchor_synthetic_tests` | Exit 0; **11 passed, 0 failed, 0 ignored**. | [Focused test output](candidate-b-independence-refusal-focused-output-20261108.txt) |
| `CARGO_TARGET_DIR=/tmp/candidate-b-independence-refusal-target cargo test -p qbind-node --test separate_bootstrap_anchor_synthetic_tests --no-run` | Exit 0; focused integration-test executable compiled. | [Compile-only output](candidate-b-independence-refusal-compile-output-20261108.txt) |
| `rustfmt --edition 2021 --check crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs` | Exit 0. | No output. |
| `git diff --check` | Exit 0. | No output. |

The retained Cargo outputs include the exact source commit/tree, command,
full compiler/test output and exit code. Existing compiler dead-code warnings
were emitted; no test failed.

An initial run using another worktree's shared build cache executed its
pre-existing nine-test binary, so it was not treated as validation and its
misattributed output was discarded. The reported eleven-test result comes
only from the fresh isolated target directory above.

## Limitations

This synthetic fixture demonstrates only its checker model and its
same-checker bypass sensitivity. It does not establish real commitment or
anchor channel independence, authority identity, credential/admin separation,
provider or recovery independence, real provisioning, key custody,
authenticated review evidence, attestation currentness, replacement,
revocation, currentness/anti-rollback, signer exclusivity, signing-history
completeness, durable intent, fencing, recovery, startup ordering, runtime
protection, or host integrity. A software flag or fixture trust field is not
evidence of real-world independence. The tests add no permission result and
do not authorize any operation.

The earlier merged synthetic evidence and its coverage correction remain
historical, separately scoped evidence; neither is modified or superseded by
these results. A23-F1 and A33-F1 / E27 remain OPEN; activation remains
DISABLED; public DevNet remains NO-GO.

## Pinned references

* Reviewed Candidate B specification:
  [`af55d73be9b3eb043a1997f7b0e6061121494fa7`](https://github.com/olivexo28/QBIND/blob/af55d73be9b3eb043a1997f7b0e6061121494fa7/docs/security/evidence/a33-f1-candidate-b-anchor-commitment-spec-20261108.md)
* Reviewed delivery/lifecycle assessment:
  [`12fbfbe77609afc659f55ee1fb41fd066cf00910`](https://github.com/olivexo28/QBIND/blob/12fbfbe77609afc659f55ee1fb41fd066cf00910/docs/security/evidence/a33-f1-bootstrap-anchor-delivery-lifecycle-assessment-20261108.md)
* Merged separate-anchor specification and historical evidence are pinned in
  the reviewed Candidate B specification; their earlier scopes are preserved.
