# Candidate B trusted-review field controls

**AUTHOR-RUN, TEST-ONLY SYNTHETIC EVIDENCE. NOT OPERATIONAL
PROVISIONING, RUNTIME ENFORCEMENT, OR AUTHORITY.**

## Revisions and changed paths

| Item | Revision |
|---|---|
| Branch | `test/candidate-b-independence-refusal` |
| Expected prior branch head/tree | `598c33de069a24b6c4d1f8898e1ab09b13d16191` / `499785efffea9795ca7698b6c1207cb3ecf0b9bf` |
| Corrected test source commit/tree | `2fda30083118b0491537235aab2b09d333c71f4c` / `b76fcb4feb259a218ed4acadbf89d14032369f00` |
| Corrected test source parent | `598c33de069a24b6c4d1f8898e1ab09b13d16191` |
| Evidence commit/tree | Recorded by the commit that adds this document and the two output logs. |
| Reviewed specification commit/tree | `af55d73be9b3eb043a1997f7b0e6061121494fa7` / `f6e8c6a773b719c0c633f1ae4cd761792e87b835` |
| Main commit/tree | `aa382fa28b2d3e97e6203d47fa8231b5f2269741` / `f1a7d40993bfefbe18635bd637a100ad5527d875` |

Relative to the expected prior branch head, the source commit changes only
`crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs`. The
separate evidence commit adds only this document and the two newly named
output files below. Prior evidence documents and output logs were preserved
without rewriting them, including the prior note about the discarded
old-binary run.

## Controls added

The checker now starts each field case with the valid synthetic
`IndependenceEvidence::Trusted(review)` and alters exactly one modeled
trusted-review predicate at a time. The anchor, matching commitment,
association, expected domain and observations are unchanged and matching.
Each altered review is checked by the same `run_candidate_b_check`, with an
assertion for the particular result category, unavailable expected-anchor
authentication, unavailable dependent association results, and zero
association-verifier calls.

The independently altered fields and failure categories are:

| Trusted-review field | Expected failure |
|---|---|
| Trusted review authority | `Insufficient` |
| Authority separation | `Insufficient` |
| Credential separation | `Insufficient` |
| Administrator separation | `Insufficient` |
| Failure-domain separation | `Insufficient` |
| Common control under the fixture threat model | `Insufficient` |
| Continued applicability | `Inapplicable` |
| Commitment channel scope | `Inapplicable` |
| Anchor channel scope | `Inapplicable` |
| Recipient scope | `Inapplicable` |
| Deployment-binding scope | `Inapplicable` |

For each field, the same checker is run again with a narrow test-only bypass
of only that predicate. Each bypass makes the corresponding refusal
assertion fail by allowing the matching expected anchor and dependent
association verification to proceed. The existing whole-independence-gate
bypass remains exercised for the missing and preclassified-conflict cases.
The positive control remains and reports association currentness as
`Unresolved`.

The preclassified conflict case propagates the supplied
`IndependenceEvidence::Conflicting` classification. The checker does **not**
inspect or compare the two review contents and this test does not demonstrate
conflict detection. The earlier evidence note's description of two differing
review values is fixture data, not evidence that the checker discovered the
conflict; this clarification supersedes that interpretation only.

All keys, reviews, credentials, channels, scopes and observations in this
fixture are synthetic. These controls do not establish channel independence,
attestation validity, real provisioning, key custody, startup ordering or
runtime enforcement. They grant no authority.

## Author-run commands and outputs

Both Cargo commands used the isolated
`/tmp/candidate-b-trusted-review-controls-target` target directory and the
exact test-source revision listed above. Complete output files contain the
source commit/tree, exact command, compiler/test output and exit code:

| Command | Result | Retained output |
|---|---|---|
| `CARGO_TARGET_DIR=/tmp/candidate-b-trusted-review-controls-target cargo test -p qbind-node --test separate_bootstrap_anchor_synthetic_tests` | Exit 0; **11 passed, 0 failed, 0 ignored**. | [Focused output](candidate-b-trusted-review-controls-focused-output-20261108.txt) |
| `CARGO_TARGET_DIR=/tmp/candidate-b-trusted-review-controls-target cargo test -p qbind-node --test separate_bootstrap_anchor_synthetic_tests --no-run` | Exit 0; focused integration-test executable compiled. | [Compile-only output](candidate-b-trusted-review-controls-compile-output-20261108.txt) |
| `rustfmt --edition 2021 --check crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs` | Exit 0. | No output. |
| `git diff --check` | Exit 0. | No output. |

Existing compiler dead-code warnings were emitted. No production code,
manifests, lockfiles, dependencies, operational keys, live signer or node
were used; no startup, PR, merge or deployment was performed.

The focused and compile-only output files are committed separately from the
tested source. Before publishing this evidence, verify that the source file
and all build inputs still have the same object IDs as at the source commit.
The previous evidence logs and note, including the discarded old-binary-run
disclosure, remain historical and unmodified.

## Pinned references and status

* Reviewed Candidate B specification:
  [`af55d73be9b3eb043a1997f7b0e6061121494fa7`](https://github.com/olivexo28/QBIND/blob/af55d73be9b3eb043a1997f7b0e6061121494fa7/docs/security/evidence/a33-f1-candidate-b-anchor-commitment-spec-20261108.md)
* Earlier synthetic fixture evidence:
  [`598c33de069a24b6c4d1f8898e1ab09b13d16191`](https://github.com/olivexo28/QBIND/tree/598c33de069a24b6c4d1f8898e1ab09b13d16191/docs/security/evidence)

CB-1 remains CLOSED within its documentation scope. A23-F1 and A33-F1 / E27
remain OPEN; activation remains DISABLED; public DevNet remains NO-GO.
