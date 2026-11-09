# QBIND — Synthetic initialization-refusal checker correction evidence

**SYNTHETIC TEST-ONLY MODEL — NOT ADAPTER ENFORCEMENT.** This correction
adds no production observation seam and does not call the real execution
adapter or storage APIs. The same checker receives bounded synthetic
event histories with initialization and worker identities, a declared
history-completeness flag, and ordered event sequence numbers.

The previously accepted synthetic cases remain covered. This correction
adds and exercises mixed work-violation/unresolved-worker reporting,
worker-to-initialization association, event-order checks, and distinctions
between rejected and admitted/executed work. The initial focused run
exposed two failing assertions; those results are retained below rather
than rewritten. The corrected focused run passes all 17 discovered tests.

The prior path-encoding branch remains not integration-ready; its retained
four contract failures are unchanged. The corrected consensus
result-category oracle remains CLOSED within its test scope. The
no-replacement-database finding, CB-1, and CB-FIXTURE-1 remain within
their accepted scopes. A23-F1 and A33-F1 / E27 remain OPEN; activation
remains DISABLED; public DevNet remains NO-GO.

## Pinned revisions and changed source

| Item | Identity |
|---|---|
| Reviewed base branch | `test/candidate-b-synthetic-initialization-refusal` |
| Reviewed endpoint | `784da9cef7bc1f0a985408747303412c259c943e`, tree `ce5a3eae24178e33cce0255610a0824211558f1f` |
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| First correction commit, compiled and initially run | `117f85a1476fe3fda8160fef0207575e6abe9b62`, tree `b2b9f8b739ecb86bb361be7cf254ab6be2d485f9`, parent `784da9cef7bc1f0a985408747303412c259c943e` |
| First-run test source blob | `crates/qbind-node/tests/candidate_b_synthetic_initialization_refusal_tests.rs`: `57577968cc9f7ef1558f1b578411f74ff8bb487d` |
| Corrected source commit, compiled and finally run | `19eeeae35d3522a5fe158174cf9b9660f3be5d44`, tree `298511541f15bfca93b40743091b26ba822201a6`, parent `117f85a1476fe3fda8160fef0207575e6abe9b62` |
| Final test source blob | `crates/qbind-node/tests/candidate_b_synthetic_initialization_refusal_tests.rs`: `a5d5fe7ddb6b94648c3769a0da58a50e2b4a4b4e` |
| Reviewed model evidence preserved unchanged | `docs/security/evidence/candidate-b-synthetic-initialization-refusal-20261109.md` at `784da9cef7bc1f0a985408747303412c259c943e` |
| Reviewed initialization specification | `docs/security/evidence/candidate-b-required-persistence-initialization-spec-20261109.md` at `c2b86892fb2235a593cdea9d829a7cf861345d08` |

## Checker semantics and corrected controls

The checker returns a contract classification separately from a worker
termination classification. For a requested-persistent refusal, it
requires a same-initialization failed-open event preceding an identifiable
persistent-open refusal, a complete supplied history, no publication,
and no admitted or executed work. A worker started for that initialization
must have a matching later termination event; otherwise refusal remains
inconclusive. An attempt with a matching explicit rejection is distinct
from admitted or executed work. An attempted work item with no observed
outcome remains unresolved. A known work violation is retained as a
`ContractViolation` even when worker termination is independently
`Unresolved`.

The tests exercise:

| Control | Result | Meaning within the model |
|---|---|---|
| Matching successful open before same-instance persistent publication | Passed | A same-instance earlier open is required for persistent availability. |
| Matching failed open followed by refusal without worker or submission | Passed | An early refusal does not require submission. |
| Explicit in-memory selection | Passed | Explicit memory remains a separate positive case. |
| Failed open followed by in-memory publication | Passed sensitivity | Unintended fallback is rejected. |
| Publication before successful open | Passed sensitivity | Premature publication is rejected. |
| Open evidence from another initialization | Passed sensitivity | Unrelated open cannot authorize publication or refusal. |
| Refusal before matching failed-open evidence | Passed sensitivity | Refusal ordering is checked. |
| Publication followed by refusal | Passed sensitivity | Publication/refusal conflict is rejected. |
| Matching failed-open/refusal plus admitted work and unresolved worker | Passed sensitivity | The work violation remains visible; termination remains unresolved. |
| Explicitly rejected attempted work versus admitted/executed work | Passed sensitivity | Rejected attempt is not treated as admitted/executed; either admission or execution violates early-refusal constraints. |
| Attempt without a supplied outcome | Passed sensitivity | Missing work outcome is inconclusive, not presumed rejected. |
| Matching worker termination, unrelated termination, running and unknown | Passed sensitivity | Only termination associated with the relevant initialization and worker establishes termination. |
| Incomplete history | Passed sensitivity | Incomplete evidence cannot establish affirmative refusal. |
| Pending, timeout, panic, missing response, setup failure | Passed sensitivity | These remain inconclusive, not successful refusal. |

## Commands, execution results, and output hashes

The source at `117f85a1476fe3fda8160fef0207575e6abe9b62` was compiled and
run first. Compilation succeeded, but the focused test run failed two
assertions: incomplete history was classified as a violation instead of
inconclusive, and a supposed unrelated-refusal case actually contained a
refusal for the tested initialization without its matching failed open.
The compiler also warned that the attempted-but-unresolved-work test was
nested and therefore not discovered. These were test/model corrections;
there was no compilation or infrastructure failure.

The source was corrected in
`19eeeae35d3522a5fe158174cf9b9660f3be5d44`. The attempted-but-unresolved
test is now at module scope, incomplete history prevents affirmative
refusal, and the unrelated-refusal control tests an initialization absent
from the supplied trace.

Commands were run from the repository root with an isolated target and
temporary directory at `/tmp/qbind-synthetic-checker-correction.8lNhI8`:

```text
CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_synthetic_initialization_refusal_tests --no-run
  first source commit exit status: 0
  corrected source commit exit status: 0

CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_synthetic_initialization_refusal_tests -- --nocapture
  first source commit exit status: 101; 14 passed, 2 failed, 0 ignored
  corrected source commit exit status: 0; 17 passed, 0 failed, 0 ignored
```

Full Cargo output is retained, including compiler warnings and test
failures:

| Output | Source revision | Exit status | SHA-256 |
|---|---|---:|---|
| [`initial compile`](candidate-b-synthetic-initialization-checker-correction-initial-compile-20261109.txt) | `117f85a1476fe3fda8160fef0207575e6abe9b62` | 0 | `4195bbdab25f516d724d086f74a79d1ced59715628f52d37c02bc8b99c613b7d` |
| [`initial focused run`](candidate-b-synthetic-initialization-checker-correction-initial-focused-20261109.txt) | `117f85a1476fe3fda8160fef0207575e6abe9b62` | 101 | `317b801a256a1df919f12c769b10fbc32b2c174bce68f619d4e91933d7a014b0` |
| [`corrected compile`](candidate-b-synthetic-initialization-checker-correction-compile-20261109.txt) | `19eeeae35d3522a5fe158174cf9b9660f3be5d44` | 0 | `867afc0a582e5f9d4211eff4e4b5e0e09b35988f5fc0e940625cf9b860144515` |
| [`corrected focused run`](candidate-b-synthetic-initialization-checker-correction-focused-20261109.txt) | `19eeeae35d3522a5fe158174cf9b9660f3be5d44` | 0 | `741d85565e40ed2d3791aa4ae40028ca2cacf9fc86bc33c2a1a382804ffb3277` |

Environment: Linux `x86_64`, kernel `6.12.8+`; `rustc 1.99.1
(58cf8f9c3 2026-10-13)`; `cargo 1.99.1 (5f94df478 2026-08-27)`.
`Cargo.lock` SHA-256:
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`.
The corrected target compiled and the focused run passed; no unchanged
historical suite was rerun.

## Trace assumptions and limits

The model assumes the supplied sequence numbers define a total order
within a trace and that `event_history_complete` truthfully declares
whether that trace is complete for the tested initialization. It checks
only supplied events; it cannot prove that omitted events did not occur.
Initialization and worker IDs are synthetic correlation inputs, not
identities observed from a real adapter. The modeled `WorkerTerminated`
event is supplied test data; the model starts, joins, or observes no real
worker. The work events likewise represent supplied outcomes, not actual
adapter calls.

Repeated lifecycle events of the same kind, sequence-number exhaustion,
real concurrent event capture, identity allocation/uniqueness, durable
storage effects, and service ownership are not established by this model.
Passing tests do not establish actual adapter refusal, production startup
ordering, real worker termination, storage durability, or node
reachability. They do not prove ordinary P2P startup reaches the adapter.
No production code, manifests, lockfiles, or historical evidence were
changed; no live node, operational key, provisioning, PR, merge, or
deployment was used.
