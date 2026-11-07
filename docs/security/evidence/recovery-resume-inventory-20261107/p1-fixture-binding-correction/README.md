# P1-IMPL-1 fixture-lifetime binding correction

**P1-IMPL-1 FIXTURE BINDING CORRECTION — INDEPENDENT REVIEW PENDING.**
The user supplied CHANGES REQUIRED at
[`f4ed8a123762dfc9aa1f1a9bdcffa78942894eed`](https://github.com/olivexo28/QBIND/tree/f4ed8a123762dfc9aa1f1a9bdcffa78942894eed).
This is a source-level finding in a synthetic test model, not an established
production vulnerability. P1-SPEC-1/2/3 are user-supplied PASSED/CLOSED at
specification level; all prior bounded acceptances remain within their scopes.
No reviewer identity or raw review artifact is asserted.

## Baseline counterexample

The [starting source](https://github.com/olivexo28/QBIND/blob/f4ed8a123762dfc9aa1f1a9bdcffa78942894eed/crates/qbind-consensus/tests/p1_provider_model_tests.rs)
stored only the fixture's numeric identity, then compared the candidate against
the fixture passed to admission. The preserved `baseline-control.patch.gz`
adds only a diagnostic test to that source; its applicability to the untouched
starting index was checked. `baseline.log.gz` records its actual execution,
not a passing security control. For independently constructed A and B sharing
numeric ID, with a policy change and separately a valid catalog weight change:

| Case | Baseline observed result |
|---|---|
| Admit B-matching candidate to A provider with B | Admitted; structural, uniqueness, context comparison, currentness and admission counters each 1. |
| Admit A, then use its live lease with B and Available | Sentinel reached; liveness, provider, lease, evidence-decoder and sentinel counters each 1; currentness counter 2 including admission. |

Both A and B are otherwise structurally valid synthetic fixtures; evidence is
the valid fixture frame. The diagnostic ran one test, 17 filtered, exit 0.
Its `ok` means the defective behavior was reproduced; it is not credited as a
security pass. See `COMMANDS.txt` and compressed raw output for exact commands.

## Corrected model and observations

Each instance owns an immutable clone of the independently supplied complete
`ExpectedCatalogFixture`, including label and every `Candidate` field. The
caller-supplied fixture must equal this bound value, not just its number.
Value-identical independent copies are intentionally equivalent: this is
complete fixture-value correspondence, not object identity or authentication.
Admission comparison uses the instance's snapshot, never the supplied
candidate or witness as the expectation. Attempted unequal substitution
returns `FixtureMismatch` at the explicitly counted binding check, before
structural/comparison/currentness work or materialization; use checks
liveness and instance identity first, then binding before lease, currentness,
evidence decoder and sentinel. Currentness remains a separately supplied
simulation. Replacement is the only modeled way to change the bound value;
it invalidates the old lease. Checked identity exhaustion leaves the old
instance, binding and lease unchanged.

The binding adds one provider-owned fixture clone in addition to the one
provider-owned admitted snapshot. `fixture_logical_charge` reports the
fixture's candidate logical field-byte charge plus eight bytes for its numeric
label; `logical_charge` separately reports the lease snapshot. Both can coexist.
The fixture charge persists after token drop, and disappears on destruction or
is replaced with the new fixture's charge on replacement. During replacement
old and newly cloned fixtures may transiently coexist; externally supplied
fixture, candidate inputs, test locals, Vec capacities, allocator overhead,
stack frames and transient copies are not included. No bound on independently
supplied fixture allocation or total memory is claimed. The single-threaded
model's immutable snapshot and equality check do not supply durable ownership,
cross-process fencing, real currentness or signer exclusivity.

The new `p1_impl1_same_id_fixture_substitution_refuses_and_replacement_succeeds`
tests policy and catalog variants separately. It validates both candidates,
asserts the binding-stage counter and preceding/following stage counters,
checks descriptor materialization is not called, and confirms that passing A
with a B candidate reaches full context comparison and independently returns
`ContextMismatch`. A admits and reaches the sentinel with Available; B at use
refuses before the sentinel and cannot be masked by a stale currentness check.
Explicit replacement with B rejects the old A token as `ProviderReplaced`,
admits and uses B, and dropping the old token does not release B's lease.
Fixture and lease charges are checked independently and after release.
`p1_impl1_bound_fixture_is_immutable_and_exhaustion_preserves_it` additionally
mutates the original caller fixture after construction and verifies that the
bound copy remains A, including after failed replacement due to exhaustion.
The 17 prior controls remain present and pass, including lease blocking,
destruction, checked exhaustion and release.

Full focused result: 19 passed, 0 failed, 0 ignored, 0 filtered; directly
related authority-context and content-binding regressions: 9 and 7 passed
respectively, both 0 failed/ignored/filtered. No production code is changed.
These synthetic observations are not evidence of real provenance, finality,
authenticated currentness or rollback resistance, upstream allocation bounds,
total-memory/runtime guarantees, durable application, signing-history
continuity, fencing, an independently authorized clear/resume, or production
enforcement. P2 and production P1/P2 approaches and B/C remain unselected.
The accepted provenance contract and narrow founder scope are unchanged.

See `COMMANDS.txt`, `check_artifacts.py` and `SHA256SUMS` for execution,
revision-aware integrity checks and hashes. The earlier implementation's
17-test evidence is preserved as historical execution, not retroactively
interpreted as fixture-lifetime enforcement.

A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation DISABLED; public DevNet NO-GO.
