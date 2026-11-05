# Reset quarantine trace-checker correction

**CORRECTED TEST MODEL — INDEPENDENT REVIEW PENDING.**

## Entry and scope

Before editing, repository `olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`, local and remote task tip
`9fc107c9717e6b71ac7f694a0c3472d7d2f2608d`, tree
`c5b7893cfaabd3a4da59b536335f1bb83746d4e1`, clean worktree/staging, and
local/remote protected main `c9aaef40b045e896ddfa8b01bad230f6b680715e`
matched.

Only the self-contained test model, this append-only correction record,
the remediation-plan append and the checksum manifest changed. Earlier
evidence bytes, including the previous model-correction evidence, remain
unchanged. No production reset, quarantine, storage, startup, signing or
network behavior was added.

## Correction

The model's `passive_event()` always sets `quarantine_latched`, regardless
of its status string. The former shared trace checker ignored every
`PassiveStatus` event, so it could accept an invoked reset write after such
an event. The checker now treats every `PassiveStatus(_)` as latch-setting.
It preserves the latch across restart, and a later refusal classification
cannot reauthorize writes.

The model now records each reset write attempt and whether it was admitted.
The same checker validates complete model-generated event histories after
the write attempts, including the six modeled reset stages. It still accepts
the explicitly hypothetical positive sequence only when ownership and
classification occur first and there is no prior latch.

Sensitivity traces separately attempt a write after (a) a passive event,
(b) a passive event and attempted reclassification, and (c) a passive event
followed by restart, ownership reacquisition and attempted reclassification.
All three are rejected by the same checker. The pre-existing
before-ownership, before-classification and post-refusal sensitivity cases
remain in place.

### Historical observation-description correction

The previous evidence file
`authority-reset-quarantine-model-correction-evidence.md` says the latch
test first classified `Applying`/no authority. That description was
inaccurate. The test in the prior producer actually starts with
`Observation::LocalCleanLooking` and `SeparateAuthority::None`, which
returns `Decision::Refuse`; it then attempts the later hypothetical
authorization. The old evidence bytes are intentionally preserved as
historical. This record is the explicit correction.

## Commands and outcomes

Focused formatting and suite:

```sh
rustfmt --edition 2021 crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs
rustfmt --edition 2021 --check crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --nocapture --test-threads=1
```

Result: **9 passed, 0 failed, 6 ignored**. The six ignored tests are
deliberately defective child traces; the focused parent test separately
launched all six and observed each expected failure. Captured full focused
output is `authority-reset-quarantine-trace-checker-correction-focused.log`.

Each child was also run directly with the corresponding exact command and
exited **101**, as expected:

```sh
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_before_ownership_must_fail --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_before_classification_must_fail --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_after_refusal_must_fail --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_after_passive_event_must_fail --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_after_passive_reclassification_must_fail --nocapture --test-threads=1
cargo test -p qbind-node --test a33_f1_authority_reset_quarantine_model_tests -- --ignored --exact negative_control_after_passive_restart_reacquire_reclassification_must_fail --nocapture --test-threads=1
```

The first two diagnostics state that the checker rejected writes before
ownership and before classification. The remaining diagnostics state that
the checker rejected writes after quarantine refusal, after a passive latch
event, after a passive event plus attempted reclassification, and after a
passive event plus restart/reacquisition/reclassification. Each child
reported one failed test and exit 101; none is counted as a passing security
outcome. Exact command, exit and checker-diagnostic records are retained in
`authority-reset-quarantine-trace-checker-correction-negative-controls.log`.
Only trailing whitespace and extra blank lines at the ends of the captured
logs were removed; commands, diagnostics and test outcomes are unchanged.

Whitespace and scope checks:

```sh
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --check
```

Result: PASS. The exact changed-path whitelist was checked and contains only
the model, remediation-plan append, checksum manifest, this evidence record
and the two captured logs.

## Historical-aware checksum results

The historical `SHA256SUMS` entries were not rewritten. Their source hashes
are confirmed against their respective revisions:

| Source hash | Revision checked |
|---|---|
| `772cc9df58bdeb052c56be30540c4db333e0ba1dc63f9bb0110e2501b7b60423` | `ce2fa5f2c6239df60497ecb811fc5e38bc5f9f5a` |
| `f13f88f6162695acf3c3aba1a98897d26c67b600e9ecedd50e28bd4507bf831b` | `9fc107c9717e6b71ac7f694a0c3472d7d2f2608d` |
| `bb89f8b9fd0d340b66129361fffbca335ebe6a3064af9fb9d4ba528968e09489` | current source bytes |

The historical-aware check verifies each old source digest against the source
at its listed revision, the appended current digest against the modified
source, and all other manifest entries against their current evidence files.
The plan and manifest are also checked to retain their exact prior-tip bytes
as prefixes. Plain `sha256sum --check SHA256SUMS` therefore exits 1 on the
two intentionally preserved historical source entries; the current source
entry and other valid entries pass. This ordinary-check result is expected
and is not described as an all-green manifest check.

The exact historical-source verification command is:

```sh
for rev in ce2fa5f2c6239df60497ecb811fc5e38bc5f9f5a 9fc107c9717e6b71ac7f694a0c3472d7d2f2608d; do
  git show "$rev:crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs" | sha256sum
done
sha256sum crates/qbind-node/tests/a33_f1_authority_reset_quarantine_model_tests.rs
```

It returned, in order, the two historical hashes shown above and the current
hash in the manifest. The ordinary check result is **exit 1 with exactly two
`FAILED` entries**, both the preserved historical source lines; the appended
current-source line passes. All other listed files pass. The plan and
manifest prefix assertions and historical-aware check pass.

The model remains abstract. It proves neither production quarantine
enforcement nor actual CLI ordering, filesystem behavior, durable latch
persistence, process restart, startup coverage, signer fencing, crash
safety or network delivery. A33-F1 / E27 and all other unresolved
obligations remain **OPEN**; activation **DISABLED**; public DevNet
**NO-GO**.
