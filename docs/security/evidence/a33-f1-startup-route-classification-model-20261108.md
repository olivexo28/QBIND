# A33-F1 test-only startup route/classification model

**TEST-ONLY STARTUP ROUTE MODEL — INDEPENDENT REVIEW PENDING.** This record
documents a synthetic ordering checker, not production startup enforcement.
TDI-1 and TSL-1/2/3/4 retain their accepted scoped status only; Transport,
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN. Activation remains
DISABLED; public DevNet remains NO-GO.

## Provenance and scope

Repository: `olivexo28/QBIND`.

| Item | Revision |
|---|---|
| Required task base | `23ecb16465e25e4e79b0f1acc894c51a0313521c` |
| Required base tree | `84fcbeead2b52c5eca81842468ee460d15c6bd1d` |
| Base parent | `a1ed2b89e3f9eeceff2ca26d58edcc254b558dd4` |
| Inspected startup-source baseline | `0d1b56515c52abe2862064027d1a9f103fef5a0c` |
| Inspected source tree | `b3e8914e6ff234afd80fd29b58470c43f2b08009` |
| Task branch | `test/a33-f1-startup-route-classification-model` |

The task branch was created at the exact required base; the later local
TDI-1 commit `037606e2` is not part of this base. The supplied TDI-1
clarification is treated as accepted design context, not as a verified file
or commit on this branch. For startup paths inspected here, the task-base
versions of `main.rs`, `cli.rs`, `identity_cli.rs`, `restore_completion.rs`,
`production_consensus_storage.rs`, `vm_v0_runtime.rs`, `p2p_node_builder.rs`,
`signer_loader.rs`, and `timeout_verification_bridge.rs` match the pinned main
revision. `binary_consensus_loop.rs` differs between the task base and pinned
main and is not used by this model.

Only these paths are added:

- `crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs`
- `docs/security/evidence/a33-f1-startup-route-classification-model-20261108.md`

The test uses synthetic `Event` arrays and one `check_trace` checker. It does
not invoke `qbind-node`, use a real lock, open production stores, exercise
Timeout signing, or observe process/restart behavior. Events corresponding
to existing source are explicitly separated below from future classifier
requirements encoded by the checker.

## Source route inventory and modeled boundary

Source links below are pinned to main
[`0d1b56515c52abe2862064027d1a9f103fef5a0c`](https://github.com/olivexo28/QBIND/tree/0d1b56515c52abe2862064027d1a9f103fef5a0c).

| Route | Existing source order represented | Future requirement represented by the model |
|---|---|---|
| Normal startup with `data_dir` | Main creates the directory, then acquires `<data_dir>/restore.lock` ([`main.rs:2515-2550`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2515-L2550)). The metrics task is spawned at `:5025-5031` before the current RTR classifier at `:5062-5133`; consensus storage opens at `:5180-5197`; VM state opens at `:5380-5400`. P2P security preflight is called at `:8124-8138`; the builder starts transport before spawning its demux task ([`p2p_node_builder.rs:1754-1821`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/p2p_node_builder.rs#L1754-L1821)). | Keep directory creation before ownership; require successful normal destination ownership before classification; require future classification before modeled storage, workers, signer loading, listener, snapshot, consensus and participation effects. This intentionally moves a *proposed Timeout classifier* earlier than the existing RTR check; it does not claim that such a classifier exists. |
| Requested restore | The same normal lock applies. Requested restore opens consensus storage at `:2619-2649` **before** its existing restore-record precondition at `:2776-2811`. It publishes the restore transaction’s own `INTENT` at `:2814-2847` before calling guarded restore at `:2852-2857`; later it persists snapshot epoch at `:5227-5257` and publishes `COMPLETE` at `:5260-5358`. | Require the proposed classifier after ownership but before modeled storage open and restore effects. Preserve source order among consensus open, restore-record check, restore `INTENT`, materialization, epoch effect and `COMPLETE`. The existing restore transaction record is not a Timeout-intent classifier. |
| Reset | `--authority-state-reset` is dispatched separately at `:2222-2281`; it creates the data directory, acquires its own destination lock, then executes reset effects. It bypasses the later normal-startup lock/classifier path. | Require a distinct reset-owner event and a distinct classifier between reset ownership and reset mutation. A normal-startup classification hook cannot be assumed to cover reset. |
| Startup without `data_dir` | The normal lock binding is `None` when no data directory is configured (`:2515-2550`). Production consensus storage likewise returns no handle if `data_dir` is absent ([`production_consensus_storage.rs:391-398`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/production_consensus_storage.rs#L391-L398)). | Treat destination identity as unavailable and require refusal with no modeled protected effect or participation authority. This is a property of the refusal-only model, not a selected production stateless-start policy. |
| Early exits before protected participation | `identity` dispatch precedes normal CLI/config/startup handling ([`main.rs:2010-2025`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2010-L2025)); generation writes identity files, including its private KEM key, before exit ([`identity_cli.rs:279-430`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/identity_cli.rs#L279-L430)). `--print-genesis-hash` reads/validates genesis and exits at `:2305-2352`; boot genesis verification also occurs before the normal lock at `:2404-2449`. | Preserve pre-exit observable effects in the trace and allow exit without classification or participation. Do not call these paths protected participation and do not erase earlier utility effects from the synthetic trace. |

The model's source-order projection for restore keeps the source sequence
`consensus open → existing restore-record check → restore INTENT → account
materialization → epoch effect → COMPLETE`. The *future* Timeout classifier
is inserted before that sequence in positive synthetic traces. That is a
proposed ordering constraint, not a source change or an assertion about
current enforcement.

## Identity separation

`IdentityClaims` has four independent synthetic claims: destination, chain,
genesis and signer. Only `SyntheticTrustedFixture` satisfies the model's
admission predicate. Missing, untrusted or display-fingerprint-only evidence
in any one field prevents synthetic admission. A no-data-dir trace has an
unavailable destination and refuses.

This fixture is only a way to exercise checker sensitivity. It does not
establish a destination identity scheme, chain/genesis currentness source,
provisioning authority, signer/key binding or exclusive key use. In
particular, the signer loader's public-key fingerprint is not treated as
trusted key identity; no four-byte display fingerprint is used as identity.
The supplied TDI-1 clarification remains design context: signed Timeout
preimage inputs, message/record identity and separately established authority
are distinct; recording fields does not make them authenticated by that
signature.

## Controls and outcomes

The focused target contains nine test bodies:

1. Positive normal ordering, explicitly retaining data-directory creation
   before ownership.
2. Positive restore ordering, with classification before storage and the
   restore-specific sequence preserved.
3. Positive reset ordering through separate ownership/classification.
4. No-data-dir refusal plus unavailable, untrusted and
   display-fingerprint-only identity in each of destination, chain, genesis
   and signer fields.
5. Early-exit traces retaining identity-file writes, genesis reads or
   configuration reads before exit, without participation.
6. Normal-route classification omission mutant.
7. Normal-route classification-after-storage mutant.
8. Reset-route classification omission mutant.
9. Reset-route classification-after-mutation mutant.

The four mutants are submitted to the exact same `check_trace` function as
the positive traces. Each returns a classification-order violation (and
where applicable a missing-classification or participation-without-admission
violation); the positive traces produce no violations.

### Executions

Toolchain:

```text
rustc 1.99.1 (58cf8f9c3 2026-10-13)
cargo 1.99.1 (5f94df478 2026-08-27)
```

Exact focused command:

```text
cargo test -p qbind-node --test a33_f1_startup_route_classification_model -- --nocapture
```

The first development execution exited **101**: 9 tests ran, 8 passed, and
`normal_classification_misordering_mutant_is_detected` failed because its
assertion required an additional `ParticipationWithoutAdmission` violation
even though the same checker had already identified the prior protected
storage effect. The assertion was corrected to require the ordering
violation; no production code was changed. The final execution of the same
command exited **0**:

```text
running 9 tests
test early_exits_preserve_prior_observable_effects_without_participation ... ok
test normal_classification_misordering_mutant_is_detected ... ok
test normal_classification_omission_mutant_is_detected ... ok
test positive_normal_ordering_keeps_directory_creation_before_ownership ... ok
test positive_reset_ordering_uses_its_own_owner_and_classification ... ok
test positive_restore_ordering_preserves_the_restore_effect_sequence ... ok
test reset_classification_misordering_mutant_is_detected ... ok
test reset_classification_omission_mutant_is_detected ... ok
test stateless_and_untrusted_identity_traces_refuse_without_authority ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The test build emitted dead-code warnings from `qbind-consensus` and
`qbind-node`; compilation completed and the warnings did not fail the test.
`rustfmt --check --edition 2021
crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs` and
`git diff --check` completed successfully after formatting. No unchanged
accepted TSL tests were rerun. No CLI process, node, key, storage durability,
signer exclusivity, crash, shutdown or restart test was run.

## Limitations

The model checks only its own event vocabulary and route constraints. It does
not prove that production emits every represented event, that all startup
and configuration branches have been enumerated, or that a durable classifier
is wired before real effects. It does not establish a storage backend or
policy, startup identity authority, production refusal behavior, power-loss
durability, signer fencing/exclusivity, restart safety, or permission to
participate. The model's accepted synthetic trace is not permission to start
a real node.
