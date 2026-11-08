# A33-F1 — public-first startup identity contract proposal

**PROPOSAL FOR INDEPENDENT REVIEW AND OWNER DECISIONS — NOT APPROVED.**
This document proposes a narrow, refusal-only public identity comparison
after destination ownership. It does not approve production startup, signing,
recovery, restart, or admission. A synthetic match is not real authority.
Activation remains **DISABLED**; public DevNet remains **NO-GO**.
A33-F1 / E27 and other recorded obligations remain **OPEN**.

## Base and scope

The proposal is based on main commit
`810a6759ef1e3ddb42c9a0f09f78502dc4655276`, tree
`52fb056deb02677260319519fad10ed588bb10de`. It is documentation only:
no production behavior, signed format, durable backend, provisioning procedure,
or restart policy is selected here. The checked-out branch started from that
commit; its parent and resulting tree are reported with the change.

The candidate normal-startup point is after the ordinary destination-lock
binding and before `restore_requested` and subsequent startup work
([`main.rs:2515-2552`][ownership]). That boundary is not shared by every
route; see [Routes](#routes-and-genesis-handling).

## Proposed public association

A candidate association would bind the complete tuple:

```text
environment
numeric_chain_id
canonical_genesis_identity
destination_identity
validator_id
signature_suite
complete_signer_public_key
```

The concrete encoding, authority source, and trust roots are **owner
decisions**, not specified formats. In particular, the destination identity
must not be silently defined as only a path, nor the signer as a display
fingerprint.

Keep three classes of information distinct:

| Class | Meaning | Examples and limits |
|---|---|---|
| **Observed** | Read from the current invocation or source, not thereby trusted as expected authority. | `config.environment`, `config.chain_id()`, the configured `data_dir`, a canonicalized path, parsed genesis fields and hash, CLI validator ID, configured key entries, and any later signer-derived public bytes. |
| **Independently authenticated expected** | Values from an authority and provisioning path explicitly approved by the owner, whose integrity, freshness, and binding to this deployment are established independently of the object being classified. | No such complete source currently exists in the candidate startup path. A config value, matching record, local file, canonical path, or short fingerprint is not independently authenticated merely by being present. |
| **Comparison result** | Equality or mismatch between an observation and its authenticated expected counterpart. | A match means only that the compared public values agree under the selected authority and representation. It grants no permission to continue, sign, recover, or restart. Missing/unavailable evidence is not a match. |

`NodeConfig::chain_id()` returns the ID derived from the configured network
environment ([`node_config.rs:5301-5303`][chain-id]). It is an observation;
the independent expected environment/chain binding still needs an approved
source. Genesis identity should be the full canonical hash, not a short display
form. The textual `GenesisConfig.chain_id` and the numeric runtime chain ID
are distinct values and both need an explicitly approved relationship.

An owner-designated authority must authenticate and provision the expected
association, and define how the node obtains and validates it. The owner must
decide who controls that authority, how it associates a tuple to a particular
deployment and destination, what protects its delivery and replacement, and
how updates, revocation, rollback and currentness are determined. A local
record that is itself under classification cannot bootstrap this authority.
No procedure or trust root is selected here.

### Destination and process assumptions

The normal route holds `DestinationLock` when `data_dir` is set; it is a
kernel advisory lock on `<data_dir>/restore.lock` and excludes only
cooperating participants ([`restore_completion.rs:800-911`][lock]).
`DestinationId::canonicalize` returns an absolute UTF-8 path after
canonicalization ([`restore_completion.rs:148-179`][destination-id]); the
normal route does not compute it at the candidate point. A path is an
observation, not proof of filesystem-incarnation identity. Neither a canonical
path nor advisory locking prevents all path substitution, namespace changes,
or writes by nonparticipants. A stable namespace and cooperating-process
assumption would need explicit owner approval; stronger destination identity
and its authority remain unresolved. None of these mechanisms proves signer
exclusivity.

## Refusal-only comparison boundary

Candidate conceptual interface (not implemented):

```text
compare_public_identity(
    observed: RequiredPublicObservations,
    expected: AuthenticatedExpectedAssociation,
) -> Match | Refuse(IdentityEvidenceError)
```

`RequiredPublicObservations` would carry every tuple field above. The
`expected` input is explicitly named authenticated; a parsed configured value
alone does not satisfy that contract. `IdentityEvidenceError` would
distinguish absent, unreadable, malformed, ambiguous, and mismatched evidence
for diagnostics, without falling back to defaults, a matching record, a
fingerprint, or the actual signer. The error taxonomy and any public diagnostic
contents remain design decisions.

Every missing, unreadable, malformed, ambiguous or mismatched required input
must result in refusal from this comparison. Refusal means this comparison
produces no positive result; it does not prescribe process-wide shutdown or
restart policy. A positive comparison is only a comparison result: it is not
permission to continue, create signer authority, sign, recover or restart. A
synthetic positive fixture in a future test has no real effect or authority.

**`SignerLoaded` remains a protected effect.** The accepted reviewed route
model explicitly includes it in `is_protected_effect`
([`a33_f1_startup_route_classification_model.rs:80-143`][model]).
This proposal does not move private-key loading before public comparison or
claim that public comparison fences the later signer. A later check against
the actual signer would be a separate, unapproved step after `SignerLoaded`,
requiring its own authority, ordering and refusal review. The later check
would need full public-key bytes and suite/validator identity, not a short
fingerprint; it still would not establish exclusive control or signing-history
currentness.

The current loader returns the derived complete public key and metadata after
loading the key ([`signer_loader.rs:303-378`][loader]); its `ValidatorSigner`
trait does not itself expose public-key bytes
([`validator_signer.rs:139-236`][signer-trait]). Loader/provider equality
checks do not supply an independent early authority: the provider can insert
the signer-derived local key if no explicit local key is configured
([`peer_key_provider.rs:329-401`][provider]).

### Source clarification: LoopbackTesting

At pinned main `810a6759ef1e3ddb42c9a0f09f78502dc4655276`, three distinct
source observations need to remain separate:

1. The operator key-management guide describes `loopback-testing` as using
   in-memory keys ([`KEY_MANAGEMENT.md:49-69`][key-doc]).
2. The signer-loader **function documentation** lists `LoopbackTesting`
   alongside `RemoteSigner` and `HsmPkcs11` as refused modes
   ([`signer_loader.rs:282-293`][loader-function-doc]).
3. The implementation and its adjacent comment say that, when a keystore
   path is configured, `LoopbackTesting` selects `LocalKeystorePlain` and
   loads the plaintext `validator-{N}` entry
   ([`signer_loader.rs:314-336`][loopback-code]).

These are documentation/implementation observations, not a demonstrated
production vulnerability. This proposal changes no operator guide, loader
documentation, implementation, or test plan.

## Routes and genesis handling

The future comparison is proposed only as a **refusal-only comparison**.
No production route coverage or startup policy is approved.

| Route | Existing boundary and proposal | Unresolved route decision |
|---|---|---|
| Normal startup with `data_dir` | Candidate point is after normal destination ownership. A future comparison would have to precede reviewed protected effects. | What authenticated tuple is available then; whether and how the normal route handles missing authority; exact protected-effect inventory and enforcement remain to be decided. |
| Requested restore | It shares the normal lock, but currently opens consensus storage early before its restore-record precondition; the restore pipeline can publish intent and materialize state later ([`main.rs:2619-2680`][restore-open], [`main.rs:2776-2857`][restore-intent]). If brought into scope, comparison would need a separately reviewed position before those protected effects. | Whether restore uses the same association and how it relates to restore-record identity/currentness are unresolved. The restore record is not an identity authority. |
| Reset | Reset takes a separate branch, requires a data directory, acquires its own destination lock, and proceeds to reset execution ([`main.rs:2222-2281`][reset]). The normal candidate point is bypassed. | Whether reset is in scope and its own required identity tuple/order are separate decisions. A normal-startup check does not cover it. |
| No data directory | The normal destination lock is absent when there is no configured directory; production consensus storage also returns no handle ([`main.rs:2515-2552`][ownership], [`production_consensus_storage.rs:391-398`][no-storage]). | No destination observation is available for this tuple. Whether future policy refuses stateless startup or defines a separately authorized destination is undecided; this proposal chooses neither. |
| LocalMesh | LocalMesh constructs its consensus loop separately and does not use the P2P signer preflight ([`main.rs:5508-5575`][local-mesh], compare [`main.rs:8119-8138`][p2p-preflight]). | Whether LocalMesh is covered, how it obtains expected validator identity, and whether a later actual-signer comparison exists are unresolved. No P2P-path conclusion is generalized to it. |

The pre-lock boot-genesis verification and configuration reads precede the
normal lock; directory creation and lock-file acquisition also precede the
candidate point. These existing effects are not characterized as absent.
Metrics-task spawn and ordinary consensus storage open are later protected
effects in the current route ([`main.rs:5025-5031`][metrics],
[`main.rs:5180-5197`][storage]).

### External and embedded genesis

On the external-genesis path, the candidate comparison may observe the
retained `boot_accepted_canonical_hash` when it is `Some`; the boot path also
produces `None` for the embedded-genesis path
([`main.rs:2404-2449`][boot-hash]). A `None` value is unavailable evidence,
not an approved identity or wildcard.

If a future step rereads external genesis to obtain fields, the parsed fields
and canonical hash must be derived from **the same owned parse**. When the
retained boot hash exists, the reread full hash must be compared byte-for-byte
with it; do not silently substitute a new read. Existing helpers have
different contracts: boot verification can skip external verification for
DevNet/TestNet embedded-genesis configurations
([`pqc_boot_genesis.rs:223-262`][boot-verify]), whereas the authority
reloader revalidates one parse and compares with the boot hash only when a
boot hash is supplied ([`genesis_consensus_authority.rs:1385-1443`][authority-reload]).
Therefore the existing helper does **not** always enforce a boot-hash match.

The required authority and identity for the `None` case and embedded genesis
are unresolved owner decisions. This proposal does not derive an expected
hash from embedded code, accept missing hash, force external genesis, or
select a refusal/restart policy.

## Future source-connected test — FUTURE / NOT EXECUTED

After owners approve the comparison authority and tuple semantics, a small
isolated test could exercise a pure comparator using synthetic public
observations and a synthetic approved expected association. Where feasible,
it could use the existing read-only destination canonicalization helper and
existing same-parse genesis verification/hash functions to construct
observations. The helper results are observations only; they do not
authenticate the fixture authority.

The test should have:

- one synthetic matching control, asserting only `Match` from the comparator
  and explicitly asserting no startup/admission/sign/restart capability;
- individual missing-value cases for environment, numeric chain, genesis,
  destination, validator ID, suite, and full public key;
- individual mismatch cases for each field, including a full-key mismatch
  whose short display prefix matches, so a fingerprint cannot satisfy the
  check;
- negative controls showing that absent/untrusted expected authority, a
  matching local record, or an embedded/no-boot-hash case does not become a
  trusted expected association;
- a sensitivity guard: bypassing/removing the required field comparison
  must make the corresponding negative test fail.

Temporary fixture creation and cleanup should be a test-harness concern,
outside the pure decision function; the comparison path should only receive
already constructed values and return match/refusal. Synthetic keys/bytes
only—no operational keys and no live signer.

Handling malformed, unreadable or ambiguous inputs **before** they reach a
comparator remains an open test-entry requirement; a pure comparator test
alone does not cover acquisition, parsing or provenance failures. Any future
test claiming orchestration order must also add explicit protected-effect
controls proving that refusal reaches none of those effects. These controls
are future requirements, not implemented or claimed here.

Every test and control in this section is **FUTURE / NOT EXECUTED**. Such a
test would not prove production CLI ordering, that real startup calls the
comparator, trusted provisioning, durability, filesystem race resistance,
filesystem-incarnation identity, signer exclusivity, currentness, recovery,
or restart safety. Existing tests are not rerun by this documentation change.

## Owner decisions, assumptions, and limitations

| Decision or assumption | Open question |
|---|---|
| Expected association authority | Which actor/system authenticates the tuple, and how are its trust roots and provenance independently checked? |
| Provisioning and replacement | Where/how is the association provisioned, updated, revoked, protected from substitution, and bound to this deployment? |
| Tuple semantics | Exact destination identity; environment/numeric-chain relationship; genesis identity source; validator-ID mapping; supported suite; complete public-key representation. |
| `None` and embedded genesis | What independent authority can supply an expected genesis identity, if any? Is comparison unavailable/refusal-only, or is a separately approved route required? No choice is made. |
| Route coverage and order | Which of normal, restore, reset, no-data-dir and LocalMesh are covered, and what are their reviewed pre-effect boundaries? |
| Stable namespace and processes | Assumes a stable namespace for observations and cooperating participants for advisory locking; neither prevents all path substitution or nonparticipant writes. Owners must decide whether stronger identity/fencing is required. |
| Signer relation | The public tuple predicts an expected signer; comparison does not verify a later-loaded signer or fence it. The separate actual-signer step is unapproved. No signer exclusivity is established. |
| Rollback/currentness and durable intent | Identity equality does not prove latest signing history, anti-rollback state, durable intent, publication/barrier completion, or recovery authority. Backend, format, restart policy and recovery authority remain unselected. |

No positive result alone is permission to continue, sign, recover or restart.
Preserve PR11-C1–C4, SRM-1/2/3, TDI-1 and TSL-1/2/3/4 only within their
previously reviewed scopes. PR #11 is merged; its transfer investigation
remains closed. This proposal does not reopen it or rerun unchanged tests.
A33-F1 / E27 and other recorded obligations remain **OPEN**.

## Pinned source references

All links below pin to base commit
[`810a6759ef1e3ddb42c9a0f09f78502dc4655276`](https://github.com/olivexo28/QBIND/tree/810a6759ef1e3ddb42c9a0f09f78502dc4655276).

[ownership]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L2515-L2552
[chain-id]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/node_config.rs#L5301-L5303
[lock]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/restore_completion.rs#L800-L911
[destination-id]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/restore_completion.rs#L148-L179
[loader]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/signer_loader.rs#L303-L378
[signer-trait]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/validator_signer.rs#L139-L236
[provider]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/peer_key_provider.rs#L329-L401
[model]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs#L80-L143
[key-doc]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/docs/release/public-devnet/security/KEY_MANAGEMENT.md#L49-L69
[loader-function-doc]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/signer_loader.rs#L282-L293
[loopback-code]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/signer_loader.rs#L314-L336
[restore-open]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L2619-L2680
[restore-intent]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L2776-L2857
[reset]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L2222-L2281
[no-storage]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/production_consensus_storage.rs#L391-L398
[local-mesh]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L5508-L5575
[p2p-preflight]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L8119-L8138
[metrics]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L5025-L5031
[storage]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L5180-L5197
[boot-hash]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/main.rs#L2404-L2449
[boot-verify]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/pqc_boot_genesis.rs#L223-L262
[authority-reload]: https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/genesis_consensus_authority.rs#L1385-L1443
