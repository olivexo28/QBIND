# QBIND Proposal/Vote Signing Domain v2

Run 422 D6 — versioned Proposal/Vote signing-domain isolation.

Status: **CODE + TEST only.** The v2 domain is implemented and tested. It is
**not** wired to any production authority: the production
`proposal_vote_authority` remains `None`, the genesis-authority startup refusal
is preserved, and there is no CLI flag, environment switch, or fallback that can
enable a v2-backed Proposal/Vote authority in a release binary. Authority
freshness/lifetime activation (D7) remains unresolved.

---

## 1. Problem

The legacy v1 Proposal/Vote preimage is

```
domain_prefix(runtime_chain_id, kind) || body
```

where `domain_prefix` (see `crates/qbind-types/src/domain.rs`) maps the runtime
`ChainId` to a short **textual scope** — `"DEV"`, `"TST"`, `"MAIN"`, or `"UNK"`
— and produces a tag `QBIND:<SCOPE>:PROPOSAL:v1` / `QBIND:<SCOPE>:VOTE:v1`.

Consequences at the v1 boundary:

* Every custom / unrecognised runtime chain id collapses to the **same**
  `"UNK"` scope, so two distinct networks that both use custom chain ids share
  an identical v1 domain prefix.
* v1 binds **nothing** about the accepted genesis identity or the accepted
  consensus-authority snapshot. Two networks that share a runtime `ChainId` but
  were bootstrapped from different genesis states are indistinguishable at the
  signing domain.

A shared prefix is not by itself a proof that a cross-chain replay succeeds —
the signed body embeds the wire `chain_id`, so replay also depends on the body
fields. But v1 offers no genesis/authority binding whatsoever, which is the gap
v2 closes.

## 2. Goal

Bind a Proposal/Vote signature unambiguously to:

1. an explicit **signing-format version**,
2. the **message family** (Proposal vs Vote),
3. the **full 64-bit runtime `ChainId`** (never truncated to the 32-bit wire
   field, never taken from an incoming message),
4. the **accepted canonical genesis identity** (32 bytes),
5. the **consensus authority commitment** (32 bytes) identifying the intended
   membership/key/suite snapshot,
6. **all currently signed, security-relevant message fields** (the exact v1
   body).

A valid signature for one domain must not authenticate the same message under a
different domain even when the key, validator index, message payload, and wire
`chain_id` are all unchanged.

## 3. Byte layout (v2 preimage)

Implemented by `ProposalVoteSigningDomainV2::{proposal_preimage, vote_preimage}`
in `crates/qbind-wire/src/pv_signing_domain.rs`.

```
offset  field                     width  encoding
------  ------------------------  -----  -------------------------------
0       domain_tag                17     ASCII "QBIND:PVDOMAIN:v2"
17      signing_format_version    1      u8, MUST be 2
18      message_family            1      u8, 1 = Proposal, 2 = Vote
19      runtime_chain_id          8      u64, big-endian (full ChainId)
27      expected_wire_chain_id    4      u32, big-endian
31      genesis_identity          32     raw bytes (accepted genesis hash)
63      authority_commitment      32     raw bytes (authority snapshot)
95      body_len                  8      u64, big-endian
103     body                      N      canonical_body() of the message
```

* All fixed fields have a fixed width and the single variable-length field
  (`body`) is length-prefixed, so the concatenation is unambiguous.
* Integers in the **domain header** are big-endian.
* `body` is `canonical_body()` — the **unchanged** little-endian v1 field
  encoding of the message. Reusing the identical body bytes means (a) the same
  security-relevant fields are bound and (b) the historical v1 golden vectors
  remain byte-identical (v1 = `domain_prefix || canonical_body()`).

### Golden vectors

Deterministic golden preimage vectors with independently specified expected
bytes are in
`crates/qbind-consensus/tests/run_422_d6_pv_domain_isolation_tests.rs`:

* `golden_vote_preimage_bytes` — full expected preimage for a fully fixed Vote
  (`runtime_chain_id = 0x0102030405060708`, `expected_wire_chain_id =
  0x0A0B0C0D`, `genesis_identity = 0x00..0x1f`, `authority_commitment =
  0x80..0x9f`). The vote body is the fixed 56-byte v1 vote body.
* `golden_proposal_preimage_prefix_bytes` — expected fixed-length header prefix
  plus the length-framed `canonical_body()` suffix for a Proposal.

These vectors are specified independently of the encoder (they do not compare
the encoder against itself).

## 4. Typed domain object

`ProposalVoteSigningDomainV2` is a validated, immutable value. Construction is
via `try_new(runtime_chain_id, expected_wire_chain_id, genesis_identity,
authority_commitment)`, which:

* rejects an **all-zero genesis identity** and an **all-zero authority
  commitment** — the constructor never defaults missing genesis/authority
  identity to zeros or to DevNet;
* stores the fields immutably; the only accessors are read-only
  (`runtime_chain_id()`, `expected_wire_chain_id()`, `genesis_identity()`,
  `authority_commitment()`, `format()`).

Format vs suite: `ProposalVoteSigningFormat` (currently only `V2`) is
**separate** from the cryptographic suite id. Selecting a suite never changes
the format and selecting a format never changes the suite.
`ProposalVoteSigningFormat::from_u8` rejects any unsupported version explicitly;
there is no fallback to another version.

## 5. Version selection rule

* The node selects its signing format from **trusted configuration / validated
  authority**, never from peer-negotiated or attacker-controlled message
  fields.
* The v2 boundary uses **only** the selected domain. It never tries v2 and then
  falls back to v1, never selects a weaker format from message fields, and
  never treats absent domain metadata as permission to use legacy verification.
* Verification failure is terminal: the verifier never retries with another
  domain, version, suite, or key after a failure.
* An unsupported signing version is rejected explicitly.

## 6. Verification entrypoints

`crates/qbind-consensus/src/proposal_vote_verify.rs` adds fail-closed
entrypoints:

* `verify_proposal_msg_with_preimage(...)`
* `verify_vote_msg_with_preimage(...)`

These take the caller-selected preimage bytes and run the **same** fail-closed
verification core used by the v1 `verify_proposal_msg` / `verify_vote_msg`
(missing signature → reject, unknown validator → reject, wrong/unsupported suite
→ reject, backend error → reject, signature mismatch → reject). The v1 and v2
entrypoints differ only in which preimage bytes they authenticate; they share
one crypto backend and one hash primitive.

## 7. Node integration (fixture/test only)

`ProposalVoteAuthority` (in
`crates/qbind-node/src/binary_consensus_loop.rs`) gains an optional
`signing_domain: Option<ProposalVoteSigningDomainV2>` field:

* Inbound Proposal/Vote verification: when a domain is present the handler
  first checks the message wire `chain_id` against the domain's
  `expected_wire_chain_id` (rejecting a mismatch **before** crypto, via a new
  typed counter, without rewriting the message), then authenticates using the
  domain's preimage through `verify_*_with_preimage`.
* Outbound Proposal/Vote signing: signs the preimage produced by the **selected
  authority's** domain. Outbound code never derives a domain from the message
  it is about to sign.
* When `signing_domain` is `None` the legacy v1 preimage path is used
  unchanged.

Admission order is preserved:

```
F6 authenticated sender binding
  → Proposal/Vote authority availability (Required + None ⇒ reject)
  → wire-chain / domain / suite / signature checks
  → delivery / restore deferral / reconfiguration observation / engine processing
```

**Production remains disabled.** `crates/qbind-node/src/main.rs` never
constructs a `ProposalVoteAuthority` (production `proposal_vote_authority`
stays `None`); only test fixtures set `signing_domain` to `Some(...)`. The
Timeout/NewView context is unchanged and cannot establish Proposal/Vote
authority (D5 policy preserved).

## 8. Compatibility

* **Wire bytes do not change.** The v2 domain changes only the *signed
  preimage* (the bytes handed to the existing signer/verifier). No wire struct,
  wire version field, transport, transaction, DAG, or Timeout/NewView signature
  format is modified.
* v1 preimage bytes and their regression vectors are preserved exactly
  (`signing_preimage_with_chain_id` still emits `domain_prefix ||
  canonical_body()`).
* A legacy v1 signature presented to the v2 verifier is rejected, and a v2
  signature presented to the v1 verifier is rejected (cases D and E in the test
  matrix).
* Downstream engine / QC verification that reconstructs the **legacy** preimage
  is unchanged and still legacy. Successful v2 boundary verification is **not**
  QC or engine validation. Any broader adoption of v2 by downstream consumers
  is a separate protocol change and is **not** performed here.

## 9. Runtime ChainId ↔ wire chain_id mapping (unresolved dependency)

Three distinct representations exist:

| identity                          | type    | source                              |
| --------------------------------- | ------- | ----------------------------------- |
| `GenesisConfig.chain_id`          | string  | genesis file                        |
| runtime `ChainId`                 | `u64`   | `qbind-types` primitive             |
| Proposal/Vote wire `chain_id`     | `u32`   | `qbind-wire` consensus messages     |

The repository does **not** contain a validated mapping from the 64-bit runtime
`ChainId` to the 32-bit wire `chain_id`. v2 therefore carries
`expected_wire_chain_id` as an **explicit** field supplied from trusted
configuration (fixtures/tests only); it is never derived by truncating the
runtime `ChainId` and never taken from an incoming message. Because a validated
production mapping is absent, a production v2 authority cannot be constructed
safely, which is one reason production activation stays unavailable. Resolving
this mapping is a prerequisite dependency recorded for later work.

## 10. Non-goals (D7 and beyond)

This task establishes a scoped cryptographic boundary only. It does **not**
establish authority freshness, activation safety, complete consensus
validation, quorum/QC formation, or liveness. Specifically out of scope:

* epoch-transition authority activation / key rotation,
* restore/restart authority freshness or durable anti-rollback,
* authority replacement through peers or caches,
* QC / engine adoption of the v2 preimage,
* any production activation path.

A commitment embedded in a signature identifies the *intended* authority
snapshot; it does not prove that snapshot is current or authorized for a later
epoch. **D7 remains unresolved.**