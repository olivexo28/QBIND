# QBIND Peer Trust-Bundle Propagation and Apply Safety Specification

**Run:** 087  
**Status:** Design gate only; no runtime behavior change  
**Date:** 2026-05-18  
**Scope:** Future peer-driven trust-bundle propagation and apply safety gates

## 1. Scope and non-goals

This document is a formal design gate for any future work that might add
peer-driven trust-bundle propagation or peer-driven live apply. It defines
minimum safety requirements before that work may begin; it does not implement
or authorize that behavior.

Current behavior remains:

- Peer-candidate `0x05` is validation-only today.
- Peer-driven live apply is not implemented today.
- Propagation or rebroadcast is not implemented today.
- This document defines gates for future work only.
- No automatic trust-bundle synchronization is allowed without satisfying the
  gates in this specification and landing a separately scoped implementation.
- Local operator SIGHUP reload remains the only running-node apply path today.
- The existing sequence anti-rollback, activation-height and minimum-margin,
  signed-bundle verification, local-leaf self-check, and issuer-root self-check
  requirements remain mandatory.

Non-goals for Run 087:

- No peer-driven live apply.
- No propagation or rebroadcast.
- No `activation_epoch` runtime source.
- No KMS/HSM custody integration.
- No bundle-signing-key ratification.
- No fast-sync or consensus-storage restore redesign.
- No KEMTLS or consensus redesign.
- No C4 or C5 closure claim.

## 2. Threat model

A future propagation/apply design MUST treat every peer-provided byte and every
peer-provided claim as adversarial. The minimum threat model includes:

- Malicious peers sending malformed bundles.
- Oversized candidates or envelope fields intended to cause allocation, decode,
  hashing, signature-verification, or logging DoS.
- Replayed old bundles.
- Validly signed but rollback or equivocation bundles.
- Wrong-chain or wrong-environment candidates.
- Activation-height manipulation, including too-soon activation attempts.
- Premature revocation activation.
- Malicious propagation flood, including duplicate and loop amplification.
- Compromised bundle-signing key.
- Split-brain trust-bundle distribution across peers or partitions.
- Peer attempts to trigger sequence burn before local apply.
- Peer attempts to trigger session eviction.
- Peer attempts to trigger local live apply.
- Peer attempts to make MainNet behave like DevNet.
- Peer attempts to bypass local operator approval.

## 3. Trust and authority model

Authority remains layered and fail-closed:

- **Bundle-signing key authority.** A candidate bundle is only eligible for
  consideration after signature verification succeeds against the configured
  bundle-signing key set. A valid signature is necessary but not sufficient for
  apply.
- **Local operator authority.** The local operator remains the authority for
  selecting whether a validated candidate is eligible for local apply under the
  current implementation. Today that authority is exercised through local file
  reload-check / reload-apply and the SIGHUP live reload path.
- **Peer authority.** Peers are advisory only unless a future ratification
  mechanism exists. A peer may provide a candidate observation, but peer input
  alone MUST NOT imply local apply, sequence commit, session eviction, or
  rebroadcast authority.
- **Chain binding.** The candidate's `chain_id` MUST match the receiver's
  runtime chain id before any apply or propagation effect is allowed.
- **Environment binding.** The candidate's environment MUST match the receiver's
  runtime environment. MainNet MUST NOT accept DevNet/TestNet policy shortcuts.
- **Sequence monotonicity.** Candidate sequence handling MUST preserve the Run
  055 anti-rollback contract. Validation-only or peer-observed candidates MUST
  NOT burn sequence numbers.
- **Activation-height and minimum-margin policy.** Bundle-level and revocation
  activation heights MUST pass the existing activation-height and per-
  environment minimum-margin checks before apply; rejected candidates MUST have
  no mutation side effects.
- **Revocation semantics.** Active and pending revocations MUST remain
  signature-covered and activation-filtered. Immediate revocations with no
  activation height retain their emergency semantics; premature scheduled
  revocations MUST NOT activate early.
- **Local leaf self-check.** A candidate MUST NOT be applied if it revokes the
  node's current local leaf certificate.
- **Local issuer-root self-check.** A candidate MUST NOT be applied if it
  revokes the issuer root of the node's current local leaf certificate.

## 4. Candidate lifecycle state machine

The future candidate state model is:

1. **Received** — a frame or local envelope is observed.
2. **Decoded** — bounded, typed, versioned decoding succeeds.
3. **ValidationRejected** — structural, signature, chain, environment,
   activation, sequence-peek, revocation, local-leaf, issuer-root, duplicate, or
   rate-limit checks reject the candidate.
4. **ValidationAccepted** — validation succeeds and public candidate metadata is
   available.
5. **ObservedOnly** — the candidate is recorded or surfaced as a non-mutating
   observation.
6. **OperatorSelected** — a local operator explicitly chooses the candidate for
   local preflight or apply workflow.
7. **LocalReloadPreflighted** — the candidate passes local reload preflight under
   the same validation pipeline as startup.
8. **LocalApplyPending** — local apply is about to execute under the existing
   `validate -> snapshot -> swap -> evict -> commit` ordering.
9. **AppliedByLocalOperator** — the local operator apply path successfully swaps
   trust state, evicts sessions, and commits sequence in the required order.
10. **RejectedAfterPreflight** — preflight or apply-stage checks fail before a
    successful local apply.
11. **Expired / superseded** — a candidate ages out, is replaced by a higher
    sequence/fingerprint, or becomes invalid under newer local policy.

Current implementation boundary:

- Peer-candidate receive may only reach **ObservedOnly** today.
- Only local operator action may move a candidate toward apply today.
- Future peer-driven apply requires a separate run and additional authority.

## 5. Future propagation gates

Before any propagation or rebroadcast exists, the implementation MUST satisfy
all of these gates:

- Bounded payload and bounded envelope metadata before allocation or crypto.
- Validation before rebroadcast.
- Duplicate suppression across candidate fingerprints and per-peer repeats.
- Rate limiting for decode, validation, and rebroadcast attempts.
- No rebroadcast loops; every propagated candidate needs loop-prevention state.
- No apply side effect from propagation.
- No sequence commit from propagation.
- No session eviction from propagation.
- Clear metrics for receive, validation, rejection, duplicate, rate-limited, and
  propagated outcomes.
- Per-peer abuse handling that can isolate or disconnect abusive peers without
  affecting honest peers.
- No private material, raw secret keys, KEM secrets, or sensitive bundle bytes in
  logs.

## 6. Future peer-driven apply gates

Before any peer-triggered apply exists, the implementation MUST satisfy all of
these gates:

- Signed-bundle verification with configured bundle-signing keys.
- Chain-id and environment enforcement.
- Sequence monotonicity with no pre-apply sequence burn.
- Activation-height and per-environment minimum-margin enforcement.
- Revocation activation filtering.
- Local leaf self-check.
- Local issuer-root self-check.
- Local policy approval that is independent of the sending peer.
- Bundle-signing-key ratification or equivalent authority beyond peer gossip.
- Operator override and emergency controls.
- Rollback handling for post-swap failures.
- Session eviction policy that defines which sessions survive, if any; the
  current safe policy is evict all after successful trust swap.
- Sequence commit only after successful swap and successful session eviction.
- Fail-closed behavior for validation, policy, swap, eviction, commit, rollback,
  and audit failures.
- Audit/evidence capture sufficient to prove which candidate was selected, why
  it was accepted, whether sessions were evicted, and whether sequence was
  committed.

## 7. Explicit unsafe designs to reject

Future work MUST reject these designs:

- Peer sends bundle and receiver immediately applies it.
- Peer candidate burns sequence before local apply.
- Receiver rebroadcasts unvalidated candidate.
- Receiver applies unsigned bundle.
- Receiver accepts wrong-chain or wrong-environment bundle.
- Receiver bypasses activation margins.
- Receiver keeps sessions alive under revoked roots after apply unless a future
  separately proved selective-retention policy exists.
- Receiver falls back to `--p2p-trusted-root`.
- Receiver uses `DummySig`, `DummyKem`, or `DummyAead` as production trust for
  this path.
- Reject receiver treatment of `0x05` as consensus ratification.
- Receiver treats majority gossip as authority without ratification.

## 8. Metrics and evidence expectations

Future propagation/apply work MUST keep validation-only metrics visibly distinct
from apply metrics. Expected counters or logs include:

- received
- validated
- rejected
- duplicate
- rate-limited
- propagated, if propagation is ever implemented
- apply-attempt
- apply-success
- apply-failure
- sequence-commit
- session-eviction
- rollback
- an explicit split between validation-only and apply metrics

Evidence for any future implementation MUST prove the negative invariants as
well as the positive path: invalid candidates do not apply, validation-only
candidates do not commit sequence, propagation does not evict sessions, and
apply failure rolls back or fails closed.

## 9. Open questions / required future runs

The following remain open and require separately scoped future runs:

- `activation_epoch` runtime source.
- KMS/HSM custody.
- In-binary or on-chain signing-key ratification.
- Peer-driven apply policy.
- Propagation topology.
- Per-environment production trust-anchor operation.
- Fast-sync / restore parity.
- MainNet operational playbook for trust-bundle propagation.