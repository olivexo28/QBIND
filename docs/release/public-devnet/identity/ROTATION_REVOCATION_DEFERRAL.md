# QBIND Public DevNet — Identity Rotation / Revocation Deferral (Run 401)

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready.

This document states, unambiguously, that **production identity rotation and
revocation are NOT implemented** for the QBIND public DevNet and are **explicitly
deferred** to C4/C5/MainNet work. It exists so operators are not misled into
believing the DevNet identity tooling provides a CA lifecycle, a revocation-list
flow, or live trust-state mutation. It is **documentation only**: **no** CLI
flag, **no** production source change, **no** live apply.

## 1. What exists today (generation + verification only)

The public DevNet identity surface (`qbind-node identity`, Run 375/376) provides:

- `generate` — mint DevNet node/seed/validator-candidate material (leaf secret
  `0600`; root signing key in memory only);
- `verify` — deterministically re-derive `node_id` from a public leaf cert;
- `print-public` — print the stored public identity;
- `seed-candidate` — emit a `status: planned` seed-list candidate object;
- `register-check` — a **non-mutating** admission verifier over **public
  material only**.

None of these is a rotation or revocation mechanism. There is **no** CA
lifecycle, **no** certificate-revocation-list (CRL) publication flow, **no**
online revocation of a previously published DevNet `node_id`, and **no** live
`LivePqcTrustState` / validator-set / epoch / sequence / marker mutation in this
tooling.

## 2. "Rotation" on DevNet is regeneration, not a live operation

To change identity on DevNet an operator simply **regenerates** a fresh identity
(`qbind-node identity generate …`) and publishes a **new** `status: planned`
seed-list candidate (verified by `register-check`). The previous DevNet
`node_id` is **not** revoked online; it is retired the DevNet-safe way — by
ceasing to advertise it and (on a DevNet reset) regenerating from a new genesis.
This is acceptable **only** because DevNet material is experimental, resettable,
and carries no value.

## 3. What is explicitly deferred (C4/C5/MainNet)

The following are **out of scope** here and are tracked as **OPEN**:

- **Operator-supplied durable-root reuse and rotation** — a persistent,
  operator-custodied root that survives and can be rotated across generations
  (the tooling mints an in-memory-only root per run).
- **Production key rotation** — a supported, audited rotation of live node /
  validator / trust-bundle signing keys without loss of identity continuity.
- **Revocation** — online revocation / CRL publication / trust-state removal of a
  compromised or retired identity.
- **Live trust-bundle apply, validator-set mutation, epoch transition,
  peer-driven apply, and MainNet authority rotation/revocation** — none are
  performed or implied by any identity command.

These belong to **C4 (authority/custody lifecycle)** and **C5 (MainNet custody /
rotation / revocation)** and remain **OPEN**; MainNet authority
rotation/revocation remains **Red**. See
`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`,
`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, and
`docs/whitepaper/contradiction.md`.

## 4. Why this cannot be closed by documentation

Rotation and revocation require live authority-lifecycle mechanisms (custody,
signing-authority transition, revocation distribution, and trust-state
application) that **do not exist** as safe, launchable surfaces in this
repository for public DevNet — and which cannot be honestly documented as
"available" without overclaiming C4/C5 closure. Documenting them as **deferred**
is therefore the only accurate posture; any stronger claim would be a
contradiction (see `docs/whitepaper/contradiction.md`).

## 5. Readiness posture (unchanged)

- **M6** remains **Yellow / Partial** — better documented (continuity guidance +
  explicit rotation/revocation deferral) but **not** Green: live registration is
  M4-gated and operator-root reuse/rotation/revocation is C4/C5-OPEN.
- **M4** remains **Yellow / launch-blocking**; **S5** and **S7** remain
  **Yellow**; public DevNet remains **NOT launch-ready**.
- **C4** and **C5** remain **OPEN**; **no** TestNet or MainNet readiness is
  claimed.