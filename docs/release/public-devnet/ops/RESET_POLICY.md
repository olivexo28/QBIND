# QBIND Public DevNet — Reset Policy (M15)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim · NOT public-DevNet launch-ready.

This document is the canonical **public DevNet reset policy**: when and how DevNet state may be
wiped, what a reset does and does not change, and what an operator must do around one. It describes
only **existing** surfaces and adds **no** CLI flag. It makes **no** legal, financial, or value
guarantee.

---

## 1. DevNet-only safety label

QBIND public DevNet is an **experimental**, **resettable** network:

- It is **experimental** infrastructure for protocol/operator evaluation only.
- Its state is **resettable at any time**, with or without notice (see §4).
- Any balances, accounts, tokens, or on-chain state have **no value** and carry **no persistence
  guarantee**.
- Nothing on DevNet is a **MainNet readiness** signal. Public DevNet is **NOT launch-ready**.
- A reset does **not** close **C4** or **C5**; both remain **OPEN**.

If you need value permanence or production guarantees, DevNet is not the right network. Do not place
anything of value on it.

---

## 2. What a DevNet reset means

A DevNet reset is a coordinated (or, for safety, unilateral) wipe / restart of DevNet state:

- **State may be wiped.** Ledger state, account balances, accumulated history, and local data
  directories may be discarded. Operators must assume DevNet state is disposable.
- **Genesis handling.** The canonical genesis may remain **pinned** (same genesis hash — operators
  re-sync from the same start), **or** a **successor genesis** may be published (new genesis hash —
  operators must re-verify and re-bootstrap). Which one applies is stated in the reset record.
- **Prior balances / state have no value and no persistence guarantee.** A reset never entitles
  anyone to compensation, migration, restoration, or carry-over of prior state.

A reset is a normal, expected part of DevNet operation — not a failure of the network's purpose.

---

## 3. Reset triggers

A DevNet reset may be initiated for any of the following:

1. **Safety incident** — a confirmed or strongly suspected safety issue requiring a clean restart.
2. **Data corruption** — corrupted state / markers / storage that cannot be safely recovered.
3. **Trust-root / key compromise** — a suspected or confirmed compromise of a DevNet trust root or
   signing key (see the security package and `INCIDENT_RESPONSE.md`).
4. **Protocol-breaking upgrade** — a consensus/state-incompatible upgrade that cannot roll forward on
   the existing chain.
5. **Unrecoverable fork** — a network partition / fork that cannot be reconciled in place.
6. **Planned maintenance** — a scheduled reset for testing, parameter changes, or hygiene.

---

## 4. Notice policy

- **Pre-announcement when possible.** Planned resets and non-emergency resets are pre-announced
  through the published DevNet operator channels before the reset takes effect.
- **Emergency reset without notice is allowed for safety.** For a live safety, security, or
  trust-root/key-compromise situation, a reset may be executed **without** prior notice. Safety takes
  priority over notice.
- **UTC-timestamped reset record required after the fact.** Every reset — planned or emergency — must
  be recorded after the fact with a **UTC** timestamp using the evidence-record shape in §7. An
  emergency reset is not exempt from the after-the-fact record.

---

## 5. Operator action around a reset

When a reset is announced or detected, an operator should:

1. **Stop the node.** Cleanly shut down `qbind-node` before touching state.
2. **Back up private keys only if still trusted.** If the reset is *not* due to a key/trust-root
   compromise affecting your material, back up your private key material (KEM leaf secret, any signer
   keystore) using the security-package permissions (`0600`). If the reset is due to suspected
   compromise of your material, **do not reuse** it — generate fresh identity material per the
   identity/security packages.
3. **Delete / reset the data dir.** Remove or reset the node `--data-dir` so a stale marker/state does
   not conflict with the post-reset chain.
4. **Verify the genesis hash.** Confirm the genesis hash against the published value using
   `--expect-genesis-hash` (see the genesis package `VERIFY.md`). If a successor genesis was
   published, verify the **new** hash; if genesis remained pinned, verify the **same** hash.
5. **Restart using the published package.** Rebuild / re-fetch the published release binary
   (provenance-verified per `docs/release/public-devnet/binary/`) and restart against the verified
   genesis and the published seed-list posture.

---

## 6. What never changes silently

A DevNet reset must never do any of the following silently:

- **No hidden genesis.** A successor genesis, if any, is published with its hash; genesis is never
  swapped without a published record.
- **No silent seed promotion.** Seed/bootnode changes follow the published network/seed-list posture
  (`docs/release/public-devnet/network/`); a seed is never silently promoted to `status: live`.
- **No implicit trust-root replacement.** Trust-root / trust-bundle changes follow the security
  package and the PQC trust lifecycle runbook; there is no silent, peer-driven, or fallback trust
  root. The node loads no hidden anchors.
- **No MainNet / TestNet reuse.** DevNet resets never touch, migrate into, or draw readiness
  conclusions for TestNet or MainNet. DevNet identity/trust material is DevNet-only.

---

## 7. Reset evidence record shape

Every reset is recorded with a **publish-safe** evidence record. It contains only non-sensitive
values — never private keys, credentials, tokens, raw logs, raw metrics dumps, private endpoints,
private hostnames, or absolute build paths. Fields:

| Field | Meaning |
|-------|---------|
| `reset_id` | Stable identifier for this reset event. |
| `reason` | One of the §3 triggers (safety / corruption / key-compromise / protocol-break / fork / maintenance). |
| `utc_timestamp` | UTC time the reset took effect (ISO-8601). |
| `old_genesis_hash` | Prior canonical genesis hash (if applicable). |
| `new_genesis_hash` | Successor genesis hash, **or** "unchanged (genesis pinned)". |
| `operator_action` | Summary of the required operator action (stop / wipe data-dir / verify genesis / restart). |
| `safety_statement` | Short statement that the reset was executed for the stated safety/operational reason. |
| `no_value_reminder` | Explicit reminder that DevNet state has no value and no persistence guarantee. |

Only publish-safe hashes and status lines belong in a committed reset record. Raw material is never
committed.

---

## 8. `--authority-state-reset` posture

`qbind-node` exposes a pre-existing, **hidden** (`hide = true`), **offline-only** operator-ceremony
flag `--authority-state-reset` (Run 127). It is documented here for completeness; it is **not** a
network-wide reset button and Run 390 adds no new flag.

**What it does:**

- Runs an **offline** operator ceremony that exits **before** any normal node startup — no
  networking, consensus, metrics, SIGHUP handlers, reload tasks, or peer-candidate dispatch are ever
  installed.
- Validates the supplied external genesis (`--genesis-path` + `--expect-genesis-hash`), the candidate
  signed trust-bundle (`--p2p-trust-bundle`) and its ratification sidecar, then either **refuses**
  (typed refusal + audit record) or persists a new authority marker derived **only** from the
  verified genesis authority block + verified ratification sidecar, writing an audit record to
  `--authority-state-reset-output-audit`.
- **Environment policy:** DevNet / TestNet allowed; **MainNet REFUSED** (the refusal still writes an
  audit record; the marker is never written on MainNet).

**What it does NOT do:**

- It does **not** wipe an operator's data dir, balances, or ledger state — a network-wide DevNet
  state wipe (§2) is an operational action, not this flag.
- It does **not** perform any live / peer-driven apply, does **not** mutate a running node's
  `LivePqcTrustState`, validator set, epoch, or per-key sequence, and does **not** synthesize a
  marker from a snapshot.
- It does **not** imply live governance, authority-lifecycle activation, or **C4 / C5** closure. C4
  and C5 remain **OPEN**. It is an offline marker-persistence ceremony only.

---

## 9. No legal / financial / value guarantees

This policy is operational guidance for an experimental network. It is **not** a contract, warranty,
or guarantee of any kind. There is **no uptime SLA**, **no value protection**, and **no** commitment
that any DevNet state will persist across a reset. DevNet carries no MainNet readiness claim and does
not close C4 or C5.

---

## Cross-links

- `README.md` — package index and scope.
- `SAFETY.md` — user-facing safety label.
- `INCIDENT_RESPONSE.md` — how reset-triggering incidents are classified and handled.
- `VERIFY.md` — reproduce the CLI-surface and doc-structure checks.
- Genesis verification — `docs/release/public-devnet/genesis/VERIFY.md`
  (`--expect-genesis-hash`).
- Release binary provenance — `docs/release/public-devnet/binary/`.
- Security package — `docs/release/public-devnet/security/`.
- Observability runbook — `docs/release/public-devnet/observability/RUNBOOK.md`.
- Network / seed-list posture — `docs/release/public-devnet/network/`.
- Internal incident-response procedure — `docs/ops/QBIND_INCIDENT_RESPONSE.md`.
- PQC trust lifecycle runbook — `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`.