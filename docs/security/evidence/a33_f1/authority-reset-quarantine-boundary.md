# Authority-reset quarantine decision boundary

**QUARANTINE DECISION INVESTIGATION — INDEPENDENT REVIEW PENDING.**

## Entry and scope

Before editing, the repository was
`/workspaces/QBIND/olivexo28/QBIND`, origin
`https://github.com/olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`; worktree and staging were clean. Local and
remote task tip were `bc33bca493c154dac47c797c518b77290da61566`, tree
`97aa67e5a7e36e86b7592b93bc0cfbcb24a3c0d5`, parent
`f30cae3f502020101edf5e447bdf26aea9c9f0e1`. Local and remote protected
main were `c9aaef40b045e896ddfa8b01bad230f6b680715e`.

This record uses the reviewed **stay-closed design contract** at
`stay-closed-contract.md` and the test-model evidence at
`stay-closed-model-evidence.txt`, together with the actual reset/lock source
at the entry tip. Those artifacts are design and test-model evidence, not
production quarantine enforcement. No production quarantine marker, reader,
gate, clear transition, recovery procedure, test model or reset behavior was
added or changed. The audit register and all earlier plan/evidence bytes
remain unchanged.

## Source trace and effect boundary

At this task's starting revision:

| Source anchor | Actual behavior and boundary |
|---|---|
| `crates/qbind-node/src/main.rs:2222-2248` | Reset CLI requires explicit data-dir, refuses non-Linux, creates that directory, then acquires `restore.lock`. This is destination ownership; neither creation nor the lock is a quarantine/currentness observation. |
| `main.rs:2249-2267` | Lock is held before inputs are assembled and public reset is called. The earliest safe quarantine classification insertion point for the CLI is **after successful lock acquisition, before reset input processing/invocation**. It must precede every reset audit or marker write. |
| `crates/qbind-node/src/restore_completion.rs:810-905` | The existing lock is a cooperating-process advisory `flock(LOCK_EX|LOCK_NB)` held by an open descriptor. It is not a marker reader, durability witness, anti-rollback mechanism, cross-copy fence or proof of a clean destination. |
| `crates/qbind-node/src/pqc_authority_state_reset.rs:1130-1248` | Public reset path checks audit separation, verifies inputs, then may publish verification-refusal audit. Success writes pending audit, persists authority marker, then final success audit. Persistence failure may publish refusal audit. |
| `pqc_authority_state_reset.rs:976-1114` | Guard inspects paths; writer may create audit parent, write `audit.with_extension("json.tmp")`, and rename it to audit destination. An audit/refusal write is still a reset-related write. |
| `crates/qbind-node/src/pqc_authority_state.rs:1308-1395` | Marker persistence may create parent, write/sync marker `.tmp`, rename, and sync parent. An error after rename/sync may have visible effects. |

Ownership setup has separate effects before that insertion point:
`create_dir_all(data_dir)` can create some or all directory components.
`acquire_destination_lock` opens with create and can leave an empty
`restore.lock`, including when the later nonblocking lock attempt is
contended. These are ownership artifacts, not reset audit or authority
marker publication and not proof of any quarantine state. Failure to acquire
ownership exits before reset audit/marker writes, but it does not promise
that these setup artifacts were not created. Missing `--data-dir` and
unsupported platform refuse before those setup effects.

The public library function `execute_authority_state_reset` does not acquire
ownership or classify quarantine. Its documented caller obligation is to
acquire and retain destination ownership. The CLI-only boundary below does
not cover arbitrary direct library callers or other processes.

## Proposed fail-closed CLI decision table

This table defines the decision needed at the insertion point; it is not an
implemented reader or status enum. “Refuse” means no reset audit or
authority-marker write is started. Ownership setup effects described above
may already have occurred. Do not repair, truncate, replace, delete or
reinitialize an uncertain quarantine record as part of this decision.

| Observation after ownership | Reset disposition | Reason / required treatment |
|---|---|---|
| Valid supported state says `Applying` | **Refuse; remain quarantined** | Intent can precede partial engine, storage, signer or outbound effects. Restart, elapsed time or a reset request does not complete or reconcile them. |
| Any recorded terminal/result state, including partial, refused, complete, no-effect, failed, reconciled-looking or unknown outcome | **Refuse; remain quarantined** | A record is evidence to interpret, not clear authority. A completed response is not a durable whole-state checkpoint; a local “no effect” result is insufficient across domains. No result state is defined here as reset permission. |
| Dedicated quarantine record absent | **Refuse; state unknown** | Absence alone does not prove a fresh store, clean state, current generation, no prior effects or absence of legacy state. Do not manufacture Clean. |
| Malformed, truncated, corrupt, unsupported-version, foreign-store/chain, or identity/generation mismatch | **Refuse; preserve evidence** | Cannot safely interpret or bind the observation to this destination. Do not downgrade, overwrite or silently migrate. |
| Storage unreadable, missing where required, unavailable, read-only, or namespace/identity cannot be established | **Refuse; unknown** | A failed read is not absence or Clean. Preserve the refusal cause; do not fall back to a volatile flag or local default. |
| Publication, sync, readback, interruption, process-restart, or durability result uncertain | **Refuse; unknown** | An error may follow visible publication; acknowledged API completion is only the selected backend's acknowledgment, not a broader power-loss guarantee. Neither error nor restart authorizes reset. |
| A locally valid record says `Clean` or a state looks internally consistent | **Refuse absent separate authority** | Local syntax, checksum, generation, lock ownership and matching marker do not prove currentness, anti-rollback, exclusive signer ownership or full effect reconciliation. |
| Data-dir absent from CLI or data-dir/lock acquisition fails | **Refuse before reset effects** | No ownership boundary, hence no quarantine read/decision and no reset audit/marker write. Directory/lock creation that preceded a lock failure is not ruled out. |
| Explicit, separately authorized current-state authority returns a bound, current, reconciled and eligible decision | **Not presently available; no allow branch specified** | Before any future Clean/eligible result: select and independently review authority, exact binding/currentness/anti-rollback, initialization/migration, effect coverage, signer exclusivity and durability semantics. No such authority or evidence is approved or implemented here. |

Therefore the implementation-ready decision under current approved
requirements is only: **ownership failure refuses; after ownership, every
available local quarantine observation fails closed; there is no locally
authorized “Clean” allow case yet**. This does not assert that a production
quarantine record currently exists. A future adapter may represent an
independently authorized clean-state decision as an explicit input, but that
input must be backed by an authority selected through a separate review;
this document does not invent or attest to it.

## No reset-as-clear and admitted work

The authority-reset ceremony cannot clear, release or reconcile catch-up
quarantine. This is true on success and refusal. Verification-refusal audit,
pending/final audit publication, marker replacement, marker persistence
acknowledgment, audit failure and process restart do not advance a quarantine
state machine or authorize participation. No reset path may remove or
rewrite a future quarantine record as a side effect. A future, separately
authorized reconciliation/clear procedure must be distinct from authority
reset and must satisfy its own currentness, continuity, exclusivity and
durable-checkpoint decision.

The boundary must not pretend to drain work it cannot observe. For each
already admitted operation, record domain-specific evidence:

| Domain | Completion that can support an observation | Not completion; disposition |
|---|---|---|
| Signing/reservation | Authoritative reservation/journal and signer/backend completion at the relevant stages (request admitted, reservation, key invocation, signature produced); retain exact stage and transaction identity. | Cancellation requested, caller timeout, lost response, local flag, or absent log is not proof of no signing effect. Any unknown stage stays `Unknown`; treat identity as potentially consumed. |
| Storage | Backend-specific completion plus required sync/readback acknowledgment for the exact operation and records. | Enqueue/submission success, timeout, failed response or uncertain sync does not prove not-written or durable. Keep unknown storage outcome. |
| Outbound work | Evidence at the strongest actual transport boundary available: serialization, queue admission, worker completion, transport acknowledgment, and any actual delivery acknowledgment. | Queue/enqueue success is not peer delivery; cancellation/timeout is not non-delivery; a local facade `Ok` or missing log is not a retraction. Preserve known stage or `Unknown`. |
| Engine/callback/snapshot/reconfiguration | Owning component observes completion and the relevant before/after state/effect boundary. | Request to abort, task cancellation, elapsed deadline or lack of callback does not prove completion/no mutation. Unknown stays quarantined. |

Only observed completion can be reported as completion, and then only for
that operation/domain. This CLI decision cannot fence a previously admitted
signer, cancel a callback safely, retract a signature, undo a committed
write, or establish that a peer did not observe a message. If required work
is in-flight or its outcome is unknown, the quarantine remains closed; the
reset CLI does not open a new observation/drain/fence protocol.

## Unresolved dependencies and explicit non-claims

Before any production allow branch, resolve and independently review:

* Dedicated versioned marker/interface, schema, exact store/chain/transaction
  identity, ownership/serialization and error-stage semantics.
* Fresh initialization, absent legacy state, upgrades/migration and backup
  or copied-store/anti-rollback treatment. Absence and local validity are not
  initialization authority.
* Filesystem/backend durability profile, atomicity, sync/readback ordering,
  failure-after-publication and process/power-loss semantics.
* Complete startup and CLI mode coverage before any participating listener,
  signer, consensus task, snapshot, storage mutation or alternate entry path.
* Currentness and trusted reconciliation evidence; no local marker or
  destination lock supplies it.
* Process-wide signer exclusivity/fencing and admission/completion
  observation across storage, callbacks, snapshots and outbound workers.
* Separate authority, protocol and evidence for any clear/resume transition.
  Authority reset is not that transition.
* Direct-library caller ownership/classification, unless the API is changed
  under separate approval; current public reset calls can bypass the CLI.

No filesystem durability, startup coverage, signer fencing, process-crash
survival, cross-host/copy exclusion or network delivery is proved here.
Existing destination lock protects only cooperating users of its stable
lock object under its stated profile. The quarantine marker/interface and
startup gate remain unimplemented; A33-F1 / E27 and all other unresolved
obligations remain **OPEN**. Activation **DISABLED**; public DevNet **NO-GO**.

## Documentation-only checks

No code/model tests or previously passed suites were rerun. After appending
this record and plan entry, the only checks are:

```sh
python3 - <<'PY'
import pathlib, subprocess
base = "bc33bca493c154dac47c797c518b77290da61566"
for path in ("docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md",
             "docs/security/evidence/a33_f1/SHA256SUMS"):
    old = subprocess.check_output(["git", "show", f"{base}:{path}"])
    assert pathlib.Path(path).read_bytes().startswith(old), path
print("prior plan and checksum-manifest bytes preserved as exact prefixes")
PY
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --check
(cd docs/security/evidence/a33_f1 && sha256sum --check SHA256SUMS)
```

Exit statuses and final source/commit/tree/parent identities are recorded
below after validation. Final documentation checks succeeded: the prior-plan
and manifest prefix assertion passed; `git -c
core.whitespace=cr-at-eol,-blank-at-eof diff --check` exited 0; and
`sha256sum --check SHA256SUMS` exited 0 for all manifest entries, including
this file. The final change scope is this evidence file, the append-only plan
entry and one append-only checksum line. `sha256sum --check` includes this evidence file. The
first prefix-check attempt exited nonzero: a repeated generic plan-ending
context caused section 42 to be inserted before existing sections 40/41.
The misplaced block was removed and appended after section 41; the final
prefix check below verifies the prior plan bytes exactly. This was a
documentation placement/check failure only, not a source or test failure.
No tests, builds, startup, process restart, signer, network, deployment,
activation or operational data were used.

A33-F1 / E27 and all other unresolved obligations remain **OPEN**.
Activation **DISABLED**; public DevNet **NO-GO**.
