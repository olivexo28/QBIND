# A33-F1 / E27 quarantine backend contract proposal

**BACKEND CONTRACT PROPOSED — INDEPENDENT REVIEW PENDING.**
A33-F1 / E27 and all other unresolved obligations remain **OPEN**; activation
**DISABLED**; public DevNet **NO-GO**.

## Status, inputs, and evidence labels

At entry, repository `olivexo28/QBIND`, branch
`copilot/a33-f1-bounded-eviction`, task tip and origin task tip were
`777e0659eebac8e1c7c6aa27a7bd14dd63478a4c` (tree
`331c3dc0404bf8ecc704f2a5591bf65a853eaea6`); the worktree and index were
clean. Local and remote `main` were
`c9aaef40b045e896ddfa8b01bad230f6b680715e`.

This is a documentation proposal based on
[the stay-closed contract](stay-closed-contract.md),
[initialization/binding/continuity](initialization-binding-continuity.md),
[the capacity inventory](capacity-inventory.md),
[the storage candidate](storage-candidate-design.md),
[the authority-reset boundary](authority-reset-quarantine-boundary.md),
and the [refusal-only Rust interface](quarantine-read-interface-evidence.md)
as corrected by
[its return-type correction](quarantine-read-interface-return-type-correction.md).
The cited source facts are observations at the prior recorded revisions and
the current source inspected for the reset/CLI anchors below. Prior tests,
models and author reports are identified as such; they were not rerun here.
Proposals are not approved requirements or implementation evidence.

No backend, codec, marker, publication, startup/reset gate, initialization,
migration, clear/resume path, or production allow result is added. In
particular, wiring `classify_for_reset` directly would refuse **every**
observation: its public return type is `ResetRefusal`, not an allow-capable
result. No authority to create an allow branch is approved by this task.

## 1. Latch facts, separate evidence, and candidate fixed layout

### Responsibilities and loss rule

The fixed latch is a *stay-closed decision record*, not a complete effect
journal. Its intended minimum facts are: format and state; monotonic revision
and observation counter; chain, logical-store and store-incarnation bindings;
operation and writer-session IDs; starting committed and lock anchors;
response binding; sticky known-effect, unresolved-domain and conflict
bitmaps; prefix/current-item positions; and a reference to separately
published evidence. All effect bits are cumulative: publication merges bits
with OR and never replaces an earlier known effect, unresolved state, or
conflict with a cleaner observation.

The latch cannot contain every block, vote, signature, request, signer result,
storage callback, snapshot/reconfiguration result, outbound attempt, error
payload, intermediate conflicting observation, publication-stage diagnostic,
or late result. Those belong in an immutable, separately bounded evidence
store, whose exact schema, lifetime, count and byte limits are **unresolved**.
The inventory finds no enforced global bound for response histories, event
revisions, workers, retries, conflicts or late observations. A hash/reference
to absent evidence is not the evidence.

If evidence is absent, stale, corrupt, inaccessible, mismatched, or cannot be
published, the owner must retain the input and result as
`RejectedUnrecorded`/unknown in volatile ownership when available, while the
already acknowledged `Applying` latch remains closed. After process loss,
details not durably recorded are **unknown/lost**, not no-effect; the latch
does not reconstruct them. No exact fact may be relabelled durable or omitted
to fit a limit. Failure to update the latch itself cannot clear an earlier
closed record; no protected effect is admitted without acknowledged intent.

### Byte-exact layout candidate (not selected or approved)

For review, this proposal uses a fixed 416-byte v1 record, all multibyte
integers unsigned big-endian, no variable-length fields, and no trailing
bytes. These are candidate widths, not established protocol requirements.
Identity binding fields are full 32-byte SHA-256 digests of canonical,
length-framed identity inputs; they are not prefixes or truncations of
strings or IDs. Candidate domain tags are the ASCII bytes
`QBIND-A33-F1-CHAIN\0`, `QBIND-A33-F1-STORE\0`,
`QBIND-A33-F1-INCARNATION\0`, `QBIND-A33-F1-RESPONSE\0`, and
`QBIND-A33-F1-EVIDENCE\0`, respectively, followed by canonical input. The
digest algorithm and canonical source inputs still require approval.

| Offset (inclusive..exclusive) | Width | Candidate field |
|---|---:|---|
| 0..4 | 4 | Magic/domain tag |
| 4..6 | 2 | Format version (`1`) |
| 6..8 | 2 | Header length (`16`) |
| 8..12 | 4 | Total record length (`416`) |
| 12..16 | 4 | State/sticky flags; all unassigned bits must be zero |
| 16..24 | 8 | Monotonic publication revision |
| 24..32 | 8 | Monotonic event counter |
| 32..64 | 32 | Chain/genesis binding digest |
| 64..96 | 32 | Logical store ID digest |
| 96..128 | 32 | Store-incarnation digest |
| 128..160 | 32 | Operation ID |
| 160..192 | 32 | Writer-session ID |
| 192..224 | 32 | Starting committed block ID |
| 224..232 | 8 | Starting committed view/height |
| 232..264 | 32 | Starting lock block ID |
| 264..272 | 8 | Starting lock view |
| 272..304 | 32 | Bound response identity digest |
| 304..312 | 8 | Sticky known-effect bitmap |
| 312..320 | 8 | Sticky unresolved-domain bitmap |
| 320..328 | 8 | Sticky conflict-domain bitmap |
| 328..336 | 8 | Completed-prefix count |
| 336..344 | 8 | Current-item index; a reserved sentinel means none |
| 344..376 | 32 | Evidence-object identity digest |
| 376..384 | 8 | Referenced evidence revision |
| 384..416 | 32 | SHA-256 of ASCII `QBIND-A33-F1-LATCH-V1\0` followed by bytes 0..384 |

Checked total: `16 + 8 + 8 + 5*32 + (32+8+32+8+32) + 3*8 + 8 + 8 + 32 + 8 + 32 = 416` bytes. Every field width, offset, and total must be verified by checked addition and checked conversion in any future codec. The layout has no implicit padding. A production bound derived from this candidate would be exactly 416 bytes for the latch only; an evidence object has a separate bound and this proposal does not establish one.

Candidate `state/sticky flags` use bit numbers from the least-significant
bit: 0 closed (required set); 1 Applying observed; 2 outcome observed; 3
evidence incomplete; 4 revision exhausted; 5 event counter exhausted; 6
publication uncertain. All other bits are reserved and must be zero in v1.
The three 64-bit bitmaps share proposed domain indices: 0 block insertion;
1 vote replay; 2 QC formation; 3 lock advance; 4 commit; 5 application
storage; 6 signer reservation; 7 key invocation; 8 signature completion;
9 signing journal; 10 snapshot; 11 reconfiguration/callback; 12 outbound
serialization/enqueue; 13 transport completion/delivery; 14 epoch state;
15 other/unknown. Known, unresolved, and conflict facts are independently
set in their corresponding maps and are never cleared. Indices 16..63 are
reserved for separately reviewed domains. Current-item index all-ones is
the candidate `none` sentinel; other values are zero-based. `event_counter`
counts accepted evidence observations, not a bound on producers or history.

All three sizes **324 bytes**, **340 bytes**, and **65,536 bytes** are
unapproved candidates, not requirements or capacity proofs. The accepted
capacity inventory explicitly finds 65,536-byte production sufficiency
unestablished; its synthetic fixture limit is not production evidence. This
proposal's 416-byte arithmetic is a new candidate calculation, not an
approved format or an assertion that the complete evidence fits.

### Identity widths and lifecycle candidate

The current interface accepts nonempty `String` store/chain identities,
whose widths are not fixed. This layout would not encode those strings
directly. It proposes full 32-byte digests over a versioned domain separator
and a canonical length-framed byte representation; it forbids truncation.
Exact source bytes, canonicalization, hash algorithm, collision assumptions,
and binding of each digest to the held object remain review decisions.

Candidate sources/lifecycle:

* **Chain/genesis:** derive from the complete canonical genesis/chain
  configuration and chain identity. The canonical source and its authority
  are unselected; a caller-supplied label alone is insufficient.
* **Store ID and incarnation:** generate independent 32-byte values using an
  approved provisioning entropy source, and persist the exact values in
  dedicated RocksDB metadata and the external latch during separately
  authorized fresh initialization. No such metadata/allocation procedure
  exists today. A copied database copies these IDs; they do not detect a
  copy.
* **Operation and writer session:** generate non-reused 32-byte IDs from an
  approved source and bind them to one operation/owner. Allocation,
  uniqueness scope, and restart semantics need review.
* **Block IDs:** preserve the source's full `[u8; 32]`; do not truncate.
  Views/heights remain full `u64`.
* **Response and evidence identities:** digest complete canonical content
  and binding data, not a prefix. Evidence storage must remain available and
  identity-bound; digest equality does not prove availability or freshness.

The checked/held object must be the exact RocksDB handle used for protected
effects, and the same ownership capability must span the operation. Matching
metadata/path/stat values do not prove that the underlying RocksDB object
remained the same. Matching local IDs establish neither currentness nor
anti-rollback, global uniqueness, complete reconciliation, or exclusive
signer ownership.

### Counters, simultaneous effects, and exhaustion

Known-effect, unresolved-domain and conflict bitmaps are independent and
sticky, so simultaneous facts coexist; an unknown outcome cannot erase a
known side effect, and a later success cannot erase an earlier conflict.
More than 64 simultaneously distinct categories, any payload, provenance,
ordering, and intermediate versions belong in separate evidence. Bitmap
capacity is not an event-count cap.

Publication revision and event counter must use checked increments, never
wrap or reuse. At `u64::MAX`, refuse further mutation/evidence admission and
retain the last closed latch. If an exhaustion marker can be durably merged
without incrementing, set it; otherwise exhaustion remains an explicit
owner-held refusal and is not claimed durable. A failed increment/publication
does not imply unchanged bytes. On restart, mismatched latch/evidence
revisions, missing evidence, counter exhaustion or any indeterminate result
maps to refusal; exact lost history remains unknown.

## 2. Path and filesystem profile candidate

Candidate paths, relative to an already-existing data directory:

* Latch: `.qbind/quarantine/latch.v1`
* Evidence: `.qbind/quarantine/evidence/<operation-id>/<revision>-<event>.ev`
* Same-directory publication temporary files: `latch.v1.tmp.<writer-id>` and
  `<revision>-<event>.ev.tmp.<writer-id>`

These are synthetic proposed names, not selected production paths. The
quarantine directory and evidence namespace must be provisioned only through
a separately approved initialization procedure. Classification is
existing-only: it must not create directories/files, repair, truncate,
rename, delete, initialize or migrate anything. Do not recover a temporary
file as the final record.

Candidate supported profile for independent review: one Linux host, a local
ext4 filesystem on a stable mount, operator-owned directories with restrictive
permissions, and cooperating processes that honor the same destination lock.
Root/privileged actors, hostile namespace replacement, mount replacement,
uncooperative writers, rollback by an administrator/snapshot, multi-host
sharing, NFS, FUSE, overlay/container writable layers, and filesystems/devices
that do not honor the selected sync contract are outside this candidate
profile. The exact kernel, ext4 mode/options, device/controller cache and
virtualization stack still require selection and evidence; no crash or
power-loss guarantee is asserted.

Candidate controls: retain a destination lock for the whole protected
lifecycle; hold directory descriptors; use directory-relative no-follow
opens (candidate Linux `openat2` constraints), exclusive temp creation,
regular-file checks, strict owner/mode/link-count policy, bounded reads,
and same-directory rename. Compare file/directory identity and metadata
before and after reading/writing; refuse on any change. These controls can
detect some races under the named assumptions. They do not prove that path
metadata remains stable outside the check window, prevent a privileged actor
from replacing a mount, or prove that a RocksDB handle is the object
represented by the pathname.

Absent latch/required evidence, symlink, unexpected file type, hard-link or
path alias, changed parent/file identity, inaccessible path, lock loss,
ambiguous path resolution, or read/write uncertainty is a closed refusal.
Directories are not accepted as records. Special files are never read.
Replacement during read is a refusal if detected; if the threat can race
undetected under the actual OS/filesystem/API, that environment is
unsupported, not covered by a metadata comparison. Held descriptors and
matching path metadata alone do **not** prove RocksDB object continuity.

All latch, evidence, temporary, audit, authority-marker, marker-temp and
`restore.lock` paths must be checked as one collision set before any future
publication. The current reset writer uses the audit final path and
`audit.with_extension("json.tmp")`; the authority marker has a `.tmp` path.
Equal canonical paths, same parent/name identity, existing same `(dev, ino)`,
hard-link aliases, symlinks, and indeterminate separation refuse. Recheck
under ownership immediately before each publication. A race outside the
assumed cooperating/permission-controlled profile remains unsupported.
Authority reset must never write over, replace, clear or repair the latch,
evidence or their publication paths.

## 3. Bounded read, decoding, and typed refusal mapping

For this exact fixed latch candidate, the candidate read limit is **416
bytes**, with one additional probe byte. A backend can use a fixed 417-byte
buffer so it reads no more than 417 bytes into that buffer; do not assume
`Vec` capacity or `read_to_end` allocation equals its logical length. An
exact 416-byte file proceeds to strict v1 decoding; 417 or more refuses as
oversized; fewer than 416 refuses as malformed/truncated. The decoder must
check magic, version, declared
length, every reserved bit, exact field count, integrity coverage, and
absence of trailing bytes. All arithmetic and integer conversions are
checked. Unknown versions, malformed lengths, trailing data and digest
mismatch are refusals. The byte limit does not bound execution time: stalled
I/O has no time guarantee in the existing interface; inability to complete
the read before caller policy/deadline is unavailable/uncertain and refuses.

416 is only a derivation for this proposed latch. A complete evidence bound
cannot be derived from current sources: response receive count, rejected
input, concurrent workers, late results, revisions, conflicts and lifetime
histories are not all bounded. Do not pass an invented evidence cap or turn
the latch limit into a cap on all evidence. Before effect admission, a future
owner must reserve sufficient evidence capacity for the supported maximum;
if that cannot be established, the operation must remain refused. The
current trait's caller-supplied `max_bytes` and post-return length check do
not enforce a production limit or prevent a backend allocating too much
before returning.

The existing interface has only `ResetRefusal` results, including:

| Observation | Existing component refusal | Additional backend rule |
|---|---|---|
| Supported `Applying` or recorded state | `Quarantined(state)` | Never authorize reset |
| Missing latch or required evidence | `Absent` | Never initialize on read |
| Wrong size, malformed framing, integrity failure | `MalformedOrCorrupt` or `Oversized { limit }` | Never repair/truncate |
| Unsupported version | `UnsupportedVersion { version }` | Never downgrade |
| Chain/store/incarnation/operation mismatch | `ForeignOrMismatchedIdentity` | Preserve both identities for diagnosis |
| Inaccessible/unreadable path | `Unavailable` | No volatile fallback |
| Partial/error after bytes read | `ReadFailure { bytes_read, kind }` | Do not treat partial bytes as absence |
| Replacement, lock loss, inconsistent latch/evidence revision, race | `Uncertain` | Keep closed; do not infer unchanged bytes |
| Locally valid Clean-looking record | `CleanLookingRequiresSeparateAuthority` | No local allow branch |
| Invalid identity/limit | `InvalidExpectedIdentity` / `InvalidReadLimit` | Fail closed |

The `ResetRefusal` interface is a read/classification seam only. It has no
allow-capable result, and even a valid Clean-looking record refuses. Absence
is also refusal. A future separate authority would need a separately reviewed
API and policy; this proposal creates none.

Concurrent publication must be serialized by the retained owner/lock. A
reader must see one complete old or new immutable publication, or refuse;
it must never accept mixed/partial bytes. If a reader races a writer without
the required lock, consistency is not established. Rename is a visibility
step, not proof of durable acknowledgment.

## 4. Publication ordering and failure semantics

The latch, evidence store and consensus database do not share an atomic
transaction. Candidate ordering:

1. Establish destination ownership, validated store binding, producer
   admission barrier and complete evidence-capacity reservation. If any is
   absent/uncertain, do not admit protected effects.
2. Write immutable initial evidence/operation binding to a unique same-dir
   temporary, fully write, sync file, rename to its immutable final name,
   then sync its directory. Only an acknowledged, exact revision is
   referenceable. This ordering may leave an orphan evidence object if later
   latch publication fails; orphan evidence is diagnostic, never permission.
3. Publish the `Applying` latch with the evidence identity/revision using the
   same temp-write, file-sync, rename, directory-sync sequence. Only after
   both evidence and latch acknowledgments may the consensus DB or any
   protected catch-up effect mutate. Do not reinterpret a visible-but-
   unacknowledged latch as acknowledged intent.
4. Apply engine/database effects under the checked owner. Their transaction
   boundaries are independent. If a mutation or response partially applies,
   preserve each known effect and uncertainty; no rollback is implied.
5. Append immutable outcome/effect evidence before publishing a newer latch
   that references it. Late outcomes are appended under the same owner with
   checked revision/counter updates; they cannot reopen admission or erase
   a previous conflict. If the owner is gone or exact attribution fails, the
   late result is unrecorded/unknown and the earlier `Applying` latch stays
   closed. A failure at either publication stage leaves that earlier latch
   closed. Never issue an allow/clear transition here.
6. On restart, missing/stale/corrupt evidence, mismatched revisions, an
   incomplete publication, or any uncertain stage refuses. Do not auto-
   complete from temp files, rewrite the latch clean, or clear on reset,
   audit publication, marker replacement or restart.

Track separately: bytes written/visible; write call returned; file sync
acknowledged; rename visibility; directory sync acknowledged; readback
result; and any independently established crash/power-loss result. A
successful API return means only the selected backend's documented
acknowledgment. Even file and directory sync acknowledgments are not a
universal power-loss guarantee; the named OS/filesystem/device profile and
separately executed crash evidence are necessary. Process-kill tests do not
prove power-loss durability.

Any error after I/O can follow visible publication; never infer unchanged
bytes from an error. Before-rename failure permits claiming the previous final
record remains only when that stage is actually known. Rename followed by
failed/uncertain directory sync means new bytes may be visible but are not
acknowledged durable. Missing/stale evidence does not downgrade to clean.
The durable `Applying` latch is the conservative restart boundary; it cannot
recover volatile effect details lost before they were separately persisted.

## 5. Reset and startup integration boundary

Source facts at this branch:

* `crates/qbind-node/src/main.rs:2211-2267`: `--authority-state-reset`
  exits before normal startup. It requires `--data-dir` and Linux, calls
  `create_dir_all(data_dir)`, acquires `restore.lock`, then builds reset
  inputs and calls the public orchestrator. The earliest CLI classification
  point would be after successful ownership and before input processing or
  reset invocation. `create_dir_all` and lock-file open/create may already
  have made directory/lock artifacts; these are ownership setup effects, not
  quarantine evidence. Failure prevents classification and reset writes,
  but does not undo those artifacts.
* `crates/qbind-node/src/restore_completion.rs:858-899`: lock acquisition is
  advisory `flock` on Linux and depends on cooperating users of the same
  lock object. It is not freshness, anti-rollback or cross-copy signer
  fencing.
* `crates/qbind-node/src/pqc_authority_state_reset.rs:976-1114,1130-1258`:
  the orchestrator can write verification-refusal audit, pending audit,
  refusal audit after marker persistence failure, and final audit. Audit
  publication includes `audit.with_extension("json.tmp")`; the authority
  marker writer has a `.tmp` path at
  `crates/qbind-node/src/pqc_authority_state.rs:1308-1395`. A future
  classification must complete before every audit and marker write,
  including refusal, pending, final and temporary-file writes. No reset path
  may clear or overwrite quarantine.
* The public `execute_authority_state_reset` library API does not acquire
  ownership or classify quarantine. CLI-only gating would not cover direct
  callers or other processes; those require a separate API/caller design.
* Ordinary/restore startup acquires destination ownership in
  `crates/qbind-node/src/main.rs:2503-2544`; restore has earlier checks and
  later materialization around `2663-2700,2781-2844`; ordinary startup
  restore-completion checks are around `5034-5118`. None is a quarantine
  gate. Future participating startup coverage must be before metrics,
  signer, network, consensus, snapshots, storage mutation or restore effects.
  Other administrative/validation modes, alternate binaries, library APIs
  and early exits need an explicit command matrix. This contract wires none.

## 6. Deterministic acceptance matrix (proposed, not executed)

All cases below are future acceptance tests, **not run by this
documentation-only change**. No Rust, CLI, filesystem, crash, node, network
or signer test was run here.

| Layer / case | Required result |
|---|---|
| Codec: each candidate field boundary, exact 416, 415, 417, trailing byte, bad magic/version/length/digest, reserved bit, integer overflow | Exact 416 valid framing decodes only to a refusal state; every malformed/oversize/unsupported case refuses without allocation beyond the bound |
| Identity: same and changed chain/store/incarnation/operation/writer; copied database; partial initialization; legacy metadata absent | Mismatch/absence/uncertainty refuses; matching IDs never proves currentness or signer exclusivity |
| Latch merge: simultaneous known-effect bits; known + unresolved; conflicting outcomes; later cleaner report; duplicate/out-of-order revisions; late results after terminal-looking evidence | All facts remain sticky or conflict is explicit; late result is attributed to same owner or remains unrecorded/unknown; no later observation erases prior knowledge or opens an allow state |
| Exhaustion/capacity: max revision/counter, one beyond, evidence exact limit/one over, counter overflow, missing/stale/corrupt referenced evidence | Refuse before protected effects; no wrap, truncation or success-shaped fallback; latch remains closed |
| Read: absent paths, permission denial, partial read, I/O error, symlink, special file, path replacement before/during/after read, lock loss | Typed refusal; never create/repair; preserve that prior read may be uncertain |
| Concurrency: reader during temp write/rename, two cooperating writers, uncooperative replacement | One consistent old/new record or refusal; no mixed decode; uncooperative case must be prevented/detected or excluded by approved profile |
| Publication failpoints: before/after write, file sync, rename, directory sync, readback; error after visible bytes | No acknowledgment on failure/uncertain stage; no claim old bytes unchanged; process restart remains closed |
| Engine/database integration: failure before intent, after acknowledged intent, at each registration/vote/QC/lock/commit/storage boundary and late completion | No protected effect before intent+evidence acknowledgment; exact observed effects retained or unknown; no asserted rollback |
| Authority reset CLI: refusal, pending, marker temp/final and audit temp/final writes, ownership failure and all path aliases | Ownership first; classification before every reset write; any refusal or uncertainty starts no reset write; setup directory/lock effects measured separately |
| Startup/restore/admin/direct-library paths | Each participating path refuses before its first protected service/effect; direct library cannot bypass ownership/classification; every unclassified route remains explicitly unsupported/refused |
| Power-loss and copied-store/signer cases | Separately authorized profile-specific tests required; no local match, checksum, process-kill test or lock is accepted as currentness/exclusivity proof |

## 7. Decisions still required

Independent review must resolve: canonical chain/genesis bytes and digest;
store ID/incarnation provisioning and RocksDB-object continuity; exact
operation/session ID source and non-reuse; whether 416-byte latch layout is
appropriate; exact record-version/integrity policy; evidence schema,
producer inventory, byte/count/time bounds and late-event ownership;
fresh-store initialization and legacy migration; supported kernel,
filesystem, mount, device and adversary profile; lock/path replacement
controls; cross-store ordering and durability/error acknowledgments; all
reset/startup/admin/library integration points; the reset refusal API policy;
and any future clear/currentness/anti-rollback/signer-exclusivity authority.

No fixed 324-, 340-, 416-, or 65,536-byte production limit, allow result,
clear/resume authority, initialization ceremony, migration, backend or
activation is approved here. Until decisions and acceptance evidence are
reviewed, every uncertain or locally observed Clean-looking state refuses;
A33-F1 / E27 remain **OPEN**, activation **DISABLED**, public DevNet
**NO-GO**.

## Documentation checks and checksum accounting

The documentation-only checks for this change are a scoped Python verifier
for local links in this new contract and plan section 48, and exact-prefix
comparisons using the starting Git revision, plus:

```sh
git -c core.whitespace=cr-at-eol,-blank-at-eof diff --check
(cd docs/security/evidence/a33_f1 && sha256sum --check SHA256SUMS)
```

The relevant local links in this new contract and the appended plan section
resolve. A broad scan of the entire historical plan also reported a
pre-existing missing target, `evidence/a33_f1/authority-reset-ownership-evidence.md`,
in an earlier plan section; that unrelated historical reference was not
rewritten. The new contract and plan remain exact append-only extensions:
the plan and checksum-manifest byte prefixes at task tip
`777e0659eebac8e1c7c6aa27a7bd14dd63478a4c` are preserved.

Revision-aware verification checks every manifest digest either against
current bytes or against a Git revision containing those exact historical
bytes. The ordinary `sha256sum --check SHA256SUMS` is expected not to be a
full pass: after current contract and plan digests are appended, it exits 1
with **six preserved historical mismatches** (two earlier model-source
digests; the earlier interface source and test digests; and two prior plan
digests), while **123 entries pass**. The mismatch details and producing
revisions are recorded in
`quarantine-backend-contract-integrity.log`; no historical line is
overwritten.

These are documentation/link/scope/whitespace and checksum checks only. No
Rust test, build, filesystem operation, crash/power-loss test, CLI, node,
signer or network test was run.
