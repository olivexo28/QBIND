# RUN 422 — Native admission resource and compatibility assessment

**Status: assessment only.** The isolated APIs remain isolated and unused by production authorization or creation. The values below are an explicitly unapproved harness configuration, not protocol limits, node defaults, deployment guidance, or approval. No helper was activated, no production code was changed, and no deployed-path readiness is established.

## Baseline and scope

- Origin: `https://github.com/olivexo28/QBIND`.
- Required starting HEAD: `8ae9ceafb2fd4fd9e491d33c44415f99c0de8a5f`; required root tree: `c5c70a9ad338f7dccd47c4fca6d0d8791312f0f5`. The starting worktree was clean and both object IDs matched exactly.
- The raw commit has `parent f976121a74d60c7af665ed20f6fa504cefd7e609`. Initially the repository was shallow and that parent object was unavailable. After fetching one level from `origin/main`, `git cat-file -t` found that parent and `git merge-base --is-ancestor <parent> HEAD` returned zero. The repository remains shallow with that parent as its boundary; ancestry beyond that boundary is not established here. Exact tree correspondence is a separate fact: the starting HEAD tree equals the required tree.
- The original assessment tested source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`, test blob `71ae4e8b294d2994d55d4127db25e92a83602b89`, before documentation-only delivery at `7bcaaeaaa359b672df5b9b5346b37eb8dfbf0949` / tree `6db553e9174758e9d27e5fd9ed40fcce8511909f`. The finishing pass started clean at that delivery on the same task branch. Its tested source is `a05bafe9bf3fca179e7fdc253064b0b7f1f404d2` / tree `1865358fd0cacf16ce7d15715a8b8b051382b79c`, test blob `1056c37978c7bb23e14ae7938e690b107c849e02`. Final Rust bytes must equal this finishing-pass tested source; later changes are documentation only.
- Only the four authorized paths change: this new assessment, the new integration test `crates/qbind-ledger/tests/run_422_native_admission_resource_tests.rs`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`, and `docs/whitepaper/contradiction.md`. Production Rust, prerequisite helpers, manifests, lockfile, wire formats, authorization/creation callers, interfaces, and defaults are unchanged.

## Candidate configuration — not approved

The test calls `evaluate_native_transaction_proofs::<8, 8, 16>` with 8 required signer indices, 8 distinct keyset account IDs, and 8 authentication proofs total. Each stored keyset is bounded to 16 encoded entries, 65,536 encoded bytes, 4,096 bytes per public key, and 65,536 aggregate public-key bytes. The signature limits are 8,192 bytes per signature and 65,536 aggregate signature bytes. Combined algorithm/parameter identifiers are limited to 128 bytes.

Create preparation is evaluated separately with 16 entries, the same key and identifier limits, 65,536 encoded call-data bytes, 65,536 stored output bytes, and an 8-distinct-proof reachability budget. **The 65,536-byte create input limit is an assessment choice**, not an inherited or approved policy. The output cap is separate. Neither is installed as a default.

These are independent ceilings, not a promise that every maximum is jointly reachable:

- Stored bytes are `12 + 6*n + sum(key_bytes)`. With 16 entries and a 65,536-byte account limit, aggregate key bytes can be at most 65,428, not 65,536. The 4,096-byte per-entry cap would permit 65,536 bytes across 16 entries only if encoding overhead were free.
- Create input bytes are `42 + 5*n + sum(key_bytes)`. With 16 entries and a 65,536-byte input ceiling, the key payload can be at most 65,414 bytes. The same 16 keys at 4,096 bytes each exceed both input and stored-output ceilings after framing.
- Eight signatures of 8,192 bytes exactly consume the 65,536-byte aggregate signature budget. The configured per-signature size is below the `u16` wire-field maximum, but this does not bound the whole transaction body, its call data, or non-signer metadata.
- The actual genuine ML-DSA-44 fixtures use 1,312-byte public keys and 2,420-byte signatures. They do not approach the synthetic generic byte maxima; the tests never pad cryptographic material or call padded values genuine.

## Executable evidence

The external harness separates key generation, keyset encoding, transaction construction, and signing from timed evaluation. Its counting `AccountStore` delegates bounded reads and legacy operations to `InMemoryAccountStore`; its counting signature suite delegates descriptors and verification to the real `MlDsa44SignatureSuite`. `Instant` measures three fixed repetitions, reports the first sample separately from the next two, and has no timing pass/fail threshold. Counter resets occur before each timed interval. Timed closures include counting-wrapper operations, their assertions and counter reads, and, for create preparation, observed-length/capacity recording and destruction of the returned Account/output buffer on closure exit. These are counted harness-workload measurements, not isolated backend benchmarks or production latency bounds. Test-owned transaction and input bytes are compared with pre-call copies; fixture insertion is explicitly outside measured store operations and the underlying store is compared after evaluation.

| Workload | Evidence from the passing harness |
|---|---|
| A — 8 distinct groups × 16 distinct genuine keys, one genuine proof/group, threshold 1 | Exact summary `(required_signer_index_count=8, distinct_keyset_account_count=8, evaluated_authentication_proof_count=8)`; 8 bounded reads; zero legacy reads, writes, or deletes; 128 delegated descriptor calls and 128 delegated signature attempts. This confirms the complete 16-candidate matching-suite scan per proof. |
| B — one 16-entry genuine keyset, 8 genuine distinct proofs, threshold already met by proof one | Exact summary `(8,1,8)`; 16 descriptors and 128 signature attempts. A copy with only the eighth signature bit-flipped returns `InvalidProof` after all 128 attempts; threshold attainment does not stop evaluation. |
| C — proof and entry boundaries | Nine proofs return exactly `Structure(AuthenticationProofCountLimit)` before digest/store/provider work (0 reads, 0 descriptors, 0 verification attempts); a valid one-proof retry succeeds. A synthetic, explicitly non-cryptographic 17-entry stored record under the configured 16-entry parser limit returns exactly `KeysetParse(EntryCountLimit)` after one bounded read and before provider work; restoring a valid 16-entry genuine keyset retries successfully. Both inputs remain unchanged. |
| D — create preparation and composition | Sixteen genuine entries, threshold 8, and an 8-proof reachability budget produce the complete expected `Account` and bytes. A threshold of 9 returns exactly `Semantics(ThresholdUnreachable)`. A separate untimed preparation returns the actual Account, which is compared completely against the independently encoded expected oracle and moved into the fixture store (not reconstructed or replaced with an oracle clone). Evaluation of eight genuine proofs returns `(8,1,8)`, with one bounded read, 16 descriptors, and 128 signature attempts; complete stored-account equality against the oracle is checked afterward. Preparation success itself performs no store write and does not authorize creation. |
| Compatibility controls | Genuine signature for the second of two same-suite entries is refused by the legacy first-match verifier but accepted by the isolated full scan. A genuine signature for a one-entry keyset whose threshold is 2 and a keyset with conflicting weights for a duplicate canonical key are accepted by legacy but refused by the isolated evaluator. A well-framed unused entry with an unsupported suite is likewise accepted by legacy but refused by isolated evaluation as `SuiteNotFound`. Additional controls show legacy acceptance/new refusal for wrong returned owner, executable flag, and returned AccountId; the legacy-only store succeeds while the isolated path returns `Unsupported` without a `get` fallback; and nine genuine proofs repeated for one signer index are accepted by legacy but rejected as `AuthenticationProofCountLimit` before bounded reads or provider work. Wrong-metadata store responses are explicit synthetic backend controls. These are local compatibility observations, not deployed-exploit evidence. |

Historical timing observations at source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`: with the ordinary profile, workload A measured first/subsequent samples of 532.043299 ms / 532.015021 ms and 530.136880 ms; workload B 472.595763 ms / 464.243324 ms and 461.192351 ms; create preparation 9.586565 ms / 9.382643 ms and 9.495701 ms; prepared-account evaluation 468.926107 ms / 468.322522 ms and 469.154126 ms. With the optimized profile, workload A measured 16.700863 ms / 16.080352 ms and 16.060252 ms; workload B 13.536407 ms / 12.928815 ms and 13.407807 ms; create preparation 447.364 us / 483.207 us and 445.071 us; prepared-account evaluation 13.006350 ms / 12.860474 ms and 13.024217 ms. These are measurements of this host, build, and counted test wrappers only; fresh finishing-pass observations are recorded below.

The genuine create fixture had 21,114 encoded input bytes. Observed output length and capacity were separately 21,100 and 21,100 bytes. The printed `source_derived_expected_reservation_request=21100` is derived from `expected.data.len()` and the helper's checked output sizing followed by `try_reserve_exact(length)` in `keyset_create.rs`; it is not an observed allocation-boundary request. No allocation-boundary observer or production instrumentation was added. The bounded in-memory account read observed maximum returned data capacity 21,100 bytes. Public Rust `size_of` observations from the harness were Transaction 160, Account 120, TxAuth 32, TxAccountMeta 36, limits 80, summary 24, and error 24 bytes. These are type-size observations only.

### Work and ownership bounds from source

`native_tx_proof.rs::preflight` checks nonempty auths, wire-representable account/auth/call-data lengths, proof count, each signature length, aggregate signature bytes, every auth index, signer marking, complete exact-index signer coverage, and the complete signer-group mapping before hashing, reading, or provider activity. It uses an 8,192-byte coverage bitmap for the full `u16` index space. It groups by exact 32-byte `AccountId`: signer-index grouping is at most `O(A*G)`, auth-to-group counting is `O(U*G)`, and proof gathering rescans all auths for each group (`O(U*G)`), where `A` is account metadata count, `U` auth count, and `G<=8`. Group thresholds do not borrow weight from another group.

The checked streaming digest in `qbind-hash/src/tx.rs::try_tx_digest_streaming` hashes an encoded signing body of `91 + 36*A + C` bytes plus the 8-byte domain tag, where `C` is call-data length. Its work is `O(A+C)` with constant-size hash state and no materialized signing preimage. This protects checked length encoding and avoids a second body allocation; it does not impose an operational body-size, metadata-size, call-data-size, or latency cap. The signer/proof caps do not cap all metadata or call-data work. No new production transaction-body cap is proposed here.

For each signer group, the evaluator makes at most one bounded read with the stored-data ceiling, parses the complete encoded keyset, and gathers that group's proofs. The borrowed parser traverses all entry prefixes in `O(E)` framing steps and advances over key spans without copying or scanning key payloads. At most 8 accounts are read, and each has at most 16 entries. Canonical descriptor preparation makes one provider lookup/descriptor operation per entry; identity deduplication performs exact descriptor comparisons against prior distinct identities, worst-case `O(E²)` comparisons per group (including byte equality over bounded descriptor fields). Threshold reachability sorts scalar weights by selection sort, `O(E²)`, then sums the largest `min(p_k, distinct_identities_k)` weights. Here `p_k` is that group's actual supplied proof count: `native_tx_proof.rs` passes `max_proof_count=proof_count` to the per-keyset evaluator, which uses it for `summarize_workspace`. It is not the configured transaction-wide maximum of eight.

Signature work generally satisfies `attempts <= sum over groups k and their proofs i of matching_entries(k,i) <= sum_k(p_k * encoded_entries_k) <= 128`, since each group has at most 16 encoded entries and `sum(p_k)<=8`. Matching counts can differ by each proof's suite; early structural, semantic, proof or backend refusals may perform fewer attempts. The genuine all-matching-suite workloads A, B and D witness the 128-attempt bound with a full candidate scan, including B's late-invalid control. Successful exact-index coverage requires `p_k>=required_indices_k`; each group's threshold requires at least its independently calculated minimum distinct-key proofs `r_k`. Thus feasibility requires `sum(max(required_indices_k,r_k)) <= sum(p_k) <= 8`. This is necessary, not sufficient: signatures, provider behavior, and each group's actual weight still have to pass. In particular, successful preparation under eight proofs says nothing about feasibility if other groups consume part of the same transaction-wide budget.

Create parsing traverses the complete call input before output. Its borrowed parser traverses `O(E)` entry prefixes and key spans without copying or scanning key payloads; it checks input framing/entry/key budgets, computes checked output length `12 + 6*n + sum(key_bytes)`, performs canonical semantic admission over every entry, and only then requests one destination reservation and encodes/copies the output bytes. Creation preparation separately uses its configured maximum distinct-proof budget of eight, summing the largest `min(8, distinct_identities)` weights for reachability; unlike transaction evaluation, no actual supplied group proofs are available here. The semantic workspace is gone before destination reservation. Parsing, sizing, semantic admission, and output encoding each traverse entries; bounded call bytes limit admitted size but do not guarantee low operational latency.

### Live owners and what is not measured

The source’s scopes do not make all observed objects simultaneous. The preflight bitmap is local to preflight and is released on return; the preflight group result and the caller-owned borrowed-proof array span the group loop. For one group, one returned owned `Account` is live while its parser view borrows the account bytes and keyset proof evaluation borrows the key/signature/provider data. The per-keyset proof workspace contains candidate references, canonical identity records, verified flags, and a scalar threshold-weight scratch array; it is dropped before the next account read. The transaction, its metadata/signature vectors, store contents, and provider are caller-owned and are outside fixed-helper workspace totals.

Create preparation borrows the caller's call-data view, performs semantic analysis, drops its identity/threshold workspace, and subsequently owns the reserved output `Vec` moved into the returned `Account`. In workload D the untimed returned Account is moved into store ownership; the independent expected Account remains a comparison oracle. Store contents remain independently owned; the in-memory bounded read materializes a second owned account buffer while the stored account remains present. Source-derived expected vector reservation requests and observed lengths/capacities are reported separately above. Provider/backend allocations, ML-DSA cryptographic workspace, allocator metadata/rounding, compiler frames/inlining, and process RSS are not measured or bounded by these figures.

Existing internal compiler-derived tests were reused, not copied or exposed through new public APIs: `native_tx_proof.rs::run422_native_tx_proof_reports_compiler_object_sizes` reports coverage 8,192 bytes, its `G=2` preflight 136 bytes, `P=2/P=4` borrowed proof workspaces 48/96 bytes, a group 48 bytes and proof 24 bytes; `keyset_proof.rs::run422_keyset_proof_scalar_aggregate_overflow_and_workspaces` reports the 16-entry proof workspace 1,688 bytes and identity workspace 904 bytes; `keyset_validation.rs::run422_keyset_semantics_usize_max_budgets_are_not_storage_sizes` confirms 56-byte records and a 904-byte 16-entry workspace; `keyset_create.rs::run422_keyset_create_preparation_compiler_object_inventory` reports a 64-byte create view and semantic workspaces for `E=0/1/2/4` of 8/64/120/232 bytes. These are compiler/profile-specific object sizes, not a physical-memory, stack-frame, stack-usage, or RSS guarantee. The selected candidate’s private `G=8/P=8` layouts were not separately measured by duplicating private types.

## Compatibility and caller mapping

The scope is the native `qbind_wire::tx::Transaction`, not `qbind_ledger::QbindTransaction`/VM execution and not `qbind_runtime::QbindTx`/EVM execution.

| Behavior | Existing native path | Isolated path / evidence |
|---|---|---|
| Empty auth and signer-index coverage | `verify_transaction_auth` refuses empty auth and requires auth coverage of every bit-0 signer index; repeated account IDs do not cover another index. | Same structural intent with typed errors and complete preflight before external work. See `auth.rs` and `native_tx_proof.rs::run422_native_tx_proof_preflight_refusals_make_no_external_calls`. |
| Owner, executable, returned account ID | Legacy auth loads with `get` and does not check these returned-account fields. | Bounded reader requires requested ID, keyset-program owner, non-executable account, and data length. The compatibility harness provides an executable faulty-backend witness for each field: legacy accepts the valid keyset bytes, while the isolated path returns the exact owner/executable/ID error before crypto. Existing reader unit tests also cover the helper errors. |
| Thresholds and duplicate canonical identities | Legacy auth finds one key by suite ID and does not enforce weighted threshold or canonical duplicate-weight consistency. | The isolated evaluator canonicalizes all entries, refuses conflicting duplicate weights/unreachable threshold, and counts verified distinct identity weight. Executable witnesses: legacy accepts a valid one-key signature at threshold 2 and a conflicting-weight duplicate; isolated refuses `ThresholdUnreachable` and `ConflictingDuplicateWeights`. |
| Multiple same-suite entries and aliases | Legacy `find`s the first entry for a suite; a valid later same-suite key cannot rescue an invalid first entry. It does not treat suite aliases as a shared canonical weighted identity. | The isolated path scans every candidate of each proof’s suite and deduplicates by exact canonical descriptor. Witness: legacy refuses a signature by the second same-suite key; isolated accepts. Existing alias/duplicate tests: `keyset_validation.rs::run422_keyset_semantics_genuine_mldsa_stored_and_create_aliases` and `keyset_proof.rs::run422_keyset_proof_duplicate_alias_repeated_and_distinct_signatures_count_once`. |
| Every supplied proof | Legacy verifies auths in order and returns on the first failure; it has no threshold-success short circuit because it has no threshold semantics. | Isolated evaluation verifies every supplied proof even after threshold is met; workload B and its late-invalid control observed all 128 candidate attempts. |
| Unsupported bounded read | Legacy needs only `get`. | The bounded-read default is `Unsupported`, with no fallback to `get`; helper refuses. The compatibility harness confirms legacy succeeds via a get-only store while the isolated evaluator refuses without fallback. Existing default/no-fallback controls are also in `store.rs` and `keyset_account.rs`. Only `InMemoryAccountStore` is a non-test `AccountStore` implementation in the repository; node callers are generic over the trait, and no representative deployed persistent implementation’s bounded-read guarantee was found. |
| Malformed or semantically invalid unused entries | Legacy decodes the complete `KeysetAccount` framing, so malformed wire/state encoding anywhere refuses; well-framed unused entries are not all canonicalized or semantically admitted before checking the selected key. | The borrowed parser checks complete framing and the evaluator semantically prepares every entry before signatures; unsupported/malformed descriptors, duplicate conflicts, and unreachable thresholds in unused entries can refuse. Executable witness: legacy accepts a keyset with a valid first entry and unused unsupported-suite entry; isolated refuses `SuiteNotFound`. Exhaustive framing and semantic boundary tests are reused (parser tests in `qbind-serde/src/keyset.rs` / `qbind-wire/src/keyset.rs`; semantics tests in `keyset_validation.rs`). |
| Resource-limit rejection | Legacy checks wire account/auth counts but has no configured signer, distinct-group, signature-byte, aggregate-signature, stored-data, or keyset entry policy. It accepts nine genuine proofs repeated for one required signer index. | These are explicit helper inputs and fail with typed errors under this harness only; the same nine-proof transaction refuses as `AuthenticationProofCountLimit` before reads/provider work. There is no approved production profile and no transaction-body/call-data operational limit. |
| Create preparation vs creation | `KeysetProgram::handle_create` decodes the create call, checks target absence with legacy `get`, copies entries, encodes, then `put`s. It does not enforce the proposed byte caps, suite/descriptor semantics, or threshold reachability. Normal `TxExecutor` first invokes native transaction auth; direct program tests invoke the program API directly. | `prepare_keyset_account_bounded` validates and produces an owned Account only. It does not check target absence, authorize payer/target, write, or establish atomicity. Existing `keyset_program_tests` and the preparation harness cover their separate behaviors; preparation success is not a creation authorization. |

The account-store contract says each bounded read is coherent for that account; several reads do not imply a common transaction snapshot. A mutable reference at the caller boundary alone does not establish that every backend prevents independent/external state changes. The test provider registers a real ML-DSA-44 suite as ID 100. `Node` accepts an injected `CryptoProvider`; the P2P builder can register ML-DSA-44 under a supplied suite ID for transport. Neither fact establishes governance, an allowed native-account suite registry, alias policy, key rotation, or provider consistency for deployed native authorization.

Current path: `Node::apply_block` decodes proposal blobs as native `Transaction` and passes them in order to `BlockExecutor`; `BlockExecutor` calls `TxExecutor::execute_transaction` sequentially. `TxExecutor` constructs `ExecutionContext`, calls `verify_tx_auth`, then dispatches the program. `ExecutionContext::verify_tx_auth` delegates to `verify_transaction_auth`. The proposal application is not the separate VM/EVM transaction route.

Independent requirements remain unresolved by proof summaries: program-specific authorization of target/authority, payer authorization, nonce and replay enforcement, provider governance, a transaction-wide snapshot/version contract, and target-absence plus atomic create/write ordering. Existing block execution is sequential and does not roll back prior successful transactions when a later transaction fails. No representative deployed transaction/keyset corpus, persistent backend implementation satisfying bounded-read semantics, or target hardware was available. Unit-generated keys and this host’s benchmark do not establish compatibility or performance approval.

## Concrete proposed integration slice — decision required, not implemented

**Caller boundary:** only native `Transaction` handling at `TxExecutor::execute_transaction`, at the current `ExecutionContext::verify_tx_auth` boundary; no VM `QbindTransaction`, EVM `QbindTx`, creation caller, node default, or automatic fallback. A first conservative slice would run the bounded evaluator as an additional explicit admission gate and discard its diagnostic summary, while retaining the legacy verifier as an independent required check and retaining all later program-specific authorization. This avoids treating a summary as an execution capability and avoids widening acceptance during the first integration. It can still reject previously accepted transactions and adds repeated crypto/read work; it is not behavior-neutral.

**Combined-route resource qualification:** retaining legacy `verify_transaction_auth` also retains its call to `qbind-hash/src/tx.rs::tx_digest`, which materializes a signing-body preimage via `tx_sign_body_preimage`. This adds `O(body length)` heap allocation and copying (body length `91 + 36*A + C`), despite the isolated evaluator's streaming hashing. The isolated helper's work/ownership accounting is not a bound for this proposed combined execution route. Its complete work, simultaneously live ownership, and snapshot contract require separate review. The proposal remains unimplemented; this finishing pass neither changes the design nor activates any caller or introduces a body cap.

**Prerequisites:** approve a versioned per-call policy/configuration; implement bounded reads for every intended backend and specify snapshot consistency; govern allowed provider suites/aliases and key lifecycle; specify program-specific authority, payer, nonce/replay checks; define target absence and atomic write ordering; assess compatibility against deployed transactions/keysets and real target hardware; define block-level resource/failure behavior. Do not introduce fallback to legacy reads.

**Error handling proposal:** preserve typed evaluator failures through the caller boundary until mapping. Map structural/resource and framing/semantic refusals to explicit deterministic native-admission errors; map bounded-read unsupported/backend/oversized/account-metadata failures to explicit account-admission errors; map invalid/ambiguous/backend verification failures to explicit authentication errors. Do not broadly collapse errors into success-shaped outcomes. The current `ExecutionError` mapping has not been added; its exact public variants/messages and observability must be approved.

**Required integration tests:** every legacy/new compatibility row above, including both witnessed acceptance-direction differences; empty/exact-index coverage; all matching candidates and late invalid proof; configured proof/entry/signature/data boundaries plus retry; unsupported bounded store and faulty backend; wrong ID/owner/executable; malformed unused entry and duplicate/alias cases; threshold isolation across groups and global budget contention; immutable transaction and unchanged store on refusal; snapshot/version changes across groups; payer/nonce/replay and program authority; target-present and target-absence races, atomic write failures, and sequential block failure behavior. Add corpus-based compatibility and target-hardware performance/resource tests before rollout.

**Policy approvals still required:** all listed signer/group/proof/entry/key/data/identifier/signature limits; whether the 65,536-byte create input choice and separate output cap are acceptable; threshold and duplicate/alias semantics; treatment of unused malformed or unsupported entries; owner/executable/returned-ID requirements; legacy compatibility and precise error mapping; supported provider suites and governance; accepted snapshot and create atomicity guarantees; and whether/when any call site may activate. No passing test resolves these decisions.

## Historical validation and delivery record

Target: `x86_64-unknown-linux-gnu`, Linux 6.12.8+, AMD EPYC 9V74, 2 visible CPUs. Compiler: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, LLVM 23.1.1. Workspace `[profile.dev]` and `[profile.test]` both set `debug=0`, `strip="debuginfo"`, and `incremental=false`; ordinary tests and `cargo check` use their respective workspace profiles. Release tests use `--release` with Cargo’s release defaults (no workspace release-profile override). No timing threshold was applied.

| Literal command | Result |
|---|---|
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --test run_422_native_admission_resource_tests -- --nocapture --test-threads=1` | Exit 0 at tested source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`; 6 selected, 6 passed, 0 failed, 0 ignored. |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked --release -p qbind-ledger --test run_422_native_admission_resource_tests -- --nocapture --test-threads=1` | Exit 0 at source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`; 6 selected, 6 passed, 0 failed, 0 ignored. |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger` | Exit 0 at source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`; 26 per-target results, 732 selected, 716 passed, 0 failed, 16 ignored (all ignored tests are doc tests). The new harness is also run separately; do not add overlapping command counts. |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-system --test keyset_program_tests -- --nocapture` | Exit 0 at source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`; 2 selected, 2 passed, 0 failed, 0 ignored. |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo check --locked -p qbind-node` | Exit 0 at source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`; compilation only, no test count. `qbind-consensus` emitted 37 warnings and `qbind-node` 8 warnings; no errors. |

Historical formatting command: `rustfmt --edition 2021 crates/qbind-ledger/tests/run_422_native_admission_resource_tests.rs` performed formatting, not a `--check` validation (exit 0; original test bytes are blob `71ae4e8b294d2994d55d4127db25e92a83602b89` at tested source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`). Preliminary attempts are reported separately: the first exact focused build exited 101 because `libclang.so` was missing from `/usr/lib/llvm-18/lib`; `libclang-18-dev` was installed as environment preparation. The next compile exited 101 on test-only `ExecutionError` equality assertions and an unused `mut`; those assertions were corrected before the original tested revision. Neither preliminary attempt selected or ran tests. The locked dependency build completed without changing Cargo manifests or lockfile.

Existing private-object inventory commands at source `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4` (each exit 0, 1 selected/passed, 0 failed/ignored; 345 filtered from the library binary) were `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --lib run422_native_tx_proof_reports_compiler_object_sizes -- --nocapture`, `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --lib run422_keyset_proof_scalar_aggregate_overflow_and_workspaces -- --nocapture`, `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --lib run422_keyset_semantics_usize_max_budgets_are_not_storage_sizes -- --nocapture`, and `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --lib run422_keyset_create_preparation_compiler_object_inventory -- --nocapture`. These reported ordinary-profile compiler sizes; they are source-attributed observations, not added/duplicated production layouts.

The historical evidence updates append to, and preserve byte-for-byte, the complete starting documents: D7 is 2,589,944 bytes, CRLF-only with no terminal newline; contradiction is 2,646,296 bytes, LF-only with no terminal newline. Both retain mode `100644`; the appended text uses each file's original EOL and no-terminal-newline convention. The preserved posture remains: `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`; `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`; §13.6 whole-lifecycle INCOMPLETE; activation DISABLED; public DevNet NO-GO; durable anti-rollback NOT-ESTABLISHED; C4/C5 OPEN; RS1 OPEN. This assessment does not approve limits, activate authorization or creation, close F1/F2, or establish independent source-review acceptance or deployed-path readiness.

## Acceptance finishing-pass validation and delivery record

Clean starting HEAD `7bcaaeaaa359b672df5b9b5346b37eb8dfbf0949` and tree `6db553e9174758e9d27e5fd9ed40fcce8511909f` were verified before editing on `copilot/run-422-native-admission-resource-assessment`. No applicable `AGENTS.md` was found. Finishing-pass tested source HEAD is `a05bafe9bf3fca179e7fdc253064b0b7f1f404d2`, tree `1865358fd0cacf16ce7d15715a8b8b051382b79c`, and test blob `1056c37978c7bb23e14ae7938e690b107c849e02`. All six existing tests and their substantive assertions remain. Actual prepared-Account handoff and the reservation-request label are the only Rust corrections.

Fresh environment: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`, LLVM 23.1.1, target `x86_64-unknown-linux-gnu`, Linux 6.12.8+, AMD EPYC 9V74 80-Core Processor, two visible CPUs. Three monotonic `Instant` samples per genuine workload, no latency threshold. Ordinary `[profile.test]` uses `debug=0`, `strip="debuginfo"`, `incremental=false`; optimized `--release` uses Cargo release defaults with no workspace release override. No environment/profile overrides beyond the literal `LIBCLANG_PATH` and `--release` below. Both profile commands were launched concurrently; Cargo reported package-cache lock waits outside the timed closures. No dependency installation, preliminary failure, full ledger/system suite, node compilation, or internal inventory rerun occurred in this pass.

| Literal finishing-pass command | Result at tested source `a05bafe9bf3fca179e7fdc253064b0b7f1f404d2` |
|---|---|
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --test run_422_native_admission_resource_tests -- --nocapture --test-threads=1` | Exit 0; 6 selected, 6 passed, 0 failed, 0 ignored, 0 filtered; runner elapsed 6.64 s. |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked --release -p qbind-ledger --test run_422_native_admission_resource_tests -- --nocapture --test-threads=1` | Exit 0; 6 selected, 6 passed, 0 failed, 0 ignored, 0 filtered; runner elapsed 0.21 s. |
| `rustfmt --check --edition 2021 crates/qbind-ledger/tests/run_422_native_admission_resource_tests.rs` | Exit 0; scoped formatting check, no test selection or file mutation. |

Historical full ledger, system, node-check and workspace-inventory results above retain their original source attribution `611c2fdca8d06b5ac2c9179e9cd56f6d46464fe4`; none are claimed for the finishing revision. Focused counts overlap and are not additive.

Fresh counted harness-workload elapsed samples, all attributed to finishing-pass tested source `a05bafe9bf3fca179e7fdc253064b0b7f1f404d2`:

| Genuine workload | Ordinary first / subsequent samples | Optimized first / subsequent samples |
|---|---|---|
| A: eight groups, sixteen keys each | 542.056497 ms / 550.680184 ms, 553.742488 ms | 16.266098 ms / 16.413917 ms, 16.066672 ms |
| B: one group, eight proofs, threshold one | 480.704321 ms / 479.993786 ms, 477.586710 ms | 13.539742 ms / 13.952104 ms, 13.330912 ms |
| Create preparation | 9.388151 ms / 9.361421 ms, 9.428651 ms | 447.604 us / 470.859 us, 445.010 us |
| Actual prepared-account proof composition | 458.276665 ms / 456.810199 ms, 460.451437 ms | 13.725548 ms / 13.045708 ms, 13.740780 ms |

The closures include counter/assertion work and, where applicable, output destruction; no isolated backend benchmark or production/cross-machine latency bound follows. Observed output length/capacity remain 21,100/21,100 bytes; 21,100 is separately the source-derived expected reservation request, not allocation-boundary instrumentation.

Finishing-pass evidence appendices preserve the complete starting D7 blob `4395361e9d8f8b6136c6a61936e4c9bb9bf3b16b` (2,592,706 bytes, CRLF-only, no terminal newline) and contradiction blob `a3765619985764c75fd9e4b938ec542c36cf2981` (2,649,048 bytes, LF-only, no terminal newline). All four paths retain mode `100644`. Byte-prefix, EOL/EOF and final-test-blob equality checks accompany delivery, separately from ancestry verification against the starting HEAD. Production/prerequisite Rust, dependencies, limits and callers remain unchanged.

CRLF-aware precommit checks `git -c core.whitespace=cr-at-eol diff --check` and `git -c core.whitespace=cr-at-eol diff --check 7bcaaeaaa359b672df5b9b5346b37eb8dfbf0949` exited 0 on the corrected source and evidence. Delivery repeats `git -c core.whitespace=cr-at-eol diff --check` and `git -c core.whitespace=cr-at-eol diff --check 7bcaaeaaa359b672df5b9b5346b37eb8dfbf0949 HEAD` for the complete committed finishing delta. Exact four-path scope/modes, both evidence-prefix/EOL/EOF checks, all six retained test names and final Rust correspondence to the tested blob passed. Final HEAD/tree, complete changed-path mode/blob manifest, clean worktree and remote-tip equality are reported after the documentation-only commit and non-force task-branch push; these identities cannot be embedded in their own hashed document. All candidate limits remain UNAPPROVED; all preserved posture strings above remain in force, with no F1/F2 closure or deployed-path readiness.
## RUN 422 - Native transaction authentication streaming digest

This current-component update is tested at Rust commit `fe4ae05a746787cfa5424d487beba8db6e8cb68a`, tree `dc533c196f33a02fd6cf0301783881cff8848db0`, parent `38a7b18158f8f1e92bd4d454a705284ae792bca4`. The required starting commit/tree were `38a7b18158f8f1e92bd4d454a705284ae792bca4` / `d12fa03c52b1e41cbbd2c6a6833c0f40c5809ff8`.

`verify_transaction_auth` now invokes `qbind_hash::tx::try_tx_digest_streaming(tx)` exactly once, after its existing empty-auth, u16 account/auth count, exact index, required-signer marker and complete exact-index coverage checks, and before the first account read or provider lookup. The resulting digest is reused in the unchanged ordered loop for every supplied auth entry. The old `tx_digest(tx)` caller path, which materialized the signed-body preimage with `tx_sign_body_preimage`, is no longer used by this verifier. All prior checks, error payloads, account/store operations, keyset decoding and matching, suite lookup, cryptographic verification and first-failure behavior remain unchanged.

The checked error mapping is exhaustive and uses fixed strings: `AccountCountTooLarge` -> `transaction account count exceeds wire limit`; `CallDataLengthTooLarge` -> `transaction call-data length exceeds wire limit`; `LengthOverflow` -> `transaction signed-body length overflow`. There is no formatting, fallback, panic or success-shaped error path. Earlier wire count validation remains first, so an account count beyond u16 is refused by the existing preflight; helper scalar tests are not evidence of an oversized transaction reaching this caller.

For wire-representable transactions, the canonical digest remains the legacy digest. The hashed stream remains the 8-byte domain tag followed by 91 + 36*A + C bytes (A account metadata entries, C call-data bytes). Hashing work is O(A+C), using the existing streaming helper's constant-size hashing state. This is specifically removal of the verifier component's signing-preimage materialization; it is not a bound or guarantee for the whole verifier, compiler stack, physical memory, latency or all transaction paths.

Explicit remaining allocations/work: caller-owned transaction and signature storage; legacy `AccountStore::get` and its account-data clone; owned keyset decode; provider/backend and cryptographic workspace; and any other callers of unchanged legacy digest APIs. The bounded evaluator plus legacy-verifier composition remains unimplemented. Historical assessment findings remain attributed to their original source/revision: this change removes only the legacy signing-preimage allocation from the active native verifier component. It does not resolve repeated reads/cryptography, common-state consistency, or other integration prerequisites, and it establishes no complete native authorization.

Acceptance controls are detailed in the appended RUN 422 evidence entry in `QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`: genuine ML-DSA-44 signatures use the legacy digest as an independent oracle; a recording wrapper delegates to real verification and observes the actual verifier digest per call; a 256 KiB call-data workload and multiple proofs are covered; changed content with an unchanged signature refuses; an earlier valid proof followed by an invalid proof refuses; and a valid re-signed retry succeeds. Existing structural-only suites are clearly separated from this cryptographic evidence. No large-input threshold is proposed or approved.

The resource assessment and admission contract remain draft and unapproved. No candidate limit is approved. The narrow digest change closes no F1/F2 item and does not establish deployed-path readiness. See the D7 append for all literal validation commands, actual counts/results, environment-only libclang preparation, preliminary failures and assertion mapping.

## RUN 422: Borrowed keyset framing in native authentication

This append-only update is tested against Rust source commit `cefe162c7e11959d5fed4f352a1dbf7118022415`, tree `94e7ed1c29ec628cf143a83886bd1970976d67e5`, whose parent is required starting commit `e634fad3a655ee9930c7b77c56d15e57d0e93e99` (starting root tree `fbc3a7adbbbdd3a32517e8d2ae89e78abb44db3b`). Source/tests were committed separately from this evidence. The starting commit's raw parent header names `38a7b18158f8f1e92bd4d454a705284ae792bca4`; that object is unavailable and the starting commit is a shallow boundary, so no established ancestry beyond that boundary is claimed.

`verify_transaction_auth` retains its existing checked streaming digest, one call after structural preflight, and digest-error mappings. `verify_single_auth` retains `AccountStore::get` and `AccountNotFound`, then calls the existing `parse_stored_keyset` over the returned `account.data`. Explicit `StoredKeysetLimits` are `max_encoded_bytes = account.data.len()`, `max_entries = usize::from(u16::MAX)`, `max_key_bytes = usize::from(u16::MAX)`, and `max_total_key_bytes = account.data.len()`. They preserve representable u16 framing; they are compatibility settings, not operational resource limits or the isolated 8/16/65,536 proposal. They do not bound acquiring/materializing the Account, prevent the existing `get` clone, or provide a useful data cap. No bounded reader is wired in.

The parser validates complete framing, including unused later entries and trailing bytes, before selection or provider lookup. The verifier then keeps the existing first matching `suite_id` selection and verifies that selected borrowed key. Exact errors remain: trailing parser bytes map to `SerializationError("trailing bytes in KeysetAccount account")`; all other parser refusals map to `SerializationError("decode KeysetAccount")`; missing matching suite remains `InvalidCallData("no key in keyset for given suite_id")`; unavailable provider remains `CryptoError("signature suite not found")`; and bad signatures remain `CryptoError("signature verification failed")`. Missing accounts remain `AccountNotFound`. Auth order, first failure and one get per processed auth are unchanged.

Genuine ML-DSA-44 tests use the actual verifier and real signature adapter. A test store observes the data address/range of the Account actually returned by `get`; a wrapper delegates to real verification while recording the public-key slice. The assertion proves the selected key's exact bytes/length and address span at offset 18 within that returned buffer. This is a borrowing regression witness, not allocator-wide or physical-memory measurement. Tests also cover truncated header, insufficient advertised entry data, truncated key body, a valid matching first entry followed by malformed unused framing, trailing bytes, a well-framed zero-entry keyset, no matching suite, missing account, unavailable provider and bad signature. Parser failures assert exact errors, one expected get, zero lookup/verification, zero writes/deletes, and unchanged complete transaction/store state. Genuine same-suite keys prove a signature valid only for a later matching entry fails with the first wrong key, while placing the valid key first succeeds. Version/reserved values, thresholds, weights and unused semantic content remain non-admission inputs. Existing multiple-auth and streaming-digest compatibility/re-sign retry tests remain.

Source inspection supports removal of the verifier's owned entry vector and per-key copies after the Account read; the executed pointer observation independently supports borrowing of the selected key. Neither establishes that the verifier is allocation-free. Caller storage, `AccountStore::get` materialization/cloning, provider/crypto workspace, repeated per-auth reads/parsing, and other owned-decoder callers remain. For each processed auth, framing traverses the encoded entries and first-match selection may traverse them again; key bodies are borrowed. Historical resource evidence remains attributed to its original source and workload, not retroactively treated as a measurement of this caller. Other isolated admission helpers remain unwired; budgeted weighted-evaluator composition and common-state guarantees remain unimplemented.

### Required validation on the tested Rust source

| Literal command | Exit | Selected | Passed | Failed | Ignored |
|---|---:|---:|---:|---:|---:|
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --test tx_auth_verifier_tests -- --nocapture` | 0 | 18 | 18 | 0 | 0 |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-serde` | 0 | 46 | 46 | 0 | 0 |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger -p qbind-runtime -p qbind-system` | 0 | 959 | 942 | 0 | 17 |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-node --test block_apply_tests -- --nocapture` | 0 | 6 | 6 | 0 | 0 |
| `LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo check --locked -p qbind-node` | 0 | Compilation only; not a test command | - | - | - |
| `rustfmt --check --edition 2021 crates/qbind-ledger/src/auth.rs crates/qbind-ledger/tests/tx_auth_verifier_tests.rs` | 0 | Formatting check | - | - | - |
| `git -c core.whitespace=cr-at-eol diff --check` | 0 | Whitespace check | - | - | - |
| `git -c core.whitespace=cr-at-eol diff --check e634fad3a655ee9930c7b77c56d15e57d0e93e99 HEAD` | 0 | Whitespace check | - | - | - |

Selected means passed + failed + ignored; overlapping command counts are not additive. The qbind-serde doctest harness selected zero tests and is not counted as passing tests. The node cargo check is compilation-only.

Preliminary attempts are separate from the final results above. The first focused `cargo test --no-run` exited 101 because `libclang.so` was unavailable; `libclang-18-dev` was installed in the environment only, with no repository dependency changes, and all required commands above then passed. The first rustfmt check exited 1 on formatting differences; `rustfmt --edition 2021` was applied, and the required final check exited 0.

Preserved posture: `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`; `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`; section 13.6 whole-lifecycle `INCOMPLETE`; activation `DISABLED`; public DevNet `NO-GO`; durable anti-rollback `NOT-ESTABLISHED`; C4/C5 `OPEN`; RS1 `OPEN`; all candidate limits `UNAPPROVED`. Whole native-admission, governance, validator and keyset authority contracts remain `DRAFT / NOT APPROVED / NOT IMPLEMENTED`. This framing-only change does not close F1/F2, establish complete authorization, or provide deployed-path readiness.


## RUN 422 - Native returned-account metadata admission (append-only evidence)

Tested source commit `42fa16cbe5074b3b75330630fe9793a2a1ecf4d6` / tree `0279aecc79425acbf68c8d386385c02b8c53da13` is directly parented by baseline `7b88dfedfbed80b6d4ffdd3180f118df1d3ce137` / tree `ce93cb505d09d73470fcdc550c0c885b9c6e363e`. The required commit/tree objects are available and match; the baseline parent header names unavailable object `e634fad3a655ee9930c7b77c56d15e57d0e93e99` at the shallow boundary. This records availability and ancestry separately; no ancestry beyond the boundary is asserted.

Immediately after legacy `get`/missing handling and before parsing, native auth now refuses returned ID mismatch (`InvalidCallData("keyset account id mismatch")`), wrong owner (`AccountOwnerMismatch`), then executable account (`InvalidCallData("keyset account is executable")`). ID > owner > executable > parser is the exact order; missing remains `AccountNotFound`. These intentional changes reject metadata the native route previously accepted. Once admitted, the digest, one-get-per-auth, complete framing, existing limits/error mappings, first matching suite selection, and borrowed actual-buffer key path are unchanged.

Evidence mapping: the verifier test adds genuine ML-DSA-44 metadata/error/precedence controls, synthetic backend-response returned-ID mismatch, zero provider/crypto work, preserved full transaction/store, malformed-data precedence, and genuine multi-auth failure/retry; existing borrowing, same-suite, missing-account, structural, and re-sign retry tests remain (20 passed). The resource harness migrates only its native metadata claims to exact refusal plus one `get`, zero provider/descriptor/verification work, zero mutations, and preserved state; isolated typed errors, get-only success, bounded-read Unsupported/no fallback, nine proofs, and other compatibility witnesses remain (6 passed). Real TxExecutor controls prove each fault stops after auth-account lookup and valid metadata reaches only the existing absent-target authority refusal (5 passed).

This change does not yield resource approval or a timing conclusion. Fields are supplied by the backend; metadata comparison neither authenticates it nor proves canonical state/freshness, and fabricated matching key bytes remain possible. Account acquisition/cloning precedes these constant-size checks; they do not parse/copy data. Repeated reads, common-state consistency, persistence, crash/restart, anti-rollback, authorized creation history, owner consent, and complete program/transaction authority remain unestablished. No operational profile or candidate limit is approved. Historical acceptance witnesses remain historical; all preserved posture values remain unchanged.

Validation was on the tested source above. Exact results: verifier command selected/passed/failed/ignored `20/20/0/0`; resource harness `6/6/0/0`; executor `5/5/0/0`; ledger/runtime/system packages `962/945/0/17`; Node block tests `6/6/0/0`; Node cargo check exit 0 (compilation only); required rustfmt and both whitespace diff checks exit 0. Literal commands and preliminary environment preparation/failure are recorded in the matching D7 evidence append. No repository dependency or lockfile changed.

## RUN 422 follow-up: returned provider suite-ID consistency

Tested source `0a74f0d91cc6df588540d3fe470389e63d0edc38`, tree `4d8f0fcc672b42fa481804f7c0819dbd16d39bd0`, adds only the post-lookup reported-ID guard to production native auth. It reads the same returned suite object's ID once per processed proof and returns exactly `ExecutionError::CryptoError("signature suite id mismatch")` before verify if inconsistent. No extra lookup, descriptor or length query is added. Structural preflight, one checked streaming digest, AccountStore::get acquisition/cloning, metadata checks, complete borrowed framing, first-match key selection, borrowed selected key, first-failure ordering and existing error mappings are unchanged.

Genuine ML-DSA-44 matched and ID-3 registered-alias controls succeed. The inconsistent returned-ID provider is a synthetic fault, deliberately distinguished from genuine cryptographic acceptance. One-auth mismatch proves one requested-account read, one requested-ID lookup, one ID observation, zero verify/digest/key observations in verify, no mutation and complete transaction/store preservation. Framing and missing-entry combined controls prevent provider access; invalid signatures preserve mismatch-before-verify precedence, matched invalid-signature errors and genuine corrected retry. A later-proof mismatch follows exactly one earlier genuine verify; a fresh matched retry verifies both proofs again. Actual TxExecutor mismatch stops before the absent target read; matched genuine authentication reaches that read and the unchanged program refusal, NOT successful execution.

Literal commands, exit codes, test-to-claim mapping, old/tested mode/blob tuples, baseline/history and separate libclang preparation failure are in the matching D7 append. Final counts per command (selected/passed/failed/ignored): verifier 24/24/0/0; executor 6/6/0/0; ledger/runtime/system 967/950/0/17; node block tests 6/6/0/0. All exit 0; node check is compilation only (exit 0). Required rustfmt and working/committed-range whitespace checks exit 0. Overlapping suites are not summed; no new ignored tests, dependency changes or broadened validation.

This intentionally refuses inconsistent providers previously allowed to reach verify, but does not hardcode 100 or reject properly registered aliases. It proves only requested-ID versus reported-ID consistency: a misreporting provider can still lie about the algorithm executed. Provider trust, registry governance, lifecycle policy, canonical key identity and full authorization are not established. Weights/thresholds, canonical identity enforcement, repeated reads/cryptography, account caching, bounded reads, common-state consistency, program/payer authority, freshness and resource-policy approval remain outside this slice. No new timing, RSS, allocation-free, persistent-storage or deployed-path claim follows.

Required baseline is `3900e7615d076788dc4ac0d63f4a7c6ac110dc32`, independently verified tree `665aaf66596c90ae2020203d65254ad2c9648a99`; clean starting worktree; origin `https://github.com/olivexo28/QBIND`. The raw parent header names `a6ad7b0a60ad2ff590b0aa99defea88bc45ea1ba`, whose object is unavailable at the baseline shallow boundary, not absent from the header. New ancestry is established from actual parent edges, never tree equality. The seven-path scope, exact starting document byte prefixes/modes/EOL/EOF and protected Run375 blob remain preserved.

Preserve `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`, `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`, section 13.6 whole-lifecycle INCOMPLETE, activation DISABLED, public DevNet NO-GO, durable anti-rollback NOT-ESTABLISHED, C4/C5 OPEN, RS1 OPEN and all candidate limits UNAPPROVED. Whole native-admission and authority contracts remain DRAFT / NOT APPROVED / NOT IMPLEMENTED. No F1/F2 closure, resource approval or release approval follows.

## RUN 422: stored-keyset format admission resource boundary (2026-11-02)

This slice intentionally introduces a narrow native-authentication compatibility restriction: after successful complete stored-keyset framing, only version 1 and zero header reserved0/reserved1 and every entry reserved0 are admitted. It is not an already-enforced protocol rule or approval of the whole native-admission contract. Framing-only parse_stored_keyset and isolated helpers remain unchanged and may still accept other versions/reservations; isolated create preparation preserves the supplied call.version. Production keyset creation remains unavailable.

The ordered errors are exactly ExecutionError::InvalidCallData("unsupported keyset account version"), then ExecutionError::InvalidCallData("nonzero keyset account reserved bytes"), then ExecutionError::InvalidCallData("nonzero keyset entry reserved bytes"). Complete malformed framing and trailing bytes retain their existing serialization errors ahead of these checks. Existing structural preflight, checked streaming digest, get/missing and returned ID/owner/executable admission remain earlier. First matching suite selection, provider-None handling, returned-suite ID guard and borrowed-key verification remain later.

The all-entry reservation check adds at most O(entry_count) work per processed authentication and O(1) control storage, using the existing borrowed iterator and borrowed key bodies. It can stop at the first nonzero reservation. No entries are collected, key bodies copied or validation vector allocated; these checks perform no provider, descriptor, length or signature queries. This is source-level accounting only, not a measured latency, RSS or allocator guarantee and not an allocation-free claim for the complete verifier. Account acquisition/cloning, repeated reads/parsing/cryptography, account caching, snapshot guarantees, bounded reads, resource caps and operational limits remain unresolved.

The matching D7 append maps the genuine ML-DSA-44 focused controls, eleven independent one-field refusals, complete-entry/other-suite coverage, combined error-precedence matrix, historical witness migration and later-auth corrected-store retry. It also records the actual TxExecutor control: format refusal precedes target read with zero provider/verify work; valid-format genuine authentication reads the absent target and retains ProgramError("native keyset creation authority unavailable"), NOT successful transaction execution. Full transaction/store and controlled response snapshots and zero writes/deletes are asserted. The earlier threshold/weight witness now uses admissible stored format; its first-key/later-key behavior and absent threshold/weight enforcement remain separate from format admission.

Stored-format admission is not full keyset semantics, canonical cryptographic identity, backend authenticity or authorization. No Transaction.version, TxAccountMeta reservation, TxAuth.reserved, extra AccountHeader or CreateKeysetCall checks are added. No provider/adapter, parser, serialization, store/interface, isolated-helper, native-program, runtime-production, dependency or lockfile change occurs. Backend authenticity, common-state consistency, positive program/payer authority, replay protection, deployed compatibility, persistence and complete native authorization remain unestablished.

Baseline/history, exact starting byte prefixes and EOL/EOF preservation, tested-source commit/tree, mode/blob provenance, literal final commands, exit codes and non-overlapping per-command test counts are recorded in the matching D7 append. Preparatory missing-libclang failure is separate from final validation; its repair is environment-only.

Preserve D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED; D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET; section 13.6 whole-lifecycle INCOMPLETE; activation DISABLED; public DevNet NO-GO; durable anti-rollback NOT-ESTABLISHED; C4/C5 OPEN; RS1 OPEN; all candidate limits UNAPPROVED. Whole native-admission and authority contracts remain DRAFT / NOT APPROVED / NOT IMPLEMENTED. No F1/F2 closure, resource approval or release approval follows.

## RUN 422 follow-up: conservative individual-key threshold admission

This append supersedes only the active verifier's historical absence of scalar
threshold/weight admission. All preceding bytes are historical evidence and are
preserved verbatim. This is a conservative compatibility restriction, NOT
implementation or approval of full weighted authorization.

### Exact rule and precedence

For EACH supplied TxAuth, retain structural exact-index coverage and digest
compatibility, then independently acquire its requested account in supplied order.
Retain returned AccountId, KEYSET_PROGRAM_ID owner and non-executable metadata
checks; complete stored framing (including unused entries and trailing bytes);
version 1; and all header and all-entry reserved-field checks.

Only after that stored-format admission, read the u16 threshold. Zero returns
exactly `ExecutionError::InvalidCallData("keyset threshold is zero")`, before
missing-entry, provider or signature handling. For a nonzero threshold, select the
FIRST matching suite entry, retaining exactly
`ExecutionError::InvalidCallData("no key in keyset for given suite_id")` when
absent. Before provider lookup compare its u16 weight directly with the u16
threshold. If lower, return exactly
`ExecutionError::InvalidCallData("selected key weight below keyset threshold")`.

Sufficient individual weight preserves provider-None
`ExecutionError::CryptoError("signature suite not found")`, returned suite-ID
consistency `ExecutionError::CryptoError("signature suite id mismatch")`, borrowed
public-key verification, and
`ExecutionError::CryptoError("signature verification failed")` mapping. Neither
threshold nor stored weight is added to or changed in the transaction digest.
No parser, crypto adapter, store/interface, dependency, lockfile, isolated
evaluator, creation helper, native program or production runtime file changes.

A valid signature from an individually insufficient selected key refuses.
Several individually insufficient proofs do not combine in this route.
Repeating a proof does not increase its admitted weight. Weight from another
keyset cannot satisfy this keyset. An unused higher-weight entry does not replace
first-match selection. An individually insufficient extra proof refuses even if
an earlier supplied proof independently met its threshold. Every supplied proof
is processed independently in order until the first failure: no cached admission,
shared-account read reuse or threshold-success short circuit.

This is intentionally stricter than general weighted multisignature
authorization. It introduces no positive authority path and does not establish
canonical duplicate/alias consistency or common-state semantics.

### Genuine controls and synthetic negative controls

`individual_threshold_matched_scalar_boundaries_preserve_complete_state` uses the
same controlled returned-account path, complete transaction, public key and
genuine ML-DSA-44 signature. Genuine controls are threshold/weight 1/1, 2/2 and
65535/65535. Refusals are 0/1 (zero threshold), 1/0, 2/1 and 65535/65534
(insufficient individual weight). Each refusal differs from its adjacent genuine
control only in the intended stored scalar; all other returned bytes and the
signed transaction are held fixed. Refusals observe one requested-account read,
zero provider lookups, suite-ID, verify/digest/key observations and writes/deletes.
Genuine controls observe one lookup, one ID check and one genuine verification.
Complete transaction, backing-map snapshot and controlled-response map remain
unchanged in every invocation.

`individual_threshold_precedence_retains_metadata_framing_and_all_entry_format_checks`
combines threshold zero with returned-ID/owner/executable faults, trailing bytes,
truncation, unsupported version, either header reserved field, the selected
entry's reserved field and a later unused entry's reserved field. Existing exact
metadata/serialization/format errors precede the zero-threshold error with no
provider work. In particular nonzero reserved data plus zero threshold is still
a format refusal.

`individual_threshold_precedes_missing_entry_provider_faults_and_invalid_signature`
crosses threshold 0/1/2, absent/present matching entry, genuine/None/inconsistent-ID
provider configurations and intact/corrupted genuine signatures. Provider None
and mismatching IDs are configured synthetic faults; signature corruption is
only a negative control. Zero precedes all later handling; nonzero missing-entry
keeps its old error; insufficient weight precedes None, mismatching ID and invalid
signature. Sufficient weight with the invalid genuine signature still reaches
one backend attempt and its existing signature-verification error. Exact read
order, lookup/ID/digest/key work, zero writes/deletes and complete input/store/
response preservation are asserted.

`individual_threshold_distinct_genuine_proofs_do_not_aggregate_or_short_circuit`
uses two distinct genuine keys with separately dispatched, correctly identified
ML-DSA-44 suites 100 and 101. At threshold 2, weights 1 and 1 mathematically sum
to 2 but the first proof refuses after one read and before any provider work.
The matched threshold-1 case genuinely verifies both keys with two reads,
lookups, ID checks and backend attempts, confirming the fixture is not a
wrong-first-key artifact. At threshold 2 with first weight 2 and second weight 1,
the first proof genuinely verifies and the extra second proof refuses: exactly
two reads and one lookup/ID/verification. Complete state is preserved.

`individual_threshold_repetition_and_unused_higher_weight_cannot_rescue_first_match`
crosses repeated/non-repeated genuine proofs and absent/present higher-weight
unused same-suite entry. First weight 1 at threshold 2 always refuses before
provider work. Matched threshold-1 controls genuinely verify every supplied
proof, with one account read per proof, without changing input/store/responses.
These refusals do NOT prove full weighted multisignature semantics.

`individual_threshold_account_groups_do_not_pool_and_corrected_store_retry_reverifies_all`
uses two AccountIds. The earlier genuine key has individually sufficient weight
65535 for threshold 1; the later weight 1 cannot meet its own threshold 2.
Exactly two ordered reads and only the earlier proof's lookup, ID and genuine
verification occur. Only the later stored weight is corrected to 2; a NEW
complete corrected-store snapshot is taken. Fresh/reset observers then see both
proofs verify again with two ordered reads and two lookup/ID/backend attempts;
the corrected store and complete transaction remain unchanged by verification.

The former
`genuine_same_suite_selection_uses_first_key_without_threshold_or_weight_enforcement`
is narrowly renamed
`genuine_same_suite_selection_uses_first_individually_sufficient_key`.
Its selected entry now has admissible threshold 1 and weight 1. Its genuine
wrong-first/later-valid-key failure and swapped-key success are retained.
Historical claims about absence of scalar threshold checks describe the old
verifier only; first-match selection remains current. Existing complete framing,
format, alias, returned-suite-ID, borrowed-key pointer, exact-index, streaming
digest compatibility, refusal and retry controls remain active.

### Historical resource witness migration and actual executor

In `run422_native_compatibility_witnesses_legacy_and_isolated_semantics`, the
one-genuine-key, weight-1, threshold-2 fixture is unchanged. ONLY its active
verifier success expectation is migrated to the exact insufficient-weight error,
with counters reset before invocation: one get, zero bounded reads, zero
provider lookups, descriptors and signature attempts, zero writes/deletes, and
complete transaction/account preservation. The isolated evaluator retains
`KeysetProofEvaluationError::ThresholdUnreachable`, one bounded read, one
descriptor admission and zero signature attempts. The paths now refuse for
DIFFERENT reasons, not because the active route implements isolated weighted
semantics. Other compatibility witnesses, workloads, candidate limits, and
isolated-helper assertions are unchanged.

`executor_individual_threshold_admission_precedes_absent_native_target_read`
uses the genuine existing-keyset/keyset-create fixture and absent target.
Threshold/weight 0/1 and 2/1 independently return their exact authentication
errors after only the authentication-account read, with zero lookup/ID/signature
work. The matched 2/2 case genuinely authenticates, then reads the absent target
and returns exactly
`ExecutionError::ProgramError("native keyset creation authority unavailable")`.
That is successful authentication followed by existing program refusal, NOT
successful transaction execution. Ordered reads, observer counts, target
absence, zero mutation and complete transaction/store preservation are asserted.

### Scope, provenance and preservation

Starting commit: ca8b772fe9962557be11ddbcb24661d78a887e89.
Required and verified starting root tree:
318f10bca46aefedfbcf3230756bc022a42a481d.
Raw starting parent header:
`parent 0f92d6460164d2131d5deb3b519dd9db679014af`.
`git rev-parse --is-shallow-repository` returned `true`.
`git cat-file -e 0f92d6460164d2131d5deb3b519dd9db679014af^{commit}`
failed because that parent object is not present; its header is NOT evidence
that its ancestry was traversed. No assertion about unavailable pre-baseline
history is made.

The initially clean task branch was created directly at the required baseline.
Committed tested Rust source:
0a163bb733f7dd160a588b5aa11cd37ad13fd143.
Tested root tree: 7499eec58c38e4056337b89abfd6d3965ba9eef8.
Raw tested parent header:
`parent ca8b772fe9962557be11ddbcb24661d78a887e89`.
Commit identity, root-tree identity and ancestry are separate checks:
`git merge-base --is-ancestor ca8b772fe9962557be11ddbcb24661d78a887e89 0a163bb733f7dd160a588b5aa11cd37ad13fd143`
exited 0. Final evidence is a separate direct child commit of that tested source.
Its exact final commit/tree and complete old/new eight-path mode/blob manifest
are reported at delivery, rather than inventing a self-referential evidence
commit ID or document blob inside its own contents.

Every excluded tracked path must compare identically with the baseline, including
`crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs`:
mode 100644, blob e03b7f6338547b0c99695cc5ae1ddcd0d28b1cf4.
All eight changed paths retain their original modes; final Rust mode/blob pairs
must equal the tested-source pairs exactly. Each document's COMPLETE baseline
bytes must be an exact prefix, not merely a matching selected range:
resource assessment 59210 bytes (LF, terminal LF); state contract 115497 bytes
(LF, terminal LF); D7 evidence 2775184 bytes (CRLF, no terminal newline);
contradiction 2707163 bytes (LF, no terminal newline). Appends preserve those
EOL/EOF conventions. Verification compares the full baseline and final trees,
document prefixes, modes and final Rust blobs; ancestry is checked separately.
Committed-range whitespace checks are repeated after the evidence commit.

### Retained limits and non-approvals

The new gate adds constant-size scalar comparisons after existing parsing and
selection. It neither adds weights, multiplies them, accumulates contributions,
deduplicates identities, searches an alternative matching key nor allocates a
threshold-validation workspace. It introduces no weight-arithmetic overflow
path. This is ordinary regression validation, NOT new performance approval,
new target-hardware evidence or a replacement for historical timings. No new
latency, RSS or allocator guarantee is made.

Full weighted threshold aggregation is NOT implemented. Canonical identity,
duplicate/alias consistency and unused-entry semantic admission remain
unresolved. Individually sufficient weight does not establish backend
authenticity, common-state consistency, program/payer authority or replay
protection. Account acquisition/cloning, repeated work, bounded-read integration,
operational limits and deployed compatibility remain unresolved. Parsers and
isolated evaluators retain their existing contracts. Positive native-program
authority remains unavailable.

Preserved status: D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED;
D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET; section 13.6 whole-lifecycle
INCOMPLETE; activation DISABLED; public DevNet NO-GO; durable anti-rollback
NOT-ESTABLISHED; C4/C5 OPEN; RS1 OPEN; all candidate limits UNAPPROVED.
Whole native-admission and authority contracts remain
DRAFT / NOT APPROVED / NOT IMPLEMENTED.
No F1/F2 closure, activation, public DevNet acceptance or release approval follows.
No PR, merge, main push, activation or deployment is part of this delivery.

### Literal validation commands and results on committed tested source

All commands below ran with Rust source committed at the tested commit above
and no evidence-document changes present. Counts are PER COMMAND:
selected = passed + failed + ignored. Overlapping focused/package runs and the
supplemental package rerun are NOT added together. The required package command
stopped at its first failing target; its counts describe only tests actually
executed. The supplemental --no-fail-fast run exposes all remaining package and
doc-test results without changing any source. Node cargo check is compilation
only, not test execution. Successful compilation does not remove the package
regression blocker.

```text
LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --test tx_auth_verifier_tests -- --nocapture
exit 0
selected = 34 = 34 passed + 0 failed + 0 ignored
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.89s
Executed focused test names (none filtered or ignored):
correctly_registered_mldsa44_alias_remains_compatible
empty_auth_is_refused_without_store_crypto_or_witness_changes
complete_framing_and_missing_entry_precede_synthetic_provider_mismatch
genuine_mldsa44_authentication_accepts_and_removal_or_tampering_fails
genuine_mldsa44_verification_borrows_selected_key_from_returned_account
genuine_multi_auth_later_format_refusal_and_fresh_corrected_store_retry
genuine_multi_auth_later_suite_mismatch_and_fresh_matched_retry
genuine_mldsa44_streaming_caller_compatibility_and_retry
genuine_multi_auth_metadata_refusal_preserves_first_proof_and_retries
genuine_same_suite_selection_uses_first_individually_sufficient_key
genuine_required_signers_use_exact_indices_not_account_ids_or_auth_count
individual_threshold_account_groups_do_not_pool_and_corrected_store_retry_reverifies_all
individual_threshold_distinct_genuine_proofs_do_not_aggregate_or_short_circuit
individual_threshold_matched_scalar_boundaries_preserve_complete_state
individual_threshold_precedence_retains_metadata_framing_and_all_entry_format_checks
individual_threshold_repetition_and_unused_higher_weight_cannot_rescue_first_match
individual_threshold_precedes_missing_entry_provider_faults_and_invalid_signature
returned_suite_id_admission_genuine_positive_mismatch_and_invalid_retry
returned_account_metadata_refusals_precede_parsing_and_crypto
stored_format_combined_fault_precedence_before_selection_provider_and_signature
stored_format_admits_every_entry_before_selecting_genuine_first_key
stored_keyset_framing_refusals_precede_provider_and_preserve_state
structural_preflight_refuses_before_store_provider_or_backend_work
verify_transaction_auth_fails_on_bad_index
verify_transaction_auth_fails_on_invalid_signature
verify_transaction_auth_fails_on_missing_keyset
verify_transaction_auth_fails_on_unknown_suite
verify_transaction_auth_fails_on_wrong_suite_id
verify_transaction_auth_multiple_auths_reject_control
verify_transaction_auth_multiple_auths_structural_provider_control
verify_transaction_auth_structural_accept_all_provider_control
stored_format_independent_refusals_and_genuine_control_share_response_path
zero_entry_missing_account_suite_and_provider_outcomes_are_exact
wire_count_and_index_boundaries_are_structural_controls
```

```text
LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger --test run_422_native_admission_resource_tests -- --nocapture --test-threads=1
exit 0
selected = 6 = 6 passed + 0 failed + 0 ignored
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.69s
Executed focused test names (none filtered or ignored):
run422_native_compatibility_witnesses_legacy_and_isolated_semantics
run422_native_compatibility_witnesses_metadata_bounded_read_and_proof_limit
run422_native_resource_all_proofs_run_after_threshold_and_late_invalid_refuses
run422_native_resource_eight_groups_full_descriptor_and_signature_scan
run422_native_resource_genuine_create_preparation_and_composed_evaluation
run422_native_resource_global_proof_and_entry_boundaries_refuse_then_retry
```

```text
LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-runtime --test tx_executor_tests -- --nocapture
exit 0
selected = 8 = 8 passed + 0 failed + 0 ignored
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
Executed focused test names (none filtered or ignored):
executor_individual_threshold_admission_precedes_absent_native_target_read
executor_authenticated_keyset_create_refuses_without_mutation
executor_refuses_nonempty_missing_signer_without_any_program_mutation
executor_native_auth_metadata_admission_precedes_target_read
executor_rejects_empty_auth_before_keyset_program_changes_state
executor_returned_suite_id_admission_precedes_native_target_read
executor_unknown_program_id_fails
executor_stored_keyset_format_admission_precedes_native_target_read
```

```text
LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger -p qbind-runtime -p qbind-system
exit 101
selected = 841 = 840 passed + 1 failed + 0 ignored
     Running unittests src/lib.rs (target/debug/deps/qbind_ledger-8c02fbfa5802e7c2)
test result: ok. 368 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.12s
     Running tests/ledger_apply_tests.rs (target/debug/deps/ledger_apply_tests-4afd78b4f3c17f69)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/run_422_native_admission_context_tests.rs (target/debug/deps/run_422_native_admission_context_tests-3896b95f280a79ba)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s
     Running tests/run_422_native_admission_resource_tests.rs (target/debug/deps/run_422_native_admission_resource_tests-3d53c083fad8255a)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.75s
     Running tests/run_422_native_admission_state_contract_tests.rs (target/debug/deps/run_422_native_admission_state_contract_tests-3fe5a319c7ad5490)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
     Running tests/run_422_native_keyset_create_model_tests.rs (target/debug/deps/run_422_native_keyset_create_model_tests-2b46fca4f010a8e7)
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s
     Running tests/run_422_native_staged_effects_tests.rs (target/debug/deps/run_422_native_staged_effects_tests-15bf6f5b4014816a)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.29s
     Running tests/suite_registry_account_tests.rs (target/debug/deps/suite_registry_account_tests-5c25d1b534a997ec)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t157_parallel_nonce_executor_tests.rs (target/debug/deps/t157_parallel_nonce_executor_tests-8cf519d4043346fb)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/t163_vm_v0_tests.rs (target/debug/deps/t163_vm_v0_tests-8314f8bdbce42d94)
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t164_vm_persistence_tests.rs (target/debug/deps/t164_vm_persistence_tests-86ccaf26996d8c32)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s
     Running tests/t168_vm_gas_tests.rs (target/debug/deps/t168_vm_gas_tests-531ead3be7df8fc7)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t171_parallel_conflict_graph_tests.rs (target/debug/deps/t171_parallel_conflict_graph_tests-e0f1306e7d7e8a06)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t171_parallel_executor_integration_tests.rs (target/debug/deps/t171_parallel_executor_integration_tests-0e99b0f5bd06c335)
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
     Running tests/t177_vm_v0_proptests.rs (target/debug/deps/t177_vm_v0_proptests-f0bc96cd69df53f3)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
     Running tests/t179_vm_v0_gas_proptests.rs (target/debug/deps/t179_vm_v0_gas_proptests-a09a9932fe8c9ed8)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
     Running tests/t193_hybrid_fee_distribution_tests.rs (target/debug/deps/t193_hybrid_fee_distribution_tests-32cf2458968a4a8c)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t195_monetary_engine_tests.rs (target/debug/deps/t195_monetary_engine_tests-5925af5627f06b4f)
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t197_monetary_seigniorage_tests.rs (target/debug/deps/t197_monetary_seigniorage_tests-481c232a1631fb51)
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t199_monetary_epoch_state_tests.rs (target/debug/deps/t199_monetary_epoch_state_tests-072d1493e0dde4e6)
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t200_validator_seigniorage_tests.rs (target/debug/deps/t200_validator_seigniorage_tests-c11b1348c1318867)
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t201_monetary_application_tests.rs (target/debug/deps/t201_monetary_application_tests-86c7cdfb6bf93e85)
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t202_ema_fee_smoothing_tests.rs (target/debug/deps/t202_ema_fee_smoothing_tests-f4c2ec26a63243b5)
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t203_rate_of_change_limiters_tests.rs (target/debug/deps/t203_rate_of_change_limiters_tests-ef12a3b517e885d5)
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t204_phase_transition_tests.rs (target/debug/deps/t204_phase_transition_tests-818909b15a93bec3)
test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t215_state_snapshot_tests.rs (target/debug/deps/t215_state_snapshot_tests-510c0d74e2224c3c)
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s
     Running tests/t232_genesis_config_tests.rs (target/debug/deps/t232_genesis_config_tests-dfaeafb05009355f)
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t233_genesis_hash_tests.rs (target/debug/deps/t233_genesis_hash_tests-0251a6da534d0e38)
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/tx_auth_verifier_tests.rs (target/debug/deps/tx_auth_verifier_tests-e90c75554fc7aa10)
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.27s
     Running unittests src/lib.rs (target/debug/deps/qbind_runtime-fdb308b3cfe45039)
test result: ok. 53 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/block_executor_tests.rs (target/debug/deps/block_executor_tests-d87f5b3c58ec1f9c)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s
     Running tests/run_422_native_governance_authority_contract_tests.rs (target/debug/deps/run_422_native_governance_authority_contract_tests-0d54677d887c7854)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.61s
     Running tests/run_422_native_keyset_create_authority_contract_tests.rs (target/debug/deps/run_422_native_keyset_create_authority_contract_tests-17043d1f191a3fbc)
test result: FAILED. 8 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.50s
error: test failed, to rerun pass `-p qbind-runtime --test run_422_native_keyset_create_authority_contract_tests`
```

```text
LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-node --test block_apply_tests -- --nocapture
exit 0
selected = 6 = 6 passed + 0 failed + 0 ignored
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
Executed focused test names (none filtered or ignored):
node_rejects_block_when_tx_count_exceeds_max
node_rejects_block_with_extra_bytes_after_tx
node_rejects_block_with_malformed_tx_blob
node_returns_block_outcome_when_authenticated_native_creation_refuses
node_missing_coverage_creation_and_would_be_signer_fail_in_order
node_returns_block_outcome_when_native_transaction_auth_fails
```

```text
LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo check --locked -p qbind-node
exit 0
    Finished `dev` profile [unoptimized] target(s) in 40.51s
Compilation only; no tests selected.
```

```text
rustfmt --check --edition 2021 crates/qbind-ledger/src/auth.rs crates/qbind-ledger/tests/tx_auth_verifier_tests.rs crates/qbind-ledger/tests/run_422_native_admission_resource_tests.rs crates/qbind-runtime/tests/tx_executor_tests.rs
exit 0
(no diagnostic output)
```

```text
git -c core.whitespace=cr-at-eol diff --check
exit 0
(no diagnostic output)
```

```text
git -c core.whitespace=cr-at-eol diff --check ca8b772fe9962557be11ddbcb24661d78a887e89 HEAD
exit 0
(no diagnostic output)
```

```text
LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger -p qbind-runtime -p qbind-system --no-fail-fast
exit 101
selected = 979 = 961 passed + 1 failed + 17 ignored
     Running unittests src/lib.rs (target/debug/deps/qbind_ledger-8c02fbfa5802e7c2)
test result: ok. 368 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.78s
     Running tests/ledger_apply_tests.rs (target/debug/deps/ledger_apply_tests-4afd78b4f3c17f69)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/run_422_native_admission_context_tests.rs (target/debug/deps/run_422_native_admission_context_tests-3896b95f280a79ba)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.28s
     Running tests/run_422_native_admission_resource_tests.rs (target/debug/deps/run_422_native_admission_resource_tests-3d53c083fad8255a)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.62s
     Running tests/run_422_native_admission_state_contract_tests.rs (target/debug/deps/run_422_native_admission_state_contract_tests-3fe5a319c7ad5490)
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
     Running tests/run_422_native_keyset_create_model_tests.rs (target/debug/deps/run_422_native_keyset_create_model_tests-2b46fca4f010a8e7)
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
     Running tests/run_422_native_staged_effects_tests.rs (target/debug/deps/run_422_native_staged_effects_tests-15bf6f5b4014816a)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.32s
     Running tests/suite_registry_account_tests.rs (target/debug/deps/suite_registry_account_tests-5c25d1b534a997ec)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t157_parallel_nonce_executor_tests.rs (target/debug/deps/t157_parallel_nonce_executor_tests-8cf519d4043346fb)
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/t163_vm_v0_tests.rs (target/debug/deps/t163_vm_v0_tests-8314f8bdbce42d94)
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t164_vm_persistence_tests.rs (target/debug/deps/t164_vm_persistence_tests-86ccaf26996d8c32)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.24s
     Running tests/t168_vm_gas_tests.rs (target/debug/deps/t168_vm_gas_tests-531ead3be7df8fc7)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t171_parallel_conflict_graph_tests.rs (target/debug/deps/t171_parallel_conflict_graph_tests-e0f1306e7d7e8a06)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t171_parallel_executor_integration_tests.rs (target/debug/deps/t171_parallel_executor_integration_tests-0e99b0f5bd06c335)
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
     Running tests/t177_vm_v0_proptests.rs (target/debug/deps/t177_vm_v0_proptests-f0bc96cd69df53f3)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
     Running tests/t179_vm_v0_gas_proptests.rs (target/debug/deps/t179_vm_v0_gas_proptests-a09a9932fe8c9ed8)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
     Running tests/t193_hybrid_fee_distribution_tests.rs (target/debug/deps/t193_hybrid_fee_distribution_tests-32cf2458968a4a8c)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t195_monetary_engine_tests.rs (target/debug/deps/t195_monetary_engine_tests-5925af5627f06b4f)
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t197_monetary_seigniorage_tests.rs (target/debug/deps/t197_monetary_seigniorage_tests-481c232a1631fb51)
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t199_monetary_epoch_state_tests.rs (target/debug/deps/t199_monetary_epoch_state_tests-072d1493e0dde4e6)
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t200_validator_seigniorage_tests.rs (target/debug/deps/t200_validator_seigniorage_tests-c11b1348c1318867)
test result: ok. 20 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t201_monetary_application_tests.rs (target/debug/deps/t201_monetary_application_tests-86c7cdfb6bf93e85)
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t202_ema_fee_smoothing_tests.rs (target/debug/deps/t202_ema_fee_smoothing_tests-f4c2ec26a63243b5)
test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t203_rate_of_change_limiters_tests.rs (target/debug/deps/t203_rate_of_change_limiters_tests-ef12a3b517e885d5)
test result: ok. 17 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t204_phase_transition_tests.rs (target/debug/deps/t204_phase_transition_tests-818909b15a93bec3)
test result: ok. 28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t215_state_snapshot_tests.rs (target/debug/deps/t215_state_snapshot_tests-510c0d74e2224c3c)
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.14s
     Running tests/t232_genesis_config_tests.rs (target/debug/deps/t232_genesis_config_tests-dfaeafb05009355f)
test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t233_genesis_hash_tests.rs (target/debug/deps/t233_genesis_hash_tests-0251a6da534d0e38)
test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/tx_auth_verifier_tests.rs (target/debug/deps/tx_auth_verifier_tests-e90c75554fc7aa10)
test result: ok. 34 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.32s
     Running unittests src/lib.rs (target/debug/deps/qbind_runtime-fdb308b3cfe45039)
test result: ok. 53 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/block_executor_tests.rs (target/debug/deps/block_executor_tests-d87f5b3c58ec1f9c)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
     Running tests/run_422_native_governance_authority_contract_tests.rs (target/debug/deps/run_422_native_governance_authority_contract_tests-0d54677d887c7854)
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.64s
     Running tests/run_422_native_keyset_create_authority_contract_tests.rs (target/debug/deps/run_422_native_keyset_create_authority_contract_tests-17043d1f191a3fbc)
test result: FAILED. 8 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.49s
error: test failed, to rerun pass `-p qbind-runtime --test run_422_native_keyset_create_authority_contract_tests`
     Running tests/run_422_native_validator_authority_contract_tests.rs (target/debug/deps/run_422_native_validator_authority_contract_tests-0532fd3b15542f5a)
test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.64s
     Running tests/t150_revm_execution_tests.rs (target/debug/deps/t150_revm_execution_tests-ce257344cc3c17e1)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t151_block_apply_tests.rs (target/debug/deps/t151_block_apply_tests-1b058b00e196bd91)
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
     Running tests/t152_block_apply_gas_tests.rs (target/debug/deps/t152_block_apply_gas_tests-bcde4484c4b6847f)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/t152_gas_model_tests.rs (target/debug/deps/t152_gas_model_tests-b52326aa30cce19b)
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/tx_executor_tests.rs (target/debug/deps/tx_executor_tests-9e8fa3d259cebca0)
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
     Running unittests src/lib.rs (target/debug/deps/qbind_system-f635c0e8e457e070)
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/governance_program_tests.rs (target/debug/deps/governance_program_tests-41858b37480b5047)
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/keyset_program_tests.rs (target/debug/deps/keyset_program_tests-801604c9ae079389)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/validator_register_tests.rs (target/debug/deps/validator_register_tests-dd7f8c6265c81f81)
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
   Doc-tests qbind_ledger
test result: ok. 40 passed; 0 failed; 16 ignored; 0 measured; 0 filtered out; finished in 4.51s
   Doc-tests qbind_runtime
test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.00s
   Doc-tests qbind_system
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
error: 1 target failed:
```

### Concrete outside-scope validation blocker (not silently migrated)

The required
`LIBCLANG_PATH=/usr/lib/llvm-18/lib cargo test --locked -p qbind-ledger -p qbind-runtime -p qbind-system`
exits 101. The supplemental identical package selection with `--no-fail-fast`
also exits 101, with only this one failing target/test:

`crates/qbind-runtime/tests/run_422_native_keyset_create_authority_contract_tests.rs`
`preseeded_threshold_two_and_threshold_one_controls_reach_unavailable_authority`
(fixture lines 607-648; read-order assertion at line 240).

Its historical threshold-2 fixture has two weight-1 entries but supplies only
one proof for the first key, then expects reads `[TARGET, FRESH]`, one
verification and the native-program authority-unavailable error. With this
intentional restriction the insufficient selected key refuses authentication
before the FRESH read. Actual assertion output reports only `[0x22; 32]`
(TARGET) versus expected `[0x22; 32], [0x33; 32]` (TARGET, FRESH). The read-order
assertion panics before that test's later error assertion; this is not reported
as an observed program error or as a pre-existing unrelated failure.

The target reports `8 passed; 1 failed; 0 ignored`. The entire supplemental run
reports 979 selected = 961 passed + 1 failed + 17 ignored (including doc-tests).
The required early-stopping run reports 841 executed = 840 passed + 1 failed +
0 ignored. These overlap and must not be summed.

That file is EXCLUDED by the exact eight-path scope, remains mode 100644 and
blob 841928e45df09ad7a74ed0946c512da05970df35, and is NOT changed, skipped,
filtered, ignored or hidden. An all-green broad package validation is therefore
NOT established within this task's authorized scope. No claim of full
validation success or release approval follows. The implementation and focused
controls are delivered with this explicit compatibility/validation blocker.

### Preparatory/environment results (separate from final validation)

Before source commit, the preparatory ledger command used the same literal
ledger command listed above and exited 101 during zstd-sys/bindgen build:
`Unable to find libclang: "couldn't find any valid shared libraries matching:
['libclang.so', 'libclang-*.so', 'libclang.so.*', 'libclang-*.so.*']"`.
No verifier tests executed in that attempt; it is not counted as a test failure.
Only libclang-cpp.so.18.1 existed initially, not a bindgen-loadable libclang.so.
Environment-only prerequisite repair:
`apt-get update -qq && apt-get install -y -qq libclang-18-dev` exited 0.
apt update emitted a separate Google Chrome repository DNS warning and reused
available indexes; installation succeeded and
`/usr/lib/llvm-18/lib/libclang.so` and `libclang.so.1` became available.
There were no repository dependency/lockfile changes.
The preparatory retry then exited 0 with 34 selected = 34 passed + 0 failed +
0 ignored. It is separate from, and not added to, committed-source validation.

### Starting and tested Rust mode/blob inventory

The following mode/blob pairs are the source-provenance equality check for the
final evidence-only commit. Final Rust must equal the tested side exactly.

```text
crates/qbind-ledger/src/auth.rs
starting 100755 blob fa7ede001a5f563cdf4a9c382493806a35936368
tested 100755 blob 895763fd47267a008fe10e2729b5db73606ca8cc
```

```text
crates/qbind-ledger/tests/tx_auth_verifier_tests.rs
starting 100755 blob 8b1b499a4b27e8bbdabce93c398d807d34c3e39c
tested 100755 blob 65b156ec44f5c84d32fc25add37a868ce473f7f0
```

```text
crates/qbind-ledger/tests/run_422_native_admission_resource_tests.rs
starting 100644 blob 47843755bda7f413dc4dea417cce373b62610ff8
tested 100644 blob ed5f0a8c2bb78c6c2eff86e73f0bc365aaccbaec
```

```text
crates/qbind-runtime/tests/tx_executor_tests.rs
starting 100755 blob b9c3b8c2b4e0ea8a3985cc83f5092cda8fe44269
tested 100755 blob 3ce8b9c5987b625b8dcbaadf512836aad4efe332
```


Document starting mode/blob inventory (the final document hashes necessarily
depend on this append and are reported after commit at delivery):

```text
100644 blob 16c90548f4a967e0af5649f1e5092591eea24049	docs/devnet/QBIND_RUN_422_NATIVE_ADMISSION_RESOURCE_ASSESSMENT.md
```

```text
100644 blob e6cc7a9d549ee4cbe17256cbf0411b66b88cfb94	docs/devnet/QBIND_RUN_422_NATIVE_ADMISSION_STATE_CONTRACT.md
```

```text
100644 blob 9c1fbd31a2bb2c9986f576b40b8adb594d2d9d79	docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md
```

```text
100644 blob b799eba7dca78ab40ffb341f27750bc01cf8333a	docs/whitepaper/contradiction.md
```


Delivery verification commands to repeat AFTER the evidence-only commit:
`git -c core.whitespace=cr-at-eol diff --check`;
`git -c core.whitespace=cr-at-eol diff --check ca8b772fe9962557be11ddbcb24661d78a887e89 HEAD`;
full-tree mode/blob comparison, complete-document-prefix and EOL/EOF checks;
`git merge-base --is-ancestor ca8b772fe9962557be11ddbcb24661d78a887e89 HEAD`;
`git merge-base --is-ancestor 0a163bb733f7dd160a588b5aa11cd37ad13fd143 HEAD`.
Push ONLY
`git push origin HEAD:refs/heads/copilot/run-422-native-auth-individual-threshold-admission`
without force, then compare the exact `git ls-remote --heads origin
refs/heads/copilot/run-422-native-auth-individual-threshold-admission` tip with
local HEAD and check a clean worktree. Those post-commit outcomes and final
identities are recorded in the delivery response, not asserted prospectively
inside this self-identifying evidence append.
