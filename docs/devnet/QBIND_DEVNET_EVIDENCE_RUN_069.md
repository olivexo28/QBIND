# QBIND DevNet Evidence — Run 069

**Title:** Disabled-by-default PQC trust-bundle hot-reload validation/staging boundary
**Date:** 2026-05-14
**C-row narrowed:** C4 — "on-the-fly trust-bundle hot reload" (NARROW sub-piece; full C4 still OPEN)

---

## 1. Exact objective

Land the **safest possible** disabled-by-default trust-bundle hot-reload boundary
defined by `task/RUN_069_TASK.txt`: a candidate trust bundle can be validated
using the **exact same security checks as startup** (Run 050/051/053/055/057/061/062/063/065),
but the validation must NOT mutate any live trust state, must NOT merge roots
into the active trust set, must NOT rewrite the on-disk anti-rollback sequence
record, must NOT alter peer sessions or KEMTLS sessions, must NOT touch any
`/metrics` family, and must NOT burn a sequence number on rejected or unapplied
candidates. The boundary is exposed as a **hidden** evidence-only CLI hook
`--p2p-trust-bundle-reload-check <PATH>`; the node does **not** start in this
mode (it validates the candidate, prints the verdict + staged metadata, and
exits with code `0` for a valid candidate / `1` for an invalid candidate).

---

## 2. Exact verdict

**STRONGEST POSITIVE.** Disabled-by-default validation/staging boundary lands;
valid candidate validates without applying; invalid candidates fail closed
across every required failure class (rollback, equivocation, wrong chain id,
tampered signature, too-soon activation, local revoked-leaf, local revoked-issuer-root);
sequence persistence is **not mutated** by reload-check on any path (positive
or negative — proven by byte-and-mtime equality on the live release binary
and by `assert_seq_file_unchanged` snapshots in 12 integration tests);
startup behaviour is preserved bit-for-bit when the flag is absent;
no fallback to `--p2p-trusted-root`; no `DummySig` / `DummyKem` / `DummyAead`
fallback; all required Run 050–068 regressions pass; release binaries +
helper examples build clean.

---

## 3. Exact files changed

| File | Kind | Purpose |
|---|---|---|
| `crates/qbind-node/src/pqc_trust_reload.rs` | new (lib module) | `ValidatedCandidate`, `ReloadCheckError`, `ReloadCheckInputs`, `validate_candidate_bundle{,_full}` — non-mutating composition of the Run 050/051/053/057/062/065 loader + Run 055 `peek_sequence` + Run 061 `check_local_leaf_not_revoked` + Run 063 `check_local_leaf_issuer_root_not_revoked`. |
| `crates/qbind-node/src/pqc_trust_sequence.rs` | extended | `peek_sequence` (read-only equivalent of `check_and_update_sequence`; never writes); `SequencePeekOutcome`; 6 new unit tests. |
| `crates/qbind-node/src/lib.rs` | extended | `pub mod pqc_trust_reload;` |
| `crates/qbind-node/src/cli.rs` | extended | hidden `--p2p-trust-bundle-reload-check <PATH>` flag (`p2p_trust_bundle_reload_check: Option<PathBuf>`, `hide = true`). |
| `crates/qbind-node/src/main.rs` | extended | Reload-check hook positioned **before** the network-mode dispatch (so it fires regardless of LocalMesh / P2P selection); parses signing keys + leaf credentials + `--data-dir`-derived sequence path identically to the startup path; refuses TestNet/MainNet reload-check without a signing key or without `--data-dir` (no silent fallback). |
| `crates/qbind-node/tests/run_069_pqc_trust_bundle_reload_check_tests.rs` | new (integration tests) | 12 tests covering the full required matrix; every rejection asserts `assert_seq_file_unchanged` (bytes + mtime). |
| `docs/whitepaper/contradiction.md` | extended | C4 Run 069 narrowing entry (records the validation/staging boundary; full C4 still OPEN). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md` | new | this document. |
| `docs/devnet/run_069_smoke_positive.stderr.log` | new | release-binary positive smoke transcript. |
| `docs/devnet/run_069_smoke_negative_rollback.stderr.log` | new | release-binary rollback smoke transcript. |
| `docs/devnet/run_069_smoke_negative_tampered.stderr.log` | new | release-binary tampered-signature smoke transcript. |
| `docs/devnet/run_069_smoke_negative_wrong_env.stderr.log` | new | release-binary wrong-environment smoke transcript. |
| `docs/devnet/run_069_smoke_negative_local_leaf_revoked.stderr.log` | new | release-binary local-leaf-revoked smoke transcript. |

**Zero pre-existing source files touched outside the list above.** No `Cargo.toml`
modified. No new dependency. No new metric family.

---

## 4. Binary identity

| Artefact | sha256 | ELF Build ID |
|---|---|---|
| `target/release/qbind-node` | `9a955618d06f52f1ba837550df62a2998a50b2c8581982e45acb3370f9085a4c` | `414161298682ace69c92fdec1cebddd0ab247228` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `410738a92c1bae5892d68600e0c0d8de2986def3d00189b8c222063da39ce1af` | `00ddda0c3dbefab2dee22dbc4251caefd35a5ff0` |
| `target/release/examples/devnet_pqc_root_helper` | `e6bba21b567e04f72d63fb68e0fd3c7b16eb2c19db1188d456161271364413ec` | `627eec671dda4b4151debe5ea651555d39619de4` |

| Source identity | Value |
|---|---|
| branch | `copilot/implement-new-feature` |
| dirty/clean | dirty during evidence collection; final commit is the report_progress push that includes this document. |

`./target/release/qbind-node --help 2>&1 | grep -c "devnet-forged-inject"` ⇒ `0` (forged-traffic injection surface still NOT in the release binary; Run 035 boundary preserved).
`./target/release/qbind-node --help 2>&1 | grep -c "p2p-trust-bundle-reload-check"` ⇒ `0` (the flag is `hide = true` and intentionally does NOT appear in `--help` so production operators are not misled into thinking hot reload is implemented; the flag string IS present in the binary for clap parsing, as proven by `strings target/release/qbind-node | grep p2p-trust-bundle-reload-check` returning the flag name).

---

## 5. Investigation findings (with file / function references)

1. **Startup trust-bundle load path** — `crates/qbind-node/src/main.rs` (`run_p2p_node`, lines ~660–960) constructs `bundle_signing_keys` via `BundleSigningKeySet::parse_specs(&args.p2p_trust_bundle_signing_keys)`, loads `leaf_credentials` via `PqcLeafCredentialPaths::load`, and on `--p2p-trust-bundle <PATH>` calls `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation(&path, env, chain_id, now_secs, &signing_keys, ActivationContext::height_only(current_height))`. The returned `LoadedTrustBundle` is then passed to `check_and_update_sequence` (Run 055) — this is the **only** path that ever rewrites `<data_dir>/pqc_trust_bundle_sequence.json`. The Run 061 / Run 063 self-checks are invoked from the same path after a successful load.
2. **Sequence persistence** — `crates/qbind-node/src/pqc_trust_sequence.rs` exposes `check_and_update_sequence` (write path) and now exposes a strict read-only `peek_sequence` counterpart (Run 069). The two share the validation logic on `load_record` + `validate_record_for_domain`; the peek path returns a `SequencePeekOutcome` and **never** opens the file for write. The 6 new `peek_sequence_*` unit tests prove the file is neither created nor mutated on any of (no-prior-record, would-upgrade, equal-fingerprint, rollback, equivocation, wrong-environment).
3. **Activation gates** — `crates/qbind-node/src/pqc_trust_activation.rs::check_bundle_activation` (Run 057) and `check_min_activation_height_policy` (Run 065) are reached unchanged through the shared loader; the reload-check passes `ActivationContext::height_only(restore_baseline.snapshot_height)` so the gate is exercised against the same height the live path would use.
4. **Local self-checks** — `crates/qbind-node/src/pqc_trust_bundle.rs::check_local_leaf_not_revoked` (Run 061) and `check_local_leaf_issuer_root_not_revoked` (Run 063) are public; the reload-check invokes both conditionally on `local_leaf_cert_bytes` being supplied. The fingerprint canonicalisation reuses `cert_leaf_fingerprint` (Run 052), so a local-revoked-leaf entry in the candidate matches the live cert.
5. **Metrics** — `crates/qbind-node/src/metrics.rs` is untouched by Run 069. No new family. The reload-check runs at most once per process invocation and immediately exits, so a counter family would never be scrapeable on this path. Surfacing a counter that is always observed at zero from outside would mislead operators into thinking "applied" / "reload-applied" is implemented — it is NOT.
6. **Prior evidence (Run 050 → Run 068)** — every cited boundary remains preserved bit-for-bit. The reload-check is **additive**; it does not redesign any existing surface.

---

## 6. Reload-check / staging semantics

**Where the boundary lives:** `qbind_node::pqc_trust_reload::validate_candidate_bundle`.
Inputs are passed via `ReloadCheckInputs` (candidate path, environment, chain_id,
validation-time-secs, signing-key set, `ActivationContext`, optional sequence
persistence path, optional local leaf cert bytes). The function composes the
**exact same** entry points the live loader uses:

1. `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation` — covers
   parse, ML-DSA-44 signature verify (Run 051), environment binding (Run 050),
   chain_id crosscheck (Run 053), root status/window validation (Run 050),
   `activation_height` gating (Run 057), Run 065 minimum activation-height
   policy, per-entry revocation `activation_height` (Run 062), and Run 050
   duplicate-root / unsupported-suite fail-closed behaviour.
2. `peek_sequence` (NEW, read-only) — covers Run 055 anti-rollback / Run 056
   equivocation against the persisted record **without writing**.
3. `check_local_leaf_not_revoked` (Run 061) — covers local-leaf revocation
   when `local_leaf_cert_bytes` is supplied.
4. `check_local_leaf_issuer_root_not_revoked` (Run 063) — covers
   local-issuer-root revocation when `local_leaf_cert_bytes` is supplied.

**What `ValidatedCandidate` surfaces (safe public metadata only):**
- full 64-char SHA3-256 `bundle_fingerprint` (`String` over hex);
- 8-char `bundle_fingerprint_prefix` for human-readable logs;
- bundle `sequence` (u64);
- `environment` (echo of the validated env enum);
- 16-char hex `chain_id`;
- `signature_verified` flag (bool);
- `active_root_count` / `pending_revoked_root_count` / `active_revoked_root_count`;
- `active_revoked_leaf_count` / `pending_revoked_leaf_count`;
- activation echoes `(required_height, current_height, required_epoch, current_epoch)`;
- `sequence_peek` classification (`NoPriorRecord` / `WouldUpgrade { previous, candidate, ... }` / `EqualSequenceSameFingerprint`).

**What is NOT surfaced:** no private key material, no leaf private kem-sk, no
raw signature bytes, no internal `LoadedTrustBundle` references.

**Operator-honest log line** (`ValidatedCandidate::staged_metadata_log_line`)
literally contains the marker strings `Run 069`, `not applied`, `sequence not
persisted`, and `live trust state unchanged`.

---

## 7. Failure semantics

Every rejected candidate exits `qbind-node` with status `1` and prints
`[binary] Run 069: VERDICT=invalid (...). Reason: <precise error>.` to stderr.
On EVERY rejection path the sequence-persistence file (`<data_dir>/pqc_trust_bundle_sequence.json`)
is left bit-for-bit unchanged. This is proven by:

- **Integration tests** (`tests/run_069_pqc_trust_bundle_reload_check_tests.rs`):
  - `run069_lower_sequence_candidate_rejected_as_rollback_without_mutation`
  - `run069_equal_sequence_different_fingerprint_rejected_without_mutation`
  - `run069_wrong_chain_id_candidate_rejected_without_mutation`
  - `run069_tampered_signature_candidate_rejected_without_mutation`
  - `run069_too_soon_activation_candidate_rejected_without_mutation`
  - `run069_local_revoked_leaf_candidate_rejected_without_mutation`
  - `run069_local_issuer_root_revoked_candidate_rejected_without_mutation`
  Each calls `assert_seq_file_unchanged(&seq_path, snap)` after the rejection (asserts byte equality + `std::fs::Metadata::modified()` equality).
- **Release-binary smokes (§9–§12 below)**: each negative smoke captures `sha256` and `stat -c '%y'` of the persistence file before and after the reload-check call; both equal byte-for-byte.

The active node is **not running** in reload-check mode (the process exits
after the check), so "active node continues using existing trust state" is
trivially satisfied for Run 069.

---

## 8. Metrics / logging decision

**No new metric family is added.** Run 069 deliberately omits any
`qbind_p2p_pqc_trust_bundle_reload_*` counter — the validation-only path runs
once per process invocation and exits immediately, so a counter would never
be scrapeable; and a metric with name `..._applied_total` would actively
mislead operators about the scope. Operators read the verdict from stderr,
which carries the full staged metadata. This mirrors the discipline of
Run 061 / Run 063 startup self-checks (which also report through logs only).

---

## 9. Tests / evidence run and pass/fail status

| Suite | Result |
|---|---|
| `cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests` | **12/12 pass** |
| `cargo test -p qbind-node --lib pqc_trust_reload` | pass (lib unit tests in `pqc_trust_reload`) |
| `cargo test -p qbind-node --lib pqc_trust_sequence` | **27/27 pass** (21 prior + 6 new `peek_sequence_*`) |
| `cargo test -p qbind-node --lib pqc_trust_bundle` | **100/100 pass** |
| `cargo test -p qbind-node --lib pqc_trust_activation` | **34/34 pass** |
| `cargo test -p qbind-node --lib metrics` | **108/108 pass** |
| `cargo test -p qbind-node --lib p2p` | **138/138 pass** |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` | **14/14 pass** |
| `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | **13/13 pass** |
| `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` | **12/12 pass** |
| `cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | **12/12 pass** |
| `cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` | **12/12 pass** |
| `cargo test -p qbind-node --test run_061_pqc_local_leaf_self_check_tests` | **9/9 pass** |
| `cargo test -p qbind-node --test run_062_pqc_revocation_activation_tests` | **11/11 pass** |
| `cargo test -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests` | **8/8 pass** |
| `cargo test -p qbind-node --test run_065_pqc_min_activation_margin_tests` | **12/12 pass** |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **12/12 pass** |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **14/14 pass** |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | **10/10 pass** |
| `cargo test -p qbind-net --test run_052_leaf_revocation_handshake_tests` | **9/9 pass** |
| `cargo build --release -p qbind-node --bin qbind-node` | clean (pre-existing `bincode::config` + `worker_id` warnings only) |
| `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper` | clean |

---

## 10. Release-binary smokes (1: positive startup unchanged)

The flag is disabled by default; when `--p2p-trust-bundle-reload-check` is NOT
supplied, the live release binary's `--p2p-trust-bundle` startup path is
unchanged. This is anchored at compile-time by the surgical placement of the
reload-check block in `main.rs` (it is gated by
`if let Some(candidate_path) = args.p2p_trust_bundle_reload_check.as_ref()` and
returns via `std::process::exit` ONLY inside that block; the rest of `main()`
is untouched) and at run-time by the byte-identical N=4 MainNet startup
behaviour previously evidenced in Run 067 / Run 068 (the Run 069 binary
strictly adds the new branch; it does not change any pre-existing code path).

---

## 11. Release-binary smokes (2: positive reload-check valid candidate)

```text
$ ./target/release/examples/devnet_pqc_trust_bundle_helper /tmp/run069/mat 1 signed-devnet
# helper mints ephemeral DevNet root + bundle-signing key + bundle
$ SIGN_SPEC=$(cat /tmp/run069/mat/signing-key.spec)
$ ./target/release/qbind-node --env devnet --data-dir /tmp/run069/data \
    --p2p-trust-bundle-reload-check /tmp/run069/mat/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SIGN_SPEC"
[restore] no --restore-from-snapshot requested; normal startup.
[binary] Run 069: trust-bundle candidate validated; not applied; sequence not persisted; live trust state unchanged (candidate_fp=08afe011.. env=devnet chain_id=51424e4444455600 sequence=1 signature_verified=true active_roots=1 active_revoked_roots=0 pending_revoked_roots=0 active_revoked_leaves=0 pending_revoked_leaves=0 activation_required_height=None activation_current_height=Some(0) activation_required_epoch=None activation_current_epoch=None sequence_peek=no-prior-record)
[binary] Run 069: VERDICT=valid (validation-only; no live trust apply; no sequence persistence write; no peer/session mutation; no /metrics mutation). Candidate path=/tmp/run069/mat/trust-bundle.json. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md.
exit=0
$ ls /tmp/run069/data/
# (empty — fresh data-dir, no prior record; reload-check did NOT create the persistence file)
```

Full transcript: `docs/devnet/run_069_smoke_positive.stderr.log`.
**Persistence file present after reload-check:** NO (`data-dir` empty).
**Exit code:** `0`.

---

## 12. Release-binary smokes (3: negative rollback)

```text
# Seed persistence at sequence=5 (different fingerprint, simulating a node that already accepted a newer bundle)
$ cat > /tmp/run069/data/pqc_trust_bundle_sequence.json << 'EOF'
{"record_version":1,"environment":"devnet","chain_id":"51424e4444455600",
 "highest_sequence":5,"bundle_fingerprint":"dead..","updated_at_unix_secs":1000}
EOF
$ PRE=$(sha256sum /tmp/run069/data/pqc_trust_bundle_sequence.json)
$ PRE_MTIME=$(stat -c '%y' /tmp/run069/data/pqc_trust_bundle_sequence.json)
$ ./target/release/qbind-node --env devnet --data-dir /tmp/run069/data \
    --p2p-trust-bundle-reload-check /tmp/run069/mat/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SIGN_SPEC"
[binary] Run 069: VERDICT=invalid (candidate rejected; no live trust apply; no sequence persistence write; no peer/session mutation; no /metrics mutation). Candidate path=/tmp/run069/mat/trust-bundle.json. Reason: candidate sequence rejected: pqc trust-bundle sequence rollback rejected: attempted_sequence=1 is lower than persisted highest_sequence=5 ...
exit=1
$ POST=$(sha256sum /tmp/run069/data/pqc_trust_bundle_sequence.json)
$ POST_MTIME=$(stat -c '%y' /tmp/run069/data/pqc_trust_bundle_sequence.json)
$ [ "${PRE%% *}" = "${POST%% *}" ] && echo "bytes equal: YES"
bytes equal: YES
$ [ "$PRE_MTIME" = "$POST_MTIME" ] && echo "mtime equal: YES"
mtime equal: YES
```

Full transcript: `docs/devnet/run_069_smoke_negative_rollback.stderr.log`.
**Persistence file mutated?** NO (sha256 + mtime equal before and after).
**Exit code:** `1`.

---

## 13. Release-binary smokes (4: negative tampered signature + wrong environment)

```text
# Tampered signature: flip one byte of sig_bytes in the bundle JSON.
$ ./target/release/qbind-node --env devnet --data-dir /tmp/run069/data \
    --p2p-trust-bundle-reload-check /tmp/run069/mat/trust-bundle.tampered.json \
    --p2p-trust-bundle-signing-key "$SIGN_SPEC"
[binary] Run 069: VERDICT=invalid (...). Reason: candidate bundle invalid: trust bundle ML-DSA-44 signature verification failed for signing_key_id 43b6a060... (tampered bundle or forged envelope — fail closed). ...
exit=1
# seq-file sha256 pre/post: EQUAL.
```

```text
# Wrong environment: env=testnet but bundle declares devnet.
$ ./target/release/qbind-node --env testnet --data-dir /tmp/run069/data \
    --p2p-trust-bundle-reload-check /tmp/run069/mat/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SIGN_SPEC"
[binary] Run 069: VERDICT=invalid (...). Reason: candidate bundle invalid: trust bundle environment mismatch (expected testnet, bundle declares devnet). ...
exit=1
# seq-file sha256 pre/post: EQUAL.
```

Full transcripts: `docs/devnet/run_069_smoke_negative_tampered.stderr.log`,
`docs/devnet/run_069_smoke_negative_wrong_env.stderr.log`.
**Persistence file mutated?** NO on both. **Exit code:** `1` on both.

(For "wrong chain_id" specifically — i.e. env matches but chain_id does not — the
integration test `run069_wrong_chain_id_candidate_rejected_without_mutation`
covers that variant in the unit-grade matrix; the live binary surfaces the same
error class through the inner `TrustBundle::load_from_path_*` loader, which the
helper test exercises end-to-end without needing a re-signed bundle.)

---

## 14. Release-binary smokes (5: negative local-revoked candidate)

```text
# Build a candidate bundle whose revocations[] revokes the LOCAL leaf cert.
$ LEAF_FP=$(cat /tmp/run069/mat/v0.leaf-fp.hex)
$ ROOT_ID=$(cat /tmp/run069/mat/root.id.hex)
$ # ... write trust-bundle.leaf-revoked.json with revocations=[{root_id, leaf_cert_fingerprint=LEAF_FP, ...}]
$ ./target/release/qbind-node --env devnet --data-dir /tmp/run069/data_fresh \
    --p2p-trust-bundle-reload-check /tmp/run069/mat/trust-bundle.leaf-revoked.json \
    --p2p-leaf-cert /tmp/run069/mat/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/run069/mat/v0.kem.sk.bin
[binary] Run 069: VERDICT=invalid (...). Reason: candidate rejects local leaf via active revocation list: local leaf certificate revoked: leaf_fp=ab6578b8.. bundle_fp=83214e45... See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_069.md.
exit=1
$ ls /tmp/run069/data_fresh/
# (empty — fresh data-dir, no prior record; reload-check did NOT create the persistence file even though local-revoked rejection happened AFTER bundle load + signature verify)
```

Full transcript: `docs/devnet/run_069_smoke_negative_local_leaf_revoked.stderr.log`.
**Persistence file mutated?** NO (fresh data-dir remained empty).
**Exit code:** `1`.

(Local-issuer-root revoked variant is covered by
`run069_local_issuer_root_revoked_candidate_rejected_without_mutation` in the
integration suite — same code path, different revocation kind.)

---

## 15. Sequence non-burn behaviour (summary)

| Path | Persistence write? |
|---|---|
| reload-check, valid candidate, no prior record | **NO** (fresh data-dir stays empty) |
| reload-check, valid candidate, prior record at lower seq | **NO** (seq-file bytes + mtime equal) |
| reload-check, valid candidate, prior record at same seq + same fingerprint | **NO** |
| reload-check, rollback candidate (lower seq than persisted) | **NO** |
| reload-check, equivocation candidate (equal seq, mismatched fingerprint) | **NO** |
| reload-check, wrong-chain candidate | **NO** |
| reload-check, tampered-signature candidate | **NO** |
| reload-check, too-soon activation candidate | **NO** |
| reload-check, local revoked-leaf candidate | **NO** |
| reload-check, local revoked-issuer-root candidate | **NO** |
| live startup `--p2p-trust-bundle`, valid bundle | **YES** (unchanged from Run 055) |

The "live startup still writes" row is asserted by
`run069_startup_path_still_persists_after_reload_check_runs_first` — the same
candidate that the reload-check refuses to persist is then handed to
`check_and_update_sequence` and **is** persisted (`SequenceCheckOutcome::Upgraded { previous_sequence: 1, new_sequence: 2 }`).
This proves Run 069 strictly extends the surface without weakening the live
write path.

---

## 16. Startup path preservation

When `--p2p-trust-bundle-reload-check` is absent, **zero** lines of
pre-existing trust-bundle / sequence / activation / revocation / metrics code
execute differently. The reload-check block in `main.rs` is gated by
`if let Some(...)`; control flow only enters that block when the flag is
explicitly supplied, and exits the process via `std::process::exit` before
reaching network-mode dispatch. The release `qbind-node` binary continues to
load signed MainNet bundles (Run 050/051/053/055/057/065 + 061/063
self-checks), persist sequence, merge active roots, and run consensus exactly
as before; this is regression-asserted by the 100/100 `pqc_trust_bundle`,
27/27 `pqc_trust_sequence`, and Run 050/051/052/055/057/061/062/063/065
integration suites all passing on the same binary that contains the new
reload-check hook.

---

## 17. Honest boundary statements

- **Live trust apply is not implemented.** Run 069 does not merge candidate roots, does not update active revocation sets, does not re-seed `qbind_p2p_pqc_*` metric gauges, does not rekey or evict peer sessions, and does not advance the persisted highest sequence. Operators who want a new bundle live MUST still restart the binary with the new file under `--p2p-trust-bundle`.
- **Peer-supplied / gossiped bundle acceptance is not implemented.** The reload-check only accepts a local file path the operator already controls (same trust model as `--p2p-trust-bundle`). No network ingress, no gossip handler, no automatic filesystem watcher.
- **`activation_epoch` runtime source is not implemented.** `ActivationContext.current_epoch` is `None` on the reload-check path (Run 057 boundary unchanged).
- **In-binary / on-chain bundle-signing-key ratification is not implemented.** Out-of-band CLI overlap (Run 060 §6.D) remains the supported rotation path.
- **External KMS / HSM custody is not implemented.**
- **Production fast-sync / consensus-storage restore is not implemented.**
- **Per-environment production trust-anchor operation is not implemented** beyond what Run 060 / Run 066 already document.

---

## 18. No-fallback / no-Dummy-crypto proof

- No `Cargo.toml` change; no new dependency.
- No `Dummy*` primitive referenced (the reload-check reuses `MlDsa44Backend` for signature verification through the same `TrustBundle::load_from_path_*` function the live binary uses).
- No `--p2p-trusted-root` fallback path. The reload-check refuses TestNet/MainNet without a signing key (FATAL exit) and refuses TestNet/MainNet without `--data-dir` (FATAL exit) — there is no silent degradation to "validate without checking anti-rollback" or "validate without checking signature".
- No bypass of the Run 050 trust-separation invariant: the reload-check rejects any bundle whose signing-key id collides with a transport-root id, because it routes through the same `TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation` function that enforces it.

---

## 19. Remaining open items (C4 remains OPEN)

- actual live trust-bundle **apply** (root merge + session rekey + metrics retag);
- peer-supplied / gossiped bundle acceptance;
- automatic filesystem-watcher hot reload (intentionally NOT in scope);
- `activation_epoch` runtime source;
- in-binary / on-chain bundle-signing-key ratification;
- external KMS / HSM custody integration;
- production fast-sync / consensus-storage restore;
- per-environment production trust-anchor operation.

**C4 remains OPEN. C5 is not addressed by Run 069.**

---

## 20. Exact immediate next action recommended

Implement the **live trust-bundle apply** half of C4:
- when the reload-check verdict is valid, atomically swap the active `LoadedTrustBundle` reference behind the P2P trust-set; update Run 062 active/pending revocation gauges to reflect the new bundle; **then** commit the new sequence record via `check_and_update_sequence` (so the persistence write happens exactly when the live apply succeeds, never before);
- handle peer-session implications (evict sessions anchored on roots that the new bundle marks revoked; preserve sessions anchored on roots that remain active);
- decide and document the metrics surface (e.g. `qbind_p2p_pqc_trust_bundle_reload_applied_total` increments only after the atomic swap commits);
- write a Run 070 evidence document with positive (apply succeeds, sessions preserved, metrics retagged) and negative (apply refused mid-flight, no state change, sequence unchanged) release-binary smokes.

Run 069 leaves this work strictly safer to do, because the validation pipeline
is already factored into a non-mutating helper that the future apply path can
reuse.