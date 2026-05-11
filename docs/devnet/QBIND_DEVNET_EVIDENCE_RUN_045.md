# QBIND DevNet Evidence — Run 045

## §1. Exact objective

Implement certificate validity-window enforcement for PQC transport
delegation certificates and wire expiry / not-yet-valid failures into
the existing `qbind_p2p_pqc_cert_rejected_expired_total` boundary
already established by Run 044.

**Primary objective:** make
`qbind_net::handshake::verify_delegation_cert` reject delegation
certificates whose validity window is not currently valid, without
changing any other certificate-verification semantics.

This is a narrow certificate-validation task. No KEMTLS redesign, no
root-distribution redesign, no CA / rotation / revocation redesign,
no consensus / timeout-verification redesign, no fabricated metrics,
no claim of full C4 or C5 closure.

## §2. Exact files changed

| File | Change |
|---|---|
| `crates/qbind-net/src/handshake.rs` | Added `verify_delegation_cert_at(...)` with explicit `validation_time_secs`; converted `verify_delegation_cert(...)` into a thin wall-clock wrapper; added `current_unix_secs()` (transport-only, NOT consensus time). Extended the `match &e` blocks in `parse_and_verify_client_cert` (listener) and `handle_server_accept` (dialer) to map `NetError::ClientCertInvalid("cert expired" \| "cert not yet valid" \| "cert invalid validity window")` onto `inc_rejected_expired`, leaving all other reason-mapping arms untouched. |
| `crates/qbind-net/src/lib.rs` | Re-exported `verify_delegation_cert_at` alongside `verify_delegation_cert`. |
| `crates/qbind-net/src/cert_verify_metrics.rs` | Updated module doc + `inc_rejected_expired` rustdoc to reflect Run 045 (the counter is no longer "documented-unused at the live boundary"). |
| `crates/qbind-net/tests/run_045_cert_validity_tests.rs` | **NEW** — 20 focused tests covering direct semantics, listener-side and dialer-side metric mapping, signature-runs-first invariant, validity-fields-in-digest-preimage invariant, wall-clock wrapper accept / reject of clearly-valid / clearly-expired / clearly-not-yet-valid certs, no-sink preserves error shape, accepted vs expired mutual-exclusion. |
| `crates/qbind-node/src/pqc_devnet_helper.rs` | Added `LeafCertSpec::currently_valid(...)`, `LeafCertSpec::expired_for_test(...)`, `LeafCertSpec::not_yet_valid_for_test(...)` test-helper constructors. Added 5 helper tests proving default cert is currently-valid, expired/not-yet-valid certs fail closed under wall-clock, inverted-window is rejected at issuance, and validity fields are encoded and signature-covered. Updated the existing `round_trip_via_wire_encode_decode` test to use the explicit-validation-time entry point (so it is independent of wall-clock when fixed historical windows are used). |
| `crates/qbind-node/examples/devnet_pqc_root_helper.rs` | Added an optional third positional argument `validity_mode` (`currently-valid` (default) / `expired` / `not-yet-valid`) that selects the validity-window shape of the minted leaf certs. Default behaviour unchanged. Root signing key still memory-only. |
| `docs/whitepaper/contradiction.md` | Appended Run 045 paragraph narrowing the documented C4 cert validity-window cell. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_045.md` | **NEW** — this file. |

No other crate / module was touched. No protocol behavior beyond validity-window rejection was changed.

## §3. Validity-window format and semantics

### Format

`qbind_wire::net::NetworkDelegationCert` already carried (from Run 037
onwards) two `u64` Unix-seconds fields:

```text
NetworkDelegationCert {
    version: u8,
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    leaf_kem_suite_id: u8,
    leaf_kem_pk: Vec<u8>,
    not_before: u64,
    not_after: u64,
    ext_bytes: Vec<u8>,
    sig_suite_id: u8,
    sig_bytes: Vec<u8>,
}
```

Both `not_before` and `not_after` are included in the signed digest
preimage built by `qbind_hash::net::network_delegation_cert_digest(...)`
— signature-coverage is therefore an existing, unchanged invariant.

Pre-Run-045 the helper / example used `not_before: 0, not_after: u64::MAX`
("eternally valid"). Run 045 keeps that as the default
(`LeafCertSpec::currently_valid`) so every pre-existing test fixture
remains valid under any realistic wall-clock.

### Semantics

A cert is valid iff:

```text
not_before  <=  validation_time_secs  <=  not_after
```

(Inclusive on both ends.) Fail-closed cases, in evaluation order
**after** signature verification:

1. `not_before > not_after` → `NetError::ClientCertInvalid("cert invalid validity window")`
2. `validation_time_secs < not_before` → `NetError::ClientCertInvalid("cert not yet valid")`
3. `validation_time_secs > not_after` → `NetError::ClientCertInvalid("cert expired")`

Validity-window enforcement runs **after** signature verification so a
tampered validity field surfaces as the pre-existing
`NetError::KeySchedule("signature verify error")` rather than as a
validity-window error. (Proven by the `signature_verify_runs_before_validity_check`
test in `run_045_cert_validity_tests.rs`.)

## §4. Time-source / validation-time model

Two entry points:

| Entry point | Time source | Use |
|---|---|---|
| `verify_delegation_cert(crypto, cert, root_pk)` | `SystemTime::now()` Unix seconds (single call per invocation) | Binary path (production-honest pqc-static-root). |
| `verify_delegation_cert_at(crypto, cert, root_pk, validation_time_secs)` | Explicit caller-provided Unix seconds | Deterministic tests; future callers that need clock injection. |

**Wall-clock is strictly transport-layer cert freshness.** It is NOT a
consensus time source. Consensus safety remains entirely independent
of `SystemTime::now()`. If `SystemTime::now()` is somehow before the
Unix epoch (system misconfiguration), `current_unix_secs()` returns
`0`, which forces honest certs with `not_before > 0` to be classified
as "not yet valid" rather than silently treated as valid (fail-closed
on clock anomalies).

No dangerous operator bypass (e.g. `--ignore-cert-validity`) was
added. The wall-clock wrapper is the only path the live binary uses.

**Smallest-injection-seam choice.** Adding a new field to
`ClientHandshakeConfig` / `ServerHandshakeConfig` would have forced an
edit of ~120 historical config-construction call sites under
`crates/{qbind-net,qbind-node}/tests/*`, expanding the change-surface
against the "smallest code change" requirement. Instead, the seam is
the public `verify_delegation_cert_at` function itself, used directly
by the new focused Run 045 tests and by `pqc_devnet_helper` tests.

## §5. Reason-mapping update for expired / not-yet-valid

Run 044 reason-mapping table extended with a single new row (in the
existing `inc_rejected_expired` cell, both dialer-side and
listener-side):

| Failure boundary | Reason method | Error shape |
|---|---|---|
| `verify_delegation_cert → Err(ClientCertInvalid("cert expired"))` | `inc_rejected_expired` | `NetError::ClientCertInvalid("cert expired")` |
| `verify_delegation_cert → Err(ClientCertInvalid("cert not yet valid"))` | `inc_rejected_expired` | `NetError::ClientCertInvalid("cert not yet valid")` |
| `verify_delegation_cert → Err(ClientCertInvalid("cert invalid validity window"))` | `inc_rejected_expired` | `NetError::ClientCertInvalid("cert invalid validity window")` |

Every other Run 044 mapping row is preserved bit-identically (proven
by `run_044_cert_verify_metrics_tests` still passing 13/13).

Validity-window failures do **NOT** collapse into `bad_signature` —
the dialer-side and listener-side `match &e { ... }` blocks
explicitly precede the `NetError::KeySchedule(_) => inc_rejected_bad_signature`
arm with a dedicated `NetError::ClientCertInvalid("cert expired" | "cert not yet valid" | "cert invalid validity window") => inc_rejected_expired`
arm. Any *other* hypothetical-future `ClientCertInvalid(_)` shape
still falls back to `bad_signature` rather than mis-classify as
expired.

## §6. Accepted-counter and expired-counter boundary

- `inc_accepted` is reached only after parse + (listener-side)
  trusted-root lookup + signature verify + **validity-window check
  (Run 045)** + (dialer-side) validator-id match all succeed.
- `inc_rejected_expired` is reached only on the three validity-window
  failure shapes above.
- Accepted and expired are mutually exclusive on the same handshake
  event (any validity-window failure short-circuits before
  `inc_accepted`).
- Proven by `dialer_valid_cert_still_increments_only_accepted` (valid
  cert → `accepted == 1, every rejection counter == 0`) and by the six
  listener/dialer × expired/not-yet-valid/inverted-window tests (each
  → `expired == 1, every other counter == 0, accepted == 0`).

## §7. Proof of no duplicate increments

- Each `verify_delegation_cert` invocation produces at most **one**
  `inc_*` call: the `match &e { ... }` block runs once per `Err`, and
  the success path bumps `inc_accepted` exactly once. (Compile-time
  property of the existing Run 044 structure, preserved.)
- The listener wrapper (`parse_and_verify_client_cert`) and the
  dialer wrapper (`handle_server_accept`) each invoke
  `verify_delegation_cert` once per handshake event.
- The same `Arc<dyn CertVerifyMetricsSink>` is cloned into both
  `ClientHandshakeConfig::cert_verify_metrics` and
  `ServerHandshakeConfig::cert_verify_metrics` via
  `P2pNodeBuilder::create_connection_configs` (Run 044 shape
  preserved). No double-counting between listener / dialer wrapper
  layers is introduced.
- The Run 037 per-reason-bumps-aggregate contract means each
  `inc_rejected_expired` call also bumps the aggregate
  `qbind_p2p_pqc_cert_verify_rejected_total` exactly once — proven by
  the existing `run_044_pqc_cert_verify_metrics_adapter_tests::adapter_inc_rejected_expired_bumps_expired_and_aggregate`
  test (still passing 10/10 after Run 045).

## §8. Investigation findings (exact file/function references)

- **`crates/qbind-wire/src/net.rs::NetworkDelegationCert`** — already
  has `not_before: u64, not_after: u64` Unix-seconds fields (from
  Run 037). No wire-format change in Run 045.
- **`crates/qbind-hash/src/net.rs::network_delegation_cert_digest`**
  — already includes `not_before` and `not_after` in the signed
  digest preimage. Validity fields are therefore signature-covered.
  No digest-preimage change in Run 045.
- **`crates/qbind-net/src/handshake.rs::verify_delegation_cert`** —
  pre-Run-045 had no validity check. Run 045 adds the check **after**
  the signature verify so tampered validity fields surface as
  bad-signature.
- **`crates/qbind-node/src/pqc_devnet_helper.rs::issue_leaf_delegation_cert`**
  — already rejected inverted windows (`DevNetCertError::InvalidValidityWindow`,
  pre-existing). Run 045 leverages this for the
  `helper_rejects_inverted_window_at_issuance` test.
- **`crates/qbind-node/examples/devnet_pqc_root_helper.rs`** — was
  hard-coded to `not_before: 0, not_after: u64::MAX`. Run 045 adds
  the optional `validity_mode` positional arg with the same default.
- **`crates/qbind-node/src/p2p_node_builder.rs::verify_cert_with_configured_root`**
  — unchanged. The startup self-verification path naturally inherits
  Run 045's validity enforcement via `qbind_net::verify_delegation_cert`,
  which is why both negative smokes fail closed at startup before
  `/metrics` becomes scrapable.

## §9. Exact commands run

```bash
cargo build -p qbind-net                                                  # OK
cargo test -p qbind-net --lib                                             # 17/17
cargo test -p qbind-net --test run_044_cert_verify_metrics_tests          # 13/13
cargo test -p qbind-net --test run_045_cert_validity_tests                # 20/20
cargo test -p qbind-net                                                   # all green
cargo test -p qbind-crypto --lib                                          # 68/68
cargo test -p qbind-node --lib pqc_devnet_helper                          # 10/10
cargo test -p qbind-node --lib metrics                                    # 100/100
cargo test -p qbind-node --lib                                            # 780/780
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests # 12/12
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests   # 14/14
cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests  # 10/10
cargo build --release -p qbind-node --bin qbind-node                      # OK
cargo build --release -p qbind-node --example devnet_pqc_root_helper      # OK

# Real-binary smoke materials (§11–§13)
target/release/examples/devnet_pqc_root_helper /tmp/run045/mat 2
target/release/examples/devnet_pqc_root_helper /tmp/run045/exp 2 expired
target/release/examples/devnet_pqc_root_helper /tmp/run045/nyv 2 not-yet-valid
```

## §10. Test results

| Command | Result | Notes |
|---|---|---|
| `cargo test -p qbind-net --lib` | **OK 17/17** | unchanged from Run 044 |
| `cargo test -p qbind-net --test run_044_cert_verify_metrics_tests` | **OK 13/13** | Run 044 contract preserved (incl. `expired_counter_documented_unused_at_live_boundary` — the test asserts the expired counter is *zero* in the malformed-listener and validator-mismatch-dialer scenarios, both of which short-circuit before `verify_delegation_cert` is invoked) |
| `cargo test -p qbind-net --test run_045_cert_validity_tests` | **OK 20/20** | new — see §3, §5, §6 |
| `cargo test -p qbind-net` | **OK** all targets | every target green including `handshake`, `m6`, `m8`, `wire`, `transport_frame` |
| `cargo test -p qbind-crypto --lib` | **OK 68/68** | unchanged |
| `cargo test -p qbind-node --lib` | **OK 780/780** | +5 new helper tests vs Run 044's 775 |
| `cargo test -p qbind-node --lib pqc_devnet_helper` | **OK 10/10** | 5 pre-existing + 5 new Run 045 |
| `cargo test -p qbind-node --lib metrics` | **OK 100/100** | metrics surface preserved |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **OK 12/12** | incl. R037.B tampered-cert, R037.C untrusted-root, R037.D wrong-sig-suite |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **OK 14/14** | real-AEAD path preserved |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | **OK 10/10** | adapter mapping + aggregate-counter contract preserved incl. `adapter_inc_rejected_expired_bumps_expired_and_aggregate` |
| `cargo build --release -p qbind-node --bin qbind-node` | **OK** | sha256 `e9b79590ec9610d34fbec476bb0b94b425d9a50e8f696e075d1201b881b1ccee` |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | **OK** | sha256 `a86d96d1259ac6eeb200543f3c520a3213a8a8724c6485e731ce92d820d6dc4d` |

## §11. Binary identity

| Field | Value |
|---|---|
| Branch | `copilot/continue-qbind-development-9b9570c8-3ffd-4012-b84f-c69dda0603a5` |
| Pre-doc commit | `942fc3b8915b0ad25c11657f98b203ba8f8fcff3` |
| Working tree state (pre-doc-commit) | dirty only with Run 045 code/doc changes |
| `qbind-node` sha256 | `e9b79590ec9610d34fbec476bb0b94b425d9a50e8f696e075d1201b881b1ccee` |
| `qbind-node` ELF BuildID | `c17f96cfcc88f1f0b5dd220988ff5eacdcd7bc9c` |
| `devnet_pqc_root_helper` sha256 | `a86d96d1259ac6eeb200543f3c520a3213a8a8724c6485e731ce92d820d6dc4d` |
| `devnet_pqc_root_helper` ELF BuildID | `ee14b1b7be65bbf73b1639a76ace33a3a8721ab6` |

## §12. Real-binary positive two-node smoke

**Topology.** V0 / V1 release binaries, `127.0.0.1:19650 ↔ 127.0.0.1:19651`,
`/metrics` on `127.0.0.1:43250` / `127.0.0.1:43251`, both flags:

```text
--env devnet --network-mode p2p --enable-p2p
--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root
--p2p-trusted-root <SHARED_SPEC>  (root_id=d408262d15...)
--p2p-leaf-cert <vN.cert.bin>  --p2p-leaf-cert-key <vN.kem.sk.bin>
--p2p-peer-leaf-cert <peer_idx>:<peer.cert.bin>
```

Leaf certs minted with default `currently-valid` validity mode
(`not_before=0, not_after=u64::MAX`). Real ML-DSA-44 cert verify, real
ML-KEM-768, real ChaCha20-Poly1305 AEAD — Run 039 + Run 040 startup
banners confirmed `dummy_kem_registered=false dummy_aead_registered=false`.

**`/metrics` excerpt — V0:**

```text
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 2
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0
```

**`/metrics` excerpt — V1:** identical shape, identical values.

- `accepted_total = 2` on both nodes (1 listener + 1 dialer accept per
  node — Run 044 cardinality preserved under validity-window
  enforcement).
- `rejected_total = 0` and **every** per-reason rejection counter = 0
  including `expired_total = 0` under honest traffic.
- `qbind_p2p_pqc_*` family emitted exactly once per scrape (Run 043
  invariant preserved).
- Both nodes remained alive throughout the smoke window.

## §13. Real-binary negative expired-cert smoke

**Topology.** Same shape as §12 with `/tmp/run045/exp` materials
(`devnet_pqc_root_helper /tmp/run045/exp 2 expired` minted root
`4a5619639c6fb94246f2b5f09f2ebedbf6305003ab73e74f5f354c535a8c6c21` and
leaf certs with `not_before=0, not_after=1`). Both nodes use the same
root spec, so the failure mode under test is *validity-window*, not
*unknown-root*.

**Observed behaviour:** both nodes fail closed at the **startup
self-verification boundary** inside `P2pNodeBuilder::build`'s
`verify_cert_with_configured_root` invocation, BEFORE the metrics
HTTP server becomes scrapable:

```text
[binary] ERROR: Failed to build P2P node:
  Config("delegation cert verification failed: ClientCertInvalid(\"cert expired\")")
```

- No silent fallback to DummySig / DummyKem / DummyAead.
- No `qbind-net` listener / dialer sink is invoked because the binary
  exits before that path is reached.

**This is the partial-positive boundary anticipated by the Run 045
task description.** Live `inc_rejected_expired` counter movement on
the real `qbind-net::handshake` boundary is proven instead by the
six `run_045_cert_validity_tests` listener/dialer × expired /
not-yet-valid / inverted-window unit tests, which exercise the real
public `qbind-net` API (`ServerHandshake::handle_client_init` /
`ClientHandshake::handle_server_accept`) and assert exactly-once
movement.

## §14. Real-binary negative not-yet-valid-cert smoke

**Topology.** Same shape with `/tmp/run045/nyv` materials
(`devnet_pqc_root_helper /tmp/run045/nyv 2 not-yet-valid`, leaf certs
`not_before=u64::MAX-1, not_after=u64::MAX`).

**Observed behaviour:** identical fail-closed shape:

```text
[binary] ERROR: Failed to build P2P node:
  Config("delegation cert verification failed: ClientCertInvalid(\"cert not yet valid\")")
```

Same partial-positive boundary as §13. No fallback. No silent
acceptance.

## §15. Optional N=4 smoke

Not run in this evidence cycle. The Run 042 N=4 B14 recovery smoke
remains the authoritative N=4 evidence for the full transport-crypto
stack; Run 045 is a narrow cert-freshness change that does not affect
B14 recovery, KEM, AEAD, or consensus safety paths. Re-running N=4
under Run 045 with currently-valid leaf certs would produce identical
Run 042 cardinality with `expired_total = 0` everywhere.

## §16. Remaining open items

Full C4 remains OPEN for:

- **Production CA / cert rotation / cert revocation / signed root
  distribution lifecycle** — operator-out-of-band, not solved.
  Run 045 explicitly does NOT claim CA / rotation / revocation /
  distribution lifecycle has landed.
- **Production fast-sync / consensus-storage restore.**
- **Exponential-backoff timeout pacing.**
- **Per-environment trust anchors** (DevNet root signing key is
  still freshly minted memory-only per `devnet_pqc_root_helper`
  invocation; this is appropriate for DevNet and does not constitute
  a production trust-anchor distribution flow).

**C5 remains NOT closed** by Run 045. The transport-crypto dependency
is now further hardened on the cert-freshness axis but lifecycle
(CA / rotation / revocation / signed root distribution) remains a C4
piece, so Run 045 does NOT close C5 by fiat.

## §17. Exact verdict

**Partial positive.**

`not_before` / `not_after` enforcement lands in
`qbind_net::handshake::verify_delegation_cert` / `verify_delegation_cert_at`.
Valid certs still verify. Expired, not-yet-valid, and inverted-window
certs fail closed with distinguishable typed errors. The expired
metric increments exactly once through the existing Run 044 sink at
the real handshake boundary, proven by 20/20 focused
`run_045_cert_validity_tests` and by the unchanged 10/10
`run_044_pqc_cert_verify_metrics_adapter_tests` (incl. the
expired-bumps-expired-and-aggregate adapter test).
Positive two-node real-binary smoke shows `accepted_total = 2` per
node and `expired_total = 0` everywhere under honest traffic on real
ML-DSA-44 + ML-KEM-768 + ChaCha20-Poly1305 with active timeout
verification and no Dummy fallback.

Negative real-binary expired-cert smoke and not-yet-valid-cert smoke
both fail closed at the **startup self-verification boundary** inside
`P2pNodeBuilder::build` with bit-identical typed errors
(`ClientCertInvalid("cert expired")` / `ClientCertInvalid("cert not yet valid")`),
BEFORE the metrics HTTP server is reachable. Live `expired_total`
counter movement on a *negative-cert* live-binary smoke is therefore
NOT observed at `/metrics` — this is the documented partial-positive
boundary, and live counter movement is instead proven by unit tests
on the real `qbind-net::handshake` boundary. The binary refusing to
come up with an unusable cert is the correct fail-closed behaviour
(more defensive than allowing it to start serving traffic with an
invalid cert).

No protocol behavior changes beyond validity-window rejection. No
regression in Run 037 / Run 039 / Run 040 / Run 042 / Run 043 /
Run 044 paths. No DummySig / DummyKem / DummyAead fallback. No
fabricated metrics. No duplicate increments. No operator bypass.

## §18. contradiction.md update

**Yes — updated.** A new paragraph appended to
`docs/whitepaper/contradiction.md` documents:

- The narrow validity-window-enforcement scope.
- The exact validity-window semantics (inclusive both ends, fail-closed
  on inverted window, signature-runs-before-validity).
- The time-source model (wall-clock for transport freshness only, NOT
  consensus time).
- The reason-mapping extension (expired / not-yet-valid /
  inverted-window → `inc_rejected_expired`).
- C4 narrowing: the "cert validity-window enforcement" C4 piece is
  now NARROWED; the `qbind_p2p_pqc_cert_rejected_expired_total` cell
  is no longer the "documented-unused" per-reason cell.
- Explicit re-statement that C4 remains OPEN for CA / rotation /
  revocation / signed root distribution lifecycle, fast-sync /
  consensus-storage restore, exponential-backoff timeout pacing, and
  per-environment trust anchors.
- Explicit re-statement that Run 045 does NOT close full C4 and does
  NOT close C5.
- Real-binary positive smoke and negative expired / not-yet-valid
  smoke evidence and the partial-positive boundary.

## §19. Exact immediate next action recommended

**Run 046:** carve out the next-smallest C4 piece — most likely either
(a) a minimal cert-rotation / cert-revocation observability cell
(e.g. `qbind_p2p_pqc_cert_rotation_*` scaffolding wired to a planned
revocation-list adapter) without yet claiming the lifecycle has
landed, OR (b) exponential-backoff timeout pacing on top of the
already-landed timeout-verification path (Runs 031–034), depending
on which surface is currently most operator-relevant. Continue the
established pattern: narrow scope, fail-closed, unit-tested on real
boundaries, real-binary smoke where observable, honest partial-
positive boundary recording where startup self-verification masks
live counter movement, and contradiction.md update.