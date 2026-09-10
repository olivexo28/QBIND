# QBIND DevNet Evidence — Run 418

**Authenticated KEMTLS peer → consensus sender binding (F6).** Run 418 is a
**production-code security-remediation run**: it implements and proves, in code and test, the
transport-session-to-consensus-sender binding identified as finding **F6** by the Run 417
foundational runtime-security audit. It binds the authenticated KEMTLS peer identity (a full
32-byte certificate-derived `NodeId`, plus the peer's validator identity) to the sender a
consensus message claims to be from, and it fails closed on any missing, unknown, ambiguous, or
mismatched identity.

**F6 is transport-session-to-consensus-sender binding and accountability only.** Closing F6
does **not** make cryptographic proposal/vote/timeout/new-view/QC signatures meaningful and must
**not** be represented as fixing F3, F4, F5, F7, F8, RS1, C4, or C5. Run 418 published **no**
live seed, moved **no** readiness item Green, and changed **no** TestNet/MainNet posture.

**Safety label:** DevNet · experimental · resettable · no value · no uptime SLA ·
**code/test remediation of F6 only** · **no release-binary evidence** · NOT public-DevNet
launch-ready · **M4 Yellow / launch-blocking** · M6 Yellow/Partial · S5 Yellow · S7 Yellow ·
**RS1 OPEN / launch-blocking** · **C4/C5 OPEN** · public DevNet **NO-GO** · no TestNet readiness ·
no MainNet readiness. **No private key material is committed.**

## 1. Exact verdict

- **Overall:** `F6-REMEDIATED-IN-CODE-AND-TEST / NO-RELEASE-BINARY-EVIDENCE`.
- **Run 418 harness:** `RESULT=POSITIVE-FOR-F6-CODE-TEST-REMEDIATION`,
  `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`.
- **Scope guard:** F6 remediation is asserted for the in-crate consensus-ingress path
  (`binary_consensus_loop::handle_inbound_consensus_msg` under an installed
  `PeerConsensusBindingGate`), proven by unit + integration tests. It is **not** asserted for
  the deployed release binary: no real release-binary run captured mismatched-identity rejection
  on a live multi-node network. That release-binary evidence remains outstanding.

F6 alone does not close F3/F4/F5/F7/F8. Consensus proposals and votes are still emitted
**unsigned** with the **toy** suite id `0`, inbound messages are still accepted **without**
signature/membership/suite verification, and proposal-carried **QCs are still imported with empty
signer evidence**. Run 418 changes none of that; it only binds the authenticated transport peer
to the claimed sender.

## 2. Baseline

- Run 417 finalization base: `2974f203251a57ded30c9486abf59adfd08419cc`.
- Task-file swap commit (`RUN_417_TASK.txt` → `RUN_418_TASK.txt`):
  `51deb6d543ce5cfc4884d373e49925d0aafefb04` (pre-implementation baseline).
- Run 418 preliminary implementation commit: `82c4b6d` ("update").
- Run 418 continuation (this run) builds on `82c4b6d`. The semantic footprint vs `82c4b6d` is
  the ten files listed in §6. All other pre-existing files were restored to their original
  line-ending style after an accidental package-wide formatting pass was reverted (see §5).

## 3. What F6 binding enforces

The authoritative decision point is `PeerConsensusBindingGate::authorize`
(`crates/qbind-node/src/peer_consensus_binding.rs`). For every inbound consensus message that
reaches the binary consensus loop with a gate installed:

1. An **authenticated origin must be present**. A message with no verified transport origin is
   rejected `MissingOrigin` (fail-closed). This is the mandatory, non-bypassable path: the
   default `ConsensusInboundHandler::handle_consensus_msg_from` is now required, and the
   bare-message compatibility surface forwards `origin = None`, which fails closed under any
   installed production gate.
2. The authenticated peer's **full 32-byte `NodeId`** must be present in the authoritative
   one-to-one `NodeId ↔ ValidatorId` map, else `UnknownPeer`.
3. The authenticated peer's `NodeId` and `ValidatorId` must agree with the configured one-to-one
   mapping, else `AmbiguousMapping` (this rejects an alternate root-valid certificate for the
   same validator that carries an unconfigured leaf `NodeId`).
4. The **claimed sender** (`proposer_index` for proposals, `validator_index` for votes) must be a
   known validator (`UnknownValidator`) and must equal the authenticated peer's validator
   (`ClaimedSenderMismatch`).

Only when all checks pass is the authenticated `ValidatorId` returned and used as the engine
sender. Every rejection increments a **fixed, low-cardinality** metric label
(`qbind_consensus_binding_total{result="…"}`) and the loop's
`inbound_sender_binding_rejected_total`, and causes **no** engine call, reconfiguration
observation, mutation, outbound action, or accepted/delivered increment.

## 4. Certificate-map construction and identity provenance

- **Authoritative map admission** (`p2p_node_builder::validated_cert_bound_node_id`): a
  certificate is admitted into the binding map only after structural/suite validation,
  verification against the configured PQC root, a canonical validator-ID match, a validator index
  `< num_validators`, revocation/environment checks where the active handshake policy provides
  them, and derivation of the full 32-byte `NodeId`. Decode success alone never admits a binding.
  Duplicate, ambiguous, or colliding entries fail map construction (startup).
- **Strict validator-ID parsing** (`p2p_node_builder::parse_test_validator_id_from_cert_validator_id`):
  `qbind-val-<N>` must be followed only by canonical zero padding. Noncanonical leading zeros,
  trailing nonzero/arbitrary bytes, overflow, and out-of-range indices are rejected via a
  definitive canonical round-trip.
- **Inbound (server-side) verified client identity**: surfaced from the established session and
  carried on `InboundConsensusEnvelope.origin`; it drives the engine end-to-end (a matching
  authenticated proposal produces a real outbound vote).
- **Outbound (client-side) verified server identity**: surfaced from the established client-side
  connection via `VerifiedServerIdentity` (full cert-derived `NodeId`, validator identity,
  authentication-complete state) and compared against the configured expected pair. Configuration
  and `vid@addr` identify the *expected* peer but never mint the authenticated origin: an
  unexpected server certificate/identity cannot inherit the configured address's origin, and a
  mismatch rejects the session.

The `AuthenticatedConsensusOrigin` type is a purely in-process value: it does not derive
`serde` and is never serialized onto the wire. The origin is absent from the serialized consensus
bytes.

## 5. Line-ending / formatting reconciliation

The preliminary continuation accidentally ran a package-wide `cargo fmt` that both converted
CRLF→LF and rustfmt-reformatted ~516 pre-existing files unrelated to F6. That churn was reverted:
every pre-existing file was restored to its original line-ending style and formatting, so the
tree vs the preliminary base `82c4b6d` shows **only** the ten intended files in §6. New
shell/text evidence files are LF. No repository-wide formatting that rewrites unrelated files
remains.

## 6. Changed files (vs `82c4b6d`)

| File | Purpose |
| --- | --- |
| `crates/qbind-node/src/peer_consensus_binding.rs` | F6 gate/map/origin/metrics (pre-existing in `82c4b6d`; unchanged here) |
| `crates/qbind-node/src/binary_consensus_loop.rs` | ingress gate wiring; F5/NewView wording |
| `crates/qbind-node/src/p2p_node_builder.rs` | validated cert-map admission + strict validator parsing |
| `crates/qbind-node/src/p2p_tcp.rs` | outbound verified-server-identity comparison on both dial paths |
| `crates/qbind-node/src/secure_channel.rs` | `VerifiedServerIdentity` + identity-surfacing connect |
| `crates/qbind-node/src/p2p_inbound.rs` | mandatory origin-carrying handler; fail-closed bare surface |
| `crates/qbind-node/src/lib.rs` | re-exports |
| `crates/qbind-net/src/handshake.rs` | surface verified server `NodeId` in `HandshakeResult` |
| `crates/qbind-net/src/connection.rs` | client-side `peer_node_id` = verified server identity |
| `crates/qbind-node/src/p2p_liveness.rs` | restored (undo accidental clobber) |
| `crates/qbind-node/tests/run_418_authenticated_peer_consensus_sender_binding_tests.rs` | new: 12 acceptance tests |

## 7. Evidence classification

- **Code + test remediation:** POSITIVE for F6 on the in-crate consensus-ingress path (unit +
  integration tests pass).
- **Release-binary evidence:** ABSENT. No live multi-node release-binary capture exists.
- This run does not, and does not claim to, resolve F3/F4/F5/F7/F8, RS1, C4, or C5.

## 8. Preserved posture (unchanged by this run)

- F1–F5 and F7–F8 remain **unresolved**.
- **RS1 OPEN / launch-blocking.**
- M4 Yellow / launch-blocking · M6 Yellow/Partial · S5 Yellow · S7 Yellow.
- **C4/C5 OPEN.**
- public DevNet **NO-GO / not launch-ready**.
- No `devnet-seeds.live.json`; candidate remains `planned` with null reachability evidence.
- TestNet and MainNet untouched.

## 9. Provenance

- Evidence archive: `docs/devnet/run_418_authenticated_peer_consensus_sender_binding/`.
- Standing reconciliation: `docs/protocol/QBIND_FOUNDATIONAL_RUNTIME_SECURITY_RECONCILIATION.md`.
- Fail-closed harness: `scripts/devnet/run_418_authenticated_peer_consensus_sender_binding.sh`.