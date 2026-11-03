# RUN 422 — Separately protected, stateful PQ consensus signer

**DRAFT / FEASIBILITY ASSESSMENT / NOT APPROVED / NOT IMPLEMENTED**

This assessment evaluates a candidate for fixed founding-authority membership
(Profile A) and one separately protected, stateful PQ signing service per
validator. It does not choose a service operator, hosting provider, key
custodian, activation credential, rollback boundary, hardware, capacity,
membership, voting weight, or production profile. It does not enable signing,
change a protocol, or establish deployment readiness. No code, tests, builds,
services, keys, or activation were run or created for this assessment.

The assessment is limited to repository source and already-recorded evidence at
starting commit `bd0e4ebeb658fb5001e31f1ff10fd094e847f8c8` (tree
`325bbeab1381c4922c78446732585abd43b31dfc`). That checkout is shallow at the
starting commit: its two parent headers are `69867501a867669bcf177e8f5d6d2389f632818e`
and `fa6e5e5fd3ee987173c67e48fe75d1301d74df40`, but neither parent object is
available locally. The boundary does not mean either parent was absent from
history. No ancestry beyond the baseline is inferred.

## Executive assessment

A separately administered signer could reduce exposure of validator private
keys to a compromised consensus-node host, but only if the key, signer state,
activation roots, administration, recovery credentials, and any freshness or
fencing service are genuinely outside the node's rollback and compromise
domains. A different process, VM, disk, cloud account, backup, or transport
connection alone does not establish that independence.

The repository has reusable local consensus-signing interfaces, canonical
preimage encoders, KEMTLS channel components, local Proposal/Vote reservation
logic, and isolated safety-record/QC/TC work. It does not have a live
stateful remote consensus signer: the standalone daemon does not handshake or
dispatch; the production node signer loader rejects remote and HSM modes; the
node's production consensus loop supplies no D10 journal and no active
Proposal/Vote authority; the D7D14 store is disabled and unwired; and no
independent rollback-resistant history or cross-host exclusivity mechanism is
established. The different `pqc_remote_*` family concerns governance/trust
authority custody and remains source/test-only.

**Feasibility:** conditionally plausible as a future architecture, but the
complete safe cross-process protocol cannot yet be specified because activation
trust, independent currentness, rollback/fencing, owner/recovery roles, and the
node/signer state correspondence are unresolved.

**Implementation:** not implemented for consensus signing; the existing
components have local, isolated, simulated, or unsupported scope as detailed
below.

**Deployment:** not deployable or approved today. Activation remains disabled,
public DevNet remains NO-GO, C4/C5 and RS1 remain OPEN, and candidate limits
remain unapproved.

## What exists in source

“Actual caller” distinguishes executable callers from a helper's possible
caller or a test. “Evidence scope” describes source reachability, not an
operational claim.

| Path / symbol | Actual caller | Implemented behavior | Evidence scope | Reusable part | Missing requirement |
|---|---|---|---|---|---|
| `validator_signer.rs::ValidatorSigner`, `LocalKeySigner` | `signer_loader::load_validator_signer_from_config`, reached from `main.rs::run_p2p_node`; harness `hotstuff_node_sim.rs` also constructs signers | In-process signing of caller-provided bytes for Proposal, Vote and Timeout; exposes identity/suite; Timeout can construct a canonical timeout preimage | Implemented local interface and local-key signer; not an independently protected service | Typed signer boundary and operation-specific methods | No remote protocol, durable state, activation/root admission, canonical-request validation, or independent key custody |
| `remote_signer.rs::RemoteSignerClient`, `LoopbackSignerTransport` | `hotstuff_node_sim.rs` harness constructs the loopback client; no production constructor found | Client increments an in-memory request counter and sends supplied preimage; `sign_common` itself does not compare the returned `request_id`. `TcpKemTlsSignerTransport::decode_response` validates the echoed ID before returning; loopback checks the counter and delegates to a colocated `LocalKeySigner` | Simulated/in-process; no production caller | Request/response structs, byte codec, fail-closed client shape, and client transport interface | Counter is reset on client construction, is not a consensus position, and is neither durable history nor cross-client exclusion |
| `remote_signer.rs::TcpKemTlsSignerTransport` | No production construction found; `RemoteSignerClient` is only documented with a generic transport | Opens `SecureChannel`, sends a framed request, and returns a response after `decode_response` checks the matching response ID | Implemented source transport primitive; unverified as a live signer route | Existing client-side channel and message framing | No reachable server handler, durable signer policy, authenticated activation binding, continuity state, or failover/fencing contract |
| `qbind-remote-signer/src/main.rs` accept loop | Standalone `qbind-remote-signer` binary | Loads a backend, binds a TCP listener, accepts streams and increments a metric | Binary exists, but accepted sockets are not handshaken or dispatched; `handle_connection` is dead-code-allowed and not called | CLI/config parsing, request codec, and isolated handler shape | KEMTLS server identity/handshake, handler dispatch, durable request tracking, production stateful policy, release operation and evidence |
| `qbind-remote-signer::validate_and_sign` | Only `handle_connection`, itself not reached from the accept loop | Checks validator ID, suite 100 and preimage size; Proposal dispatches through `sign_proposal`, while Vote and Timeout dispatch through `sign_vote`. For Timeout, the client constructs the Timeout preimage, and `LocalKeySigner::sign_vote` signs supplied bytes unchanged; the method name alone does not establish a wrong domain or signature | Unreachable helper, not a live signing vulnerability or deployable behavior | Bounded framing and some identity/suite checks | Server-side canonical operation/domain validation and an explicit backend dispatch and policy contract, durable continuity, and authenticated client identity |
| `signer_loader.rs::load_validator_signer_from_config` | P2P startup in `main.rs` | Loads local plaintext/encrypted keystore signer; explicitly returns `SignerModeNotWiredYet` for `RemoteSigner` and `HsmPkcs11` | Implemented production startup loader with fail-closed unsupported modes | Local key loading and signer abstraction | Remote signer selection, signer-identity authentication, state-store construction and a safe production activation path |
| `hsm_pkcs11.rs::HsmPkcs11Signer` | Loader rejects HSM mode; daemon backend constructor can ask for it | Validates configuration but PKCS#11 calls are placeholders; signing returns tagged deterministic non-cryptographic bytes | Unsupported placeholder, not a usable HSM integration | Configuration boundary only | Real PKCS#11 calls, supported PQ mechanism, durable anti-rollback state and tested custody |
| `secure_channel.rs::SecureChannel` | TCP signer client uses `SecureChannel::connect`; server-side methods are available elsewhere | Implements client/server KEMTLS channel mechanics and surfaces verified peer information for supported channel setup | Channel primitive is implemented; signer-daemon integration is absent | PQ transport building block | Independently distributed roots, signer-specific client/server role binding, active server handshake and a complete request authorization policy |
| `pqc_remote_authority_signer.rs`, `pqc_remote_signer_transport.rs`, `pqc_production_remote_signer_backend.rs` | Pure typed functions/policies; fixture/mock paths in source/tests; no consensus `ValidatorSigner` caller | Governance/trust-authority identity, transport-envelope, transcript and backend outcome models; production policies fail closed | Isolated source/test boundary; no real service I/O, KMS, HSM or production runtime wiring | Typed envelope and fail-closed modeling patterns, only if separately reviewed for consensus use | This is not the consensus signer protocol, its state, or a deployable service |
| `signing_reservation_journal.rs` (D10) and `storage.rs` | `binary_consensus_loop` guard accepts an optional journal; D10 storage implementations and focused tests | Local Proposal/Vote decision reservation before invocation, refusal on conflicts/uncertainty, durable result publication, and exact retained-result reuse; RocksDB path uses synced writes | Implemented isolated local code/storage scope and historical process evidence; production loop passes `None`, startup does not initialize it | The local reservation/result state machine and storage contract | Cross-process ownership, signer-side RPC identity, external anti-rollback, independent freshness, and production initialization/wiring |
| `safety_record_store/` (D7D14) | Focused tests only; no production runtime/engine/signing caller | Bounded record encoding, validation, O1–O5 durable publication/recovery, profile accounting; recovered evidence remains `Unverified` absent separate verification | `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`; `D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`; default Disabled | Bounded storage/accounting and local safety-record operations | Engine and signer integration, authenticated recovery evidence, genesis activation, whole-copy anti-rollback and cross-host use |
| `BasicHotStuffEngine` / `HotStuffStateEngine::verified_justification` | Consensus engine verified-proposal flow | Retains verified QC evidence for a block in process memory; node recovery and persisted lock reconstruction are separate code paths | Implemented engine-local evidence handoff; not a signer-state service | Node-side verified-QC and safety-decision concepts | No transfer/restore protocol to an external signer; QC presence alone does not establish current authority or signing history |

The daemon's actual `main` loop accepts a `_tcp_stream`, clones some state and
logs “KEMTLS handshake not yet implemented”; it neither calls
`SecureChannel::from_accepted` nor `handle_connection`. Its helper routes
Timeout through a method named `sign_vote`, but the client constructs the
Timeout preimage and `LocalKeySigner::sign_vote` signs supplied bytes unchanged.
That method-name dispatch alone does not establish a wrong domain or signature.
The helper remains unreachable; server-side canonical operation/domain
validation and an explicit backend dispatch and policy contract are unresolved.
Similarly, a transport request counter and matching response ID establish
neither D10 continuity nor an authorized consensus position.

## Candidate boundary and trust assumptions

This candidate is an assessment, not an architecture selection:

* A founding authority would approve exact public validator identities, public
  keys and suites, validator membership and weights, network and genesis
  commitments, and the applicable QBIND signing domains/protocol version.
  Bootstrap evidence and how each signer receives independently authenticated
  trust roots must be specified. Founder authorization is only an option being
  evaluated; no founder, credential, trust root or policy is selected.
* Each validator operator would retain its own private signing key. A distinct
  signer service for that validator would mediate signing and own durable
  per-key signing history, with independent storage and administration. There
  must be one effective signing authority for each validator identity: an old
  signer, restored image, secondary key copy or replacement may not silently
  remain able to sign concurrently.
* Operator, provider, physical/virtual host, storage, backup, IAM, recovery
  credential and incident-control facts are unknown. “Separate” is a required
  property to demonstrate against a named attacker/rollback domain, not a
  property implied by a separate VM, disk or account.
* Four equal-weight validators may be used as a laboratory topology only. The
  repository's classic helper computes `f=floor((n-1)/3)` and `2f+1`; its
  weighted quorum path uses at least two-thirds of total voting power. Thus an
  equal four-member illustration has the familiar three-of-four threshold,
  assuming the selected set and weights actually match that illustration.
  The helper itself says it does not enforce the 3f+1 premise. Four processes
  do not imply four operators or independent failure domains. No validator
  count, weight, service capacity or public deployment is approved.

**Consensus node may control or falsify:** all request timing and ordering;
whether to send, withhold, duplicate or reconnect; the chosen canonical bytes;
its claimed proposal, view, parent, QC/TC, lock, ancestry, current membership or
recovery status; and its report of a prior node-side reservation or result.
A compromised node can submit syntactically valid but strategically malicious
requests. A matching `validator_id`, authenticated channel, valid historical QC,
counter, or CRC is not itself authority or a safety proof.

**Signer must validate independently, or reject:** authenticated caller and
service identities against independently provisioned trust roots; activation
and current exact network/genesis/membership/key/suite/domain bindings; the
operation kind and canonical QBIND preimage; the signing position and its
binding to exact bytes; applicable prior history and safety restrictions;
supporting authorization/evidence needed for the request; bounded framing and
resource admission; request/result identity and retry semantics; and the
durable effect/acknowledgement state before returning a result.

Proposal and Vote preimages are not opaque generic messages: the wire types
include domain-separated canonical fields (for example proposal payload kind,
next epoch, batch commitment, embedded QC and transactions; Vote version,
chain, epoch, height, round, step, block ID, validator index and suite). Timeout
has its own domain and view/high-QC fields. A signer handed raw preimage bytes
cannot know that those bytes are canonical or safe merely by signing them. It
must parse/reconstruct and bind fields or trust an authenticated, independently
verifiable proof carrying the necessary authorization and safety facts. Even
then, a signer cannot learn unprovided engine/network state: it must state
exactly what it trusts the node to establish, or refuse operations it cannot
establish. Implementing a second consensus engine is not assumed.

**Signer still trusts the node for:** truthful, complete and timely
presentation of required consensus evidence and any current-state proof not
independently observable by the signer. Unless the signer independently
validates those proofs and records the relevant lock/history relation, its
signature is not a guarantee of consensus safety. The node remains responsible
for its own consensus engine, lock, verified evidence, restore and peer state.

**People and failure domains:** the key reader, signer binary replacer,
administrator, storage/backup restorer, activation-root distributor and
recovery approver are not identified. They may be the same principal or
provider. A per-validator process failure can isolate one validator if
independent; shared administration, provider, region, credentials, update
pipeline or backup controls can affect several or all. Key export/copy or
authorized malicious signing by an administrator can defeat the intended
separation. Availability and continuity guarantees depend on honest operator,
storage, recovery and key-custody behavior unless an independently specified
and tested mechanism changes those assumptions.

### Failure cases

| Case | Conditional expected behavior | What this assessment does not establish |
|---|---|---|
| a. Consensus-node process crash | Signer history survives; on restart, exact retained result may be returned or the position remains potentially signed and refuses. | Current service does not maintain signer-side history or recovery. |
| b. Node disk/VM rollback, signer current | Signer compares an authenticated canonical position/binding to current history; conflicting/older node requests refuse; exact retained result is reusable only after revalidation. | Node lock/safety records can still be stale; correspondence and currentness proof are unspecified. |
| c. Signer process crash, ordinary durable recovery | Recover an acknowledged consistent journal; retain uncertain reservations as potentially signed; resume only exact result/state. | Existing consensus daemon has no reachable server-side handler or signer journal. |
| d. Signer database rollback | Refuse if an independent trusted freshness anchor proves the copy is stale. | Without a surviving independent anchor, an older valid database can be indistinguishable from current state. A fail-closed intention does not detect rollback. |
| e. Whole signer-host/VM rollback | Same as (d), including signer binary, disk and local secrets. | A separate host or disk is not an independent anti-rollback root if the same restore/control domain can roll it back. |
| f. Simultaneous node and signer rollback | Require a third independently current authority/freshness source or refuse. | Two coordinated stale copies cannot establish that they are stale by comparing only to each other. |
| g. Cloned signer or copied unrestricted key | Require external fencing/exclusive-use evidence, non-exportable policy or an explicit single-instance trust assumption; otherwise refuse ambiguous migration/use. | A local mutex, process token or store lock cannot fence another host. Copied unrestricted key yields multiple signing authorities. |
| h. Compromised node submits malicious requests | Signer validates authorization, canonical operation, domain, position, evidence and safety restrictions; refuse unsupported requests. | Raw-byte signing or identity checks alone allow the node to use the key for any accepted bytes. |
| i. Shared administrator/provider compromise | Treat all affected signers/state/roots as compromised; stop and follow a pre-agreed authority/key retirement and recovery procedure. | Per-validator processes do not isolate shared control planes. No operator model or recovery authority is chosen. |
| j. Partition and simultaneous restart of all validators | Each signer may resume only from independently verified current state; uncertain/absent state blocks that validator. Consensus proceeds only if its actual quorum is reachable. | Restarting all nodes does not create freshness; a partitioned collection of local stores cannot prove global currency. No quorum availability is promised. |

No automatic alternate signer, local-key fallback, request-counter reset, signer
replacement, empty-database bootstrap, or “new instance” exception may bypass
history. If old and current valid state cannot be distinguished, the result is
unknown and signing must stop pending an owner-authorized recovery decision.

## Obligation owners: A/B/C and consensus recovery

`Evidence` means the concrete data needed; `root/state` means what authenticates
it and proves it is current; `consumer` means the component that must enforce
the decision. “No capability” is not repaired by transport authentication.

| Obligation | Evidence | Authenticated identity binding | Trusted state/root | Owner → consumer | Failure behavior required | Missing capability |
|---|---|---|---|---|---|---|
| A. Activation authorization | Founder-approved exact validator identities, keys/suites, network, genesis, membership/weights and domains; explicit bootstrap and activation event | Founder credential to exact network/genesis and signer identity; independently provisioned verifier/root | Independently distributed founding root and durable activation record | Owner not selected → node and every signer must enforce same active profile | Absent, invalid, stale or mismatched activation refuses; no silent empty-state initialization | No selected founder/credential/root distribution or signer-side verifier |
| B. Current-authority freshness | Current authorized profile/version, supersession/revocation state and freshness proof | Authority signature/proof bound to validator, network/genesis, membership, suite and domain | State outside the relevant node+signer rollback domain, or a stated trusted single-copy assumption | Owner unknown → signer checks before each new signing position; node independently checks for consensus | Missing, uncertain, stale, conflicting or unprovable currentness refuses | No independent currentness source, anti-rollback anchor or update/readback contract |
| C. Signing-history continuity | Canonical position, exact decision binding, reservation, uncertain/pending status, durable signature result and acknowledgements | Authenticated client identity plus per-validator signer identity; operation/domain and consensus position in each record | Signer-owned durable state plus an independently established freshness boundary if rollback is in scope | Current D10 belongs to node-local code → candidate would need one coherent signer-side D10 owner or a defined coordinator; signer is the signing consumer | Conflicts and uncertainty refuse; exact result reuse only for same bound operation after validation | No RPC-safe continuation, cross-host ownership, anti-rollback, transaction/ack protocol or production journal initialization |
| D. Consensus-lock/safety-record recovery | Node lock/view, committed history, authenticated QC/TC and exact candidate/ancestry as required by the accepted contract | Membership/key/domain verification of evidence and correspondence to the node's current engine state | Node-owned consensus store plus validated current authority; distinct from signer history | Node recovery owner → consensus engine; signer consumes only an agreed proof or per-position restriction | Missing/invalid/unverified evidence does not authorize a new signature; preserve current refusal | D7D14 does not wire to engine or signer; recovery ownership/proof transfer across process boundary is absent |
| E. Cross-host exclusive use and copied-key assumptions | Instance incarnation, lease/fence or other exclusive-use proof; key identity/custody and retirement record | Operator/admin authorization bound to one exact active service instance and validator identity | A non-rollbackable or independently current fencing authority, if exclusivity is claimed | Owner/operator unspecified → all instances and key consumers must enforce | Ambiguous duplicate, stale lease, lost fence or uncertain retirement refuses | No cross-host fencing or non-copyable key guarantee; no HSM/PQ support established |
| F. Authorized bootstrap/absent-QC behavior | Explicit initial state, authorized empty-history/bootstrap evidence, and permitted absent-QC semantics for each operation | Founder/activation root to exact genesis, validator, operation and domain | Independently current bootstrap record; not mere absence of a local file/QC | Bootstrap authority unknown → node and signer separately verify their own required initial state | Empty, missing, corrupt or unrecognized state is not “never signed”; only explicit authorized bootstrap proceeds | No approved bootstrap credential, absent-QC policy or current signer history initialization protocol |

The current D10 journal's local operation token/continuation and its shared
ownership domain are Rust process/storage concepts, not RPC capabilities. They
cannot be assumed to survive serialization, reconnect, process death, migration
or another host. Similarly, the D7D14 `PreparedPin`/owner evidence and engine
guard lifetimes cannot be carried across an RPC by serializing a token or
relying on a borrowed reference. The process boundary needs authenticated,
durable, versioned proof and acknowledgement semantics with revalidation at
each consumer.

**Proposed ownership split for evaluation, not selected:** the node remains
owner of consensus engine state, lock and recovery evidence; a signer would own
the one authoritative signing-history journal associated with its private key.
The node's D10 eligibility and the signer's record would have to agree on the
same canonical validator, network/genesis/domain, operation kind, signing
position and exact-byte binding. Every cross-process update needs a defined
authority, durable acknowledgement and recovery rule. It is not safe to keep
two independent “authoritative” histories without a reconciliation/fencing
protocol. Moving D10 to the signer, mirroring it, or making a coordinator
authoritative are unresolved design decisions.

### Proposal, Vote and Timeout are different operations

`ValidatorSigner` exposes all three. Proposal and Vote have distinct canonical
wire preimages and existing D10 guards; production currently has no PV
authority and supplies no journal. Timeout has its own signing domain and
preimage path, and is kept separate from Proposal/Vote authority in the node.
The remote daemon helper dispatches Timeout through `sign_vote`, but is
unreachable. The client constructs the Timeout preimage, and
`LocalKeySigner::sign_vote` signs supplied bytes unchanged, so the method name
alone does not establish a wrong domain or signature. Server-side canonical
operation/domain validation and an explicit backend dispatch and policy
contract remain unresolved; no generic backend boundary is established to
enforce those distinctions.

The candidate must decide whether Timeout is in scope for the signer and what
its position, high-QC, replay and state requirements are. Sharing a validator
key across operation families would not make their authorization or history
interchangeable; server-side operation/domain binding, backend dispatch and
policy must be explicit. No new key/domain or Timeout behavior is approved
here.

## Conditional cross-process state transitions

The following is a necessary-effects checklist, not a specified or implemented
wire protocol. It deliberately does not choose which process is transaction
coordinator or invent a remote database API.

1. **Identity and activation admission:** mutually authenticate the exact node
   and signer/service identities using independently distributed roots. Bind
   the request to the active founder-approved network, genesis, validator,
   public key, suite and signing domain. Authenticate the transport peer; do
   not infer identity from address, requested validator ID or request counter.
2. **Currentness and safety restrictions:** validate current authority and
   freshness from its selected trusted root. Validate the canonical request,
   operation and position; establish that the node's necessary lock/QC/TC,
   ancestry and safety evidence are authentic and current, or explicitly state
   the facts trusted from the node. Apply existing restrictions before any
   side effect and revalidate them after any delay/recovery that can invalidate
   the snapshot.
3. **Durable node safety publication (where required):** node-owned safety
   record publication and recovery state must be acknowledged before any
   dependent consensus action; no local D7D14 token is an RPC authorization.
   The contract must define whether this publication is before D10 reservation
   or another effect and how it relates to the exact candidate/decision.
4. **D10 reservation:** reserve the canonical signing position and exact
   decision binding durably, then receive a durable acknowledgement from the
   single history owner before invoking the key. An uncertain reservation is
   potentially signed and cannot be treated as unused.
5. **Independent history update, if required:** if rollback-resistant history
   is separate from the D10 journal, durably update it and obtain its own
   authenticated acknowledgement before key invocation. Define whether this
   update is reservation or commit, how it is correlated to D10, and how
   partial success is recovered. If no independent history capability exists,
   do not claim rollback protection.
6. **Signer invocation:** invoke only for the exact authorized, admitted and
   reserved canonical bytes, key, suite and operation. No fallback to a local
   node key, another signer or another identity may bypass a refusal.
7. **Durable result recording:** persist the exact output and binding in the
   history owner with its durability barrier. Acknowledgement loss after a
   successful write is an unknown outcome, not proof the operation did not
   occur. Existing local D10 has distinct reservation/result publication
   semantics; the cross-process composition is not defined.
8. **Response and network publication:** return only a response bound to the
   exact request, operation, signer, domain and retained result, after required
   durable acknowledgements. The node must revalidate current authorization
   and its safety decision before network publication. Signer response success
   is not consensus commit.
9. **Exact retained-result reuse:** on duplicate/retry, retrieve only the
   result whose canonical position and exact binding match; revalidate identity,
   current authority and consumer policy; then return identical retained bytes
   without signing again. A transport `request_id` is correlation only, not the
   consensus signing position or authorization.

The missing protocol decisions are exact request/position and canonical-binding
schemas; which process owns D10 and any independent history; atomicity or
recovery across the two stores; authority/freshness proof and fencing roots;
acknowledgement meaning, identity and durability; recovery of lost acknowledgements;
node-side validation of returned signatures; cross-host concurrency and
migration fencing; history compaction/retirement; and Timeout inclusion.
Without them, no complete safe process-boundary protocol can be claimed.

| Event | Required conditional handling |
|---|---|
| Duplicate request / reconnect | Same position and exact binding may recover exact retained result; conflicting binding refuses. Request transport IDs can change. |
| Concurrent clients | One durable serialization authority orders the same validator's positions; all other instances must be fenced or rejected. A process-local lock is insufficient. |
| Client restart / counter reset | Do not reset signer history; request counter is not the replay/consensus authority. Reconcile from durable operation identity. |
| Crash after reservation, before key call | Preserve as potentially signed unless durable evidence proves invocation did not happen under a specified atomic protocol; otherwise refuse/recover exact state. |
| Signature produced, response lost | Recover and return exact retained result; never sign a different request at that position. |
| Durable update succeeded, acknowledgement lost | Read/recover and establish the exact durable record; do not assume failure or issue a fresh signature. |
| Node rolls back, signer remains current | Signer rejects conflicting older state; node must independently recover its lock and not infer safety from a successful signature response. |
| Signer history missing, corrupt, restored or uncertain | Refuse; do not create an empty journal or reset; require explicit authorized recovery/currentness proof. |
| Migration while old instance may run | Fence old instance/key use before enabling replacement; without proof of exclusion, both remain a duplicate-authority risk and signing stops. |

No later committed checkpoint automatically licenses deletion of pending or
uncertain history. Compaction requires a separately approved authenticated
checkpoint that covers every reserved/pending/result state and a mechanism
preventing old snapshots or retired instances from reintroducing discarded
history. A checksum, local lock, historical QC, monotonic client counter,
authenticated transport, matching validator ID or “fail closed” label is not
that mechanism.

## Post-quantum and operational dependencies

| Dependency | Existing evidence | Still needs an owner decision or evidence |
|---|---|---|
| Activation credentials and trust-root distribution | QBIND has authority/activation types and disabled/fail-closed boundaries; no credential/root distribution for this signer is selected | Who may activate; exact root/key, signature suite, independent distribution, bootstrap/revocation and recovery authorization |
| Client/server authentication and transport | `SecureChannel` implements KEMTLS channel mechanics; the client transport calls it; the standalone daemon does not perform the server handshake or dispatch | Active server identity and client authentication, trust roots, revocation/update, exact service-to-validator binding and tested integration |
| Request/response/domain identity | Current consensus wire encoders have canonical domains; remote signer message includes an operation and echoed request ID | Typed canonical request validation, domain/position/result commitment, identity-independent verification and durable retry correlation |
| Key custody/storage | Local plaintext/encrypted keystores exist; HSM adapter is a deterministic placeholder; governance `pqc_remote_*` code is a separate pure/source-test family | Per-validator key creation/import, access roles, backup/restore, non-copyability assumption, retirement, recovery and proven PQ operation |
| Administration/recovery | No operator, machine, provider, activation credential, backup root or recovery principal was specified | Separation of duties, audit, binary replacement, IAM, emergency stop, recovery approval and independence of control planes |
| Firmware/attestation/external services | None is selected or required by existing consensus signer code | If considered, exact verifier, trust root, evidence freshness, rollback properties and integration tests; do not presume them |

The native cryptographic trust path is QBIND's configured PQ signature suite
(suite ID 100 in current signer code) and KEMTLS channel implementation.
Repository types/source do not establish that a real signer host, token, HSM,
firmware, attestation service or cloud product supports the required PQ
algorithm, safe stateful policy, or rollback-resistant history. No classical
authentication, cloud KMS, external chain, HSM attestation root, new
cryptographic construction, threshold scheme or witness network is imported.
No external product claim is made; no integration or operational capability
was tested.

## Symbolic performance and availability consequences

These are costs to account for, not measured performance or selected limits.

| Cost area | Existing source | Candidate integration cost / constraint |
|---|---|---|
| Durable effects per first signing position | Local D10 separates durable reservation acknowledgement from durable signed-result publication; exact reuse avoids a new signature | At least reservation write+ack and result write+ack if D10 is signer-owned; add each independently required freshness/history or safety-record write+ack. No async durability or unsafe batching. |
| Network/authentication | Current TCP transport establishes `SecureChannel` for each call and performs request/response exchange; daemon's matching server path is absent | One authenticated request/response exchange plus handshake/auth work and recovery/readback exchanges as needed; unknown RTT, throughput and cryptographic cost |
| Serialization/concurrency | Local journal ownership domain serializes supported local handles | One per-validator durable ordering authority across clients/hosts; contention grows with signing rate; no local mutex can fence remote instances |
| Bytes/history | Request carries preimage and response carries signature plus correlation/status; canonical payload/QC/transaction size affects preimage | Envelope/authentication/evidence overhead; retained reservation/result growth with unique positions and unresolved retries; no capacity or TPS estimate |
| Admission/refusal | Existing D10 and D7D14 have bounded local admission/refusal behavior | Candidate must bound frame, parse, pending-history and evidence work before allocation/effect; capacity exhaustion refuses; no limits approved |
| Compaction | Existing D10 retains records and has explicit bounded local behavior; D7D14 profile caps concern isolated safety records | Compaction only after authorized, current, durable checkpoint coverage and stale-copy/instance fencing; none established |
| Outage/recovery | No production remote route; local proposal/vote path refuses without a journal/authority | Signer outage removes its validator; with four independent equal-weight validators and a three-vote quorum, one unavailable may leave a quorum, two may not. Common failure domains can remove several at once. No availability claim or topology approval. |

No TPS, latency, RSS, hardware, disk, limit or public-network capacity value is
estimated. Source-level costs are distinct from the additional RPC, cross-store
acknowledgements, verification, signer concurrency and recovery costs of the
proposed integration.

## FUTURE / NOT EXECUTED acceptance matrix

Expected outcomes are conditional requirements, not results. Source tests,
process tests, standalone release-binary tests and operational evidence are
separate evidence layers. Historical results cited by the existing D7/D10
contracts remain attributed to their original revisions and are not rerun or
re-attributed here.

| Scenario | Expected effect / refusal | Required observation | Evidence layer |
|---|---|---|---|
| Genuine authorized signing | One authorized exact request reserves, signs, durably records, returns and publishes | Identity/domain/position binding, ordered durable acknowledgements, verified signature and exact result | Source test, then process and release-binary |
| Wrong identity, genesis, network, suite or domain | Refuse before durable reservation or key invocation | Typed refusal and no write/sign/response-success | Source test and release-binary |
| Malicious authenticated client/node | Refuse unsupported bytes, false evidence, unauthorized position or safety-conflicting request | Authenticated principal plus parser/evidence checks, no key call on refusal | Source test and process test |
| Conflicting requests at one position | First durable binding remains; conflicting bytes refuse | Persisted binding, refusal, no second signature | Source and multi-client process test |
| Exact duplicate / retry / reconnect | Reuse exact retained result or preserve uncertainty and refuse | Identical result bytes, no second key invocation, correct request correlation | Source and process test |
| Client restart / request-counter reset | Existing signing history remains authoritative | No replay acceptance based on a reset counter; history survives new client | Process test |
| Crash before reservation, after reservation, before key invocation | No signature before acknowledged reservation; uncertain reservation remains potentially signed | Crash-point record and recovered durable state | Process test |
| Crash after signature, before result write; after result write, before ack; after ack, before response | Never treat uncertain effect as unused; recover only exact committed result or refuse | Fault injection at each effect/ack boundary; exact write/read and invocation count | Process test |
| Response lost / network publication interruption | Recover exact result; node revalidates before publication | Same binding/result, no re-sign; no false publication success | Process and release-binary |
| Node-only restore while signer remains current | Refuse stale/conflicting request or require node lock recovery; signer history unchanged | Node and signer positions/roots compared; no unsafe signature | Process test |
| Signer database or whole-host restore | Detect only through independent freshness/fencing; otherwise explicitly refuse/declare unestablished | Freshness-root proof and restored-state refusal; no claim based only on checksum | Process and operational evidence |
| Simultaneous node+signer restore | Refuse unless an independent current root resolves it | External root survives both restore domains and binds recovered identity/history | Operational evidence |
| Cloned signer / copied key | One instance must be fenced or duplicate use refused | Attempt concurrent old/new instance signing; observe one authority or refusal | Process test and operational evidence |
| Partition / all-validator restart | Each signer recovers only from established current state; quorum is unavailable when required validators cannot safely sign | Per-validator recovery/refusal and actual quorum formation or loss | Multi-process test, then operational evidence |
| Migration / retirement | Old instance/key is fenced before replacement can sign | Old instance request rejected after fence; auditably bound retirement and new identity | Process and operational evidence |
| Capacity exhaustion / corrupt or absent history | Refuse before unsafe allocation/signing; no empty-history fallback | Explicit bounded refusal, preserved records, no signing | Source and process test |
| Retained-result reuse after currentness/safety revalidation | Return byte-identical result only when exact position/binding remains authorized | Revalidation proof, result digest equality, invocation count unchanged | Source and process test |
| Timeout operation and shared-key/domain interactions | Preserve the supplied Timeout preimage; define server-side canonical operation/domain validation and an explicit backend dispatch and policy contract | Validate Timeout domain/position/history; dispatch through a method named `sign_vote` alone proves neither a wrong domain nor a wrong signature | Source test and release-binary |

## Decision card

* **Reusable now:** local `ValidatorSigner` and canonical QBIND preimage
  encoders; client/channel framing primitives; isolated local D10 reservation
  and result-reuse semantics; isolated bounded D7D14 storage/accounting and
  node-side QC/TC/verified-justification work. Reuse is not production wiring.
* **Deployable today? No.** No reachable signer handshake/handler, remote
  production loader, production D10 journal, active Proposal/Vote authority,
  signer-state owner, independent freshness/anti-rollback, cross-host fence, or
  node/signer recovery correspondence exists.
* **What it could protect under assumptions:** against consensus-node process
  or host compromise that does not reach the separately administered signer,
  its key, its state, its trust roots or recovery controls; the signer must
  independently enforce request authority, canonical domains, continuity and
  safety restrictions, and signer-state rollback must be detectable or
  excluded by an explicit trusted assumption.
* **What remains unprotected/unestablished:** database/host rollback without an
  external currentness source, copied unrestricted keys, shared administrator
  or provider compromise, malicious but authenticated signing requests,
  activation/current-authority correctness, QC/TC/lock recovery across process
  boundaries, Timeout semantics, and availability/production security.
* **Operational/decentralization consequence:** a separate signer adds a
  privileged service and durable dependency per validator. Four processes
  provide no organizational independence; shared control or provider failures
  can centralize or remove voting power. Static founding authority is a
  governance concentration choice, not an approved policy.
* **Owner facts/decisions (maximum three):**
  1. Who may authenticate activation and distribute the exact founding
     network/genesis/membership/key/domain trust root independently?
  2. What actual state, administration and rollback/fencing domain can each
     signer use, including cold restore, cloned instances, all-validator
     restart and recovery authorization?
  3. Which process is to own the authoritative D10/history and which
     independently verifiable node safety evidence must be acknowledged before
     signing, if the owner elects to continue?
* **Exactly one bounded next engineering task:** write an isolated
  cross-process signing-state protocol design, without implementation, for the
  node-owned safety record ↔ signer-owned D10/history boundary. **Proposed
  paths:** this assessment and the authority lifecycle, signing continuity, and
  recovery correspondence contracts. **Prerequisites:** owner answers naming
  activation roots, rollback/fencing assumptions, state owner, and recovery
  authority; absent those facts, record explicit refusal paths rather than
  inventing mechanisms. **Acceptance:** specify exact request/position/binding
  fields; authenticated identity/root and currentness evidence; owner/consumer
  for A–F; durable effect and acknowledgement ordering; lost-ack/crash/retry/
  concurrency/migration behavior; node/signing-history correspondence;
  compaction and refusal rules; source-backed open issues and a FUTURE
  acceptance matrix. **Exclusions:** Rust changes, new cryptography, service
  or infrastructure selection, test/build execution, operational-key
  generation, activation, deployment, release approval and public DevNet.

**Preserved verdicts:** `D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED`;
`D7D14_STORAGE_ACCEPTANCE=PASS-ACCEPTED-SUBSET`;
`D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE`;
§13.6 whole-lifecycle `INCOMPLETE`; activation `DISABLED`; public DevNet
`NO-GO`; durable anti-rollback `NOT-ESTABLISHED`; C4/C5 `OPEN`; RS1 `OPEN`;
candidate limits `UNAPPROVED`. No F1/F2 closure, configured-authority
acceptance or release approval follows.

## Source and evidence map

* Signer interface and operation methods:
  `crates/qbind-node/src/validator_signer.rs:125-203,361-400`.
* Remote request/counter/loopback and TCP transport:
  `crates/qbind-node/src/remote_signer.rs:143-171,254-267,303-428,447-539,904-921,963-1047`.
* Standalone daemon backend, handler and accept loop:
  `crates/qbind-remote-signer/src/main.rs:409-459,467-597,627-687`.
* Production signer loader and P2P wiring:
  `crates/qbind-node/src/signer_loader.rs:290-330`;
  `crates/qbind-node/src/main.rs:5660-5728,8660-8685`;
  `crates/qbind-node/src/binary_consensus_loop.rs:6120-6142`.
* HSM placeholder and channel methods:
  `crates/qbind-node/src/hsm_pkcs11.rs:382-530`;
  `crates/qbind-node/src/secure_channel.rs:213-393,1008-1075`.
* Separate governance/trust-authority custody boundaries:
  `crates/qbind-node/src/pqc_remote_authority_signer.rs:1-68`;
  `crates/qbind-node/src/pqc_remote_signer_transport.rs:1-78`;
  `crates/qbind-node/src/pqc_production_remote_signer_backend.rs:1-96`.
* D10 local journal semantics and storage:
  `crates/qbind-node/src/signing_reservation_journal.rs:1-31`;
  `crates/qbind-node/src/binary_consensus_loop.rs:4371-4480,4951-5030,6136-6142`;
  `crates/qbind-node/src/storage.rs:1456-1495,1764-1788`.
* D7D14 isolation/default policy:
  `crates/qbind-node/src/safety_record_store/mod.rs:1-32`;
  `crates/qbind-node/src/safety_record_store/backend.rs:358-365,526-535`;
  `crates/qbind-node/src/safety_record_store/owner.rs:1121-1165,2170-2228`.
* Canonical proposal/vote fields, Timeout domain, quorum caveat:
  `crates/qbind-wire/src/consensus.rs:168-245,867-968`;
  `crates/qbind-consensus/src/timeout.rs:50,157-211`;
  `crates/qbind-consensus/src/validator_set.rs:465-510`.
* Existing accepted local D10, D7D14 and QC/TC recovery scope is recorded in
  `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`,
  `docs/protocol/QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`,
  and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`. Those historical
  validations are not rerun or reattributed by this assessment.


## RUN 422 — founding-authority decision cross-reference

The documentation-only decision in `docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md` selects founder-authorized bootstrap as the **design direction for one exact initial DevNet configuration**. This supersedes only the earlier open choice of who may authorize that initial configuration. Earlier statements that no founder/credential/root was selected, and the owner question asking who may authenticate activation, accurately describe their historical assessment scope; they are not rewritten as implementation evidence.

The founder role is not a completed cryptographic ceremony, approval of the whole Profile A contract, or approval of an operating/deployment profile. Credential/root distribution, exact record and verification, currentness, signing-history continuity, consensus-lock recovery, cross-host exclusivity, operational trust assumptions, and deployment approval remain pending. The intended split remains signer-owned per-key history and node-owned consensus-lock/recovery state; their cross-process correspondence is unimplemented. All preserved verdicts and refusal boundaries in this assessment are unchanged.
