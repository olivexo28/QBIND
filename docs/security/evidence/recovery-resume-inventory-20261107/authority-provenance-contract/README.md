# Authority-context provenance contract

**AUTHORITY PROVENANCE CONTRACT — INDEPENDENT REVIEW PENDING.**

Documentation-only proposed boundary. No format, verifier, provider, test,
production caller, authority activation or recovery/resume procedure is
implemented. B/C remain unselected.

```text
TASK_BASE=1d5d12e85f7ad939b731e56bf929d20403d00d11
TASK_BASE_TREE=eb022df7169bb18e00de464ce97ce0a1c364ac1f
PROTECTED_MAIN=9bf0eb43e4e3c601d02d3886d220b0abeb3a103e
PROTECTED_MAIN_TREE=56509b20084ee1cbe2c42fda9d73d87e4c82c33f
A17-F1 / RS1-F7=OPEN
RS1=OPEN
A33-F1 / E27=OPEN
ACTIVATION=DISABLED
PUBLIC_DEVNET=NO-GO
```

The user supplied **PASS WITH LIMITATIONS** for the nine authority-context
controls. They are **PASSED / CLOSED within their test-only scope**. The
seven content-binding controls, R/D/S/M's 87 distinct author-reported passes,
AP1, I1, W1/W2 and all earlier bounded acceptances are preserved. No reviewer
identity, unavailable raw review report or reviewer rerun is asserted. No
unchanged Rust test or build ran in this documentation task.

## 1. Pinned source inventory: distinct authority surfaces

All production-source links below pin protected main, not moving branches.
The authority-context experiment and founder decision are explicitly pinned
to the unmerged task base. Their presence on this task branch must not be
mistaken for production-main provenance or an implemented bootstrap ceremony.

### 1.1 Genesis identity and configuration

[GenesisValidator fields](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-ledger/src/genesis.rs#L129-L150)
carry address, hex public key, stake and optional metadata, not an explicit
consensus quorum/weight/suite profile. The distinct
[GenesisAuthorityConfig](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-ledger/src/genesis.rs#L754-L880)
contains policy version, sequence/optional epoch and transport/bundle-signing
roots. It validates environmental policy and rejects duplicate root
fingerprints/key strings; it is not automatically a consensus validator set
or recovery-clear authority.

The production wrapper
[loads external JSON and invokes boot verification](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/pqc_boot_genesis.rs#L180-L254).
No external path on DevNet/TestNet returns `SkippedNoExternalGenesis`;
MainNet refuses. External parsing already reads/allocates the whole file:
this is not bounded recovery ingress. The
[boot verifier](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-ledger/src/genesis.rs#L1797-L1848)
validates structure/authority, checks the MainNet/TestNet chain-name
environment substring, computes canonical hash and compares an independently
configured expected hash **if supplied**. MainNet requires it; TestNet/DevNet
do not universally require it. A chain-name check is not a validated mapping
between runtime u64 chain identity, wire u32 alias and genesis string.

[Canonical genesis hashing](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-ledger/src/genesis.rs#L1576-L1665)
binds environment, chain string, ordered validator key strings/stakes and
other genesis fields including authority block. It is deterministic
identity/integrity, **not an approval signature or root-distribution proof**.
An expected hash copied from the same untrusted download is not independent
provenance. Neither computed hash nor a successfully compared pin establishes
who may approve it or that no newer authority exists.

The
[genesis consensus builder](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L334-L440)
is a callable library capability: maps genesis order to ValidatorId index,
decodes fixed-length ML-DSA-44 keys, rejects duplicate addresses/key bytes,
checks local membership and assigns **weight1 / fixed supported suite**.
It does not infer consensus voting weights from stake. Its founding epoch
is0 and production `authorized_wire_chain_id` is `None`.
The
[commitment construction](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L1462-L1480)
directly encodes genesis string/hash and ordered ID/suite/key tuples, not an
explicit quorum rule, weight vector, provenance credential or approval.
Genesis hash contributes its own fields indirectly; this is not a reviewed
complete future authority-record commitment.

Most importantly,
[main's actual activation refusal](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L5420-L5441)
exits on `--consensus-authority-from-genesis` before per-mode network/consensus
startup. The
[retained downstream loader branch](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L5821-L5883)
is unreachable under that production guard; its one-snapshot revalidation/
boot-hash matching checks are library/test source evidence, not a currently
installed genesis Proposal/Vote authority.

### 1.2 Transport trust-bundle authentication and installation

[Bundle fields and separately configured signing keys](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/pqc_trust_bundle.rs#L278-L409)
describe environment, optional runtime chain ID, validity windows, sequence,
transport roots/revocations and activation constraints. These are transport
delegation trust inputs, not consensus membership/weights/quorum. Some
historical Run050 comments in this module still say signature verification
is unavailable; the
[actual Run051 verification body](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/pqc_trust_bundle.rs#L1480-L1556)
instead looks up a **configured** signing key, checks suite/signature shape
and verifies canonical domain-separated bundle bytes with real ML-DSA-44.
Do not treat the obsolete comments as the actual dispatch.

[P2P startup parses signing-key CLI configuration and loads the bundle](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L6483-L6620).
It rejects ID collision with CLI transport roots, requires signing keys for
TestNet/MainNet bundles, uses wall-clock validity and supplies snapshot/local
committed-state activation height/epoch. Signed bundles fail if verification
fails; DevNet unsigned policy is not cryptographic provenance. Signing-key
provisioning remains an operator trust input; a signed bundle's own key label
does not establish that provisioning was authorized.

There are additional **transport-specific** ratification paths:
[v1 startup enforcement](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L130-L290)
extracts the external genesis authority block and verifies candidate
bundle-signing-key ratification against it; the inputs are local
operator-supplied files. This branch rereads genesis, unlike the retained
one-snapshot consensus loader. Environment/legacy opt-in and unsigned cases
are explicit, not universal passed ratification.
[Actual startup gate and versioned sidecar dispatch](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L6664-L6785)
apply ratification/marker preflight after bundle/activation validation;
MainNet/TestNet invoke by default, DevNet is opt-in; v2 sidecars use their
separate preflight, not the v1 verifier. No claim is made that these distinct
paths provide one immutable recovery-authority snapshot or independently
authenticated genesis provenance.

[Sequence publication](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L6928-L7010)
precedes transport root merge and authority-marker publication follows the
sequence commit. A
[marker failure after sequence write](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L7110-L7205)
is an explicit partial persistent effect and startup refusal, not no-effect.
DevNet without data-dir warns that sequence persistence is absent;
TestNet/MainNet refuse. Only after successful gates does
[root merge](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L7194-L7219)
install active transport roots. This is actual source wiring, **not new
execution evidence**, consensus authority installation or recovery activation.

[Local sequence checking](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/pqc_trust_sequence.rs#L542-L607)
rejects lower sequence/equal-sequence different fingerprint against retained
local state and writes a first record if none exists. It cannot distinguish
joint rollback/copy of bundle and sequence store from genuine old first load.
Wall-clock/activation epoch gates likewise do not prove absence of a newer
authority outside this node's retained information.

### 1.3 Proposal/Vote versus Timeout/NewView

[Legacy peer-key provider](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/peer_key_provider.rs#L329-L452)
loads explicit IDs/suites/keys, rejects duplicate IDs, checks local key
against signer (or inserts signer-derived local key when missing), requires
static peer keys and assigns weight1. This is configured key correspondence,
not independent approval or a production arbitrary weighted authority record.
[Its actual main caller](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L5936-L5995)
feeds security preflight. Successful legacy configuration builds only the
Timeout/NewView context; no transport key or timeout context implicitly
promotes to Proposal/Vote authority.

[ProposalVoteAuthority capability](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/binary_consensus_loop.rs#L1030-L1093)
holds validator-set/key-provider/backend/signer primitives and mandatory v2
domain. These public library primitives can be supplied in fixtures; the
field's descriptive "governance-backed" comment is not evidence that this
instance was produced by authenticated governance.
[Production preflight returns None](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L6162-L6173)
and
[the actual IO caller selects Required](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/main.rs#L8672-L8705).
Inbound Proposal/Vote refuse and outbound suppress in the absence of required
authority; the selected future context must not turn this into an implicit
activation route.

[V2 signing-domain layout and limits of its meaning](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-wire/src/pv_signing_domain.rs#L37-L78)
bind runtime chain, expected wire ID, genesis, authority commitment,
purpose/format and canonical message body. Domain construction checks are
not provenance/currentness evidence. The outbound preimage helpers and
actual inbound message-bound
[Proposal](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/proposal_vote_verify.rs#L405-L432)
and
[Vote](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/proposal_vote_verify.rs#L511-L538)
functions are distinct: inbound recomputes bytes from the actual message.
These single-message APIs do not independently supply an authorized epoch
or prove a quorum.
[Domain-QC verification](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-consensus/src/qc_verify_domain.rs#L849-L876)
requires caller-supplied domain, epoch and validator set, preflights already
allocated vectors, checks individual signatures and ceil(2W/3). It cannot
authenticate the caller's authority source, replace missing provenance or
validate full content/parent graphs.

[CurrentAuthorizationOwner production constructor](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L1069-L1146)
is unavailable/current-state refusing; generation/issuer are in-process
checks, not external durable currentness. The founding-epoch
[configuration guard](https://github.com/olivexo28/QBIND/blob/9bf0eb43e4e3c601d02d3886d220b0abeb3a103e/crates/qbind-node/src/genesis_consensus_authority.rs#L805-L849)
requires founding scope and rejects divergence; no unchanged set grants
later-epoch authority.

### 1.4 Accepted test boundary, not real-world provenance

At task-base revision, the
[test verifier](https://github.com/olivexo28/QBIND/blob/1d5d12e85f7ad939b731e56bf929d20403d00d11/crates/qbind-consensus/tests/authority_context_experiment_tests.rs#L149-L231)
and
[independently supplied synthetic fixture](https://github.com/olivexo28/QBIND/blob/1d5d12e85f7ad939b731e56bf929d20403d00d11/crates/qbind-consensus/tests/authority_context_experiment_tests.rs#L234-L289)
show expected-context comparison/weight checking. The caller supplies fresh
synthetic keys, chain5/epoch9/label, weights2/1/1/1, threshold4.
These accepted tests establish their stated test-only controls, not authentic
origin, a signed set digest, currentness or real founder approval. The new
contract supplies no new author execution of them.

## 2. Logical expected-context binding obligations

The following is a **proposed requirements contract**, not a serialization
schema or an implemented verifier. An authority label alone is insufficient.

| Required fact | Binding/check before supplying context | Independent source/assumption |
|---|---|---|
| Network/chain/genesis | Exact environment, full runtime chain, explicit reviewed wire correspondence and canonical genesis identity; reject partial aliases/defaults | Relying verifier's independently provisioned identity, not witness-provided expected values |
| Applicability | Exact epoch or explicitly bounded range, operation and transition boundary; no implicit all-future-epochs extension | Owner-approved lifetime and transition policy; historical scope separate from current authority |
| Complete members | Stable identities, canonical ordering/index mapping, full key bytes, key encoding/suites and exact weights | Approved full set; no stake-to-weight inference or transport-key promotion |
| Quorum rule | Explicit rule identifier/version and any threshold/total/rounding parameters, positive checked weights and representable sums | Separately approved fault/quorum assumptions; fixture4-of-weight5 is not such approval |
| Purpose/version | Authority-context purpose distinct from bootstrap, transport ratification, Vote, recovery attestation or resume; schema/signing policy support | Relying policy allowlist, not peer negotiation |
| Provenance | Exact subject/context, approval scope, issuer identity/root, delegation chain if allowed, predecessor/transition reference if relevant, policy version | Trust root and authorizer independently established; a record cannot authorize its own carried key |
| Evidence ownership | One immutable context/evidence snapshot with correspondence between approved bytes and parsed keys/weights; verifier context derived from that same snapshot | Explicit provider owner and read/publication boundary, not separate mutable files read opportunistically |
| Currentness status | Separately classified currentness/supersession evidence and its observation boundary | Independent source or explicit operational assumption described below; no cryptographic shortcut |

Reject duplicate IDs, duplicate decoded keys across IDs (unless a future
reviewed policy explicitly handles them without extra weight), invalid key
encoding/suite, zero/overflow weights, unsupported quorum rule/threshold,
ambiguous ID/index mapping and unsupported applicability. Labels must match
the complete tuple they identify; witness claims are compared exactly or
ignored as non-authoritative, never used to repair missing expectation.

Future encoding review must specify fixed-width/tagged/length-delimited
fields, supported versions, ordering, exact consumption, duplicate object
fields, unknown fields, normalization/hex variants, optional/absent semantics
and full field coverage. Refuse ambiguity instead of picking first/last field
or guessing normalization. This task selects no JSON/binary format, digest,
signature construction, set commitment or transition parser.

Finite input/evidence limits must precede relevant allocation and crypto:
encoded bytes, count/field lengths, keys/suites/signatures, endorsements/
delegation depth, duplication, decoded and simultaneously retained capacity,
and separately measured working memory. Existing whole-file loaders/QC
decoded-vector preflight are not evidence of pre-ingress bounds. No previously
proposed fixture ceiling/deadline becomes a production memory/runtime/
cancellation guarantee; concrete limits for this boundary remain unselected.

## 3. Narrow provenance candidates (unselected)

| Candidate | Trust root / who may authorize | Delivery and checks | What remains assumed / refusal |
|---|---|---|---|
| P1: independently provisioned exact configuration | Separately approved provisioning policy and designated owner, outside the recovery witness/responder; may pin a complete context or a reviewed identity of it | Provider reads one owned snapshot through an independent configuration channel; compare expected network/genesis/scope/full set/weights/quorum/version and witness claims; audit provisioning attribution | Provisioning integrity, independence, custody, exact agreement and freshness must be evidenced operationally. Local files/CLI/checksum alone do not establish the policy's authorizer. Missing/untrusted/mismatching configuration refuses; no witness fallback. |
| P2: independently authenticated authority record | Separately pinned root and scope-constrained authorizer/delegation policy. The record cannot replace its root or expand its purpose. Initial founder role only within section5 | Untrusted delivery may carry record, but admission checks bounded exact bytes, complete subject, issuer signatures under independent root, allowed scope/version/chain/genesis/applicability and any reviewed predecessor proof; creates owned read-only context | Root distribution/custody, approver legitimacy, non-equivocation and supersession remain external assumptions unless separately demonstrated. Valid old/conflicting signatures are not currentness. Unsupported chain/delegation, missing proof, mismatched subject or conflict refuses. No existing record format is selected. |
| P0: continued refusal | No independently established provenance/currentness | Keep current absent authority/refusal; do not source expected context from witness | Safest containment while prerequisites missing, but recovery/participation may stall indefinitely. Unknown evidence remains refusal, not no-effect or auto-resume. |

These are narrow acquisition choices, **not B/C quorum-to-content protocol
selection**. Existing transport signing-key ratification offers prior art for
separate purposes/root lookup, not approval to reuse its authorizers or type
as consensus/recovery context. Existing genesis pins offer identity checking,
not a complete provenance/currentness provider. No network service, trust
registry, operational root or independent approval record is claimed to exist.

## 4. Authenticity is not currentness

Authenticity asks who approved these exact facts for this scope; currentness
asks whether that approval is applicable now and not superseded. Historical
verification may intentionally need a past epoch's authority while current
participation needs a different current authority. A fresh current set cannot
validate historical signatures by replacing their original keys/policy; old
signatures cannot be reinterpreted as newly introduced authority attestations.
Transitions require independently authorized complete successor and an
accepted predecessor/ordering/applicability rule, not merely higher epoch.

| Case | What local checks can establish | Additional requirement / failure |
|---|---|---|
| Lower sequence with intact newer local state | Local relative rollback detected, as transport sequence source does | Does not prove node saw newest authority; independent authoritative observation or explicit "trusted unchanged provisioning" assumption still needed |
| Context + marker/database jointly rolled back | Old signatures/checksum/revision may all match | Independently retained nonrollback state or separately authenticated current authority observation outside the rollback domain; without it currentness is Unknown/refuse for current use |
| Copied store on another host | Bitwise integrity and past approval only | Explicit copy/instance policy and independent currentness source; store copying does not grant authority, ownership or signer exclusivity |
| Fresh/absent store | Absence of local history | Cannot infer first use or newest state; require independently authorized initial provisioning/currentness procedure, otherwise Unavailable/refuse |
| Stale valid record / same label different set | Past signature can remain valid | Bind full set and applicability; independently resolve supersession/conflict. Do not choose highest claimed revision, arrival order or a responder's assertion |
| Provider unavailable or observation expires | Cannot re-establish applicability/currentness | Preserve typed unavailable/unknown/refusal; no last-known automatic authority upgrade |

Possible independent assumptions include controlled provisioning with an
explicit no-change interval, a separately administered nonrollback witness,
or an independently authenticated current-state service under a reviewed
authorizer/availability policy. None exists by declaration here. Each would
need scope, observation freshness, conflict behavior, failure/deadline,
rollback domains and how a use-time invalidation is detected. A signed
checkpoint proves an assertion at its scope, **not that no newer state exists**.
Wall-clock expiry, local sequence, generation, checksum or matching label alone
cannot fill that gap. Loss of independent evidence remains Unknown, not a
successful historical-context admission for present participation.

## 5. Founder-bootstrap decision stays within its scope

The
[task-base founder decision](https://github.com/olivexo28/QBIND/blob/1d5d12e85f7ad939b731e56bf929d20403d00d11/docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md#L1-L60)
selects the founder role to approve **one exact initial DevNet configuration
and founding set** under a separate PQ bootstrap credential. It explicitly
does not supply an actual credential/ceremony, freshness, history continuity
or exclusive signer use. This role decision is preserved, not reopened.
It does not authorize later membership/weight changes, later-epoch signing,
stale authority, erasing history, or interpreting absence as never signed.
[Its independent root requirements](https://github.com/olivexo28/QBIND/blob/1d5d12e85f7ad939b731e56bf929d20403d00d11/docs/devnet/QBIND_RUN_422_DEVNET_BOOTSTRAP_AUTHORITY_DECISION.md#L97-L143)
remain unresolved mechanisms, not existing provenance infrastructure.

P1/P2 may eventually embody that exact initial approval only after a separate
root/record/policy review. Founder approval must never become consensus
finality, a signer override, recovery-clear authority, blanket quorum model
approval or a substitute for independently authorized clear/resume. Node
lock/history recovery and signer reservations/uncertain outcomes remain
separate obligations. Later transitions and any resume authorizer require
separate owner/independent-review decisions.

## 6. Proposed future verifier-facing boundary

Logical interface, **FUTURE / NOT EXECUTED**, no implementation:

1. Inputs: independent expected network/genesis/purpose/version policy;
   bounded candidate context/provenance evidence; independent roots/approved
   configuration handle; required applicability epoch/range; separately
   classified currentness evidence/assumption. Recovery witness may carry
   claims but cannot supply the expected root, rule or threshold by fiat.
2. Ownership: provider owns one immutable parsed/evidence snapshot and
   identity correspondence. A pure admission operation borrows expectation,
   checks bounds/structure/full subject/root authorization and produces an
   owned read-only admitted context with exact applicability and attribution.
   Witness mutations cannot alter that snapshot; no signer object or durable
   application handle is returned. Root/context replacement requires explicit
   provider ownership/policy, not a second opportunistic file read.
3. Results: proposed distinctions `Unavailable`, `MalformedOrOversized`,
   `Unsupported`, `ProvenanceUntrusted`, `ContextMismatch`, `Conflict`,
   `Inapplicable`, `CurrentnessUnknown` / `Stale`, or context-validation success.
   These are logical names, not existing Rust types. Unsupported/missing
   evidence refuses; no fallback to transport identity, witness committee,
   weak version or unsigned input.
4. Use: evidence verification receives the admitted context explicitly by
   immutable reference/handle, deriving its member lookup, keys, weights,
   quorum and domain from that exact context. Epoch/message scope is checked
   at verification. No implicit conversion to `ProposalVoteAuthority`,
   activation, recovery store writer or resume permission. If required
   currentness changes between admission/use, refuse until independently
   re-established; snapshot ownership alone does not prevent supersession.
5. Effects: pure context/evidence checking produces no application effect.
   If a later separately reviewed provider publishes durable state, its intent,
   evidence/context stores, revision/currentness observations and crash/
   ownership-loss boundaries must be separately specified. Attempted write
   with uncertain result stays Unknown; cancellation/late result/ownership
   loss cannot be converted to "no effect". This task defines no such writer.

Successful provenance validation may answer "authentic under these scoped
roots"; independently authenticated **current** applicability is an additional
classification. Even both together do not authorize prefix application,
signing-history continuity, signer fencing/exclusivity, quarantine clearance
or participation. Catch-up completion/mode flip/height/checksum/database
success cannot grant those. Existing restore containment remains: non-empty
responses refuse; admitted empty responses are ignored before peer-height/
mode effects; restore can persist indefinitely and is not a complete
engine/worker/signer fence. No automatic resume is proposed.

## 7. Future acceptance matrix and smallest review step

**Every row below is FUTURE / NOT EXECUTED.** "Admit" means only hypothetical
context validation, never effects or activation. Existing nine accepted
controls are not reopened or counted as these new cases.

| Case / layer | Proposed entry boundary and isolated control | Required observable result |
|---|---|---|
| Valid independent input / structure | Test-only provider receives pre-established immutable expected catalog plus separately delivered candidate; record allocations before entry | Scoped context equality/admission; zero application/signing/clear/resume capabilities |
| Witness-controlled replacement / trust selection | Candidate supplies its own root/set/threshold; keep expected catalog unchanged | `ProvenanceUntrusted` or `ContextMismatch`; restoring independent original passes |
| Wrong network/genesis/epoch or out-of-range scope / structure | Mutate one field under same proposed checker, keep other prerequisites valid | Specific mismatch/inapplicability; no domain fallback; restore passes |
| Duplicate/ambiguous member IDs or decoded keys / parser | Duplicate ID/key, duplicate object field, unsupported normalization/order, inconsistent lengths/trailing bytes | Explicit structure/ambiguity refusal before crypto/output; restored canonical input passes |
| Changed keys/weights/quorum/threshold / complete binding | Same label with altered complete context, unsigned mutation against original approvals | Exact context or signature refusal; no extra weight; restore passes |
| Authenticated record bytes / synthetic crypto | Only if P2 is independently selected for a later test slice: synthetic root supplied outside record, separately bounded proof | Correct synthetic signature/issuer-scope passes; wrong carried root/purpose/version/signature refuses; NOT evidence of real-world approver legitimacy |
| Missing/stale currentness / provider model | Provider separately yields unavailable, old observation, conflicting supersession or expiry; do not derive from candidate revision | Unavailable/Unknown/Stale/Conflict; never automatic authority reuse or first-use inference |
| Local/combined rollback or copied snapshot / model | Restore candidate and local marker together while independent simulated observation retains newer state | Stale/refusal where independent signal exists; without it Unknown, not claimed rollback detection |
| Omitted context field / binding sensitivity | Private defective checker skips full key/weight/rule/scope binding while same label stays valid | Defective acceptance detected by strict refusal assertion; no production bypass |
| Omitted provenance/currentness / trust sensitivity | Private branch trusts record's own root or candidate sequence; strict path uses separate input | Incorrect admission observed as defect; valid expected/restored control reaches same strict checker |
| Limits / pre-materialization vs decoded | Test-only descriptor gate and borrowed scanner before callback, separately already allocated decoded cases | Zero callback/crypto before negative limit at its actual boundary; positive restored input invokes it; no claim of production ingress/working-memory guarantee |
| Replacement/ownership / pure model | Invalidate independently supplied provider generation between check/use | Refusal/recheck; borrowed immutable snapshot does not imply durable ownership, signer fence or no newer authority |
| Real provisioning/currentness / operational evidence | Independent approved channel/root ceremony and currentness policy outside tests | Separately attributed operational evidence required; synthetic structure/signature/model tests cannot mark this row passed |

**Recommend the smallest next independent review:** choose a test-only **P1
provider-envelope/attribution model** with an independently supplied immutable
catalog, explicit provenance-source identity and separately simulated
Available/Unavailable/Stale/Conflict currentness status. Review its complete
logical input/output and negative/bypass oracles before implementing a new
test target. This adds provenance-source separation/availability handling
without selecting P2 cryptography, a digest/wire format, production provider
or B/C protocol. Numeric bounds remain to be justified at that review; no
runtime/cancellation guarantee is imported from earlier fixtures.

Owner decisions still required: exact provenance authorizer/root/channel and
scope; full network/genesis/wire identity mapping; ID/key/suite/order semantics
and duplicate policy; quorum/fault rule and explicit weights; founding versus
transition applicability; currentness source/operational assumptions and
rollback domain; conflict/supersession/retirement policy; independent provider
ownership/use-time invalidation; justified resource ceilings and exact failure
observability. Production implementation/activation requires separate review
of real root provisioning, actual callers, crash/restart publication,
historical evidence compatibility, signing-history/fencing and independently
authorized clear/resume. This documentation selects none of those mechanisms.

**A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN.
Activation remains DISABLED; public DevNet remains NO-GO.**

## 8. Documentation and integrity evidence

`COMMANDS.txt` records exact initial/publication/documentation commands,
source navigation/ranges, the unsuccessful source lookup and failed link-edit
context, and outcomes. `01-integrity.stdout/.stderr/.exit` preserve the full
documentation check execution (exit0, empty stderr). Checks passed: four
historical byte prefixes,91 byte-identical evidence/Audit files, twelve
producing-revision manifests/198 entries,33 pinned source/decision ranges,
append navigation, source/test/config scope and whitespace. All13 new
acceptance rows remain FUTURE / NOT EXECUTED. No Rust tests/builds ran.
Current delivery hashes are in this directory's `SHA256SUMS`; these are
separate from old manifest values verified at their producing revisions.
