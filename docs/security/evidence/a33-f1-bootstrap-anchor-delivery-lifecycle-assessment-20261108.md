# QBIND bootstrap anchor delivery and lifecycle assessment

**DOCUMENTATION-ONLY PROPOSALS FOR INDEPENDENT REVIEW. NO MECHANISM SELECTED
OR OPERATING PROCEDURE APPROVED.**

A separate association-verification bootstrap anchor is an owner-approved
direction for specification and synthetic testing only. This assessment does
not authorize an actual key, signature suite, encoding, trust root, initial
delivery or enrollment procedure, currentness mechanism, storage backend,
replacement, revocation, or recovery process. Association-verification
authority remains separate from validator consensus-signing authority and
bundle-signing authority. None of its results authorizes startup, signer
loading, participation, signing, restart, restore, reset, or recovery.

**A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED; public
DevNet remains NO-GO.** Earlier accepted findings and qualifications are
preserved, not reopened or promoted by this assessment.

## 1. Baseline, evidence, and assessment boundary

Remote `refs/heads/main` was checked using `git ls-remote`; the remote Git
commit API supplied its tree. Both matched the requested baseline:

| Item | Verified value |
|---|---|
| Remote main commit / assessment parent | `aa382fa28b2d3e97e6203d47fa8231b5f2269741` |
| Remote main tree | `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| New documentation branch | `docs/bootstrap-anchor-delivery-lifecycle` |
| Only added path | `docs/security/evidence/a33-f1-bootstrap-anchor-delivery-lifecycle-assessment-20261108.md` |

A separate clean worktree was created from that exact commit. The original
workspace inspection showed `main`, a clean status, and no other registered
worktree. The reported unstaged append on another branch was not visible in
that inspection; no existing change was discarded, staged, committed, moved,
or used as assessment input. Its existence or location is not independently
verified here.

The primary reviewed input is the merged [separate-anchor specification][spec],
including its delivery properties, lifecycle limitations, and non-authorizing
results. The earlier [authentication candidate][candidate] and
[public-first route proposal][routes] supply background, not permission to
reuse bundle-signing roots or generalize normal-route ordering.

The merged [synthetic evidence][synthetic-evidence] records seven tests at
`3cf05468bd753d279433904eeaa0cbdc73550706`, tree
`33157f8936410775657d85932498231fa5414a87`.
The [coverage correction][correction] records nine tests at
`b841fa4e8fb5718b5f74d60363d7d1ad8e50cea5`, tree
`398f4b8648748e7769482ed94d98f4374e089653`, and names reviewed specification
ancestor `15bd45ce8e42fb71c4bb98a550eb2c5d6f14e1cc`. These are historical
producing revisions reported by the merged evidence, not runs or new reviews
performed for this assessment. Primary links below pin the merged documents
and inspected source to the verified baseline; historical test-source links
are separately pinned.

The correction preserves independently fixed expected-domain checks for
environment, numeric chain, full genesis identity, and destination even when
the authorized synthetic bootstrap key signs a foreign tuple and observations
match it. It also separates missing anchor, association, and signature
acquisition failures. Its positive result remains only
`Verified / Equal / Unresolved`. The earlier phrase "wrong-suite signing key"
was corrected: the key was unauthorized but still ML-DSA-44; an actually
incompatible-suite signing key was **not tested**. No stronger coverage is
claimed here.

The [public-identity comparison evidence][comparison] likewise remains
synthetic and limited. The [merged harness][harness] supplies an authenticated
provenance flag, expected anchor, policy, and deployment domain as fixed
fixture inputs; it does not establish their real delivery. This assessment
adds no code, executes no tests, uses no operational keys, and runs no node.

## 2. Shared trust and identity requirements

Every candidate below must start with an independently authenticated owner
decision about **who may approve this association-verification authority for
this deployment**. Moving that question into a package signer, digest channel,
platform enrollment account, genesis hash, or registry does not answer it.
Physical separation, two URLs, two files, or two accounts under one compromised
administrator are not automatically independent trust sources.

The proposed authenticated scope must identify the intended deployment and
permitted association domain. The exact representation remains an owner
decision, but the association must cover, as one indivisible tuple:

```text
environment
numeric_chain_id
full_genesis_identity
destination_identity
validator_id
validator_consensus_signature_suite
complete_validator_consensus_public_key
```

The anchor's complete public-key identity and suite, its association-only
purpose, supported version, allowed domain, and verifier policy must be
authenticated independently of the local association. A signed deployment
label alone is insufficient if labels are reused or their relationship to
these fields is not independently established. Policy must define whether an
anchor is permitted for one association or a bounded set; neither a global
anchor scope nor a per-validator anchor is selected. Expected domain must
not be copied from the association or the observations under evaluation.

Cross-deployment reuse is detectable only when the checker compares against
that independently established domain, including every required scope
restriction. A valid signature over an attacker-selected foreign tuple is not
an acceptable substitute. For external genesis, fields and the full canonical
hash must come from one owned parse, and the hash must match the retained
boot hash when present. [Boot verification][boot] consumes a configured
expected hash; it does not authenticate the configuration's origin.
[Retained boot identity][retained-boot] leaves the embedded-genesis case at
`None`; embedded genesis and missing retained hash remain unresolved, not
wildcards or approved default values.

### Common attacker boundary

With the verifier, independent trust inputs, and execution boundary intact,
an attacker controlling local association bytes, configuration, or destination
can substitute, delete, truncate, create conflicts, or replay artifacts and
deny availability. It cannot create founder approval under an uncompromised
independent authority merely by obtaining a signature from its own key.
Configuration may identify where to fetch bytes, but cannot select a new
trusted root, weaker suite, foreign deployment, fallback record, or currentness
policy without independently authenticated authorization.

An attacker controlling the **entire local host** may modify the verifier,
its trust inputs or observations, suppress diagnostics, fake success, or
bypass a future refusal. None of the software-only delivery candidates proves
enforcement on such a host. Even a protected trust store does not by itself
force a compromised host to use it or honor its answer. Claims under host
compromise would require separately evidenced protected execution, trusted
I/O and enforcement boundaries, not just anchor storage. Attacker control of
the authority or its enrollment channel defeats the associated trust
assumption; cryptographic verification then proves only the compromised
authority's signature, not the intended owner's approval.

A canonical destination path is not filesystem-incarnation identity.
[Destination canonicalization][destination] and the existing
[advisory descriptor lock][lock] do not exclude non-cooperating writers,
namespace replacement, cloned disks, or another host with a copied signer.
Directory control may preserve a matching path while changing its backing
storage. No candidate treats that path or lock as provenance, currentness,
or exclusive signer control.

## 3. Bounded delivery candidates, not selections

Candidates A-C are the mechanisms already identified in the merged
specification. D bounds the earlier genesis-based proposal without replacing
the separate-anchor direction. E illustrates a delivery/currentness dependency
that would itself need a separately authenticated bootstrap. All remain
unapproved alternatives; combinations inherit every component's assumptions.

### A. Independently authenticated deployment package

**Trust source and first delivery.** An owner-designated deployment-package
authority authenticates a package containing the separate public anchor,
its suite/purpose, deployment binding, and approved verifier policy. The
package-verification root and its permitted role must already reach the
verifier through an independently authenticated enrollment channel. A root
included only inside the same package cannot authenticate that package.
A repository commit, release download, or successful TLS connection alone
does not establish founder approval.

**Substitution and scope.** Verify the authenticated package contents and
compare scope with independently expected deployment values before trusting
the anchor. A substituted key, package component, suite, or foreign domain
must refuse. A valid old package is still cryptographically authentic; its
signature does not identify the latest authorized package or anchor.

**Attacker capability.** Control of the package download channel, config,
or destination permits replacement, deletion, and replay, but not a new
authorized package signature while the enrolled root and verifier remain
intact. Replacing both the package and a locally mutable verification root
defeats the model if that namespace is the only root source. Complete host
control permits bypass as described in section 2. Compromise of the package
authority permits forged provisioning evidence within its authorized scope;
separating it from validator and bundle signers does not eliminate that risk.

**Dependencies, availability, and refusal.** Requires package signing and
custody, independently protected root enrollment and update authorization,
unambiguous package parsing, and domain-policy review. Offline delivery can
avoid a runtime network dependency but may delay replacement/revocation
visibility. Missing package, unverifiable provenance, conflict, wrong scope,
or unauthorized root change refuses authentication. Independently required
currentness evidence being unavailable prevents an eligible result, not a
fallback to the last downloadable package.

**Cryptographic and other assumptions.** Package signatures and hash binding
need approved algorithms, key sizes, canonical bytes, and uncompromised
signers/verifiers. RSA/ECDSA/EdDSA package signatures, ordinary WebPKI/TLS
authentication, and typical classical key exchange are not silently PQ.
Using ML-DSA for the association would not upgrade a classical package-root
delivery chain. Build/release account security and human enrollment remain
additional non-cryptographic assumptions.

### B. Separately delivered authenticated anchor digest

**Trust source and first delivery.** An independently authenticated owner
channel conveys an exact digest commitment to the complete anchor and its
suite/purpose and deployment context, or to an unambiguous envelope covering
them. The public anchor bytes may arrive over an untrusted deployment channel.
Digest algorithm, commitment framing, channel authentication, and adequate
digest length remain owner decisions; a short display fingerprint is not
enough. The recipient must know independently which authority and deployment
the digest message represents.

**Substitution and scope.** Check the delivered key/envelope against the
independent commitment and check the authenticated scope against the intended
deployment. An unchanged key reused for a foreign deployment can have the same
key-only digest; scope must therefore be authenticated and checked separately
or included in the commitment. Replay of an older genuine digest message is
not rejected by digest equality alone.

**Attacker capability.** Control of only the key-delivery channel, config, or
destination can supply wrong bytes or withhold them, but cannot match an
independent uncompromised commitment except by breaking the selected hash
assumptions. Control of the digest channel can cause false enrollment if it
is the sole authenticated approval source; comparing with an arbitrary key
download is not independent confirmation. Two compromised pages on the same
service are one compromised authority domain, not two-channel protection.
Complete host control can falsify the digest check or operator display.

**Dependencies, availability, and refusal.** Requires independent message
authentication, reliable exact comparison, recipient/deployment identification,
and auditable delivery. Human-assisted channels introduce transcription,
impersonation, ambiguous-recipient, and scheduling risks. Missing or conflicting
authenticated digests, mismatch, unverifiable sender, or unclear scope refuses.
No majority among unauthenticated messages, first-message-wins, fingerprint
truncation, or same-channel fallback. Offline commitments reduce network
dependency but do not propagate revocation or prove currentness.

**Cryptographic and other assumptions.** Collision/second-preimage resistance
and appropriate output size under the accepted classical and quantum attacker
models are required; an unkeyed digest does not authenticate its sender.
Signed digest messages inherit their signature-root assumptions; common
email, messaging, TLS, or identity channels may be classical. In-person
delivery substitutes human identity/custody assumptions, not a cryptographic
proof of PQ security. No channel or hash is selected here.

### C. Independently enrolled platform-protected trust store

**Trust source and first delivery.** An owner-designated enrollment authority
places the separate public anchor, role, and deployment binding into a
protected store. Its administrative trust root, enrollment permissions,
device/deployment association, read interface, and update policy must be
independently authenticated. A file described as a "trust store" or a
root-writable configuration file is not this protection.

**Substitution and scope.** A trusted read must return the expected enrolled
entry and authenticated policy for this device/deployment; wrong slot,
unauthorized update, or foreign-domain entry refuses. Update isolation could
protect stored integrity, but it does not establish currentness unless a
separately approved mechanism also prevents stale enrollment, snapshot restore,
device reset/re-enrollment, and policy rollback.

**Attacker capability.** Under evidenced access isolation, destination or
ordinary-config control cannot replace the protected anchor; it can alter
association inputs, choose an unavailable store, or deny access. A hostile
delivery channel cannot enroll a new root without enrollment authorization.
An administrator or host attacker with permitted update/reset rights may
erase or replace it. Even where hardware prevents root alteration by the
host, the host can bypass ordinary verification or present fake outputs
unless protected execution and the relying boundary are separately established.

**Dependencies, availability, and refusal.** Requires supported platform,
enrollment controls, device lifecycle, verified read/update semantics, and
independent recovery evidence. Hardware failure, device replacement, migration,
unsupported platform, missing slot, inaccessible store, or unverifiable reset
history refuses the proposed trust result. Local hardware may reduce online
dependency but makes hardware loss and replacement availability issues.
An unavailable protected store must not silently downgrade to a local file.

**Cryptographic and other assumptions.** Hardware isolation, firmware, vendor
supply chain, administrator separation, and device-binding semantics need
evidence. TPM/secure-boot/attestation certificates commonly depend on classical
RSA/ECC and are not assumed PQ. Non-exportability of a stored credential,
attestation, and a monotonic counter are distinct capabilities, not universal
properties of a platform store. A public anchor store says nothing about the
validator private key's non-exportability or exclusive use.

### D. Separate anchor bound by independently authenticated genesis identity

**Trust source and first delivery.** An independently authenticated expected
genesis identity could commit to a distinct association-only anchor or to
an owner-authenticated association-anchor policy delivered alongside genesis.
The expected genesis identity itself needs an independent approved delivery
channel. This is an earlier candidate's trust-chain pattern, not approval to
repurpose existing `bundle_signing_authority_roots`, alter genesis, or select
a new root set.

**Substitution and scope.** Check the full canonical hash against the
independently expected hash, derive fields and hash from one owned parse,
then check the association's separately authenticated complete domain.
[Genesis authority hashing][genesis-hash] binds existing authority metadata;
it does not authenticate who supplied the expected hash. Numeric chain,
destination and validator association restrictions cannot be assumed from a
textual chain name or transport/bundle root. A valid older genesis-bound
anchor remains replayable without separate currentness evidence.

**Attacker capability.** A genesis-file or delivery-channel attacker cannot
change committed bytes while the expected hash and verification boundary
remain intact, under the selected hash assumptions. Config control that
also changes an unauthenticated expected hash defeats the check. Destination
control still allows replay and storage replacement; host control permits
bypass. Whoever controls the independent hash-enrollment authority can
authorize a malicious commitment if that authority is compromised.

**Dependencies, availability, and refusal.** Requires independently protected
expected-hash delivery, explicit association-only authority semantics, and
deployment checks not supplied by existing root types. The
[existing root schema][genesis-roots] is purpose-specific; [DevNet validation
allows empty sets][genesis-authority]. Missing association authority, unknown
provenance, hash mismatch, inconsistent parses, or unsupported domain refuses.
No fallback to a transport/bundle root. Replacing a genesis-bound anchor may
require an independently authorized transition rather than rewriting the
deployment's genesis identity; that identity/lifecycle decision is unresolved.
Embedded genesis and `None` remain outside the proposed normal external-genesis
boundary.

**Cryptographic and other assumptions.** Existing canonical genesis hashing
uses SHA3-256; this is a hash binding, not a signature or proof of delivery.
The preceding expected-hash channel inherits its own classical/PQ and human
trust assumptions. Existing ML-DSA bundle-root verification does not make that
channel PQ or authorize an association-signing purpose.

### E. Independently authenticated registry or witnessed delivery

**Trust source and first delivery.** An owner-designated registry could
publish deployment-bound anchor enrollment and transition records; an
independent witness arrangement could corroborate them. The registry/witness
verification roots, authority delegation, domain, and acceptable evidence
must first be enrolled independently. A registry whose root comes only from
the requested association is circular. A transparency log is not automatically
an approving authority or proof that an entry is current.

**Substitution and scope.** Check authenticated statements for the complete
anchor/policy and intended domain. Genuine archived statements can authenticate
historical enrollment. Proving currentness additionally needs a separately
approved freshness and consistency mechanism: for example, properly bound
challenge responses, trusted time with bounded age, or protected state and
independent witnesses. These are alternatives, not selections. A signed
sequence or timestamp alone does not show no newer transition exists; log
inclusion alone does not prove absence of revocation or a consistent latest
view.

**Attacker capability.** Control of a network channel, config, or destination
can block, replay, or redirect responses but cannot forge valid registry
evidence while the pinned registry authority and verifier remain intact.
Without separately established freshness, replay may be indistinguishable
from an old legitimate view. A compromised registry can sign false or split
views; witness independence and any threshold matter only if their exact
checking and honest-party assumptions are established. Complete host control
still permits bypass, even when remote evidence is sound.

**Dependencies, availability, and refusal.** Requires service custody,
delegation and compromise policy, network availability, domain-aware clients,
and possibly trusted clocks, challenge binding, witness consistency and
retention. Offline operation may authenticate cached historical bytes, but
cannot label them current without an approved offline policy and evidence.
Unverifiable responses or conflicting provenance refuse authentication;
missing fresh/consistent evidence leaves currentness unresolved and prevents
eligibility. No fallback to peers, an unsigned registry answer, or an older
cached "current" assertion. Network partitions and authority outage trade
availability for refusal, not for silently weaker trust.

**Cryptographic and other assumptions.** Registry/witness signatures, endpoint
authentication, time sources, quorum independence, service administrators and
availability are explicit dependencies. Ordinary TLS/WebPKI, classical service
signatures, hardware attestation and clocks are not presumed PQ or incorruptible.
PQ association signatures alone do not protect a classical registry bootstrap.
No online service, witness threshold, refresh interval or cache policy is
authorized.

## 4. Proposed lifecycle evidence, not an operating procedure

These are logical stages for owner review, not commands or approved
transitions. Owners must name the founder/approval authority, separate
bootstrap credential custodian, enrollment authority, transition/revocation
authority, currentness authority, and any recovery authority. One entity
could hold several administrative roles only by explicit owner decision;
association verification must not derive authority from validator or bundle
signing. Operators may deliver or observe evidence, not create missing
approval by editing config.

| Proposed stage | Who would authorize it (unresolved) | Independently authenticated evidence needed | Refusal boundary and remaining uncertainty |
|---|---|---|---|
| Initial enrollment | Owner-designated founder approval authority approves association scope; separately designated enrollment authority provisions the anchor and verifier policy. Bootstrap custodian signs only within approved association scope. | Authenticated approving identity/delegation; exact anchor/suite/role/domain commitment; independently delivered verifier policy and deployment expectations; signed complete association and approval relationship; evidence the chosen enrollment channel reaches this verifier intact. | Missing/conflicting provenance or domain refuses authenticated enrollment. A first local record or new key's self-signature cannot bootstrap authority. Initial currentness is still unresolved without a separately established mechanism, even on a supposedly new directory. |
| Normal verification | No new authority is created by a verifier or operator. It evaluates previously approved evidence; a separately designated currentness authority would establish status under approved policy. | Trusted anchor provenance and permitted suite/purpose/version; complete signed tuple; independently expected domain; available observations; any separately required currentness evidence bound to this exact anchor, association and deployment. | Parsing/authentication failure refuses verification; missing/mismatched observations refuse equality. Authentic/equal without currentness remains non-authorizing. No local matching record supplies an absent anchor. |
| Association replacement under an unchanged anchor | Owner-designated association transition authority, with bootstrap custodian signing within that delegation. Validator-key changes require separate validator authority and safety review. | Authenticated authorization identifying old and new association commitments, complete new tuple, scope, action and permitted transition relationship; approved currentness evidence establishing the applicable transition. | A second valid association is not automatically the new expected one. Conflicting/partial transitions refuse transition acceptance; without currentness, order and supersession remain unknown. Updating the public tuple proves neither later signer identity nor preserved signing history. |
| Anchor replacement | Independently designated replacement authority; an old bootstrap credential is sufficient only if separately delegated this role and independently established as eligible. | Authenticated transition binding old/new complete anchor identities and suites, role/policy, deployment, affected associations, predecessor relationship and intended cutover; authenticated new provisioning evidence; separately established transition currentness/continuity. | New-anchor self-authorization refuses. Old-to-new cross-signature alone may be replayed or issued by a compromised old key. Mixed old/new anchor, association, policy or status evidence refuses a coherent replacement result. Overlap/cutover and acknowledgement rules remain undecided. |
| Revocation of anchor, association or delegation | Separately designated revocation authority; who can revoke a lost/compromised authority must be decided before relying on it. | Authenticated revocation naming exact target, domain, action and authorization; separately trusted evidence of its applicability/currentness and defined propagation/effect semantics. | Trusted applicable revocation bars a current/eligible result for the target; it need not erase the fact that old bytes once verified. Absence of a revocation message is not proof of no revocation. Conflicting or unverifiable revocation evidence prevents eligibility; no local clear or automatic substitute. |
| Loss or compromise | Pre-established independent recovery/emergency authority, if owners later approve one; not a newly generated local key, affected validator signer or compromised authority acting alone. | Independently authenticated incident/recovery authorization, authority/delegation status, intended new enrollment, scope and transition evidence; separate evidence for any signer/history/storage restoration claim. A compromise report's provenance and authority to change status are distinct. | Lost public bytes may be reacquired only against intact independent provenance and currentness. Lost private authority cannot authorize itself anew. Suspected compromise prevents eligibility pending trusted resolution; confirmed compromised approval roots cannot prove recovery merely by signing it. Without an intact independently designated authority, recovery authorization remains unavailable. |

Replacement must consider partial distribution: one verifier may see a new
anchor but an old association, another the reverse, and another neither.
Deleting the old file or observing local rename completion is not global
cutover evidence. A future design would need a coherent authenticated
generation and a defined acceptance boundary, with decisions about overlap,
acknowledgements, crashes, uncertain publication and partitions. This does
not select a transaction format, persistence technique or rollout procedure.
Until that evidence exists, neither majority of local files nor "newest
mtime" establishes the accepted generation.

Loss of a directory, local marker or hardware device does not restore a
trusted baseline. Re-enrollment of a new host or destination is a separate
authorization question, not evidence that it never signed before. Loss of the
bootstrap private credential may stop future association signing without
invalidating historical signatures; compromise may permit fresh-looking
forgeries. Owners must separately decide who can suspend reliance, confirm
compromise, revoke, and authenticate recovery. No backup, threshold,
emergency key or replacement process is approved here.

## 5. Three claims that must remain separate

**Authentication and association.** An independently authenticated expected
anchor and verifier policy can establish that a complete representation
verifies under a permitted association authority for the intended scope.
Equality separately compares every required observation. Neither claim
establishes that the actual later-loaded signer is the observed public key.

**Currentness.** An authentic anchor enrollment, association or transition may
have been superseded or revoked. Signatures authenticate statements; an
authenticated sequence supplies a signed number, not knowledge of the maximum
authorized number. Time/expiry checks depend on authenticated policy and a
trusted clock, and do not alone prove no newer revocation. A protected local
counter would require evidenced enrollment, anti-reset/restore properties,
scope and recovery; a remote source would require evidenced freshness,
consistency and availability. None is established for this association here.
If trusted currentness evidence/policy is unavailable, report
`Currentness::Unresolved`, not current, stale, eligible, or rollback-protected.
Even an authentic replay cannot be called stale solely because an analyst's
fixture knows a later generation exists.

**Complete signing history and exclusive signer control.** Neither anchor
authentication nor association currentness commits to every prior signing
decision, protects durable anti-equivocation state from rollback, recovers
consensus locks, fences concurrent/restarted actors, or excludes copied keys
on other hosts. Those need separate authority, custody, persistence and
runtime evidence. The [signing-state continuity contract][continuity] keeps
its external durable anti-rollback commitment unresolved and separates
activation, current-authority freshness and continuity. Anchor replacement
must not be portrayed as restoring that history or granting recovery.

All three remain separate from permission to act. A future result may be
authentic, equal, and current under a selected policy yet still carry no
startup, signing, recovery or restart authority.

## 6. Concrete failures and required non-authorizing outcomes

These are proposed decision semantics consistent with the merged
specification, **not assertions of implemented runtime enforcement**.
"Refuse" below means no trusted enrollment/transition, verified association,
equality, or eligibility result at the failed stage; earlier independently
established historical facts are not rewritten into current authorization.

| Failure case | Required outcome | What remains unknown |
|---|---|---|
| Anchor available but provenance missing, unreadable, malformed or from an unknown issuer | Refuse authentication; surface acquisition/provenance failure; no default config/root or local-record fallback. | Intended founder authority and permitted deployment. |
| Two authenticated provenance messages disagree on anchor, policy or scope | Refuse coherent enrollment/transition; do not use arrival order, local majority or an untrusted timestamp to choose. | Which statement is currently applicable and whether authority equivocates or a transition is incomplete. |
| Substituted anchor plus association validly signed by attacker's replacement key | Refuse independently expected-anchor identity/provenance check. Self-consistency is not authorization. | If independent provisioning and host are also compromised, intended authority cannot be established by this verifier. |
| Authorized bootstrap key signs a foreign deployment and all observations match it | Refuse independent domain check, even though cryptographic signature and observation equality hold. | Authority for this deployment; whether signing occurred outside the key's delegated scope. |
| Genuine old association or old anchor package replayed with matching observations | Historical authentication/equality may hold. Without trusted currentness evidence return unresolved and no eligibility. If trusted evidence establishes supersession, refuse current/eligible status. | Whether it is actually latest in the unavailable-evidence case. |
| Genuine old replacement/revocation transition replayed, including a valid old-to-new cross-signature | Do not accept applicability from signature, signed sequence or timestamp alone. Missing trusted transition currentness means unresolved/no eligible transition; contradictory trusted state refuses. | Latest authorized transition and effect of unseen revocation or delegation change. |
| New anchor installed with old association, new association with old anchor, or policy/status for another generation | Refuse coherent replacement; do not repair, delete, combine generations or retain old eligibility automatically. | Whether partial deployment, corruption or attack occurred; completion/cutover status. |
| Missing signature, unsupported purpose/version/suite, invalid signature, omitted signed field or ambiguous encoding | Refuse acquisition or verification at the relevant stage; no unsigned DevNet compatibility or attacker-selected algorithm. | Authentic approved association. |
| Missing observation, complete-key mismatch despite same short fingerprint, unavailable destination/genesis identity | Refuse equality. `None`, short prefixes and directory names are not substitute observations. | Actual complete identity and any independently approved handling of the unavailable field. |
| Namespace replaced, disk/marker snapshot restored, or local version rolled back | Do not infer incarnation identity or currentness from path, lock or local marker. Refuse the claim requiring unavailable independent continuity evidence. | Storage continuity, latest association and signing-history completeness. |
| Bootstrap/approval credential lost or suspected compromised | Prevent an eligible reliance/recovery result pending independently authorized resolution; no key regeneration or local "clear" authorization. Historical signature verification may remain possible. | Ability to approve future transitions; incident scope, unseen forged statements and intact recovery authority. |
| Revocation/currentness service, clock, witness or protected state unavailable or inconsistent | Currentness unresolved; no current/eligible status or weaker cached/local fallback. Distinguish outage from authenticated revocation. | Whether a valid anchor or association was superseded; availability duration and permitted future offline policy. |
| Validator signer, bundle signer, operator config or new bootstrap key attempts to authorize anchor enrollment/recovery by itself | Refuse unauthorized role/delegation and circular provenance. | Legitimate separate association authority and its approval. |
| Fully compromised verifier host reports a successful check | No host-compromise enforcement claim follows from any candidate or log. Require independent protected-boundary evidence for such a future claim. | Whether verification occurred, inputs were genuine, or refusal was honored. |

## 7. Implementation-entry decisions and future verification

Before any implementation-entry approval, owners and independent reviewers
would need to settle the following, explicitly without approval by this
document:

| Decision area | Unresolved entry decision |
|---|---|
| Authority and separation | Named approving, enrollment, custody, transition, revocation, currentness and recovery authorities; delegation/threshold rules and compromise handling; no validator/bundle authority substitution. |
| Delivery and attacker scope | Which candidate or bounded combination; independent first trust source; accepted host/admin/channel/device compromise assumptions; verifier/execution boundary and evidence of independence. |
| Identity and cryptography | Full deployment/tuple semantics, anchor scope, complete key/suite commitments, distinct purposes and versions, canonical bounded encoding and algorithm policy; classical/PQ assurance for every dependency, not just association signing. |
| Currentness and transition | Separately approved anti-replay/currentness mechanism, predecessor/cutover/overlap semantics, conflict handling, revocation applicability, outage policy and recovery after missing/rolled-back state. |
| Storage and operations | Coherent generation publication and read boundary; durability, reset/migration, uncertain writes, partial distribution, custody loss, diagnostics and availability; no automatic repair or re-enrollment. |
| Runtime integration | Whether normal initial DevNet with `data_dir` is the only scope; exact pre-protected-effect position and later actual-signer checks; separate restore/reset/no-directory/LocalMesh/embedded-genesis decisions. |
| Independent review | Evidence gates and who accepts them; authentication, equality, currentness, permission, history and exclusivity remain separately reportable. No readiness promotion from this document. |

The [normal ownership source][ownership] and [protected-effect model][effects]
support only the previously reviewed candidate boundary after normal
destination ownership and before protected effects. `SignerLoaded` stays
protected; [complete signer public bytes][signer] are available after loading,
not proof of an independently provisioned pre-load key. The [route proposal
limits][routes] remain: pre-lock config/genesis reads and directory/lock
creation are not absent; restore, reset, no-data-directory, LocalMesh and
embedded-genesis handling need separate decisions. No production hook is
added or authorized.

### Future verification matrix

**Every proposed test/control in this subsection is FUTURE / NOT EXECUTED
for this assessment.** Earlier executed synthetic evidence in section 1 is
historical and separately attributed, not new lifecycle or provisioning
evidence. Future work must be independently authorized before execution.

| Status and evidence class | Proposed controls and expected bounded evidence |
|---|---|
| **FUTURE / NOT EXECUTED - synthetic authentication/domain** | Fixed independently supplied synthetic anchor/policy/domain; positive control; attacker-key substitution, missing/conflicting provenance, unsupported suite/purpose/version, incomplete/ambiguous commitment, each seven-field mutation and foreign signed tuple with matching observations. Same-checker per-field encoding/domain/policy bypasses must break corresponding negative assertions. Positive controls must defeat reject-all implementations. Include an actually incompatible-suite key control separately from the earlier same-primitive unauthorized-key control. |
| **FUTURE / NOT EXECUTED - synthetic delivery candidate models** | Model package-root circularity, key-only digest cross-domain reuse, same-channel digest substitution, wrong platform slot/enrollment, config-swapped expected genesis hash, registry root self-enrollment and split views. Explicit harness trust labels model assumptions only; do not claim actual channel, hardware or operator independence. |
| **FUTURE / NOT EXECUTED - synthetic lifecycle/currentness** | Model independently fixed generations and transition authority, signed old association/package/transition replay, new-key self-authorization, compromised-old-key cross-signature, revoked delegation, partial generation, conflicts, lost authority and unavailable freshness. Keep harness-only knowledge of "old" out of the evaluator. Without approved evidence expect unresolved/no eligibility; only a separately approved mock currentness contract may yield current/not-current. A bypass treating authenticity or a signed sequence as freshness must invalidate the corresponding negative control. |
| **FUTURE / NOT EXECUTED - real provisioning** | After owner selection, establish actual first-root delivery and recipient/deployment verification, administrative/channel independence, complete commitment comparison, policy enrollment and custody approvals. Exercise one-channel compromise, sender impersonation, conflicting delivery and unavailable enrollment on disposable non-operational credentials. Synthetic provenance flags cannot replace these records. |
| **FUTURE / NOT EXECUTED - real storage/platform** | After separate design approval, exercise protected-store access/update/reset and trusted read boundaries, device replacement, namespace/symlink substitution, snapshot rollback, concurrent readers/writers, crash/power-loss and uncertain publication during replacement. Demonstrate coherent generations and selected anti-rollback properties at the actual backend; mocks, canonical paths and successful renames do not prove durability or enforcement. |
| **FUTURE / NOT EXECUTED - real currentness operations** | After mechanism approval, exercise genuine endpoint/witness authentication, replay, fork/equivocation, partitions, delayed revocation, clock/reset uncertainty, cache expiration, missing prior state, authority loss and independently authenticated recovery. Document exact honest-party, time, freshness and availability assumptions. Service signatures/log inclusion alone cannot establish latest status. |
| **FUTURE / NOT EXECUTED - runtime and protected effects** | Only after integration approval, use observable protected-effect counters/callbacks for signer loading, storage effects, network tasks and participation; refusal must leave the protected effects unreached. Sensitive bypasses must break that assertion. Synthetic callbacks establish harness ordering only; actual configured CLI/runtime evidence and separate route-specific controls are needed for production ordering claims. |
| **FUTURE / NOT EXECUTED - signer/history operations** | Separate approved work must evidence actual signer identity after load, custody/exclusivity/fencing, complete durable history, lock recovery, cross-restart/copy/rollback behavior and restore authority. Anchor lifecycle positives cannot be used as proxies for these claims. |

Any future evidence package should retain producing source commit/tree,
fixture and policy inputs, exact commands, full output, exit codes, positive
and negative counts, which same-checker mutant defeats each negative, and
cleanup outcome. Distinguish simulated acquisition errors from actual helper
I/O, model freshness from real witnesses, and synthetic ordering from configured
runtime effects. Provisioning, hardware, custody and operational records need
independent provenance and review with sensitive information excluded.

## 8. Preserved source findings and review limitations

[Existing ratification input][sidecar] reads and parses a local sidecar with
explicit I/O/parse errors; it is not independent provisioning.
[V1 ratification verification][ratification-v1] authenticates a
bundle-signing target under a bundle authority, not this seven-field
validator association. The [v2 type's historical Run 130 comment][ratification-v2]
does not erase the later [conditional startup dispatch][v2-dispatch] and
[preflight][v2-preflight] in pinned source. That preflight returns early
without a v2 sidecar or data directory, and the [DevNet outer gate][devnet-gate]
is operator opt-in. Neither this bounded wiring nor its bundle-purpose
rotation/revocation/markers provides association authority or currentness.

The [audit register][audit] keeps A23-F1's K!=T ratified-target/bundle-signer
gap, invocation/data-directory and independent-genesis-provenance qualifications
OPEN. A33-F1 / E27 retains its operator-crafted-anchor/admitted-catch-up,
registration-before-vote and ancestry-cycle/runtime qualifications; this
public identity assessment does not establish termination or close E27.
The older [trust-anchor model][authority-model] states trusted out-of-band
genesis delivery as an assumption; its historical "None today" genesis-root
inventory is not a description of the later pinned schema.

The [activation guard][disabled] remains unchanged, including its explicitly
separate legacy CLI-key route qualification. No claim is made that every
possible QBIND signing route is disabled; the accepted genesis-authority
activation and public-DevNet posture are preserved.

This is a bounded document/source assessment, not a new security audit,
independent cryptographic review, executed test report, operational attestation,
or readiness decision. No external service, hardware product or delivery
procedure was evaluated in operation. No provisioning, storage, runtime,
signing, durability, recovery or restart behavior was exercised. Only this
document is added; earlier documents, outputs, code and tests are unchanged.
The branch is for independent review, not approval to activate or deploy.

## 9. Pinned references

Unless explicitly marked historical below, all links pin to verified merged
main `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree
`f1a7d40993bfefbe18635bd637a100ad5527d875`. They are evidence locators, not
assurances of currentness or independent founder authorization.

[spec]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-separate-bootstrap-anchor-spec-test-plan-20261108.md#L1-L229
[candidate]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-devnet-public-association-authentication-candidate-20261108.md#L35-L193
[routes]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-public-first-startup-identity-contract-proposal-20261108.md#L145-L173
[synthetic-evidence]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-evidence-20261108.md
[correction]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-20261108.md
[comparison]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-public-identity-comparison-test-evidence-20261108.md#L47-L146
[harness]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs#L29-L224
[boot]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/pqc_boot_genesis.rs#L215-L245
[retained-boot]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/main.rs#L2404-L2449
[destination]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/restore_completion.rs#L148-L179
[lock]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/restore_completion.rs#L800-L911
[genesis-hash]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-ledger/src/genesis.rs#L1555-L1672
[genesis-roots]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-ledger/src/genesis.rs#L369-L400
[genesis-authority]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-ledger/src/genesis.rs#L749-L840
[continuity]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md#L13-L45
[ownership]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/main.rs#L2515-L2552
[effects]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/tests/a33_f1_startup_route_classification_model.rs#L124-L143
[signer]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/signer_loader.rs#L92-L115
[sidecar]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/pqc_ratification_input.rs#L1-L99
[ratification-v1]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-ledger/src/bundle_signing_ratification.rs#L575-L705
[ratification-v2]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-ledger/src/bundle_signing_ratification.rs#L1309-L1370
[v2-dispatch]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/main.rs#L6692-L6813
[v2-preflight]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/main.rs#L1176-L1258
[devnet-gate]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/pqc_ratification_policy.rs#L140-L171
[audit]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md#L220-L226
[authority-model]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md#L140-L205
[disabled]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/main.rs#L5403-L5435

Historical producing-source locators (not newly executed evidence):
[original synthetic source](https://github.com/olivexo28/QBIND/blob/3cf05468bd753d279433904eeaa0cbdc73550706/crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs)
and [corrected synthetic source](https://github.com/olivexo28/QBIND/blob/b841fa4e8fb5718b5f74d60363d7d1ad8e50cea5/crates/qbind-node/tests/separate_bootstrap_anchor_synthetic_tests.rs).
