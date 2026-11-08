# QBIND — Candidate B anchor commitment specification

**DOCUMENTATION-ONLY SPECIFICATION. OWNER-APPROVED DIRECTION FOR
SPECIFICATION ONLY. NO CHANNEL, CREDENTIAL, FORMAT, ALGORITHM, OR PROCEDURE
SELECTED.**

Candidate B is the direction to authenticate a commitment to the expected
association-verification bootstrap anchor through an independent commitment
channel, separate from the channel that delivers the anchor and association
deployment inputs. The commitment is not itself an anchor, a signer, an
association, a currentness statement, or permission to act.

This specification selects no actual key, algorithm, channel, encoding, file
format, trust root, provisioning procedure, authority, policy, storage,
currentness mechanism, replacement/revocation process, or recovery mechanism.
It authorizes no implementation, operational key use, startup, signer loading,
signing, participation, recovery, restart, merge, or deployment.
Association-verification authority remains separate from validator
consensus-signing and bundle-signing authority.

**A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED; public
DevNet remains NO-GO.** Earlier accepted findings and historical evidence
remain in their reviewed scopes.

## 1. Revision, provenance and scope

The remote refs were checked before creating this branch:

| Reference | Expected and verified value |
|---|---|
| `refs/heads/main` | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| `refs/heads/docs/bootstrap-anchor-delivery-lifecycle` | `12fbfbe77609afc659f55ee1fb41fd066cf00910`, tree `0144ad760655a7f8d36a8a3cb43adff1680f1a25`, parent `aa382fa28b2d3e97e6203d47fa8231b5f2269741` |
| New branch | `docs/candidate-b-anchor-commitment`, created from the verified assessment commit above |
| Only path added by this specification | `docs/security/evidence/a33-f1-candidate-b-anchor-commitment-spec-20261108.md` |

The immediate reviewed input is the
[bootstrap-anchor delivery and lifecycle assessment][assessment], especially
its candidate-B comparison, common attacker boundary, open lifecycle
decisions, and synthetic-vs-operational evidence plan. That assessment itself
pins relevant merged source and earlier reviewed documents. This specification
is a narrower elaboration of Candidate B, not a selection among its
unresolved choices and not an implementation review.

The merged synthetic test evidence and correction remain what their pinned
records say they are. They construct an independently expected anchor and
authenticated provenance as test fixtures; they do not prove any real
channel independence, credential custody, deployment binding, currentness,
or runtime enforcement. The earlier assessment records that the previous
"wrong-suite signing key" description was corrected: an unauthorized key
using the same ML-DSA-44 primitive was exercised, but an actually
incompatible-suite signing key was not. This document does not expand or
reinterpret those results.

Relevant source examples are cited at pinned main
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree
`f1a7d40993bfefbe18635bd637a100ad5527d875`. They describe existing bounded
mechanisms, not Candidate B or proof of its assumptions.

## 2. Threat model and trust vocabulary

### Assets and claim under review

The narrow target is the **expected public association-verification anchor**
and the exact deployment scope in which a verifier may use it to authenticate
a proposed validator association. An accepted commitment would let a future
verifier detect that the anchor bytes delivered alongside the association
are not the bytes-and-scope independently expected for that deployment, under
the selected commitment and channel assumptions.

It would not demonstrate that the anchor's holder is currently authorized,
that the association is current, that an associated validator key is
exclusively controlled, or that any action is permitted. The commitment
channel authenticates an assertion about expected anchor material; the
separate anchor/deployment channel transports material to compare. Neither
channel derives authority from a self-asserted value in the other.

### Principals and channels (roles, not selected organizations)

| Logical role | What it would do | Must not be silently conflated with |
|---|---|---|
| Commitment authority | Approve and authenticate the commitment statement and its deployment binding. | The bootstrap association signer, validator signer, bundle signer, or transport endpoint merely hosting a digest. |
| Commitment-channel custodian | Operate the independent mechanism that delivers the authenticated statement to the intended verifier/operator. | The commitment authority unless owners explicitly approve the same role and accept the resulting common failure domain. |
| Anchor/deployment-channel authority | Publish or deliver the anchor bytes, signed association and required deployment materials. | The independent commitment authority by virtue of providing the anchor, package, configuration or URL. |
| Anchor custodian / association signer | Protect the bootstrap private credential and sign approved association statements if later authorized. | Authority to set or change its own expected anchor commitment, approve its own enrollment, or authorize recovery by itself. |
| Verifier/operator | Obtain both evidence streams and perform the proposed checks. | A root of authority merely because the verifier has local configuration or possesses both messages. |
| Currentness/revocation authority | If separately approved, provide evidence about supersession, revocation and applicable state. | The commitment authority unless separately designated and its freshness role reviewed. |

Names, roles, delegation and approval thresholds are all unresolved. The
table states separation obligations, not an organizational model.

### Adversary capabilities and limits

Consider separately an adversary able to control or disrupt:

1. **Anchor/deployment channel only:** replace, replay, omit, reorder, redirect
   or withhold the delivered anchor/association/deployment bytes, and alter
   configuration that chooses that source. With the commitment channel,
   verifier, expected deployment and comparison intact, the adversary should
   not be able to substitute a different anchor or scope and pass the
   commitment check. It can cause refusal/denial of service and can replay
   an authentic old artifact; this channel alone does not establish
   currentness.
2. **Commitment channel only:** replace, replay, suppress or redirect the
   commitment message. The anchor channel cannot vouch for a commitment
   delivered by an unauthenticated or compromised commitment source. The
   verifier must refuse missing, unauthenticated, conflicting or
   wrong-scope commitment evidence. If the compromised channel controls the
   credential trusted to authenticate commitments, it can authorize an
   attacker-chosen commitment within the verifier's trust policy. A digest
   does not help against that authority compromise.
3. **Both channels, or a common administrator/root controlling both:**
   choose a substituted anchor and matching commitment. Candidate B's
   independence benefit is lost; a digest match only demonstrates
   consistency between mutually controlled inputs. Unless a separately
   trusted authority or execution boundary exists, the verifier cannot
   identify the intended founder-approved anchor.
4. **Shared identity, account, credential, signing service, administrator,
   recovery path, deployment pipeline, or upstream provider:** a compromise
   affecting that shared dependency may control both channels even when
   messages use different URLs, vendors, accounts, devices, or physical
   media. The independence claim fails for that failure domain unless the
   shared component is constrained and that constraint is independently
   evidenced.
5. **Local configuration, destination directory, or local artifact store:**
   alter channel locators, replace/delete/replay local files, race reads,
   or deny access. Secure authenticated commitment handling must not let
   these values select a different verifier root, deployment scope, digest
   policy, algorithm, or fallback. Availability attacks cause refusal.
   The earlier assessment notes that canonicalized destination paths and
   advisory locks do not prove filesystem-incarnation identity or exclude
   non-cooperating writers.
6. **Entire verifier host or execution environment:** modify verifier code,
   roots, trust decisions, inputs, displayed results, or subsequent control
   flow. Candidate B alone cannot force a compromised host to enforce a
   correct refusal. No software-only commitment check establishes trusted
   execution, trusted I/O, or real startup/runtime ordering.
7. **Authority, credential, or enrollment process:** issue a commitment
   the verifier treats as valid while approving a wrong or malicious
   anchor. Cryptography can authenticate the statement under its key, not
   establish that key's intended owner, delegation, honest operation or
   independence.

The intended bounded claim against a *single* channel compromise depends on
the other channel's independently authenticated inputs, channel separation,
uncompromised verifier, exact scope checks and refusal semantics. It is not
a claim against joint compromise, an authorized-but-malicious authority, or
a compromised host.

### Independence decision boundary — proposal, not an established fact

**Proposed boundary:** a future deployment's independence review is a
precondition to claiming Candidate B's independently authenticated
expected-anchor result. A future verifier would receive a separately trusted
input attesting that a specifically scoped review was completed and accepted
for this commitment authority, anchor/deployment channel, recipient and
deployment. The attestation would need to bind the review scope and the
identified channels/authorities; a Boolean configuration flag, operator
assertion, two-channel count, or synthetic fixture label is not that
attestation and does not prove real administrative independence.

This boundary does not select an attestation format, signer, trust root,
review body, delivery channel, or provisioning procedure. Before reliance,
an independent process must establish the review's authority and evidence;
the verifier must authenticate the attestation under a separately established
trust policy and check that its scope matches the actual channels and
deployment. That introduces trust dependencies on the review authority,
attestation credential and enrollment, review evidence integrity, recipient
binding, and verifier enforcement. It also introduces a **currentness**
dependency: an authentic prior review may be withdrawn, superseded or made
inapplicable by changed channel administration, credentials, providers or
deployment. Without separate authenticated evidence that the scoped review
remains applicable, independence is not established for a current result.
Neither the raw commitment match nor a self-asserted or stale attestation can
repair missing review evidence.

If owners later choose not to provide a separately authenticated review
attestation to the verifier, independence would remain an externally reviewed
deployment prerequisite, and the verifier could not itself claim to have
established it. That alternative is not selected. Under either boundary,
missing, conflicting, insufficient or threat-model-disqualifying
independence evidence makes expected-anchor authentication **refused or
unavailable**. Association authenticity and tuple equality that depend on
that expected-anchor result must likewise be **refused or unavailable**;
they cannot be promoted by a raw match, a signature under the delivered
anchor, or matching observations. No startup, signer-loading, signing,
participation, recovery, restart or other authority follows.

A byte-for-byte anchor match or equality between a computed digest and
delivered digest may be retained only as **non-authoritative diagnostic
information** (for example, to explain which values matched during a
refused evaluation). It is not Candidate B's independently authenticated
expected-anchor result. That result additionally requires authenticated
commitment provenance, independently established deployment binding, and
applicable channel-independence evidence under the approved threat model.

## 3. What independence would mean and what evidence is missing

Physical separation or different transport protocols is not the independence
criterion. Before accepting a real-world independence claim, owners and an
independent reviewer would need evidence that, for the defined threat model:

* **Authority separation:** identify who approves the expected anchor and
  who operates/delivers each channel; establish authority and delegation
  through independently authenticated evidence. Two statements signed by
  the same credential, or two messages controlled by the same account, are
  one trust source.
* **Credential separation:** identify the credentials that authenticate the
  commitment source and the anchor/deployment source; show distinct custody,
  issuance, recovery, revocation and administrator permissions where
  independence is claimed. Demonstrate that disclosure/revocation of one
  does not automatically grant the other. Different key IDs are not enough
  if keys share one exportable seed, signer, HSM role, cloud KMS account,
  backup, or reset authority.
* **Administrative separation:** map interactive administrators,
  organization owners, identity providers, privileged roles, help-desk
  reset, break-glass accounts, CI/CD operators, approvers, audit-log
  writers, and policy maintainers. Identify whether one principal can
  change both channel content and the verifier's trust in it. Where one
  person or principal can control both, document it as a common failure
  domain rather than claiming independence.
* **Infrastructure/failure-domain separation:** identify shared hosting,
  provider control planes, DNS/registrar, account recovery, build/release
  systems, package repositories, network endpoints, time sources, backup
  storage, device fleet, and outage/censorship dependencies. Explain which
  shared infrastructure can forge/authenticate content versus only deny
  service. Two URLs or two vendors do not prove separate identity,
  administration, or recovery.
* **Recipient and deployment binding:** show how the commitment statement
  is delivered to and interpreted by the intended verifier for the exact
  initial-DevNet deployment. Establish independently what authority
  designates the recipient, deployment identity and policy. A hostname,
  operator-provided label, mutable environment variable or textual chain
  name alone cannot establish this binding.
* **Auditable provenance and change control:** preserve approval,
  credential-custody, delivery, receipt, verification and transition
  records with independently protected audit provenance. Demonstrate
  controls for account changes, key rotation, revoked access, recipient
  changes and administrator recovery. An audit log writable by the same
  compromised principal is not independent evidence.
* **Single-channel compromise exercise:** under separately authorized,
  non-operational conditions, demonstrate that changing or withholding
  either channel alone cannot produce a false accepted anchor and that
  the failure is observable as refusal. This exercise cannot prove that
  unseen common administrators or dependencies do not exist; it must be
  paired with the authority/credential/failure-domain review and any
  separately authenticated review attestation required by the proposed
  verifier boundary.

No evidence satisfying these criteria is supplied or asserted here. No
authority, account, provider, root, credential or delivery channel is
selected. Owners must accept a threat model that names residual common
dependencies and specifies which compromises Candidate B is intended to
withstand.

### Initial trust and non-circularity

An authenticated commitment still needs a trust basis for the commitment
authority and its intended deployment binding. That basis must be available
independently of the anchor/deployment channel being checked and must have a
reviewed initial enrollment story. Otherwise the design only moves the
substitution question one layer outward:

```text
trusted commitment credential
    <- how independently authenticated and enrolled?
authenticated commitment statement
    <- how bound to this recipient and deployment?
commitment to anchor and scope
    <- compared with which exact received bytes?
```

Each arrow requires an owner-approved trust statement and evidence. A public
key, digest, certificate, signature, authenticated network session, local
configuration value, QR code, file path, or account label is not
self-authenticating. Trust-on-first-use is not independent initial
authentication unless an explicit owner decision accepts that first contact
as the trust root and separately addresses substitution during enrollment.
No recursive or implicit first-use fallback is authorized.

The proposed reviewer attestation described above has the same
non-circularity requirement: its own authority and initial enrollment must
be authenticated separately; it cannot attest to its own trustworthiness.
An attestation of a past review is evidence that the review occurred, not
proof that the reviewed conditions remain true. Updates to either channel's
administrators, recovery mechanisms, credentials, shared providers or
deployment scope may invalidate its applicability. A separate currentness
source/policy would be needed to claim that the attestation remains in force;
without it, independence is unavailable for that claim.

## 4. Abstract commitment statement and binding requirements

This section defines logical information that a future approved statement
would need to authenticate. It deliberately does not define bytes, fields'
serialization, canonical encoding, hash algorithm, signature suite,
certificate, transport, file, protocol or trust root.

The commitment must be unambiguously about the **complete expected anchor
and its allowed deployment scope**, not merely an unlabeled key digest. At a
minimum, its authenticated meaning must bind:

* the complete anchor public-key value and its declared key/signature suite;
* the anchor's association-verification purpose, distinguishable from
  validator consensus signing, bundle signing and transport use;
* an explicit format/policy version and the permitted association-signing
  verification policy, so untrusted anchor or association metadata cannot
  choose or downgrade the verifier;
* the deployment domain under owner-approved identity semantics, including
  the intended initial-DevNet environment, numeric chain identifier, full
  genesis identity, destination identity, and any validator/association scope
  restrictions the owner decides must constrain anchor reuse;
* a commitment-method identifier and exact digest length/representation,
  authenticated as policy rather than selected from attacker-supplied data;
* the issuer/authority role and recipient/deployment binding needed to
  interpret the statement, conveyed under the independently reviewed
  commitment-channel authentication mechanism.

These are information requirements, not a chosen transcript. Owners must
decide whether the commitment covers the anchor key directly or a complete
anchor record. If it covers an encoding, that encoding must be unique and
unambiguous; a different encoding of the same semantic key/scope must not
silently be accepted as equivalent, and two different semantics must not
collide by concatenation ambiguity. Any optional field/default, suite alias,
text normalization, key identifier, digest formatting, or policy-version
rule needs explicit semantics. A short fingerprint is not the full-key
commitment.

Deployment binding must not consist only of a label copied from the
anchor-delivery message. The verifier needs independently expected domain
values/policy, authenticated by the commitment authority or another
owner-approved source, and must compare the received anchor's permitted
scope to those values. The association separately binds its required
identity tuple: environment, numeric chain, full genesis identity,
destination identity, validator ID, validator consensus suite and complete
validator public key. Whether all these values are also directly included
in the anchor commitment, or which are restrictions on an anchor versus
fields of an association, is an explicit owner decision. No scope can be
inferred from a matching signature or key bytes.

### How the commitment channel must authenticate its statement

A digest is a collision-resistant consistency check under a selected hash
assumption; it contains no proof of who chose it or which deployment it
approves. A future design must authenticate the *commitment statement*
through an independently trusted mechanism. That mechanism must bind the
statement's full meaning, issuer role/delegation, intended recipient or
deployment, and any freshness fields that are separately approved.
Authenticating a transport endpoint without authenticating the statement's
origin/authority may be insufficient; authenticating the sender without
binding the destination permits cross-deployment redirection. The exact
mechanism, trust root and initial enrollment are unresolved.

Evidence must allow a verifier/reviewer to establish: (1) who or what
authenticated the statement; (2) why that source is authorized to approve
this association anchor; (3) the complete statement bytes/meaning received;
(4) its intended recipient/deployment; (5) the credential and policy used
to validate it; and (6) whether required currentness evidence exists.
An authenticated signature or channel can establish only claims within its
key/endpoint and delegation scope, not the truth of an undelegated role
assertion.

## 5. Proposed verification sequence

The following is a refusal-only conceptual sequence for a future,
independently authorized verifier. It is not implemented and does not specify
an API, exact evaluation order among internal parsing operations, or startup
hook.

1. **Establish expected context.** Obtain the intended environment,
   numeric chain, full genesis identity, destination and other approved
   domain restrictions from an independently authenticated source. Do not
   derive expected values from the anchor, association, channel locator,
   operator-controlled local file or observations being compared. If
   required context is absent or conflicting, refuse that verification.
2. **Acquire commitment evidence.** Obtain the complete commitment statement
   and its authentication/provenance evidence from the designated commitment
   channel. Missing, unreadable, malformed, truncated, ambiguous,
   unsupported, unauthenticated or unavailable evidence refuses; do not
   substitute a digest from config, the anchor channel, a cached local file,
   or first-use.
3. **Authenticate issuer and binding.** Verify the statement under
   independently enrolled commitment-channel policy. Check issuer role,
   credential authority, purpose, policy version, intended recipient and
   deployment binding. Do not allow the statement to introduce the root
   used to authenticate itself. Unknown role, revoked/unsupported
   credential, wrong recipient, policy downgrade or conflicting
   authenticated statement refuses.
4. **Acquire anchor/deployment evidence separately.** Read the complete
   anchor record and associated deployment materials from the separately
   authorized anchor/deployment channel. Treat them as untrusted until
   checked. Do not accept the anchor channel's statement that it matches,
   or a signature under the received anchor, as provenance for the anchor.
5. **Parse exact semantics.** Apply only a separately authenticated,
   supported interpretation policy. Refuse ambiguous, duplicate, malformed,
   truncated, unknown-critical, unsupported-version or unsupported-suite
   representations. Refuse algorithm selection, permissive fallback or
   purpose reuse controlled by untrusted bytes. Preserve the exact owned
   bytes/value that will be checked and used.
6. **Bind scope and full anchor.** Calculate the commitment using the
   future approved canonical meaning and commitment method over the full
   anchor and all commitment-bound scope/purpose/policy data. Compare to the
   authenticated expected commitment. Independently compare every required
   deployment restriction to the expected context. A matching raw byte/digest
   value is diagnostic only until the channel-independence precondition and
   any required separately trusted review attestation are established. If
   independence is missing, conflicting, insufficient or disqualified under
   the approved threat model, expected-anchor authentication is refused or
   unavailable despite a raw match. A mismatch, incomplete field, unbound
   scope, wrong deployment, duplicate candidate, or more than one inconsistent
   evidence set also refuses; no partial match or first-match selection.
7. **Verify the association, separately.** Only after anchor authentication
   succeeds may a distinct, future approved association verifier evaluate
   its signature using the authenticated anchor and independently
   authenticated verifier policy. Verify that every required association
   field, purpose and version is covered, then separately compare the
   authenticated tuple to observations. Anchor commitment match does not
   prove association signature validity; a valid association signature
   does not prove its anchor is expected.
8. **Report results separately.** Report raw commitment comparison (if
   useful, diagnostic and non-authoritative), independently authenticated
   expected-anchor status, association authenticity, tuple equality and
   currentness as distinct findings. If expected-anchor authentication is
   refused or unavailable, association authenticity and equality that depend
   on that anchor are also refused or unavailable. No result or combination
   grants permission to start, load a signer, participate, sign, restore,
   recover or restart.
9. **Protect check/use consistency.** Future code must ensure the bytes and
   policy that passed the commitment comparison are the same immutable
   values consumed by association verification and any separately authorized
   later check. If inputs can change between check and use, the verifier must
   snapshot/retain the checked values or refuse on detected change. Reopening
   a mutable path, re-resolving a locator, or rereading configuration after
   successful validation without revalidation creates a substitution race.
   If a compromised host can change both evidence and verifier state, this
   property is not established by this specification.
10. **Treat currentness separately.** An authentic commitment may be an
    authentic old commitment. Without separately authenticated currentness
    evidence and policy, report currentness unresolved, not current, stale,
    revoked or eligible. If required currentness evidence is missing,
    conflicting or unavailable, refuse any current/eligible conclusion
    rather than silently accepting cached state.

### Substitution, reuse and representation boundaries

The commitment must name or commit to the **complete anchor value and
purpose**, not only a file path, display name, short fingerprint, certificate
subject, or a key identifier that can resolve differently. The verification
policy must check the complete public key and declared suite, not a prefix
that permits same-prefix replacement. A key digest without its authenticated
deployment binding may be replayed or reused across deployments using the
same anchor. A deployment label without independent semantics may likewise
be copied. Candidate B detects neither error unless the verifier checks the
complete expected commitment and each independently expected scope value.

Multiple valid commitments are not automatically a quorum. Conflicting
authenticated statements, ambiguity about which authority is entitled to
issue, duplicate anchor records, or competing channel results refuse pending
an approved conflict-resolution/currentness rule. Availability pressure
cannot turn "choose one" into authorization.

Changes between checking and use include replacement of a path target,
symlink/namespace swap, mutable buffer, file rewrite, config reload, changed
environment, changed destination identity, changed expected-context source,
or policy update. Holding an advisory lock or canonical path is not by itself
proof that all inputs are immutable or that no other writer can replace
them. The existing destination lock is advisory, and a canonical path is a
path identity, not a filesystem-incarnation identity. Any future
implementation-specific race defense requires its own review and evidence.

## 6. Trust review obligations of the commitment channel

Commitment-channel security is a separate review obligation from the
association signature. A post-quantum association signature cannot secure
the message that tells the verifier which anchor is expected, the channel's
authentication credentials, its administration, delivery endpoint, issuer
delegation, or recipient binding.

The independent review must inventory and evaluate, at minimum:

* cryptographic authentication of commitment statements and any channel
  transport, including the actual algorithms, parameters, key custody,
  credential issuance, domain separation, delegation, verification policy,
  revocation and parser behavior;
* cryptographic hash assumptions for the commitment, including collision
  and second-preimage resistance for the selected output size and expected
  classical and quantum attacker models;
* initial authentication/enrollment of commitment authority credentials,
  and how root rotation, compromise and recovery avoid circular
  authorization;
* account, identity-provider, organization-owner, cloud/KMS/HSM, device,
  deployment-pipeline, registrar/DNS, repository, backup, help-desk and
  break-glass administration shared with the anchor channel;
* human approval, identification, transcription, delivery, receipt and
  escalation procedures, including ambiguous names, coercion, conflicting
  messages, loss of a device and compromised contact details;
* endpoint/recipient/deployment binding, replay and downgrade handling,
  channel availability, censorship, delayed delivery, audit provenance and
  behavior during partial outages;
* how a verifier rejects missing, stale, malformed, conflicting or
  unavailable commitment evidence without fallback, while distinguishing
  "not obtained" from an authenticated negative/revocation result.

### Classical and non-cryptographic assumptions

The channel has no post-quantum guarantee merely because the association
signature later uses a PQ scheme. If an eventual channel relies on ordinary
WebPKI/TLS, RSA, ECDSA, EdDSA, classical KEM/key exchange, SSH host keys,
classical code signing, or classical hardware-attestation credentials, those
are classical assumptions at that boundary unless a separate review
establishes otherwise. A classical channel may protect against a specified
present-day adversary under its assumptions, but it is not silently described
as post-quantum.

Even a future PQ message signature would not remove human authority,
credential issuance, signer custody, endpoint compromise, account recovery,
administrative collusion, provider control, availability, audit integrity,
or verifier-host assumptions. A hash is not an authenticated sender. An
authenticated session does not automatically prove the correct founder
approved the statement. A commitment signature proves control of an
authorized signing credential under the assumed policy; it does not prove
that administrators or approvers were independent or honest.

No algorithm, hash, TLS profile, certificate hierarchy, hardware platform,
human process, audit system or threat-model threshold is approved by this
specification. Any future selection requires a separate cryptographic and
operational trust review with explicit classical/PQ boundaries.

## 7. Required refusals

Proposed future behavior is fail-closed at the claim being established.
Refusal means no accepted expected-anchor commitment, no verified
association/equality result dependent on it, and no current/eligible
conclusion. It does not claim that existing production code currently
enforces these outcomes.

| Condition | Required proposed outcome |
|---|---|
| Commitment absent, inaccessible, unreadable, delayed beyond any separately approved rule, or channel unavailable | Refuse anchor authentication/current-eligibility claim; no unsigned, local-config, anchor-channel or cached fallback. |
| Commitment sender/authenticator missing, unknown, invalid, unauthorized, revoked under trusted applicable evidence, or its enrollment provenance circular | Refuse; a digest comparison alone cannot repair missing sender authentication. |
| Commitment and anchor channels share an unreviewed account, key, administrator, identity provider, recovery root or publishing pipeline, or available evidence is insufficient to distinguish their failure domains under the approved threat model | Independence is **not established**; expected-anchor authentication is refused or unavailable, and dependent association-authenticity and tuple-equality results are refused or unavailable. A raw digest/byte match may be diagnostic only. |
| Commitment messages conflict, are ambiguous, incomplete, duplicate, malformed, truncated, unsupported or bind different recipients/policies; independence-review evidence is missing, conflicting, insufficient or stale for the claimed scope | Refuse or mark unavailable the expected-anchor result and all dependent association-authenticity/equality results; do not choose by arrival order, local majority, filename, timestamp or operator convenience. |
| Full anchor bytes or suite differ from the independently authenticated commitment | Refuse expected-anchor authentication, even if an association verifies under the delivered anchor. |
| Anchor key matches but purpose, policy, environment, numeric chain, genesis, destination, validator scope or recipient differs | Refuse deployment binding; no key-only match or label-only fallback. |
| Association or commitment representation admits multiple interpretations, duplicate fields, unknown critical values, omitted signed/committed values or downgrade | Refuse before accepting an anchor or association; do not guess a parser or compatibility behavior. |
| Inputs, deployment context or policy change between check and use and equality of checked/used values is not established | Refuse/revalidate; do not use a value that was not covered by the accepted check. |
| Authentic older commitment/association is replayed, and currentness evidence is absent, unavailable or conflicting | Authentication of old bytes may be reportable, but currentness remains unresolved; refuse current/eligible status. If separately trusted evidence proves supersession or revocation, refuse current/eligible status. |
| Verifier host is fully compromised | No successful result is trusted on the basis of Candidate B alone; host integrity/enforcement is outside this commitment construction. |
| A validator key, bundle-signing key, local operator or newly delivered anchor attempts to authorize or authenticate its own expected commitment without separate authority | Refuse circular or out-of-role authorization. |

No availability fallback, "first record wins", self-signed anchor, selected
local fingerprint, path-based trust, compatibility downgrade or automatic
repair is specified.

## 8. Claims intentionally left open

Candidate B addresses one narrow substitution question: whether the full
delivered anchor and its bound deployment scope match a separately
authenticated expected commitment. It does **not** solve:

* **Currentness / anti-rollback:** a valid old commitment or association
  remains valid evidence of a past statement. Candidate B does not prove no
  later commitment, anchor, association or revocation exists; a digest
  sequence, local version, timestamp or cached response is not by itself a
  trusted view of the latest authority.
* **Anchor replacement / revocation:** B does not define transition authority,
  predecessor links, cutover, overlap, revocation scope/propagation,
  partial rollout, conflict resolution or response to lost/compromised
  commitment credentials. Signing a new digest with an old or new key does
  not independently authorize the transition or establish its currentness.
* **Signer exclusivity:** binding an expected public key does not prove who
  holds its private key, whether it is copied, whether another host can use
  it, whether hardware enforces non-exportability, or whether the later
  loaded signer is that key.
* **Complete signing history:** neither a commitment nor an association
  records every prior validator signature or proves anti-equivocation state
  is complete and rollback-resistant.
* **Durable intent:** B says nothing about write-ahead intent, effect
  ordering, uncertain publication, power-loss durability, or durable
  recording of signing decisions.
* **Fencing and concurrency:** channel separation and a local comparison do
  not fence concurrent/restarted processes, non-cooperating writers, other
  hosts, storage snapshots, or a second signer.
* **Recovery:** B does not authorize restoring missing/corrupt state,
  replacing a lost key, re-enrolling a host, resolving conflicting
  generations, recovering a validator lock, or declaring prior history
  complete.
* **Runtime enforcement or permission:** successful commitment, signature
  authenticity or tuple equality grants no startup, signer-loading,
  participation, signing, recovery or restart authority.

These boundaries match the reviewed
[signing-state continuity contract][continuity], which leaves a durable
anti-rollback anchor unresolved and distinguishes authority freshness from
signing/consensus-state continuity. A valid old commitment can be
superseded; absent a separate currentness mechanism and trust assumption, the
verifier does not know whether it has been.

## 9. Future evidence plan

**Every new control below is FUTURE / NOT EXECUTED.** The controls are
proposals only and require separate authorization before implementation or
execution. They select no key, algorithm, message format, channel, platform,
operational identity, or live environment.

### Synthetic fixture controls — FUTURE / NOT EXECUTED

Use disposable generated keys or opaque fixture values and explicit,
independent harness inputs for the expected commitment, commitment-channel
authentication policy, expected deployment domain, anchor/deployment
evidence and association. Do not include an operational key, live signer,
real service credential, production startup hook or authority-bearing
callback. Synthetic labels that say "independent" model an assumption; they
do not prove real independence.

| Proposed control | Required observable result and sensitivity |
|---|---|
| Positive control: properly authenticated synthetic commitment covers full expected anchor and deployment scope; a separately fixed synthetic input attests that the scoped independence review passed; separately delivered anchor matches; association test fixture is valid. | Report raw match only as diagnostic, then independently report expected-anchor authentication, association authenticity and tuple equality. Currentness remains unresolved without separately approved synthetic currentness evidence. No permission/capability result exists. The fixture models, but cannot prove, real channel or administrative independence. |
| Anchor-channel substitution: keep independently authenticated commitment fixed; alter one byte of full anchor, suite, purpose or bound scope; use an attacker key with a valid synthetic association signature. | Anchor comparison refuses despite signature validity under substituted key. A test-only bypass of commitment comparison must make this negative control fail; positive control prevents reject-all passing. |
| Commitment-channel substitution: keep anchor delivery fixed; alter commitment or authenticated deployment binding; test bad/untrusted authenticator, unauthorized issuer and statement alteration. | Refuse commitment authentication or scope. Bypassing sender authentication or binding must break the negative assertion. |
| Same-credential/common-administrator control | Model both channels as authenticated by one credential, one account or one administrator; demonstrate that changing both inputs can produce an internally matching raw byte/digest result, but independence is **not established** under the fixture's stated threat model. The expected-anchor result and dependent association authenticity/equality must be refused or unavailable; any raw match is diagnostic only. A positive fixture with the separately trusted independence-review input must pass, and a same-checker bypass of the independence gate must make this negative assertion fail. The fixture models this boundary; it does not prove real administrative independence. |
| Missing/conflicting/insufficient independence evidence | Hold a positive raw commitment match, anchor, association and observations fixed; remove, conflict, stale, or make insufficient the independence-review evidence or its trusted scope binding. | Refuse or mark unavailable expected-anchor authentication and dependent association authenticity/equality; preserve raw match as diagnostic only and keep currentness distinct. A same-checker bypass of the independence gate must make the negative assertion fail; the positive fixture must still pass. Do not treat a software flag or fixture label as operational proof. |
| One-channel compromise matrix | Independently inject substitution, replay, delay, omission, conflict and denial on commitment channel only, then anchor/deployment channel only; hold the other synthetic source and verifier policy fixed. Alteration must not produce accepted false anchor; unavailability causes refusal. Separate controls must show joint compromise is outside the guarantee. |
| Wrong deployment / cross-deployment reuse | Reuse the same synthetic anchor or commitment in another environment, numeric chain, full genesis, destination, recipient or approved validator scope; vary one field at a time, including a signed/committed foreign tuple matching its observations. | Refuse the independently expected-domain check. Per-field same-checker omission/bypass must make the negative assertion fail. |
| Ambiguous representation and downgrade | Exercise duplicate/conflicting fields, alternate encodings, concatenation-boundary ambiguity, unknown critical values, unsupported versions/suites, omitted purpose/scope, attacker-selected method and permissive fallback. | Refuse before trust; mutating the parser/policy to accept the ambiguous or downgraded case must break the negative control. No encoding or method is chosen by this plan. |
| Conflicting/missing evidence | Remove each statement, authenticator, anchor, deployment field or expected context independently; supply two inconsistent authenticated statements or ambiguous sources. | Correct refusal stage is observable; no verifier success, fallback, first/last-match selection or equality result. |
| TOCTOU/change-between-check-and-use | Mutate a fixture path, underlying object, buffer, context or policy after the commitment check and before association verification. | Demonstrate verifier consumes the exact checked immutable value or detects/rejects the change. A control bypassing snapshot/equality must invalidate the negative assertion. Harness behavior does not prove filesystem or production race resistance. |
| Authentic old commitment/association replay | Supply a historically valid, matching old fixture while evaluator receives no trustworthy currentness evidence; separately supply a newer fixture only to test harness bookkeeping, not as evaluator knowledge. | Authenticity/equality may be reported; currentness is `Unresolved`, not stale/current/eligible. Only a separate, independently approved synthetic currentness contract could support a current/not-current result. Signed sequence or valid signature alone must not pass freshness. |
| Joint compromise / malicious authority boundary | Let both synthetic channels or their common root authorize a substituted anchor. | Document as outside Candidate B's one-channel guarantee; no claim that cryptography distinguishes intended owner from the authority whose trust was compromised. |

For each negative, retain a positive control and an appropriately narrow
same-checker sensitivity mutation. A mutant that skips that control must
cause the associated negative assertion to fail. Do not replace individual
binding/sender/context controls with a generic signature-failure test.
Simulated account compromise, administrator overlap, network outage,
provider independence and human provenance are conceptual model evidence
only; they are not demonstrated real-world independence.

### Evidence requiring real provisioning and operations — FUTURE / NOT EXECUTED

No synthetic fixture can demonstrate that real commitment and anchor
channels have independent owners, credentials, administrators, recovery,
infrastructure or honest human approvals. Before any future Candidate B
claim, separately authorized work would need:

* a documented, independently reviewed trust and administration map for
  both channels, authorities, credentials, enrollment, recovery and common
  failure domains;
* verifiable real evidence of credential custody, issuance and delegated
  authority; actual recipient/deployment binding; separate approvals and
  receipt records; protected audit provenance; and a reviewed initial
  authentication path for the commitment channel;
* a threat-model-specific adversarial exercise in which authorized reviewers
  control one real channel at a time using non-operational/disposable
  material, demonstrate refusal on substitution and unavailability, and
  record what shared control plane still remains; no operational private key
  or public DevNet use is required or permitted by this document;
* independent cryptographic and channel review for the chosen statement
  authentication, hash, transport, enrollment, replay, downgrade and
  recipient-binding properties, explicitly marking classical and PQ
  assumptions;
* if a platform, storage or runtime check is later proposed, separate
  platform/custody and implementation reviews, actual failure/race/rollback
  evidence at the selected backend, and configured-runtime protected-effect
  tests. Synthetic callbacks or a successful helper test do not prove
  production enforcement, startup order, signer loading order, durability
  or host integrity;
* distinct independently authenticated currentness/revocation evidence
  before claiming an anchor/association is latest, eligible or not revoked.

All such work is outside this specification's authorization. Evidence from
the earlier synthetic association tests remains historical and scoped to
their documented checker behavior. This document runs no tests and makes no
operational observation.

## 10. Owner decisions before any implementation entry

At minimum, owners and independent reviewers must resolve:

1. Which authority approves the commitment and deployment binding; what
   delegation/threshold applies; how does that approval remain separate
   from validator and bundle-signing authority?
2. What actual commitment channel authenticates sender, authority, recipient
   and deployment? How is its initial trust root independently provisioned
   and recovered without circularity?
3. What exact authority, credential, account, administrator, infrastructure,
   recovery and audit dependencies are shared with the anchor/deployment
   channel, and which residual common failures are accepted?
4. What information and scope does the commitment cover, including complete
   anchor, suite, purpose, deployment and policy; which validator-association
   restrictions must it bind?
5. What unambiguous bounded representation, digest/signature/transport
   algorithms, key lifecycle and downgrade policy are approved, with what
   classical/PQ assumptions at each trust boundary?
6. What authenticated source establishes expected deployment context, and
   how are external/embedded genesis, numeric chain, destination incarnation
   and recipient represented? The existing source does not answer all these
   questions.
7. How do authenticated conflicting messages, missing evidence, replay,
   stale statements, outage, partial replacement, revocation and suspected
   credential compromise affect refusal and operations?
8. What separate trusted mechanism, authority, and failure policy establish
   currentness/anti-rollback? Candidate B's commitment itself cannot answer
   whether a newer valid commitment exists.
9. What separate evidence is required for signer exclusivity, complete
   signing history, durable intent, fencing, recovery and runtime ordering?
10. Which independent reviewers accept the channel, threat model, synthetic
    sensitivity evidence, real provisioning evidence and any later runtime
    evidence? What exact limitations must accompany each claim?

Until these are decided and independently evidenced, Candidate B remains a
direction for specification only. No absence of known failure is proof of
channel independence.

## 11. Pinned references and source limitations

The reviewed assessment is pinned at commit
`12fbfbe77609afc659f55ee1fb41fd066cf00910`, tree
`0144ad760655a7f8d36a8a3cb43adff1680f1a25`. The source and merged documents
below pin to main commit `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree
`f1a7d40993bfefbe18635bd637a100ad5527d875`. Historical evidence-source
commits are explicit and are not represented as the current main tree.

* [Reviewed Candidate B assessment][assessment]
* [Merged separate-bootstrap-anchor specification/test plan][merged-spec]
* [Merged synthetic test evidence][synthetic]
* [Merged synthetic coverage correction][correction]
* [Genesis canonical hash and authority-block encoding][genesis-hash]
* [Boot-time genesis verification boundary][boot-genesis]
* [Destination path identity][destination-id]
* [Signing-state continuity contract and unresolved anti-rollback][continuity]
* [Pinned audit-register A23-F1 and A33-F1 / E27 dispositions][audit-register]
* Historical synthetic source revision `3cf05468bd753d279433904eeaa0cbdc73550706`, tree `33157f8936410775657d85932498231fa5414a87`
* Historical corrected synthetic source revision `b841fa4e8fb5718b5f74d60363d7d1ad8e50cea5`, tree `398f4b8648748e7769482ed94d98f4374e089653`

The genesis hash helper produces a hash of the parsed genesis representation;
that hash does not authenticate the provenance of an expected hash or its
delivery. The boot verifier consumes a configured expected value; local
configuration is not thereby an independent commitment channel. Destination
canonicalization reports a canonical absolute path; it does not establish
filesystem incarnation or resistance to changes between checking and use.
These source boundaries are not evidence that Candidate B has been wired.

The audit register retains A23-F1's K!=T ratified-target/bundle-signer gap
and its independent-genesis-provenance qualifications; A33-F1 / E27 retains
its separate operator-crafted-anchor/admitted-catch-up and ancestry/runtime
scope. Neither is closed or addressed by this specification. The
signing-state continuity contract states durable anti-rollback is not
established. Those findings and their earlier accepted limitations are
preserved.

This is a documentation-only specification, not a security audit,
independent cryptographic review, channel-independence attestation, executed
test report, operational provisioning record, runtime verification, or
readiness decision. No tests were run, no operational keys used, and no node
started. Only this document is added. No PR is created; the pushed branch is
for independent review.

[assessment]: https://github.com/olivexo28/QBIND/blob/12fbfbe77609afc659f55ee1fb41fd066cf00910/docs/security/evidence/a33-f1-bootstrap-anchor-delivery-lifecycle-assessment-20261108.md
[merged-spec]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-separate-bootstrap-anchor-spec-test-plan-20261108.md
[synthetic]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-evidence-20261108.md
[correction]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/evidence/a33-f1-separate-bootstrap-anchor-synthetic-coverage-correction-20261108.md
[genesis-hash]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-ledger/src/genesis.rs#L1555-L1672
[boot-genesis]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/pqc_boot_genesis.rs#L215-L245
[destination-id]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/crates/qbind-node/src/restore_completion.rs#L148-L179
[continuity]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md#L13-L45
[audit-register]: https://github.com/olivexo28/QBIND/blob/aa382fa28b2d3e97e6203d47fa8231b5f2269741/docs/security/QBIND_AUDIT_REMEDIATION_PLAN.md#L220-L226
