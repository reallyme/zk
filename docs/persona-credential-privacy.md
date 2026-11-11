# Credential claims and personas

ReallyMe ZK supports **data minimization**, which limits the credential claims
a verifier sees, and **relationship minimization**, which limits the
connections a verifier can make between issuers, subjects, holders, and personas.
A hidden claim alone does not prevent correlation if issuance and
presentation expose the same subject identifier.

Each baseline bundle proves one selected claim from one credential and binds
it to the active verifier request. Persona proofs
also prove that the credential's hidden subject authorized the presenting
persona. Common-credential-root proofs additionally establish that two exact
credentials carry issuer-authenticated lineage from one ReallyMe-assured
private root. Production use requires the
[toolchain and composition checks](noir-production-security-profile.md).

## Circuit families

| Circuit family | Verified result | Visibility |
| --- | --- | --- |
| `credential_subject_claim_v1` | Issuer-bound selected claim from a hidden credential subject. | Claim and issuer key are public. |
| `private_persona_claim_v1` | Subject authorization and session control for a hidden persona. | Persona key stays hidden. |
| `common_credential_root_v1` | Two issuer-bound selected claims, one persona session, and common assured-root provenance. | Root, lineage values, and issuance subjects stay hidden. |
| `persona_credential_evidence_v1` source stages | Four credential-evidence proofs and a refreshable current-state proof joined to a holder key; the live signature is checked separately. | Public mode exposes a reusable persona key; private mode exposes a one-time key authorized by the hidden persona. |

A public persona key is verified as a public input. It is not just display
metadata attached to a private proof. The verifier also applies issuer trust
and claim policy.

Persona credential evidence separates three checks. Four proofs establish the
issuer envelope, claim root, issuer-signed validity, and selected claim with
persona authorization. A fifth, refreshable proof establishes hidden-index
membership in the current status snapshot. The holder signs the active request
under the key exposed by the selected-claim proof. All five proofs share a
token-specific credential binding and a half-open proof window contained in
the issuer's validity interval.

The verifier matches the presentation to its
authenticated request, verifies all five exact source proofs against pinned
keys and an independently authenticated current status feed tied to the
credential issuer's identity, checks the live holder signature, then consumes
the request nonce through a durable replay store.

The wallet durably reserves private tokens before disclosing their proofs or
one-time keys. The
wallet selects an available token for the authenticated request's claim from
protected inventory, then rechecks that claim inside the reservation
transaction. A request for another claim leaves the token available. The
public prepared proof can be presented repeatedly within its proof window;
each presentation still requires an authenticated current status feed, a new
request signature, and a fresh verifier nonce. If the issuer's current status
root changes, the cached current-state proof must be regenerated against that
root before another presentation can pass. The private proof is durably spent
before disclosure. A conforming wallet must prevent its one-time key from
signing another presentation and retire that key from protected storage when
safe. The
[circuit contract](../circuits/sha256/families/persona_credential_evidence_v1/README.md)
specifies the source stages and joins.
The status authority maps the proof-verified issuer key to its SSI issuer
identity and supplies the signed current list at a monotonic status floor;
the proof's list locator selects that list without supplying its root.

## Correlation boundaries

| Boundary | Intended separation | Limit |
| --- | --- | --- |
| Issuer ↔ issuer | Different subject keys and relationship identifiers. | ZK cannot erase identifiers or records already shared at issuance. |
| Verifier ↔ verifier | Different private presentation personas avoid a common public holder key. | Reuse of a public persona, disclosed claims, and application data can correlate. |
| Issuer ↔ verifier | An issuance subject key need not be disclosed at presentation. | A party that knows a credential envelope hash may test presentation bindings. |

Identity, Wallet, and issuance flows must establish separate keys and
identifiers before proving. Network metadata and other records remain
outside the proof contract.

## Credential and session binding

A selected-claim proof discloses the claim name hash and value and proves
membership in an issuer-bound, salted Merkle commitment. A request-bound
four-stage bundle contains `session`, `credential_envelope`, `credential_root`,
and `claim`. A verifier checks every stage, their shared public bindings,
the active nonce, audience, transaction-data hash, and presentation expiry.
One valid stage is not a presentation.

The `claim_bundle_4` source circuit is experimental. A credential can hold
several claims, but a baseline production bundle presents one claim at a
time. The current claim circuit can prove membership of an issuer-signed
`over_18` value. Deriving age from a hidden birthdate requires a separate
predicate circuit.

### Several bundles in one presentation

The verifier authenticates every bundle and applies issuer policy to every
claim. To treat several bundles as one persona presentation, it must compare
the verified persona and session commitments with a compatible bundle kind,
hash lane, transaction binding, and expiry. All bundles must match the same
active challenge and audience. Each credential's actual subject
independently authorizes that persona; the persona controller proves
control for the session.

To establish that several claims came from one credential,
the verifier compares their issuer, envelope, and Merkle-root bindings.
A shared persona binding alone is insufficient. Equal credential bindings
identify the same committed credential context in that request, not a
globally unique credential ID or a unique claim name within the root.

**Adapter limit:** The OpenID4VP verifier authenticates individual
bundles but does not enforce the cross-bundle persona rule. Its typed
verified-claim comparison supports compatible proofs; Identity must enforce
that comparison across the selected claims before concluding that they use
one persona. Unequal session-link commitments are inconclusive when bundle kind,
lane, transaction binding, or expiry differs. The
[OpenID4VP presentation binding contract](openid4vp-presentation-binding.md)
defines the active-request mapping.

## Authorization and privacy limits

The direct and private-persona claim bundles keep the subject key, credential
envelope hash, and claim root out of the verifier's public inputs. The
private-persona bundle also hides its persona key. Disclosed claims, issuer keys,
and surrounding data may still identify or correlate the holder.

A credential subject signs authorization for a persona public key. The
subject need not know that persona's private key; its controller need not
be the credential subject. Several subjects can authorize the same
persona, including for delegation, a household, a team, or an entity.
A verifier can conclude that the persona was authorized to present each
verified credential. It cannot conclude that one natural person received
all of them.

Subject-to-persona authorization remains valid across presentations. The
circuit does not restrict it to an issuer, credential, session, revocation
state, or expiration time. An issuer or party with a known envelope hash can
correlate private presentations; a party with the hidden persona key can
also test session bindings. These proofs do not guarantee unlinkability
against those parties.

Prepared private tokens use a different one-time holder key and nonce for each
disclosure. The current-state proof still exposes its status-list identity and
root. A per-credential status list would link the tokens, so private-token
presentations require an issuer status feed shared across credentials.

The four request-bound claim proofs establish an issuer signature over the
credential envelope and claim root, but do not establish the issuer-signed
validity interval or current revocation state. Presentation `expiry_unix` is
chosen by the presenter. A direct or private request-bound presentation must
also include the issuer-credential-status proof. The verifier joins its
issuer-signed validity and hidden status index to the same request-scoped
credential binding, verifies active membership against an independently
authenticated current issuer feed, and rejects a missing or stale status
proof. The four claim proofs alone do not establish credential validity or status.
The v1 credential binds one status pointer with one declared purpose, such as
revocation or suspension. A verifier whose policy requires multiple independent
issuer feeds must reject a presentation that supplies only this proof.
`prove_status_qualified_claim_proof_bundle_with` constructs the five-proof package from
typed claim and status witnesses. `verify_status_qualified_claim_proof_bundle_with` is the
credential-acceptance boundary; the four-stage `verify_presentation_bound_claim_bundle_with` result is
claim evidence only. The same fifth source circuit is shared with each
issuer-credential-status slot in common-credential-root presentations.
The `common_credential_root_v1` presentation adds separate proofs for the ReallyMe
attestation's active status and for each issuer credential's signed validity
and current revocation or suspension state. The
[common-credential-root guide](common-credential-root-persona-presentations.md) explains those
distinct assurance statements.

## Ownership and contracts

OpenID4VP binds and verifies bundles for the active request. Wallet owns
credential state and consent. Identity chooses the issuance credential and
presenting persona in its application-facing API. All three use
`reallyme-zk-api`; circuit semantics remain in this repository.

- [Credential subject claim family](../circuits/sha256/families/credential_subject_claim_v1/README.md)
- [Private persona family](../circuits/sha256/families/private_persona_claim_v1/README.md)
- [Persona credential evidence family](../circuits/sha256/families/persona_credential_evidence_v1/README.md)
- [Common-credential-root proof contract](common-credential-root-v1-proof-contract.md)
- [Production bundle contract](../crates/api/src/bundle.rs)

The Poseidon2 circuits use the same families and presentation modes. Hash choice does
not change these authorization guarantees.
