# Common-credential-root credential presentations

`common_credential_root_v1` enables holders to present selected claims from two
credentials issued under different relationship identifiers and prove that
both share a ReallyMe-assured private root. The presentation uses one private
or public persona without disclosing the root or either issuance identifier.

This proof family is optional. Ordinary persona presentations do not
require common-credential-root assurance.

## The relationships

```text
ReallyMe assurance ────────> private root R
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
             university context            employer context
                    │                           │
             lineage value U               lineage value E
                    │                           │
             degree credential         employment credential
                    │                           │
             hidden subject U           hidden subject E
                    └──────────┬────────────────┘
                               ▼
                    presenting persona P
                               │
                               ▼
                     verifier's request
```

Each issuer signs its own credential facts, subject binding, and
relationship-specific lineage claim. Each credential subject authorizes the
presenting persona. The persona signs the verifier's fresh request. The
common-credential-root proof relates the two signed lineage claims to one hidden root.
These are separate assertions by separate parties.

## Enrollment and issuance

The wallet generates a random 32-byte root `R`. ReallyMe signs a **Root
Assurance Attestation** for a commitment to `R`, a named assurance policy, and
a validity window. ReallyMe does not receive `R`. The attestation is private
proof material, not a public DID or a credential issuer's subject identifier.

ReallyMe publishes signed snapshots of active attestation instances. A
root-attestation status proof shows that the exact signed attestation is in
the verifier's trusted active set. The verifier checks the snapshot's
signature, freshness, and validity window outside the circuit. This status
concerns the ReallyMe attestation; it says nothing about revocation of either
presented credential.

For each issuance relationship, the wallet derives a distinct lineage value
from `R` and a context containing the issuer key, relationship DID, subject
key, and fresh nonce. It rejects reused contexts. The issuer signs the lineage
value as a reserved claim in the exact credential. The wallet verifies that
claim against its own derivation before accepting the credential. The
lineage value is neither a signing key nor a substitute for the credential's
normal holder binding. A wallet cannot add lineage to an older credential
after issuance.

The [proof contract](common-credential-root-v1-proof-contract.md) defines the derivation,
claim commitment transcript, reserved leaf, attestation identity, and issuer
binding rules.

## Presentation

The holder selects one claim from each credential. The proof set contains:

| Proof | Count | Purpose |
| --- | ---: | --- |
| Root attestation | 1 | Prove the ReallyMe attestation for the hidden root and assurance policy. |
| Root-attestation status | 1 | Prove membership of that exact attestation in the active set. |
| Issuer credential status | 2 | Prove the current issuer-signed status for each selected credential. |
| Lineage | 2 | Relate each signed credential's lineage claim to the same root. |
| Selected claim | 2 | Present one issuer-bound claim and subject authorization per credential. |
| Persona session | 1 | Prove control of the presenting persona for this request. |

A fresh private salt binds the proof joins to this presentation.
The verifier checks all nine proofs, joins the corresponding root,
attestation, subject, credential, and persona bindings, and compares every
proof with the active request. It also checks trusted issuers, the accepted
assurance policy, presentation expiry, the signed attestation snapshot, and
both issuers' signed status lists under its configured freshness and rollback
policy. Each credential's issuer-signed validity interval covers the session.
The [proof contract](common-credential-root-v1-proof-contract.md#verifier-acceptance-rule)
defines the ordered public inputs and complete acceptance rule.

The wallet can prepare credential lineage material at issuance. Completed proofs
must be generated for the current request and cannot be reused for another
verifier session. The proof joins do not introduce a stable
identifier that can be reused to link presentations.

## What the result means

Verified persona bundles establish that each credential's hidden subject
authorized the presenting persona. When the verifier also checks their shared
persona and session bindings, it can establish that they use one persona for
the session. With `common_credential_root_v1`, it additionally learns that the
two exact issuer-authenticated credentials carry lineage values derived from
one ReallyMe-assured private root.

The assurance policy defines what ReallyMe established at enrollment.
Common-credential-root provenance does not independently prove that both
issuers issued their credentials to the same person. The verifier still applies
issuer trust and credential policy. The two issuer credential status proofs
establish validity and an unset revocation or suspension bit for the exact
presented credentials under the verifier's authenticated status lists. The
root-attestation status proof addresses ReallyMe assurance separately.
Ordinary persona bundles have their own, narrower credential policy.

## Privacy boundaries

Different issuer contexts and fresh nonces keep lineage values from acting
as a shared public identifier. Presentations do not expose the root, its
commitment, the lineage values, issuance DIDs, or hidden subject keys. A
public persona key is intentionally reusable; a private persona key stays
hidden from the ordinary verifier.

Disclosed claims, network metadata, or facts known to issuers can still
correlate relationships. Issuers should publish status lists shared by many
credentials: the list identity and URL hash are public proof inputs, even
though each credential's status index remains hidden. The
[credential and persona guide](persona-credential-privacy.md) describes
those limits and the separate cross-bundle persona rule.

## Protocol ownership

SSI and Identity construct and sign the ZK credential profile. OpenID4VCI
transports the issued credential. OpenID4VP binds proof bundles to the active
request. `did:me` supplies relationship identifiers and key lifecycle.
The [proof contract](common-credential-root-v1-proof-contract.md) defines the circuit
rules and verifier acceptance.
