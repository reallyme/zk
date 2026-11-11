# Common credential root v1 proof contract

The optional `common_credential_root_v1` family links selected claims from two credentials to one
presenting persona and the same ReallyMe-assured private root. The proofs
verify each credential's issuer-authenticated lineage and its hidden subject's
authorization of the persona. Separate circuits handle the root, active-status
path, lineage opening, and selected claim to limit mobile proving memory.

Each lineage and selected-claim circuit handles one credential. The wallet
proves these stages sequentially and releases each stage's witness and
backend state before the next. Circuit size therefore does not grow with the
number of credential slots. Peak process memory also depends on when the
platform backend releases its resources.

The proof suite is Barretenberg UltraHonk with the Keccak ZK verifier target
(`evm` in Barretenberg 6.0.0). SHA-256 and Poseidon2 are separate credential
hash lanes. Root assurance, HKDF-SHA-256, the SSI issuer-signature
transcripts, the status trees, and the salted root, subject, and attestation
joins use SHA-256 in both lanes. The selected lane hashes the claim tree, the
request-scoped credential binding (`CREDB1`), the persona session binding
(`PSESB1` or `PSESB2`), and the digests signed by the persona key (`PERS1`)
and by the subject key for the persona link (`LINK1`). A persona or subject
key used in the Poseidon2 lane therefore signs a Poseidon2 digest, and those
signatures are specific to that lane. A verifier never substitutes an
artifact or verification key from one lane for the other. The root
attestation and root status circuits have identical source in both lanes, so
that separation is enforced for them by artifact selection, not by the
circuits.
The fixed synthetic HKDF inputs and outputs are in
[`vectors/common-credential-root-v1-derivation.tsv`](../vectors/common-credential-root-v1-derivation.tsv).
The ZK claim transcript, reserved lineage leaf, selected leaf, and two-leaf
Merkle root have fixed synthetic vectors for
[SHA-256](../vectors/common-credential-root-v1-sha-commitments.tsv) and
[Poseidon2](../vectors/common-credential-root-v1-poseidon2-commitments.tsv).

Credential claim openings use the ZK commitment profile: the `CLM1`,
`LEAF1`, and `NODE1` domain transcripts and the selected SHA-256 or Poseidon2
hash lane. SSI's generic `RMCLM1`/`RMLEAF1`/`RMNODE1` claim commitment has a
different byte transcript; its openings cannot be substituted for this
profile's openings.

The issuer's `BINDMRK1` and `BINDSUB1` signatures use the same
`envelope_hash`. Issuance computes that hash from the canonical signed SSI
credential envelope containing the subject and claims commitment. The wallet
recomputes it from the received envelope before accepting either binding.
An arbitrary holder-supplied 32-byte envelope hash is not a valid credential
reference. Binding both signatures to the same envelope prevents a claim root
and subject from separate issuances being combined under a reused hash.

## Issuer-authenticated claim tree

For credential tree operations, `H_lane` means SHA-256 in the SHA-256 lane
and the bounded Poseidon2 byte hash in the Poseidon2 lane. The 32-byte claim
name hash is SHA-256 of the canonical UTF-8 name in either lane. The reserved
name is exactly `reallyme.lineage.v1`; its leaf has index zero and its value
is `context_hash[32] || lineage_tag[32]`.

```text
inner       = H_lane("CLM1" || u32be(value_length) || value || salt[16])
leaf        = H_lane("LEAF1" || claim_name_hash[32] || inner[32])
parent      = H_lane("NODE1" || left[32] || right[32])
root_bind   = SHA-256("BINDMRK1" || envelope_hash[32] || merkle_root[32])
subject_bind= SHA-256("BINDSUB1" || envelope_hash[32] || subject_x[32]
                       || subject_y[32])
```

The issuer signs `root_bind` and `subject_bind` with its trusted P-256 key.
These SSI issuer-signature transcripts use SHA-256 in both credential hash
lanes; the selected lane controls the claim tree, not the signature digest.
The canonical envelope hash is SHA-256 of the SSI signed-envelope encoding;
the envelope contains the subject and this exact claim commitment. Issuance
builds leaves in explicit order and places lineage first. Every claim tree has
a fixed depth of six. Positions beyond the issued leaves hold the empty
subtree for that level: an empty leaf is 32 zero bytes, and each higher level
is the node over two empty subtrees below it. The lineage and selected-claim
circuits accept only a path of exactly six levels. Issuance accepts two through
64 leaves, including the reserved lineage leaf, and rejects duplicate claim names. A claim
value has one through 64 bytes; every claim has a nonzero 16-byte salt.
Issuer root recomputation and wallet restoration validate the empty subtrees.
The circuits have no authenticated issued-leaf count and do not establish
which leaf positions are padding.
Before signing, the issuer checks each non-lineage leaf against the exact
claim name and value it is issuing. For the reserved lineage slot the wallet
supplies only the salted `CLM1` claim digest; the issuer applies the `LEAF1`
domain and the reserved lineage name hash itself, then recomputes the root.
The issuer therefore constructs every leaf under the root it signs and must
not accept a finished leaf digest from the wallet. The fixed tree depth
enforces the same property inside the circuits: a node placed in a leaf
position would need a path longer than six levels to reach a claim beneath
it, which no circuit accepts. The issuer can authenticate the claims without
learning the private lineage value.
The wallet verifies the signed envelope and both bindings, recomputes the
tree and lineage derivation, and retains the private openings. This
transcript is distinct from SSI's general-purpose claim commitment.

## Issuance transport and wallet material

OpenID4VCI carries one base64url-encoded `ReallyMeZkV1Credential` Buffa
protobuf under `reallyme_zk_v1`. It contains the issuer-signed SSI credential
envelope, signed status evidence, public proof binding, and verified holder
key. The credential request carries a separate versioned Buffa issuance
intent with the proposed claim root, holder key, and commitments to the
wallet's lineage tag and private opening, plus the salted lineage claim
digest from which the issuer derives the lineage leaf and recomputes the
approved claim root. The v1 wire field for that digest is named
`opaque_lineage_leaf`. The credential response
does not carry the private root, lineage tag, claim
values, salts, or Merkle paths. The wallet retains those openings in a
versioned `ZkCommonCredentialRootPreparedClaims` protobuf. It stores that message and
the received OpenID4VCI credential envelope together as
`ZkWalletStoredCredential` inside an authenticated encrypted local record.
On retrieval, it checks the exact credential-envelope bytes, stored claim
root, and issuance binding against the authenticated credential, then
reconstructs every claim path before using an opening as witness material.
The wallet can then generate proofs for new verifier sessions without
reissuing the credential.

## Root attestation and lineage derivation

The wallet generates the private root `R` as 32 random bytes. ReallyMe signs
a Root Assurance Attestation for a commitment to `R`, the assurance-policy
identifier, the versioned transcript, issuance and expiration times, and a
root epoch. ReallyMe receives the commitment, not `R` itself. The presentation
circuit proves knowledge of a root that opens the signed commitment.
The authority returns those signed fields in a canonical
`ZkRootAssuranceAttestation` protobuf. The wallet stores the record encrypted,
checks its root commitment against its private `R`, and verifies the exact
ReallyMe signature and pinned assurance policy before proving. The record's
commitment, signature, and signer are not ordinary presentation fields.

The attestation identifier is SHA-256 of the versioned transcript containing
the ReallyMe verification key, signed attestation digest, and signature.
The active-set leaf hashes that identifier under the `RMSTL2` domain. The
identifier stays private in the root-attestation status proof. Attestation
and status proofs expose only a freshly salted `attestation_join` for the
exact instance. The verifier must validate the signed active-set snapshot and
its freshness independently of circuit verification.
The authority signs the 32-byte active-set root, issuance and expiration
times, and a monotonically increasing sequence number as a P-256 signature
over `SHA-256("RMRSTAT1" || root[32] || issued_u64be || expires_u64be ||
sequence_u64be)`. The verifier pins the authority key, checks the signature,
enforces a deployment-owned sequence floor and maximum age, and rechecks the
signed interval at presentation verification. The snapshot travels in a
versioned `ZkRootStatusSnapshot` protobuf. The verifier accepts its root only
after these checks.
The authority also publishes `ZkRootActiveSetPublication`: one canonical
protobuf containing that signed snapshot and the complete, ascending list of
active 32-byte attestation identifiers. The wallet recomputes the Merkle root
from the list and compares it to the signature-verified snapshot, then derives
its private membership path locally. All holders download the same complete
publication; the feed does not accept an attestation identifier as a query.
The authority derives the set and root from its signed commitment attestations
with `build_root_active_set_from_authority`, signs that root, and passes the
same inventory and signed snapshot to the publication encoder. The encoder
recomputes the set and rejects an inventory that changed after signing.
The single-feed publisher holds an exclusive local lock while selecting the
next sequence and signing, then installs the complete protobuf with an atomic
rename and directory sync before distribution. It first syncs a canonical
unsigned publication intent containing the exact active set, feed, sequence,
and interval. An independent durable anchor commits the matching signing
digest before signing; a restored older valid publication fails the anchor
check. After a crash, the authority signs only an intent whose derived digest
matches that anchor.
The v1 status tree has a fixed depth of 20 and holds at most 1,048,576
active attestation identifiers in one snapshot. The packed identifier list
can reach 32 MiB, plus protobuf framing, at that limit. The wallet checks
this bound before decoding and derives its path from the authenticated set.
For a list with an odd number of entries, absent leaves are padded with the
`RMSTL2` leaf hash of the reserved all-zero identifier. An empty list has that
same leaf as its root and admits no membership proof. The identifiers are
public within the bulk publication, so integrations must keep the holder's
own identifier and path out of request URLs, telemetry, and presentations.
Revoking one attestation does not affect a different attestation for the same
root, and a still-active attestation cannot reactivate a revoked instance.

### Active-set capacity and feed privacy

The v1 circuit admits one active-root status tree per root-attestation status
proof. One tree supports at most 1,048,576 active attestations. Raising
`COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH`, resealing artifacts, or claiming a
larger single-feed capacity requires new circuit, release-package, and mobile
peak-memory tests.

The supported Wallet/Identity integration uses one complete status feed.
Multi-feed wallet operation is unsupported; the
`ZkRootActiveSetPathAssignment` protobuf and codec do not provide wallet
storage or feed selection.

The signed active root is a public input. A verifier that knows the published
feeds can identify the feed and snapshot cohort from that root. Each holder's
status anonymity set is therefore bounded by the active population of that
feed and snapshot. A feed must never expose a per-attestation lookup, and feed
assignment must not be derived from PII, credential contents, or the hidden
attestation identifier.

The v1 attestation identifier does not cryptographically bind a feed. If the
same identifier appears in two trusted feeds and only one removes it, a holder
can still prove against the other active root. Deployments must prevent that
revocation bypass; a larger aggregate feed capacity cannot be inferred from
the low-level proof contract.

For each issuance relationship, the wallet forms a fixed-length context from
the issuer's trusted P-256 verification key, the SHA-256 hash of the canonical
relationship DID, the credential subject's P-256 key, and a fresh 32-byte
relationship nonce. Each curve coordinate uses 32 big-endian bytes. The
lineage value is derived as follows:

```text
context_hash = SHA-256(
    "RMCTX1" ||
    issuer_key_x[32] || issuer_key_y[32] ||
    SHA-256(UTF8(canonical_relationship_did))[32] ||
    subject_key_x[32] || subject_key_y[32] ||
    relationship_nonce[32]
)

ReallyMeLineageV1Salt =
    SHA-256(UTF8("ReallyMe/common-credential-root/v1/HKDF-Extract"))

prk = HKDF-Extract(
    salt = ReallyMeLineageV1Salt,
    input_key_material = R
)
T_i = HKDF-Expand(
    pseudorandom_key = prk,
    info = context_hash,
    length = 32
)
```

The derivation uses [HKDF as specified in RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

The extraction salt is a fixed public domain separator. The wallet uses a
distinct nonce for each relationship, including relationships with the same
issuer, and rejects reused contexts. `T_i` is a lineage value, not a signing
key or replacement for the credential holder-binding key. The wallet checks
its derived lineage leaf against the issuer-signed claim root before
accepting the credential. An older credential without this issuer-authenticated
claim cannot be upgraded by the wallet. The reserved lineage claim remains
internal proof material and cannot be selected for disclosure in ordinary
v1 presentations.

## Nine verified proofs

For exactly two credential slots, the presentation contains:

| Proof | Count | Statement |
| --- | ---: | --- |
| Root attestation | 1 | ReallyMe signed the commitment to the private root under the requested assurance policy and valid time window. |
| Root-attestation status | 1 | That exact signed attestation is in the current active-attestation set. |
| Lineage | 2 | Each issuer-signed credential root contains the canonical lineage leaf derived from the attested private root and that credential's relationship context. |
| Selected claim | 2 | Each exact issuer-bound hidden subject authorizes the same persona and presents the selected claim from that credential. |
| Persona session | 1 | The persona signed the verifier's fresh request. |
| Issuer credential status | 2 | Each issuer signed the exact credential's validity interval and private status pointer; the pointer opens to an unset bit in the verifier's current authenticated status list. |

The selected-claim proof computes `subject_join` from the **same hidden
subject key** used to verify its issuer binding and persona authorization.
The corresponding lineage proof computes that join from the subject key in
the issuer-authenticated lineage context. Equal `CREDB1` values alone do
not prove this subject equality, because `CREDB1` omits the subject key.

The two lineage proofs share a salted `root_join` with the attestation and
status proofs. The attestation and status proofs also share a salted
`attestation_join` for the exact signed attestation instance. Each lineage
and selected-claim pair shares its own salted `subject_join`. Each selected
claim shares `PSESB1` or `PSESB2` with the verified persona-session proof.
These joins are calculated with one fresh, private 32-byte presentation
salt and the active challenge, audience hash, and transaction-data hash.
The verifier receives only the joins, not the salt or hidden keys.
The private active-status membership path has at most 20 levels, supporting
up to 1,048,576 leaves in one signed active-set snapshot.

## Ordered public inputs

Each byte in a public byte array is encoded as a separate canonical BN254
scalar field element in the raw public-input stream. `u64`, `u32`, and `u8`
are one field element each and must be range-checked by the decoder.
Array lengths below are byte counts; the last column gives the raw field
count. Extra or missing fields are invalid.

| Proof | Public inputs in source order | Fields |
| --- | --- | ---: |
| Root attestation | ReallyMe P-256 key X/Y `[32,32]`; policy ID `[32]`; verifier request time `u64`; presentation expiry `u64`; challenge, audience, transaction hash `[32,32,32]`; root join `[32]`; attestation join `[32]` | 258 |
| Root-attestation status | challenge, audience, transaction hash `[32,32,32]`; active status root `[32]`; root join `[32]`; attestation join `[32]` | 192 |
| Each lineage | challenge, audience, transaction hash `[32,32,32]`; root join `[32]`; issuer key X/Y `[32,32]`; expiry `u64`; credential binding `[32]`; subject join `[32]` | 257 |
| Private-persona selected claim | issuer key X/Y `[32,32]`; challenge, audience, transaction hash `[32,32,32]`; expiry `u64`; session binding `[32]`; credential binding `[32]`; subject join `[32]`; value length `u32`; selected value `[64]`; claim-name hash `[32]` | 354 |
| Public-persona selected claim | issuer key X/Y `[32,32]`; persona key X/Y `[32,32]`; remaining inputs in private-persona selected-claim order | 418 |
| Private-persona session | challenge, audience, transaction hash `[32,32,32]`; expiry `u64`; session binding `[32]` | 129 |
| Public-persona session | persona key X/Y `[32,32]`; remaining inputs in private-persona session order | 193 |
| Each issuer credential status | challenge, audience, transaction hash `[32,32,32]`; issuer key X/Y `[32,32]`; presentation expiry `u64`; credential binding `[32]`; status root `[32]`; status length `u64`; list ID `[32]`; URL hash `[32]`; purpose `u8`; status validation time `u64` | 292 |

The selected value's bytes after `value length` are zero padded. The
selected-claim circuit constrains the active length and padding. The
reserved lineage claim name is rejected as a selected disclosure in both
persona modes, so its context hash and derived tag never enter the public
claim value. Credential membership paths have at most six levels, supporting
up to 64 leaves. The reserved lineage leaf occupies slot zero; a lineage
proof for any other leaf index is invalid. Credential issuance rejects a
second leaf with the reserved name. Selected claim values are at
most 64 bytes. The
credential request interprets the claim name, value, issuer role, and
expiry; proof verification by itself is not an authorization decision.

## Verifier acceptance rule

The verifier accepts the common-credential-root result only after it:

1. Checks the circuit ID, hash lane, artifact digest, verification key,
   proof shape, and every proof cryptographically. It decodes public inputs
   with the exact ordered schema and rejects noncanonical or out-of-range
   fields.
2. Compares **every proof's** challenge, audience hash, and
   transaction-data hash to the active verifier request. It checks the
   attestation proof's request time against its own request clock and
   policy, rather than a holder-chosen time. Every selected claim and the
   persona-session proof must have an expiry after that clock and at most
   five minutes later.
3. Treats the verifier request time and status validation time as distinct
   public inputs. The request time anchors the OpenID4VP transcript.
   The issuer-status proof's validation time must match the verifier's
   authenticated status-list evidence. It must be no earlier than the request,
   no later than the verifier's trusted evaluation time, within the configured
   maximum age, and strictly before presentation expiry. Presentation expiry
   must also be strictly before the holder attestation expiry and both
   selected credentials' issuer-signed validity end times.
4. Trusts the ReallyMe attestation signer and accepted assurance policy.
   It verifies the status authority's signature, signed validity interval,
   and maximum age outside the circuit, and validates and durably records the
   signed sequence and digest before using the snapshot. An older sequence or a
   conflicting snapshot at the same sequence fails across verifier restarts.
   It then requires the
   status proof's public root to equal that trusted snapshot root. A verifier
   rejects requests after the interval or age bound until trusted
   infrastructure supplies a refreshed signed snapshot.
5. Compares the attestation and status `attestation_join`; compares the
   attestation, status, and both lineage `root_join` values; and compares
   each ordered lineage `subject_join` with its selected-claim proof.
6. Rejects a duplicate credential binding in the two slots. For each
   requested credential role, compares lineage and selected-claim
   issuer key, credential binding, expiry, and active request fields. The
   two roles and their proof slots are ordered; swapping or duplicating a
   slot is invalid unless the request explicitly permits that assignment.
7. Requires both selected-claim proofs to use the same persona mode and
   session binding. The verified persona-session proof must have that
   session binding, the same active request fields and expiry, and, for
   public personas, the same public persona key. The verifier checks the
   requested claim names, values, issuer trust, and presentation policy.
8. Authenticates each issuer's status-list signature under the deployment's
   trusted issuer key, its exact issuer, list ID, URL and purpose, and its
   freshness window. A durable per-list floor rejects older lists and
   conflicting lists at the same issue time across restarts. The verifier
   computes the Merkle root from those authenticated bytes; the holder never
   chooses the expected root. Each issuer-status proof must use that root and
   match the exact issuer key, `CREDB1` credential binding, session expiry,
   and request fields of its lineage proof. The circuit verifies the issuer's
   separate validity/status signature over the same hidden envelope hash and
   claims root used by lineage, checks the hidden status bit is clear, and
   requires credential validity from request creation through the entire
   presentation session.

A valid proof with a different subject key for the same issuer, envelope,
Merkle root, and selected claim is rejected by step 5. A valid proof for a
different persona or an old verifier request is rejected by steps 2 and 7.
A valid attestation for the same root but a different revoked instance is
rejected by the exact `attestation_join` in step 5.

## Privacy and lifecycle

The wallet generates the root as 32 random bytes and generates a fresh
presentation salt for every request. An issuer sees its relationship context
and a commitment to its distinct lineage value. ReallyMe signs a commitment
to the root and does not receive the root. The verifier sees no root, root
commitment, lineage value, issuance DID, hidden subject key, or stable
cross-presentation join.
Issuer-specific contexts and nonces prevent two colluding issuers from
testing their lineage values for a common root from those values alone.

Credential data and proof artifacts can still reveal a relationship through
claims or other metadata. The common-credential-root result proves common assured
root provenance and persona authorization; it does not independently prove
that two credentials were issued to the same natural person. The assurance
policy defines the identity-proofing meaning of the root.

Credential and lineage witness material can be prepared at issuance, but
finished presentation proofs are bound to the fresh request and must not be
reused across verifiers. The status proof uses the current trusted snapshot.
