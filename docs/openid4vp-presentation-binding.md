# OpenID4VP ZK presentation binding

This contract maps an active OpenID4VP request to the public inputs of a
ReallyMe ZK proof bundle. OpenID4VP owns the `vp_token` format, request
interpretation, issuer policy, and presentation acceptance. `reallyme-zk-api`
owns the circuit bindings and typed claim/status verification interfaces.

Cryptographic proof verification alone does not make an OpenID4VP presentation
acceptable. For a direct or private credential, the format adapter verifies
the four claim proofs and the fifth issuer-credential-status proof against the
same request and credential binding. It also authenticates the current issuer
status list at the verifier's clock. The four-stage result alone is claim
evidence: `ZkPresentationBoundClaimBundleVerification` exposes a
`ZkPresentationBoundClaimStatement`. Only the joined status-qualified result
exposes `ZkVerifiedClaimStatement` for credential acceptance. Missing proof,
verifier, or trusted status authority fails closed.

## Active request

The ZK API receives 32-byte nonce, audience, and optional transaction-data
hashes. It compares them with proof public inputs; it does not parse the
OpenID4VP request or derive hashes from request strings.

The OpenID4VP verifier adapter hashes the UTF-8 bytes of the active,
case-sensitive `nonce` and audience values. Its wallet adapter accepts an
API-defined status-qualified bundle, a verified authorization-request receipt,
and authenticated invocation context. Before encoding the `vp_token` entry, the
wallet adapter checks the same preimages and selected-claim policy. The
verifier compares decoded proof public inputs with the active request.
Matching only an outer envelope binding is insufficient.

For [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html)
Digital Credentials API requests, the audience is the authenticated request
Origin prefixed with `origin:`, including for signed requests. It is not
the `client_id`. An unsigned DC API request omits `client_id`; the wallet
ignores one if supplied. The Origin comes from the authenticated platform
context, never an untrusted body field. Other request forms use the same
audience wire value in wallet and verifier, including the selected
`client_id.to_wire_value()` mapping.

SHA-256 is the preferred credential hash lane. Poseidon2 requires explicit
selection and matching issuer commitments, circuits, artifacts, and provider
support; the verifier must not silently substitute one lane for another.

## Transaction data and claim selection

The OpenID4VP SD-JWT VC transaction-data profile hashes each base64url
`transaction_data` string as received, without decoding it. The ZK format
has its own binding rule. Its v1 session ABI carries one optional
transaction-data hash, while OpenID4VP permits an array. The v1 adapter
accepts at most one SHA-256 transaction-data digest per credential query.
It rejects any request that would require dropping transaction data.

An absent hash maps to the circuit's reserved 32-byte absence sentinel. A
caller cannot supply that sentinel as a real transaction-data hash. The
verifier compares the resulting public input with the active request.

The `reallyme.openid4vp.zk_presentation.v1` DCQL format selects one claim
through `profile`, `hash_strategy`, and `claim_name_hash` metadata.
The format adapter maps the wire hash selector to the ZK API’s typed
`ZkCredentialHashAlgorithm`.
Optional `claim_value_b64u` requires one specified value. Without it,
verified claim bytes are returned as a zeroizing disclosure. The verifier
applies the query to a statement produced only after the joined five-proof
verification and current-status check. A free-form derived-claim label is not
proof of that claim.

## Runtime and composition

The `direct_post` runtime reserves and commits sessions. The
decode-only Digital Credentials API runtime rejects responses because it
lacks a server-owned session, authenticated browser Origin, and a way to
consume each response exactly once. A proof bound to one response mode cannot authorize
the other; their audience contracts differ.

Nonce, audience, and transaction-data bindings prevent a proof from satisfying a
different active request. Presentation expiry limits its time window. These
cryptographic checks do not remember prior uses: even a status-qualified proof
can verify again under identical inputs. Before granting access, the verifier
must atomically accept an outstanding, unexpired session exactly once in a
shared durable store. Concurrent submissions must yield at most one successful
acceptance; storage failure must fail closed. Application claim policy must
also pass before acceptance. The four-proof SDK sample flows are fixture
verification, not single-use credential-acceptance flows.

Several valid bundles in one response remain independent verified claims.
The current verifier adapter does not establish that they use one private
persona. `VerifiedZkClaim` exposes a presenting-key comparison for
compatible proofs, but the response pipeline does not apply it
automatically. Identity must compare claims under the same compatible
bundle kind, hash lane, transaction binding, and expiry before concluding that
they use one persona. A differing session-link commitment alone is
inconclusive when those parameters differ.

The [credential and persona guide](persona-credential-privacy.md) explains
the authorization meaning of that comparison. The
[conformance documentation](../conformance/README.md) defines integration
coverage and production validation requirements. Shared test vectors must
confirm consistent behavior across platforms before the ZK format is described
as interoperable.
