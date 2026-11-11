# private_persona_claim_v1_claim_bundle_4

This is the bundled claim stage for `private_persona_claim_v1`.

Its public inputs bind `challenge`, `audience_hash`, `transaction_data_hash`,
and `expiry_unix` to the presentation.

This diagnostic stage proves up to four claims from one credential while
keeping the persona hidden from Bob. It is not part of the production bundle.

Alice proves to Bob:

- the credential's hidden subject key authorized the hidden private persona
- the bundled claims all belong to the same hidden credential context
- the bundled claims are all valid Merkle members of the same hidden Merkle root
- the bundled claims belong to the same live private-persona session

Bob learns:

- the issuer key
- the active claim count and canonical `bundle_hash`

Bob does not learn:

- the hidden credential subject key
- the hidden private persona key
- `envelope_hash`
- `merkle_root`

This stage combines several claims from one credential in one bounded proof.
Claim names, lengths, and values remain private circuit inputs. If Alice
discloses plaintext claims through a separate protocol field, Bob must
recompute the ordered bundle hash and compare it with the public
`bundle_hash`; the circuit does not reveal plaintext claims directly.

Privacy boundary: the public `bundle_hash` is deterministic and unsalted.
Low-entropy claim names or values can therefore be tested by dictionary attack,
especially when an observer can guess the other bundled fields. This stage is
not supported for production use. The hash alone must not be treated as a
commitment that hides the claims.
