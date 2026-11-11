# private_persona_claim_v1_session

`circuit_private_persona_claim_v1_session` is the hidden private persona session stage of the `private_persona_claim_v1` flow.

Alice proves to Bob that:

- she controls the hidden private persona key `P` for this presentation
- she answered Bob's challenge with `P`
- the proof emits a presentation-scoped `session_binding` that each `circuit_private_persona_claim_v1_claim` must match

Public inputs:

- `challenge`
- `audience_hash`
- `transaction_data_hash`
- `expiry_unix`
- `session_binding`

Private inputs:

- `pk_persona_x`, `pk_persona_y`
- `persona_sig` over `SHA-256("PERS2" || challenge || audience_hash || transaction_data_hash || expiry_unix)`

Public output meaning:

- `session_binding = SHA-256("PSESB2" || pk_persona_x || pk_persona_y || challenge || audience_hash || transaction_data_hash || expiry_unix)`

This uses the same proof layout as `circuit_credential_subject_claim_v1_session`,
but the hidden key belongs to the private persona rather than the credential
subject.
