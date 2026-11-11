# private_persona_claim_v1_claim

`circuit_private_persona_claim_v1_claim` is the claim stage of the `private_persona_claim_v1` flow.

Alice proves to Bob that:

- the issuer bound this credential to its credential-specific hidden subject key
- that subject authorized the same hidden private persona `P`
- the disclosed claim belongs to the same hidden, issuer-authenticated Merkle root
- the proof belongs to the private-persona session and credential context in its four-stage bundle

Public inputs:

- `pk_issuer_x`, `pk_issuer_y`
- `challenge`, `audience_hash`, `transaction_data_hash`, `expiry_unix`
- `session_binding`
- `credential_binding`
- `val_len`, `val_pub`, `name_hash`

Private inputs:

- `envelope_hash`, `merkle_root`
- `issuer_subject_bind_sig`
- `pk_subject_x`, `pk_subject_y`
- `pk_persona_x`, `pk_persona_y`
- `subject_link_sig`
- `salt`, `index`, `path_len`, `path`

Verifier contract:

- `session_binding` must match between `session` and `claim`
- `envelope_binding` must match between `credential_envelope` and `credential_root`
- `credential_binding` must match between `credential_root` and `claim`
- `challenge`, `audience_hash`, `transaction_data_hash`, and `expiry_unix` must match across the proof bundle

Privacy notes:

- `pk_persona_x` and `pk_persona_y` stay private
- `envelope_hash` and `merkle_root` stay private
- the private persona key must differ from this credential's subject key
- the private persona key is not a public input; correlation limits are described in the family README
