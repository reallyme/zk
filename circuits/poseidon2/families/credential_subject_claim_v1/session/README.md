# credential_subject_claim_v1_session

`circuit_credential_subject_claim_v1_session` is the holder-session stage of the `credential_subject_claim_v1` flow.

Alice proves to Bob that:

- she controls the hidden subject key for this presentation
- she answered Bob's challenge for this presentation
- the proof produces a `session_binding` that Bob must match with the corresponding `circuit_credential_subject_claim_v1_claim` proof

Public inputs:

- `challenge`
- `audience_hash`
- `transaction_data_hash`
- `expiry_unix`
- `session_binding`

Private inputs:

- `pk_subject_x`, `pk_subject_y`
- `subject_sig` over `Poseidon2("SESS1" || challenge || audience_hash || transaction_data_hash || expiry_unix)`

Public output meaning:

- `session_binding = Poseidon2("SESSB1" || pk_subject_x || pk_subject_y || challenge || audience_hash || transaction_data_hash || expiry_unix)`

Security notes:

- `session_binding` links proofs for the same request from Bob.
- `session_binding` does not expose `envelope_hash`, `merkle_root`, or a stable credential identifier.
- Bob must reject replayed or expired `(challenge, audience_hash, transaction_data_hash, expiry_unix)` tuples at the application layer.
