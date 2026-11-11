# credential_subject_claim_v1_credential_root

`circuit_credential_subject_claim_v1_credential_root` is the issuer-root stage of the `credential_subject_claim_v1` flow.

Alice proves to Bob that:

- the issuer signed the binding between the hidden `envelope_hash` and `merkle_root`
- the proof is linked to the same presentation-scoped `envelope_binding`
- the proof emits the `credential_binding` that `circuit_credential_subject_claim_v1_claim` must match

Public inputs:

- `pk_issuer_x`, `pk_issuer_y`
- `challenge`
- `audience_hash`
- `transaction_data_hash`
- `expiry_unix`
- `envelope_binding`
- `credential_binding`

Private inputs:

- `envelope_hash`
- `merkle_root`
- `issuer_root_bind_sig`

Public output meanings:

- `envelope_binding = Poseidon2("ENVB1" || pk_issuer_x || pk_issuer_y || envelope_hash || challenge || audience_hash || transaction_data_hash || expiry_unix)`
- `credential_binding = Poseidon2("CREDB1" || pk_issuer_x || pk_issuer_y || envelope_hash || merkle_root || challenge || audience_hash || transaction_data_hash || expiry_unix)`

Security notes:

- Neither `envelope_hash` nor `merkle_root` are public.
- `credential_binding` links the stages of this presentation; it is not a stable credential identifier.
- Bob must match `envelope_binding` against `circuit_credential_subject_claim_v1_credential_envelope` and `credential_binding` against `circuit_credential_subject_claim_v1_claim`.
