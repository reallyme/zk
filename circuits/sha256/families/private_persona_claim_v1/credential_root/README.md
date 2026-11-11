# private_persona_claim_v1_credential_root

`circuit_private_persona_claim_v1_credential_root` is the second issuer-side stage of the `private_persona_claim_v1` flow.

It verifies the same issuer statement as `circuit_credential_subject_claim_v1_credential_root`:

- issuer signed the hidden binding between `envelope_hash` and `merkle_root`
- proof matches the same `envelope_binding`
- proof emits `credential_binding`

Public inputs:

- `pk_issuer_x`, `pk_issuer_y`
- `challenge`, `audience_hash`, `transaction_data_hash`, `expiry_unix`
- `envelope_binding`
- `credential_binding`

Private inputs:

- `envelope_hash`
- `merkle_root`
- `issuer_root_bind_sig`

Bob matches `credential_binding` against the corresponding `circuit_private_persona_claim_v1_claim` proof for that credential.
