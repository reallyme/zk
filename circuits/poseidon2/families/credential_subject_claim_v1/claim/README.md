# credential_subject_claim_v1_claim

`circuit_credential_subject_claim_v1_claim` is the selected-claim stage of the `credential_subject_claim_v1` flow.

Alice proves to Bob that:

- the issuer bound the hidden subject key to the same hidden credential envelope
- the disclosed claim belongs to the same hidden, issuer-authenticated Merkle root
- the proof is bound to the same holder session and credential as the other `credential_subject_claim_v1` stages

Public inputs:

- `pk_issuer_x`, `pk_issuer_y`
- `challenge`
- `audience_hash`
- `transaction_data_hash`
- `expiry_unix`
- `session_binding`
- `credential_binding`
- `val_len`
- `val_pub`
- `name_hash`

Private inputs:

- `envelope_hash`
- `merkle_root`
- `issuer_subject_bind_sig`
- `pk_subject_x`, `pk_subject_y`
- `salt`
- `index`
- `path_len`
- `path`

Bob verifies four proofs together:

1. `circuit_credential_subject_claim_v1_session`
2. `circuit_credential_subject_claim_v1_credential_envelope`
3. `circuit_credential_subject_claim_v1_credential_root`
4. `circuit_credential_subject_claim_v1_claim`

Verifier obligations:

- `session_binding` must match between `circuit_credential_subject_claim_v1_session` and `circuit_credential_subject_claim_v1_claim`
- `envelope_binding` must match between `circuit_credential_subject_claim_v1_credential_envelope` and `circuit_credential_subject_claim_v1_credential_root`
- `credential_binding` must match between `circuit_credential_subject_claim_v1_credential_root` and `circuit_credential_subject_claim_v1_claim`
- `challenge`, `audience_hash`, `transaction_data_hash`, and `expiry_unix` must match across all four proofs
- Bob must still apply application policy to the disclosed `name_hash` and `val_pub`

Security notes:

- `circuit_credential_subject_claim_v1_claim` does not reveal `envelope_hash`, `merkle_root`, or Alice's hidden subject key.
- The public join values bind this presentation together. They are not stable credential identifiers across relying parties.
