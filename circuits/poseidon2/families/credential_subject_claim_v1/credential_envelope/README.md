# credential_subject_claim_v1_credential_envelope

`circuit_credential_subject_claim_v1_credential_envelope` is the issuer-envelope stage of the `credential_subject_claim_v1` flow.

Alice proves to Bob that:

- the prover holds a signature that verifies under the issuer key for the
  hidden `envelope_hash`. Because that hash is an unconstrained private input,
  this alone does not authenticate the issuer; see the family README
- the proof belongs to this presentation through `envelope_binding`

Public inputs:

- `pk_issuer_x`, `pk_issuer_y`
- `challenge`
- `audience_hash`
- `transaction_data_hash`
- `expiry_unix`
- `envelope_binding`

Private inputs:

- `envelope_hash`
- `issuer_sig`

Public output meaning:

- `envelope_binding = Poseidon2("ENVB1" || pk_issuer_x || pk_issuer_y || envelope_hash || challenge || audience_hash || transaction_data_hash || expiry_unix)`

Security notes:

- `envelope_binding` is presentation-scoped. It is not a stable public credential identifier across sites.
- This proof does not reveal `envelope_hash`.
- Bob must match `envelope_binding` against `circuit_credential_subject_claim_v1_credential_root` and also ensure `challenge`, `audience_hash`, `transaction_data_hash`, and `expiry_unix` are the same across the whole proof bundle.
