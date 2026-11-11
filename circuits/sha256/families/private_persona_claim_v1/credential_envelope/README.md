# private_persona_claim_v1_credential_envelope

`circuit_private_persona_claim_v1_credential_envelope` is the first issuer-side stage of the `private_persona_claim_v1` flow.

It verifies the same issuer statement as `circuit_credential_subject_claim_v1_credential_envelope`:

- the prover holds a signature that verifies under the issuer key for the
  hidden `envelope_hash`. Because that hash is an unconstrained private input,
  this alone does not authenticate the issuer; see the family README
- proof emits the presentation-scoped `envelope_binding`

Public inputs:

- `pk_issuer_x`, `pk_issuer_y`
- `challenge`, `audience_hash`, `transaction_data_hash`, `expiry_unix`
- `envelope_binding`

Private inputs:

- `envelope_hash`
- `issuer_sig`

Bob matches `envelope_binding` against `circuit_private_persona_claim_v1_credential_root` for the same credential.
