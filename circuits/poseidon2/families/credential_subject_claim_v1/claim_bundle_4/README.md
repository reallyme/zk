# credential_subject_claim_v1_claim_bundle_4

`claim_bundle_4` is a bounded bundle stage for `credential_subject_claim_v1`.

Alice proves to Bob, in one claim-stage proof, that up to four claims:

- come from the same hidden issuer-approved credential context
- are bound to the same hidden subject key
- belong to the same holder session
- are all valid Merkle members of the same hidden Merkle root

Public inputs:

- `pk_issuer_x`, `pk_issuer_y`
- `challenge`
- `audience_hash`
- `transaction_data_hash`
- `expiry_unix`
- `session_binding`
- `credential_binding`
- `bundle_count`
- `bundle_hash`

Private inputs include the hidden credential context plus the bounded per-claim arrays:

- `envelope_hash`
- `merkle_root`
- `issuer_subject_bind_sig`
- `pk_subject_x`, `pk_subject_y`
- `val_lens`
- `val_pubs`
- `name_hashes`
- `salts`
- `indices`
- `path_lens`
- `paths`

The circuit exposes only the active count and a canonical `bundle_hash`; claim
names, lengths, and values remain private circuit inputs. If Alice discloses
plaintext claims through a separate protocol field, Bob must recompute the
ordered bundle hash and compare it with this public output. The circuit proves
that the committed claims are valid members of the issuer-approved credential
context, but does not itself reveal their plaintext.

Privacy boundary: the public `bundle_hash` is deterministic and unsalted.
Low-entropy claim names or values can therefore be tested by dictionary attack,
especially when an observer can guess the other bundled fields. This
experimental stage is not supported for production use. The hash alone must
not be treated as a commitment that hides the claims.
