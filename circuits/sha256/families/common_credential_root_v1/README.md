# Common credential root v1 SHA-256 proof family

A presentation contains nine proofs covering two selected credential claims:

1. `root_attestation` verifies the ReallyMe P-256 attestation.
   `root_status` proves private active-status membership for that exact
   signed attestation instance. Both publish presentation-scoped `root_join`
   and `attestation_join` values.
2. `issuer_credential_status` runs once for each ordered credential and proves
   the issuer-signed validity interval and an unset bit in the current
   authenticated credential status list.
3. `lineage` runs once for each ordered credential. It derives that
   credential's issuer-authenticated lineage value from the hidden root,
   verifies its signed Merkle path, and publishes `root_join`, the exact
   session-scoped `CREDB1` binding, and `subject_join`.
4. `private_persona_claim` or `public_persona_claim` runs once for each
   credential. It verifies the selected claim, issuer `BINDSUB1` subject
   binding, and subject `LINK1` persona authorization. It computes
   `subject_join` from that same hidden subject. It rejects selection of the
   reserved lineage claim, whose value would otherwise become public.
5. `public_session` verifies a fresh public-persona signature over the active
   request. A private presentation uses the private-persona `session` stage.
   The claim proofs and selected session proof
   publish the same `PSESB1` or `PSESB2` binding.

Root assurance, HKDF derivation, and presentation joins use SHA-256.
Credential transcript hashes use bounded SHA-256.

The verifier must verify every proof against its pinned verification key and
compare the root joins, attestation joins, ordered subject joins, issuer keys,
credential bindings, verified persona/session binding, active request, expiry, status
snapshot, and requested credential roles. It rejects duplicate credential
slots and an expiry longer than five minutes. Matching `CREDB1` alone does not
identify the hidden subject. The selected-claim proof's `subject_join` must
match its lineage proof, so the selected claim and lineage use the same
issuer-bound subject. No root, subject key, relationship DID, or lineage tag
is public.

Run `scripts/test-common-credential-root-production-circuits.sh` with the pinned
Nargo, Barretenberg, and CRS paths. The test proves and verifies the
attestation, status, lineage, selected claims, and persona sessions.
