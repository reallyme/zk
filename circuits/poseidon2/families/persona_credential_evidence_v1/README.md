# Persona credential evidence v1

The Poseidon2 circuits prove the same persona credential evidence statement
and use the same public-input order as the SHA-256 circuits. Its `PRECB2` credential join uses the reviewed
Poseidon2 bounded-byte sponge over the 310-byte transcript. Issuer signatures,
status-list Merkle nodes, and holder-authentication digests remain SHA-256.

See the [SHA-256 circuit reference](../../../sha256/families/persona_credential_evidence_v1/README.md)
for the complete statement, verifier joins, and shared issuer-status-feed requirement.
