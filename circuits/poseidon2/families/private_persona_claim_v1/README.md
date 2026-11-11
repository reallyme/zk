# private_persona_claim_v1

`private_persona_claim_v1` enables holders to present a credential claim
through an authorized persona while keeping both keys hidden.

The production bundle proves one selected claim from one credential without
exposing the credential subject key or the persona key to the ordinary verifier.

In this family:

- the issuer binds the credential to a hidden credential subject key
- that subject key authorizes the hidden private persona
- the presenter proves session control of the private persona

Authorizing a persona does not establish that different credential subject
keys belong to the same person. This bundle does not prove that several
credentials have the same holder.
Several bundles may be verified for one persona session, but this establishes
persona continuity only; every bundle still needs independent verification.

**Privacy and delegation:** v1 does not prove unlinkability, and its
subject-to-persona authorization applies across sessions without a
circuit-enforced revocation mechanism. The issuer or a party that knows an `envelope_hash` can
correlate presentations. Deployments requiring unlinkability or revocable
delegation must reject this family.
Anyone who knows the hidden persona's public key plus the public challenge,
audience hash, transaction-data hash, and expiry can recompute `session_binding` and test the
presentation for that persona.

**Issuer signatures:** the v1 envelope stage verifies a signature over the
32-byte `envelope_hash` directly, and that hash is a private input the circuit
does not derive. ECDSA over a digest the signer of the proof chooses can be
satisfied for any public key without the private key, so an envelope-stage
proof on its own does not show that the issuer signed anything. Issuer
authentication in this family comes from the domain-tagged `BINDMRK1` and
`BINDSUB1` signatures in the credential-root and claim stages, whose digests
are computed inside the circuit over the same hidden `envelope_hash`. A
verifier must accept the envelope stage only as part of the complete joined
bundle, and an issuer must sign `BINDMRK1` and `BINDSUB1` only over an envelope
digest it computed from a credential it issued. Deployments that require the
envelope stage itself to authenticate the issuer must reject v1.

**P-256 signatures:** witnesses must carry canonical low-`s` signatures.
Upstream signing adapters must normalize valid high-`s` output before witness
serialization; the circuit rejects non-canonical high-`s` input.

Source stages:

1. [`session/README.md`](session/README.md)
2. [`credential_envelope/README.md`](credential_envelope/README.md)
3. [`credential_root/README.md`](credential_root/README.md)
4. [`claim/README.md`](claim/README.md)
5. [`claim_bundle_4/README.md`](claim_bundle_4/README.md)
