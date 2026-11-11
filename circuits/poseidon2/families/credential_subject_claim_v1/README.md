# credential_subject_claim_v1

`credential_subject_claim_v1` enables holders to prove a selected credential
claim without revealing their subject key.

For example, Alice can present one claim to Bob without sharing a reusable
public persona or stable credential identifiers.

Alice proves to Bob:

- a trusted issuer issued a credential
- the credential contains the disclosed claim
- Alice controls the hidden credential subject key for this session

Bob learns:

- the issuer key
- the disclosed claim
- the join values needed to verify this presentation

Bob does not learn:

- Alice's subject identifier
- Alice's hidden credential subject key
- `envelope_hash`
- `merkle_root`

**Privacy:** v1 does not guarantee unlinkability. The issuer, or any party that
already knows an `envelope_hash`, can correlate a presentation by recomputing
the presentation-scoped bindings. Verifier policy must therefore treat this
family as potentially linkable.
Anyone who knows the hidden subject's public key plus the public challenge,
audience hash, transaction-data hash, and expiry can also recompute `session_binding` and test the
presentation for that key.

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

The claim bundle has four stages:

1. [`session/README.md`](session/README.md)
2. [`credential_envelope/README.md`](credential_envelope/README.md)
3. [`credential_root/README.md`](credential_root/README.md)
4. [`claim/README.md`](claim/README.md)

An additional bounded bundle stage is available for circuit iteration:

5. [`claim_bundle_4/README.md`](claim_bundle_4/README.md)

`claim_bundle_4` is diagnostic. It proves membership of up to four claims in
one claim-stage proof, with their values committed by a public bundle hash.
Production providers must not expose it without the required conformance checks.
