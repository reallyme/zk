# Persona credential evidence v1

Persona credential evidence combines three checks: an issuer-authenticated
claim, current credential status, and a fresh holder signature. The same v1
contract supports public persona keys and one-time private persona keys. A
verifier accepts the presentation only after checking every proof, all public
input joins, an authenticated current issuer-status snapshot, the proof window,
the active request, and the holder's live signature over `RMPAUTH1`.

`current_state` proves that an issuer signed the exact hidden credential
envelope, claim root, validity interval, status-list pointer, and status index.
It proves that the selected status bit is clear in the public Merkle root that
the verifier authenticates. The wallet-chosen half-open prepared interval must
be wholly contained in the issuer-signed credential interval.

`issuer_envelope` verifies one signature over the hidden envelope digest
directly. That digest is a private input the circuit does not derive, so this
check can be satisfied for any issuer key and does not authenticate the issuer
by itself. Issuer authentication comes from the domain-tagged `BINDSUB1`,
`BINDMRK1`, and `BINDVLD1` signatures, whose digests are computed inside the
circuits over the same hidden envelope digest and joined by the credential
binding. No stage proof is evidence outside the complete joined presentation.

`public_claim` proves issuer subject binding, the subject's authorization of
the public persona key, and membership of the disclosed claim in the credential
root authenticated by `current_state`. `private_claim` proves the same claim
membership and subject authorization of a hidden persona key. It also verifies
that the hidden persona authorized the one-time holder key, token nonce, and proof
window. Each claim stage and `current_state` derive the same credential binding
from the same hidden envelope, claim root, and subject key.

The public `credential_binding` is

```text
SHA-256(
  "PRECB2" || issuer_x || issuer_y || hidden_envelope_hash || hidden_claims_root ||
  hidden_subject_x || hidden_subject_y ||
  holder_x || holder_y || token_nonce ||
  u64_be(prepared_from) || u64_be(prepared_until)
)
```

The claim proof derives the same value from its own hidden credential witness.
In private mode, the holder key is a one-time key authorized by the
hidden persona; the wallet reserves the token durably before disclosure. For
public mode, the holder key is the public persona key. The verifier
checks the holder signature under the key exposed by the verified claim proof.

The issuer-status list identity and root remain public inputs in this stage.
Private-token unlinkability therefore requires a verifier-trusted status feed
shared across the issuer's credentials. A per-credential status list is
incompatible with private mode. The verifier authenticates the signed
snapshot, enforces its freshness and durable issue-time floor, and checks its exact
root, list identity, and purpose against these public inputs.
