# reallyme-zk-proto-codec

`reallyme-zk-proto-codec` is the strict conversion boundary between generated
`reallyme-zk-proto` messages and the semantic types owned by
`reallyme-zk-api` and `reallyme-zk-artifacts`.

Generated messages are transport values, not validated domain objects. This
crate rejects unspecified or unknown enums, missing oneofs, incorrect fixed
lengths, inconsistent circuit identities, unsupported versions, and unsupported
claims before passing values to a provider. Applications and protocol
adapters normally map typed ZK failures into their own public error
envelopes. The optional `stack-error` feature provides the canonical adapter to
the shared `IdentityStackError` envelope from `reallyme-ssi-proto` 0.6.2. The
feature remains in this integration crate so the public ZK contracts
stay independent of SSI.

The `operation` module validates provider requests. It applies named
protobuf and ProtoJSON resource limits, rejects unknown binary fields and
malicious JSON shapes, rejects proving operations before JSON decoding, and
moves a recognized `NoirWitnessStackV1` directly into `ZkWitness` zeroizing
storage. Unspecified or unknown witness encodings fail as malformed protobuf
before provider dispatch. Provider, FFI, JNI, WASM, and Connect adapters should
dispatch only the resulting `ZkProviderOperation` domain enum.

The sealed `protojson` module applies the binary-only proving rule before every
generic request decode and before every request encode, so callers cannot
bypass it by skipping `operation`. `ZkProvingVectorSet` is intentionally absent
from the ProtoJSON allowlist because it contains proving requests and
synthetic witness material.

The `artifact` module retains and validates every canonical manifest identity
field, including both circuit-version representations and bounded Nargo and
Barretenberg version tokens. Toolchain metadata is part of the atomic stage and
bundle manifest identity and cannot vary across stages.

Artifact conversion is bidirectional. Release tooling seals a validated draft
into deterministic protobuf bytes and a domain manifest carrying the SHA-256 of
those exact bytes. Encoding an existing domain manifest recomputes and compares
that identity, so stale pins and hand-assembled package metadata fail closed.
The protobuf message remains the canonical persisted representation; there is
no parallel JSON manifest contract. Release assembly decodes persisted
manifest bytes through an additional bounded, zero-unknown-field,
deterministic-wire boundary before those bytes may contribute to an index.

The `error` module converts structured errors in both directions, covers every
error oneof variant, and rejects unknown, unspecified, or mismatched top-level
and detail codes.

The `proof` module owns exact proof and production-bundle conversion, while the
private `domain` and `binding` modules own shared conversion helpers and
fixed-size presentation-session binding decoding.

The `result` module converts each canonical response into exactly one
typed success value or one structured domain error. It rejects missing result
oneofs, incomplete bundle-verification counts, unsupported versions, and
inconsistent stage, bundle-kind, or circuit identities.

The `persona_credential_evidence_proof_set` module owns the canonical
`ZkPersonaCredentialEvidenceProofSet` plaintext for Wallet-authenticated encryption.
It accepts four exact source proofs only when their presentation mode,
production suite, hash lane, proof window, holder key, token nonce, and
credential binding join.
It excludes the current-status proof, which is refreshed for each presentation.
Decoding this record does not verify its proofs, issuer trust, current status,
or the live holder signature; those checks remain at the presentation boundary.

The `vector` module is the binary-only boundary for pre-manifest proving
specifications. It accepts only deterministic protobuf encodings with no
unknown fields, the exact supported format version, a known explicit proof
suite, one-based contiguous vector numbers, proving-only base operations, and
expected shapes consistent with the bundle kind, hash, and stage. Negative
cases use a fixed set of typed mutation recipes; executing a recipe re-enters
the canonical operation decoder
and must produce its exact privacy-safe `ZkErrorReason`. Encoded base operations
and temporary mutated requests are zeroized because they transitively contain
synthetic witness material.

The `release` module validates the canonical release index. It bounds binary
decoding, rejects non-deterministic encodings and unknown fields, validates
release and toolchain tokens, requires the production suite, and requires the
complete ordered 24-manifest, six-vector-set, twelve common-credential-root-artifact, and
six persona-credential-evidence artifact matrices with unique digests.
Encoding accepts only that validated domain owner; generated `ZkReleaseIndex`
messages are never treated as trusted release metadata directly.

The `verification_vector` module owns concrete post-manifest proof vectors.
It requires four ordered artifact pins, verifies every proof's exact
bundle kind, hash, stage, suite, and manifest identity, permits only verification
operations, and validates the canonical expected response. Its closed mutation
executor distinguishes preflight failures from structurally valid tampered or
stale-proof operations that must reach the injected provider. Serialized base
operations and mutation temporaries are zeroized because proof bytes remain
privacy-sensitive even though they are not witnesses.

The message-only proto crate must not depend on this crate, the ZK API,
artifacts, backends, identity-common, or transport implementations.
