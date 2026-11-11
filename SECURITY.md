# Security Policy

ReallyMe ZK is security-sensitive infrastructure. Reports involving proof
soundness, verifier bypass, replay/binding failures, artifact-hash confusion,
witness disclosure, memory handling, or dependency compromise are security
issues.

## Supported Surface

Security review applies to:

- `reallyme-zk-api` circuit identifiers, capabilities, errors, and traits.
- Noir circuit source under `circuits/`.
- Artifact manifests and cache/fetch verification logic.
- Barretenberg backend bindings and FFI boundaries.
- Provider-operation contracts consumed by downstream native and WebAssembly
  packages.
- Positive and negative vectors.

The [memory ownership model](docs/security-memory-model.md) describes which
buffers this repository clears and which copies upstream libraries may retain.

## Non-Negotiable Behaviors

- ZK presentation verification fails closed when no verifier is injected.
- Presentation nonce, verifier identity, and transaction-data hash are checked
  as public-input bindings before a ZK presentation is accepted. The v1
  absence sentinel cannot be supplied as actual transaction data.
- Circuit capability semantics come only from `reallyme-zk-api`.
- Production paths do not shell out to `bb`.
- Errors do not include PII, witness data, proofs, public inputs, or backend
  exception text.

## Reporting

Submit suspected vulnerabilities through GitHub private vulnerability
reporting for this repository. If that channel is unavailable, contact the
maintainers through a private organizational security channel; do not open a
public issue. Include affected circuit IDs, artifact hashes, crate/package
versions, and a minimal reproduction that avoids real PII or live credentials.

Do not disclose a suspected vulnerability publicly before coordinated triage.
