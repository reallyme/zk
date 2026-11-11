# Contributing

Use an issue to discuss changes to circuit semantics, proof formats, or public
APIs before implementing them. Report vulnerabilities privately through
[SECURITY.md](SECURITY.md).

Keep changes focused and include tests for accepted and rejected inputs.
Errors must stay typed and must not expose claims, keys, witnesses, proof bytes,
or backend diagnostics.

## Checks

Use the pinned toolchain. Native checks require the Barretenberg libraries
and artifacts described in [platform builds](docs/platform-builds.md).

```sh
cargo fmt --check
RUSTFLAGS=-Dwarnings cargo check --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo nextest run --locked --workspace --all-features
cargo deny check
buf lint
scripts/check-generated-protos.sh
scripts/check-open-stack-boundaries.sh
```

Run the matching Swift, Kotlin, or JavaScript tests when changing a provider.
The boundary check requires sibling repositories; a skipped check does not
establish integration compatibility.

## Circuit and contract changes

Circuit changes must include matching artifact manifests, verification-key
hashes, capability metadata, and positive and negative vectors. Cover malformed
inputs, tampered proofs, stale artifacts, replay, and session-binding failures.
See [conformance](conformance/README.md) and [provider compatibility](PROVIDER_POLICY.md).

Keep protobuf wire compatibility separate from Rust API compatibility. Schema
changes require regenerated bindings and compatibility checks. Record public
API changes in [CHANGELOG.md](CHANGELOG.md).
