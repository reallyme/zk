# Security Memory Model

## Scope

This memory-safety and secret-handling model covers:

- Noir witness inputs and generated witness data.
- Proof bytes, verification keys, public inputs, and artifact hashes.
- Rust API, backend, and artifact crates.
- Swift and Kotlin provider packages and the optional `bb.js` adapter.
- FFI adapters that move proof or witness material across platform boundaries.

## Data Inventory

| Data class | Examples | Sensitivity | Required owner model |
| --- | --- | --- | --- |
| Witness inputs | Credential subject claims, issuer secrets, persona secrets | Critical | Zeroizing secret owner for every repository-owned buffer; decoded request fields sit behind wiping guards |
| Derived witness data | Serialized witness stacks and proving commands | Critical | Zeroizing owner; no logs. Copies made inside Noir, ACVM, compression libraries, Barretenberg, and `bb.js` are outside this owner model; see Residual Risks |
| Session binding | Nonce hash, audience hash, transaction-data hash | Integrity-sensitive | Fixed-size typed arrays |
| Public inputs | Claim commitments, binding hashes, derived statements | Integrity-sensitive/privacy-sensitive | Typed wrappers and size bounds |
| Proof bytes | Barretenberg proof output | Privacy-sensitive/integrity-sensitive | Owned bytes with size bounds; no log bodies |
| Artifacts | Bytecode, verification keys, manifests | Integrity-critical | Content-addressed hashes and manifest verification |
| Backend handles | Barretenberg linked-library objects | Critical boundary | Backend-owned; no handles cross into open-stack crates |

## Lifecycle Model

### 1. Ingest

- External bytes enter as untrusted input.
- Length and shape checks run before parsing or allocating large buffers.
- Buffer lengths, offsets, and capacities use checked arithmetic.
- Witness and private inputs move into explicit secret owners as early as the API allows.

### 2. Operate

- Proof operations run on bounded inputs with typed circuit identifiers.
- Temporary secrets use `Zeroizing<T>` or an owner that implements `ZeroizeOnDrop`.
- Backend failures return typed errors and must not expose backend exception text, raw inputs, witnesses, or proofs.
- Presentation binding checks happen at the proof-format/session boundary, not inside a backend-specific crate.

### 3. Export

- Public outputs use typed wrappers.
- Proof bytes are privacy-sensitive and must not be logged or embedded in errors.
- FFI exports prefer owned buffers with explicit destroy paths.
- Platform providers must document any managed-runtime copies of witness or proof data.

### 4. Clear / Drop

- Repository-owned secret owners zeroize on drop. The Noir ABI input-map owner overwrites upstream field values on a best-effort basis because the upstream type has no zeroizing implementation.
- Temporary witness buffers are cleared before returning when waiting for drop would retain them too long.
- Tests that inspect witness internals must keep that access local to the test crate and avoid logging raw values.

## Controls

| Control | Enforcement or reference |
| --- | --- |
| Panic, unwrap, and debug-print restrictions | Root `Cargo.toml` workspace lints |
| Member lint inheritance | Member crates use `[lints] workspace = true` |
| Typed API errors | `crates/api/src/error.rs` |
| Secret witness ownership | `ZkWitness` wraps `SecretBox<Zeroizing<Vec<u8>>>` |
| Backend isolation | [Package boundaries](PACKAGING.md), [provider requirements](PROVIDER_POLICY.md), and the open-stack boundary check |
| Dependency policy | `deny.toml` |
| Dual-license source headers | SPDX headers on hand-written source and configuration files |

## Residual Risks

1. Zeroization cannot remove copies created by the OS, allocator, CPU, compiler, browser runtime, or platform managed runtimes.
2. FFI callers can copy or log sensitive bytes after receiving them; Rust-side controls cannot erase caller-owned copies.
3. Crash reporters, telemetry, swap, hibernation, and process snapshots remain deployment responsibilities.
4. Browser and mobile managed runtimes provide best-effort memory hygiene only.
5. Noir ABI encoding, ACVM execution, the gzip encoder and decoder, linked
   Barretenberg, and `bb.js` with its WebAssembly memory keep internal copies
   of witness data that this repository cannot overwrite. The
   [memory ownership guide](docs/security-memory-model.md) lists them.
6. Circuit-iteration scripts invoke command-line tools. Releases must use the
   pinned release tooling; runtime proving must use linked providers.

## Mandatory Operational Controls

1. Disable raw request, witness, proof, public-input, key, and error-context logging in applications that use this workspace.
2. Keep crash and diagnostic upload policies aligned with proof and witness sensitivity.
3. Run the full workspace validation gate before merging ZK changes.
4. Require positive and negative vectors for every new circuit version, backend, artifact manifest, or session-binding change.
5. Treat FFI destroy/zeroize paths as part of the API contract.
