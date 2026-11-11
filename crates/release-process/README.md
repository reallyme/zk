# ReallyMe ZK Release Process

This unpublished crate is the only Rust component allowed to invoke Nargo
or Barretenberg to produce release artifacts and conformance vectors.
Runtime proving and verification use linked-library providers.

The adapter requires explicit absolute executable paths, rejects symlinks,
and checks executable hashes against the repository toolchain lock. The
current circuit source uses the pinned Noir `1.0.0` and Barretenberg
`6.0.0` versions. It also checks the pinned full-prover CRS before running the
backend. It supports only a fixed set of typed operations. Production vector
commands pin UltraHonk, Keccak, zero knowledge enabled, and IPA accumulation
absent. Tool output, local paths, and backend diagnostics are never retained in
errors.

`ReleaseProofCyclePaths` requires absolute, non-symlinked inputs, an exact
circuit reference, and a new empty output directory. `prove_and_verify`
generates the verification key and proof, verifies the exact proof and public
inputs, and immediately adopts bounded owned copies of every verified output.
The completed value retains no mutable filesystem path. A failed or incomplete
backend run never yields a completed release proof cycle.

Before accepting a completed run, the adapter validates pinned Noirc metadata,
bounds every file before allocation, rejects empty or changing payloads, and
decodes backend public fields under the original `ZkCircuitRef`. It requires a byte-exact round trip
into the compact provider ABI. Later manifest association checks the original
circuit, suite, bytecode digest, and verification-key digest. Diagnostics
retain only the typed output class, never output bytes or host paths.

The `prove-and-verify` binary accepts explicit
Nargo and Barretenberg paths paired with lowercase SHA-256 pins, followed by
the CRS directory, compiled program, witness, existing empty output directory,
and exact circuit reference. An optional final argument selects an explicitly
acknowledged proof suite. It performs no `PATH` discovery and prints no tool
output or local paths.

Use `generate-and-verify` for a complete release run. It requires
a constraint-checked compile and witness solve before the same verified proof
cycle. The generated witness is overwritten in bounded chunks, truncated,
synced, and removed on both the success and handled-failure paths. This is
best-effort filesystem sanitization—copy-on-write media can retain historical
blocks—so release hosts must also use encrypted ephemeral storage.

For resumable package assembly, `ExistingReleaseProofPaths` and
`verify_existing` re-admit retained proof outputs only after the pinned backend
re-derives the verification key from the exact compiled program, compares it
byte-for-byte with the retained key, and then accepts the exact proof and public
inputs. The temporary key is sanitized and removed on success and on handled
failure.
`ReleaseWitnessMaterialPaths` and `regenerate_witness_and_load_material`
regenerate only the matching serialized witness stack, validate the retained
compiled program against the exact circuit target, load all bytes through
bounded typed owners, and sanitize the temporary witness. This operation cannot
compile, replace a retained verification key, or prove.
