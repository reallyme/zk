# Toolchain and artifact provenance

ReallyMe ZK builds its Noir circuits with Noir `1.0.0` and Barretenberg
`6.0.0`. Aztec's `v6.0.0` release notes identify Noir `1.0.0-rc.3`; the
subsequent Noir `1.0.0` release pins Barretenberg `6.0.0`. Tests check this
combination against every circuit, invalid-proof vectors, and the linked
backend. The [toolchain lock](../../circuits/toolchain-lock.json) pins the upstream source
revisions, archive sizes and SHA-256 digests, executable digests, Barretenberg
static archives, and BN254 Common Reference String (CRS) identities. The
[installer](../../scripts/install-modern-ci-toolchain.sh) checks downloaded
bytes against that lock before using them.

The pinned releases are [Noir 1.0.0](https://github.com/noir-lang/noir/releases/tag/v1.0.0)
and [Aztec packages 6.0.0](https://github.com/AztecProtocol/aztec-packages/releases/tag/v6.0.0).

## Circuit source and proof artifacts

The [circuit source lock](../../circuits/modern-circuit-source-lock.tsv)
pins every source file used by each registered SHA-256 and Poseidon2 circuit.
The registry distinguishes Credential Subject Claim, Private Persona Claim,
Persona Credential Evidence, and Common Credential Root. `claim_bundle_4` is a diagnostic circuit;
it is outside the production four-stage presentation contract.

A release package binds each included circuit to its source files, Noir
bytecode, verification key, proof suite, and public-input layout. The
[sealed release verifier](../../scripts/verify_sealed_release_candidate.mjs)
checks package contents and identities before an artifact can be loaded. A
proof, public-input array, verification key, or bytecode from another circuit
or artifact generation is rejected during loading or verification.

The verifier checks every stage of a complete presentation and compares its
public challenge, audience, transaction-data hash, expiry, and inter-stage
bindings with the active request. A backend rejection fails closed with a typed
error; exception text from Barretenberg is not used to classify a proof as
valid or invalid.

## Common Reference String

ReallyMe ZK uses the BN254 CRS produced by the Aztec Ignition ceremony. The
[Aztec ceremony overview](https://aztec.network/zh/blog/aztec-crs-the-biggest-mpc-setup-in-history-has-successfully-finished)
describes the completed CRS and its intended use by other zero-knowledge
systems. [Ignition verification](https://github.com/AztecProtocol/ignition-verification)
provides tooling for checking ceremony contributions and the final output. The
[Aztec Barretenberg bootstrap](https://github.com/AztecProtocol/aztec-packages/blob/49a592109ec4f18d79212b43d621891aaf36f7b6/barretenberg/crs/bootstrap.sh)
names the `g1.dat` and `g2.dat` sources. The lock pins the source G1 prefix,
the 1,048,577-point prover G1 package, and the G2 point by exact byte count
and SHA-256. The installer records source URLs, retrieval times, byte counts,
and verified digests.

ReallyMe distributes pinned copies of the
[G1 source prefix](https://static.reallyme.net/zk/crs/ea6069e3563ad79f186d1c0088499309cbdaeb54254346760ffec7fe15ae49cd/bn254_g1.dat),
[prover G1 package](https://static.reallyme.net/zk/crs/0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5/bn254_g1.prover), and
[G2 point](https://static.reallyme.net/zk/crs/01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f/bn254_g2.dat).
Consumers check each file against the toolchain lock before use.

Barretenberg holds the CRS process-wide. A proving process initializes the
pinned full-prover CRS before verifying proofs; a verifier-only process can
initialize the pinned smaller verifier profile. The two profiles are not mixed
within one process.

## Release verification

The release gate runs against the exact source revision and sealed artifacts.
It requires circuit compilation, witness generation, proving, verification,
and negative tests for modified proofs, public inputs, verification keys,
artifact identities, and session bindings. It checks the Noir soundness
regressions, linked-library and independent CLI interoperability, source and
artifact hashes, native package freshness, and Swift and Android presentation
flows. The [release readiness runner](../../scripts/check_release_readiness.mjs)
checks repository policy and packaging boundaries. Passing those checks does
not replace the proof and device tests.

The toolchain lock records `candidateMatchedPair.status = "promoted"` for
the approved compiler and backend pair. Release builds use those exact pins
and run the validation gates against the source revision and distributed
packages. The `claim_bundle_4` diagnostic is outside the production circuit
contract.

Use these pinned compiler and backend versions to generate release artifacts.
Package publication and deployment have their own checks in the
[release procedures](../rust-publishing.md).
