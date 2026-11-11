# Noir source and toolchain security profile

The [toolchain lock](../circuits/toolchain-lock.json) pins the compiler,
Barretenberg libraries, CRS, and circuits. Release builds check the hashes of
these inputs as well as the public-input ABI and proof suite. Matching version
numbers alone are insufficient.

## Toolchain

The source circuits target Noir `1.0.0` with Barretenberg `6.0.0`.
The toolchain lock records this pair as approved for production artifact
generation. Release checks cover circuit execution, linked-library proving
and verification, negative vectors, repeat runs, memory use, and device tests. Each provider package also
requires its own conformance tests. Earlier compiler and backend versions
are unsupported by the current source tree.

The production proof suite is UltraHonk with a Keccak transcript, zero
knowledge enabled, and IPA accumulation disabled. The `sha256` and
`poseidon2` source lanes select the hash used *inside the circuit*; neither
name changes the UltraHonk transcript.

## Source constraints

The 20 request-bound circuits, fourteen common-credential-root stages, and
twelve persona-credential-evidence stages use fixed-size arrays, bounded loops,
field arithmetic, SHA-256 or Poseidon2, and asserted
ECDSA verification. The source profile excludes unconstrained source
functions, source-authored Brillig, dynamic slices, signed and 128-bit integer
types, mutable references outside
method receivers, and unused cryptographic black boxes.

`scripts/check-noir-security-profile.mjs` checks this source profile. Its
result must be paired with compiler-produced ABI checks and executable
positive and negative proof vectors. A source scan alone cannot establish
constraint soundness or proof-system behavior.

## Required tests

Release builds must pass every check in `candidateMatchedPair.requiredPromotionGate`
in the toolchain lock for the 20 request-bound circuits. Common-credential-root
tests also cover its fourteen source circuits and complete nine-proof presentation.
Tests cover each production bundle stage, wrong-key and
wrong-session negatives, canonical proof mutations, input boundaries,
bounded-hash tail behavior, compiler advisory regressions, repeat runs, and
per-circuit memory peaks.
Swift and Android builds must use the same pinned artifacts and libraries as
their runtime proof tests.

The compiler soundness regressions require tampered witnesses to fail the
pinned prover's internal proof verification. Crashes, missing CRS data, and
unrelated CLI failures do not satisfy that check. They also mutate a valid
proof without changing its length and require the standalone verifier to
reject it.

The release process must validate the exact source tree, compiler revision,
public-input ABI, artifact hashes, CRS identity, and proof-suite settings
before packaging artifacts. Changes to these inputs require rerunning the
tests and reviewing their results. The [provenance reference](provenance/toolchain-artifact-provenance.md)
lists the pinned inputs and validation checks.

## Security limits

The circuits depend on properties they do not enforce themselves:

- **Claim tree depth and padding.** Every claim circuit accepts only a
  Merkle path of exactly six levels, so a digest in a leaf position cannot
  stand for a subtree of further claims. Positions beyond the issued leaves
  hold the empty subtree for that level; an empty leaf is 32 zero bytes.
  Issuer root recomputation and wallet restoration check this padding. The
  circuits do not receive an authenticated issued-leaf count and therefore
  establish full-depth membership without identifying unused leaf positions.
  The issuer-side root check in
  `reallyme-zk-api` builds the fixed-depth tree and derives the reserved
  lineage leaf from the wallet's salted claim digest instead of accepting a
  finished leaf. The Rust admission layers reject a claim path of any other
  length before proving.
- **Envelope signatures.** Stages that verify an issuer signature over the
  hidden envelope digest take that digest as an unconstrained private input.
  Such a check can be satisfied for any public key, so it authenticates
  nothing on its own. Issuer authentication rests on the `BINDMRK1`,
  `BINDSUB1`, and `BINDVLD1` signatures, whose digests are computed in
  circuit, and on verifying the complete joined proof set.
- **Public-key validity.** The persona-link and holder-authorization
  transcripts bind a compressed key, that is, the x coordinate and the parity
  of y, while the full coordinates are passed to the ECDSA verification
  gadget. The circuits do not assert the curve equation and rely on the
  pinned Barretenberg gadget to reject a point that is not on P-256. Keys
  exposed as public inputs must also be validated on curve by the verifier.
  This behaviour of the pinned gadget has not been independently verified in
  this repository.
- **Status purpose.** A status proof covers the single issuer-signed status
  pointer and purpose it presents. A verifier that needs both revocation and
  suspension must require evidence for each.

The upstream witness executor and proving library can retain internal copies
of private inputs beyond ReallyMe-owned zeroizing buffers. The
[memory model](security-memory-model.md) defines those ownership boundaries
and the application controls for on-device proving. CRS files are pinned by
SHA-256; see [Aztec Ignition provenance](provenance/toolchain-artifact-provenance.md#common-reference-string).
Mobile resource tests use the exact release package.

## Standalone stage diagnostics

Production native FFI rejects the `VerifyStage` operation with
`UNSUPPORTED_TRANSPORT`. Local diagnostic builds can enable the
`reallyme-zk-platform-ffi` Cargo feature `diagnostic-stage-verification`.
The `diagnostic-exact-source` feature also enables it.

Swift and Kotlin retain the Boolean `verifyDiagnosticStage` API for source
compatibility. Production native builds return a typed unsupported-transport
error. In diagnostic builds, a successful result establishes that the standalone
circuit relation held for the expected public binding. Credential acceptance for
the staged claim format requires status-qualified bundle verification and atomic
consumption of the active session.
