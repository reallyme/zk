# ReallyMe ZK Release Assembly

This unpublished crate assembles the 24 production stage packages, six
canonical pre-manifest proving-vector sets, six proof-bearing post-manifest
verification-vector sets, and the canonical release index from already
verified proof outputs. It is release tooling, not a runtime provider.

Assembly can resume from retained proof outputs. For each hash, bundle kind, and
stage, the crate:

1. regenerates only the Nargo `WitnessStack::serialize()` witness;
2. re-derives a temporary verification key from the admitted program, compares
   it byte-for-byte with the retained key, and reverifies the retained proof
   and public inputs with the pinned Barretenberg adapter;
3. validates proof and witness bytes and places them in bounded typed owners;
4. zeroizes and removes the temporary witness file;
5. constructs the canonical seven-case bundle vector set;
6. writes and rechecks each deterministic artifact package under a new empty
   staging root;
7. binds the four concrete proofs to the four sealed manifest identities and
   emits all 14 verification cases; and
8. writes and rechecks the six post-manifest vectors before writing `index.pb`
   as the release-readiness marker.

It never regenerates or replaces a retained proof or verification key. The
temporary verification key exists only for identity comparison and is
sanitized and removed. The output root must be empty, packages and the indexed
release use create-new persistence, and a failure leaves any completed staging
packages in place for inspection.
Promotion to the reviewed release tree is a separate operation; this crate
never overwrites `artifacts/`.

The CLI accepts nine explicit values and performs no `PATH` discovery:

```text
assemble-production-packages \
  <nargo> <nargo-sha256> <barretenberg> <barretenberg-sha256> <crs-directory> \
  <workspace-root> <retained-proof-matrix-root> <empty-output-root> \
  <release-version>
```

The default toolchain is Noir `1.0.0` with
Barretenberg `6.0.0`. The optional `--modern-candidate` flag is accepted for
older automation that already passed it, but it selects the same pinned
toolchain and command grammar as the default path.

Release hosts must use encrypted ephemeral storage. Best-effort witness-file
overwriting cannot guarantee erasure from copy-on-write filesystems or storage
media.
