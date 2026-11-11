# Upstream witness memory erasure

The repository zeroizes the serialized witness and proving-command buffers it
owns. Its witness serializer holds the uncompressed MessagePack
intermediate in a zeroizing owner, counts before allocating, and refuses
growth beyond the reserved capacity. That protection does not establish
erasure of every secret copy created while constructing the witness or proving
a circuit. The pinned versions use Noir revision
`275d3ab1a5c916c6ea73e8d6b943f685f574500c` and
Barretenberg revision `0219f11d8133970df3974fe5ae65e006bf8c193a`.

## Ownership trace

| Boundary | Secret-bearing allocation or copy | Erasure evidence |
| --- | --- | --- |
| Noir ABI | `InputMap` is a `BTreeMap<String, InputValue>`; `InputValue` can contain fields, strings, vectors, and nested maps. `Abi::encode` clones each parameter value on the successful path before converting it to fields, then builds an initial `WitnessMap`. Type-checking errors can clone a rejected value again. | ReallyMe recursively wipes its owned input map immediately after encoding and scrubs known parser and ABI error variants before dropping them. Upstream successful-path clones, encoded field vectors, and internal temporary allocations still lack a verified zeroizing drop. |
| Noir ACVM | `ACVM` owns a `WitnessMap` and call-result vectors. Completed maps enter a `WitnessStack`; child return values are copied into another vector. | No verified zeroizing drop on success or early error. |
| Noir serialization | The pinned `WitnessStack::serialize_with_format` creates an uncompressed ordinary `Vec<u8>` and then a gzip output vector. ReallyMe's witness generation uses a byte-compatible local serializer with zeroizing plaintext and compressed owners, fixed-capacity writes, and typed failure. | Byte-parity tests cover empty and nested witness stacks; fixture tests compare serialized witnesses after a serialize/decode round trip. This removes the known unwiped full-plaintext intermediate on ReallyMe's call path; it does not establish erasure of serializer internals or compiler temporaries. |
| Linked Barretenberg | The repository adapter decompresses the witness before constructing a C ABI command. The C ABI receives that command; upstream MessagePack decoding materializes a `CircuitProve` witness vector, then converts it into a circuit witness vector and prover state. | The adapter counts decompressed bytes with zeroizing scratch, allocates exact plaintext capacity, and rejects growth on its second pass. The repository shim wipes an upstream *output* buffer before freeing it. Neither measure establishes erasure of decoded C++ input, circuit, or prover allocations. |
| Swift/Kotlin mobile transport | SDK providers serialize proto requests into mutable mobile-runtime buffers, compute a request digest, dispatch into native FFI/JNI, then parse protobuf responses. Generated protobuf objects and Swift `Data`/JVM `ByteString` values can retain immutable copies. | Swift and Kotlin clear their mutable serialized request/response owners after dispatch; both clear the mutable request digest owner; Kotlin compares the response digest without allocating another digest array. This does not erase immutable generated-protobuf storage or custom transport copies retained outside the borrowed dispatch contract. |

Relevant pinned sources are the [Noir ABI input types](https://github.com/noir-lang/noir/blob/275d3ab1a5c916c6ea73e8d6b943f685f574500c/tooling/noirc_abi/src/input_parser/mod.rs),
[ACVM state](https://github.com/noir-lang/noir/blob/275d3ab1a5c916c6ea73e8d6b943f685f574500c/acvm-repo/acvm/src/pwg/mod.rs),
[witness stack serialization](https://github.com/noir-lang/noir/blob/275d3ab1a5c916c6ea73e8d6b943f685f574500c/acvm-repo/acir/src/native_types/witness_stack.rs),
and [Barretenberg proving](https://github.com/AztecProtocol/aztec-packages/blob/0219f11d8133970df3974fe5ae65e006bf8c193a/barretenberg/cpp/src/barretenberg/bbapi/bbapi_ultra_honk.cpp).
The repository call sites are `crates/noir-witness-core/src/execution.rs`,
`crates/noir-witness-core/src/witness_serialization.rs`, and
`crates/backend-bb/native/reallyme_bbapi_shim.cc`.

The source trace establishes that secret-bearing objects exist and that their
erasure is **unverified**. It does not establish how long any freed allocation
retains recoverable data on a particular device. A passing proof, explicit
cleanup of a repository-owned vector, or a wrapper's zeroizing `Drop` is not
evidence about copies created by upstream libraries or foreign runtimes.

## Evidence required for complete erasure

Complete witness erasure may be claimed only after every secret-bearing owner
in the pinned Noir, Barretenberg, and platform transport paths has a reviewed
destroy path on both success and failure, including ABI error copies,
serializer-internal buffers, and decoded C++ commands. Verify that claim with
allocator-instrumented tests that detect freeing secret-bearing storage before it is wiped, and repeat
the tests for each supported platform and toolchain revision. If that cannot be
established, document the remaining process-memory risk and account for it
when deciding whether to deploy.
