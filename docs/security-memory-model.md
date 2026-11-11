# Memory Ownership and Residual Risk

ReallyMe ZK handles issuer material, holder keys, claims, witness inputs, and
serialized witness stacks as secrets. Repository-owned Rust buffers use
zeroizing owners and bounded decoding. Platform FFI returns owned buffers with
matching destruction paths; callers must destroy them promptly after use.

## Ownership boundaries

- The application owns private inputs until it submits an operation. It must
  clear its original buffers after transfer and must not log request bodies.
- The Rust operation boundary validates and copies private inputs into
  short-lived zeroizing owners. A proof provider must not retain references to
  caller-owned buffers after dispatch.
- The Noir ABI input-map owner recursively overwrites fields, strings,
  vectors, and map keys on success and error, and is dropped immediately after
  ABI encoding. Strings and keys use a zeroizing write. Field elements are an
  upstream type with no zeroizing implementation, so they are overwritten in
  place with an ordinary store that is kept visible to the optimizer; this is
  best-effort rather than a volatile-write guarantee.
  Error variants carrying rejected values or parser text are scrubbed before
  mapping to a typed public error. Noir's own encoding clones remain outside
  this owner's erasure guarantee.
- Serialized witness and proving-command owners clear their current buffers
  when dropped. The proving-command builder reserves its expected capacity to
  reduce secret-bearing reallocations. This does not establish that every
  allocation is wiped before being freed on every input and failure path. A successful
  proof also does not imply that the originating application buffer was cleared.
- The backend adapter counts decompressed witness bytes through a zeroizing
  scratch buffer before allocating the exact plaintext capacity. It then
  rejects any second-pass growth, so decoding does not free an earlier
  plaintext allocation while growing a vector. This does not cover
  copies created by the downstream native prover, or the internal state of
  the gzip encoder and decoder, which see witness plaintext and release their
  windows without overwriting them.
- Witness-domain encoders borrow secret arrays from their owners and place
  temporary claim aggregates in zeroizing owners before filling them. Some
  FFI inputs are still assembled on the stack before transfer to a zeroizing
  owner. Compiler-generated transient copies also have no verified erasure
  path. They may remain accessible to an attacker who can read process memory.
- Swift, Kotlin, JNI, and C callers must use the matching release operation for
  returned native buffers. A foreign runtime's garbage collector is not a
  zeroization guarantee.
- Swift and Kotlin request wrappers redact their own string representations,
  but generated protobuf messages containing private inputs are ordinary
  runtime objects. Directly logging or reflecting those messages can reveal
  claims, keys, or salts. Callers must keep raw messages out of logs and
  diagnostics, limit their lifetime, and clear any mutable source buffers.
  Wrapper redaction does not erase immutable protobuf storage or copies made
  by the foreign runtime.
- The native Swift and Kotlin providers clear their mutable serialized request
  and response buffers after dispatch. Kotlin also clears its mutable request
  digest owner and compares response digests without allocating another digest
  array. Swift clears the corresponding digest `Data`. Parsed protobuf response
  objects still retain immutable digest/proof/public-input storage until the
  foreign runtime releases them; that storage is outside the repository's
  byte-overwrite guarantee.

## Mitigation hierarchy

Production Swift, Kotlin, JNI, and C integrations should keep secrets in native
memory whenever the API permits it. Witnesses, credential subject claims,
subject keys, salts, issuer material, and derived proving inputs should remain
inside native retained handles. Foreign runtimes pass opaque handle identifiers
and receive proofs, verification results, or typed errors.

When a secret-bearing buffer must cross a foreign-runtime boundary, callers
must keep it mutable, bound its lifetime to the dispatch operation, and wipe it
immediately after transfer using the platform's explicit byte-fill primitive.
This provides best-effort cleanup. Garbage collectors, immutable objects,
protobuf storage, and interned strings can still retain copies.

Complete erasure has not been established for ACVM, Barretenberg, or foreign
runtimes. Proving it requires allocator-level tests that check every
secret-bearing allocation is wiped on both success and failure.

## Upstream memory

ReallyMe's byte-compatible witness serializer zeroizes its uncompressed
MessagePack intermediate and compressed output and prevents its own buffers
from reallocating while they contain witness bytes. Noir ABI and ACVM still
create additional `InputMap`, `WitnessMap`, and `WitnessStack` copies without
verified zeroizing owners. Upstream field serialization also allocates one
temporary byte vector per witness value. Linked
Barretenberg also makes internal copies outside this repository's Rust owner
model. Those copies can remain in process memory after a proof completes.
Repository-level buffer cleanup does not erase them.
The [upstream erasure review](provenance/upstream-secret-erasure-review.md)
traces these allocations in the pinned source and describes the tests needed
to establish complete erasure.

The optional `bb.js` adapter overwrites the caller's witness buffer and its
own copy. `bb.js` decompresses the witness, copies it into WebAssembly linear
memory, and may pass it to a worker. WebAssembly memory is not cleared when
freed and does not shrink, so those copies last until the instance or worker
is discarded. Browser and Node proving should run in a dedicated worker or
page that is destroyed after use.

Until those upstream lifetimes and destruction paths are audited, production
deployments should keep proving processes short lived, avoid reusing them
across unrelated holders, and treat process memory, core dumps, swap, and crash
reports as sensitive. This release does not guarantee complete memory
erasure at the ACVM or Barretenberg boundary.
An in-process mobile prover cannot rely on process termination after each
proof, so the residual exposure may persist for the app process lifetime.
For single-holder, on-device proving, keep inputs and witnesses out of logs,
uploads, crash dumps, and process-wide caches. Release buffers promptly and
treat a process memory compromise as a credential compromise. A shared or
multi-tenant proving service needs a separate security review. Neither deployment may claim
complete upstream memory erasure without direct evidence.
