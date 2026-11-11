# Contract

This repository provides the ZK contract for the ReallyMe stack.

## API Contract

The public API includes:

- `ZkCircuitId`,
- `ZkCircuitCapabilities`,
- typed errors,
- proof/public-input/witness wrappers,
- structurally complete proof-bundle types,
- typed issuer-trust and verified-statement types, and
- stage and production-bundle prover/verifier traits.

It must not depend on Barretenberg, Noir, OpenID4VP, identity, wallet-core,
SDK packages, or service crates.

## Backend Contract

Backends implement the API traits and are injected at the top of the stack.
Backends return typed errors and never expose backend exception text, raw proof
bytes, public inputs, or witness data in errors.

Proofs must match the circuit-specific public-input descriptor before
they can be constructed. The API boundary uses a compact logical encoding;
linked Barretenberg providers alone translate that encoding to and from backend
field elements. A production bundle additionally requires consistent expiry,
session, envelope, and credential commitments across every stage that exposes
the corresponding field.

Request-bound claim verification requires a complete four-stage bundle. An
accepted claim statement requires every stage, the active session binding,
trusted issuer policy, and a trusted verifier clock. These four claim stages
do not establish an issuer-signed validity period or stable credential-status
handle; expiry and revocation must not be inferred from proof success.

## Format Contract

OpenID4VP owns the ZK `vp_token` proof format. The format layer validates:

- circuit identifier parsing,
- proof byte shape,
- derived-claim statements,
- nonce binding,
- verifier/audience binding,
- transaction-data binding for circuit versions that advertise it,
- unsupported verifier behavior.

The current v1 circuits bind the transaction-data hash as a public input.
When the request has no transaction data, they bind the reserved absence
sentinel. The format layer compares the decoded input with the active
OpenID4VP request and rejects an attempt to supply the sentinel as actual
transaction data.

The four request-bound claim stages do not prove issuer-signed validity periods
or revocation state. Those checks require separate verifier evidence. Private
v1 presentations may still permit correlation by an envelope observer or
issuer; callers that require unlinkability must reject them rather than infer a
guarantee from the name.

## Transport Contract

`reallyme-zk-proto` owns the uncompressed Buffa/protobuf and Buffa protobuf JSON
boundary for artifact manifests, proof bundles, provider requests, provider
responses, and ZK error reasons. The versioned message schema is message-only;
the separate, transport-neutral `zk_service.proto` imports it to declare the
provider service. Connect dependencies, generated Connect output, and concrete
HTTP/Connect adapters are excluded from the message crate and belong to SDKs,
apps, and services.

Executable proving operations and witness-bearing values are binary-only.
Every witness carries the closed `ZkWitnessEncoding` discriminator; production
currently admits only `NoirWitnessStackV1`, the serialized output of the typed
repository witness generator. Identity and claim fields must not be
duplicated in this repository's transport or API types.
Canonical ProtoJSON remains available only through the bounded, validated codec
for approved contracts. This codec admits a strict canonical subset: it rejects
snake_case field names, numeric enum values, numeric representations of uint64,
null aliases, and unpadded base64 even where general proto3 JSON decoders might
accept them. Generated sensitive borrowed views also reject JSON,
and all generated views are borrowed-only so a reference-counted owned wire
buffer cannot outlive its explicit cleanup owner. Every generated message owns
unknown fields through a recursively zeroizing wrapper.

Compression belongs at the transport or package layer. ZK crates must use the
shared identity Brotli implementation and keep compression out of proof and
provider domain logic.

## Artifact Contract

Production artifacts are content-addressed. A circuit source change is not
complete unless the artifact manifest, vector hashes, and API capability
registry move with it in the same commit.
