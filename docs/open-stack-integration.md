# Open Stack Integration

`reallyme/zk` provides the proof contracts and providers used by
`reallyme/identity`: Rust traits, artifact validation, protobuf/Buffa messages,
and backend adapters. Identity provides the application SDKs.

## SSI

[`reallyme/ssi`](https://github.com/reallyme/ssi) has no dependency on
`reallyme-zk-api`. SSI owns credential, envelope, and status semantics without
importing ZK circuit types, defining a second circuit registry, calling a
prover or verifier, or linking `backend-bb` or Barretenberg.

The private `reallyme-zk-proto-codec` crate can enable `stack-error` to map a
typed ZK failure into SSI's shared error envelope. This transport adapter uses the
published `reallyme-ssi-proto` 0.6.1 contract. It is not part of
`reallyme-zk-api`, the public ZK crates, or the proving backend.

## OpenID4VCI

`reallyme/openid4vci` is issuer-focused. Its issuer can produce the signed
`reallyme_zk_v1` credential and bind it to the wallet's issuance intent. ZK
presentation proving and verification remain outside issuance.

Allowed:

- issuer code may use `reallyme-zk-api` for the shared credential binding and
  typed circuit contract;
- generated transport code may carry the ZK credential and issuance intent.

Forbidden:

- OpenID4VCI defining a circuit registry;
- OpenID4VCI linking `backend-bb`, Barretenberg, or a downstream ZK WebAssembly
  provider package;
- OpenID4VCI silently falling back from derivation to disclosure.

## OpenID4VP

OpenID4VP owns the ZK presentation format. It encodes the `vp_token` entry,
binds proof public inputs to the active request, applies issuer and claim
policy, and rejects a ZK presentation when no verifier is injected.

OpenID4VP depends on `reallyme-zk-api`, not on `backend-bb`. The ZK API
verifies circuit bindings supplied as hashes; OpenID4VP derives those
hashes from the authenticated request and enforces the wire-format rules.
The wallet and verifier must agree on nonce, audience, and transaction-data
preimages. A request that cannot fit the v1 ZK transaction-data ABI fails
closed.

Several bundles in one response are independent verified claims. Identity
must enforce the cross-bundle persona rule before treating them as one
persona presentation. The current OpenID4VP response pipeline does not
apply that rule automatically.

The [OpenID4VP presentation binding contract](openid4vp-presentation-binding.md)
defines the wire mapping, claim selection, response-mode limits, and
comparison rule. [Conformance](../conformance/README.md) records the linked
integration coverage and production validation requirements.

## SDKs And Apps

Applications, SDKs, and services select the proving and verification providers:

- native apps and SDKs consume the first-party Swift or Kotlin ZK provider
  packages when the ZK feature is enabled;
- Identity's combined WebAssembly module can include the `wasm` backend;
- browser or Node applications can opt into the ZK-owned
  `packages/bbjs-provider` adapter, which lazy-loads Aztec `bb.js` rather than
  bundling Barretenberg into the default SDK;
- verifier services may link a verifier backend;
- issuer services need no ZK backend.

`identity` owns the consumer package names and the single native/WebAssembly
module composition. ZK owns its provider packages and does not publish
a `wasm-bindgen` surface or standalone Rust WebAssembly binary. ZK contracts
cross the Identity boundary as owned proof, public-input, manifest, and
typed-error bytes or structs. Backend handles do not cross this boundary.

## Boundary Check

Run the boundary check from a workspace containing the sibling repositories:

```sh
scripts/check-open-stack-boundaries.sh
```

The script checks for duplicate circuit registries and forbidden backend
dependencies across the available open-stack siblings. CI checks out pinned
SSI, OpenID4VCI, and OpenID4VP revisions and fails if any required checkout is
missing. This CI lane does not pin or certify Identity and wallet revisions;
those integrations require separate validation against their release source.
A local run may skip missing siblings only through an explicit opt-out; a skip is not a
passing integration check.
