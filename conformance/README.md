# ReallyMe ZK Conformance

This unpublished crate runs canonical post-manifest verification
vectors against an injected `ZkPresentationBoundClaimBundleVerifier`. It contains no Barretenberg,
FFI, JNI, WASM, filesystem, network, or ambient-provider implementation.

The harness decodes the bounded canonical protobuf vector set, then passes each
case through the strict operation decoder. Mutations rejected before provider
dispatch must produce their exact typed `ZkErrorReason`; structurally valid
proof mutations are dispatched to the injected verifier and must produce their
exact expected result or error. The harness returns only bounded counts and a
typed privacy-safe failure reason.

Native, Swift, Kotlin/Android, TypeScript/WebAssembly, and service providers should
run the same six release vector files through their adapters. A provider
that cannot inject a production verifier must fail closed rather than skipping
or treating the vectors as structural fixtures.

## OpenID4VP integration coverage

Verifier adapter tests cover request binding, format selection, issuer trust,
claim projection, and backend rejection. Wallet tests cover bundle encoding
against a verified request, claim policy, audience selection, and the one-item
transaction-data limit.

A linked Barretenberg integration test proves two credentials with different hidden
subject keys. It encodes their bundles through the wallet API and verifies them
through the OpenID4VP format adapter. It rejects a wrong nonce, audience,
transaction binding, or tampered proof. The same harness exercises signed
`direct_post` reservation and commit with a JOSE request verifier and fixture
trust resolver. Its in-memory session store accepts claims once and rejects
replay. It also rejects a DC API-bound proof submitted through an otherwise valid
DirectPost session.

The Digital Credentials API flow uses the verifier's non-authorizing
diagnostics operation. Production acceptance requires an injected Identity
service, a durable session store, a trusted request-object resolver, and
integration evidence for the exact release commit. The authorizing DC API
runtime is outside this test coverage. These tests do not establish deployment
trust or status resolution. The
[presentation binding contract](../docs/openid4vp-presentation-binding.md)
defines the request and claim rules exercised by this flow.
