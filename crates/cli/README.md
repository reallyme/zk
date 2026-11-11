# reallyme-zk-cli

`reallyme-zk-cli` provides command-line access to the ReallyMe ZK protocol.
It uses the circuit registry in `reallyme-zk-api` and the transport limits in
`reallyme-zk-proto-codec`, without duplicating circuit definitions, protobuf
messages, artifact formats, witness generation, or proving logic.

Production proving and verification use the linked Barretenberg provider. The
CLI requires explicit manifest, artifact, CRS, and session-binding inputs; it
does not shell out to `bb` or `nargo` on production paths.

The `witness` command accepts one size-bounded compiled Noir artifact JSON and
its matching `Prover.toml`, runs the pinned ACVM witness executor, and emits a raw serialized
Noir witness stack. The resulting file must be paired with the same reviewed
artifact manifest and circuit reference before it is used for production
proving.
