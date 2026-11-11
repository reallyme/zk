# Generated Proto Hardening

`core.mjs` hardens Buffa's generated code. It covers owned messages,
borrowed views, oneofs, unknown fields, redacted diagnostics, and zeroization.

`zk-scalar-policy.mjs` classifies every
`bytes` and `string` field in `manifest.proto`. Adding an unclassified scalar
field makes generation fail closed.

`../harden-zk-generated.mjs` supplies paths and policy to the shared hardener.
Keep transport and platform code generation separate from this step.

Sensitive bytes also use a generated zeroizing base64 serialization helper.
Buffa's general bytes serializer returns an ordinary temporary `String`; the
hardener routes standard encoding through `reallyme-codec` and zeroizes the
result immediately after Serde writes it. The ProtoJSON-compatible lenient
decoder owns its scratch allocation in `Zeroizing<Vec<u8>>`, clears a failed
standard-alphabet attempt before trying URL-safe input, and zeroizes either
successful or rejected proof, public-input, binding, digest, and witness bytes.
The direct `base64` decoder is deliberately narrow: protobuf ProtoJSON accepts
padded or unpadded standard and URL-safe alphabets, while ReallyMe Codec keeps
those public contracts separate and canonical.

Executable requests require stricter checks than the compatibility parser. The
sealed operation codec re-encodes the parsed message canonically and requires a
byte-for-byte match. Alternate Base64 alphabets or padding, non-canonical
trailing bits, numeric enum aliases, and additional JSON whitespace therefore
fail closed; the only permitted transport variation is one trailing line feed.

The repository wrapper also classifies `ZkWitness` as binary-only. The shared
hardener makes both direct Serde serialization and deserialization fail closed,
so callers cannot bypass the sealed ProtoJSON operation API by naming the
generated witness type. Buffa's `Message` contract requires generated messages
to implement `Clone`; production code does not clone proving DTOs, and each
sensitive generated owner retains explicit `clear()` and `Drop` zeroization.
Borrowed views for every direct or transitively sensitive message reject Serde
serialization. The hardener computes that closure from the protobuf message
graph, so adding a sensitive nested message also hardens every containing view.
Their bytes remain owned by the caller, while non-zeroizing, reference-counted
Buffa owned-view wrappers are removed from generated output and are not
re-exported. Canonical ProtoJSON remains available through the hardened owned
message types that have explicit zeroizing scratch policy.

Every generated message stores Buffa unknown fields in a generated
`ReallyMeZeroizingUnknownFields` owner. The wrapper preserves Buffa's required
unknown-field API and forwarding behavior while recursively zeroizing
length-delimited and grouped data on drop. This avoids adding `Drop` to every
message, which would invalidate Serde's generated field-move deserializers.

No generated owned-view wrapper is retained, including for messages whose
declared fields are public. An owned view keeps the complete original wire
buffer, so an unknown field could otherwise place arbitrary sensitive bytes in
non-zeroizing reference-counted memory. Borrowed views remain available and
keep buffer ownership explicit at the caller boundary.
