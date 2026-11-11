# Protobuf Compatibility Baseline

`reallyme-zk-v1.binpb` is the pinned Buf image for the current
`reallyme.zk.v1` contract. It includes the separate transport-neutral
`zk_service.proto` declaration and the persona-credential-evidence proof messages.

`scripts/check-proto-breaking.sh` checks the image's SHA-256 digest before Buf
compares it with the current schema. Changes to the image or digest require
protocol review.
