# Vendored Poseidon dependency

This directory contains the `Poseidon2` API used by the ReallyMe circuits,
vendored from `noir-lang/poseidon` release `v0.2.0` at commit
`4bc50d88dd8d94a00a95730fd76501e676417abf`.

The upstream project is licensed under Apache-2.0. The applicable license text
is included in the repository-level `LICENSE-APACHE` file. `src/lib.nr` was
reduced to expose only the upstream `poseidon2` module. The vendored
`src/poseidon2.nr` carries a file-local modification notice. Its cache
absorption was adapted for the pinned Noir compiler, and the source was
formatted for this repository. The dependency-integrity gate pins the reviewed
vendored tree, while cross-lane vectors check the resulting hash contract.
