# Circuits

This directory contains the Noir circuits. Each circuit version must keep its
source, artifact hashes, test vectors, and API capability metadata in sync.

The source is split by credential hash algorithm:

- `sha256/`
- `poseidon2/`

Both hash lanes contain the same circuit families:

| Family | Semantics | Stages |
| --- | --- | --- |
| `credential_subject_claim_v1` | One selected credential claim with a hidden subject | `session`, `credential_envelope`, `credential_root`, `claim` |
| `private_persona_claim_v1` | One selected claim authorized through a hidden persona | `session`, `credential_envelope`, `credential_root`, `claim` |
| `common_credential_root_v1` | Two issuer-bound selected claims with common assured-root provenance, current issuer status, and one persona session | `root_attestation`, `root_status`, `issuer_credential_status`, `lineage`, `private_persona_claim`, `public_persona_claim`, `public_session` |
| `persona_credential_evidence_v1` | A selected issuer-bound claim and current issuer status joined to a holder key, token nonce, and bounded proof window | `issuer_envelope`, `claim_root`, `signed_validity`, `public_claim`, `private_claim`, `current_state` |

There are 46 versioned circuits across both lanes: 16 baseline claim stages,
four diagnostic stages, fourteen common-credential-root stages, and twelve
persona-credential-evidence stages. The diagnostic `claim_bundle_4` circuits
are outside the production presentation contract. Common-credential-root
presentations use nine proofs; the [proof contract](../docs/common-credential-root-v1-proof-contract.md)
defines their order and joins.

The API registry identifies the persona-credential-evidence stages, and the
source lock and release index pin their versions. Mobile packages carry their
exact compiled bytecode and verification keys. Their
[circuit contract](sha256/families/persona_credential_evidence_v1/README.md) describes the
proof joins and verifier checks.

`ZkCircuitRef` identifies an exact source circuit by `credential_hash_algorithm`, `family`,
`stage`, and `version`. Policy code uses the smaller `ZkCircuitId` and
capabilities registry in `reallyme-zk-api`.

Generated Noir targets, proofs, verification keys, `node_modules`, and credential
script outputs are not part of the source tree. Reproducible build artifacts
belong in `crates/artifacts` manifests and must be hash-pinned to this source
tree.

Every claim tree has a fixed depth of six. Positions beyond the issued leaves
hold the empty subtree for that level, where an empty leaf is 32 zero bytes.
Each claim circuit accepts only a path of exactly six levels; the
`ProverShortPath` fixtures are correctly bound trees of a shorter depth that
must be rejected at that assertion.

The issuer's root construction and wallet restoration check canonical
padding. The circuits do not receive an authenticated issued-leaf count, so
they prove full-depth membership in the committed root without determining
which positions should be empty. Unused slots in a four-claim disclosure are
separate from unused leaves in the tree; the bundle circuits constrain those
disclosure slots to zero.

Fixtures are generated from repository source with synthetic keys:

| Family | Generator |
| --- | --- |
| `credential_subject_claim_v1`, `private_persona_claim_v1` | `scripts/generate-claim-family-fixtures.py` |
| `common_credential_root_v1` | `generate_split_fixtures.py` in each lane's family directory |
| `persona_credential_evidence_v1` | `scripts/generate-persona-credential-evidence-joined-fixtures.py` |

Checked-in `Prover.toml` files are deterministic circuit fixtures, not live
presentation tests. Their timestamps are fixed and must not be interpreted
against the current wall clock. Complete-bundle verifier tests check runtime
expiry and issuer-trust policy.
The baseline credential-family bundle validates issuer signatures and its
cross-stage joins; credential status remains an application policy input. The
common-credential-root family separately proves membership in an active-status snapshot
whose authenticity and freshness the verifier must establish.

## Signature and correlation boundaries

Stages that verify P-256 ECDSA use strict low-`s` signatures. Witness builders
must normalize a valid high-`s` signature to its low-`s` equivalent before
serializing witness material; they must never silently retry, weaken, or bypass
signature verification. A non-normalized high-`s` signature is rejected.
An individual stage proof is diagnostic evidence only. The credential-envelope
stage does not by itself establish issuer authenticity. The verifier must also
check the root signature and every cross-stage binding in the complete bundle.

The request-bound families' session-binding hashes are presentation-scoped,
not anonymous. Anyone who already knows the relevant subject or persona public
key and the public challenge, audience hash, transaction-data hash, and expiry
can recompute a session binding and test whether it belongs to that key.
Deployments requiring unlinkability against such a party must reject those
request-bound families. Private persona credential evidence uses a one-time holder
key and token nonce; its status feed must also avoid a per-credential public
identifier.

## Toolchain

The circuit-iteration scripts require `nargo` and `bb` and remain dev-only.
Production proving and verification use the repository's `backend-bb`
linked-library Barretenberg implementation through an injected provider.
The circuits use Noir `1.0.0` and Barretenberg `6.0.0`.

`circuits/toolchain-lock.json` pins the release archives, executables, static
libraries, and CRS. CI checks their hashes before compiling.

A production circuit version requires matching Noir source, artifact manifest,
verification-key hash, vectors, and `reallyme-zk-api` semantic capabilities.
