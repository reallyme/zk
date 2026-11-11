# ZK Fuzzing Harnesses

Coverage-guided libFuzzer targets exercise the untrusted boundaries that turn
provider, artifact, proof, vector, and backend field bytes into validated domain
types. Arbitrary input must fail with typed errors or produce a valid bounded
value; it must never panic, overflow, bypass canonical protobuf checks, or reach
a backend call.

The fuzz crate is kept outside the production workspace because libFuzzer's
runtime uses unsafe code and `#![no_main]`; production crates remain under the
workspace's `unsafe_code = "deny"` policy. Harnesses contain no parser policy of
their own and call only public production validation functions.

## Targets

| Target | Production boundaries |
| --- | --- |
| `provider_operation` | Canonical binary provider request/response and strict request ProtoJSON |
| `artifact_contracts` | Artifact manifest, capability registry, and release index |
| `proof_contracts` | Proof-bearing response plus pre- and post-manifest vector sets |
| `protojson_contracts` | Sealed generated ProtoJSON messages and binary-only proving rejection |
| `public_input_abi` | Barretenberg field decoding and complete-proof normalization for every registered circuit |
| `claim_proof_contracts` | Exact proof package, status-qualified claim proof bundle, and common-credential-root raw public inputs |
| `persona_evidence_contracts` | Persona-credential-evidence proof set, stage proof, verifier request, and holder-authentication transcript |
| `root_status_contracts` | Root status snapshot, root-assurance attestation, active-set publication and path assignment, prepared claims, and wallet-stored credential plaintext |

The three codec targets above use the first input byte to select one decoder
and pass the remaining bytes to it. Their seeds are synthetic and carry no
credential, key, or witness material.

The provider target always exercises known-valid canonical binary request and
response bytes in addition to arbitrary input. Its corpus contains a valid
non-secret artifact lookup ProtoJSON request. For release validation, seed the
other corpora with canonical sealed manifests, indexes, and proof vectors from
each approved release. Do not add witnesses, plaintext claims, or private user
material.

The ProtoJSON corpus contains only public request/response fixtures plus a
synthetic proving selector whose witness list is empty. The proving seed exists
to exercise rejection before deserialization; real or
synthetic witness bytes must never be added to a JSON corpus.

## Running

Use the exact CI tool versions:

```sh
rustup toolchain install nightly-2026-09-15
cargo install cargo-fuzz --version 0.13.2 --locked

cargo +nightly-2026-09-15 fuzz build
cargo +nightly-2026-09-15 fuzz run provider_operation -- -runs=1000
```

CI builds all targets once from the committed fuzz lockfile. Affected pull
requests and pushes exercise every staged executable for 20 seconds with the
committed corpus. Scheduled and manually dispatched jobs reuse those executables
in parallel, run each target for five minutes, and retain evolved corpora and
crash artifacts. The runner validates target selection and execution limits;
missing executables and failed fuzz runs fail the job.

Local smoke validation can reuse a completed build through
`scripts/run-fuzz-smoke.sh`; without a binary-directory override it builds once
before running the configured targets. Smoke validation does not replace the
scheduled fuzz campaign.
