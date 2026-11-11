# Poseidon2 circuit families

Each family uses the Poseidon2 hash lane for credential commitments. The proof
suite independently selects the UltraHonk transcript and masking mode.

| Family | Presentation contract |
| --- | --- |
| [`credential_subject_claim_v1`](credential_subject_claim_v1/README.md) | One selected claim and control of the hidden credential subject key. |
| [`private_persona_claim_v1`](private_persona_claim_v1/README.md) | One selected claim presented through a hidden, subject-authorized persona. |
| [`persona_credential_evidence_v1`](persona_credential_evidence_v1/README.md) | Credential evidence and current issuer status joined to a public or one-time private holder key. |
| [`common_credential_root_v1`](common_credential_root_v1/README.md) | Two exact credentials with common assured-root provenance and one presenting persona. |

The direct and private-persona claim families split claim evidence into
`session`, `credential_envelope`, `credential_root`, and `claim` stages.
Their additional `claim_bundle_4` source circuits are diagnostic and are
outside the production presentation contract.

Each family reference defines its statements, public inputs, proof joins, and
privacy limits. The [circuit inventory](../../README.md) and
[provider policy](../../../PROVIDER_POLICY.md) define artifact and provider
compatibility requirements.
