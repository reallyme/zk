# Changelog

## 0.3.2

- Align API, artifacts, proto, proto-codec, and backend-bb Rust packages at
  `0.3.2`, including their workspace and fuzz dependency versions.
- Update the optional SSI stack-error contract and linked-wallet conformance
  dependency pins to SSI `0.6.2`.

## 0.3.1

- Swift and Kotlin retain their existing provider interfaces and Boolean
  `verifyDiagnosticStage` signatures. Production native builds reject standalone
  stage verification with the typed `UNSUPPORTED_TRANSPORT` error. Credential
  acceptance requires status-qualified bundle verification and atomic consumption
  of the active session.
- Refreshed Apple and Android native binaries include the standalone verification
  guard. Linked regression tests cover production refusal, diagnostic verification
  of a forged envelope relation, and rejection of that envelope in a joined bundle.
- Swift and Kotlin SDK package versions are validated independently of the public
  Rust crates, which remain at `0.3.0`.

## 0.3.0

Initial release.
