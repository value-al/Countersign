# Golden principles — Countersign

Short code rules. Most are enforced by a test, the build or a scan; the weekly
cleanup agent opens small PRs where code drifts from them.

| # | Rule | Enforced by |
|---|---|---|
| 1 | No runtime dependencies: the core uses the .NET base class library only. Build-time tools get `PrivateAssets="all"`. | Architecture test |
| 2 | Outbound (`RequestSigner`) and inbound (`WebhookVerifier`) are separate types and never use each other. | Architecture test |
| 3 | Sign and verify the exact bytes. Canonical forms build `byte[]`; never re-serialise a body. | Unit tests, review |
| 4 | A scheme turns bytes into a signature and back; only the verifier decides `Valid`, `Expired` and the rest. | Architecture test |
| 5 | Compare MACs only with `Internal.Mac.FixedTimeEquals`. Never `==`, `SequenceEqual` or an early-exit loop. | Architecture test, review |
| 6 | With several candidate signatures, check all of them; no early exit. | Unit tests, review |
| 7 | Malformed input returns a result (`MalformedSignature`, `false`), never an unhandled exception; misuse by the caller (null, missing timestamp) throws `ArgumentException`. | Unit tests |
| 8 | Crypto behaviour has known-answer vectors where a standard publishes them (RFC 4231 for HMAC). | Review |
| 9 | Code must build for `netstandard2.0` and `net8.0`; newer APIs go behind `#if NET8_0_OR_GREATER` with a fallback. | Build, `net48` tests on Windows |
| 10 | Public classes are sealed; helpers live in `Countersign.Internal` and stay internal. | Architecture tests |
| 11 | The public API changes only on purpose: update `PublicApi.approved.txt` and `CHANGELOG.md`, follow semantic versioning. | `PublicApiTests` |
| 12 | Every public member has XML docs; warnings are errors. | Build (`Directory.Build.props`) |
| 13 | No secrets or private keys in the repo; tests generate keys at run time. | gitleaks in CI |
