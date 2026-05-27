# Contributing to Countersign

Thanks for your interest! Countersign aims to stay a **small, focused, dependency-free** primitive
for request signing and webhook verification. Contributions are welcome within that scope.

## Scope

In scope: signing, verification, canonical forms, encodings, correctness, security, docs, tests.

Out of scope (by design): a full PSP framework, provider-specific SDKs, HTTP client plumbing,
header parsing, secret storage. These keep the library small and auditable — please open a
discussion before proposing anything that grows the surface area.

## Getting started

```sh
git clone https://github.com/value-al/Countersign.git
cd Countersign
dotnet build
dotnet test
```

The library multi-targets `netstandard2.0` and `net8.0`; tests run on `net8.0` and `net48`
(the latter exercises the netstandard2.0 build on .NET Framework, Windows only).

## Before you open a PR

- **Add tests** for any behavior change. Crypto needs known-answer coverage where possible.
- **Keep zero runtime dependencies.** Build-time analyzers/SourceLink are fine (`PrivateAssets=all`).
- **Mind the public API.** `PublicApiTests` snapshots the surface; if you intentionally change it,
  copy `PublicApi.approved.txt.received.txt` over `PublicApi.approved.txt` and explain why.
- **Update `CHANGELOG.md`** under `## [Unreleased]`.
- Builds run with warnings-as-errors and full XML docs — document new public members.

## Commit & PR

- Keep PRs focused; describe the motivation and any security implications.
- CI (build + test on Linux and Windows) must pass.

By contributing, you agree your contributions are licensed under the [MIT License](LICENSE).
