# ADR-0001 — Targets and dependencies

**Status:** Accepted 2026-05-27 (recorded 2026-11-08 from the code, README and CHANGELOG)

## Context

Countersign is meant for any .NET app that talks to a payment provider,
including older .NET Framework services. It sits on a security boundary, so
it has to be small enough to audit, and every dependency would be one more
thing a consumer has to trust.

## Decision

- **Targets:** `netstandard2.0` for reach (.NET Framework and older .NET
  Core) and `net8.0` for modern consumers. Code that differs between them
  sits behind `#if NET8_0_OR_GREATER` (for example the fixed-time compare in
  `Internal/Mac.cs`).
- **No runtime dependencies.** HMAC, RSA and ECDSA come from the .NET base
  class library. Build-time tools (SourceLink) use `PrivateAssets="all"`.
  Ed25519 needs a crypto dependency, so it ships as a separate package,
  `Countersign.Ed25519`.
- **Build:** warnings as errors, nullable on, full XML docs, deterministic and
  SourceLink-enabled packages with symbols.
- **Tests:** xUnit on `net8.0` and `net48` (the `net48` run exercises the
  `netstandard2.0` build on .NET Framework, Windows only). RFC 4231
  known-answer vectors for HMAC, BCL interop for RSA and ECDSA, and a public
  API snapshot (`PublicApiGenerator`) so a breaking change can't slip in.
- **Release:** a `v*` tag runs `release.yml`, which tests, packs and pushes to
  nuget.org and creates a GitHub Release. Semantic versioning; the API is
  frozen from 1.0.0.

## Consequences

- No `Span`-based or newer BCL APIs in shared code paths without a
  `netstandard2.0` fallback.
- The `net48` tests only run in the Windows CI job.
- Adding any runtime dependency is a design change: it needs a new ADR, and
  the architecture test `Library_depends_only_on_the_base_class_library`
  fails until then.
