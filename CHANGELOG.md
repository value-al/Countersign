# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Public API snapshot test (PublicApiGenerator) that guards against accidental breaking changes.
- `net48` test leg that exercises the `netstandard2.0` build on .NET Framework.
- `SECURITY.md` (threat model + private vulnerability reporting), `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, issue/PR templates, and Dependabot.
- Release automation: a GitHub Actions workflow publishes to NuGet on a `v*` tag.

## [0.1.0-alpha.1] - 2026-05-27

### Added
- `RequestSigner` (outbound) and `WebhookVerifier` (inbound) — deliberately separate, so the two
  secrets and two canonical forms can't be conflated.
- HMAC-SHA256 / HMAC-SHA512; hex, hex-upper, and base64 signature encodings.
- Canonical-form presets `RawBody`, `TimestampDotBody`, `MethodPathTimestampBody`, plus the
  `CanonicalFormBuilder` plug-in point for custom forms.
- Raw `byte[]` body support so the **exact received bytes** are signed/verified (with a UTF-8 string
  convenience overload).
- Constant-time signature comparison.
- Optional replay tolerance with an injectable clock.
- Multi-signature verification (verify-any) for key rotation.
- Multi-targets `netstandard2.0` and `net8.0`; no runtime dependencies.

[Unreleased]: https://github.com/value-al/Countersign/compare/v0.1.0-alpha.1...HEAD
[0.1.0-alpha.1]: https://github.com/value-al/Countersign/releases/tag/v0.1.0-alpha.1
