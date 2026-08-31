# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-08-31

First stable release. No API changes since 0.2.0-alpha.1; the public surface is frozen under
semantic versioning from here.

### Why now
- In production use as the webhook boundary of [Remit](https://github.com/value-al/Remit), a
  reference money-movement backend: every inbound PSP webhook is verified with `WebhookVerifier`
  over the raw bytes, per-provider secret, `TimestampDotBody`, five-minute tolerance — and its
  test-suite signs with `RequestSigner`, so both directions are exercised end to end.
- 36 tests including RFC 4231 known-answer vectors and RSA/ECDSA BCL interop, on net8.0 and net48;
  the public API is snapshot-tested.

### Changed
- Repository-local `nuget.config` pinning nuget.org, so builds never touch a private feed.
- README: a "Design notes" section recording the three decisions the library is built on.

## [0.2.0-alpha.1] - 2026-05-27

### Added
- `ISignatureScheme` abstraction; `RequestSigner` and `WebhookVerifier` gain scheme-based constructors.
- `RsaScheme` — asymmetric RSA signatures, PKCS#1 v1.5 and PSS padding.
- `EcdsaScheme` — asymmetric ECDSA signatures, both DER and IEEE-P1363 signature formats.
- `HmacScheme` — the existing HMAC, now a first-class, reusable scheme.
- HMAC-SHA384 and HMAC-SHA1 (legacy, provider-mandated only) algorithms.

### Notes
- **Backward compatible** — the existing string/byte-secret HMAC constructors are unchanged.
- Core stays dependency-free (RSA/ECDSA use the BCL). Ed25519 will ship as a separate
  `Countersign.Ed25519` package so the core keeps zero runtime dependencies.

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
- Public API snapshot test (PublicApiGenerator); `net48` test leg exercising the netstandard2.0 build.
- `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates, Dependabot.
- Release automation: a GitHub Actions workflow publishes to NuGet on a `v*` tag.

[Unreleased]: https://github.com/value-al/Countersign/compare/v0.2.0-alpha.1...HEAD
[0.2.0-alpha.1]: https://github.com/value-al/Countersign/compare/v0.1.0-alpha.1...v0.2.0-alpha.1
[0.1.0-alpha.1]: https://github.com/value-al/Countersign/releases/tag/v0.1.0-alpha.1
