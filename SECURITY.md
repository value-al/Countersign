# Security Policy

## Reporting a vulnerability

Please report security issues **privately** using GitHub's **"Report a vulnerability"** button
under this repository's **Security → Advisories** tab — not as a public issue. We aim to
acknowledge reports within a few days and will coordinate a fix and disclosure with you.

## Supported versions

Countersign is pre-1.0. Only the latest released version receives security fixes.

## Threat model — what Countersign does and does not do

Countersign is a small primitive for HMAC request signing and webhook signature verification.
Understanding its boundaries is part of using it safely.

**It helps with**

- **Authenticity & integrity** — HMAC-SHA256/512 over a canonical form you control.
- **Timing-safe comparison** — signatures are compared in constant time, so a wrong guess leaks
  no information about the correct value.
- **Replay resistance** — an optional timestamp tolerance rejects stale messages.
- **Exact-byte signing** — raw `byte[]` bodies are signed/verified as-is, avoiding the
  re-serialization mismatch that makes string-based verification fragile.

**It does NOT**

- **Store, rotate, or protect your secrets** — that's your responsibility (use a secret manager;
  never commit keys). Anyone with the key can forge valid signatures.
- **Provide transport security** — always use TLS; signatures are not a substitute.
- **Parse provider-specific signature headers** — you extract the value(s) and pass them in.
- **Make trust decisions for you** — you choose the canonical form, secret, and tolerance.

## Notes

- HMAC is not vulnerable to length-extension attacks, so prefix-style canonical forms
  (`{timestamp}.{body}`) are safe. Always match the exact form your provider documents.
- Verification distinguishes a malformed signature, a mismatch, and an expired timestamp so you
  can log/alert appropriately — but treat all non-`Valid` outcomes as "reject".
