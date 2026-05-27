# Countersign

[![CI](https://github.com/value-al/Countersign/actions/workflows/ci.yml/badge.svg)](https://github.com/value-al/Countersign/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/v/Countersign.svg)](https://www.nuget.org/packages/Countersign)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Two-direction signing and webhook verification for payment/PSP integrations — in one small, dependency-free .NET library.

> **The insight behind it:** integrating a payment provider is two signing problems, not one.
> You **sign outbound** requests with your key, and you **verify inbound** webhooks with *theirs*.
> Those two directions usually use **different canonical forms** and **different secrets** — and conflating
> them is the bug that silently passes in the sandbox and fails in production. Countersign keeps the two
> directions explicitly separate so you can't mix them up.

## Why this exists

Every PSP integration re-implements the same crypto plumbing — HMAC over some canonical string, a header
to compare in constant time, a webhook secret that is *not* the API secret. It's easy to get subtly wrong:

- signing the wrong canonical form (raw body vs. `method+path+timestamp+body`),
- reusing the API secret to verify webhooks instead of the dedicated webhook secret,
- comparing signatures with `==` (timing leak) instead of a constant-time compare,
- verifying a *re-serialized* body instead of the exact received bytes,
- forgetting replay protection on the inbound timestamp.

Countersign packages these as two clearly separated concerns: **`RequestSigner`** (outbound) and
**`WebhookVerifier`** (inbound).

## Install

```sh
dotnet add package Countersign
```

Targets `netstandard2.0` and `net8.0`. **No runtime dependencies.**

## Sign an outbound request

```csharp
using Countersign;

var signer = new RequestSigner(
    secret: "sk_live_...",
    canonicalForm: CanonicalForms.MethodPathTimestampBody,
    algorithm: SignatureAlgorithm.HmacSha256,
    encoding: SignatureEncoding.Hex);

string signature = signer.Sign(new SignatureContext(
    body: requestBody,
    timestamp: unixSeconds,
    method: "POST",
    path: "/v1/charges"));

httpRequest.Headers.Add("X-Signature", signature);
```

## Verify an inbound webhook

Verify over the **raw received bytes** — never a parsed-then-re-serialized body, which can differ
byte-for-byte from what the provider signed.

```csharp
using Countersign;

// Note the *webhook* secret — usually different from the API secret above.
var verifier = new WebhookVerifier(
    webhookSecret: "whsec_...",
    canonicalForm: CanonicalForms.TimestampDotBody,
    tolerance: TimeSpan.FromMinutes(5)); // rejects stale/replayed messages

var result = verifier.Verify(
    new SignatureContext(rawBodyBytes, timestamp: headerTimestamp),
    providedSignature: headerSignature,
    messageTimestamp: DateTimeOffset.FromUnixTimeSeconds(long.Parse(headerTimestamp)));

if (result != VerificationResult.Valid)
{
    // VerificationResult.SignatureMismatch | MalformedSignature | Expired
    return Results.Unauthorized();
}
```

Comparison is constant-time. When a `tolerance` is configured, `Verify` requires a `messageTimestamp`
and returns `Expired` if it falls outside the window.

### ASP.NET Core minimal API

```csharp
var verifier = new WebhookVerifier("whsec_...", CanonicalForms.TimestampDotBody, tolerance: TimeSpan.FromMinutes(5));

app.MapPost("/webhooks/psp", async (HttpRequest req) =>
{
    using var ms = new MemoryStream();
    await req.Body.CopyToAsync(ms);
    byte[] rawBody = ms.ToArray();           // the exact bytes the provider signed

    string timestamp = req.Headers["X-Timestamp"]!;
    string signature = req.Headers["X-Signature"]!;

    var result = verifier.Verify(
        new SignatureContext(rawBody, timestamp: timestamp),
        signature,
        DateTimeOffset.FromUnixTimeSeconds(long.Parse(timestamp)));

    return result == VerificationResult.Valid ? Results.Ok() : Results.Unauthorized();
});
```

### Key rotation (multiple candidate signatures)

When a provider sends signatures under both an old and a new key during rotation, pass them all —
verification succeeds if **any** matches:

```csharp
var result = verifier.Verify(context, new[] { sigFromHeaderV1, sigFromHeaderV2 }, messageTimestamp);
```

## Signature schemes

HMAC is the default, but the same `Sign`/`Verify` works with any `ISignatureScheme`. For providers that
sign with a private key, verify with their **public key** by passing an asymmetric scheme:

| Scheme | Type | Notes |
| --- | --- | --- |
| `HmacScheme` | symmetric | HMAC-SHA256/384/512 (and SHA-1 for legacy). Same secret both sides; constant-time verify. |
| `RsaScheme` | asymmetric | RSA — PKCS#1 v1.5 or PSS. Verify with the provider's public key. |
| `EcdsaScheme` | asymmetric | ECDSA — DER **or** IEEE-P1363 signatures (providers differ; match theirs). |

```csharp
// Verify an RSA-signed webhook with the provider's public key:
using var rsa = RSA.Create();
rsa.ImportFromPem(providerPublicKeyPem); // net8+
var verifier = new WebhookVerifier(
    new RsaScheme(rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
    CanonicalForms.RawBody,
    SignatureEncoding.Base64);

var result = verifier.Verify(new SignatureContext(rawBody), headerSignature);

// ECDSA — JOSE/ES256 uses the IEEE-P1363 format; classic APIs use DER:
var ec = ECDsa.Create();
ec.ImportFromPem(providerPublicKeyPem);
var es256 = new EcdsaScheme(ec, HashAlgorithmName.SHA256, EcdsaSignatureFormat.Ieee1363);
```

All built-in schemes use the .NET BCL, so the core stays **dependency-free**. Ed25519 ships separately
as `Countersign.Ed25519` (it needs a crypto dependency) to keep that promise.

## Canonical forms

A canonical form is just a `CanonicalFormBuilder` — `SignatureContext → byte[]` — so you can supply your
own for any provider. The presets emit ASCII metadata followed by the **raw body bytes**:

| Preset | Produces | Typical use |
| --- | --- | --- |
| `CanonicalForms.RawBody` | `body` | many inbound webhooks |
| `CanonicalForms.TimestampDotBody` | `{timestamp}.` + `body` | Stripe-style signed webhooks |
| `CanonicalForms.MethodPathTimestampBody` | `{method}\n{path}\n{timestamp}\n` + `body` | outbound requests |

### Choosing one

- Read the provider's docs for the **string-to-sign** (a.k.a. "signed payload" / "canonical request").
- If it's just the body, use `RawBody`.
- If it prefixes a timestamp (to bind the signature to a moment, for replay protection), use
  `TimestampDotBody` — and configure a `tolerance`.
- If it includes the HTTP method and path (typical for *outbound* request signing), use
  `MethodPathTimestampBody`.
- Anything else: write a one-line `CanonicalFormBuilder`. Match the provider's separators and byte order
  exactly — a single stray newline changes the HMAC.

## Security

Countersign is a signing/verification **primitive**, so its boundaries matter:

- **It provides** HMAC authenticity, constant-time comparison, replay tolerance, and exact-byte signing.
- **It does not** store/rotate your secrets, provide transport security (use TLS), or parse provider
  headers — you extract the signature value(s) and pass them in.

Treat every non-`Valid` result as "reject". See [SECURITY.md](SECURITY.md) for the full threat model
and how to report a vulnerability privately.

## Status

`0.2.0-alpha` — HMAC (SHA-256/384/512/1), RSA (PKCS#1 + PSS), and ECDSA (DER + IEEE-P1363) schemes,
raw-byte bodies, canonical-form presets, constant-time HMAC compare, replay tolerance, and
multi-signature verification, covered by 36 tests (including RFC 4231 known-answer vectors and
RSA/ECDSA BCL-interop), running on `net8.0` and `net48`. The public API is snapshot-tested.
See [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
