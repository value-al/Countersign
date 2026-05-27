# Countersign

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
- forgetting replay protection on the inbound timestamp.

Countersign packages these as two clearly separated concerns: **`RequestSigner`** (outbound) and
**`WebhookVerifier`** (inbound).

## Install

```sh
dotnet add package Countersign
```

Targets `netstandard2.0` and `net8.0`, no third-party dependencies.

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

```csharp
using Countersign;

// Note the *webhook* secret — usually different from the API secret above.
var verifier = new WebhookVerifier(
    webhookSecret: "whsec_...",
    canonicalForm: CanonicalForms.TimestampDotBody,
    tolerance: TimeSpan.FromMinutes(5)); // rejects stale/replayed messages

var result = verifier.Verify(
    new SignatureContext(rawBody, timestamp: headerTimestamp),
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

## Canonical forms

A canonical form is just a `CanonicalFormBuilder` — `SignatureContext → string` — so you can supply your
own for any provider. Presets cover the common cases:

| Preset | Produces | Typical use |
| --- | --- | --- |
| `CanonicalForms.RawBody` | `body` | many inbound webhooks |
| `CanonicalForms.TimestampDotBody` | `"{timestamp}.{body}"` | Stripe-style signed webhooks |
| `CanonicalForms.MethodPathTimestampBody` | `"{method}\n{path}\n{timestamp}\n{body}"` | outbound requests |

## Status

`0.1.0-alpha` — core `Sign`/`Verify`, canonical-form presets, constant-time compare, and replay
tolerance are implemented and covered by tests (including RFC 4231 known-answer vectors). Not yet
published to NuGet.

## License

MIT — see [LICENSE](LICENSE).
