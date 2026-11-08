# Architecture — Countersign

Five parts, as the value-al Architecture standard asks. Kept true by the
architecture tests in `tests/Countersign.ArchitectureTests` and by the
reviewer, who fails a PR that changes structure without updating this file.

## 1. System context

```mermaid
flowchart LR
    APP["Integrating app<br/>e.g. Remit"]
    CS["Countersign<br/>NuGet package, in-process<br/>netstandard2.0 + net8.0"]
    BCL[".NET base class library<br/>HMAC, RSA, ECDsa"]
    PSP["Payment provider (PSP)"]
    NG["nuget.org"]
    GH["GitHub Actions<br/>release.yml on a v* tag"]

    APP -- "Sign / Verify" --> CS
    CS --> BCL
    APP -- "signed request" --> PSP
    PSP -- "signed webhook" --> APP
    GH -- "dotnet nuget push" --> NG
    NG -. "package" .-> APP
```

Countersign makes no network calls, reads no files and stores nothing. It
gets bytes, secrets or keys, and signatures from the app, and returns a
signature string or a `VerificationResult`. Header parsing, secret storage and
transport security stay with the app (`SECURITY.md`).

## 2. Components and allowed dependencies

```mermaid
flowchart TD
    subgraph public["namespace Countersign (public API)"]
        RS["RequestSigner<br/>outbound"]
        WV["WebhookVerifier<br/>inbound, tolerance, multi-signature"]
        CF["CanonicalForms<br/>CanonicalFormBuilder"]
        CTX["SignatureContext<br/>body bytes, timestamp, method, path"]
        ISS["ISignatureScheme"]
        SCH["HmacScheme · RsaScheme · EcdsaScheme"]
        EN["enums: SignatureAlgorithm, SignatureEncoding,<br/>EcdsaSignatureFormat, VerificationResult"]
    end
    subgraph internal["namespace Countersign.Internal (internal)"]
        MAC["Mac<br/>HMAC + fixed-time compare"]
        ENC["SignatureEncoder · Hex"]
        PAY["Payload"]
        DER["EcdsaSignature<br/>DER ⇄ IEEE P1363"]
    end
    RS --> ISS
    RS --> CF
    RS --> ENC
    WV --> ISS
    WV --> CF
    WV --> ENC
    CF --> CTX
    CF --> PAY
    SCH -. implements .-> ISS
    SCH --> MAC
    SCH --> DER
    MAC --> EN
    ENC --> EN
```

Rules enforced by `tests/Countersign.ArchitectureTests`:

- Everything in `Countersign.Internal` is internal, and it never uses
  `RequestSigner`, `WebhookVerifier`, `ISignatureScheme` or a scheme.
- Schemes turn message bytes into signature bytes and back. They never use
  the signer, the verifier, `VerificationResult`, `SignatureContext`,
  canonical forms or encodings: validity is the verifier's decision.
- `RequestSigner` and `WebhookVerifier` never use each other.
- HMAC types and `CryptographicOperations` are used only in `Internal.Mac`,
  so every HMAC check goes through its fixed-time compare.
- Public non-static classes are sealed.
- The assembly references only the base class library.

The public surface itself is pinned by `PublicApiTests` against
`tests/Countersign.Tests/PublicApi.approved.txt`.

## 3. Key flows

**Verifying an inbound webhook**

```mermaid
sequenceDiagram
    participant App as integrating app
    participant WV as WebhookVerifier
    participant CF as canonical form
    participant S as scheme (e.g. HmacScheme)
    participant Mac as Internal.Mac
    App->>WV: Verify(context with raw body bytes, signature, messageTimestamp)
    WV->>WV: decode signature (hex / base64)
    alt cannot decode
        WV-->>App: MalformedSignature
    end
    WV->>CF: build message bytes from context
    WV->>S: Verify(message, signature bytes)
    S->>Mac: Compute HMAC, FixedTimeEquals
    alt no match
        WV-->>App: SignatureMismatch
    end
    WV->>WV: if tolerance set: |clock − messageTimestamp| ≤ tolerance
    WV-->>App: Valid or Expired
```

**Signing an outbound request**

```mermaid
sequenceDiagram
    participant App as integrating app
    participant RS as RequestSigner
    participant CF as canonical form
    participant S as scheme
    participant E as SignatureEncoder
    App->>RS: Sign(context: body, timestamp, method, path)
    RS->>CF: e.g. "{method}\n{path}\n{timestamp}\n" + body
    RS->>S: Sign(message bytes)
    S-->>RS: signature bytes
    RS->>E: encode (hex, HEX, base64)
    RS-->>App: signature string for the header
```

**Key rotation: several candidate signatures**

```mermaid
sequenceDiagram
    participant App as integrating app
    participant WV as WebhookVerifier
    participant S as scheme
    App->>WV: Verify(context, [sigOldKey, sigNewKey], messageTimestamp)
    WV->>WV: build message bytes once
    loop every candidate, no early exit
        WV->>S: Verify(message, candidate)
    end
    WV-->>App: Valid / Expired if any matched, else SignatureMismatch
```

## 4. Data model

No database: the library keeps no state between calls. These are the
in-memory types a call works with.

```mermaid
erDiagram
    WEBHOOK_VERIFIER ||--|| SIGNATURE_SCHEME : uses
    REQUEST_SIGNER ||--|| SIGNATURE_SCHEME : uses
    WEBHOOK_VERIFIER ||--|| CANONICAL_FORM : uses
    REQUEST_SIGNER ||--|| CANONICAL_FORM : uses
    CANONICAL_FORM ||--o{ SIGNATURE_CONTEXT : reads
    WEBHOOK_VERIFIER {
        enum encoding "Hex | HexUpper | Base64"
        timespan tolerance "optional, replay window"
        func clock "UtcNow unless injected"
    }
    REQUEST_SIGNER {
        enum encoding "Hex | HexUpper | Base64"
    }
    SIGNATURE_SCHEME {
        string kind "HMAC (secret) | RSA | ECDSA (key)"
        enum algorithm "HMAC: SHA256 | SHA384 | SHA512 | SHA1"
        string padding_or_format "RSA: PKCS1 | PSS; ECDSA: DER | P1363"
    }
    CANONICAL_FORM {
        string preset "RawBody | TimestampDotBody | MethodPathTimestampBody | custom"
    }
    SIGNATURE_CONTEXT {
        bytes body "copied on construction"
        string timestamp "optional"
        string method "optional"
        string path "optional"
        map extras "optional, for custom forms"
    }
```

## 5. Decision log

| Date | Decision | ADR |
|---|---|---|
| 2026-05-27 | `netstandard2.0` + `net8.0`, no runtime dependencies, BCL crypto only; Ed25519 in a separate package; xUnit with known-answer vectors and a public API snapshot | [ADR-0001](docs/adr/0001-targets-and-dependencies.md) |
| 2026-05-27 | Two types for two directions, bytes in, schemes as plug-ins while the verifier owns the policy | [ADR-0002](docs/adr/0002-two-directions-bytes-in-scheme-plug-in.md) |
