# ADR-0002 — Two directions, bytes in, schemes as plug-ins

**Status:** Accepted 2026-05-27 (recorded 2026-11-08 from the README's design notes)

## Context

A PSP integration has two signing problems: signing outbound requests with
your API secret, and verifying inbound webhooks with the provider's webhook
secret or public key. They use different secrets and usually different
canonical forms. The common bugs are mixing the two, verifying a
re-serialised body, comparing with `==`, and forgetting replay protection.

## Decision

1. **Two types, not one.** `RequestSigner` (outbound) and `WebhookVerifier`
   (inbound) are separate classes with separate constructors, so reusing the
   wrong secret or canonical form is a visible shape in the code, not a
   runtime surprise.
2. **Bytes in, not strings.** `SignatureContext` holds the raw body bytes
   (copied on construction) and canonical forms build `byte[]`. A provider
   signs the bytes it sent; anything re-serialised can differ by a space.
   String overloads exist for convenience and are UTF-8 encoded.
3. **The scheme is a plug-in; the policy is not.** `ISignatureScheme` lets
   HMAC, RSA and ECDSA share one verifier, but constant-time comparison,
   replay tolerance and multi-signature acceptance belong to the verifier and
   a scheme cannot turn them off. A scheme decides how to sign, never whether
   a result is valid.

## Consequences

- `WebhookVerifier.Verify` returns a `VerificationResult` (`Valid`,
  `SignatureMismatch`, `MalformedSignature`, `Expired`); callers treat
  everything but `Valid` as reject.
- With several candidate signatures the verifier checks all of them, without
  an early exit, so timing doesn't show which one matched.
- The architecture tests keep the directions apart and keep schemes free of
  verification policy.
