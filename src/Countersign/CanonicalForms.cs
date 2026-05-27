using Countersign.Internal;

namespace Countersign;

/// <summary>
/// Builds the canonical byte sequence that gets HMAC-signed, from the parts of a request or webhook.
/// Different providers canonicalize differently — and the outbound and inbound directions often differ
/// from each other — so this is a plug-in point. Working in bytes (not strings) lets the raw body be
/// signed exactly. See <see cref="CanonicalForms"/> for presets.
/// </summary>
/// <param name="context">The available request/webhook parts.</param>
/// <returns>The exact bytes to sign.</returns>
public delegate byte[] CanonicalFormBuilder(SignatureContext context);

/// <summary>Canonical forms commonly seen in payment-provider integrations.</summary>
public static class CanonicalForms
{
    /// <summary>The raw body, signed as-is. The simplest and most common inbound webhook form.</summary>
    public static readonly CanonicalFormBuilder RawBody = context => context.Body;

    /// <summary>
    /// <c>{timestamp}.{body}</c> — the timestamp and a literal dot (ASCII) followed by the raw body
    /// bytes. Used by Stripe-style signed webhooks. Requires <see cref="SignatureContext.Timestamp"/>.
    /// </summary>
    public static readonly CanonicalFormBuilder TimestampDotBody = context =>
        context.Timestamp is null
            ? throw new InvalidOperationException("CanonicalForms.TimestampDotBody requires SignatureContext.Timestamp.")
            : Payload.Prefixed(context.Timestamp + ".", context.Body);

    /// <summary>
    /// <c>{method}\n{path}\n{timestamp}\n{body}</c> — newline-separated metadata (ASCII) followed by
    /// the raw body bytes. A common outbound request form. Requires <see cref="SignatureContext.Method"/>,
    /// <see cref="SignatureContext.Path"/>, and <see cref="SignatureContext.Timestamp"/>.
    /// </summary>
    public static readonly CanonicalFormBuilder MethodPathTimestampBody = context =>
    {
        if (context.Method is null || context.Path is null || context.Timestamp is null)
        {
            throw new InvalidOperationException(
                "CanonicalForms.MethodPathTimestampBody requires Method, Path, and Timestamp.");
        }

        string prefix = string.Join("\n", context.Method, context.Path, context.Timestamp) + "\n";
        return Payload.Prefixed(prefix, context.Body);
    };
}
