namespace Countersign;

/// <summary>
/// Builds the canonical string that gets HMAC-signed, from the parts of a request or webhook.
/// Different providers canonicalize differently — and the outbound and inbound directions often
/// differ from each other — so this is a plug-in point. See <see cref="CanonicalForms"/> for presets.
/// </summary>
/// <param name="context">The available request/webhook parts.</param>
/// <returns>The exact string to sign.</returns>
public delegate string CanonicalFormBuilder(SignatureContext context);

/// <summary>Canonical forms commonly seen in payment-provider integrations.</summary>
public static class CanonicalForms
{
    /// <summary>The raw body, signed as-is. The simplest and most common inbound webhook form.</summary>
    public static readonly CanonicalFormBuilder RawBody = context => context.Body;

    /// <summary>
    /// <c>{timestamp}.{body}</c> — a timestamp, a literal dot, then the body. Used by Stripe-style
    /// signed webhooks. Requires <see cref="SignatureContext.Timestamp"/>.
    /// </summary>
    public static readonly CanonicalFormBuilder TimestampDotBody = context =>
        context.Timestamp is null
            ? throw new InvalidOperationException("CanonicalForms.TimestampDotBody requires SignatureContext.Timestamp.")
            : context.Timestamp + "." + context.Body;

    /// <summary>
    /// <c>{method}\n{path}\n{timestamp}\n{body}</c> — newline-separated. A common outbound request
    /// form. Requires <see cref="SignatureContext.Method"/>, <see cref="SignatureContext.Path"/>,
    /// and <see cref="SignatureContext.Timestamp"/>.
    /// </summary>
    public static readonly CanonicalFormBuilder MethodPathTimestampBody = context =>
    {
        if (context.Method is null || context.Path is null || context.Timestamp is null)
        {
            throw new InvalidOperationException(
                "CanonicalForms.MethodPathTimestampBody requires Method, Path, and Timestamp.");
        }

        return string.Join("\n", context.Method, context.Path, context.Timestamp, context.Body);
    };
}
