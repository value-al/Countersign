using Countersign.Internal;

namespace Countersign;

/// <summary>
/// Verifies inbound webhooks. This is the "counter-verify" half of Countersign; the outbound half is
/// <see cref="RequestSigner"/>. For HMAC, comparison is constant-time; for RSA/ECDSA, the provider's
/// public key verifies the signature. An optional tolerance guards against replayed (stale) messages.
/// Pass an <see cref="ISignatureScheme"/> for RSA/ECDSA, or a string/byte secret for the HMAC default.
/// </summary>
public sealed class WebhookVerifier
{
    private readonly ISignatureScheme _scheme;
    private readonly CanonicalFormBuilder _canonicalForm;
    private readonly SignatureEncoding _encoding;
    private readonly TimeSpan? _tolerance;
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>Creates a verifier from a signature scheme (e.g. <see cref="RsaScheme"/>, <see cref="EcdsaScheme"/>, <see cref="HmacScheme"/>).</summary>
    /// <param name="scheme">The verification strategy. For asymmetric schemes, build it with the provider's <b>public</b> key.</param>
    /// <param name="canonicalForm">How the provider builds the bytes it signs. Defaults to <see cref="CanonicalForms.RawBody"/>.</param>
    /// <param name="encoding">How the provider encodes the signature. Defaults to <see cref="SignatureEncoding.Hex"/>.</param>
    /// <param name="tolerance">Optional maximum clock skew for the message timestamp. When set, verification requires a timestamp and rejects messages outside the window.</param>
    /// <param name="clock">Optional time source, for testing. Defaults to <see cref="DateTimeOffset.UtcNow"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="scheme"/> is null.</exception>
    public WebhookVerifier(
        ISignatureScheme scheme,
        CanonicalFormBuilder? canonicalForm = null,
        SignatureEncoding encoding = SignatureEncoding.Hex,
        TimeSpan? tolerance = null,
        Func<DateTimeOffset>? clock = null)
    {
        _scheme = scheme ?? throw new ArgumentNullException(nameof(scheme));
        _canonicalForm = canonicalForm ?? CanonicalForms.RawBody;
        _encoding = encoding;
        _tolerance = tolerance;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Creates an HMAC verifier from a raw webhook secret.</summary>
    /// <param name="webhookSecret">The provider's webhook signing key. Must not be empty.</param>
    /// <param name="canonicalForm">How the provider builds the bytes it signs. Defaults to <see cref="CanonicalForms.RawBody"/>.</param>
    /// <param name="algorithm">The HMAC algorithm. Defaults to <see cref="SignatureAlgorithm.HmacSha256"/>.</param>
    /// <param name="encoding">How the provider encodes the signature. Defaults to <see cref="SignatureEncoding.Hex"/>.</param>
    /// <param name="tolerance">Optional maximum clock skew for the message timestamp.</param>
    /// <param name="clock">Optional time source, for testing. Defaults to <see cref="DateTimeOffset.UtcNow"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="webhookSecret"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="webhookSecret"/> is empty.</exception>
    public WebhookVerifier(
        byte[] webhookSecret,
        CanonicalFormBuilder? canonicalForm = null,
        SignatureAlgorithm algorithm = SignatureAlgorithm.HmacSha256,
        SignatureEncoding encoding = SignatureEncoding.Hex,
        TimeSpan? tolerance = null,
        Func<DateTimeOffset>? clock = null)
        : this(new HmacScheme(webhookSecret, algorithm), canonicalForm, encoding, tolerance, clock)
    {
    }

    /// <summary>Creates an HMAC verifier from a UTF-8 string webhook secret.</summary>
    /// <param name="webhookSecret">The provider's webhook signing key. Must not be null or empty.</param>
    /// <param name="canonicalForm">How the provider builds the bytes it signs. Defaults to <see cref="CanonicalForms.RawBody"/>.</param>
    /// <param name="algorithm">The HMAC algorithm. Defaults to <see cref="SignatureAlgorithm.HmacSha256"/>.</param>
    /// <param name="encoding">How the provider encodes the signature. Defaults to <see cref="SignatureEncoding.Hex"/>.</param>
    /// <param name="tolerance">Optional maximum clock skew for the message timestamp.</param>
    /// <param name="clock">Optional time source, for testing. Defaults to <see cref="DateTimeOffset.UtcNow"/>.</param>
    public WebhookVerifier(
        string webhookSecret,
        CanonicalFormBuilder? canonicalForm = null,
        SignatureAlgorithm algorithm = SignatureAlgorithm.HmacSha256,
        SignatureEncoding encoding = SignatureEncoding.Hex,
        TimeSpan? tolerance = null,
        Func<DateTimeOffset>? clock = null)
        : this(new HmacScheme(webhookSecret, algorithm), canonicalForm, encoding, tolerance, clock)
    {
    }

    /// <summary>Verifies a received webhook signature (and, if a tolerance is configured, its freshness).</summary>
    /// <param name="context">The webhook parts the canonical form needs (typically the raw body and timestamp).</param>
    /// <param name="providedSignature">The signature received from the provider (e.g. from a header).</param>
    /// <param name="messageTimestamp">The webhook's timestamp; required when a tolerance was configured.</param>
    /// <returns>The verification outcome.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> or <paramref name="providedSignature"/> is null.</exception>
    /// <exception cref="ArgumentException">A tolerance was configured but <paramref name="messageTimestamp"/> was not supplied.</exception>
    public VerificationResult Verify(SignatureContext context, string providedSignature, DateTimeOffset? messageTimestamp = null)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (providedSignature is null)
        {
            throw new ArgumentNullException(nameof(providedSignature));
        }

        if (!SignatureEncoder.TryDecode(providedSignature, _encoding, out byte[] provided))
        {
            return VerificationResult.MalformedSignature;
        }

        if (!_scheme.Verify(_canonicalForm(context), provided))
        {
            return VerificationResult.SignatureMismatch;
        }

        return CheckTimestamp(messageTimestamp);
    }

    /// <summary>
    /// Verifies against several candidate signatures, succeeding if <b>any</b> matches. Useful during
    /// key rotation, when a provider sends signatures under both the old and new keys.
    /// </summary>
    /// <param name="context">The webhook parts the canonical form needs.</param>
    /// <param name="providedSignatures">The candidate signatures received from the provider.</param>
    /// <param name="messageTimestamp">The webhook's timestamp; required when a tolerance was configured.</param>
    /// <returns><see cref="VerificationResult.Valid"/> if any signature matches (and the timestamp, if checked, is fresh); otherwise <see cref="VerificationResult.SignatureMismatch"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> or <paramref name="providedSignatures"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="providedSignatures"/> is empty, or a tolerance was configured but <paramref name="messageTimestamp"/> was not supplied.</exception>
    public VerificationResult Verify(SignatureContext context, IEnumerable<string> providedSignatures, DateTimeOffset? messageTimestamp = null)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        if (providedSignatures is null)
        {
            throw new ArgumentNullException(nameof(providedSignatures));
        }

        byte[] message = _canonicalForm(context);

        bool any = false;
        bool matched = false;
        foreach (string candidate in providedSignatures)
        {
            any = true;
            if (candidate is not null
                && SignatureEncoder.TryDecode(candidate, _encoding, out byte[] provided)
                && _scheme.Verify(message, provided))
            {
                matched = true; // keep iterating so timing doesn't reveal which candidate matched
            }
        }

        if (!any)
        {
            throw new ArgumentException("At least one signature must be provided.", nameof(providedSignatures));
        }

        return matched ? CheckTimestamp(messageTimestamp) : VerificationResult.SignatureMismatch;
    }

    private VerificationResult CheckTimestamp(DateTimeOffset? messageTimestamp)
    {
        if (!_tolerance.HasValue)
        {
            return VerificationResult.Valid;
        }

        if (messageTimestamp is null)
        {
            throw new ArgumentException(
                "A message timestamp is required because this verifier was configured with a tolerance.",
                nameof(messageTimestamp));
        }

        TimeSpan skew = _clock() - messageTimestamp.Value;
        if (skew < TimeSpan.Zero)
        {
            skew = skew.Negate();
        }

        return skew > _tolerance.Value ? VerificationResult.Expired : VerificationResult.Valid;
    }
}
