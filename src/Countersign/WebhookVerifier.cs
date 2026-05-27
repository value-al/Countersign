using System.Text;
using Countersign.Internal;

namespace Countersign;

/// <summary>
/// Verifies inbound webhooks using the provider's webhook secret — which is normally a different
/// secret from your API key. This is the "counter-verify" half of Countersign; the outbound half
/// is <see cref="RequestSigner"/>. Comparison is constant-time, and an optional tolerance guards
/// against replayed (stale) messages.
/// </summary>
public sealed class WebhookVerifier
{
    private readonly byte[] _webhookSecret;
    private readonly CanonicalFormBuilder _canonicalForm;
    private readonly SignatureAlgorithm _algorithm;
    private readonly SignatureEncoding _encoding;
    private readonly TimeSpan? _tolerance;
    private readonly Func<DateTimeOffset> _clock;

    /// <summary>Creates a verifier from a raw webhook secret.</summary>
    /// <param name="webhookSecret">The provider's webhook signing key. Must not be empty.</param>
    /// <param name="canonicalForm">How the provider builds the string it signs. Defaults to <see cref="CanonicalForms.RawBody"/>.</param>
    /// <param name="algorithm">The HMAC algorithm. Defaults to <see cref="SignatureAlgorithm.HmacSha256"/>.</param>
    /// <param name="encoding">How the provider encodes the signature. Defaults to <see cref="SignatureEncoding.Hex"/>.</param>
    /// <param name="tolerance">Optional maximum clock skew for the message timestamp. When set, <see cref="Verify"/> requires a timestamp and rejects messages outside the window.</param>
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
    {
        if (webhookSecret is null)
        {
            throw new ArgumentNullException(nameof(webhookSecret));
        }

        if (webhookSecret.Length == 0)
        {
            throw new ArgumentException("Webhook secret must not be empty.", nameof(webhookSecret));
        }

        _webhookSecret = webhookSecret;
        _canonicalForm = canonicalForm ?? CanonicalForms.RawBody;
        _algorithm = algorithm;
        _encoding = encoding;
        _tolerance = tolerance;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>Creates a verifier from a UTF-8 string webhook secret.</summary>
    /// <param name="webhookSecret">The provider's webhook signing key. Must not be null or empty.</param>
    /// <param name="canonicalForm">How the provider builds the string it signs. Defaults to <see cref="CanonicalForms.RawBody"/>.</param>
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
        : this(ToBytes(webhookSecret), canonicalForm, algorithm, encoding, tolerance, clock)
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

        byte[] expected = Mac.Compute(_webhookSecret, _canonicalForm(context), _algorithm);
        if (!SignatureEncoder.TryDecode(providedSignature, _encoding, out byte[] provided))
        {
            return VerificationResult.MalformedSignature;
        }

        if (!Mac.FixedTimeEquals(expected, provided))
        {
            return VerificationResult.SignatureMismatch;
        }

        if (_tolerance.HasValue)
        {
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

            if (skew > _tolerance.Value)
            {
                return VerificationResult.Expired;
            }
        }

        return VerificationResult.Valid;
    }

    private static byte[] ToBytes(string secret)
    {
        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        return Encoding.UTF8.GetBytes(secret);
    }
}
