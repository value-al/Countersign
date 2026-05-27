using System.Text;
using Countersign.Internal;

namespace Countersign;

/// <summary>
/// Signs outbound requests with your secret. This is the "sign" half of Countersign; the inbound
/// half is <see cref="WebhookVerifier"/>. The two are deliberately separate because outbound and
/// inbound usually use different secrets and different canonical forms.
/// </summary>
public sealed class RequestSigner
{
    private readonly byte[] _secret;
    private readonly CanonicalFormBuilder _canonicalForm;
    private readonly SignatureAlgorithm _algorithm;
    private readonly SignatureEncoding _encoding;

    /// <summary>Creates a signer from a raw secret key.</summary>
    /// <param name="secret">The signing key bytes. Must not be empty.</param>
    /// <param name="canonicalForm">How to build the bytes to sign. Defaults to <see cref="CanonicalForms.RawBody"/>.</param>
    /// <param name="algorithm">The HMAC algorithm. Defaults to <see cref="SignatureAlgorithm.HmacSha256"/>.</param>
    /// <param name="encoding">How to encode the signature. Defaults to <see cref="SignatureEncoding.Hex"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="secret"/> is empty.</exception>
    public RequestSigner(
        byte[] secret,
        CanonicalFormBuilder? canonicalForm = null,
        SignatureAlgorithm algorithm = SignatureAlgorithm.HmacSha256,
        SignatureEncoding encoding = SignatureEncoding.Hex)
    {
        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        if (secret.Length == 0)
        {
            throw new ArgumentException("Secret must not be empty.", nameof(secret));
        }

        _secret = secret;
        _canonicalForm = canonicalForm ?? CanonicalForms.RawBody;
        _algorithm = algorithm;
        _encoding = encoding;
    }

    /// <summary>Creates a signer from a UTF-8 string secret.</summary>
    /// <param name="secret">The signing key. Must not be null or empty.</param>
    /// <param name="canonicalForm">How to build the bytes to sign. Defaults to <see cref="CanonicalForms.RawBody"/>.</param>
    /// <param name="algorithm">The HMAC algorithm. Defaults to <see cref="SignatureAlgorithm.HmacSha256"/>.</param>
    /// <param name="encoding">How to encode the signature. Defaults to <see cref="SignatureEncoding.Hex"/>.</param>
    public RequestSigner(
        string secret,
        CanonicalFormBuilder? canonicalForm = null,
        SignatureAlgorithm algorithm = SignatureAlgorithm.HmacSha256,
        SignatureEncoding encoding = SignatureEncoding.Hex)
        : this(ToBytes(secret), canonicalForm, algorithm, encoding)
    {
    }

    /// <summary>Computes the signature for the given request parts.</summary>
    /// <param name="context">The request parts the canonical form needs.</param>
    /// <returns>The encoded signature, ready to place in a header.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="context"/> is null.</exception>
    public string Sign(SignatureContext context)
    {
        if (context is null)
        {
            throw new ArgumentNullException(nameof(context));
        }

        byte[] mac = Mac.Compute(_secret, _canonicalForm(context), _algorithm);
        return SignatureEncoder.Encode(mac, _encoding);
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
