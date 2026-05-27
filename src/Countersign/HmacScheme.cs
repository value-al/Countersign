using System.Text;
using Countersign.Internal;

namespace Countersign;

/// <summary>
/// Symmetric HMAC signing/verification — the same secret signs and verifies. Verification is
/// constant-time. This is the default scheme behind <see cref="RequestSigner"/> /
/// <see cref="WebhookVerifier"/> when you pass a string/byte secret.
/// </summary>
public sealed class HmacScheme : ISignatureScheme
{
    private readonly byte[] _secret;
    private readonly SignatureAlgorithm _algorithm;

    /// <summary>Creates an HMAC scheme from a raw secret key.</summary>
    /// <param name="secret">The shared secret. Must not be empty.</param>
    /// <param name="algorithm">The HMAC algorithm. Defaults to <see cref="SignatureAlgorithm.HmacSha256"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="secret"/> is empty.</exception>
    public HmacScheme(byte[] secret, SignatureAlgorithm algorithm = SignatureAlgorithm.HmacSha256)
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
        _algorithm = algorithm;
    }

    /// <summary>Creates an HMAC scheme from a UTF-8 string secret.</summary>
    /// <param name="secret">The shared secret. Must not be null or empty.</param>
    /// <param name="algorithm">The HMAC algorithm. Defaults to <see cref="SignatureAlgorithm.HmacSha256"/>.</param>
    public HmacScheme(string secret, SignatureAlgorithm algorithm = SignatureAlgorithm.HmacSha256)
        : this(ToBytes(secret), algorithm)
    {
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] message) => Mac.Compute(_secret, message, _algorithm);

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature) =>
        Mac.FixedTimeEquals(Mac.Compute(_secret, message, _algorithm), signature);

    private static byte[] ToBytes(string secret)
    {
        if (secret is null)
        {
            throw new ArgumentNullException(nameof(secret));
        }

        return Encoding.UTF8.GetBytes(secret);
    }
}
