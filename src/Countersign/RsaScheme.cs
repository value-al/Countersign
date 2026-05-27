using System.Security.Cryptography;

namespace Countersign;

/// <summary>
/// Asymmetric RSA signing/verification. Sign with a private key (your outbound requests); verify
/// with the provider's public key (their inbound webhooks). Supports PKCS#1 v1.5 and PSS padding.
/// </summary>
/// <remarks>The supplied <see cref="RSA"/> key is not disposed by this scheme — the caller owns it.</remarks>
public sealed class RsaScheme : ISignatureScheme
{
    private readonly RSA _key;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly RSASignaturePadding _padding;

    /// <summary>Creates an RSA scheme.</summary>
    /// <param name="key">An <see cref="RSA"/> with a private key (to sign) or public key (to verify).</param>
    /// <param name="hashAlgorithm">The hash to sign over. Defaults to <see cref="HashAlgorithmName.SHA256"/>.</param>
    /// <param name="padding">The signature padding. Defaults to <see cref="RSASignaturePadding.Pkcs1"/>; pass <see cref="RSASignaturePadding.Pss"/> for PSS.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    public RsaScheme(RSA key, HashAlgorithmName? hashAlgorithm = null, RSASignaturePadding? padding = null)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        _hashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
        _padding = padding ?? RSASignaturePadding.Pkcs1;
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] message) => _key.SignData(message, _hashAlgorithm, _padding);

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature)
    {
        try
        {
            return _key.VerifyData(message, signature, _hashAlgorithm, _padding);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
