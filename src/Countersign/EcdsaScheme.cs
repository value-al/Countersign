using System.Security.Cryptography;
using Countersign.Internal;

namespace Countersign;

/// <summary>
/// Asymmetric ECDSA signing/verification. Sign with a private key; verify with the provider's public
/// key. Supports both DER and IEEE-P1363 signature encodings (see <see cref="EcdsaSignatureFormat"/>).
/// </summary>
/// <remarks>The supplied <see cref="ECDsa"/> key is not disposed by this scheme — the caller owns it.</remarks>
public sealed class EcdsaScheme : ISignatureScheme
{
    private readonly ECDsa _key;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly EcdsaSignatureFormat _format;
    private readonly int _coordinateSize;

    /// <summary>Creates an ECDSA scheme.</summary>
    /// <param name="key">An <see cref="ECDsa"/> with a private key (to sign) or public key (to verify).</param>
    /// <param name="hashAlgorithm">The hash to sign over. Defaults to <see cref="HashAlgorithmName.SHA256"/>.</param>
    /// <param name="format">The signature encoding. Defaults to <see cref="EcdsaSignatureFormat.Der"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    public EcdsaScheme(ECDsa key, HashAlgorithmName? hashAlgorithm = null, EcdsaSignatureFormat format = EcdsaSignatureFormat.Der)
    {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        _hashAlgorithm = hashAlgorithm ?? HashAlgorithmName.SHA256;
        _format = format;
        _coordinateSize = (key.KeySize + 7) / 8;
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] message)
    {
        byte[] ieee = _key.SignData(message, _hashAlgorithm); // .NET produces IEEE P1363
        return _format == EcdsaSignatureFormat.Der ? EcdsaSignature.P1363ToDer(ieee) : ieee;
    }

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature)
    {
        byte[] ieee;
        if (_format == EcdsaSignatureFormat.Der)
        {
            if (!EcdsaSignature.TryDerToP1363(signature, _coordinateSize, out ieee))
            {
                return false;
            }
        }
        else
        {
            ieee = signature;
        }

        try
        {
            return _key.VerifyData(message, ieee, _hashAlgorithm);
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
