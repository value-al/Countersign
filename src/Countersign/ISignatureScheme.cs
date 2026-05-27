namespace Countersign;

/// <summary>
/// A signing/verification strategy over raw bytes. Decouples <see cref="RequestSigner"/> and
/// <see cref="WebhookVerifier"/> from the underlying algorithm. Built-in implementations:
/// <see cref="HmacScheme"/> (symmetric), <see cref="RsaScheme"/> and <see cref="EcdsaScheme"/> (asymmetric).
/// </summary>
public interface ISignatureScheme
{
    /// <summary>Produces a signature over <paramref name="message"/>.</summary>
    /// <param name="message">The exact bytes to sign (the canonical form output).</param>
    /// <returns>The raw signature bytes (before any hex/base64 encoding).</returns>
    byte[] Sign(byte[] message);

    /// <summary>Checks whether <paramref name="signature"/> is valid for <paramref name="message"/>.</summary>
    /// <param name="message">The exact bytes that were signed.</param>
    /// <param name="signature">The raw signature bytes (already decoded from hex/base64).</param>
    /// <returns><c>true</c> if the signature is valid; otherwise <c>false</c>. Never throws for a bad signature.</returns>
    bool Verify(byte[] message, byte[] signature);
}
