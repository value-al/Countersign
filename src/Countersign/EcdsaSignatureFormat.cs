namespace Countersign;

/// <summary>How an ECDSA signature's <c>(r, s)</c> pair is encoded — providers differ, and a mismatch
/// is a common integration bug.</summary>
public enum EcdsaSignatureFormat
{
    /// <summary>
    /// ASN.1 DER <c>SEQUENCE</c> of two <c>INTEGER</c>s (also called Rfc3279). Common in classic and
    /// REST/X.509-style APIs.
    /// </summary>
    Der,

    /// <summary>
    /// IEEE P1363: fixed-length big-endian <c>r</c> concatenated with <c>s</c>. Common in JOSE/JWT
    /// (e.g. ES256).
    /// </summary>
    Ieee1363,
}
