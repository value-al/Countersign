namespace Countersign;

/// <summary>How a signature is encoded as text on the wire.</summary>
public enum SignatureEncoding
{
    /// <summary>Lowercase hexadecimal.</summary>
    Hex,

    /// <summary>Uppercase hexadecimal.</summary>
    HexUpper,

    /// <summary>Base64.</summary>
    Base64,
}
