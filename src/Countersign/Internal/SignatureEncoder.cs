namespace Countersign.Internal;

internal static class SignatureEncoder
{
    public static string Encode(byte[] bytes, SignatureEncoding encoding)
    {
        return encoding switch
        {
            SignatureEncoding.Hex => Hex.Encode(bytes, upperCase: false),
            SignatureEncoding.HexUpper => Hex.Encode(bytes, upperCase: true),
            SignatureEncoding.Base64 => Convert.ToBase64String(bytes),
            _ => throw new ArgumentOutOfRangeException(nameof(encoding), encoding, "Unsupported signature encoding."),
        };
    }

    public static bool TryDecode(string value, SignatureEncoding encoding, out byte[] bytes)
    {
        switch (encoding)
        {
            case SignatureEncoding.Hex:
            case SignatureEncoding.HexUpper:
                return Hex.TryDecode(value, out bytes);

            case SignatureEncoding.Base64:
                try
                {
                    bytes = Convert.FromBase64String(value);
                    return true;
                }
                catch (FormatException)
                {
                    bytes = Array.Empty<byte>();
                    return false;
                }

            default:
                bytes = Array.Empty<byte>();
                return false;
        }
    }
}
