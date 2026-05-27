using System.Security.Cryptography;
using System.Text;

namespace Countersign.Internal;

internal static class Mac
{
    public static byte[] Compute(byte[] secret, string message, SignatureAlgorithm algorithm)
    {
        byte[] data = Encoding.UTF8.GetBytes(message);
        using HMAC hmac = Create(algorithm, secret);
        return hmac.ComputeHash(data);
    }

    public static bool FixedTimeEquals(byte[] a, byte[] b)
    {
#if NET8_0_OR_GREATER
        return CryptographicOperations.FixedTimeEquals(a, b);
#else
        if (a.Length != b.Length)
        {
            return false;
        }

        int diff = 0;
        for (int i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }

        return diff == 0;
#endif
    }

    private static HMAC Create(SignatureAlgorithm algorithm, byte[] key)
    {
        return algorithm switch
        {
            SignatureAlgorithm.HmacSha256 => new HMACSHA256(key),
            SignatureAlgorithm.HmacSha512 => new HMACSHA512(key),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported signature algorithm."),
        };
    }
}
