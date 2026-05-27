using System.Globalization;
using System.Text;

namespace Countersign.Internal;

internal static class Hex
{
    public static string Encode(byte[] bytes, bool upperCase)
    {
        string format = upperCase ? "X2" : "x2";
        var builder = new StringBuilder(bytes.Length * 2);
        foreach (byte b in bytes)
        {
            builder.Append(b.ToString(format, CultureInfo.InvariantCulture));
        }

        return builder.ToString();
    }

    public static bool TryDecode(string value, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (value.Length == 0 || value.Length % 2 != 0)
        {
            return false;
        }

        var result = new byte[value.Length / 2];
        for (int i = 0; i < result.Length; i++)
        {
            int high = FromHexChar(value[i * 2]);
            int low = FromHexChar(value[(i * 2) + 1]);
            if (high < 0 || low < 0)
            {
                return false;
            }

            result[i] = (byte)((high << 4) | low);
        }

        bytes = result;
        return true;
    }

    private static int FromHexChar(char c)
    {
        if (c >= '0' && c <= '9')
        {
            return c - '0';
        }

        if (c >= 'a' && c <= 'f')
        {
            return (c - 'a') + 10;
        }

        if (c >= 'A' && c <= 'F')
        {
            return (c - 'A') + 10;
        }

        return -1;
    }
}
