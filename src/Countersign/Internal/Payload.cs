using System.Text;

namespace Countersign.Internal;

internal static class Payload
{
    /// <summary>Returns <c>UTF8(prefix)</c> followed by the raw <paramref name="body"/> bytes.</summary>
    public static byte[] Prefixed(string prefix, byte[] body)
    {
        byte[] head = Encoding.UTF8.GetBytes(prefix);
        var result = new byte[head.Length + body.Length];
        Buffer.BlockCopy(head, 0, result, 0, head.Length);
        Buffer.BlockCopy(body, 0, result, head.Length, body.Length);
        return result;
    }
}
