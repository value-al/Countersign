namespace Countersign.Internal;

/// <summary>
/// Converts ECDSA signatures between IEEE P1363 (fixed-length r||s) and ASN.1 DER. .NET's
/// <c>ECDsa.SignData/VerifyData</c> work in P1363; this lets us offer DER everywhere (the clean
/// DSASignatureFormat API is net7+ only, so we hand-roll the minimal encoding for netstandard2.0).
/// </summary>
internal static class EcdsaSignature
{
    public static byte[] P1363ToDer(byte[] p1363)
    {
        int half = p1363.Length / 2;
        var r = new byte[half];
        var s = new byte[half];
        Buffer.BlockCopy(p1363, 0, r, 0, half);
        Buffer.BlockCopy(p1363, half, s, 0, half);

        byte[] rInt = ToDerInteger(r);
        byte[] sInt = ToDerInteger(s);

        using var ms = new MemoryStream();
        ms.WriteByte(0x30); // SEQUENCE
        WriteLength(ms, rInt.Length + sInt.Length);
        ms.Write(rInt, 0, rInt.Length);
        ms.Write(sInt, 0, sInt.Length);
        return ms.ToArray();
    }

    public static bool TryDerToP1363(byte[] der, int coordinateSize, out byte[] p1363)
    {
        p1363 = Array.Empty<byte>();
        try
        {
            int pos = 0;
            if (der.Length < 2 || der[pos++] != 0x30)
            {
                return false;
            }

            int seqLen = ReadLength(der, ref pos);
            if (seqLen < 0 || pos + seqLen != der.Length)
            {
                return false;
            }

            if (pos >= der.Length || der[pos++] != 0x02)
            {
                return false;
            }

            int rLen = ReadLength(der, ref pos);
            if (rLen < 0 || pos + rLen > der.Length)
            {
                return false;
            }

            byte[] r = Slice(der, pos, rLen);
            pos += rLen;

            if (pos >= der.Length || der[pos++] != 0x02)
            {
                return false;
            }

            int sLen = ReadLength(der, ref pos);
            if (sLen < 0 || pos + sLen > der.Length)
            {
                return false;
            }

            byte[] s = Slice(der, pos, sLen);

            if (!TryToFixed(r, coordinateSize, out byte[] rFixed) ||
                !TryToFixed(s, coordinateSize, out byte[] sFixed))
            {
                return false;
            }

            var result = new byte[coordinateSize * 2];
            Buffer.BlockCopy(rFixed, 0, result, 0, coordinateSize);
            Buffer.BlockCopy(sFixed, 0, result, coordinateSize, coordinateSize);
            p1363 = result;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] ToDerInteger(byte[] value)
    {
        int start = 0;
        while (start < value.Length - 1 && value[start] == 0)
        {
            start++;
        }

        int len = value.Length - start;
        bool pad = (value[start] & 0x80) != 0; // prepend 0x00 so it stays positive
        var content = new byte[len + (pad ? 1 : 0)];
        int offset = 0;
        if (pad)
        {
            content[offset++] = 0x00;
        }

        Buffer.BlockCopy(value, start, content, offset, len);

        using var ms = new MemoryStream();
        ms.WriteByte(0x02); // INTEGER
        WriteLength(ms, content.Length);
        ms.Write(content, 0, content.Length);
        return ms.ToArray();
    }

    private static bool TryToFixed(byte[] integer, int size, out byte[] result)
    {
        result = Array.Empty<byte>();
        int start = 0;
        while (start < integer.Length && integer[start] == 0)
        {
            start++;
        }

        int len = integer.Length - start;
        if (len > size)
        {
            return false;
        }

        var fixedBytes = new byte[size];
        Buffer.BlockCopy(integer, start, fixedBytes, size - len, len);
        result = fixedBytes;
        return true;
    }

    private static void WriteLength(Stream stream, int length)
    {
        if (length < 0x80)
        {
            stream.WriteByte((byte)length);
        }
        else if (length <= 0xFF)
        {
            stream.WriteByte(0x81);
            stream.WriteByte((byte)length);
        }
        else
        {
            stream.WriteByte(0x82);
            stream.WriteByte((byte)(length >> 8));
            stream.WriteByte((byte)(length & 0xFF));
        }
    }

    private static int ReadLength(byte[] data, ref int pos)
    {
        if (pos >= data.Length)
        {
            return -1;
        }

        int first = data[pos++];
        if (first < 0x80)
        {
            return first;
        }

        int numBytes = first & 0x7F;
        if (numBytes is 0 or > 2)
        {
            return -1;
        }

        int len = 0;
        for (int i = 0; i < numBytes; i++)
        {
            if (pos >= data.Length)
            {
                return -1;
            }

            len = (len << 8) | data[pos++];
        }

        return len;
    }

    private static byte[] Slice(byte[] data, int offset, int count)
    {
        var result = new byte[count];
        Buffer.BlockCopy(data, offset, result, 0, count);
        return result;
    }
}
