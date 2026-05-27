using Countersign;

namespace Countersign.Tests;

public class KnownAnswerTests
{
    // RFC 4231, Test Case 2.
    private const string Rfc4231Key = "Jefe";
    private const string Rfc4231Data = "what do ya want for nothing?";

    [Fact]
    public void HmacSha256_RawBody_Hex_matches_rfc4231_vector()
    {
        var signer = new RequestSigner(Rfc4231Key, CanonicalForms.RawBody, SignatureAlgorithm.HmacSha256, SignatureEncoding.Hex);
        string signature = signer.Sign(new SignatureContext(Rfc4231Data));
        Assert.Equal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", signature);
    }

    [Fact]
    public void HmacSha512_RawBody_Hex_matches_rfc4231_vector()
    {
        var signer = new RequestSigner(Rfc4231Key, CanonicalForms.RawBody, SignatureAlgorithm.HmacSha512, SignatureEncoding.Hex);
        string signature = signer.Sign(new SignatureContext(Rfc4231Data));
        Assert.Equal(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            signature);
    }

    [Fact]
    public void HexUpper_is_uppercase_of_hex()
    {
        var lower = new RequestSigner(Rfc4231Key, encoding: SignatureEncoding.Hex).Sign(new SignatureContext(Rfc4231Data));
        var upper = new RequestSigner(Rfc4231Key, encoding: SignatureEncoding.HexUpper).Sign(new SignatureContext(Rfc4231Data));
        Assert.Equal(lower.ToUpperInvariant(), upper);
    }
}
