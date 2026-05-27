using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Countersign;

namespace Countersign.Tests;

public class SchemeTests
{
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("the exact message to sign");
    private static readonly byte[] Tampered = Encoding.UTF8.GetBytes("the exact message to sign!");

    // ---------- HMAC ----------

    [Theory]
    [InlineData(SignatureAlgorithm.HmacSha256)]
    [InlineData(SignatureAlgorithm.HmacSha384)]
    [InlineData(SignatureAlgorithm.HmacSha512)]
    [InlineData(SignatureAlgorithm.HmacSha1)]
    [SuppressMessage("Security", "CA5350:Do Not Use Weak Cryptographic Algorithms", Justification = "Verifying HMAC-SHA1 support against the BCL.")]
    public void Hmac_scheme_matches_the_bcl(SignatureAlgorithm algorithm)
    {
        byte[] key = Encoding.UTF8.GetBytes("topsecret");
        var scheme = new HmacScheme(key, algorithm);
        byte[] signature = scheme.Sign(Message);

        using HMAC bcl = algorithm switch
        {
            SignatureAlgorithm.HmacSha256 => new HMACSHA256(key),
            SignatureAlgorithm.HmacSha384 => new HMACSHA384(key),
            SignatureAlgorithm.HmacSha512 => new HMACSHA512(key),
            SignatureAlgorithm.HmacSha1 => new HMACSHA1(key),
            _ => throw new InvalidOperationException(),
        };

        Assert.Equal(bcl.ComputeHash(Message), signature);
        Assert.True(scheme.Verify(Message, signature));
        Assert.False(scheme.Verify(Tampered, signature));
    }

    // ---------- RSA ----------

    [Theory]
    [InlineData(false)] // PKCS#1 v1.5
    [InlineData(true)]  // PSS
    public void Rsa_signs_and_verifies(bool pss)
    {
        using var rsa = RSA.Create(2048);
        RSASignaturePadding padding = pss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        var scheme = new RsaScheme(rsa, HashAlgorithmName.SHA256, padding);

        byte[] signature = scheme.Sign(Message);

        Assert.True(scheme.Verify(Message, signature));
        Assert.True(rsa.VerifyData(Message, signature, HashAlgorithmName.SHA256, padding)); // interop with BCL
        Assert.False(scheme.Verify(Tampered, signature));

        RSASignaturePadding other = pss ? RSASignaturePadding.Pkcs1 : RSASignaturePadding.Pss;
        Assert.False(new RsaScheme(rsa, HashAlgorithmName.SHA256, other).Verify(Message, signature));
    }

    [Fact]
    public void Rsa_roundtrips_through_signer_and_verifier()
    {
        using var rsa = RSA.Create(2048);
        var scheme = new RsaScheme(rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        var ctx = new SignatureContext("{\"id\":\"evt_1\"}", timestamp: "1700000000");

        string sig = new RequestSigner(scheme, CanonicalForms.TimestampDotBody, SignatureEncoding.Base64).Sign(ctx);
        var verifier = new WebhookVerifier(scheme, CanonicalForms.TimestampDotBody, SignatureEncoding.Base64);

        Assert.Equal(VerificationResult.Valid, verifier.Verify(ctx, sig));
        Assert.Equal(VerificationResult.SignatureMismatch, verifier.Verify(new SignatureContext("{}", timestamp: "1700000000"), sig));
    }

    // ---------- ECDSA ----------

    [Theory]
    [InlineData(EcdsaSignatureFormat.Der)]
    [InlineData(EcdsaSignatureFormat.Ieee1363)]
    public void Ecdsa_signs_and_verifies(EcdsaSignatureFormat format)
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var scheme = new EcdsaScheme(ec, HashAlgorithmName.SHA256, format);

        byte[] signature = scheme.Sign(Message);

        Assert.True(scheme.Verify(Message, signature));
        Assert.False(scheme.Verify(Tampered, signature));
    }

    [Fact]
    public void Ecdsa_formats_are_not_interchangeable()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var der = new EcdsaScheme(ec, HashAlgorithmName.SHA256, EcdsaSignatureFormat.Der);
        var ieee = new EcdsaScheme(ec, HashAlgorithmName.SHA256, EcdsaSignatureFormat.Ieee1363);

        byte[] derSignature = der.Sign(Message);
        Assert.False(ieee.Verify(Message, derSignature));
    }

    [Fact]
    public void Ecdsa_ieee1363_interops_with_bcl()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var scheme = new EcdsaScheme(ec, HashAlgorithmName.SHA256, EcdsaSignatureFormat.Ieee1363);

        byte[] signature = scheme.Sign(Message);
        Assert.True(ec.VerifyData(Message, signature, HashAlgorithmName.SHA256)); // BCL expects P1363
    }

#if NET8_0_OR_GREATER
    [Fact]
    public void Ecdsa_der_interops_with_bcl()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var scheme = new EcdsaScheme(ec, HashAlgorithmName.SHA256, EcdsaSignatureFormat.Der);

        byte[] der = scheme.Sign(Message);
        Assert.True(ec.VerifyData(Message, der, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    }
#endif

    [Fact]
    public void Ecdsa_verify_rejects_garbage_without_throwing()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var scheme = new EcdsaScheme(ec, HashAlgorithmName.SHA256, EcdsaSignatureFormat.Der);

        Assert.False(scheme.Verify(Message, new byte[] { 0x30, 0x01, 0x00 }));
        Assert.False(scheme.Verify(Message, Array.Empty<byte>()));
    }
}
