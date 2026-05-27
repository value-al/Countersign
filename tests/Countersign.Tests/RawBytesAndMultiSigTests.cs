using System.Text;
using Countersign;

namespace Countersign.Tests;

public class RawBytesAndMultiSigTests
{
    [Fact]
    public void Raw_byte_body_roundtrips()
    {
        const string secret = "whsec_123";
        byte[] body = { 0x00, 0x01, 0x02, 0xFA, 0xFF }; // non-UTF8-clean bytes
        var ctx = new SignatureContext(body);

        string sig = new RequestSigner(secret).Sign(ctx);
        Assert.Equal(VerificationResult.Valid, new WebhookVerifier(secret).Verify(ctx, sig));
    }

    [Fact]
    public void String_body_and_equivalent_byte_body_produce_the_same_signature()
    {
        var signer = new RequestSigner("whsec_123");
        string fromString = signer.Sign(new SignatureContext("hello"));
        string fromBytes = signer.Sign(new SignatureContext(Encoding.UTF8.GetBytes("hello")));
        Assert.Equal(fromString, fromBytes);
    }

    [Fact]
    public void Body_is_copied_so_later_mutation_does_not_change_the_signature()
    {
        byte[] body = Encoding.UTF8.GetBytes("hello");
        var ctx = new SignatureContext(body);
        string before = new RequestSigner("whsec_123").Sign(ctx);

        body[0] ^= 0xFF; // mutate the caller's array after constructing the context

        string after = new RequestSigner("whsec_123").Sign(ctx);
        Assert.Equal(before, after);
    }

    [Fact]
    public void Multi_signature_succeeds_when_any_matches()
    {
        const string secret = "whsec_123";
        var ctx = new SignatureContext("payload", timestamp: "1700000000");
        string good = new RequestSigner(secret, CanonicalForms.TimestampDotBody).Sign(ctx);

        var verifier = new WebhookVerifier(secret, CanonicalForms.TimestampDotBody);
        Assert.Equal(VerificationResult.Valid, verifier.Verify(ctx, new[] { "deadbeef", good }));
    }

    [Fact]
    public void Multi_signature_fails_when_none_match()
    {
        var verifier = new WebhookVerifier("whsec_123");
        Assert.Equal(VerificationResult.SignatureMismatch, verifier.Verify(new SignatureContext("payload"), new[] { "deadbeef", "zz" }));
    }

    [Fact]
    public void Multi_signature_empty_collection_throws()
    {
        var verifier = new WebhookVerifier("whsec_123");
        Assert.Throws<ArgumentException>(() => verifier.Verify(new SignatureContext("payload"), Array.Empty<string>()));
    }
}
