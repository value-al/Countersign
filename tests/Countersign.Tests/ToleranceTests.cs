using Countersign;

namespace Countersign.Tests;

public class ToleranceTests
{
    private const string Secret = "whsec_123";
    private static readonly DateTimeOffset MessageTime = DateTimeOffset.FromUnixTimeSeconds(1700000000);

    private static (SignatureContext Context, string Signature) SignedMessage()
    {
        var ctx = new SignatureContext("body", timestamp: "1700000000");
        string sig = new RequestSigner(Secret, CanonicalForms.TimestampDotBody).Sign(ctx);
        return (ctx, sig);
    }

    [Fact]
    public void Within_tolerance_is_valid()
    {
        var (ctx, sig) = SignedMessage();
        DateTimeOffset now = MessageTime.AddSeconds(120);
        var verifier = new WebhookVerifier(Secret, CanonicalForms.TimestampDotBody, tolerance: TimeSpan.FromMinutes(5), clock: () => now);

        Assert.Equal(VerificationResult.Valid, verifier.Verify(ctx, sig, MessageTime));
    }

    [Fact]
    public void Outside_tolerance_is_expired()
    {
        var (ctx, sig) = SignedMessage();
        DateTimeOffset now = MessageTime.AddMinutes(10);
        var verifier = new WebhookVerifier(Secret, CanonicalForms.TimestampDotBody, tolerance: TimeSpan.FromMinutes(5), clock: () => now);

        Assert.Equal(VerificationResult.Expired, verifier.Verify(ctx, sig, MessageTime));
    }

    [Fact]
    public void Tolerance_set_but_no_timestamp_throws()
    {
        var (ctx, sig) = SignedMessage();
        var verifier = new WebhookVerifier(Secret, CanonicalForms.TimestampDotBody, tolerance: TimeSpan.FromMinutes(5));

        Assert.Throws<ArgumentException>(() => verifier.Verify(ctx, sig));
    }
}
