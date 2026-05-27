using Countersign;

namespace Countersign.Tests;

public class CanonicalFormAndGuardTests
{
    [Fact]
    public void RawBody_is_the_body()
    {
        Assert.Equal("hello", CanonicalForms.RawBody(new SignatureContext("hello")));
    }

    [Fact]
    public void TimestampDotBody_joins_with_dot()
    {
        Assert.Equal("1700000000.hello", CanonicalForms.TimestampDotBody(new SignatureContext("hello", timestamp: "1700000000")));
    }

    [Fact]
    public void TimestampDotBody_requires_timestamp()
    {
        Assert.Throws<InvalidOperationException>(() => CanonicalForms.TimestampDotBody(new SignatureContext("hello")));
    }

    [Fact]
    public void MethodPathTimestampBody_joins_with_newlines()
    {
        var ctx = new SignatureContext("body", timestamp: "1700000000", method: "POST", path: "/v1/charges");
        Assert.Equal("POST\n/v1/charges\n1700000000\nbody", CanonicalForms.MethodPathTimestampBody(ctx));
    }

    [Fact]
    public void Empty_secret_is_rejected()
    {
        Assert.Throws<ArgumentException>(() => new RequestSigner(Array.Empty<byte>()));
        Assert.Throws<ArgumentException>(() => new WebhookVerifier(Array.Empty<byte>()));
    }
}
