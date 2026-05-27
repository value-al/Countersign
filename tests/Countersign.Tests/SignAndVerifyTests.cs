using Countersign;

namespace Countersign.Tests;

public class SignAndVerifyTests
{
    [Fact]
    public void Sign_then_verify_roundtrips_hex()
    {
        const string secret = "whsec_123";
        var ctx = new SignatureContext("{\"hello\":\"world\"}", timestamp: "1700000000");
        string sig = new RequestSigner(secret, CanonicalForms.TimestampDotBody).Sign(ctx);

        var verifier = new WebhookVerifier(secret, CanonicalForms.TimestampDotBody);
        Assert.Equal(VerificationResult.Valid, verifier.Verify(ctx, sig));
    }

    [Fact]
    public void Sign_then_verify_roundtrips_base64()
    {
        const string secret = "whsec_123";
        var ctx = new SignatureContext("payload");
        string sig = new RequestSigner(secret, encoding: SignatureEncoding.Base64).Sign(ctx);

        var verifier = new WebhookVerifier(secret, encoding: SignatureEncoding.Base64);
        Assert.Equal(VerificationResult.Valid, verifier.Verify(ctx, sig));
    }

    [Fact]
    public void Tampered_body_fails()
    {
        const string secret = "whsec_123";
        string sig = new RequestSigner(secret).Sign(new SignatureContext("original"));

        var verifier = new WebhookVerifier(secret);
        Assert.Equal(VerificationResult.SignatureMismatch, verifier.Verify(new SignatureContext("tampered"), sig));
    }

    [Fact]
    public void Malformed_signature_is_reported()
    {
        var verifier = new WebhookVerifier("whsec_123");
        Assert.Equal(VerificationResult.MalformedSignature, verifier.Verify(new SignatureContext("body"), "zz"));
    }

    [Fact]
    public void Outbound_and_inbound_are_independent()
    {
        // The provider signs the webhook it sends us, using the webhook secret and its own form.
        const string webhookSecret = "whsec_provider";
        CanonicalFormBuilder inboundForm = CanonicalForms.TimestampDotBody;
        var inboundCtx = new SignatureContext("{\"id\":\"evt_1\"}", timestamp: "1700000000");
        string webhookSignature = new RequestSigner(webhookSecret, inboundForm).Sign(inboundCtx);

        // We verify it with the same webhook secret and form.
        var verifier = new WebhookVerifier(webhookSecret, inboundForm);
        Assert.Equal(VerificationResult.Valid, verifier.Verify(inboundCtx, webhookSignature));

        // Our outbound requests use a different secret and a different canonical form.
        const string apiSecret = "sk_live_self";
        var outboundCtx = new SignatureContext("{}", timestamp: "1700000000", method: "POST", path: "/v1/charges");
        string outboundSignature = new RequestSigner(apiSecret, CanonicalForms.MethodPathTimestampBody).Sign(outboundCtx);

        // Using the API secret to verify the webhook must fail — the two directions don't share a key.
        Assert.Equal(VerificationResult.SignatureMismatch, new WebhookVerifier(apiSecret, inboundForm).Verify(inboundCtx, webhookSignature));
        Assert.NotEqual(webhookSignature, outboundSignature);
    }
}
