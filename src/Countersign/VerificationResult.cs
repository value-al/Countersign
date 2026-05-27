namespace Countersign;

/// <summary>The outcome of verifying an inbound webhook.</summary>
public enum VerificationResult
{
    /// <summary>The signature matched and, if checked, the timestamp was within tolerance.</summary>
    Valid,

    /// <summary>The signature did not match the expected value.</summary>
    SignatureMismatch,

    /// <summary>The provided signature was not valid for the configured encoding (e.g. not valid hex or base64).</summary>
    MalformedSignature,

    /// <summary>The signature matched but the message timestamp was outside the allowed tolerance (possible replay).</summary>
    Expired,
}
