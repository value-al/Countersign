namespace Countersign;

/// <summary>The HMAC algorithm used to compute a signature.</summary>
public enum SignatureAlgorithm
{
    /// <summary>HMAC with SHA-256. The most common choice for payment providers.</summary>
    HmacSha256,

    /// <summary>HMAC with SHA-512.</summary>
    HmacSha512,
}
