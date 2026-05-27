namespace Countersign;

/// <summary>The HMAC algorithm used by <see cref="HmacScheme"/>.</summary>
public enum SignatureAlgorithm
{
    /// <summary>HMAC with SHA-256. The most common choice for payment providers.</summary>
    HmacSha256,

    /// <summary>HMAC with SHA-512.</summary>
    HmacSha512,

    /// <summary>HMAC with SHA-384.</summary>
    HmacSha384,

    /// <summary>HMAC with SHA-1. Legacy — only for providers that still mandate it.</summary>
    HmacSha1,
}
