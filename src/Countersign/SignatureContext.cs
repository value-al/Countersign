using System.Text;

namespace Countersign;

/// <summary>
/// The parts of an HTTP request or webhook that a <see cref="CanonicalFormBuilder"/> may use to
/// build the bytes that get signed. Only the body is required; supply whatever else the chosen
/// canonical form needs.
/// </summary>
/// <remarks>
/// For webhook verification, prefer constructing from the <b>raw received bytes</b>. Re-encoding a
/// parsed/!re-serialized body to a string can produce different bytes than the provider signed,
/// causing valid webhooks to fail (or, worse, letting a tampered body verify).
/// </remarks>
public sealed class SignatureContext
{
    private readonly byte[] _body;

    /// <summary>Creates a context from the raw body bytes — exactly as received or to be sent.</summary>
    /// <param name="body">The raw payload bytes. Use an empty array for bodyless requests.</param>
    /// <param name="timestamp">The timestamp exactly as it appears on the wire (e.g. unix seconds).</param>
    /// <param name="method">The HTTP method, when the canonical form includes it.</param>
    /// <param name="path">The request path, when the canonical form includes it.</param>
    /// <param name="extras">Any additional named values a custom canonical form needs.</param>
    /// <exception cref="ArgumentNullException"><paramref name="body"/> is null.</exception>
    public SignatureContext(
        byte[] body,
        string? timestamp = null,
        string? method = null,
        string? path = null,
        IReadOnlyDictionary<string, string>? extras = null)
    {
        if (body is null)
        {
            throw new ArgumentNullException(nameof(body));
        }

        _body = (byte[])body.Clone();
        Timestamp = timestamp;
        Method = method;
        Path = path;
        Extras = extras;
    }

    /// <summary>
    /// Creates a context from a UTF-8 string body. Convenient when you already hold the body as a
    /// string; prefer the <see cref="SignatureContext(byte[], string?, string?, string?, IReadOnlyDictionary{string, string}?)"/>
    /// overload for webhook verification, where the exact received bytes matter.
    /// </summary>
    /// <param name="body">The payload body, UTF-8 encoded. Use an empty string for bodyless requests.</param>
    /// <param name="timestamp">The timestamp exactly as it appears on the wire (e.g. unix seconds).</param>
    /// <param name="method">The HTTP method, when the canonical form includes it.</param>
    /// <param name="path">The request path, when the canonical form includes it.</param>
    /// <param name="extras">Any additional named values a custom canonical form needs.</param>
    public SignatureContext(
        string body,
        string? timestamp = null,
        string? method = null,
        string? path = null,
        IReadOnlyDictionary<string, string>? extras = null)
        : this(ToUtf8(body), timestamp, method, path, extras)
    {
    }

    /// <summary>The raw payload bytes. Treat the returned array as read-only.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Performance",
        "CA1819:Properties should not return arrays",
        Justification = "The raw body bytes are intentionally exposed so canonical forms can sign the exact bytes.")]
    public byte[] Body => _body;

    /// <summary>The timestamp exactly as it appears on the wire. Used by timestamped canonical forms.</summary>
    public string? Timestamp { get; }

    /// <summary>The HTTP method, when the canonical form includes it.</summary>
    public string? Method { get; }

    /// <summary>The request path, when the canonical form includes it.</summary>
    public string? Path { get; }

    /// <summary>Any additional named values a custom canonical form needs.</summary>
    public IReadOnlyDictionary<string, string>? Extras { get; }

    private static byte[] ToUtf8(string body)
    {
        if (body is null)
        {
            throw new ArgumentNullException(nameof(body));
        }

        return Encoding.UTF8.GetBytes(body);
    }
}
