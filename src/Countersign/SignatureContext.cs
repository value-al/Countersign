namespace Countersign;

/// <summary>
/// The parts of an HTTP request or webhook that a <see cref="CanonicalFormBuilder"/> may use
/// to build the string that gets signed. Only the body is required; supply whatever else the
/// chosen canonical form needs.
/// </summary>
public sealed class SignatureContext
{
    /// <summary>Creates a new context.</summary>
    /// <param name="body">The raw payload body. Use an empty string for bodyless requests.</param>
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
    {
        Body = body ?? throw new ArgumentNullException(nameof(body));
        Timestamp = timestamp;
        Method = method;
        Path = path;
        Extras = extras;
    }

    /// <summary>The raw payload body.</summary>
    public string Body { get; }

    /// <summary>The timestamp exactly as it appears on the wire. Used by timestamped canonical forms.</summary>
    public string? Timestamp { get; }

    /// <summary>The HTTP method, when the canonical form includes it.</summary>
    public string? Method { get; }

    /// <summary>The request path, when the canonical form includes it.</summary>
    public string? Path { get; }

    /// <summary>Any additional named values a custom canonical form needs.</summary>
    public IReadOnlyDictionary<string, string>? Extras { get; }
}
