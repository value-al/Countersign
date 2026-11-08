using System.Reflection;
using NetArchTest.Rules;

namespace Countersign.ArchitectureTests;

/// <summary>
/// The library's structure, as drawn in ARCHITECTURE.md (part 2). Each rule fails with a message that
/// says how to fix the violation. If a rule is wrong because the design changed on purpose, change the
/// rule and ARCHITECTURE.md in the same PR.
/// </summary>
public class ArchitectureRules
{
    private static readonly Assembly Library = typeof(RequestSigner).Assembly;

    private const string Internal = "Countersign.Internal";
    private const string Signer = "Countersign.RequestSigner";
    private const string Verifier = "Countersign.WebhookVerifier";

    private static readonly string[] Schemes =
    {
        "Countersign.HmacScheme",
        "Countersign.RsaScheme",
        "Countersign.EcdsaScheme",
    };

    [Fact]
    public void Internal_helpers_stay_internal()
    {
        TestResult result = Types.InAssembly(Library)
            .That().ResideInNamespace(Internal)
            .Should().NotBePublic()
            .GetResult();

        AssertRule(result,
            "Types in Countersign.Internal are implementation details and must not be public. " +
            "Make the type internal; if callers need it, add a public type in the Countersign namespace " +
            "and update tests/Countersign.Tests/PublicApi.approved.txt on purpose.");
    }

    [Fact]
    public void Internal_helpers_do_not_depend_on_the_public_entry_points()
    {
        TestResult result = Types.InAssembly(Library)
            .That().ResideInNamespace(Internal)
            .ShouldNot().HaveDependencyOnAny(new[] { Signer, Verifier, "Countersign.ISignatureScheme" }.Concat(Schemes).ToArray())
            .GetResult();

        AssertRule(result,
            "Countersign.Internal is the bottom layer: byte helpers, HMAC and encodings. It may use the " +
            "enums and SignatureContext, never RequestSigner, WebhookVerifier or a scheme. Move the code " +
            "that needs them up into the calling type.");
    }

    [Fact]
    public void Schemes_sign_and_verify_bytes_but_never_decide_validity()
    {
        TestResult result = Types.InAssembly(Library)
            .That().ImplementInterface(typeof(ISignatureScheme))
            .ShouldNot().HaveDependencyOnAny(
                Signer,
                Verifier,
                "Countersign.VerificationResult",
                "Countersign.SignatureContext",
                "Countersign.CanonicalForms",
                "Countersign.SignatureEncoding")
            .GetResult();

        AssertRule(result,
            "A signature scheme only turns message bytes into signature bytes and back (README, design " +
            "note 3). Canonical forms, encodings, replay tolerance and the VerificationResult belong to " +
            "RequestSigner and WebhookVerifier. Move that logic into the signer or verifier.");
    }

    [Fact]
    public void Outbound_and_inbound_stay_separate()
    {
        TestResult signer = Types.InAssembly(Library)
            .That().HaveName("RequestSigner")
            .ShouldNot().HaveDependencyOnAny(Verifier, "Countersign.VerificationResult")
            .GetResult();
        TestResult verifier = Types.InAssembly(Library)
            .That().HaveName("WebhookVerifier")
            .ShouldNot().HaveDependencyOn(Signer)
            .GetResult();

        AssertRule(signer,
            "RequestSigner (outbound) must not use WebhookVerifier or VerificationResult (README, design " +
            "note 1). Put shared code in Countersign.Internal and call it from both.");
        AssertRule(verifier,
            "WebhookVerifier (inbound) must not use RequestSigner (README, design note 1). Put shared " +
            "code in Countersign.Internal and call it from both.");
    }

    [Fact]
    public void Hmac_primitives_are_used_only_where_the_constant_time_compare_lives()
    {
        TestResult result = Types.InAssembly(Library)
            .That().DoNotHaveName("Mac")
            .ShouldNot().HaveDependencyOnAny(
                // NetArchTest matches whole type names, so every HMAC type is listed.
                "System.Security.Cryptography.HMAC",
                "System.Security.Cryptography.HMACMD5",
                "System.Security.Cryptography.HMACSHA1",
                "System.Security.Cryptography.HMACSHA256",
                "System.Security.Cryptography.HMACSHA384",
                "System.Security.Cryptography.HMACSHA512",
                "System.Security.Cryptography.IncrementalHash",
                "System.Security.Cryptography.CryptographicOperations")
            .GetResult();

        AssertRule(result,
            "HMAC computation and the fixed-time compare live only in Countersign.Internal.Mac, so every " +
            "HMAC check goes through Mac.FixedTimeEquals. Call Mac.Compute / Mac.FixedTimeEquals instead " +
            "of using HMAC classes or CryptographicOperations directly.");
    }

    [Fact]
    public void Public_classes_are_sealed()
    {
        TestResult result = Types.InAssembly(Library)
            .That().ArePublic().And().AreClasses().And().AreNotStatic()
            .Should().BeSealed()
            .GetResult();

        AssertRule(result,
            "Public classes are sealed so callers can't override signing or verification behaviour. " +
            "Mark the class sealed; extension points are interfaces (ISignatureScheme) or delegates " +
            "(CanonicalFormBuilder).");
    }

    [Fact]
    public void Library_depends_only_on_the_base_class_library()
    {
        string[] foreign = Library.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(name => !(name == "netstandard" || name == "mscorlib" || name.StartsWith("System", StringComparison.Ordinal)))
            .ToArray();

        Assert.True(foreign.Length == 0,
            "Countersign has no runtime dependencies (README, CONTRIBUTING). It references: " +
            string.Join(", ", foreign) + ". Remove the reference, or make it build-time only with " +
            "PrivateAssets=\"all\"; a crypto dependency goes in a separate package, like Countersign.Ed25519.");
    }

    private static void AssertRule(TestResult result, string howToFix)
    {
        string failing = result.FailingTypeNames is null ? string.Empty : string.Join(", ", result.FailingTypeNames);
        Assert.True(result.IsSuccessful, $"{howToFix}\nViolating types: {failing}");
    }
}
