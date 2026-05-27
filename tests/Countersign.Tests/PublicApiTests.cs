#if NET8_0_OR_GREATER
using System.Runtime.CompilerServices;
using Countersign;
using PublicApiGenerator;

namespace Countersign.Tests;

/// <summary>
/// Snapshots the library's public API. If the surface changes, this test fails and writes a
/// <c>PublicApi.approved.txt.received.txt</c> next to the approved file — review the diff, and if the
/// change is intended, copy it over the approved file. Guards against accidental breaking changes.
/// </summary>
public class PublicApiTests
{
    [Fact]
    public void Public_api_surface_is_unchanged()
    {
        string api = typeof(RequestSigner).Assembly.GeneratePublicApi(new ApiGeneratorOptions());
        string normalized = api.Replace("\r\n", "\n").TrimEnd() + "\n";

        string approvedPath = Path.Combine(ProjectDir(), "PublicApi.approved.txt");
        if (!File.Exists(approvedPath))
        {
            File.WriteAllText(approvedPath, normalized);
        }

        string approved = File.ReadAllText(approvedPath).Replace("\r\n", "\n").TrimEnd() + "\n";
        if (approved != normalized)
        {
            File.WriteAllText(approvedPath + ".received.txt", normalized);
        }

        Assert.Equal(approved, normalized);
    }

    private static string ProjectDir([CallerFilePath] string path = "") => Path.GetDirectoryName(path)!;
}
#endif
