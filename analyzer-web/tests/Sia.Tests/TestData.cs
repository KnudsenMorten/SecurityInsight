namespace Sia.Tests;

/// <summary>Locates the shared demo seed (the same file the PS POC ships) from the test bin.</summary>
internal static class TestData
{
    public static string SeedPath()
    {
        var d = new DirectoryInfo(AppContext.BaseDirectory);
        while (d is not null)
        {
            var candidate = Path.Combine(d.FullName, "SOLUTIONS", "SecurityInsight", "analyzer", "seed", "demo-snapshot.json");
            if (File.Exists(candidate)) return candidate;
            // Also handle running from within analyzer-web.
            var local = Path.Combine(d.FullName, "analyzer", "seed", "demo-snapshot.json");
            if (File.Exists(local)) return local;
            var sibling = Path.Combine(d.FullName, "..", "analyzer", "seed", "demo-snapshot.json");
            if (File.Exists(sibling)) return Path.GetFullPath(sibling);
            d = d.Parent;
        }
        throw new FileNotFoundException("Could not locate analyzer/seed/demo-snapshot.json from " + AppContext.BaseDirectory);
    }
}
