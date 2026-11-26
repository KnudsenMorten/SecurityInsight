using System.Text.RegularExpressions;
using SI.Management.Web.Data;
using SI.Management.Web.EnvReport;

namespace SI.Management.Web.ChangeJournal;

/// Who of a commit as a person reads it: <see cref="Text"/>, and <see cref="Raw"/> -- the stored value, shown as the
/// tooltip -- when the text is a name for it (null = the stored value is shown as it is).
public sealed record CommitWhoName(string Text, string? Raw);

/// The install's own identities and the Invardia Support app, by client / object id (lower case) -> the name shown.
public sealed class CommitNames(IReadOnlyDictionary<string, string> known)
{
    public static readonly CommitNames None = new(new Dictionary<string, string>());
    public IReadOnlyDictionary<string, string> Known { get; } = known;
    public CommitWhoName Of(string? who) => CommitWho.Name(who, Known);
}

/// <summary>
/// #1377 (owner 2026-11-25 "Fix both", Operations &gt; Commits): WHO, READABLE. A write the product makes is journaled
/// under the database login it runs as -- for a managed identity "&lt;client id&gt;@&lt;tenant id&gt;" -- or, from a
/// PowerShell job, "managed identity &lt;client id&gt;". Shown at display time (nothing stored is rewritten) as the
/// install's identity by name: "SecurityInsight update (id-si-updater)", the engine, the web app, the MCP server, the
/// database setup, asset tagging, or the "Invardia Support app"; the stored value stays as the tooltip. A person's
/// commit shows the name stored with it, as before; an id that is none of these shows as it is.
/// The identities come from what the updater last read of the install's resource group (cfg.EnvironmentFacts
/// 'install': every user-assigned managed identity with its client and object id) and the Support app's client id the
/// install records (cfg.InstallState 'SupportApp'). PURE except <see cref="SqlCommitNamesReader"/>.
/// </summary>
public static partial class CommitWho
{
    public const string SupportApp = "Invardia Support app";

    [GeneratedRegex(@"^(?:managed identity\s+)?(?<id>[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})(?:@[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})?$")]
    private static partial Regex IdForm();

    /// "configuration backup (managed identity &lt;id&gt;)" -- a job's actor (Get-SIAuditActor -Job).
    [GeneratedRegex(@"^(?<job>.+?)\s+\((?<inner>[^()]+)\)$")]
    private static partial Regex JobForm();

    private static bool IsGuid(string? s) => Guid.TryParse((s ?? "").Trim(), out _);

    /// PURE. The name an install identity is shown by, from its resource name: the role in words, the name after it.
    public static string Label(string identityName)
    {
        var name = (identityName ?? "").Trim();
        var n = name.ToLowerInvariant();
        string? role = n.Contains("support") ? null
            : n.Contains("updater") ? "SecurityInsight update"
            : n.Contains("dbinit") ? "SecurityInsight database setup"
            : n.Contains("tagging") ? "SecurityInsight asset tagging"
            : n.Contains("mcp") ? "SecurityInsight MCP server"
            : n.EndsWith("-web", StringComparison.Ordinal) || n.Contains("-web-") || n.Contains("management") ? "SecurityInsight web app"
            : n.Contains("engine") || n.StartsWith("id-si-", StringComparison.Ordinal) || n.StartsWith("uami-si", StringComparison.Ordinal) ? "SecurityInsight engine"
            : null;
        return role is null ? name : $"{role} ({name})";
    }

    /// PURE. Client / object id -> name: every user-assigned managed identity of the install (both its ids), the web app's
    /// own identity (-webClientId) when the facts do not name it, and the Support app (-supportAppId).
    public static IReadOnlyDictionary<string, string> Known(AzureFacts? az, string? supportAppId, string? webClientId = null)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in (az?.Resources ?? Array.Empty<AzureResource>()).Where(r => r.Type.Equals("Microsoft.ManagedIdentity/userAssignedIdentities", StringComparison.OrdinalIgnoreCase)))
        {
            var label = Label(r.Name);
            if (label.Length == 0) continue;
            foreach (var id in new[] { r.ClientId, r.PrincipalId }.Where(IsGuid)) d.TryAdd(id!.Trim().ToLowerInvariant(), label);
        }
        if (IsGuid(webClientId)) d.TryAdd(webClientId!.Trim().ToLowerInvariant(), "SecurityInsight web app");
        if (IsGuid(supportAppId)) d[supportAppId!.Trim().ToLowerInvariant()] = SupportApp;
        return d;
    }

    private static string? Lookup(string s, IReadOnlyDictionary<string, string> known)
    {
        var m = IdForm().Match(s.Trim());
        if (!m.Success) return null;
        var id = m.Groups["id"].Value.ToLowerInvariant();
        return known.TryGetValue(id, out var n) ? n : null;
    }

    /// PURE. The stored Who / Approved by as a person reads it (see the class).
    public static CommitWhoName Name(string? who, IReadOnlyDictionary<string, string> known)
    {
        var w = (who ?? "").Trim();
        if (w.Length == 0 || known.Count == 0) return new(who ?? "", null);
        if (Lookup(w, known) is { } n) return new(n, w);
        var j = JobForm().Match(w);
        if (j.Success && Lookup(j.Groups["inner"].Value, known) is { } inner) return new($"{j.Groups["job"].Value} ({inner})", w);
        return new(w, null);
    }
}

public interface ICommitNamesReader
{
    Task<CommitNames> ReadAsync(CancellationToken ct);
}

/// The names from the Pro database (the updater's environment facts + the recorded Support app). Never fails the page:
/// what cannot be read gives no names, and Who shows the stored value as before.
public sealed class SqlCommitNamesReader(IAzureFactsReader azure, ISqlExecutor sql, IConfiguration config, ILogger<SqlCommitNamesReader> log) : ICommitNamesReader
{
    public const string SupportAppSql = "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'SupportApp';";

    public async Task<CommitNames> ReadAsync(CancellationToken ct)
    {
        AzureFacts? az = null; string? support = null;
        try { az = await azure.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "commits: the install's identities could not be read"); }
        try { support = (await sql.QueryAsync(SupportAppSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Str("Value"); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "commits: the Support app could not be read"); }
        return new CommitNames(CommitWho.Known(az, support, config["Identity:ManagedIdentityClientId"]));
    }
}
