using SI.Management.Web.Data;

namespace SI.Management.Web.Collection;

/// <summary>
/// A SAVED PIVOT VIEW (#360): a pivot of the weighted risk page under a name. Personal by default (Owner = who saved it);
/// an Admin may share one with every reader. <see cref="State"/> is the pivot as URL parameters -- field and measure KEYS,
/// read back through the same whitelist as a URL (<see cref="PivotRequest.Parse"/>), so a stored view can never carry SQL.
/// </summary>
public sealed record PivotView(long Id, string Name, string Owner, bool Shared, string State, DateTime UpdatedAt)
{
    public const int MaxName = 100;
    public const int MaxState = 2000;

    /// What is wrong with a name (null = fine).
    public static string? NameProblem(string? name)
    {
        var n = name?.Trim();
        if (string.IsNullOrEmpty(n)) return "Give the view a name.";
        if (n.Length > MaxName) return $"A name has at most {MaxName} characters.";
        if (n.Any(char.IsControl)) return "A name cannot contain control characters.";
        return null;
    }
}

/// The saved pivot views (cfg.PivotView).
public interface IPivotViewStore
{
    Task<bool> ReadyAsync(CancellationToken ct);
    /// The caller's own views and every shared one.
    Task<IReadOnlyList<PivotView>> ListAsync(string owner, CancellationToken ct);
    /// Saves (or, for the same owner and name, replaces) a view; returns its id.
    Task<long> SaveAsync(string name, string owner, bool shared, string state, CancellationToken ct);
    /// Removes a view: the owner's own, or (an Admin) a shared one. False = not found / not allowed.
    Task<bool> RemoveAsync(long id, string by, bool admin, CancellationToken ct);
}

public sealed class SqlPivotViewStore(ISqlExecutor sql) : IPivotViewStore
{
    public const string ReadySql = "SELECT CASE WHEN OBJECT_ID(N'cfg.PivotView') IS NOT NULL THEN 1 ELSE 0 END AS Ready;";
    public const string ListSql = """
SELECT ViewId, Name, Owner, Shared, State, UpdatedAt
FROM cfg.PivotView
WHERE RemovedAt IS NULL AND (Owner = @Owner OR Shared = 1)
ORDER BY Shared, Name, ViewId;
""";
    public const string SaveSql = """
UPDATE cfg.PivotView SET State = @State, Shared = @Shared, UpdatedAt = SYSUTCDATETIME()
WHERE Owner = @Owner AND Name = @Name AND RemovedAt IS NULL;
IF @@ROWCOUNT = 0
    INSERT cfg.PivotView (Name, Owner, Shared, State) VALUES (@Name, @Owner, @Shared, @State);
SELECT TOP (1) ViewId FROM cfg.PivotView WHERE Owner = @Owner AND Name = @Name AND RemovedAt IS NULL ORDER BY ViewId DESC;
""";
    public const string RemoveSql = """
UPDATE cfg.PivotView SET RemovedAt = SYSUTCDATETIME(), RemovedBy = @By
WHERE ViewId = @Id AND RemovedAt IS NULL AND (Owner = @By OR (@Admin = 1 AND Shared = 1));
SELECT @@ROWCOUNT AS N;
""";

    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;

    public async Task<bool> ReadyAsync(CancellationToken ct) => (await sql.QueryAsync(ReadySql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("Ready") == 1;

    public async Task<IReadOnlyList<PivotView>> ListAsync(string owner, CancellationToken ct) =>
        (await sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["Owner"] = Cut(owner, 256) }, ct)).Select(r => new PivotView(
            r.Long("ViewId") ?? 0, r.Str("Name") ?? "", r.Str("Owner") ?? "", r.TryGetValue("Shared", out var s) && s is true or 1 or 1L,
            r.Str("State") ?? "", DateTime.SpecifyKind(r.Date("UpdatedAt") ?? DateTime.UtcNow, DateTimeKind.Utc))).ToList();

    public async Task<long> SaveAsync(string name, string owner, bool shared, string state, CancellationToken ct) =>
        (await sql.QueryAsync(SaveSql, new Dictionary<string, object?>
        {
            ["Name"] = Cut(name.Trim(), PivotView.MaxName), ["Owner"] = Cut(owner, 256), ["Shared"] = shared, ["State"] = Cut(state, PivotView.MaxState),
        }, ct)).FirstOrDefault()?.Long("ViewId") ?? 0;

    public async Task<bool> RemoveAsync(long id, string by, bool admin, CancellationToken ct) =>
        (await sql.QueryAsync(RemoveSql, new Dictionary<string, object?> { ["Id"] = id, ["By"] = Cut(by, 256), ["Admin"] = admin ? 1 : 0 }, ct)).FirstOrDefault()?.Long("N") == 1;
}
