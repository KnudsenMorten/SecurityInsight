using SI.Management.Web.Data;

namespace SI.Management.Web.Cis;

/// A named layout of one view as the selector lists it: a person's own, or one an Admin published for everyone.
public sealed record NamedLayout(int Id, string Name, bool Shared)
{
    /// Pinned to the person's own menu ("My views").
    public bool PinnedMine { get; init; }
    /// Pinned by an Admin to everyone's menu (a published layout only).
    public bool PinnedForAll { get; init; }
}

/// A named layout pinned to the menu (owner 2026-10-19): in the person's "My views" (<see cref="ForAll"/> false) or by an
/// Admin for everyone; <see cref="Path"/> is the page it opens.
public sealed record PinnedView(int Id, string Name, string View, string Path, bool ForAll);

/// <summary>
/// What is stored for one view and one person, from ONE read: the tenant default (an Admin's) and the person's own
/// columns (null = not set), and -- once the view settings tables exist (<see cref="More"/>) -- the person's last sort /
/// filters / search, their column widths, the named layouts they can switch between and the one in use.
/// </summary>
public sealed record StoredLayouts(bool Ready, string? Tenant, string? User)
{
    /// cfg.ViewState and cfg.ViewLayout exist: the sort / filters, the widths and named layouts can be saved.
    public bool More { get; init; }
    /// The person's last sort / filters / search of the view (a JSON object, <see cref="SI.Management.Web.Columns.ViewState"/>).
    public string? State { get; init; }
    /// The person's column widths ({"column key": pixels}).
    public string? Widths { get; init; }
    /// The named layout in use (null = none, or it was deleted).
    public int? ActiveId { get; init; }
    /// The person changed something since they chose (or saved) the layout in use.
    public bool ActiveChanged { get; init; }
    /// The person's own named layouts and the published ones, by name.
    public IReadOnlyList<NamedLayout> Named { get; init; } = Array.Empty<NamedLayout>();
}

/// One named layout to save: a new one (by <see cref="Name"/>; the same name replaces) or, with <see cref="Id"/>, the
/// columns / sort / filters / widths of an existing one. <see cref="StateJson"/> null with <see cref="UseStoredState"/> =
/// the person's remembered sort and filters. The widths are always the person's stored ones.
public sealed record NamedLayoutWrite(int? Id, string UserKey, string View, string Name, bool Shared, bool Admin, string ColumnsJson, string? StateJson, bool UseStoredState, string By);

/// <summary>
/// The column layouts of the grids (V3-DATA-MODEL 2.13): cfg.ColumnLayout, one row per (Scope, UserKey, View) --
/// Scope 'tenant' (UserKey '') is the default an Admin sets, Scope 'user' a person's own. ColumnsJson is a JSON array of
/// column keys. The table is additive (sql\si-pro-settings.sql); until it exists every read answers "not set" and a save
/// says the table is missing -- the grid then shows the shipped default.
/// Next to it, per person and view: cfg.ViewState (the last sort / filters / search, the column widths, the named layout
/// in use) and cfg.ViewLayout (named layouts: a person's own, or Scope 'shared' = published by an Admin for everyone).
/// Everything a page needs comes from ONE read (<see cref="ReadAsync"/>); each change is one keyed batch.
/// </summary>
public interface IColumnLayoutStore
{
    Task<StoredLayouts> ReadAsync(string view, string userKey, CancellationToken ct);
    /// Saves a layout; false = the table does not exist yet.
    Task<bool> SaveAsync(string scope, string userKey, string view, string columnsJson, string by, CancellationToken ct);
    /// Removes a layout: a person's own (they see the tenant default again) or, Scope tenant, the tenant default (everyone
    /// without their own sees the shipped default again); false = the table does not exist yet.
    Task<bool> ResetAsync(string scope, string userKey, string view, CancellationToken ct);

    /// The person's last sort / filters / search of a view (null = none: the view's standard); false = not in the database yet.
    Task<bool> SaveStateAsync(string userKey, string view, string? stateJson, CancellationToken ct) => Task.FromResult(false);
    /// The person's column widths of a view (null = none); false = not in the database yet.
    Task<bool> SaveWidthsAsync(string userKey, string view, string? widthsJson, CancellationToken ct) => Task.FromResult(false);
    /// With "Reset to the tenant default": the person's widths and the layout in use are forgotten too.
    Task<bool> ClearSettingsAsync(string userKey, string view, CancellationToken ct) => Task.FromResult(false);
    /// Saves a named layout and makes it the one in use; the outcome is one of <see cref="LayoutOutcome"/>.
    Task<(string Outcome, int? Id)> SaveNamedAsync(NamedLayoutWrite layout, CancellationToken ct) => Task.FromResult<(string, int?)>((LayoutOutcome.Missing, null));
    /// Makes a named layout (the person's own, or a published one) the person's set-up: its columns, sort, filters and widths.
    Task<string> ApplyNamedAsync(int id, string userKey, string view, CancellationToken ct) => Task.FromResult(LayoutOutcome.Missing);
    /// Renames a named layout (the person's own; a published one only with <paramref name="admin"/>).
    Task<string> RenameNamedAsync(int id, string userKey, string view, string name, bool admin, string by, CancellationToken ct) => Task.FromResult(LayoutOutcome.Missing);
    /// Deletes a named layout (the person's own; a published one only with <paramref name="admin"/>). Whoever used it keeps their columns.
    Task<string> DeleteNamedAsync(int id, string userKey, string view, bool admin, CancellationToken ct) => Task.FromResult(LayoutOutcome.Missing);
    /// Publishes one of the caller's own named layouts for everyone (the caller is an Admin -- checked by the page).
    Task<string> PublishNamedAsync(int id, string userKey, string view, string by, CancellationToken ct) => Task.FromResult(LayoutOutcome.Missing);

    /// Pins a named layout to the menu (<paramref name="pin"/>) or takes it off: <paramref name="forAll"/> = everyone's
    /// menu (an Admin, a published layout), else the person's "My views" (their own layout or a published one).
    /// <paramref name="path"/> = the page it opens.
    Task<string> PinNamedAsync(int id, string userKey, string view, bool pin, bool forAll, bool admin, string path, string by, CancellationToken ct) => Task.FromResult(LayoutOutcome.Missing);
    /// The layouts pinned to this person's menu: their own "My views" and the ones pinned for everyone (none = the table is not there yet).
    Task<IReadOnlyList<PinnedView>> PinnedAsync(string userKey, CancellationToken ct) => Task.FromResult<IReadOnlyList<PinnedView>>(Array.Empty<PinnedView>());
}

/// How a change of a named layout ended.
public static class LayoutOutcome
{
    public const string Saved = "Saved";
    /// The tables are not in the Pro database yet.
    public const string Missing = "Missing";
    /// The layout no longer exists (deleted meanwhile).
    public const string Gone = "Gone";
    /// Another layout of the same kind already has that name.
    public const string Taken = "Taken";
    /// Not the caller's layout, or a published one and the caller is no Admin.
    public const string Forbidden = "Forbidden";
}

public sealed class SqlColumnLayoutStore(ISqlExecutor sql) : IColumnLayoutStore
{
    public const string ScopeTenant = "tenant";
    public const string ScopeUser = "user";
    /// A named layout an Admin published for everyone (cfg.ViewLayout.Scope).
    public const string ScopeShared = "shared";
    public const int MaxUserKey = 256;
    public const int MaxView = 64;
    public const int MaxColumnsJson = 200_000;
    public const int MaxName = 80;
    public const int MaxStateJson = 16_000;
    public const int MaxWidthsJson = 40_000;

    // ONE batch, one result set: a marker row (what exists), the tenant default, the person's own columns, their view state,
    // and the named layouts of the view (their own + the published ones). Every branch is a key seek. The named layouts
    // carry their content only for the one in use (to say whether the person changed something since).
    public const string ReadSql = """
IF OBJECT_ID(N'cfg.ColumnLayout') IS NULL
BEGIN
    SELECT CAST(N'none' AS nvarchar(16)) AS Kind, CAST(NULL AS int) AS LayoutId, CAST(NULL AS nvarchar(80)) AS Name,
           CAST(NULL AS nvarchar(max)) AS ColumnsJson, CAST(NULL AS nvarchar(max)) AS StateJson, CAST(NULL AS nvarchar(max)) AS WidthsJson;
END
ELSE IF OBJECT_ID(N'cfg.ViewState') IS NULL OR OBJECT_ID(N'cfg.ViewLayout') IS NULL
BEGIN
    SELECT CAST(N'ready' AS nvarchar(16)) AS Kind, CAST(NULL AS int) AS LayoutId, CAST(NULL AS nvarchar(80)) AS Name,
           CAST(NULL AS nvarchar(max)) AS ColumnsJson, CAST(NULL AS nvarchar(max)) AS StateJson, CAST(NULL AS nvarchar(max)) AS WidthsJson
    UNION ALL
    SELECT N'tenant', NULL, NULL, t.ColumnsJson, NULL, NULL FROM cfg.ColumnLayout AS t WHERE t.Scope = N'tenant' AND t.UserKey = N'' AND t.[View] = @View
    UNION ALL
    SELECT N'user', NULL, NULL, u.ColumnsJson, NULL, NULL FROM cfg.ColumnLayout AS u WHERE u.Scope = N'user' AND u.UserKey = @UserKey AND u.[View] = @View;
END
ELSE IF OBJECT_ID(N'cfg.ViewPin') IS NULL
BEGIN
""" + MoreRowsSql + """
;
END
ELSE
BEGIN
""" + MoreRowsSql + """

    UNION ALL
    -- the pins of the view's layouts (cfg.ViewPin, additive): the person's own and the ones for everyone; Name = the pin's scope
    SELECT N'pin', p.LayoutId, p.Scope, NULL, NULL, NULL
    FROM cfg.ViewPin AS p JOIN cfg.ViewLayout AS pl ON pl.LayoutId = p.LayoutId AND pl.[View] = @View
    WHERE (p.Scope = N'tenant' AND p.UserKey = N'') OR (p.Scope = N'user' AND p.UserKey = @UserKey);
END
""";

    // the 'more' rows of ReadSql: the marker, the tenant default, the person's own columns, their view state and the named layouts
    private const string MoreRowsSql = """
    SELECT CAST(N'more' AS nvarchar(16)) AS Kind, CAST(NULL AS int) AS LayoutId, CAST(NULL AS nvarchar(80)) AS Name,
           CAST(NULL AS nvarchar(max)) AS ColumnsJson, CAST(NULL AS nvarchar(max)) AS StateJson, CAST(NULL AS nvarchar(max)) AS WidthsJson
    UNION ALL
    SELECT N'tenant', NULL, NULL, t.ColumnsJson, NULL, NULL FROM cfg.ColumnLayout AS t WHERE t.Scope = N'tenant' AND t.UserKey = N'' AND t.[View] = @View
    UNION ALL
    SELECT N'user', NULL, NULL, u.ColumnsJson, NULL, NULL FROM cfg.ColumnLayout AS u WHERE u.Scope = N'user' AND u.UserKey = @UserKey AND u.[View] = @View
    UNION ALL
    SELECT N'state', s.LayoutId, NULL, NULL, s.StateJson, s.WidthsJson FROM cfg.ViewState AS s WHERE s.UserKey = @UserKey AND s.[View] = @View
    UNION ALL
    SELECT CASE WHEN l.Scope = N'shared' THEN N'shared' ELSE N'named' END, l.LayoutId, l.Name,
           CASE WHEN a.LayoutId IS NOT NULL THEN l.ColumnsJson END, CASE WHEN a.LayoutId IS NOT NULL THEN l.StateJson END, CASE WHEN a.LayoutId IS NOT NULL THEN l.WidthsJson END
    FROM cfg.ViewLayout AS l
    LEFT JOIN cfg.ViewState AS a ON a.UserKey = @UserKey AND a.[View] = @View AND a.LayoutId = l.LayoutId
    WHERE l.[View] = @View AND ((l.Scope = N'shared' AND l.UserKey = N'') OR (l.Scope = N'user' AND l.UserKey = @UserKey))
""";

    public const string SaveSql = """
IF OBJECT_ID(N'cfg.ColumnLayout') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END
UPDATE cfg.ColumnLayout SET ColumnsJson = @Columns, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHERE Scope = @Scope AND UserKey = @UserKey AND [View] = @View;
IF @@ROWCOUNT = 0
    INSERT cfg.ColumnLayout (Scope, UserKey, [View], ColumnsJson, UpdatedBy) VALUES (@Scope, @UserKey, @View, @Columns, @By);
SELECT N'Saved' AS Outcome;
""";

    public const string ResetSql = """
IF OBJECT_ID(N'cfg.ColumnLayout') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome;
    RETURN;
END
DELETE FROM cfg.ColumnLayout WHERE Scope = @Scope AND UserKey = @UserKey AND [View] = @View;
SELECT N'Saved' AS Outcome;
""";

    private const string MoreGuardSql = """
IF OBJECT_ID(N'cfg.ColumnLayout') IS NULL OR OBJECT_ID(N'cfg.ViewState') IS NULL OR OBJECT_ID(N'cfg.ViewLayout') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome, CAST(NULL AS int) AS LayoutId;
    RETURN;
END

""";

    public const string SaveStateSql = MoreGuardSql + """
UPDATE cfg.ViewState SET StateJson = @State, UpdatedAt = SYSUTCDATETIME() WHERE UserKey = @UserKey AND [View] = @View;
IF @@ROWCOUNT = 0 AND @State IS NOT NULL
    INSERT cfg.ViewState (UserKey, [View], StateJson) VALUES (@UserKey, @View, @State);
SELECT N'Saved' AS Outcome, CAST(NULL AS int) AS LayoutId;
""";

    public const string SaveWidthsSql = MoreGuardSql + """
UPDATE cfg.ViewState SET WidthsJson = @Widths, UpdatedAt = SYSUTCDATETIME() WHERE UserKey = @UserKey AND [View] = @View;
IF @@ROWCOUNT = 0 AND @Widths IS NOT NULL
    INSERT cfg.ViewState (UserKey, [View], WidthsJson) VALUES (@UserKey, @View, @Widths);
SELECT N'Saved' AS Outcome, CAST(NULL AS int) AS LayoutId;
""";

    public const string ClearSettingsSql = MoreGuardSql + """
UPDATE cfg.ViewState SET WidthsJson = NULL, LayoutId = NULL, UpdatedAt = SYSUTCDATETIME() WHERE UserKey = @UserKey AND [View] = @View;
SELECT N'Saved' AS Outcome, CAST(NULL AS int) AS LayoutId;
""";

    // the layout the caller names: it exists in this view, and it is the caller's own or (for a change) a published one and
    // the caller is an Admin
    private const string TargetSql = """
DECLARE @TScope nvarchar(16), @TUser nvarchar(256);
SELECT @TScope = l.Scope, @TUser = l.UserKey FROM cfg.ViewLayout AS l WHERE l.LayoutId = @Id AND l.[View] = @View;
IF @TScope IS NULL
BEGIN
    SELECT N'Gone' AS Outcome, CAST(NULL AS int) AS LayoutId;
    RETURN;
END
IF (@TScope = N'shared' AND @Admin = 0) OR (@TScope <> N'shared' AND @TUser <> @UserKey)
BEGIN
    SELECT N'Forbidden' AS Outcome, CAST(NULL AS int) AS LayoutId;
    RETURN;
END

""";

    // the person's own set-up becomes the layout: their columns, their sort / filters, the layout in use
    private const string UseSql = """
UPDATE cfg.ColumnLayout SET ColumnsJson = @UseColumns, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
WHERE Scope = N'user' AND UserKey = @UserKey AND [View] = @View;
IF @@ROWCOUNT = 0
    INSERT cfg.ColumnLayout (Scope, UserKey, [View], ColumnsJson, UpdatedBy) VALUES (N'user', @UserKey, @View, @UseColumns, @By);
UPDATE cfg.ViewState SET StateJson = @UseState, WidthsJson = @UseWidths, LayoutId = @Target, UpdatedAt = SYSUTCDATETIME() WHERE UserKey = @UserKey AND [View] = @View;
IF @@ROWCOUNT = 0
    INSERT cfg.ViewState (UserKey, [View], StateJson, WidthsJson, LayoutId) VALUES (@UserKey, @View, @UseState, @UseWidths, @Target);
SELECT N'Saved' AS Outcome, @Target AS LayoutId;
""";

    // the locals of a save: the person's stored widths, and their stored sort / filters when the page named none (never
    // assigned to a parameter: a parameter that came as null is a one-character text to the server)
    private const string SaveLocalsSql = """
DECLARE @UseColumns nvarchar(max) = @Columns, @UseWidths nvarchar(max), @UseState nvarchar(max), @Stored nvarchar(max), @Target int;
SELECT @UseWidths = s.WidthsJson, @Stored = s.StateJson FROM cfg.ViewState AS s WHERE s.UserKey = @UserKey AND s.[View] = @View;
SET @UseState = CASE WHEN @UseStored = 1 THEN @Stored ELSE @State END;

""";

    public const string SaveNamedNewSql = MoreGuardSql + SaveLocalsSql + """
SELECT @Target = l.LayoutId FROM cfg.ViewLayout AS l WHERE l.[View] = @View AND l.Scope = @Scope AND l.UserKey = @Owner AND l.Name = @Name;
IF @Target IS NULL
BEGIN
    INSERT cfg.ViewLayout (Scope, UserKey, [View], Name, ColumnsJson, StateJson, WidthsJson, UpdatedBy)
    VALUES (@Scope, @Owner, @View, @Name, @UseColumns, @UseState, @UseWidths, @By);
    SET @Target = CONVERT(int, SCOPE_IDENTITY());
END
ELSE
    UPDATE cfg.ViewLayout SET ColumnsJson = @UseColumns, StateJson = @UseState, WidthsJson = @UseWidths, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE LayoutId = @Target;

""" + UseSql;

    public const string SaveNamedExistingSql = MoreGuardSql + TargetSql + SaveLocalsSql + """
SET @Target = @Id;
UPDATE cfg.ViewLayout SET ColumnsJson = @UseColumns, StateJson = @UseState, WidthsJson = @UseWidths, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE LayoutId = @Target;

""" + UseSql;

    // choosing a layout: the caller's own or a published one (reading a published one needs no Admin)
    public const string ApplyNamedSql = MoreGuardSql + """
DECLARE @UseColumns nvarchar(max), @UseState nvarchar(max), @UseWidths nvarchar(max), @Target int = @Id;
SELECT @UseColumns = l.ColumnsJson, @UseState = l.StateJson, @UseWidths = l.WidthsJson FROM cfg.ViewLayout AS l
WHERE l.LayoutId = @Id AND l.[View] = @View AND ((l.Scope = N'shared' AND l.UserKey = N'') OR (l.Scope = N'user' AND l.UserKey = @UserKey));
IF @UseColumns IS NULL
BEGIN
    SELECT N'Gone' AS Outcome, CAST(NULL AS int) AS LayoutId;
    RETURN;
END

""" + UseSql;

    public const string RenameNamedSql = MoreGuardSql + TargetSql + """
IF EXISTS (SELECT 1 FROM cfg.ViewLayout AS o WHERE o.[View] = @View AND o.Scope = @TScope AND o.UserKey = @TUser AND o.Name = @Name AND o.LayoutId <> @Id)
BEGIN
    SELECT N'Taken' AS Outcome, CAST(NULL AS int) AS LayoutId;
    RETURN;
END
UPDATE cfg.ViewLayout SET Name = @Name, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE LayoutId = @Id;
SELECT N'Saved' AS Outcome, @Id AS LayoutId;
""";

    // whoever used the layout keeps the columns, sort and widths they have; only the pointer goes
    public const string DeleteNamedSql = MoreGuardSql + TargetSql + """
DELETE FROM cfg.ViewLayout WHERE LayoutId = @Id;
UPDATE cfg.ViewState SET LayoutId = NULL WHERE LayoutId = @Id;
IF OBJECT_ID(N'cfg.ViewPin') IS NOT NULL DELETE FROM cfg.ViewPin WHERE LayoutId = @Id;
SELECT N'Saved' AS Outcome, @Id AS LayoutId;
""";

    public const string PublishNamedSql = MoreGuardSql + TargetSql + """
IF @TScope <> N'shared'
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.ViewLayout AS o WHERE o.[View] = @View AND o.Scope = N'shared' AND o.UserKey = N'' AND o.Name = (SELECT n.Name FROM cfg.ViewLayout AS n WHERE n.LayoutId = @Id))
    BEGIN
        SELECT N'Taken' AS Outcome, CAST(NULL AS int) AS LayoutId;
        RETURN;
    END
    UPDATE cfg.ViewLayout SET Scope = N'shared', UserKey = N'', UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE LayoutId = @Id;
END
SELECT N'Saved' AS Outcome, @Id AS LayoutId;
""";

    public const int MaxPinPath = 512;

    // pinning a layout to the menu: the layout exists in this view; for everyone = a published layout and an Admin; for the
    // person's own "My views" = their own layout or a published one. Unpin removes the pin.
    public const string PinNamedSql = MoreGuardSql + """
IF OBJECT_ID(N'cfg.ViewPin') IS NULL
BEGIN
    SELECT N'Missing' AS Outcome, CAST(NULL AS int) AS LayoutId;
    RETURN;
END
DECLARE @LScope nvarchar(16), @LUser nvarchar(256);
SELECT @LScope = l.Scope, @LUser = l.UserKey FROM cfg.ViewLayout AS l WHERE l.LayoutId = @Id AND l.[View] = @View;
IF @LScope IS NULL
BEGIN
    SELECT N'Gone' AS Outcome, CAST(NULL AS int) AS LayoutId;
    RETURN;
END
IF (@ForAll = 1 AND (@Admin = 0 OR @LScope <> N'shared')) OR (@ForAll = 0 AND @LScope <> N'shared' AND @LUser <> @UserKey)
BEGIN
    SELECT N'Forbidden' AS Outcome, CAST(NULL AS int) AS LayoutId;
    RETURN;
END
DECLARE @PScope nvarchar(16) = CASE WHEN @ForAll = 1 THEN N'tenant' ELSE N'user' END;
DECLARE @PUser nvarchar(256) = CASE WHEN @ForAll = 1 THEN N'' ELSE @UserKey END;
IF @Pin = 1
BEGIN
    UPDATE cfg.ViewPin SET [Path] = @Path, PinnedAt = SYSUTCDATETIME(), PinnedBy = @By WHERE Scope = @PScope AND UserKey = @PUser AND LayoutId = @Id;
    IF @@ROWCOUNT = 0
        INSERT cfg.ViewPin (Scope, UserKey, LayoutId, [Path], PinnedBy) VALUES (@PScope, @PUser, @Id, @Path, @By);
END
ELSE
    DELETE FROM cfg.ViewPin WHERE Scope = @PScope AND UserKey = @PUser AND LayoutId = @Id;
SELECT N'Saved' AS Outcome, @Id AS LayoutId;
""";

    // the menu's pinned views of one person: their own pins (of their own layouts or published ones) and the pins for
    // everyone (of published layouts) -- by key; none while the table is not there
    public const string PinnedSql = """
IF OBJECT_ID(N'cfg.ViewPin') IS NULL OR OBJECT_ID(N'cfg.ViewLayout') IS NULL
BEGIN
    SELECT CAST(NULL AS nvarchar(16)) AS Scope, CAST(NULL AS int) AS LayoutId, CAST(NULL AS nvarchar(80)) AS Name,
           CAST(NULL AS nvarchar(64)) AS [View], CAST(NULL AS nvarchar(512)) AS [Path] WHERE 1 = 0;
    RETURN;
END
SELECT p.Scope, p.LayoutId, l.Name, l.[View], p.[Path]
FROM cfg.ViewPin AS p
JOIN cfg.ViewLayout AS l ON l.LayoutId = p.LayoutId
WHERE (p.Scope = N'tenant' AND p.UserKey = N'' AND l.Scope = N'shared')
   OR (p.Scope = N'user' AND p.UserKey = @UserKey AND (l.Scope = N'shared' OR (l.Scope = N'user' AND l.UserKey = @UserKey)))
ORDER BY p.Scope, l.Name;
""";

    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;

    private static bool Same(string? a, string? b) => string.Equals(a ?? "", b ?? "", StringComparison.Ordinal);

    public async Task<StoredLayouts> ReadAsync(string view, string userKey, CancellationToken ct)
    {
        var rows = await sql.QueryAsync(ReadSql, new Dictionary<string, object?> { ["View"] = Cut(view, MaxView), ["UserKey"] = Cut(userKey, MaxUserKey) }, ct);
        return FromRows(rows);
    }

    /// The rows of <see cref="ReadSql"/> as one answer (no row, or the 'none' marker = the layouts table is not there yet).
    public static StoredLayouts FromRows(IReadOnlyList<SqlRow> rows)
    {
        string? tenant = null, user = null, state = null, widths = null;
        int? activeId = null;
        bool ready = false, more = false;
        var named = new List<NamedLayout>();
        var pinsMine = new HashSet<int>();
        var pinsAll = new HashSet<int>();
        SqlRow? active = null;
        foreach (var r in rows)
        {
            switch (r.Str("Kind"))
            {
                case "ready": ready = true; break;
                case "more": ready = true; more = true; break;
                case "tenant": tenant = r.Str("ColumnsJson"); break;
                case "user": user = r.Str("ColumnsJson"); break;
                case "state":
                    state = r.Str("StateJson");
                    widths = r.Str("WidthsJson");
                    activeId = r.Long("LayoutId") is { } sid ? (int?)sid : null;
                    break;
                case "pin":
                    if (r.Long("LayoutId") is not { } pid) break;
                    (r.Str("Name") == "tenant" ? pinsAll : pinsMine).Add((int)pid);
                    break;
                case "named" or "shared":
                    if (r.Long("LayoutId") is not { } lid) break;
                    named.Add(new NamedLayout((int)lid, r.Str("Name") ?? "", r.Str("Kind") == "shared"));
                    // the read hands over the content of the layout in use only
                    if (r.Str("ColumnsJson") is not null) active = r;
                    break;
            }
        }
        if (!ready) return new StoredLayouts(false, null, null);
        // a layout in use that was deleted meanwhile: none is in use, the person's columns stay as they are
        if (activeId is { } a && !named.Any(n => n.Id == a)) activeId = null;
        var changed = activeId is not null && active is not null
            && !(Same(user, active.Str("ColumnsJson")) && Same(state, active.Str("StateJson")) && Same(widths, active.Str("WidthsJson")));
        return new StoredLayouts(true, tenant, user)
        {
            More = more, State = string.IsNullOrEmpty(state) ? null : state, Widths = string.IsNullOrEmpty(widths) ? null : widths,
            ActiveId = activeId, ActiveChanged = changed,
            Named = named.Select(n => n with { PinnedMine = pinsMine.Contains(n.Id), PinnedForAll = n.Shared && pinsAll.Contains(n.Id) })
                .OrderBy(n => n.Shared).ThenBy(n => n.Name, StringComparer.OrdinalIgnoreCase).ToList(),
        };
    }

    public async Task<bool> SaveAsync(string scope, string userKey, string view, string columnsJson, string by, CancellationToken ct)
    {
        if (scope is not (ScopeTenant or ScopeUser)) throw new ArgumentException("the scope is tenant or user");
        if (columnsJson.Length > MaxColumnsJson) throw new ArgumentException("too many columns");
        var r = await sql.QueryAsync(SaveSql, new Dictionary<string, object?>
        {
            ["Scope"] = scope, ["UserKey"] = scope == ScopeTenant ? "" : Cut(userKey, MaxUserKey), ["View"] = Cut(view, MaxView),
            ["Columns"] = columnsJson, ["By"] = Cut(by, MaxUserKey),
        }, ct);
        return r.FirstOrDefault()?.Str("Outcome") == "Saved";
    }

    public async Task<bool> ResetAsync(string scope, string userKey, string view, CancellationToken ct)
    {
        if (scope is not (ScopeTenant or ScopeUser)) throw new ArgumentException("the scope is tenant or user");
        var r = await sql.QueryAsync(ResetSql, new Dictionary<string, object?>
        {
            ["Scope"] = scope, ["UserKey"] = scope == ScopeTenant ? "" : Cut(userKey, MaxUserKey), ["View"] = Cut(view, MaxView),
        }, ct);
        return r.FirstOrDefault()?.Str("Outcome") == "Saved";
    }

    private Dictionary<string, object?> Key(string userKey, string view) =>
        new() { ["UserKey"] = Cut(userKey, MaxUserKey), ["View"] = Cut(view, MaxView) };

    private async Task<(string Outcome, int? Id)> RunAsync(string batch, Dictionary<string, object?> p, CancellationToken ct)
    {
        var r = (await sql.QueryAsync(batch, p, ct)).FirstOrDefault();
        return (r?.Str("Outcome") ?? LayoutOutcome.Missing, r?.Long("LayoutId") is { } id ? (int?)id : null);
    }

    public async Task<bool> SaveStateAsync(string userKey, string view, string? stateJson, CancellationToken ct)
    {
        if (stateJson is { Length: > MaxStateJson }) throw new ArgumentException("too many filters");
        var p = Key(userKey, view);
        p["State"] = string.IsNullOrEmpty(stateJson) ? null : stateJson;
        return (await RunAsync(SaveStateSql, p, ct)).Outcome == LayoutOutcome.Saved;
    }

    public async Task<bool> SaveWidthsAsync(string userKey, string view, string? widthsJson, CancellationToken ct)
    {
        if (widthsJson is { Length: > MaxWidthsJson }) throw new ArgumentException("too many column widths");
        var p = Key(userKey, view);
        p["Widths"] = string.IsNullOrEmpty(widthsJson) ? null : widthsJson;
        return (await RunAsync(SaveWidthsSql, p, ct)).Outcome == LayoutOutcome.Saved;
    }

    public async Task<bool> ClearSettingsAsync(string userKey, string view, CancellationToken ct) =>
        (await RunAsync(ClearSettingsSql, Key(userKey, view), ct)).Outcome == LayoutOutcome.Saved;

    public async Task<(string Outcome, int? Id)> SaveNamedAsync(NamedLayoutWrite layout, CancellationToken ct)
    {
        if (layout.Shared && !layout.Admin) return (LayoutOutcome.Forbidden, null);
        if (layout.ColumnsJson.Length > MaxColumnsJson) throw new ArgumentException("too many columns");
        if (layout.StateJson is { Length: > MaxStateJson }) throw new ArgumentException("too many filters");
        var p = Key(layout.UserKey, layout.View);
        p["Columns"] = layout.ColumnsJson;
        p["State"] = string.IsNullOrEmpty(layout.StateJson) ? null : layout.StateJson;
        p["UseStored"] = layout.UseStoredState ? 1 : 0;
        p["By"] = Cut(layout.By, MaxUserKey);
        if (layout.Id is { } id)
        {
            p["Id"] = id;
            p["Admin"] = layout.Admin ? 1 : 0;
            return await RunAsync(SaveNamedExistingSql, p, ct);
        }
        var name = layout.Name.Trim();
        if (name.Length is 0 or > MaxName) throw new ArgumentException("the name is 1 to 80 characters");
        p["Name"] = name;
        p["Scope"] = layout.Shared ? ScopeShared : ScopeUser;
        p["Owner"] = layout.Shared ? "" : Cut(layout.UserKey, MaxUserKey);
        return await RunAsync(SaveNamedNewSql, p, ct);
    }

    public async Task<string> ApplyNamedAsync(int id, string userKey, string view, CancellationToken ct)
    {
        var p = Key(userKey, view);
        p["Id"] = id;
        p["By"] = Cut(userKey, MaxUserKey);
        return (await RunAsync(ApplyNamedSql, p, ct)).Outcome;
    }

    public async Task<string> RenameNamedAsync(int id, string userKey, string view, string name, bool admin, string by, CancellationToken ct)
    {
        var n = name.Trim();
        if (n.Length is 0 or > MaxName) throw new ArgumentException("the name is 1 to 80 characters");
        var p = Key(userKey, view);
        p["Id"] = id; p["Admin"] = admin ? 1 : 0; p["Name"] = n; p["By"] = Cut(by, MaxUserKey);
        return (await RunAsync(RenameNamedSql, p, ct)).Outcome;
    }

    public async Task<string> DeleteNamedAsync(int id, string userKey, string view, bool admin, CancellationToken ct)
    {
        var p = Key(userKey, view);
        p["Id"] = id; p["Admin"] = admin ? 1 : 0;
        return (await RunAsync(DeleteNamedSql, p, ct)).Outcome;
    }

    public async Task<string> PublishNamedAsync(int id, string userKey, string view, string by, CancellationToken ct)
    {
        var p = Key(userKey, view);
        // only an Admin reaches this (the page checks); the layout is the Admin's own, or already published
        p["Id"] = id; p["Admin"] = 1; p["By"] = Cut(by, MaxUserKey);
        return (await RunAsync(PublishNamedSql, p, ct)).Outcome;
    }

    public async Task<string> PinNamedAsync(int id, string userKey, string view, bool pin, bool forAll, bool admin, string path, string by, CancellationToken ct)
    {
        if (forAll && !admin) return LayoutOutcome.Forbidden;
        if (path.Length is 0 or > MaxPinPath) throw new ArgumentException("the page address is 1 to 512 characters");
        var p = Key(userKey, view);
        p["Id"] = id; p["Pin"] = pin ? 1 : 0; p["ForAll"] = forAll ? 1 : 0; p["Admin"] = admin ? 1 : 0;
        p["Path"] = path; p["By"] = Cut(by, MaxUserKey);
        return (await RunAsync(PinNamedSql, p, ct)).Outcome;
    }

    public async Task<IReadOnlyList<PinnedView>> PinnedAsync(string userKey, CancellationToken ct)
    {
        var rows = await sql.QueryAsync(PinnedSql, new Dictionary<string, object?> { ["UserKey"] = Cut(userKey, MaxUserKey) }, ct);
        var list = new List<PinnedView>();
        foreach (var r in rows)
        {
            if (r.Long("LayoutId") is not { } id || r.Str("Path") is not { Length: > 0 } path) continue;
            var forAll = r.Str("Scope") == "tenant";
            // the same layout pinned for everyone AND in My views is listed once, for everyone
            if (list.Any(x => x.Id == id)) { if (forAll) list[list.FindIndex(x => x.Id == id)] = list.First(x => x.Id == id) with { ForAll = true }; continue; }
            list.Add(new PinnedView((int)id, r.Str("Name") ?? "", r.Str("View") ?? "", path, forAll));
        }
        return list;
    }
}
