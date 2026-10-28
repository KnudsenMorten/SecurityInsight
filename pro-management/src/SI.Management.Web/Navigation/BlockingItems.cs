using System.Globalization;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Changes;
using SI.Management.Web.Data;

namespace SI.Management.Web.Navigation;

/// <summary>
/// Framework PENDING-1 (owner 2026-10-08: "if there is a pending task like an approval, show it very clearly in the main
/// menu + submenu"): what waits for a person's decision and BLOCKS work, counted from the data on every page load -- no
/// acknowledgement, gone by itself once decided. Each kind names the page where it is decided and who decides it, so a
/// person who cannot act sees it too, read-only, with who can.
/// </summary>
/// <param name="Kind">guard-hold | approval-guard-release | approval-restore | approval-import | approval-other | exemption-request | template-held</param>
/// <param name="Page">The Razor page it is decided on (a menu item or a tab of one); null = no page of its own.</param>
public sealed record BlockingItem(string Kind, string? Page, int Count, string Text, string WhoCanAct);

public sealed record BlockingSummary(IReadOnlyList<BlockingItem> Items)
{
    public static readonly BlockingSummary None = new(Array.Empty<BlockingItem>());

    public int Total => Items.Sum(i => i.Count);

    /// The count on one menu entry: its own page, or any of its tabs.
    public int CountFor(NavItem item) => Items.Where(i => On(item, i)).Sum(i => i.Count);

    /// The count on one tab of a menu entry.
    public int CountFor(NavTab tab) => Items.Where(i => Same(tab.Page, i.Page)).Sum(i => i.Count);

    /// The count on a top-menu group: the sum over the entries of it the person sees.
    public int CountFor(IEnumerable<NavItem> shown) => shown.Sum(i => CountFor(i));

    /// The one Overview line: "2 items are blocking: 1 guard hold waits for a SuperAdmin, ...".
    public string Line => Total switch
    {
        0 => "",
        1 => "1 item is blocking: " + Words + ".",
        var n => n.ToString(CultureInfo.InvariantCulture) + " items are blocking: " + Words + ".",
    };

    private string Words => string.Join("; ", Items.Select(i => i.Text + " -- " + i.WhoCanAct));

    /// The tooltip of a badge: what waits there and who decides it.
    public string TitleFor(NavItem item) => string.Join(" ", Items.Where(i => On(item, i)).Select(i => i.Text + " -- " + i.WhoCanAct + "."));

    /// The items shown on one menu entry: decided on its page or on one of its tabs.
    private static bool On(NavItem item, BlockingItem i) => Same(item.Page, i.Page) || (item.Tabs?.Any(t => Same(t.Page, i.Page)) ?? false);

    private static bool Same(string page, string? other) => other is not null && NavModel.HrefOf(page).Equals(NavModel.HrefOf(other), StringComparison.OrdinalIgnoreCase);
}

public interface IBlockingItemSource
{
    Task<BlockingSummary> ReadAsync(CancellationToken ct);
}

/// <summary>
/// The blocking items of this install: held guard sets (cfg.GuardRelease, held and not expired), requests waiting for a
/// second SuperAdmin (cfg.ConfigApproval, pending and not expired) and Microsoft content held from installing (the
/// template releases, split install only). The two counts are read on every load (one small batch); the template state,
/// which only an updater run or an Install changes, is kept for 30 seconds. Never fails a page: what cannot be read
/// counts as nothing.
/// </summary>
public sealed class SqlBlockingItemSource(ISqlExecutor sql, TemplateReleases releases, IMemoryCache cache, ILogger<SqlBlockingItemSource> log) : IBlockingItemSource
{
    public const string CountsSql = """
DECLARE @r TABLE (Kind NVARCHAR(40) NOT NULL, N INT NOT NULL);
IF OBJECT_ID(N'cfg.GuardRelease') IS NOT NULL
    INSERT @r SELECT N'guard-hold', COUNT(*) FROM cfg.GuardRelease WHERE State = N'held' AND ExpiresUtc > SYSUTCDATETIME();
IF OBJECT_ID(N'cfg.ConfigApproval') IS NOT NULL
    INSERT @r SELECT N'approval-' + k.K, COUNT(*) FROM cfg.ConfigApproval a
        CROSS APPLY (SELECT CASE WHEN a.Kind = N'restore' AND a.Title LIKE N'Import %' THEN N'import' ELSE a.Kind END AS K) k
        WHERE State = N'pending' AND ExpiresUtc > SYSUTCDATETIME() GROUP BY k.K;
IF OBJECT_ID(N'cfg.ExemptionRequest') IS NOT NULL
    INSERT @r SELECT N'exemption-request', COUNT(*) FROM cfg.ExemptionRequest WHERE State = N'requested';
SELECT Kind, N FROM @r WHERE N > 0;
""";

    private const string TemplateKey = "si-blocking-templates";
    public static readonly TimeSpan TemplateCacheFor = TimeSpan.FromSeconds(30);

    public async Task<BlockingSummary> ReadAsync(CancellationToken ct)
    {
        var items = new List<BlockingItem>();
        try
        {
            foreach (var r in await sql.QueryAsync(CountsSql, new Dictionary<string, object?>(), ct))
                if (Of(r.Str("Kind") ?? "", (int)(r.Long("N") ?? 0)) is { } i) items.Add(i);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { log.LogDebug(ex, "blocking items (guards, approvals) could not be read"); }

        if (await HeldTemplatePacksAsync(ct) is { } t) items.Add(t);
        return new BlockingSummary(items.OrderBy(i => Order(i.Kind)).ToList());
    }

    private async Task<BlockingItem?> HeldTemplatePacksAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(TemplateKey, out int held)) return Templates(held);
        held = 0;
        try
        {
            var (packTable, versioning) = await releases.SchemaAsync(ct);
            if (packTable && versioning)
            {
                var summary = TemplateInstallSummary.From(await releases.InstallStateAsync(ct), await releases.HistoryAsync(ct), await releases.HoldAsync(ct));
                if (summary.Split) held = HeldPacks(await releases.StagedAsync(ct), summary);
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { log.LogDebug(ex, "held template packs could not be read"); }
        cache.Set(TemplateKey, held, TemplateCacheFor);
        return Templates(held);
    }

    /// The staged packs that wait for a person's Install: held -- the customer's Hold, or a roll back from the pack. Owner
    /// decision 2026-10-11: every other pack installs automatically (also one that carries more than Microsoft content, and on
    /// ring 1's direct install), so it is never counted. A pack that waits for a newer SecurityInsight waits for the updater.
    public static int HeldPacks(IEnumerable<StagedPackInfo> staged, TemplateInstallSummary summary)
    {
        var all = staged as IReadOnlyList<StagedPackInfo> ?? staged.ToList();
        var sum = summary.WithStaged(all);
        return all.Count(s => TemplatePackState.Of(s, sum).State is TemplatePackState.Held);
    }

    private static BlockingItem? Templates(int n) => n <= 0 ? null
        : new("template-held", "/Templates/Releases", n, Plural(n, "template pack is", "template packs are") + " held from installing", "a SuperAdmin installs it on Template releases");

    /// One row of the count batch in words, or null for a kind with nothing waiting.
    public static BlockingItem? Of(string kind, int n) => n <= 0 ? null : kind switch
    {
        "guard-hold" => new(kind, "/Admin/Guards", n, Plural(n, "guard hold waits", "guard holds wait") + " for a release", "a SuperAdmin releases it on Guards; an Admin acknowledges it"),
        "approval-" + SI.Management.Web.ChangeJournal.ConfigApproval.GuardRelease => new(kind, "/Admin/Guards", n,
            Plural(n, "guard release waits", "guard releases wait") + " for a second SuperAdmin", "another SuperAdmin than the one who asked approves it on Guards"),
        "approval-" + SI.Management.Web.ChangeJournal.ConfigApproval.Restore => new(kind, "/Admin/Backups", n,
            Plural(n, "restore waits", "restores wait") + " for a second SuperAdmin", "another SuperAdmin than the one who asked approves it on Backups"),
        // a configuration import (Export / Import) with the second person on is a restore request titled "Import ..." -- the
        // import staging: nothing of the file is applied until another SuperAdmin approves it on Backups
        "approval-" + ImportKind => new(kind, "/Admin/Backups", n,
            Plural(n, "configuration import waits", "configuration imports wait") + " for a second SuperAdmin", "another SuperAdmin than the one who imported approves it on Backups"),
        // an exemption request (Ignore / Accept the risk) waits for an approver of its domain / category: it blocks the
        // requester's exemption until decided (SI #473)
        "exemption-request" => new(kind, "/Exemptions/Index", n, Plural(n, "exemption request waits", "exemption requests wait") + " for a decision",
            "an owner or approver of its domain or category (or an Admin) decides it on Exemptions"),
        _ when kind.StartsWith("approval-", StringComparison.Ordinal) => new("approval-other", null, n,
            Plural(n, "request waits", "requests wait") + " for a second SuperAdmin", "another SuperAdmin approves it"),
        _ => null,
    };

    /// The count batch's kind for a configuration import waiting for its second SuperAdmin (approval-import).
    public const string ImportKind = "import";

    private static int Order(string kind) => kind switch { "guard-hold" => 0, "approval-guard-release" => 1, "approval-restore" => 2, "approval-import" => 3, "exemption-request" => 4, "template-held" => 5, _ => 6 };

    private static string Plural(int n, string one, string many) => n.ToString(CultureInfo.InvariantCulture) + " " + (n == 1 ? one : many);
}
