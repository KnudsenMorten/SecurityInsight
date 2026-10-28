using System.Globalization;
using SI.Management.Core.ProData;
using SI.Management.Web.Navigation;
using SI.Management.Web.Pages;

namespace SI.Management.Web.RiskExec;

/// One line of a block: what it is, the value as shown, its change since the last report, where a click goes, a note.
public sealed record FigureLine(string Key, string Label, string Value, ChangeSince? Change = null, string? Href = null, string? Note = null, double? Raw = null);

/// A small table of a block or a topic: headers, rows of cells (text), a link per row (or none), a note under it.
public sealed record FigureTable(string Key, string Title, IReadOnlyList<string> Headers, IReadOnlyList<IReadOnlyList<string>> Rows,
    IReadOnlyList<string?>? Hrefs = null, string? Note = null, IReadOnlyList<double>? Bars = null);

/// One block of the Executive report (and its topics): its lines and tables, or why it is not available.
public sealed record ReportBlock(string Key, string Title, IReadOnlyList<FigureLine> Lines, IReadOnlyList<FigureTable> Tables, string? Unavailable = null);

/// <summary>
/// THE KEY FIGURES of one collection, read ONCE and shown by BOTH Overview > Executive overview (the topics) and Overview >
/// Executive report (the blocks in their fixed order, its PDF and the management mail) -- one source, so the two can never
/// disagree (#636, owner 2026-10-19). Every figure is a stored row of sidata.KeyFigure (the data sync writes them per
/// collection, SI-DataKeyFigures.ps1); "change since the last report" is the same row of the collection before; the top
/// fixes and assets are the stored remediations. Nothing is computed from the findings here.
/// </summary>
public sealed class ExecutiveFigures
{
    public ViewCollection? Current { get; init; }
    public ViewCollection? Previous { get; init; }
    public IReadOnlyList<KeyFigureRow> Now { get; init; } = [];
    public IReadOnlyList<KeyFigureRow> Before { get; init; } = [];
    public IReadOnlyList<KeyFigurePoint> Trend { get; init; } = [];
    public IReadOnlyList<IReadOnlyDictionary<string, object?>> TopFixes { get; init; } = [];
    public IReadOnlyList<IReadOnlyDictionary<string, object?>> TopAssets { get; init; } = [];
    public List<QueryInfo> Queries { get; } = new();
    /// #818 (owner 2026-10-20: "why can i not select previous data collection sets ... so we can easily compare"): every
    /// complete run a page can show (the published one first, never a loading / stopped one -- CollectionViewSql.CollectionsReady)
    /// and whether the run compared with was CHOSEN (else it is the run before the shown one).
    public IReadOnlyList<ViewCollection> Collections { get; init; } = [];
    public bool Compared { get; init; }
    /// Said under the headline when the run compared with has no key figures (the change column stays empty).
    public string? CompareNote { get; init; }
    /// Why there is nothing to show (no collection, not built yet); null = figures are there.
    public string? Missing { get; init; }
    public string? Error { get; init; }

    public bool Ready => Missing is null && Now.Count > 0;

    /// The blocks of the Executive report, in their fixed order (owner 2026-10-19), and the topics' keys.
    public static readonly IReadOnlyList<(string Key, string Title)> Blocks =
    [
        // the protection score leads (owner 2026-10-19: "a new number which defines our ability to protect our assets")
        ("protection", "Protection score"),
        ("patching", "1. Patching"), ("exposure", "2. Exposure"), ("coverage", "3. Coverage"), ("identity", "4. Identity"),
        ("cloud", "5. Cloud"), ("todo", "6. What to do first"), ("trend", "7. Trend"),
    ];

    /// The headline figures on top of both pages, each opening its topic.
    public static readonly IReadOnlyList<(string Key, string Label, string Block, string Figure, Better Better, string Topic)> Headlines =
    [
        // owner 2026-10-19: "i prefer both models as mgmt are different" -- the two views side by side, the accepted lifecycle first
        // owner 2026-10-20: "the word technical must be changed to Protection Score, Actual Risks. The other should be Protection
        // Score, within Accepted Lifecycle" (the codes lifecycle / technical stay: URLs, stored figures)
        ("protection_lifecycle", LifecycleName + " (higher is better)", "headline", "protection_lifecycle", Better.Higher, "protection"),
        ("protection_technical", ActualName + " (higher is better)", "headline", "protection_technical", Better.Higher, "protection"),
        ("very_high_high", "Very High + High findings open", "headline", "very_high_high", Better.Lower, "patches"),
        ("known_exploited", "Known exploited CVEs open", "headline", "known_exploited", Better.Lower, "exploited"),
        ("sla_breaches", "Findings past their due date", "patching", "sla_breaches", Better.Lower, "patches"),
    ];

    /// The topics of the Executive overview (owner 2026-10-19: "buttons of most interesting topics so they can click around").
    public static readonly IReadOnlyList<(string Key, string Label)> Topics =
    [
        ("protection", "Protection score"), ("patches", "Missing patches & findings"), ("os", "Windows vs Linux"), ("devices", "Servers vs clients"), ("exploited", "Known exploited"),
        ("internet", "Internet exposed"), ("tier0", "Tier 0"), ("eos", "End of support"), ("coverage", "Not onboarded / not seen"),
        ("identity", "MFA & admins"), ("cloud", "Cloud (per subscription)"), ("fixes", "Top fixes"), ("trend", "Trend"),
    ];

    public KeyFigureRow? Get(string block, string figure, string dim1 = "", string dim2 = "") =>
        Now.FirstOrDefault(r => r.Block == block && r.Figure == figure && r.Dim1 == dim1 && r.Dim2 == dim2);

    /// <summary>
    /// #859 (owner 2026-10-21: "do we have static values in the code ?"): the window a figure of THIS collection was worked
    /// out with -- its meta "window" row, written by the key figures from the install's setting (Get-SIKeyFigureWindowSettings,
    /// SI_KeyFigures_*). A collection figured before the windows were recorded was figured with the shipped defaults
    /// (<see cref="KeyFigureWindows"/>), so the label says what was in force then.
    /// </summary>
    public int Window(string key) =>
        Now.FirstOrDefault(r => r.Block == "meta" && r.Figure == "window" && r.Dim1 == key && r.Dim2 == "") is { Value: { } v } && v >= 1 ? (int)Math.Round(v) : KeyFigureWindows.Default(key);

    /// "N days" / "1 day" (a window in words, invariant digits).
    public static string Days(int n) => n.ToString(CultureInfo.InvariantCulture) + (n == 1 ? " day" : " days");

    private KeyFigureRow? Was(string block, string figure, string dim1 = "", string dim2 = "") =>
        Before.FirstOrDefault(r => r.Block == block && r.Figure == figure && r.Dim1 == dim1 && r.Dim2 == dim2);

    public string? Since => Previous is null || Before.Count == 0 ? null : Fmt.Day(DateOnly.FromDateTime(Previous.CollectionTime));

    /// The value of a figure as shown ("–" when there is none), the figure's assets when <paramref name="assets"/>.
    public static string Show(KeyFigureRow? r, bool assets = false, bool score = false) =>
        r is null ? "–" : !r.Available ? "not available yet" : (assets ? r.Assets : r.Value) is { } v ? (score ? Fmt.Score(v) : Fmt.Int((long)Math.Round((double)v))) : "–";

    /// The change of one figure since the last report (null = nothing to compare).
    public ChangeSince? Change(string block, string figure, Better better, string dim1 = "", string dim2 = "", bool assets = false, ChangeKind kind = ChangeKind.Count)
    {
        var a = Get(block, figure, dim1, dim2); var b = Was(block, figure, dim1, dim2);
        if (a is not { Available: true } || b is not { Available: true } || Since is null) return null;
        double? V(KeyFigureRow r) => assets ? r.Assets : r.Value;
        return ChangeSince.Of(V(a), V(b), better, kind, Since);
    }

    /// The headline line of one headline key -- what BOTH pages show (one source).
    public FigureLine Headline(string key)
    {
        var h = Headlines.First(x => x.Key == key);
        var dim = key == "sla_breaches" ? "(all)" : "";
        var r = Get(h.Block, h.Figure, dim);
        var pct = key.StartsWith("protection_", StringComparison.Ordinal);
        return new FigureLine(key, h.Label, pct ? ShowScore(r) : Show(r), Change(h.Block, h.Figure, h.Better, dim, kind: pct ? ChangeKind.Percent : ChangeKind.Count),
            TopicHref(h.Topic) + (key == "protection_technical" ? "&view=technical" : ""), r is { Available: false } ? r.Note : null, r?.Value);
    }

    /// A percentage figure as shown: "53.7 %" ("–" when there is none).
    public static string ShowPct(KeyFigureRow? r) => r is null ? "–" : !r.Available ? "not available yet" : r.Value is { } v ? Fmt.Pct(v, 1) : "–";

    /// A Protection Score as shown: the % and its band's words ("96.5 % · Very Good"; the bands: ProtectionBands, one definition).
    public static string ShowScore(KeyFigureRow? r) => r is { Available: true, Value: { } v } ? Fmt.Pct(v, 1) + " · " + ProtectionBands.Of(v).Name : ShowPct(r);

    /// The two Protection Score names (owner 2026-10-20) -- every page, mail and export says them the same way.
    public const string LifecycleName = "Protection Score, within Accepted Lifecycle";
    public const string ActualName = "Protection Score, Actual Risks";

    public static string TopicHref(string topic, string? mode = null, string? pivot = null) =>
        "/Management/Overview?topic=" + Uri.EscapeDataString(topic) + (mode is null ? "" : "&mode=" + mode) + (pivot is null ? "" : "&pivot=" + pivot);

    // ---- the patch cycle (owner 2026-10-19: "we need a filter option, where we filter between 'being fixed during monthly
    // lifecycle' vs. 'catch-up older than 1 month'") ---------------------------------------------------------------------

    /// The cycles of the topic's first split, in toggle order: the code, the words.
    public static readonly IReadOnlyList<(string Code, string Label)> Cycles =
        [("all", "All"), ("cycle", "In monthly cycle"), ("catchup", "Catch-up (older than 1 month)"), ("nofix", "No single update / no fix"), ("unknown", "Not classified (unknown cycle)")];

    public static string CycleCode(string? c) => Cycles.Any(x => x.Code == c) ? c! : "all";
    public static string ModeCode(string? m) => m == "all" ? "all" : "cve";

    /// The stored figure of a patch-topic table: "matrix_cve_catchup".
    public static string Fig(string what, string mode, string cycle) => what + "_" + ModeCode(mode) + "_" + CycleCode(cycle);

    /// The headline numbers side by side: "In monthly cycle: N findings on M devices", one per cycle that has findings.
    public IReadOnlyList<FigureLine> CycleLines(string mode) =>
        Cycles.Where(c => c.Code != "all").Select(c => Get("patches", "cycle_" + ModeCode(mode), c.Code) is { } r
            ? new FigureLine("cycle." + c.Code, c.Label, Fmt.Int((long)(r.Value ?? 0)) + " findings on " + Fmt.Int(r.Assets) + " devices",
                Change("patches", "cycle_" + ModeCode(mode), Better.Lower, c.Code), TopicHref("patches", ModeCode(mode)) + "&cycle=" + c.Code, Raw: r.Value)
            : null).Where(l => l is not null).Select(l => l!).ToList();
    /// The Executive report top to bottom: every chosen block in the fixed order; the patching block is followed by its three
    /// groups (in the monthly cycle, catch-up, no single update) as the owner's mail lays them out. The page, its PDF and the
    /// management mail all read this list.
    public IReadOnlyList<ReportBlock> ReportBlocks(Func<string, bool>? include = null, string? protectionView = null)
    {
        var list = new List<ReportBlock>();
        foreach (var (key, _) in Blocks)
        {
            if (include is not null && !include(key)) continue;
            list.Add(key == "protection" ? Protection(protectionView) : Block(key));
            if (key == "patching" && Ready)
            {
                list.AddRange(PatchSections("cve"));
            }
        }
        return list;
    }
    // ---- the topic "Missing patches & findings" laid out as the owner's mail (2026-10-19: "can you rewrite the email and
    // then structure it into this view"): the total and the three groups on top, then a section per group ending with a
    // suggested action worked out from the data ----------------------------------------------------------------------

    /// The three groups of the topic, in order: the cycle code, the tile's words, what it means.
    public static readonly IReadOnlyList<(string Code, string Label, string Means)> PatchGroups =
    [
        ("cycle", "1. In monthly cycle", "normal rollout, no action"),
        ("catchup", "2. Catch-up", "the fix is older than the monthly cycle: act"),
        ("nofix", "3. No single update / no fix", "browsers, third-party software, configuration: who owns those updates?"),
    ];

    private KeyFigureRow? Cell(string mode, string cycle, string dim1, string dim2) => Get("patches", Fig("matrix", mode, cycle), dim1, dim2);

    /// The tiles on top: the total, then each group with its share of the total; a tile opens (filters to) its group.
    public IReadOnlyList<FigureLine> PatchTiles(string mode)
    {
        var all = Cell(mode, "all", "(all)", "(all)");
        var noun = ModeCode(mode) == "all" ? "findings" : "missing CVEs";
        var tiles = new List<FigureLine>
        {
            new("total", "Total " + noun, all is null ? "–" : Fmt.Int((long)(all.Value ?? 0)) + " on " + Fmt.Int(all.Assets) + " devices",
                Change("patches", Fig("matrix", mode, "all"), Better.Lower, "(all)", "(all)"), TopicHref("patches", ModeCode(mode)), Raw: all?.Value),
        };
        foreach (var (code, label, means) in PatchGroups)
        {
            var c = Cell(mode, code, "(all)", "(all)");
            tiles.Add(new FigureLine("group." + code, label, c is null ? "0" : Fmt.Int((long)(c.Value ?? 0)) + " on " + Fmt.Int(c.Assets) + " devices (" + Pct((long?)c.Value, (long?)all?.Value) + ")",
                Change("patches", Fig("matrix", mode, code), Better.Lower, "(all)", "(all)"), TopicHref("patches", ModeCode(mode)) + "&cycle=" + code, means, c?.Value));
        }
        // #906 never hide findings: the ones no group takes (an update whose month cannot be read) are a 4th tile whenever there are any
        if (Unclassified(mode) is { } u)
            tiles.Add(new FigureLine("group." + UnknownGroup.Code, UnknownGroup.Label, Fmt.Int((long)(u.Value ?? 0)) + " on " + Fmt.Int(u.Assets) + " devices (" + Pct((long?)u.Value, (long?)all?.Value) + ")",
                Change("patches", Fig("matrix", mode, UnknownGroup.Code), Better.Lower, "(all)", "(all)"), TopicHref("patches", ModeCode(mode)) + "&cycle=" + UnknownGroup.Code, UnknownGroup.Means, u.Value));
        return tiles;
    }

    /// #906 (internal 2026-10-27: 13 workstations, 12,709 CVE findings, all Unknown, the page said "Clients: 0 findings on 0
    /// devices"): the findings no group takes -- shown as their own group whenever there are any, never left out.
    public static readonly (string Code, string Label, string Means) UnknownGroup =
        ("unknown", "Not classified (unknown cycle)", "the update's month cannot be read: counted in none of the three groups");

    /// The unclassified findings of the run (null when there are none: the 4th group is then not shown).
    public KeyFigureRow? Unclassified(string mode) => Cell(mode, UnknownGroup.Code, "(all)", "(all)") is { Value: > 0 } r ? r : null;

    private FigureLine Side(string mode, string cycle, string dc, string label, bool devicesFirst)
    {
        var r = Cell(mode, cycle, "(all)", dc);
        var findings = Fmt.Int((long)(r?.Value ?? 0)); var devices = Fmt.Int(r?.Assets ?? 0); var vh = Fmt.Int(r?.VeryHigh ?? 0);
        var text = devicesFirst ? devices + " devices behind (" + findings + " findings, " + vh + " Very High)" : findings + " findings on " + devices + " devices (" + vh + " Very High)";
        return new FigureLine(cycle + "." + dc, label, text, Change("patches", Fig("matrix", mode, cycle), Better.Lower, "(all)", dc, assets: devicesFirst),
            CiFindings(AssetTypeOf(dc) is { } at ? new[] { ("f.AssetType", at), ("f.FindingKey", ModeCode(mode) == "all" ? "" : "CVE-") } : Array.Empty<(string, string)>()), Raw: devicesFirst ? r?.Assets : r?.Value);
    }

    private FigureTable Devices(string mode, string cycle, string title)
    {
        var rows = Now.Where(r => r.Block == "patches" && r.Figure == Fig("devices", mode, cycle)).OrderByDescending(r => r.Value).Take(15).ToList();
        return new FigureTable("devices-" + cycle, title, ["Device", "Type", "Findings", ModeCode(mode) == "all" ? "Fixes / software" : "Updates / software", "Very High"],
            rows.Select(r => (IReadOnlyList<string>)[r.Dim2, r.Note ?? "", Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Items), Fmt.Int(r.VeryHigh)]).ToList(),
            rows.Select(r => (string?)("/Collection/Asset?key=" + Uri.EscapeDataString(r.Dim1))).ToList(), rows.Count == 0 ? "No device in this group." : null, rows.Select(r => r.Value ?? 0).ToList());
    }

    /// The fixes of a group, as the mail lists them: "KB5124008 · September 2026 Security Updates · 23.610 on 36 clients", oldest first for catch-up.
    private FigureTable GroupFixes(string mode, string cycle, string title, bool oldestFirst)
    {
        var rows = Now.Where(r => r.Block == "patches" && r.Figure == Fig("fix", mode, cycle) && r.Dim1 != "(no single update)").ToList();
        rows = oldestFirst ? rows.OrderBy(r => Array.IndexOf(LagOrder, r.Note ?? "") is var i and >= 0 ? -i : 0).ThenByDescending(r => r.Value).ToList() : rows.OrderByDescending(r => r.Value).ToList();
        rows = rows.Take(15).ToList();
        string On(KeyFigureRow r) => Fmt.Int((long)(r.Value ?? 0)) + " on " + (r.Clients is > 0 ? Fmt.Int(r.Clients) + " clients" : "") + (r.Clients is > 0 && r.Servers is > 0 ? " + " : "") + (r.Servers is > 0 ? Fmt.Int(r.Servers) + " servers" : "")
            + (r.Clients is not > 0 && r.Servers is not > 0 ? Fmt.Int(r.Assets) + " devices" : "");
        return new FigureTable("fixes-" + cycle, title, ["Update", "Name", "Findings", "Behind", ModeCode(mode) == "all" ? "Recommendations" : "CVEs"],
            rows.Select(r => (IReadOnlyList<string>)["KB" + r.Dim1.TrimStart('K', 'B'), r.Dim2, On(r), r.Note ?? "", Fmt.Int(r.Items)]).ToList(),
            rows.Select(r => (string?)null).ToList(), rows.Count == 0 ? "No update in this group." : null, rows.Select(r => r.Value ?? 0).ToList());
    }

    /// The sections of the topic (one group when <paramref name="cycle"/> names one), each with its suggested action.
    public IReadOnlyList<ReportBlock> PatchSections(string mode, string cycle = "all")
    {
        var list = new List<ReportBlock>();
        var want = CycleCode(cycle);
        string Count(KeyFigureRow? r) => Fmt.Int((long)(r?.Value ?? 0));
        if (want is "all" or "cycle")
        {
            var g = Cell(mode, "cycle", "(all)", "(all)");
            var top = Now.Where(r => r.Block == "patches" && r.Figure == Fig("fix", mode, "cycle") && r.Dim1 != "(no single update)").OrderByDescending(r => r.Value).FirstOrDefault();
            var action = g is not { Value: > 0 } ? "Nothing waits for the monthly rollout."
                : "Let the monthly rollout finish" + (top is null ? "" : " (" + top.Dim2 + ")") + ": " + Count(g) + " findings on " + Fmt.Int(g.Assets) + " devices close with this month's updates; check again after the rollout.";
            list.Add(new ReportBlock("group-cycle", "1. In monthly cycle -- normal rollout",
                [Side(mode, "cycle", "Client", "Clients", false), Side(mode, "cycle", "Server", "Servers", false),
                 new FigureLine("cycle.note", "What to expect", "should fall to near zero after the rollout; what is left becomes catch-up"),
                 new FigureLine("cycle.action", "Suggested action", action)],
                [GroupFixes(mode, "cycle", "The updates of this month", oldestFirst: false), Components(mode, "cycle")]));
        }
        if (want is "all" or "catchup")
        {
            var g = Cell(mode, "catchup", "(all)", "(all)");
            var oldest = Now.Where(r => r.Block == "patches" && r.Figure == Fig("fix", mode, "catchup") && r.Dim1 != "(no single update)")
                .OrderBy(r => Array.IndexOf(LagOrder, r.Note ?? "") is var i and >= 0 ? -i : 0).ThenByDescending(r => r.Value).FirstOrDefault();
            var action = g is not { Value: > 0 } ? "No device is behind the monthly cycle."
                : "Find out why " + Fmt.Int(g.Assets) + " devices are not taking updates" + (oldest is null ? "" : "; start with " + "KB" + oldest.Dim1.TrimStart('K', 'B') + " (" + (oldest.Note ?? "") + "): " + Count(oldest) + " findings on " + Fmt.Int(oldest.Assets) + " devices") + ".";
            list.Add(new ReportBlock("group-catchup", "2. Catch-up -- devices behind",
                [Side(mode, "catchup", "Client", "Clients behind", true), Side(mode, "catchup", "Server", "Servers behind", true),
                 new FigureLine("catchup.question", "The question", "why are these devices not taking updates?"),
                 new FigureLine("catchup.action", "Suggested action", action)],
                [GroupFixes(mode, "catchup", "The fixes, oldest and largest first", oldestFirst: true), Devices(mode, "catchup", "Devices behind"), Components(mode, "catchup")]));
        }
        if (want is "all" or "nofix")
        {
            var g = Cell(mode, "nofix", "(all)", "(all)");
            var sw = Now.Where(r => r.Block == "patches" && r.Figure == Fig("software", mode, "nofix")).OrderByDescending(r => r.Value).FirstOrDefault();
            var action = g is not { Value: > 0 } ? "Every finding here has a recommended update."
                : "Name an owner for these updates" + (sw is null ? "" : ": " + sw.Dim1 + " carries " + Count(sw) + " findings on " + Fmt.Int(sw.Assets) + " devices") + ".";
            list.Add(new ReportBlock("group-nofix", "3. No single update / no fix -- browsers, third-party, configuration",
                [Side(mode, "nofix", "Client", "Clients", false), Side(mode, "nofix", "Server", "Servers", false), new FigureLine("nofix.action", "Suggested action", action)],
                [Components(mode, "nofix"), Software(mode, 15, "nofix"), Devices(mode, "nofix", "Single machines far behind")]));
        }
        // #906: the 4th group whenever it has findings (the whole topic), or when it is asked for (a filter to it)
        if (want is "unknown" || (want is "all" && Unclassified(mode) is not null))
        {
            var g = Cell(mode, UnknownGroup.Code, "(all)", "(all)");
            var note = g is not { Value: > 0 } ? "Every finding has a known patch cycle."
                : Count(g) + " findings on " + Fmt.Int(g.Assets) + " devices have no known patch cycle: they are counted in none of the three groups above.";
            list.Add(new ReportBlock("group-unknown", "4. " + UnknownGroup.Label,
                [Side(mode, UnknownGroup.Code, "Client", "Clients", false), Side(mode, UnknownGroup.Code, "Server", "Servers", false),
                 new FigureLine("unknown.note", "Not in the groups", note),
                 new FigureLine("unknown.action", "Suggested action", g is not { Value: > 0 } ? "Nothing to do." : "Look at the recommended updates of these findings: SI cannot read the month they were released in.")],
                [GroupFixes(mode, UnknownGroup.Code, "The updates without a readable month", oldestFirst: false), Components(mode, UnknownGroup.Code), Software(mode, 15, UnknownGroup.Code)]));
        }
        return list;
    }
    // ---- the drill-downs: the pre-filtered views behind a number ---------------------------------------------------------

    private string Detailed(params (string K, string V)[] f)
    {
        var parts = new List<string>();
        if (Current is not null) parts.Add("c=" + Uri.EscapeDataString(Current.CollectionId));
        parts.AddRange(f.Select(x => Uri.EscapeDataString(x.K) + "=" + Uri.EscapeDataString(x.V)));
        return NavModel.HrefOf(NamedViews.DetailedPage) + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }

    private static string CiFindings(params (string K, string V)[] f) =>
        "/Cis/Findings" + (f.Length > 0 ? "?" + string.Join("&", f.Select(x => Uri.EscapeDataString(x.K) + "=" + Uri.EscapeDataString(x.V))) : "");

    /// The device type a matrix cell names as the CI's asset type (null = several / none).
    private static string? AssetTypeOf(string deviceClass) => deviceClass switch { "Server" => "Server", "Client" => "Workstation", _ => null };

    // ---- the blocks ------------------------------------------------------------------------------------------------------

    private static string Pct(long? part, long? whole) => part is { } p && whole is { } w && w > 0 ? Fmt.Pct(100.0 * p / w, 1) : "–";

    /// One block by its key, built from the stored figures.
    public ReportBlock Block(string key, string mode = "cve")
    {
        var title = Blocks.FirstOrDefault(b => b.Key == key).Title ?? key;
        if (!Ready) return new ReportBlock(key, title, [], [], Missing ?? "Not available yet.");
        return key switch
        {
            "protection" => Protection(null),
            "patching" => Patching(title, mode),
            "exposure" => Lines(key, title,
                Line("exposure", "tier0_very_high_high", "Tier-0 assets with Very High / High findings", Better.Lower, assets: false, total: true, href: Detailed(("f.Tier", "0"), ("f.Severity", "Very High"), ("f.Severity", "High"))),
                Line("exposure", "internet_very_high_cve", "Internet-exposed assets with a Very High CVE", Better.Lower, total: true),
                Line("exposure", "end_of_support", "Devices on end-of-support software", Better.Lower, dim1: "(all)", total: true),
                Line("exposure", "end_of_support", "Servers on end-of-support software", Better.Lower, dim1: "Servers", total: true)),
            "coverage" => Lines(key, title,
            [
                // #855 W11: the ACTIVE devices not onboarded, linked to exactly them (the CI list's Onboarding filter), then split by
                // Defender's onboarding status -- only "can be onboarded" is actionable; unsupported / insufficient info are devices
                // Defender only discovered on the network (#858)
                Line("coverage", "not_onboarded", "Active devices not onboarded to Defender for Endpoint", Better.Lower, total: true, href: SI.Management.Web.Pages.Cis.NotOnboardedModel.Route),
                .. OnboardingSplit(),
                // #855: the lifecycle's own "not seen" (no source saw it within its window; retired after its grace period) -- the
                // figure's key keeps its old name, its count follows the lifecycle in force
                Line("coverage", "not_seen_30d", "Devices not seen recently (retired after their grace period)", Better.Lower, total: true, href: "/Cis/Index?class=device&lifecycle=not_seen"),
                Line("coverage", "azure_vm_no_agent", "Azure VMs without the Defender agent", Better.Lower, total: true, href: "/Cis/Index"),
            ]),
            "identity" => Lines(key, title,
                Line("identity", "users_without_mfa", "Users without MFA", Better.Lower, total: true, href: "/Cis/Index"),
                Line("identity", "tier0_identities_at_risk", "Tier-0 (privileged) identities with Very High / High findings", Better.Lower, total: true),
                Line("identity", "stale_admins", "Privileged accounts without a sign-in for " + Days(Window(KeyFigureWindows.StaleAdminDays)), Better.Lower, total: true)),
            "cloud" => Cloud(title),
            "todo" => ToDo(title),
            "trend" => TrendBlock(title),
            _ => new ReportBlock(key, title, [], [], "Not available yet."),
        };
    }

    private ReportBlock Lines(string key, string title, params FigureLine[] lines) => new(key, title, lines, []);

    /// <summary>
    /// #855 W11 / #858: the onboarding statuses of the active devices not onboarded (the key figures' not_onboarded_status rows),
    /// in this order, the actionable one first; each links to the CI list's Onboarding filter (the active devices of that status).
    /// </summary>
    public static readonly IReadOnlyList<(string Code, string Label)> OnboardingSplitOrder =
    [
        ("can_be_onboarded", "… can be onboarded (actionable: Defender can onboard them)"),
        ("unsupported", "… unsupported by Defender for Endpoint"),
        ("insufficient_info", "… insufficient info (discovered on the network only)"),
        ("offboarded", "… offboarded"),
        ("unknown", "… no onboarding status"),
    ];

    /// The CI list of the active devices not onboarded (every status but onboarded and none).
    public static string NotOnboardedHref => "/Cis/Index?class=device"
        + string.Concat(OnboardingSplitOrder.Where(s => s.Code != "unknown").Select(s => "&" + SI.Management.Core.ProData.CiColumns.OnboardingParam + "=" + s.Code));

    /// The CI list of the active devices of one onboarding status ("unknown" = the active devices).
    public static string OnboardingHref(string code) => code == "unknown" ? "/Cis/Index?class=device"
        : "/Cis/Index?class=device&" + SI.Management.Core.ProData.CiColumns.OnboardingParam + "=" + Uri.EscapeDataString(code);

    /// The split's lines -- only the statuses the run figured (a run figured before the split has none: the total stands alone).
    private FigureLine[] OnboardingSplit() => OnboardingSplitOrder
        .Where(s => Get("coverage", "not_onboarded_status", s.Code) is not null)
        .Select(s => Line("coverage", "not_onboarded_status", s.Label, Better.Lower, dim1: s.Code, total: true, href: OnboardingHref(s.Code)))
        .ToArray();

    private FigureLine Line(string block, string figure, string label, Better better, string dim1 = "", bool assets = true, bool total = false, string? href = null)
    {
        var r = Get(block, figure, dim1);
        var v = Show(r, assets);
        if (total && r is { Available: true, Total: { } t } && t > 0) v += " of " + Fmt.Int(t) + " (" + Pct(assets ? r.Assets : (long?)Math.Round(r.Value ?? 0), t) + ")";
        return new FigureLine(block + "." + figure + (dim1.Length > 0 ? "." + dim1 : ""), label, v, Change(block, figure, better, dim1, assets: assets), r is { Available: true } ? href : null,
            r is { Available: false } ? r.Note : r is null ? "Not available yet: this figure is written by the next data sync." : null, assets ? r?.Assets : r?.Value);
    }

    private ReportBlock Patching(string title, string mode)
    {
        // owner 2026-10-19 ("include both angles with gaps vs. monthly lifecycle"): the missing patches are NEVER a raw total
        // on their own -- the headline is the three groups side by side (in the monthly cycle, catch-up, no single update)
        // with their share and devices; the total follows as "the three together"
        var lines = new List<FigureLine>(PatchTiles(mode).Where(l => l.Key != "total"));
        var all = Get("patching", "missing_patches", "(all)", "(all)");
        lines.AddRange(
        [
            new("patching.missing", Unclassified(mode) is null ? "All three together" : "All four together", Show(all) + " on " + Show(all, assets: true) + " of " + Fmt.Int(all?.Total) + " devices",
                Change("patching", "missing_patches", Better.Lower, "(all)", "(all)"), Detailed(("view", "cve"), ("f.Cve", "CVE-")),
                "one monthly cumulative update can close hundreds of CVEs per device: read the three groups, not the total", all?.Value),
            new("patching.vhdevices", "Devices with a Very High CVE", Show(Get("patching", "very_high_cve_devices", "(all)", "(all)"), assets: true)
                + " (" + Pct(Get("patching", "very_high_cve_devices", "(all)", "(all)")?.Assets, Get("patching", "very_high_cve_devices", "(all)", "(all)")?.Total) + ")",
                Change("patching", "very_high_cve_devices", Better.Lower, "(all)", "(all)", assets: true), Detailed(("view", "cve"), ("f.Cve", "CVE-"), ("f.Severity", "Very High"))),
            Line("patching", "known_exploited", "Known-exploited CVEs open", Better.Lower, assets: false, href: Detailed(("view", "exploited"), ("f.HasExploit", "1"))),
            Line("patching", "known_exploited_servers", "Servers with a known-exploited CVE", Better.Lower, total: true),
            Line("patching", "opened_30d", "Vulnerabilities opened in the last " + Days(Window(KeyFigureWindows.RecentDays)), Better.Lower, assets: false),
            Line("patching", "fixed_30d", "Vulnerabilities fixed in the last " + Days(Window(KeyFigureWindows.RecentDays)), Better.Higher, assets: false),
            new("patching.mttr", "Mean time to fix (days, last " + Days(Window(KeyFigureWindows.MeanTimeToFixDays)) + ")", Get("patching", "mean_days_to_fix") is { Available: true, Value: { } d } ? d.ToString("N1", ScoreFormat.Culture) : Show(Get("patching", "mean_days_to_fix")),
                Change("patching", "mean_days_to_fix", Better.Lower, kind: ChangeKind.Percent), Note: Get("patching", "mean_days_to_fix") is { Available: false } m ? m.Note : null),
        ]);
        var tables = new List<FigureTable> { Matrix(mode), GroupFixes(mode, "catchup", "Catch-up: the fixes, oldest and largest first", oldestFirst: true), FixLag(mode), Age(), Sla() };
        return new ReportBlock("patching", title, lines, tables.Where(t => t.Rows.Count > 0 || t.Note is not null).ToList());
    }

    /// The scope a reader must know (owner: "assumptions and filters should be transparent"): the run, the lifecycle default,
    /// exemptions, and what catch-up means -- from the real settings (<paramref name="seenDays"/>, <paramref name="catchUpDays"/>).
    public string ScopeLine(int? seenDays = null, int catchUpDays = DefaultCatchUpDays) => Current is null ? (Missing ?? "")
        : "Data from the published run of " + Fmt.Day(DateOnly.FromDateTime(Current.CollectionTime)) + " (Detailed findings); active assets (seen within "
          + (seenDays ?? CiLifecycleDefinitions.Defaults.SeenWithinDays).ToString(CultureInfo.InvariantCulture) + " days); exempted findings left out; catch-up = the fix is older than "
          + catchUpDays.ToString(CultureInfo.InvariantCulture) + " days; accepted lifecycle: " + Grace + " (per your settings)" + (Since is null ? "" : "; change since " + Since) + ".";
    /// Missing patches (or every finding) per OS family x device type: findings, devices, distinct CVEs, Very High, share.
    public FigureTable Matrix(string mode, string cycle = "all")
    {
        var fig = Fig("matrix", mode, cycle);
        var rows = Now.Where(r => r.Block == "patches" && r.Figure == fig && r.Dim1 != "(all)" && r.Dim2 != "(all)")
            .OrderBy(r => r.Dim1 == "Unknown" ? 1 : 0).ThenByDescending(r => r.Value).ToList();
        if (rows.Count == 0) return OldMatrix(mode);
        return new FigureTable("matrix", mode == "all" ? "All security findings on devices, by OS family and device type" : "Missing patches (CVEs) by OS family and device type",
            ["OS family", "Device type", "Findings", "Devices", mode == "all" ? "Recommendations" : "CVEs", "Very High", "Share"],
            rows.Select(r => (IReadOnlyList<string>)[r.Dim1, r.Dim2, Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Assets), Fmt.Int(r.Items), Fmt.Int(r.VeryHigh), Pct((long?)r.Value, r.Total)]).ToList(),
            rows.Select(r => (string?)CiFindings(AssetTypeOf(r.Dim2) is { } at ? new[] { ("f.AssetType", at), ("f.FindingKey", mode == "all" ? "" : "CVE-") } : new[] { ("f.FindingKey", mode == "all" ? "" : "CVE-") })).ToList(),
            "A number opens the findings of that device type; the OS family filter follows with the OS family field.",
            rows.Select(r => r.Value ?? 0).ToList());
    }

    /// Before the patch topic's rows exist (a collection prepared before it): the OS family x device type of missing patches.
    private FigureTable OldMatrix(string mode)
    {
        var rows = Now.Where(r => r.Block == "patching" && r.Figure == "missing_patches" && r.Dim1 != "(all)" && r.Dim2 != "(all)").OrderByDescending(r => r.Value).ToList();
        return new FigureTable("matrix", "Missing patches by OS family and device type", ["OS family", "Device type", "Missing patches", "Devices with one", "Devices"],
            rows.Select(r => (IReadOnlyList<string>)[r.Dim1, r.Dim2, Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Assets), Fmt.Int(r.Total)]).ToList(),
            Note: mode == "all" ? "All security findings per OS family come with the next data sync." : null);
    }

    private FigureTable Age()
    {
        var rows = Now.Where(r => r.Block == "patching" && r.Figure == "cve_age").ToList();
        if (rows.Count == 1 && !rows[0].Available) return new FigureTable("age", "Age of open CVE findings", [], [], Note: "Not available yet: " + rows[0].Note + ".");
        return new FigureTable("age", "Age of open CVE findings", ["Age", "Findings", "Devices", "Share"],
            rows.OrderBy(r => AgeBandDays(r.Dim1)).ThenBy(r => r.Dim1, StringComparer.Ordinal).Select(r => (IReadOnlyList<string>)[r.Dim1, Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Assets), Pct((long?)r.Value, r.Total)]).ToList());
    }

    /// #859: an age band's days ("older than 45 days" -> 45), so the bands the install chose sort by age, not as text.
    public static int AgeBandDays(string band) =>
        System.Text.RegularExpressions.Regex.Match(band ?? "", "\\d+") is { Success: true } m && int.TryParse(m.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var d) ? d : int.MaxValue;

    private FigureTable Sla()
    {
        var rows = Now.Where(r => r.Block == "patching" && r.Figure == "sla_breaches").ToList();
        if (rows.Count == 1 && !rows[0].Available) return new FigureTable("sla", "Past the due date, per severity", [], [], Note: "Not available yet: " + rows[0].Note + ".");
        return new FigureTable("sla", "Past the due date, per severity", ["Severity", "Past due", "Devices", "With a due date"],
            rows.OrderBy(r => r.Dim1 == "(all)" ? 9 : SeverityOrder.Rank(r.Dim1)).Select(r => (IReadOnlyList<string>)[r.Dim1, Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Assets), Fmt.Int(r.Total)]).ToList());
    }

    public static readonly string[] LagOrder = ["current", "1 month behind", "2+ months behind", "not known"];

    /// How far behind the recommended updates are (owner: normal patch lag vs real laggards).
    public FigureTable FixLag(string mode, string cycle = "all")
    {
        var rows = Now.Where(r => r.Block == "patches" && r.Figure == Fig("fixlag", mode, cycle))
            .OrderBy(r => Array.IndexOf(LagOrder, r.Dim1) is var i and >= 0 ? i : 9).ToList();
        return new FigureTable("fixlag", "How far behind the missing updates are", ["Update", "Findings", "Devices", "Servers", "Clients", "Updates"],
            rows.Select(r => (IReadOnlyList<string>)[r.Dim1, Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Assets), Fmt.Int(r.Servers), Fmt.Int(r.Clients), Fmt.Int(r.Items)]).ToList(),
            Note: rows.Count == 0 ? null : "\"current\" = this month's update; the month is read from the update's name (\"not known\" when it names none).");
    }

    /// The recommended fixes by reach (the topic's table): update, findings closed, devices, servers / clients, CVEs, lag.
    public FigureTable Fixes(string mode, int top = 15, string cycle = "all")
    {
        var rows = Now.Where(r => r.Block == "patches" && r.Figure == Fig("fix", mode, cycle)).OrderByDescending(r => r.Value).Take(top).ToList();
        return new FigureTable("fixes", "Fixes by reach", ["Update", "Fix", "Findings closed", "Share", "Devices", "Servers", "Clients", mode == "all" ? "Recommendations" : "CVEs", "Behind"],
            rows.Select(r => (IReadOnlyList<string>)[r.Dim1 == "(no single update)" ? "no single update" : "KB" + r.Dim1.TrimStart('K', 'B'), r.Dim2, Fmt.Int((long)(r.Value ?? 0)), Pct((long?)r.Value, r.Total),
                Fmt.Int(r.Assets), Fmt.Int(r.Servers), Fmt.Int(r.Clients), Fmt.Int(r.Items), r.Note ?? ""]).ToList(),
            rows.Select(r => (string?)null).ToList(), rows.Count == 0 ? "No missing update in this collection." : null, rows.Select(r => r.Value ?? 0).ToList());
    }

    public FigureTable Components(string mode, string cycle = "all")
    {
        var fig = Fig("component", mode, cycle);
        var all = Now.Where(r => r.Block == "patches" && r.Figure == fig).ToList();
        var comps = all.Where(r => r.Dim2 == "(all)").OrderByDescending(r => r.Value).ToList();
        string Of(string comp, string dc) => Fmt.Int((long)(all.FirstOrDefault(r => r.Dim1 == comp && r.Dim2 == dc)?.Value ?? 0));
        return new FigureTable("components", "By component", ["Component", "Findings", "Servers", "Clients", "Other", "Devices", "Very High", "Share"],
            comps.Select(r => (IReadOnlyList<string>)[r.Dim1, Fmt.Int((long)(r.Value ?? 0)), Of(r.Dim1, "Server"), Of(r.Dim1, "Client"), Of(r.Dim1, "Other"), Fmt.Int(r.Assets), Fmt.Int(r.VeryHigh), Pct((long?)r.Value, r.Total)]).ToList(),
            Bars: comps.Select(r => r.Value ?? 0).ToList());
    }

    public FigureTable Software(string mode, int top = 15, string cycle = "all")
    {
        var rows = Now.Where(r => r.Block == "patches" && r.Figure == Fig("software", mode, cycle)).OrderByDescending(r => r.Value).Take(top).ToList();
        return new FigureTable("software", "Top affected software", ["Software", "Findings", "Devices", "Servers", "Clients"],
            rows.Select(r => (IReadOnlyList<string>)[r.Dim1, Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Assets), Fmt.Int(r.Servers), Fmt.Int(r.Clients)]).ToList(),
            Bars: rows.Select(r => r.Value ?? 0).ToList());
    }

    /// One dimension of the matrix: by OS family or by device type (the pivot buttons).
    public FigureTable MatrixBy(string mode, string pivot, string cycle = "all")
    {
        var fig = Fig("matrix", mode, cycle);
        var os = pivot != "devices";
        var rows = Now.Where(r => r.Block == "patches" && r.Figure == fig && (os ? r.Dim1 != "(all)" && r.Dim2 == "(all)" : r.Dim1 == "(all)" && r.Dim2 != "(all)"))
            .OrderByDescending(r => r.Value).ToList();
        return new FigureTable("by-" + (os ? "os" : "device"), os ? "By OS family" : "By device type", [os ? "OS family" : "Device type", "Findings", "Devices", mode == "all" ? "Recommendations" : "CVEs", "Very High", "Share"],
            rows.Select(r => (IReadOnlyList<string>)[os ? r.Dim1 : r.Dim2, Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Assets), Fmt.Int(r.Items), Fmt.Int(r.VeryHigh), Pct((long?)r.Value, r.Total)]).ToList(),
            rows.Select(r => (string?)(os ? null : CiFindings(AssetTypeOf(r.Dim2) is { } at ? new[] { ("f.AssetType", at) } : Array.Empty<(string, string)>()))).ToList(), Bars: rows.Select(r => r.Value ?? 0).ToList());
    }

    private ReportBlock Cloud(string title)
    {
        var rows = Now.Where(r => r.Block == "cloud" && r.Figure == "high_recommendations").OrderByDescending(r => r.Value).ToList();
        return new ReportBlock("cloud", title, [],
            [new FigureTable("cloud", "Very High / High recommendations on cloud resources, per subscription", ["Subscription", "Recommendations open", "Resources"],
                rows.Select(r => (IReadOnlyList<string>)[r.Dim1, Fmt.Int((long)(r.Value ?? 0)), Fmt.Int(r.Assets)]).ToList(),
                Note: rows.Count == 0 ? "No Very High or High recommendation on a cloud resource in this collection." : null, Bars: rows.Select(r => r.Value ?? 0).ToList())]);
    }

    private static string? S(IReadOnlyDictionary<string, object?> r, string k) => r.TryGetValue(k, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;
    private static double N(IReadOnlyDictionary<string, object?> r, string k) => r.TryGetValue(k, out var v) && v is not null ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : 0;

    private ReportBlock ToDo(string title)
    {
        var fixes = new FigureTable("topfixes", "Top 5 fixes by reach", ["Fix", "Kind", "Assets", "Findings closed", "Risk removed"],
            TopFixes.Select(r => (IReadOnlyList<string>)[S(r, "Fix") ?? "", S(r, "Kind") ?? "", Fmt.Int((long)N(r, "Assets")), Fmt.Int((long)N(r, "Findings")), Fmt.Score(N(r, "RiskRemoved"))]).ToList(),
            TopFixes.Select(r => S(r, "RemediationKey") is { } k ? (string?)Detailed(("fix", k)) : null).ToList(), TopFixes.Count == 0 ? "The remediations of this collection are being prepared." : null);
        var assets = new FigureTable("topassets", "Top 5 assets to fix", ["#", "Asset", "Tier", "What to do", "Findings closed"],
            TopAssets.Select(r => (IReadOnlyList<string>)[S(r, "AssetRank") ?? "", S(r, "AssetName") ?? "", S(r, "Tier") is { } t && t != ProDataFilters.Unclassified ? "Tier " + t : "Unclassified", S(r, "Fix") ?? "", Fmt.Int((long)N(r, "Findings"))]).ToList(),
            TopAssets.Select(r => S(r, "AssetKey") is { } a ? (string?)("/Collection/Asset?key=" + Uri.EscapeDataString(a)) : null).ToList(), TopAssets.Count == 0 ? "The remediations of this collection are being prepared." : null);
        // catch-up first (owner 2026-10-19): the devices behind the monthly cycle are the work; the monthly rollout needs none
        var first = PatchSections("cve", "catchup").SelectMany(b => b.Lines).FirstOrDefault(l => l.Key == "catchup.action");
        return new ReportBlock("todo", title, first is null ? Array.Empty<FigureLine>() : new[] { first with { Key = "todo.catchup", Label = "First: catch-up" } }, [fixes, assets]);
    }

    private ReportBlock TrendBlock(string title)
    {
        // the newest first: a mail shows the first rows of a table, and those must be the latest collections
        var byCollection = Trend.GroupBy(p => p.CollectionId).OrderByDescending(g => g.First().CollectionTime).ToList();
        string V(IEnumerable<KeyFigurePoint> g, string f) => g.FirstOrDefault(p => p.Figure == f) is { Available: true, Value: { } v } ? Fmt.Int((long)Math.Round(v)) : "–";
        string P(IEnumerable<KeyFigurePoint> g, string f) => g.FirstOrDefault(p => p.Figure == f) is { Available: true, Value: { } v } ? Fmt.Pct(v, 1) : "–";
        return new ReportBlock("trend", title, [],
            [new FigureTable("trend", "The last 90 days", ["Collection", LifecycleName, ActualName, "Very High + High", "Known exploited CVEs", "Open findings"],
                byCollection.Select(g => (IReadOnlyList<string>)[Fmt.Day(DateOnly.FromDateTime(g.First().CollectionTime)), P(g, "protection_lifecycle"), P(g, "protection_technical"), V(g, "very_high_high"), V(g, "known_exploited"), V(g, "open_findings")]).ToList(),
                Note: byCollection.Count < 2 ? "The trend grows with every collection: the key figures are kept per collection from this release on." : null)]);
    }

    /// <summary>
    /// The two numbers of the scope line from the real settings: the lifecycle default -- active = seen within the seen window
    /// in force, read by THE lifecycle reader (<see cref="ICiLifecycleRulesReader"/>: SI_Pro_CmdbSql_SeenWithinDays, the CI
    /// list's and the CI build's own; #855 W5: the name read before, SI_CiLifecycle_NotSeenDays, is no setting at all, so the
    /// mail always said 30 days while the window was 8) -- and the patch cycle's catch-up threshold (SI_PatchCycle_CatchUpDays,
    /// its shipped default 30 when not set).
    /// </summary>
    public static async Task<(int SeenDays, int CatchUpDays)> ScopeDaysAsync(IServiceProvider services, CancellationToken ct)
    {
        var seen = CiLifecycleDefinitions.Defaults.SeenWithinDays;
        if (services.GetService(typeof(ICiLifecycleRulesReader)) is ICiLifecycleRulesReader rules)
        {
            try { seen = (await rules.ReadAsync(ct)).SeenWithinDays; }
            catch (Exception ex) when (ex is not OperationCanceledException) { _ = ex; }
        }
        int catchUp = DefaultCatchUpDays;
        if (services.GetService(typeof(SI.Management.Web.Settings.ISettingsStoreReader)) is not SI.Management.Web.Settings.ISettingsStoreReader reader) return (seen, catchUp);
        try
        {
            var (rows, _) = await reader.ReadSettingsAsync(ct);
            int? Days(string name) => rows.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))?.ValueJson is { } v
                && int.TryParse(v.Trim('"'), NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) && d > 0 ? d : null;
            catchUp = Days("SI_PatchCycle_CatchUpDays") ?? catchUp;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _ = ex; }
        return (seen, catchUp);
    }

    /// The shipped default of SI_PatchCycle_CatchUpDays (the setting's own default; used only when it is not set).
    public const int DefaultCatchUpDays = 30;
    // ---- the protection score (#636, owner 2026-10-19: "a new number which defines our ability to protect our assets. that
    // is a % from 0-100. a higher number is good" / "in the gui, i prefer to have both views") ------------------------------

    /// The two views, in toggle order: the code, the words. The accepted lifecycle is the default ("most mgmt accept the
    /// accepted lifecycle risks, but ciso focus on the other").
    public static readonly IReadOnlyList<(string Code, string Label)> ProtectionViews =
        [("lifecycle", "Within Accepted Lifecycle"), ("technical", "Actual Risks")];

    public static string ProtectionView(string? v) => v == "technical" ? "technical" : "lifecycle";

    /// The accepted lifecycle as the reader's settings set it ("30 days", or per asset type when they differ).
    public string Grace { get; init; } = "30 days";
    /// The tier weights as set ("Tier 0 = 8, Tier 1 = 4, Tier 2 = 2, Tier 3 = 1").
    public string TierWeights { get; init; } = "Tier 0 = 8, Tier 1 = 4, Tier 2 = 2, Tier 3 = 1";

    private static readonly string[] ProtectionTypes = ["Devices", "Identities", "Cloud resources", "Public IPs"];
    private static readonly string[] ProtectionTiers = ["Tier 0", "Tier 1", "Tier 2", "Tier 3", "Unclassified"];

    private string PctCell(string view, string dim1, string dim2) => Get("protection", view, dim1, dim2) is { Available: true, Value: { } v } ? Fmt.Pct(v, 1) : "–";

    /// The protection score block: both views as headline lines (always both), then -- for the chosen view first -- the
    /// split by asset type and by tier, asset type x tier for the chosen view, and where each finding's age came from.
    public ReportBlock Protection(string? view)
    {
        var v = ProtectionView(view);
        const string title = "Protection Score";
        if (!Ready) return new ReportBlock("protection", title, [], [], Missing ?? "Not available yet.");
        FigureLine Head(string code, string label)
        {
            var r = Get("headline", "protection_" + code);
            var shown = ShowScore(r) + (r is { Available: true, Total: { } t } && t > 0 ? " (" + Fmt.Int(r.Assets) + " of " + Fmt.Int(t) + " assets in good standing)" : "");
            return new FigureLine("protection." + code, label, shown, Change("headline", "protection_" + code, Better.Higher, kind: ChangeKind.Percent),
                TopicHref("protection") + (code == "technical" ? "&view=technical" : ""),
                r is null ? "Not available yet: this figure is written by the next data sync." : r is { Available: false } ? r.Note : null, r?.Value);
        }
        var noDate = Get("protection", "agebasis", "no date (counted)");
        // owner 2026-10-20 ("the toggle is also confusing as it just flips the 2 numbers around, but the numbers below doesnt
        // chg"): the two lines stay in place, whatever the view; the view chosen is named, and it is what the tables below show
        var lines = new List<FigureLine>
        {
            Head("lifecycle", LifecycleName),
            Head("technical", ActualName + " (every finding counts)"),
            new("protection.view", "The tables below show", ProtectionViews.First(p => p.Code == v).Label),
        };
        if (noDate is { Available: true })
            // #860 (owner 2026-10-21: "a risk detected can also be easy to say: we have a risk with no first seen date") -- its own count, never hidden
            lines.Add(new FigureLine("protection.nodate", NoDateLabel, Fmt.Int((long)Math.Round(noDate.Value ?? 0)) + " of " + Fmt.Int(noDate.Total) + " Very High / High findings",
                Note: "no fix release date, no first-seen from the source and no first detection by SecurityInsight: such a finding is a risk, in both views", Raw: noDate.Value));
        var other = v == "technical" ? "lifecycle" : "technical";
        string Words(string code) => ProtectionViews.First(p => p.Code == code).Label;
        var byType = new FigureTable("protection-types", "By asset type", ["Asset type", Words(v), Words(other), "In good standing", "Assets in scope"],
            ProtectionTypes.Where(t => Get("protection", v, t, "(all)") is not null)
                .Select(t => (IReadOnlyList<string>)[t, PctCell(v, t, "(all)"), PctCell(other, t, "(all)"), Fmt.Int(Get("protection", v, t, "(all)")?.Assets), Fmt.Int(Get("protection", v, t, "(all)")?.Total)]).ToList(),
            Bars: ProtectionTypes.Where(t => Get("protection", v, t, "(all)") is not null).Select(t => Get("protection", v, t, "(all)")?.Value ?? 0).ToList());
        var byTier = new FigureTable("protection-tiers", "By tier", ["Tier", Words(v), Words(other), "In good standing", "Assets in scope"],
            ProtectionTiers.Where(t => Get("protection", v, "(all)", t) is not null)
                .Select(t => (IReadOnlyList<string>)[t, PctCell(v, "(all)", t), PctCell(other, "(all)", t), Fmt.Int(Get("protection", v, "(all)", t)?.Assets), Fmt.Int(Get("protection", v, "(all)", t)?.Total)]).ToList());
        var tiers = ProtectionTiers.Where(t => Get("protection", v, "(all)", t) is not null).ToList();
        var matrix = new FigureTable("protection-matrix", Words(v) + ": asset type x tier", ["Asset type", .. tiers],
            ProtectionTypes.Where(t => Get("protection", v, t, "(all)") is not null)
                .Select(t => (IReadOnlyList<string>)[t, .. tiers.Select(x => PctCell(v, t, x))]).ToList());
        var basis = new FigureTable("protection-age", "Where a finding's age came from", ["Age from", "Findings", "Assets"],
            new[] { "fix release", "source first seen", "SI first detected", "no date (counted)" }.Select(b => Get("protection", "agebasis", b) is { } r
                ? (IReadOnlyList<string>)[BasisWords(b, r.Note), Fmt.Int((long)Math.Round(r.Value ?? 0)), Fmt.Int(r.Assets)] : null).Where(r => r is not null).Select(r => r!).ToList(),
            Note: "The age of a finding is the first that is known: the fix's release date, the source's own first-seen, the day SecurityInsight first saw it. A finding with none is a risk.");
        var how = new FigureLine("protection.how", "How it is counted",
            "the share of active assets (devices, identities, cloud resources, public IPs; groups left out) with no open, non-exempted Very High / High finding, weighted by tier ("
            + TierWeights + "). Within Accepted Lifecycle: a PATCH finding (a vulnerability with a vendor fix) younger than its asset type's grace does not count (accepted lifecycle: " + Grace
            + ", per your settings); every other finding -- configuration, identity, Azure, attack paths -- counts from the day it is found unless your settings give it a grace. Actual Risks: every finding counts -- a patch released yesterday lowers it. Bands: "
            + string.Join(", ", ProtectionBands.All.Select(b => b.Name + " " + b.Min.ToString("0", CultureInfo.InvariantCulture) + "+")) + ".");
        lines.Add(how);
        return new ReportBlock("protection", title, lines, new[] { byType, byTier, matrix, basis }.Where(t => t.Rows.Count > 0).ToList());
    }

    /// #860 (owner 2026-10-21): a finding with no date at all is "a risk with no first-seen date" -- its own count.
    public const string NoDateLabel = "A risk with no first-seen date";

    /// <summary>
    /// #860: an age basis in words. SI's own first detection is "first seen by SecurityInsight on &lt;date&gt;" (the first and the
    /// last such date the figure stored, "yyyy-MM-dd|yyyy-MM-dd"); no date is "no first-seen date (a risk)".
    /// </summary>
    public static string BasisWords(string basis, string? note)
    {
        if (basis == "no date (counted)") return "no first-seen date (a risk)";
        if (basis != "SI first detected") return basis;
        var p = (note ?? "").Split('|');
        static string? Day(string s) => DateOnly.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? Fmt.Day(d) : null;
        var a = p.Length > 0 ? Day(p[0]) : null;
        var b = p.Length > 1 ? Day(p[1]) : null;
        return a is null ? "first seen by SecurityInsight" : b is null || b == a ? "first seen by SecurityInsight on " + a : "first seen by SecurityInsight on " + a + " to " + b;
    }

    /// The accepted lifecycle in force (the time to fix per asset type, the severities that count) -- the line under the
    /// "within Accepted Lifecycle" score on every page and mail that shows it (owner 2026-10-20).
    public AcceptedLifecycle Lifecycle { get; init; } = AcceptedLifecycle.Unknown;

    /// The protection score settings as words (the grace per asset type, the tier weights) and the accepted lifecycle, from
    /// the reader's settings -- one read of the settings.
    public static async Task<(string Grace, string Weights, AcceptedLifecycle Lifecycle)> ProtectionWordsAsync(IServiceProvider services, CancellationToken ct)
    {
        var weights = "Tier 0 = 8, Tier 1 = 4, Tier 2 = 2, Tier 3 = 1";
        var life = AcceptedLifecycle.Unknown;
        if (services.GetService(typeof(SI.Management.Web.Settings.ISettingsStoreReader)) is SI.Management.Web.Settings.ISettingsStoreReader reader)
        {
            try
            {
                var (rows, _) = await reader.ReadSettingsAsync(ct);
                life = AcceptedLifecycle.From(rows);
                string? Val(string name) => rows.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))?.ValueJson?.Trim('"');
                if (Val("SI_ProtectionScore_TierWeights") is { Length: > 0 } w)
                {
                    var parts = w.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 4 && parts.All(p => double.TryParse(p, NumberStyles.Float, CultureInfo.InvariantCulture, out var x) && x >= 0))
                        weights = string.Join(", ", parts.Select((p, i) => "Tier " + i.ToString(CultureInfo.InvariantCulture) + " = " + p));
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _ = ex; }
        }
        return (life.Words, weights, life);
    }
    // ---- loading ---------------------------------------------------------------------------------------------------------

    public const string NotBuilt = "The key figures of this collection are being prepared: the data sync writes them after the collection's context. They appear after the next data sync.";

    /// The key figures exist since this release; an earlier run synced before it has none until the data sync back-fills it.
    public const string IntroducedOn = "2026-10-19";

    /// #818: an EARLIER run without key figures -- not computed for it (never a blank).
    public static string NotComputed(ViewCollection run) =>
        "The key figures were not computed for the run of " + run.CollectionTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) +
        " UTC: they exist since the release of " + IntroducedOn + ", and the data sync back-fills only the newest earlier runs (the 4 newest) after an update. Pick a newer run, or open this one again after the next data sync.";

    /// Reads the figures of the collection (the published one when null) and of the one it is compared with -- the run before
    /// it, or <paramref name="compareId"/> when chosen (#818) -- the trend and the top fixes / assets. Never throws: a failure is
    /// <see cref="Error"/>.
    public static async Task<ExecutiveFigures> LoadAsync(IServiceProvider services, string? collectionId, CancellationToken ct, string? compareId = null)
    {
        if (services.GetService(typeof(ICollectionViews)) is not ICollectionViews views || services.GetService(typeof(IRecommendationViews)) is not IRecommendationViews rec)
            return new ExecutiveFigures { Missing = "The key figures are not available in this installation." };
        try
        {
            var (grace, weights, life) = await ProtectionWordsAsync(services, ct);
            var cols = (await views.CollectionsAsync(ct)).Data;
            if (cols.Count == 0) return new ExecutiveFigures { Missing = "No complete collection has been loaded into the Pro database yet.", Grace = grace, TierWeights = weights, Lifecycle = life };
            var cur = collectionId is null ? cols[0] : cols.FirstOrDefault(c => c.CollectionId == collectionId) ?? cols[0];
            // the run compared with: the chosen one (another listed run), else the run before the shown one
            var chosen = compareId is null ? null : cols.FirstOrDefault(c => c.CollectionId == compareId && c.CollectionId != cur.CollectionId);
            var prev = chosen ?? cols.Where(c => c.CollectionTime < cur.CollectionTime).OrderByDescending(c => c.CollectionTime).FirstOrDefault();
            var now = await rec.KeyFiguresAsync(cur.CollectionId, ct);
            IReadOnlyList<KeyFigureRow> before = prev is null ? [] : (await rec.KeyFiguresAsync(prev.CollectionId, ct)).Data;
            var trend = await rec.TrendAsync(90, ct);
            IReadOnlyList<IReadOnlyDictionary<string, object?>> fixes = [], assets = [];
            try
            {
                var p = new Dictionary<string, object?> { ["CollectionId"] = cur.CollectionId, ["Top"] = 5 };
                fixes = (await views.GridAsync(new GridQuery(RecommendationSql.TopFixes, p, cur.Version + "|remtop5", new GridRequest { Size = 25 }), ct)).Data.Rows;
                assets = (await views.GridAsync(new GridQuery(RecommendationSql.TopAssets, p, cur.Version + "|remassets5", new GridRequest { Size = 25, Sort = "AssetRank", Desc = false }), ct)).Data.Rows
                    .Where(r => Convert.ToString(r.TryGetValue("FixRank", out var fr) ? fr : null, CultureInfo.InvariantCulture) == "1").ToList();
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _ = ex; }
            var f = new ExecutiveFigures
            {
                Grace = grace, TierWeights = weights, Lifecycle = life,
                Current = cur, Previous = prev, Now = now.Data, Before = before, Trend = trend.Data, TopFixes = fixes, TopAssets = assets,
                Collections = cols, Compared = chosen is not null,
                // the shown (published) run is being prepared; an earlier run synced before the figures existed has none
                Missing = now.Data.Count == 0 ? (cur.CollectionId == cols[0].CollectionId ? NotBuilt : NotComputed(cur)) : null,
                CompareNote = prev is not null && before.Count == 0 && now.Data.Count > 0
                    ? "No change is shown: the run of " + prev.CollectionTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC it is compared with has no key figures (" +
                      (cols.Count > 0 && prev.CollectionId == cols[0].CollectionId ? "they are being prepared" : "not computed for that run") + ")."
                    : null,
            };
            f.Queries.Add(QueryInfo.From(now, "The key figures of this collection"));
            f.Queries.Add(QueryInfo.From(trend, "The headline figures over 90 days"));
            return f;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ExecutiveFigures { Missing = NotBuilt, Error = "The key figures could not be read from the Pro database: " + ex.Message };
        }
    }
}
