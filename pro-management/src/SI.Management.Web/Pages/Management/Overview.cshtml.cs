using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Overview > Executive overview > Topics (#636, owner 2026-10-19: "one could be report and other could be click to see the
/// stats with buttons of most interesting topics so they can click around"): the Overview landing page to EXPLORE --
/// the headline tiles, a board of topic buttons, and the open topic's figures (small tables, a bar per row) with pivot
/// buttons, every number linking to the pre-filtered view behind it. Reads the SAME stored figures as the Executive report
/// (<see cref="ExecutiveFigures"/>), never the findings.
/// </summary>
public sealed class OverviewModel : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Topic { get; set; }
    [BindProperty(SupportsGet = true)] public string? Mode { get; set; }
    [BindProperty(SupportsGet = true)] public string? Cycle { get; set; }
    [BindProperty(SupportsGet = true)] public string? Pivot { get; set; }
    [BindProperty(SupportsGet = true)] public string? C { get; set; }
    /// #818: the run the figures are compared with (null = the run before the shown one).
    [BindProperty(SupportsGet = true)] public string? Vs { get; set; }
    /// The protection score view: lifecycle (default, "within accepted lifecycle") | technical.
    [BindProperty(SupportsGet = true)] public string? View { get; set; }
    public string ViewKey => ExecutiveFigures.ProtectionView(View);

    public ExecutiveFigures Figures { get; private set; } = new() { Missing = ExecutiveFigures.NotBuilt };
    public string TopicKey => ExecutiveFigures.Topics.Any(t => t.Key == Topic) ? Topic! : "patches";
    public string TopicLabel => ExecutiveFigures.Topics.First(t => t.Key == TopicKey).Label;
    public string ModeKey => ExecutiveFigures.ModeCode(Mode);
    public string CycleKey => ExecutiveFigures.CycleCode(Cycle);
    public string PivotKey => Pivot is "os" or "devices" or "components" or "software" ? Pivot : "matrix";

    /// The pivots of the patch topic, in button order.
    public static readonly IReadOnlyList<(string Key, string Label)> Pivots =
        [("matrix", "OS family x device type"), ("os", "By OS family"), ("devices", "By device type"), ("components", "By component"), ("software", "By software")];

    public string Href(string? topic = null, string? mode = null, string? cycle = null, string? pivot = null, string? view = null)
    {
        var parts = new List<string> { "topic=" + Uri.EscapeDataString(topic ?? TopicKey) };
        if ((view ?? ViewKey) == "technical") parts.Add("view=technical");
        if ((mode ?? ModeKey) == "all") parts.Add("mode=all");
        if ((cycle ?? CycleKey) is var cy && cy != "all") parts.Add("cycle=" + cy);
        if ((pivot ?? PivotKey) is var pv && pv != "matrix") parts.Add("pivot=" + pv);
        if (Vs is not null) parts.Insert(0, "vs=" + Uri.EscapeDataString(Vs));
        if (C is not null) parts.Insert(0, "c=" + Uri.EscapeDataString(C));
        return "/Management/Overview?" + string.Join("&", parts);
    }

    /// The run picker (#818): keeps the open topic and its choices when another run is picked.
    public RunPickerModel Picker()
    {
        var keep = new List<(string, string)> { ("topic", TopicKey) };
        if (ViewKey == "technical") keep.Add(("view", "technical"));
        if (ModeKey == "all") keep.Add(("mode", "all"));
        if (CycleKey != "all") keep.Add(("cycle", CycleKey));
        if (PivotKey != "matrix") keep.Add(("pivot", PivotKey));
        return new RunPickerModel(Figures, "/Management/Overview", keep);
    }

    /// The open topic's blocks and tables.
    public IReadOnlyList<ReportBlock> TopicBlocks()
    {
        var f = Figures;
        if (!f.Ready) return [new ReportBlock(TopicKey, TopicLabel, [], [], f.Missing ?? ExecutiveFigures.NotBuilt)];
        var patching = f.Block("patching", ModeKey);
        return TopicKey switch
        {
            // laid out as the owner's mail: the total and the three groups on top (a tile filters to its group), a section per
            // group with its suggested action, then the pivots and the months-behind split
            "patches" => [new ReportBlock("patches", TopicLabel, f.PatchTiles(ModeKey), []), .. f.PatchSections(ModeKey, CycleKey),
                new ReportBlock("patches-more", "More views", [], [PivotTable(), f.FixLag(ModeKey, CycleKey)])],
            "os" => [new ReportBlock("os", TopicLabel, [], [f.MatrixBy(ModeKey, "os", CycleKey), f.Matrix(ModeKey, CycleKey)])],
            "devices" => [new ReportBlock("devices", TopicLabel, [], [f.MatrixBy(ModeKey, "devices", CycleKey), f.Components(ModeKey, CycleKey)])],
            "exploited" => [new ReportBlock("exploited", TopicLabel, patching.Lines.Where(l => l.Key.Contains("known_exploited", StringComparison.Ordinal)).ToList(), [])],
            "internet" => [Only(f.Block("exposure"), "internet")],
            "tier0" => [Only(f.Block("exposure"), "tier0"), Only(f.Block("identity"), "tier0")],
            "eos" => [Only(f.Block("exposure"), "end_of_support")],
            "coverage" => [f.Block("coverage")],
            "identity" => [f.Block("identity")],
            "cloud" => [f.Block("cloud")],
            "fixes" => [f.Block("todo"), new ReportBlock("fixes", "Updates by reach", [], [f.Fixes(ModeKey, 15, CycleKey)])],
            "trend" => [f.Block("trend")],
            "protection" => [f.Protection(ViewKey)],
            _ => [patching],
        };
    }

    private static ReportBlock Only(ReportBlock b, string part) => b with { Lines = b.Lines.Where(l => l.Key.Contains(part, StringComparison.Ordinal)).ToList() };

    private FigureTable PivotTable() => PivotKey switch
    {
        "os" => Figures.MatrixBy(ModeKey, "os", CycleKey),
        "devices" => Figures.MatrixBy(ModeKey, "devices", CycleKey),
        "components" => Figures.Components(ModeKey, CycleKey),
        "software" => Figures.Software(ModeKey, 15, CycleKey),
        _ => Figures.Matrix(ModeKey, CycleKey),
    };

    /// The topics with pivots of their own (the patch topic, and OS / devices which are its pivots).
    public bool HasPivots => TopicKey == "patches";
    public bool HasCycles => TopicKey is "patches" or "os" or "devices" or "fixes";

    public async Task OnGetAsync(CancellationToken ct) => Figures = await ExecutiveFigures.LoadAsync(HttpContext.RequestServices, C, ct, Vs);
}
