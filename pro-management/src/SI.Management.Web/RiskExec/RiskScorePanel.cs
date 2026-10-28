using SI.Management.Core.ProData;
using SI.Management.Web.Pages;

namespace SI.Management.Web.RiskExec;

/// <summary>
/// The Risk Analysis panel (the domain x severity table of the kept view; #636 retired its old 0-100 score card)
/// as the wall board / home page shows it (#415, operator 2026-10-06: "the wallboard is the default (home) page ... can we
/// include this on the wall board also" and "make it mgmt friendly"). It READS the kept Risk Analysis view
/// (<see cref="ExecKpi"/>, picked by <see cref="ExecViewLoader"/>) -- the same figures the Risk Analysis page and the mail
/// show; it never computes a score of its own (one risk-score source, #388). Rendered by Pages/Shared/_RiskScorePanel.cshtml.
/// OWNER 2026-10-20 ("the toggle is also confusing as it just flips the 2 numbers around, but the numbers below doesnt chg"):
/// the Protection Score view drives the table too -- its counts are the stored per-collection figures of THAT view
/// (block protection, figure findings_lifecycle | findings_technical, Dim1 domain, Dim2 severity; written by the data sync,
/// never counted per page load). A run synced before they existed: Actual Risks falls back to the kept Risk Analysis table
/// (every finding of the run), within Accepted Lifecycle keeps the table with "–" cells and says when its counts come (owner
/// 2026-10-20: "the table also dissapears when i use the toggle").
/// </summary>
public sealed record RiskScorePanel(ExecKpi? Kpi, string Grain, DateTimeOffset? GeneratedAt)
{
    /// The table's columns after Domain, in the order management reads them: the severities, then Total.
    public static readonly IReadOnlyList<string> Columns = [.. ExecKpi.Severities, "Total"];

    /// The Protection Score view the table shows: lifecycle | technical.
    public string View { get; init; } = "lifecycle";
    /// The stored key figures of the run shown (null = none read).
    public ExecutiveFigures? Figures { get; init; }

    /// The figure name of the view's stored counts.
    public string StoredFigure => "findings_" + View;

    /// The stored counts of the view are there for the run shown.
    public bool Stored => Figures is { Ready: true } f && f.Get("protection", StoredFigure, "(all)", "(all)") is { Available: true };

    /// The table is the kept Risk Analysis one (every finding of the run): the Actual Risks view of a run without stored counts.
    public bool FromKpi => !Stored && View == "technical" && Kpi is not null;

    /// owner 2026-10-20 ("the table also dissapears when i use the toggle"): the within Accepted Lifecycle view of a run whose
    /// per-view counts the data sync has not written yet -- the table STAYS (its cells "–", never a made-up or another view's
    /// number) and its caption says when the counts come. Never counted per page load (the pages stay fast).
    public bool Pending => !Stored && View == "lifecycle" && Kpi is not null;

    /// What the panel shows: stored | risk-analysis | pending | none.
    public string Source => Stored ? "stored" : FromKpi ? "risk-analysis" : Pending ? "pending" : "none";

    /// A cell as shown: the count, or "–" while the view's counts are pending.
    public string Cell(string domain, string column) => Pending ? "–" : Fmt.Int(Count(domain, column));
    public string TotalCell(string column) => Pending ? "–" : Fmt.Int(TotalCount(column));

    /// The view's name, for the caption.
    public string ViewName => View == "technical" ? ExecutiveFigures.ActualName : ExecutiveFigures.LifecycleName;

    /// One cell: the stored count of the view (domain key x severity key, "Total" = every severity), or the kept table's.
    public long Count(string domain, string column)
    {
        if (Stored)
        {
            var r = Figures!.Get("protection", StoredFigure, domain, column == "Total" ? "(all)" : column);
            return r?.Value is { } v ? (long)Math.Round(v) : 0;
        }
        return Kpi?.Count(domain, column) ?? 0;
    }

    /// The Total row's cell.
    public long TotalCount(string column)
    {
        if (Stored)
        {
            var r = Figures!.Get("protection", StoredFigure, "(all)", column == "Total" ? "(all)" : column);
            return r?.Value is { } v ? (long)Math.Round(v) : 0;
        }
        return Kpi?.TotalCount(column) ?? 0;
    }

    /// What the table counts, for its caption.
    public string Counts => Stored
        ? (View == "technical" ? "every open finding of the run (exempted left out)" : "the open findings past their accepted time to fix, on active assets -- the ones this score counts as risks")
        : Grain == RiskExecGrain.Detailed ? "findings" : "distinct assets";

    /// The caption of a pending table: what it will count and when.
    public const string PendingNote = "counts the open findings past their accepted time to fix. They are counted by the data sync for this run and appear after the next data sync; until then the cells show –. Switch to Actual Risks for every open finding of the run.";

    // #636 (owner 2026-10-19: "replace it with the Protection score everywhere ... retire the old KPI"): the score card, its
    // rating scale, marker and plain line are retired; the wall board shows the protection score tile above this panel.

    public static RiskScorePanel Of(ExecViewLoader.Loaded? loaded)
    {
        var f = loaded?.View.Figures;
        return new RiskScorePanel(f?.Kpi, f?.FiguresFromGrain ?? loaded?.View.Grain ?? RiskExecGrain.Detailed, f?.FiguresGeneratedAt);
    }
}
