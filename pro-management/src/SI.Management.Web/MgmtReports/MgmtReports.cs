using System.Globalization;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using SI.Management.Core.Mail;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.MgmtReports;

/// <summary>
/// THE MANAGEMENT SUMMARY REPORT (#291): a report definition (Configuration > Reports > Management summary)
/// with selectable sections -- (a) the Risk Score KPI + band + the summary, (b) risk by domain, (c) the timeline of
/// vulnerabilities opened vs closed per week over the last month and the last 3 months -- for the Summary or the Detailed
/// report's data (and the agreement mode, as the executive view, #288). It is sent as an HTML mail in the Risk Analysis
/// mail's look on a weekly or monthly schedule, through the outbox (cfg.ReportMail, sent by the mail job on the one SMTP
/// path), and can be previewed and sent now. Every save, removal and send is audited.
/// </summary>
public sealed record MgmtReport(long Id, string Name, string Grain, bool Kpi, bool Domains, bool Timeline, IReadOnlyList<string> Recipients,
    string Cadence, int Day, string TimeUtc, bool Enabled, string? LastPeriodKey, DateTime? LastSentAt, DateTime CreatedAt)
{
    public const string Weekly = "weekly";
    public const string Monthly = "monthly";
    public static readonly IReadOnlyList<string> Cadences = [Weekly, Monthly];

    /// A new definition with the defaults: every section, Detailed (#636: the Summary step is optional and off by default), monthly on the 1st at 07:00 UTC.
    public static MgmtReport New(DateTime now) => new(0, "Management summary", RiskExecGrain.Detailed, true, true, true, [], Monthly, 1, "07:00", true, null, null, now);

    /// #636: the key figures blocks the report carries (the Executive report's blocks; null = every block, the default --
    /// also for a report saved before the blocks existed; empty = none).
    public IReadOnlyList<string>? KeyBlocks { get; init; }

    public bool Includes(string block) => KeyBlocks is null || KeyBlocks.Contains(block, StringComparer.Ordinal);
}

/// <summary>PURE: when a report is due, without ever sending one period twice, and catching up a missed period ONCE.</summary>
public static class MgmtSchedule
{
    private static readonly Regex Hm = new(@"^(?<h>[01]\d|2[0-3]):(?<m>[0-5]\d)$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    private static readonly Regex Mail = new(@"^[^@\s;,<>""]+@[^@\s;,<>""]+\.[^@\s;,<>""]+$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    /// What is wrong with a definition (empty = fine).
    public static IReadOnlyList<string> Problems(MgmtReport r)
    {
        var p = new List<string>();
        if (string.IsNullOrWhiteSpace(r.Name) || r.Name.Length > 100) p.Add("A name of 1 to 100 characters is needed.");
        if (RiskExecGrain.Parse(r.Grain) is null) p.Add("The data is Summary or Detailed.");
        if (!r.Kpi && !r.Domains && !r.Timeline) p.Add("Choose at least one section.");
        if (r.Recipients.Count == 0) p.Add("Add at least one recipient.");
        foreach (var m in r.Recipients) if (!Mail.IsMatch(m)) p.Add($"'{m}' is not a mail address.");
        if (r.Recipients.Count > 50) p.Add("At most 50 recipients.");
        if (!MgmtReport.Cadences.Contains(r.Cadence)) p.Add("The schedule is weekly or monthly.");
        if (r.Cadence == MgmtReport.Weekly && r.Day is < 1 or > 7) p.Add("A weekly report needs a weekday (Monday to Sunday).");
        if (r.Cadence == MgmtReport.Monthly && r.Day is < 1 or > 28) p.Add("A monthly report needs a day of the month from 1 to 28.");
        if (!Hm.IsMatch(r.TimeUtc ?? "")) p.Add("The time is HH:mm (UTC), e.g. 07:00.");
        return p;
    }

    private static TimeSpan Time(string hm) => Hm.Match(hm) is { Success: true } m
        ? new TimeSpan(int.Parse(m.Groups["h"].Value, CultureInfo.InvariantCulture), int.Parse(m.Groups["m"].Value, CultureInfo.InvariantCulture), 0) : TimeSpan.FromHours(7);

    /// The newest scheduled slot at or before now (UTC). Weekly Day: 1 = Monday .. 7 = Sunday.
    public static DateTime LastSlot(MgmtReport r, DateTime nowUtc)
    {
        var t = Time(r.TimeUtc);
        if (r.Cadence == MgmtReport.Weekly)
        {
            var back = ((int)nowUtc.DayOfWeek + 6) % 7 - (r.Day - 1);     // days since this week's slot day
            var slot = nowUtc.Date.AddDays(-back).Add(t);
            if (back < 0) slot = slot.AddDays(-7);
            if (slot > nowUtc) slot = slot.AddDays(-7);
            return slot;
        }
        var m = new DateTime(nowUtc.Year, nowUtc.Month, r.Day, 0, 0, 0, DateTimeKind.Utc).Add(t);
        return m <= nowUtc ? m : m.AddMonths(-1);
    }

    /// The next slot after now.
    public static DateTime NextSlot(MgmtReport r, DateTime nowUtc) =>
        r.Cadence == MgmtReport.Weekly ? LastSlot(r, nowUtc).AddDays(7) : LastSlot(r, nowUtc).AddMonths(1);

    /// The period a slot sends for: ISO week ("2026-W41") or month ("2026-10").
    public static string PeriodKey(MgmtReport r, DateTime slot) => r.Cadence == MgmtReport.Weekly
        ? $"{ISOWeek.GetYear(slot)}-W{ISOWeek.GetWeekOfYear(slot):00}"
        : slot.ToString("yyyy-MM", CultureInfo.InvariantCulture);

    /// Due now: the newest slot's period has not been sent, and the slot is after the definition was created. A run of
    /// missed slots (the app was down) is ONE send, for the newest period -- never one per missed period.
    public static string? DuePeriod(MgmtReport r, DateTime nowUtc)
    {
        if (!r.Enabled || r.Recipients.Count == 0) return null;
        var slot = LastSlot(r, nowUtc);
        if (slot < r.CreatedAt) return null;
        var key = PeriodKey(r, slot);
        return string.Equals(r.LastPeriodKey, key, StringComparison.Ordinal) ? null : key;
    }

    /// In words: "Monthly on day 1 at 07:00 UTC", "Weekly on Monday at 07:00 UTC".
    public static string Describe(MgmtReport r) => r.Cadence == MgmtReport.Weekly
        ? $"Weekly on {CultureInfo.InvariantCulture.DateTimeFormat.GetDayName((DayOfWeek)(r.Day % 7))} at {r.TimeUtc} UTC"
        : $"Monthly on day {r.Day} at {r.TimeUtc} UTC";
}

/// One week of the timeline: opened, closed, open at the end of the week.
public sealed record TimelineWeek(DateOnly Monday, long Opened, long Closed, long? OpenAtEnd);

/// <summary>
/// NEW CONTEXT in the summary mail: what the continuous discovery found since the last summary mail -- how many properties
/// are new, per source (counted from the prepared rows, sidata.SourceProperty by first seen) -- and the link to
/// Configuration > New context available (null when the web app's public address is not set). ONE line of the mail, and
/// only when something is new: a mail with nothing new says nothing about it, and there is no mail of its own.
/// </summary>
public sealed record NewContextLine(IReadOnlyList<SI.Management.Web.NewContext.NewContextSource> Sources, string? Link)
{
    /// The page the line links to.
    public const string Page = "/SchemaOverlay/NewContext";

    public int Total => Sources.Sum(s => s.Properties);

    /// The window of the page that fits the report's schedule: this week for a weekly report, the last 30 days for a monthly one.
    public static string PagePath(MgmtReport r) => Page + "?show=" + (r.Cadence == MgmtReport.Weekly ? "week" : "month");

    /// From when "new" counts: the last summary mail of this report; a report never sent looks one period back.
    public static DateTime Since(MgmtReport r, DateTime nowUtc) =>
        r.LastSentAt is { } last && last <= nowUtc ? last : (r.Cadence == MgmtReport.Weekly ? nowUtc.AddDays(-7) : nowUtc.AddMonths(-1));

    /// "A", "A and B", "A, B and C" -- the sources by their names, in the order given.
    public static string SourceList(IReadOnlyList<string> names) => names.Count switch
    {
        0 => "",
        1 => names[0],
        _ => string.Join(", ", names.Take(names.Count - 1)) + " and " + names[^1],
    };

    /// "12 new properties are available from Microsoft Entra ID (Microsoft Graph) and Microsoft Intune"; "" when nothing is new.
    public string Text(Func<long, string> n)
    {
        var total = Total;
        if (total <= 0) return "";
        var names = Sources.Where(s => s.Properties > 0).Select(s => SI.Management.Web.NewContext.NewContextText.Source(s.Source)).Where(x => x.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var what = total == 1 ? "1 new property is available" : n(total) + " new properties are available";
        return names.Count == 0 ? what : what + " from " + SourceList(names);
    }
}

/// <summary>PURE: the report's HTML, in the Risk Analysis mail's look (inline styles: it is a mail).</summary>
public static class MgmtSummaryComposer
{
    private const string Font = "font-family:Segoe UI,Arial,sans-serif;";
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    /// Weeks (Monday starts) covering the last <paramref name="days"/> days up to today, summed from the daily rows.
    public static IReadOnlyList<TimelineWeek> Weeks(IReadOnlyList<LifecycleDay> daily, DateOnly today, int days)
    {
        var from = today.AddDays(-(days - 1));
        static DateOnly Monday(DateOnly d) => d.AddDays(-(((int)d.DayOfWeek + 6) % 7));
        var weeks = new List<TimelineWeek>();
        for (var w = Monday(from); w <= today; w = w.AddDays(7))
        {
            var inWeek = daily.Where(d => d.Day >= w && d.Day < w.AddDays(7) && d.Day >= from && d.Day <= today).OrderBy(d => d.Day).ToList();
            weeks.Add(new TimelineWeek(w, inWeek.Sum(d => d.Opened), inWeek.Sum(d => d.Closed), inWeek.LastOrDefault(d => d.OpenAtEndOfDay is not null)?.OpenAtEndOfDay));
        }
        return weeks;
    }

    /// A plain summary when the AI summary is off: the protection score (both views), the weakest asset type, the counts.
    /// #636 (owner 2026-10-19): the protection score replaced the old 0-100 KPI here too.
    public static string PlainSummary(ExecKpi k)
    {
        var inv = CultureInfo.InvariantCulture;
        var p = k.Protection;
        var head = p is null ? "The Protection Score comes with the next Detailed run. "
            : string.Format(inv, "{0}: {1:0.0} % ({2}); {3}: {4:0.0} % ({5}) -- higher is better. ", SI.Management.Web.RiskExec.ExecutiveFigures.LifecycleName, p.Lifecycle,
                ProtectionBands.Of(p.Lifecycle).Name, SI.Management.Web.RiskExec.ExecutiveFigures.ActualName, p.Technical, ProtectionBands.Of(p.Technical).Name)
              + (p.ByType.Where(x => x.Lifecycle is not null).OrderBy(x => x.Lifecycle).FirstOrDefault() is { } w ? string.Format(inv, "The weakest asset type is {0} at {1:0.0} %. ", w.Type, w.Lifecycle) : "");
        return head +
               $"There are {k.TotalCount("Critical").ToString("N0", CultureInfo.InvariantCulture)} critical and {k.TotalCount("High").ToString("N0", CultureInfo.InvariantCulture)} high findings in total.";
    }

    public sealed record Composed(string Subject, string Html);

    /// <paramref name="newContext"/>: what the discovery found since the last summary mail -- one line in a small block of
    /// its own ("Also new this week"), left out entirely when nothing is new.
    public static Composed Compose(MgmtReport r, ExecPresentation view, IReadOnlyList<LifecycleDay> daily, DateTime nowUtc, CultureInfo culture, string? tenant = null,
        NewContextLine? newContext = null, SI.Management.Web.RiskExec.ExecutiveFigures? keyFigures = null, int seenDays = 30, int catchUpDays = 30,
        SI.Management.Web.RiskExec.AcceptedLifecycle? lifecycle = null)
    {
        string N(long v) => v.ToString("N0", culture);
        var f = view.Figures;
        var sb = new StringBuilder();
        var subject = $"{r.Name} · {nowUtc:yyyy-MM-dd}";   // MAIL-3 (#653): the transport names the environment and the product
        // #728: the summary block first -- the protection score (#636: it replaced the old 0-100 KPI), the very high / high
        // counts, the weakest asset type (no table anywhere)
        if (f?.Kpi is { } ks)
        {
            var lines = new List<string> { ProtectionLine(ks.Protection, culture), $"<strong>Findings:</strong> {N(ks.TotalCount("Critical"))} very high, {N(ks.TotalCount("High"))} high" };
            if (ks.Protection?.ByType.Where(x => x.Lifecycle is not null).OrderBy(x => x.Lifecycle).FirstOrDefault() is { } weak)
                lines.Add($"<strong>Weakest asset type:</strong> {E(weak.Type)} at {E(Pct(weak.Lifecycle, culture))} within Accepted Lifecycle");
            sb.Append(MailLayout.Summary(lines));
        }
        else sb.Append(MailLayout.Summary(new[] { $"<strong>Risk figures:</strong> not available yet for the {E(view.Grain)} report" }));
        if (f is null)
        {
            sb.Append(Para("No Risk Analysis figures are available yet for the " + E(view.Grain) + " report; the timeline below is from the vulnerability close-loop."));
        }
        else
        {
            var from = view.FromLeader ? $"figures from the {E(view.Leader)} report, as in the Risk Analysis mails" : $"the {E(f.Grain)} report's figures";
            sb.Append($"<p style=\"{Font}font-size:12px;color:#5a6a7a;margin:0 0 12px 0;\">Data: {from}, generated {f.FiguresGeneratedAt:yyyy-MM-dd HH:mm} UTC.</p>");
        }
        if (r.Kpi && f?.Kpi is { } k)
        {
            sb.Append(H2("Protection Score"));
            sb.Append("<div data-mail-protection>");
            if (k.Protection is { } p)
            {
                // owner 2026-10-20: the value in its band's words and colour (ProtectionBands), never a fixed green; the two names
                var bl = ProtectionBands.Of(p.Lifecycle); var bt = ProtectionBands.Of(p.Technical);
                // owner 2026-10-20 ("make the headline bigger and the % Very good smaller (balanced)"): each name above its value,
                // the name the larger words, the value balanced with it; the accepted lifecycle's actual values under it
                sb.Append($"<div data-mail-ps-cap style=\"{Font}font-size:18px;font-weight:700;color:#1a2b3c;line-height:1.25;\">{E(SI.Management.Web.RiskExec.ExecutiveFigures.LifecycleName)}</div>");
                sb.Append($"<div data-mail-ps-value data-band=\"{bl.Tone}\" style=\"{Font}font-size:26px;font-weight:700;color:{bl.Ink};line-height:1.2;margin:2px 0;\">{E(Pct(p.Lifecycle, culture))} &middot; {E(bl.Name)}</div>");
                if ((lifecycle ?? keyFigures?.Lifecycle) is { } life)
                    sb.Append($"<div data-lifecycle-line style=\"{Font}font-size:12px;color:#5a6a7a;margin:0 0 10px 0;\">{E(life.Line)}</div>");
                sb.Append($"<div style=\"{Font}font-size:15px;color:#333;margin:4px 0;\"><strong style=\"color:#1a2b3c;\">{E(SI.Management.Web.RiskExec.ExecutiveFigures.ActualName)}:</strong> <strong data-band=\"{bt.Tone}\" style=\"color:{bt.Ink};\">{E(Pct(p.Technical, culture))} &middot; {E(bt.Name)}</strong></div>");
                sb.Append($"<div style=\"{Font}font-size:11px;color:#8a99aa;\">higher is better &middot; the share of active assets with no open Very High / High finding, tier-weighted &middot; {N(p.NoDate)} of {N(p.Findings)} counted findings had no usable date and count as open</div>");
            }
            else sb.Append(Para("The Protection Score comes with the next Detailed run (it is computed from the Detailed findings and the CIs)."));
            sb.Append("</div>");
            sb.Append(H3("Summary"));
            if (f.AISummaryEnabled && !string.IsNullOrWhiteSpace(f.AISummaryText))
            {
                sb.Append($"<div style=\"{Font}font-size:13px;color:#333;line-height:1.55;\">{SI.Management.Web.RiskExec.ExecNarrative.ToHtml(f.AISummaryText)}</div>");
                sb.Append($"<p style=\"{Font}font-size:11px;color:#888;font-style:italic;\">This narrative was generated by AI and may contain mistakes.</p>");
            }
            else sb.Append(Para(E(PlainSummary(k))));
        }
        if (r.Domains && f?.Kpi is { } kd)
        {
            sb.Append(H2("Findings by domain"));
            // #728: one line per domain (no table): "Endpoint: 1,234 findings – very high 5, high 20, medium 30, low 40"; #636: the
            // per-domain 0-100 score is retired with the old KPI -- the protection score per asset type is above
            sb.Append("<div data-mail-domains>");
            foreach (var (key, label) in ExecKpi.Domains)
                sb.Append(Row(label, N(kd.Count(key, "Total")), N(kd.Count(key, "Critical")), N(kd.Count(key, "High")), N(kd.Count(key, "Medium")), N(kd.Count(key, "Low"))));
            sb.Append(Row("Total", N(kd.TotalCount("Total")), N(kd.TotalCount("Critical")), N(kd.TotalCount("High")), N(kd.TotalCount("Medium")), N(kd.TotalCount("Low"))));
            sb.Append("</div>");
            if (kd.Protection is { ByType.Count: > 0 } pt)
            {
                sb.Append(H3("Protection Score by asset type"));
                foreach (var x in pt.ByType)
                    sb.Append(MailLayout.Line(x.Type, html: $"{E(Pct(x.Lifecycle, culture))} within Accepted Lifecycle &middot; {E(Pct(x.Technical, culture))} Actual Risks &middot; {N(x.Assets)} assets"));
            }
            // #636: the mail reads the Detailed figures only -- no Summary-vs-Detailed note (it named distinct-asset counts the mail no longer shows)
        }
        if (r.Timeline)
        {
            var today = DateOnly.FromDateTime(nowUtc);
            sb.Append(H2("Vulnerabilities opened and closed"));
            foreach (var (title, days) in new[] { ("Last month, per week", 30), ("Last 3 months, per week", 91) })
            {
                var weeks = Weeks(daily, today, days);
                sb.Append(H3(title));
                if (weeks.All(w => w.Opened == 0 && w.Closed == 0 && w.OpenAtEnd is null)) { sb.Append(Para("No vulnerability changes were recorded in this period.")); continue; }
                // #728: one line per week (no table): "Week of 2026-10-05: 12 opened, 8 closed, 340 open at week end"
                sb.Append($"<div data-weeks=\"{days}\">");
                foreach (var w in weeks)
                    sb.Append(MailLayout.Line($"Week of {w.Monday:yyyy-MM-dd}", html:
                        $"<span style=\"color:#8a3d00;\">{N(w.Opened)} opened</span>, <span style=\"color:#1b5e20;\">{N(w.Closed)} closed</span>, {(w.OpenAtEnd is { } o ? N(o) : "–")} open at week end"));
                sb.Append("</div>");
            }
            sb.Append($"<p style=\"{Font}font-size:11px;color:#5a6a7a;\">Opened = first seen after the connector's first snapshot (that snapshot is the baseline); closed = closed by SecurityInsight or an engineer.</p>");
        }
        // #636: the key figures -- the Executive report's blocks the report carries (default every block), from the same stored figures
        if (keyFigures is { Ready: true } kf) sb.Append(KeyFiguresHtml(r, kf, seenDays, catchUpDays));
        if (newContext is not null && newContext.Text(N) is { Length: > 0 } found)
        {
            sb.Append(H2(r.Cadence == MgmtReport.Weekly ? "Also new this week" : "Also new this month"));
            var page = newContext.Link is { Length: > 0 } href
                ? $"<a href=\"{E(href)}\" style=\"color:#1B4FE4;\" data-mail-new-context-link>New context available</a>"
                : E(SI.Management.Web.Navigation.NavModel.PathOf("/SchemaOverlay/NewContext")) + " in SecurityInsight";
            sb.Append($"<p style=\"{Font}font-size:13px;color:#333;line-height:1.55;margin:6px 0;\" data-mail-new-context=\"{newContext.Total.ToString(CultureInfo.InvariantCulture)}\">{E(found)} &ndash; see {page}.</p>");
        }
        return new Composed(subject, Wrap(r.Name, f?.ReportTemplate ?? ("RiskAnalysis_" + view.Grain), tenant ?? f?.Tenant, nowUtc, sb.ToString()));
    }

    /// MAIL-2 items 1 and 4: the composed mail with the recipient audience's blue button at the top of the body and the
    /// web app's home linked in the footer (the preview stays as composed).
    public static string WithButton(string html, string buttonHtml, string? homeUrl)
    {
        // #728: the summary block stays first -- the button follows it (the mail job puts the portal link line directly under
        // the summary too); a body without a summary takes the button at its top.
        var s = html.IndexOf("data-mail-summary", StringComparison.Ordinal);
        var end = s >= 0 ? html.IndexOf("</div>", s, StringComparison.Ordinal) : -1;
        var withButton = end >= 0
            ? html.Insert(end + "</div>".Length, buttonHtml)
            : html.Replace("data-mgmt-body>", "data-mgmt-body>" + buttonHtml, StringComparison.Ordinal);
        return homeUrl is null ? withButton
            : withButton.Replace("SecurityInsight Pro &middot; management summary", $"<a href=\"{E(homeUrl)}\" style=\"color:#1B4FE4;\" data-mail-home>Open SecurityInsight</a> &middot; management summary", StringComparison.Ordinal);
    }

    /// #636: the key figures blocks as mail lines (no table: #728) -- the same blocks, lines and rows as the Executive report.
    public static string KeyFiguresHtml(MgmtReport r, SI.Management.Web.RiskExec.ExecutiveFigures kf, int seenDays = 30, int catchUpDays = 30)
    {
        var sb = new StringBuilder();
        sb.Append("<div data-mail-key-figures>");
        // the scope a reader must know, from the real settings (owner: "so we dont send wrong signals")
        sb.Append($"<p style=\"{Font}font-size:12px;color:#5a6a7a;margin:0 0 12px 0;\" data-mail-scope>{E(kf.ScopeLine(seenDays, catchUpDays))}</p>");
        foreach (var b in kf.ReportBlocks(r.Includes))
        {
            sb.Append(H2(b.Title));
            if (b.Unavailable is not null) { sb.Append(Para(E(b.Unavailable))); continue; }
            foreach (var l in b.Lines)
                sb.Append(MailLayout.Line(l.Label, html: E(l.Value) + (l.Change is { Tone: not "none" } c ? " &middot; " + E(c.Text) : "") + (l.Note is null ? "" : " &middot; " + E(l.Note))));
            foreach (var t in b.Tables.Where(t => t.Rows.Count > 0).Take(3))
            {
                sb.Append(H3(t.Title));
                foreach (var row in t.Rows.Take(8))
                    sb.Append(MailLayout.Line(row[0], html: string.Join(" &middot; ", row.Skip(1).Select((v, i) => E(t.Headers.Count > i + 1 ? t.Headers[i + 1] + " " + v : v)))));
            }
        }
        sb.Append("</div>");
        return sb.ToString();
    }

    private static string Pct(double? v, CultureInfo culture) => v is { } x ? x.ToString("0.0", culture) + " %" : "–";

    /// #636: the protection score as the summary's first line -- both views, the accepted lifecycle first.
    private static string ProtectionLine(ExecProtection? p, CultureInfo culture) => p is null
        ? "<strong>Protection Score:</strong> comes with the next Detailed run"
        : $"<strong>{E(SI.Management.Web.RiskExec.ExecutiveFigures.LifecycleName)}:</strong> {E(Pct(p.Lifecycle, culture))} &middot; {E(ProtectionBands.Of(p.Lifecycle).Name)}<br>"
          + $"<strong>{E(SI.Management.Web.RiskExec.ExecutiveFigures.ActualName)}:</strong> {E(Pct(p.Technical, culture))} &middot; {E(ProtectionBands.Of(p.Technical).Name)}";
    private static string Para(string html) => $"<p style=\"{Font}font-size:14px;color:#333;line-height:1.55;margin:0 0 12px 0;\">{html}</p>";
    private static string H2(string t) => MailLayout.Heading(t);
    private static string H3(string t) => $"<h3 style=\"{Font}font-size:14px;font-weight:700;color:#5a6a7a;margin:16px 0 8px 0;\">{E(t)}</h3>";
    /// #728: one domain's figures as ONE line, the domain in bold.
    private static string Row(string label, string total, string c, string h, string m, string l) =>
        MailLayout.Line(label, html: $"{total} findings &ndash; very high {c}, high {h}, medium {m}, low {l}");
    /// #728: the frame (a max-width div, no table); data-mgmt-body closes the content div's opening tag (WithButton).
    private static string Wrap(string name, string report, string? tenant, DateTime now, string body) =>
        MailLayout.Frame($"SecurityInsight &middot; {E(name)}<br><span style=\"font-size:12px;font-weight:400;color:#cfdce8;\">{E(report)} &middot; {E(string.IsNullOrWhiteSpace(tenant) ? "—" : tenant)} &middot; {now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC</span>",
            null, null, body, "SecurityInsight Pro &middot; management summary", brandAttr: "data-mail-brand", bodyAttr: "data-mgmt-body");
}

/// The definitions and the outbox (cfg.MgmtReport, cfg.ReportMail).
public interface IMgmtReportStore
{
    Task<bool> ReadyAsync(CancellationToken ct);
    Task<IReadOnlyList<MgmtReport>> ListAsync(CancellationToken ct);
    /// Inserts (Id 0) or updates; returns the id.
    Task<long> SaveAsync(MgmtReport r, string by, CancellationToken ct);
    Task<bool> RemoveAsync(long id, string by, CancellationToken ct);
    /// Claims a period for a report: true only for the ONE caller that moved LastPeriodKey to it (no double send).
    Task<bool> ClaimAsync(long id, string periodKey, CancellationToken ct);
    Task QueueMailAsync(long reportId, string? periodKey, IReadOnlyList<string> to, string subject, string html, string by, CancellationToken ct);
}

public sealed class SqlMgmtReportStore(ISqlExecutor sql) : IMgmtReportStore
{
    public const string ReadySql = "SELECT CASE WHEN OBJECT_ID(N'cfg.MgmtReport') IS NOT NULL AND OBJECT_ID(N'cfg.ReportMail') IS NOT NULL THEN 1 ELSE 0 END AS Ready;";
    public const string ListSql = "SELECT ReportId, Name, Grain, Sections, Recipients, Cadence, [Day], TimeUtc, Enabled, LastPeriodKey, LastSentAt, CreatedAt FROM cfg.MgmtReport WHERE RemovedAt IS NULL ORDER BY Name, ReportId;";
    public const string InsertSql = """
INSERT cfg.MgmtReport (Name, Grain, Sections, Recipients, Cadence, [Day], TimeUtc, Enabled, CreatedBy, UpdatedBy)
VALUES (@Name, @Grain, @Sections, @Recipients, @Cadence, @Day, @TimeUtc, @Enabled, @By, @By);
SELECT CAST(SCOPE_IDENTITY() AS bigint) AS ReportId;
""";
    public const string UpdateSql = """
UPDATE cfg.MgmtReport SET Name = @Name, Grain = @Grain, Sections = @Sections, Recipients = @Recipients, Cadence = @Cadence, [Day] = @Day,
       TimeUtc = @TimeUtc, Enabled = @Enabled, UpdatedBy = @By, UpdatedAt = SYSUTCDATETIME()
WHERE ReportId = @Id AND RemovedAt IS NULL;
SELECT @Id AS ReportId;
""";
    public const string RemoveSql = "UPDATE cfg.MgmtReport SET RemovedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE ReportId = @Id AND RemovedAt IS NULL; SELECT @@ROWCOUNT AS N;";
    /// The claim: only one caller moves the period (the WHERE re-checks it), so a period is sent once.
    public const string ClaimSql = "UPDATE cfg.MgmtReport SET LastPeriodKey = @Key, LastSentAt = SYSUTCDATETIME() WHERE ReportId = @Id AND RemovedAt IS NULL AND (LastPeriodKey IS NULL OR LastPeriodKey <> @Key); SELECT @@ROWCOUNT AS N;";
    public const string QueueSql = """
INSERT cfg.ReportMail (ReportId, PeriodKey, ToList, Subject, BodyHtml, QueuedBy) VALUES (@ReportId, @PeriodKey, @ToList, @Subject, @BodyHtml, @By);
SELECT N'Saved' AS Outcome;
""";

    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;
    public static string SectionsText(MgmtReport r) => string.Join(",", new[] { r.Kpi ? "kpi" : null, r.Domains ? "domains" : null, r.Timeline ? "timeline" : null }.Where(x => x is not null)
        .Concat(r.KeyBlocks is null ? Array.Empty<string>() : r.KeyBlocks.Count == 0 ? new[] { "kf:none" } : r.KeyBlocks.Select(b => "kf:" + b).ToArray()));

    /// The key figures blocks of a stored Sections text (no kf: token = every block; kf:none = none).
    public static IReadOnlyList<string>? KeyBlocksOf(IReadOnlyList<string> sections)
    {
        var kf = sections.Where(s => s.StartsWith("kf:", StringComparison.Ordinal)).Select(s => s[3..]).ToList();
        return kf.Count == 0 ? null : kf.Where(b => b != "none").ToList();
    }

    public async Task<bool> ReadyAsync(CancellationToken ct) => (await sql.QueryAsync(ReadySql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("Ready") == 1;

    public async Task<IReadOnlyList<MgmtReport>> ListAsync(CancellationToken ct) =>
        (await sql.QueryAsync(ListSql, new Dictionary<string, object?>(), ct)).Select(r =>
        {
            var s = (r.Str("Sections") ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            return new MgmtReport(r.Long("ReportId") ?? 0, r.Str("Name") ?? "", r.Str("Grain") ?? RiskExecGrain.Detailed, s.Contains("kpi"), s.Contains("domains"), s.Contains("timeline"),
                (r.Str("Recipients") ?? "").Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries), r.Str("Cadence") ?? MgmtReport.Monthly,
                (int)(r.Long("Day") ?? 1), r.Str("TimeUtc") ?? "07:00", r.TryGetValue("Enabled", out var e) && e is true or 1 or 1L,
                r.Str("LastPeriodKey"), r.Date("LastSentAt"), DateTime.SpecifyKind(r.Date("CreatedAt") ?? DateTime.UtcNow, DateTimeKind.Utc)) { KeyBlocks = KeyBlocksOf(s) };
        }).ToList();

    public async Task<long> SaveAsync(MgmtReport r, string by, CancellationToken ct)
    {
        var p = new Dictionary<string, object?>
        {
            ["Id"] = r.Id, ["Name"] = Cut(r.Name.Trim(), 100), ["Grain"] = r.Grain, ["Sections"] = SectionsText(r), ["Recipients"] = Cut(string.Join(";", r.Recipients), 2000),
            ["Cadence"] = r.Cadence, ["Day"] = r.Day, ["TimeUtc"] = r.TimeUtc, ["Enabled"] = r.Enabled, ["By"] = Cut(by, 256),
        };
        return (await sql.QueryAsync(r.Id == 0 ? InsertSql : UpdateSql, p, ct)).FirstOrDefault()?.Long("ReportId") ?? 0;
    }

    public async Task<bool> RemoveAsync(long id, string by, CancellationToken ct) =>
        (await sql.QueryAsync(RemoveSql, new Dictionary<string, object?> { ["Id"] = id, ["By"] = Cut(by, 256) }, ct)).FirstOrDefault()?.Long("N") == 1;

    public async Task<bool> ClaimAsync(long id, string periodKey, CancellationToken ct) =>
        (await sql.QueryAsync(ClaimSql, new Dictionary<string, object?> { ["Id"] = id, ["Key"] = periodKey }, ct)).FirstOrDefault()?.Long("N") == 1;

    public Task QueueMailAsync(long reportId, string? periodKey, IReadOnlyList<string> to, string subject, string html, string by, CancellationToken ct) =>
        sql.QueryAsync(QueueSql, new Dictionary<string, object?>
        {
            ["ReportId"] = reportId, ["PeriodKey"] = periodKey, ["ToList"] = Cut(string.Join(";", to), 2000), ["Subject"] = Cut(subject, 400), ["BodyHtml"] = SI.Management.Core.Mail.MailLayout.Normalize(html), ["By"] = Cut(by, 256),
        }, ct);
}

/// <summary>Composes a report from the live data and hands it to the outbox (then wakes the mail job, best effort).</summary>
public sealed class MgmtReportSender(IMgmtReportStore store, IRiskExecViews views, IProDataQueries data, IJobsClient jobs,
    Microsoft.Extensions.Options.IOptions<JobsOptions> options, SI.Management.Web.Audit.IAuditWriter audit, TimeProvider clock, ILogger<MgmtReportSender> log,
    SI.Management.Web.Notify.NotificationService notify, SI.Management.Web.Links.WebSettings web, SI.Management.Web.NewContext.INewContextStore newContext,
    SI.Management.Web.Jobs.ISummaryStep? summaryStep = null, IServiceProvider? services = null)
{
    public IMgmtReportStore Store => store;
    /// #636: is the Risk Analysis Summary step on? (no step service = as before: on)
    public async Task<bool> SummaryOnAsync(CancellationToken ct) => summaryStep is null || await summaryStep.IsOnAsync(ct);
    public DateTime Now => clock.GetUtcNow().UtcDateTime;

    /// What the discovery found since this report's last summary mail (null = nothing new, or it could not be read --
    /// the mail is sent either way, without the line). One grouped read of the prepared rows.
    public async Task<NewContextLine?> NewContextAsync(MgmtReport r, CancellationToken ct)
    {
        try
        {
            var sources = await newContext.NewSinceAsync(NewContextLine.Since(r, Now), ct);
            if (sources.Sum(s => s.Properties) <= 0) return null;
            string? baseUrl = null;
            try { baseUrl = (await web.ReadAsync(ct)).PublicBaseUrl; } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "management summary: the web app's address"); }
            return new NewContextLine(sources, SI.Management.Web.Notify.MailBrand.Link(baseUrl, NewContextLine.PagePath(r)));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "management summary: new context"); return null; }
    }

    public async Task<MgmtSummaryComposer.Composed> ComposeAsync(MgmtReport r, CultureInfo culture, CancellationToken ct)
    {
        IReadOnlyList<ExecSnapshot> all = [];
        try { var v = await views.ViewsAsync(ct); all = v.Data.Views; } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "management summary: risk analysis views"); }
        IReadOnlyList<LifecycleDay> days = [];
        if (r.Timeline)
            try { days = (await data.LifecycleAsync(92, ct)).Data; } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "management summary: lifecycle"); }
        // #636: while the Summary step is off a stored Summary report shows the Detailed report (the updater moves it too)
        var summaryOn = summaryStep is null || await summaryStep.IsOnAsync(ct);
        // #636: the key figures (the Executive report's blocks), read once from the stored figures; a report without blocks reads none
        SI.Management.Web.RiskExec.ExecutiveFigures? kf = null;
        if (services is not null && (r.KeyBlocks is null || r.KeyBlocks.Count > 0))
            try { kf = await SI.Management.Web.RiskExec.ExecutiveFigures.LoadAsync(services, null, ct); } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "management summary: key figures"); }
        // #855 W5: the seen window in force (the lifecycle reader), never a literal day count
        var (seen, catchUp) = services is null ? (CiLifecycleDefinitions.Defaults.SeenWithinDays, SI.Management.Web.RiskExec.ExecutiveFigures.DefaultCatchUpDays)
            : await SI.Management.Web.RiskExec.ExecutiveFigures.ScopeDaysAsync(services, ct);
        // owner 2026-10-20: the accepted lifecycle in force under the score (read with the key figures, else on its own)
        var life = kf?.Lifecycle ?? (services is null ? null : await SI.Management.Web.RiskExec.AcceptedLifecycle.ReadAsync(services, ct));
        // #636: the Detailed report's figures while the Summary step is off (the default); a Summary report keeps its own only while the step is on
        return MgmtSummaryComposer.Compose(r, RiskExecSelector.Select(all, r.Grain, summaryOn), days, Now, culture, newContext: await NewContextAsync(r, ct), keyFigures: kf,
            seenDays: seen, catchUpDays: catchUp, lifecycle: life);
    }

    /// Queues one send. Scheduled sends claim their period first, so a period is never sent twice.
    public async Task<bool> SendAsync(MgmtReport r, string? periodKey, string by, string actorSource, CancellationToken ct)
    {
        if (periodKey is not null && !await store.ClaimAsync(r.Id, periodKey, ct)) return false;
        var c = await ComposeAsync(r, CultureInfo.GetCultureInfo("en-US"), ct);
        // MAIL-2: each recipient's notifications (switched off = left out) and audience (one mail per audience, its button)
        var groups = (await notify.PrefsAsync(ct)).Route(r.Recipients, SI.Management.Web.Notify.NotifyCatalog.MgmtSummaryId(r.Id));
        var baseUrl = (await web.ReadAsync(ct)).PublicBaseUrl;
        foreach (var g in groups)
            await store.QueueMailAsync(r.Id, periodKey, g.To, c.Subject,
                MgmtSummaryComposer.WithButton(c.Html, SI.Management.Web.Notify.MailBrand.AudienceButton(baseUrl, g.Audience), SI.Management.Web.Notify.MailBrand.Link(baseUrl, "/")), by, ct);
        // a person's "send now" is written by the page's audit filter (one row per request); the scheduler writes its own
        if (actorSource == "job") await audit.WriteAsync(new SI.Management.Web.Audit.AuditRecord("report.summary.send", by, actorSource, "ok")
        {
            Target = $"management summary #{r.Id} {r.Name}", OutcomeText = $"queued for {r.Recipients.Count} recipient(s)" + (periodKey is null ? " (send now)" : " for " + periodKey),
        }, CancellationToken.None);
        if (jobs.IsConfigured && !string.IsNullOrWhiteSpace(options.Value.CloseLoopMailJob))
        {
            try { await jobs.StartWithEnvAsync(options.Value.CloseLoopMailJob, new Dictionary<string, string> { [SI.Management.Web.Exemptions.OutboxExemptionMailer.OnlyEnv] = "1" }, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the mail job could not be started -- the management summary goes with its next run"); }
        }
        return true;
    }

    /// One scheduler pass: every due report, once. Returns how many were queued.
    public async Task<int> RunDueAsync(CancellationToken ct)
    {
        if (!await store.ReadyAsync(ct)) return 0;
        var n = 0;
        foreach (var r in await store.ListAsync(ct))
        {
            if (MgmtSchedule.DuePeriod(r, Now) is not { } key) continue;
            try { if (await SendAsync(r, key, "scheduler", "job", ct)) n++; }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogError(ex, "management summary {Id} was not queued", r.Id); }
        }
        return n;
    }
}

/// The schedule's clock: every 5 minutes one pass (the web app's own; a slot missed while it was stopped is caught up once).
public sealed class MgmtReportScheduler(IServiceProvider services, ILogger<MgmtReportScheduler> log) : BackgroundService
{
    public static readonly TimeSpan Every = TimeSpan.FromMinutes(5);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(Every, stoppingToken); } catch (OperationCanceledException) { return; }
            // management summary mails are a paid feature (Licensing/ProFeatures.cs, Alerts): no Pro licence = no pass
            try { if (services.GetService<SI.Management.Web.Licensing.IProLicence>() is { } lic && !await lic.IsProAsync(stoppingToken)) continue; }
            catch (Exception ex) when (ex is not OperationCanceledException) { continue; }
            try { await services.GetRequiredService<MgmtReportSender>().RunDueAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "management summary schedule pass"); }
        }
    }
}
