using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Data;
using SI.Management.Web.Pages;

namespace SI.Management.Web.Changes;

/// <summary>
/// Framework LICENCE-DIMENSION (owner 2026-10-08: "business (with limitations) and Enterprise ... invardia, pim and si
/// all align to that"): Pro has two dimensions, decided by the SIGNED licence -- Pro Business carries `limits`
/// (SecurityInsight reads <c>devices</c>), Pro Enterprise carries none. Community has no limits. The updater verifies the
/// licence and records its limits (cfg.InstallState 'Licence'); the web app only shows them.
/// A limit is a WARNING, never a stop: from 90 % of the devices a Business licence covers a banner says so, above the
/// limit it says so on every page, and above the limit + 10 % in the alarm colour -- nothing is refused, switched off or
/// skipped; every collection and every run goes on.
/// </summary>
public static class LicenceDimension
{
    public const string Business = "Pro Business", Enterprise = "Pro Enterprise", Community = "Community";
    public const string DevicesLimit = "devices";
    /// The share of the limit at which the warning starts, and the share above which it turns to the alarm colour.
    public const double WarnFrom = 0.90, AlarmAbove = 1.10;

    /// Pro while the Pro jobs run (valid, ending soon, in grace) AND the signed sku names a Pro edition; Business when the
    /// signed licence carries limits.
    public static string Of(InstalledLicence? l, DateTime todayUtc)
    {
        if (l is null) return Community;
        var st = l.StateOn(todayUtc);
        if (st is not (LicenceState.Valid or LicenceState.EndsSoon or LicenceState.InGrace)) return Community;
        if (EditionOf(l.Sku) == EditionCommunity) return Community;
        return l.Limits is not null ? Business : Enterprise;
    }

    public const string EditionPro = "Pro", EditionMsp = "MSP", EditionCommunity = "Community";

    /// <summary>
    /// Framework §12.6a LICENCE-FEATURES (SI #510; owner 2026-10-09: "but does that mean we have to sign licenses when new
    /// features are released, that is not smart"): the signed licence names the EDITION in its sku, and the edition -- never
    /// the licence's features[] list -- decides the Pro features, current and future. The same rule as the engines'
    /// Get-SILicenceEdition (engine/SI-FeatureCatalog.ps1): a sku that starts with Pro or Trial as a word = Pro (Pro,
    /// Pro-Business, Pro-DesignPartner, pro-single-tenant, Trial); a sku naming msp as a word = MSP; anything else
    /// (Community, Core, empty) = Community. Nothing in the web app is gated on features[]: there are no add-ons today.
    /// </summary>
    public static string EditionOf(string? sku)
    {
        var s = (sku ?? "").Trim();
        if (System.Text.RegularExpressions.Regex.IsMatch(s, "(^|[^a-z])msp([^a-z]|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) return EditionMsp;
        if (System.Text.RegularExpressions.Regex.IsMatch(s, "^(pro|trial)([^a-z]|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase)) return EditionPro;
        return EditionCommunity;
    }

    /// The devices a Pro Business licence covers; null = no cap (Enterprise, Community, or Business without a device limit).
    public static int? DeviceCap(InstalledLicence? l, DateTime todayUtc) =>
        Of(l, todayUtc) == Business && l!.Limits!.TryGetValue(DevicesLimit, out var n) ? n : null;

    /// The one label every place shows: "Pro Business (250 devices)", "Pro Business", "Pro Enterprise", "Community".
    public static string Text(InstalledLicence? l, DateTime todayUtc)
    {
        var d = Of(l, todayUtc);
        return d == Business && DeviceCap(l, todayUtc) is { } cap ? d + " (" + Fmt.Int(cap) + " devices)" : d;
    }

    /// What a place that names the licence shows while NO licence check is on record (the updater writes it on its run;
    /// a new install has none for its first hours): the licence is not guessed -- never "Community" on a Pro install whose
    /// licence simply has not been recorded yet (owner 2026-10-12: the header said "Community" minutes after a Pro install).
    public const string BeingChecked = "being checked";
    public const string BeingCheckedDetail = "No licence check is recorded for this install yet. SecurityInsight's updater records the licence it verified on its next run (every night); until then the licence is not shown.";

    /// The label for a place that may have no record at all: "being checked" for none, else <see cref="Text"/>.
    public static string TextOrBeingChecked(InstalledLicence? l, DateTime todayUtc) => l is null ? BeingChecked : Text(l, todayUtc);

    public static LicenceUsage Usage(InstalledLicence? l, DateTime todayUtc, long? devices)
    {
        // nothing on record: said as that (neutral, no banner) -- the dimension is not worked out from nothing
        if (l is null) return new(BeingChecked, BeingChecked, null, devices, null, LicenceUsage.None, BeingCheckedDetail);
        var dim = Of(l, todayUtc);
        var text = Text(l, todayUtc);
        var cap = DeviceCap(l, todayUtc);
        if (cap is not { } c || devices is not { } n) return new(dim, text, cap, devices, null, LicenceUsage.None, "");
        var pct = c == 0 ? (n > 0 ? double.PositiveInfinity : 0) : (double)n / c;
        var covers = "Your Pro Business licence covers " + Fmt.Int(c) + " device" + (c == 1 ? "" : "s");
        var goesOn = " Nothing is stopped or switched off: every collection and every run goes on.";
        var how = " Ask Invardia for a higher limit or Pro Enterprise." + InstalledLicence.LicenceRoute;
        if (n > c)
            return new(dim, text, c, n, pct, pct > AlarmAbove ? LicenceUsage.Alarm : LicenceUsage.Over,
                covers + "; SecurityInsight sees " + Fmt.Int(n) + " -- " + Fmt.Int(n - c) + " above the limit." + goesOn + how);
        if (pct >= WarnFrom)
            return new(dim, text, c, n, pct, LicenceUsage.Near, covers + "; " + Fmt.Int(n) + " are in use (" + Percent(pct) + ")." + goesOn + how);
        return new(dim, text, c, n, pct, LicenceUsage.Ok, covers + "; " + Fmt.Int(n) + " are in use (" + Percent(pct) + ").");
    }

    private static string Percent(double p) => Fmt.Num(Math.Floor(p * 100), 0) + " %";
}

/// <param name="State">none (no limit) | ok | near (from 90 %) | over (above the limit) | alarm (above the limit + 10 %)</param>
public sealed record LicenceUsage(string Dimension, string DimensionText, int? Cap, long? Devices, double? Share, string State, string Message)
{
    public const string None = "none", Ok = "ok", Near = "near", Over = "over", Alarm = "alarm";
    /// The banner shows from 90 % of the limit; it never blocks anything.
    public bool ShowsBanner => State is Near or Over or Alarm;
    public string Tone => State == Alarm ? "error" : "warn";
}

/// <summary>
/// The licence's dimension and the devices SecurityInsight sees, for the header, the banner, Get Started and the Licence
/// card. The devices are the CIs of class device that are not retired (sidata.Ci) -- counted only for a Business licence
/// with a device limit. Kept for five minutes (the licence is verified nightly, the CIs change with a data sync). Never
/// fails a page: what cannot be read is no usage.
/// </summary>
public interface ILicenceUsageSource
{
    /// null = nothing to show (the fake of a test that does not set one).
    Task<LicenceUsage?> ReadAsync(CancellationToken ct);
}

public sealed class LicenceUsageReader(InstalledLicenceReader licence, ISqlExecutor sql, IMemoryCache cache, ILogger<LicenceUsageReader> log) : ILicenceUsageSource
{
    public const string DevicesSql = """
IF OBJECT_ID(N'sidata.Ci') IS NOT NULL SELECT COUNT_BIG(*) AS Devices FROM sidata.Ci WHERE Class = N'device' AND (Lifecycle IS NULL OR Lifecycle <> N'retired');
""";
    private const string Key = "si-licence-usage";

    public async Task<LicenceUsage?> ReadAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(Key, out LicenceUsage? hit) && hit is not null) return hit;
        InstalledLicence? l = null;
        long? devices = null;
        try
        {
            l = await licence.ReadAsync(ct);
            if (LicenceDimension.DeviceCap(l, DateTime.UtcNow) is not null)
                devices = (await sql.QueryAsync(DevicesSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("Devices");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) { log.LogDebug(ex, "the licence usage could not be read"); }
        var u = LicenceDimension.Usage(l, DateTime.UtcNow, devices);
        // "being checked" (nothing on record, or the read failed) is asked again soon: it turns into the licence by itself
        cache.Set(Key, u, l is null ? TimeSpan.FromMinutes(1) : TimeSpan.FromMinutes(5));
        return u;
    }
}
