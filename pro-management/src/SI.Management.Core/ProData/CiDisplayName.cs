using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// A CI WITHOUT A NAME (#856, owner 2026-10-21: "why do we have a device without a name"): a device Defender only
// DISCOVERED on the network (never onboarded) has no name in Defender either -- only its IP and MAC addresses. The views
// show such a CI by its best identifier instead: its IP address, else its MAC address, else the source's id -- MARKED as a
// fallback ("(no name)", CSS class ci-noname). The fallback is a DISPLAY value only: it is never written to the CI
// (si_asset_name stays empty), never exported as the name, and never sent to ServiceNow as a name.
// The best IP of a list: an IPv4 address first, then any other (IPv6), loopback last -- the same rule the data sync's
// IpAddress column fill uses (engine/pro-data/_shared/SI-DataCi.ps1, Get-SIDataCiDocFieldsSql).
// =====================================================================================================================

/// <summary>A fallback name: the value shown and what kind of identifier it is ("IP address", "MAC address", "source id").</summary>
public sealed record CiNameFallback(string Value, string Kind)
{
    /// The words a view says next to a fallback name.
    public string Hint => CiDisplayName.NoNameHint;
    /// The tooltip: why the CI is shown this way.
    public string Title => "This CI has no name -- its source gives it none (a device Defender only discovered on the network). Shown by its " + Kind + ".";
}

public static partial class CiDisplayName
{
    /// The grid key of the hidden late column that carries a nameless CI's fallback (<see cref="CiColumnCatalog.Spec"/>).
    public const string FallbackKey = "NameFallback";
    /// The words next to a fallback name.
    public const string NoNameHint = "(no name)";
    /// The CSS class a fallback name is rendered with.
    public const string CssClass = "ci-noname";

    public const string KindIp = "IP address";
    public const string KindMac = "MAC address";
    public const string KindSourceId = "source id";

    /// The source links a fallback reads the id of, in order (the CI's primary link per provider).
    public static readonly IReadOnlyList<string> LinkFields =
        ["si_link_mde", "si_link_eg", "si_link_azure", "si_link_intune", "si_link_entra", "si_link_ad", "si_link_shodan", "si_link_cmdb", "si_link_servicenow"];

    /// <summary>
    /// The best IP address of a JSON list expression <paramref name="listJson"/> (SQL, read-only): an IPv4 address first, then
    /// any other, a loopback address last, in list order within each -- NULL for an empty / missing list.
    /// </summary>
    public static string BestIpSql(string listJson) =>
        "(SELECT TOP (1) CONVERT(nvarchar(400), ip.[value]) FROM OPENJSON(" + listJson + ") AS ip WHERE ip.[type] = 1 AND LEN(ip.[value]) > 0 "
        + "ORDER BY CASE WHEN ip.[value] LIKE N'127.%' OR ip.[value] = N'::1' THEN 2 WHEN ip.[value] LIKE N'%:%' THEN 1 ELSE 0 END, TRY_CONVERT(int, ip.[key]))";

    /// The first text of a JSON list expression (SQL), NULL for none.
    private static string FirstSql(string listJson) =>
        "(SELECT TOP (1) CONVERT(nvarchar(400), x.[value]) FROM OPENJSON(" + listJson + ") AS x WHERE x.[type] = 1 AND LEN(x.[value]) > 0 ORDER BY TRY_CONVERT(int, x.[key]))";

    /// <summary>
    /// The IP address the CI grid shows for a CI, read from its document (d.J): the public IP (si_ip_address) of a public IP
    /// CI, else the best of the CI's addresses (si_ip_addresses -- a list, or one text). What the data sync fills the
    /// IpAddress column with.
    /// </summary>
    public static string IpFromDocumentSql(string doc = "d.J") =>
        "COALESCE(CONVERT(nvarchar(400), JSON_VALUE(" + doc + ", N'$.si_ip_address')), " + BestIpSql("JSON_QUERY(" + doc + ", N'$.si_ip_addresses')")
        + ", CONVERT(nvarchar(400), JSON_VALUE(" + doc + ", N'$.si_ip_addresses')))";

    /// <summary>
    /// The fallback of a nameless CI (SQL over sidata.Ci AS c and its checked document d.J): NULL when the CI has a name; else
    /// its IP address (the IpAddress column where the database has it), its MAC address, the id of its primary source link,
    /// and last its CI id. Read for the page's rows only (a late column). <paramref name="mode"/> Columns (every CI's columns
    /// are current): the COLUMNS alone -- the IpAddress column (the device's best address, filled by the data sync), else
    /// the CI id; a page never reads a CI document once the columns are filled. Otherwise the document too.
    /// </summary>
    public static string FallbackSql(CiFieldMode mode)
    {
        if (mode == CiFieldMode.Columns) return "CASE WHEN NULLIF(LTRIM(c.Name), N'') IS NULL THEN COALESCE(NULLIF(c.IpAddress, N''), c.CiId) END";
        var parts = new List<string>();
        if (mode != CiFieldMode.Document) parts.Add("NULLIF(c.IpAddress, N'')");
        parts.Add(IpFromDocumentSql());
        parts.Add(FirstSql("JSON_QUERY(d.J, N'$.si_mac_addresses')"));
        parts.Add("CONVERT(nvarchar(400), JSON_VALUE(d.J, N'$.si_mac_addresses'))");
        parts.AddRange(LinkFields.Select(f => "CONVERT(nvarchar(400), JSON_VALUE(d.J, N'$." + f + "'))"));
        parts.Add("c.CiId");
        return "CASE WHEN NULLIF(LTRIM(c.Name), N'') IS NULL THEN COALESCE(" + string.Join(", ", parts) + ") END";
    }

    [GeneratedRegex("^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$|^([0-9A-Fa-f]{4}\\.){2}[0-9A-Fa-f]{4}$", RegexOptions.CultureInvariant)]
    private static partial Regex MacPattern();

    /// What kind of identifier a fallback value is.
    public static string KindOf(string value)
    {
        var v = value.Trim();
        if (MacPattern().IsMatch(v)) return KindMac;
        if (v.Contains('.') || v.Contains(':')) { if (IPAddress.TryParse(v, out _)) return KindIp; }
        return KindSourceId;
    }

    /// The fallback of a CI with <paramref name="name"/> from a value the statement read (null when the CI has a name or
    /// there is no value).
    public static CiNameFallback? Of(string? name, string? fallback) =>
        !string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(fallback) ? null : new CiNameFallback(fallback.Trim(), KindOf(fallback));

    /// The best IP of a list (the C# twin of <see cref="BestIpSql"/>).
    public static string? BestIp(IEnumerable<string?>? ips)
    {
        if (ips is null) return null;
        var list = ips.Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!.Trim()).ToList();
        static int Rank(string s) => s.StartsWith("127.", StringComparison.Ordinal) || s == "::1" ? 2 : s.Contains(':') ? 1 : 0;
        return list.Select((s, i) => (s, i)).OrderBy(x => Rank(x.s)).ThenBy(x => x.i).Select(x => x.s).FirstOrDefault();
    }

    /// <summary>
    /// The fallback of a CI from its document (the CI page): null when the document has a name (si_asset_name); else its IP
    /// address, MAC address or source id, as <see cref="FallbackSql"/> picks it. <paramref name="ciId"/> is the last resort.
    /// </summary>
    public static CiNameFallback? FromDocument(JsonElement root, string? ciId = null)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;
        if (CiDoc.S(root, "si_asset_name") is { Length: > 0 } n && n.Trim().Length > 0) return null;
        var ip = CiDoc.S(root, "si_ip_address") ?? BestIp(Texts(root, "si_ip_addresses"));
        if (ip is { Length: > 0 }) return new CiNameFallback(ip, KindIp);
        var mac = Texts(root, "si_mac_addresses").FirstOrDefault(s => !string.IsNullOrWhiteSpace(s));
        if (mac is { Length: > 0 }) return new CiNameFallback(mac.Trim(), KindMac);
        foreach (var f in LinkFields) if (CiDoc.S(root, f) is { Length: > 0 } id) return new CiNameFallback(id, KindSourceId);
        return ciId is { Length: > 0 } ? new CiNameFallback(ciId, KindSourceId) : null;
    }

    /// The texts of a field that is a list, a list kept as JSON text, or one text.
    internal static IReadOnlyList<string?> Texts(JsonElement root, string field)
    {
        if (!root.TryGetProperty(field, out var v)) return [];
        if (v.ValueKind == JsonValueKind.String && v.GetString() is { } s)
        {
            var t = s.Trim();
            if (t.StartsWith('['))
            {
                try { using var d = JsonDocument.Parse(t); return d.RootElement.ValueKind == JsonValueKind.Array ? d.RootElement.EnumerateArray().Select(Text).ToList() : []; }
                catch (JsonException) { return [t]; }
            }
            return [t];
        }
        return v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Select(Text).ToList() : [];
        static string? Text(JsonElement e) => e.ValueKind == JsonValueKind.String ? e.GetString() : null;
    }
}
