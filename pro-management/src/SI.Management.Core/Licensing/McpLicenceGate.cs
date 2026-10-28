using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Core.Licensing;

/// <summary>
/// THE MCP SERVER'S LICENCE GATE (owner 2026-10-27, SI #750 decision (3): "the AI summary is free, the chat and the MCP
/// server are Pro, and the MCP server gets a licence gate instead of an install-time edition check"). The MCP server is
/// deployed in every install (Community edition and Pro); what decides whether it ANSWERS is the installed licence, as the
/// updater verified it and recorded it in cfg.InstallState 'Licence' -- the same record and the same rule as the web app's
/// paid pages (SI.Management.Web: InstalledLicenceReader + LicenceDimension.Of + InstalledProLicence.Decide). So a licence
/// bought later switches the MCP server on at the updater's next licence check, and a licence that is removed or ends
/// (past its grace) switches it off -- no redeploy either way.
/// DENY BY DEFAULT: no record, a record that does not read, a database that does not answer = refused.
/// The MCP project references only this Core project, so the rule lives here as a PURE function of the record's JSON;
/// a test (McpLicenceGateTests) holds it to the web app's InstalledProLicence.Decide on the same records, so they cannot drift.
/// </summary>
public static class McpLicenceRule
{
    /// The one sentence a refused MCP call carries.
    public const string RefusalText = "The SecurityInsight MCP server (AI tools over your data) is part of SecurityInsight Pro: this installation has no valid Pro licence, so nothing was answered. Licences: https://portal.invardia.com/ > Licences, or info@invardia.com.";

    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'Licence';
""";

    /// PURE. Pro = the record reads, its state today is Valid / EndsSoon / InGrace (not Missing, Invalid, WrongTenant,
    /// NotYetValid, Expired), and its signed sku names a Pro (or MSP) edition. Anything else = not Pro.
    public static bool IsPro(string? recordJson, DateTime todayUtc)
    {
        if (string.IsNullOrWhiteSpace(recordJson)) return false;
        try
        {
            using var doc = JsonDocument.Parse(recordJson);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return false;
            string? S(string n) => o.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s ? s : null;
            DateTime? D(string n) => DateTime.TryParse(S(n), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            var status = S("status") ?? "Missing";
            if (status is "Missing" or "Invalid") return false;
            if (status is not ("Valid" or "Grace" or "Expired" or "NotYetValid")) return false;
            if (o.TryGetProperty("tenantOk", out var t) && t.ValueKind == JsonValueKind.False) return false;
            if (D("validTo") is not { } to) return false;
            var today = todayUtc.Date;
            if (D("validFrom") is { } from && today < from.Date) return false;
            var inForce = today <= to.Date || (D("graceUntil") is { } g && today <= g.Date);
            if (!inForce) return false;
            return EditionIsPro(S("sku"));
        }
        catch (JsonException) { return false; }
    }

    /// PURE. The engines' Get-SILicenceEdition rule: a sku naming msp as a word, or starting with Pro / Trial as a word.
    public static bool EditionIsPro(string? sku)
    {
        var s = (sku ?? "").Trim();
        return Regex.IsMatch(s, "(^|[^a-z])msp([^a-z]|$)", RegexOptions.IgnoreCase) || Regex.IsMatch(s, "^(pro|trial)([^a-z]|$)", RegexOptions.IgnoreCase);
    }
}

/// <summary>
/// The MCP server's licence check over the Pro database (<see cref="ISqlReader"/>). Kept for one minute (the licence is
/// verified nightly; a removed licence stops the MCP server within a minute of the record changing). Never throws:
/// what cannot be read is not Pro.
/// </summary>
public sealed class McpLicenceGate(ISqlReader sql, TimeProvider? clock = null)
{
    public static readonly TimeSpan Keep = TimeSpan.FromMinutes(1);
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private (bool Pro, DateTimeOffset At)? _known;
    private readonly object _lock = new();

    public async Task<bool> IsProAsync(CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        lock (_lock) { if (_known is { } k && now - k.At < Keep) return k.Pro; }
        var pro = false;
        try
        {
            var rows = await sql.QueryAsync(McpLicenceRule.Sql, new Dictionary<string, object?>(), ct);
            var row = rows.FirstOrDefault(r => r.ContainsKey("Value"));
            pro = row is not null && McpLicenceRule.IsPro(Cell.Str(row, "Value"), now.UtcDateTime);
        }
        catch (OperationCanceledException) { throw; }
        catch { pro = false; }   // deny by default: a database that does not answer is not Pro
        lock (_lock) { _known = (pro, now); }
        return pro;
    }

    /// The JSON-RPC error body a refused MCP call gets (HTTP 403): a client shows the message as the tool error.
    public static string RefusalBody() => JsonSerializer.Serialize(new
    {
        jsonrpc = "2.0",
        id = (object?)null,
        error = new { code = -32001, message = McpLicenceRule.RefusalText, data = new { pro = true, feature = "mcp" } },
    });
}
