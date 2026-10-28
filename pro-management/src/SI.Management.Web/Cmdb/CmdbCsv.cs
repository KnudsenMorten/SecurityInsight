using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SI.Management.Web.Cmdb;

public sealed record CmdbCsvIssue(int Line, string Message)
{
    public override string ToString() => Line > 0 ? $"line {Line}: {Message}" : Message;
}

/// One service row of a CMDB.csv (the v2.2 format).
public sealed record CmdbCsvService(int Line, string Number, string Name, string? DataSensitivity, string? Criticality, string? Owner, string? OwnerMail,
    string? Environment, string? Description, string? Department, IReadOnlyDictionary<string, string> Extra);

/// One membership row: service cmdbID -> an asset (its key, or its name).
public sealed record CmdbCsvLink(int Line, string Number, string? AssetKey, string? AssetName);

public sealed record CmdbCsvResult(IReadOnlyList<CmdbCsvService> Services, IReadOnlyList<CmdbCsvLink> Links, IReadOnlyList<CmdbCsvIssue> Errors,
    IReadOnlyList<CmdbCsvIssue> Warnings)
{
    public bool Ok => Errors.Count == 0;
}

/// <summary>
/// THE CMDB.csv READER (#256), C# side. The v2.2 format: a header line, ';'-separated (',' accepted when the header has
/// no ';'), quoted fields with "" escapes. Columns, matched without regard to case:
///   cmdbID (required), cmdbName (required), DataSensitivity, Criticality, Owner, OwnerMail, Environment, Description,
///   Department -- every OTHER column is kept verbatim (ExtraJson), exactly as v2.2 surfaced every column.
/// The optional memberships file: cmdbID + AssetKey and/or AssetName.
/// ERRORS refuse the whole import (an external CMDB is imported as a snapshot, so a half-read file would retire services
/// that are not gone); WARNINGS do not. Every message names its line. engine\asset-cmdb\_shared\SI-CmdbHome.ps1
/// (ConvertFrom-SICmdbCsv) is the PowerShell twin; pro-management\tests\fixtures\cmdb-csv-cases.json holds the cases
/// BOTH must pass, so the scheduled path and the upload accept and refuse the same files.
/// </summary>
public static class CmdbCsv
{
    public const int MaxRows = 20000;
    public const long MaxBytes = 5 * 1024 * 1024;
    private static readonly string[] Known = ["cmdbID", "cmdbName", "DataSensitivity", "Criticality", "Owner", "OwnerMail", "Environment", "Description", "Department"];

    /// Splits CSV text into records: (line the record starts on, fields). Quoted fields may hold the delimiter, quotes ("")
    /// and line breaks. Returns the problem when a quote is never closed.
    public static (List<(int Line, List<string> Fields)> Rows, CmdbCsvIssue? Problem) Split(string text, char delimiter)
    {
        var rows = new List<(int, List<string>)>();
        var fields = new List<string>();
        var sb = new StringBuilder();
        int line = 1, start = 1;
        bool quoted = false, any = false;
        for (int i = 0; i < text.Length; i++)
        {
            var ch = text[i];
            if (quoted)
            {
                if (ch == '"')
                {
                    if (i + 1 < text.Length && text[i + 1] == '"') { sb.Append('"'); i++; }
                    else quoted = false;
                }
                else { if (ch == '\n') line++; sb.Append(ch); }
                continue;
            }
            if (ch == '"' && sb.ToString().Trim().Length == 0) { sb.Clear(); quoted = true; any = true; continue; }
            if (ch == delimiter) { fields.Add(sb.ToString()); sb.Clear(); any = true; continue; }
            if (ch == '\r') continue;
            if (ch == '\n')
            {
                fields.Add(sb.ToString()); sb.Clear();
                if (any || fields.Any(f => f.Length > 0)) rows.Add((start, fields));
                fields = new List<string>(); any = false; line++; start = line;
                continue;
            }
            sb.Append(ch);
            any = true;
        }
        if (quoted) return (rows, new CmdbCsvIssue(start, "a quoted value is never closed"));
        fields.Add(sb.ToString());
        if (any || fields.Any(f => f.Length > 0)) rows.Add((start, fields));
        return (rows, null);
    }

    public static string Strip(string text) => text.Length > 0 && text[0] == '﻿' ? text[1..] : text;

    public static char DelimiterOf(string text)
    {
        var nl = text.IndexOf('\n');
        var header = nl < 0 ? text : text[..nl];
        return header.Contains(';') ? ';' : header.Contains(',') ? ',' : ';';
    }

    /// Reads a services file (CMDB.csv) and, optionally, a memberships file. Never throws on content.
    public static CmdbCsvResult Parse(string servicesText, string? membersText = null)
    {
        var errors = new List<CmdbCsvIssue>();
        var warnings = new List<CmdbCsvIssue>();
        var services = new List<CmdbCsvService>();
        var links = new List<CmdbCsvLink>();
        ParseServices(Strip(servicesText ?? ""), services, errors, warnings);
        if (!string.IsNullOrEmpty(membersText)) ParseMembers(Strip(membersText), services, links, errors, warnings);
        return new CmdbCsvResult(services, links, errors, warnings);
    }

    private static void ParseServices(string text, List<CmdbCsvService> services, List<CmdbCsvIssue> errors, List<CmdbCsvIssue> warnings)
    {
        var (rows, problem) = Split(text, DelimiterOf(text));
        if (problem is not null) { errors.Add(problem); return; }
        if (rows.Count == 0) { errors.Add(new CmdbCsvIssue(0, "the file is empty -- it needs a header line (cmdbID;cmdbName;...) and one line per service")); return; }
        var header = rows[0].Fields.Select(h => h.Trim()).ToList();
        if (!Header(header, rows[0].Line, errors)) return;
        int Col(string name) => header.FindIndex(h => string.Equals(h, name, StringComparison.OrdinalIgnoreCase));
        if (Col("cmdbID") < 0 || Col("cmdbName") < 0) { errors.Add(new CmdbCsvIssue(rows[0].Line, "the header needs the columns cmdbID and cmdbName")); return; }
        if (rows.Count - 1 > MaxRows) { errors.Add(new CmdbCsvIssue(0, $"the file holds {rows.Count - 1} services; at most {MaxRows} are read")); return; }
        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var (line, raw) in rows.Skip(1))
        {
            if (raw.Count != header.Count) { errors.Add(new CmdbCsvIssue(line, $"has {raw.Count} values, the header has {header.Count}")); continue; }
            var f = raw.Select(v => v.Trim()).ToList();
            string? V(string name) { var i = Col(name); return i < 0 || f[i].Length == 0 ? null : f[i]; }
            var id = V("cmdbID"); var name = V("cmdbName");
            var before = errors.Count;
            if (id is null) errors.Add(new CmdbCsvIssue(line, "cmdbID is empty"));
            else if (id.Length > CmdbVocabulary.MaxNumber) errors.Add(new CmdbCsvIssue(line, $"cmdbID is longer than {CmdbVocabulary.MaxNumber} characters"));
            else if (id.Any(char.IsControl)) errors.Add(new CmdbCsvIssue(line, "cmdbID contains a control character"));
            else if (seen.TryGetValue(id, out var first)) errors.Add(new CmdbCsvIssue(line, $"cmdbID '{id}' is already on line {first}"));
            if (name is null) errors.Add(new CmdbCsvIssue(line, "cmdbName is empty"));
            else if (name.Length > CmdbVocabulary.MaxName) errors.Add(new CmdbCsvIssue(line, $"cmdbName is longer than {CmdbVocabulary.MaxName} characters"));
            void Len(string col, int max) { if (V(col) is { } v && v.Length > max) errors.Add(new CmdbCsvIssue(line, $"{col} is longer than {max} characters")); }
            Len("Owner", CmdbVocabulary.MaxOwner); Len("Environment", CmdbVocabulary.MaxEnvironment); Len("Description", CmdbVocabulary.MaxDescription); Len("Department", CmdbVocabulary.MaxDepartment);
            if (V("OwnerMail") is { } mail && !CmdbVocabulary.IsMail(mail)) errors.Add(new CmdbCsvIssue(line, $"OwnerMail '{mail}' is not an e-mail address"));
            var extra = new SortedDictionary<string, string>(StringComparer.Ordinal);
            for (int i = 0; i < header.Count; i++)
            {
                if (Known.Contains(header[i], StringComparer.OrdinalIgnoreCase) || f[i].Length == 0) continue;
                if (f[i].Length > CmdbVocabulary.MaxExtra) errors.Add(new CmdbCsvIssue(line, $"{header[i]} is longer than {CmdbVocabulary.MaxExtra} characters"));
                else extra[header[i]] = f[i];
            }
            var crit = CmdbVocabulary.Canonical(CmdbVocabulary.Criticalities, V("Criticality"));
            var sens = CmdbVocabulary.Canonical(CmdbVocabulary.Sensitivities, V("DataSensitivity"));
            if (errors.Count > before) continue;
            if (crit is not null && !CmdbVocabulary.Criticalities.Contains(crit))
                warnings.Add(new CmdbCsvIssue(line, $"Criticality '{crit}' is kept as written; risk weighting understands {string.Join(", ", CmdbVocabulary.Criticalities)}"));
            if (sens is not null && !CmdbVocabulary.Sensitivities.Contains(sens))
                warnings.Add(new CmdbCsvIssue(line, $"DataSensitivity '{sens}' is kept as written; risk weighting understands {string.Join(", ", CmdbVocabulary.Sensitivities)}"));
            seen[id!] = line;
            services.Add(new CmdbCsvService(line, id!, name!, sens, crit, V("Owner"), V("OwnerMail"), V("Environment"), V("Description"), V("Department"), extra));
        }
        if (services.Count == 0 && errors.Count == 0) errors.Add(new CmdbCsvIssue(0, "the file holds no service"));
    }

    private static bool Header(List<string> header, int line, List<CmdbCsvIssue> errors)
    {
        var ok = true;
        if (header.Any(h => h.Length == 0)) { errors.Add(new CmdbCsvIssue(line, "a column in the header has no name")); ok = false; }
        foreach (var d in header.Where(h => h.Length > 0).GroupBy(h => h, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
        { errors.Add(new CmdbCsvIssue(line, $"the column '{d.Key}' is in the header twice")); ok = false; }
        return ok;
    }

    private static void ParseMembers(string text, List<CmdbCsvService> services, List<CmdbCsvLink> links, List<CmdbCsvIssue> errors, List<CmdbCsvIssue> warnings)
    {
        var (rows, problem) = Split(text, DelimiterOf(text));
        if (problem is not null) { errors.Add(problem with { Message = "memberships: " + problem.Message }); return; }
        if (rows.Count == 0) { errors.Add(new CmdbCsvIssue(0, "memberships: the file is empty -- it needs a header line (cmdbID;AssetName or cmdbID;AssetKey)")); return; }
        var header = rows[0].Fields.Select(h => h.Trim()).ToList();
        if (!Header(header, rows[0].Line, errors)) return;
        int Col(string name) => header.FindIndex(h => string.Equals(h, name, StringComparison.OrdinalIgnoreCase));
        if (Col("cmdbID") < 0 || (Col("AssetKey") < 0 && Col("AssetName") < 0)) { errors.Add(new CmdbCsvIssue(rows[0].Line, "memberships: the header needs cmdbID and AssetKey or AssetName")); return; }
        if (rows.Count - 1 > MaxRows * 10) { errors.Add(new CmdbCsvIssue(0, $"memberships: at most {MaxRows * 10} lines are read")); return; }
        var known = services.Select(s => s.Number).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (line, raw) in rows.Skip(1))
        {
            if (raw.Count != header.Count) { errors.Add(new CmdbCsvIssue(line, $"memberships: has {raw.Count} values, the header has {header.Count}")); continue; }
            string? V(string name) { var i = Col(name); var v = i < 0 ? "" : raw[i].Trim(); return v.Length == 0 ? null : v; }
            var id = V("cmdbID"); var key = V("AssetKey"); var name = V("AssetName");
            if (id is null) { errors.Add(new CmdbCsvIssue(line, "memberships: cmdbID is empty")); continue; }
            if (key is null && name is null) { errors.Add(new CmdbCsvIssue(line, "memberships: neither AssetKey nor AssetName is given")); continue; }
            if ((key?.Length ?? 0) > 400 || (name?.Length ?? 0) > 400) { errors.Add(new CmdbCsvIssue(line, "memberships: the asset is longer than 400 characters")); continue; }
            if (!known.Contains(id)) { errors.Add(new CmdbCsvIssue(line, $"memberships: no service with cmdbID '{id}' in the services file")); continue; }
            if (!seen.Add(id + "\u0001" + (key ?? "") + "\u0001" + (name ?? ""))) { warnings.Add(new CmdbCsvIssue(line, "memberships: the same link is listed twice -- read once")); continue; }
            links.Add(new CmdbCsvLink(line, services.First(s => string.Equals(s.Number, id, StringComparison.OrdinalIgnoreCase)).Number, key, name));
        }
    }

    /// The import the procedure cfg.CmdbImportSnapshot takes (the PowerShell import builds the same JSON).
    public static string ToPayload(CmdbCsvResult r, bool linksIncluded) => JsonSerializer.Serialize(new
    {
        services = r.Services.Select(s => new
        {
            number = s.Number, externalId = s.Number, name = s.Name, description = s.Description, owner = s.Owner, ownerMail = s.OwnerMail,
            criticality = s.Criticality, dataSensitivity = s.DataSensitivity, environment = s.Environment, department = s.Department, extra = s.Extra,
        }),
        links = r.Links.Select(l => new { number = l.Number, assetKey = l.AssetKey, assetName = l.AssetName }),
        linksIncluded,
    });

    public static string Sha256(params string?[] texts)
    {
        var bytes = Encoding.UTF8.GetBytes(string.Join("\n", texts.Where(t => t is not null)));
        return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    }
}
