using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Settings;

/// One field as a card's Save posts it: the value text (a list: one item per line), whether Reset was asked for, the
/// RowVersion the page read (empty = no row then) and the scope the field edits.
public sealed record FieldPost(string Name, string? Value, bool Reset, string? Version, string? Scope);

/// <summary>
/// A card's Save, field by field: what the posted value means for the stored row -- nothing (the value is what applies
/// already), a Set or a Reset -- before the settings writer validates and writes it. The page's rules live here so they
/// can be tested without a browser:
///   - blank = the default: a blank text or number field (or an emptied list whose default is empty) removes the row;
///   - a value equal to what applies now writes nothing, so saving a card changes only the fields that changed;
///   - a list of mail addresses refuses an entry that is not an address (the engines read the list as it is stored);
///   - a secret is a Key Vault secret NAME, never a value (the writer refuses anything else);
///   - the CMDB source is changed only on its own page.
/// </summary>
public static class SettingsForm
{
    /// The reason the change log records for a change saved on the Settings page (the reason is optional there).
    public const string Reason = "changed in Settings";

    /// Loose on purpose: one @, something on both sides, a dot in the domain, no spaces or list separators.
    private static readonly Regex Mail = new(@"^[^@\s<>,;""]+@[^@\s<>,;""]+\.[^@\s<>,;""]+$", RegexOptions.CultureInvariant);

    public static bool IsMailAddress(string s) => Mail.IsMatch(s.Trim());

    /// The items a list field posted: one per line; a mail list also splits on comma and semicolon.
    public static IReadOnlyList<string> SplitItems(CatalogSetting s, string? text) =>
        (text ?? "").Split(s.IsMailList ? new[] { '\n', '\r', ',', ';' } : new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(x => x.Length > 0).ToList();

    /// <summary>The change one posted field asks for: (null, null) when nothing changes, (write, null) to write, or
    /// (null, reason) when the field is refused before it reaches the writer.</summary>
    public static (SettingWrite? Write, string? Error) Plan(CatalogSetting s, FieldPost p, SettingRow? current)
    {
        long? expected = long.TryParse(p.Version, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
        var scope = string.IsNullOrWhiteSpace(p.Scope) ? s.DefaultScope : p.Scope!.Trim();
        if (!s.AllowedScopes().Contains(scope, StringComparer.Ordinal) && current is null)
            return (null, $"'{scope}' is not a scope of this setting");
        SettingWrite Set(JsonElement? value, string? kv) => new(s.Name, scope, "Set", value, kv, expected, Reason);
        (SettingWrite?, string?) ResetOrNothing() => current is null && expected is null ? (null, null) : (new SettingWrite(s.Name, scope, "Reset", null, null, expected, Reason), null);

        if (SettingsLayout.EditorOf(s, current) == EditorKind.Elsewhere)
            return string.Equals(s.Name, SI.Management.Web.Cmdb.CmdbSources.Setting, StringComparison.OrdinalIgnoreCase)
                ? (null, "the CMDB source is changed on the CMDB source page, which says what the switch does first")
                : (null, "this value is changed on its own Edit page");
        if (p.Reset) return ResetOrNothing();

        if (s.Secret)
        {
            var kv = (p.Value ?? "").Trim();
            if (kv.Length == 0) return ResetOrNothing();
            if (current is not null && string.Equals(current.KeyVaultSecretName, kv, StringComparison.Ordinal) && current.ValueJson is null) return (null, null);
            return (Set(null, kv), null);
        }

        if (s.Type == "list")
        {
            var items = SplitItems(s, p.Value);
            if (s.IsMailList)
            {
                var bad = items.Where(i => !IsMailAddress(i)).ToList();
                if (bad.Count > 0) return (null, $"'{bad[0]}' is not an e-mail address");
            }
            var now = SettingsLayout.Items(current is not null ? current.ValueJson : SettingsLayout.DefaultRaw(s));
            if (items.SequenceEqual(now, StringComparer.Ordinal)) return (null, null);
            // emptied, and the default is empty too: remove the row so the default applies
            if (items.Count == 0 && SettingsLayout.Items(SettingsLayout.DefaultRaw(s)).Count == 0) return ResetOrNothing();
            return (Set(JsonSerializer.SerializeToElement(items), null), null);
        }

        var text = p.Value ?? "";
        if (text.Trim().Length == 0 && s.Type != "bool") return ResetOrNothing();
        if (s.Type == "bool" && text.Trim().Length == 0) return ResetOrNothing();   // Not set on a three-way switch
        var value = SettingJson.FromForm(s, s.Type is "int" or "number" or "enum" or "bool" ? text.Trim() : text);
        var stored = SettingJson.ToStoredText(value);
        var applies = current is not null ? current.ValueJson : SettingsLayout.DefaultRaw(s);
        if (applies is not null && SettingsDiff.JsonEquals(applies, stored)) return (null, null);
        return (Set(value, null), null);
    }

    /// The value a field shows after a save (what the page puts back into the field).
    public static string ShownAfter(CatalogSetting s, PreparedChange p) =>
        p.Change.Action == "Reset" ? (s.Secret ? "" : SettingsLayout.DefaultText(s))
        : s.Secret ? p.KeyVaultSecretName ?? "" : SettingJson.ToFormText(p.ValueJson);

    /// A value as the audit trail and the result show it: a Key Vault secret by its name, else the stored JSON.
    public static string Display(string? valueJson, string? kv) => kv is not null ? "keyvault:" + kv : valueJson ?? "(default)";
}
