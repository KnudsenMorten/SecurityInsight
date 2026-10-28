using System.Globalization;
using System.Text.Json.Serialization;

namespace SI.Management.Web.Settings;

/// "More info" of one setting (framework SETTING-INFO-1): what it does, what happens ON / OFF (or when changed), risk and
/// reversibility, what it requires, the default, the recommendation and its page on invardia.com -- plus, for a destructive
/// or security-reducing setting, the value that needs a confirmation (on | off | lower) and the words shown in it.
/// The catalog's settings carry it (composed by engine\pro-settings\Build-SISettingsCatalog.ps1 from the help words and
/// config\settings.info.locked.json); the web app's own settings get it from <see cref="SettingInfoComposer"/>.
public sealed class SettingInfo
{
    [JsonPropertyName("what")] public string? What { get; init; }
    [JsonPropertyName("whenOn")] public string? WhenOn { get; init; }
    [JsonPropertyName("whenOff")] public string? WhenOff { get; init; }
    [JsonPropertyName("whenChanged")] public string? WhenChanged { get; init; }
    [JsonPropertyName("risk")] public string? Risk { get; init; }
    [JsonPropertyName("requires")] public string? Requires { get; init; }
    [JsonPropertyName("default")] public string? Default { get; init; }
    [JsonPropertyName("recommended")] public string? Recommended { get; init; }
    [JsonPropertyName("docUrl")] public string? DocUrl { get; init; }
    /// The value that needs a confirmation: "on", "off" or "lower" (a smaller number, or a number where none was set).
    [JsonPropertyName("confirmWhen")] public string? ConfirmWhen { get; init; }
    /// The words shown in that confirmation.
    [JsonPropertyName("confirm")] public string? Confirm { get; init; }

    public const string DocBase = "https://invardia.com/docs/si/settings/";
    public static string DocUrlOf(string name) => DocBase + name + "/";

    /// The fields this setting's info must carry; missing ones make <see cref="Gaps"/> non-empty (the test fails on any).
    public IEnumerable<string> Gaps(string type)
    {
        var need = new List<(string Field, string? Value)> { ("what", What), ("risk", Risk), ("requires", Requires), ("default", Default), ("recommended", Recommended), ("docUrl", DocUrl) };
        if (type == "bool") { need.Add(("whenOn", WhenOn)); need.Add(("whenOff", WhenOff)); } else { need.Add(("whenChanged", WhenChanged)); }
        foreach (var (f, v) in need) { if (string.IsNullOrWhiteSpace(v)) { yield return f; } }
        if (!string.IsNullOrWhiteSpace(ConfirmWhen))
        {
            if (ConfirmWhen is not ("on" or "off" or "lower")) { yield return "confirmWhen"; }
            if (string.IsNullOrWhiteSpace(Confirm)) { yield return "confirm"; }
        }
    }

    /// True when changing the value from <paramref name="current"/> to <paramref name="next"/> (the field's text: "true" /
    /// "false" / a number / "" = not set) moves INTO the risky value -- the page then shows <see cref="Confirm"/> first.
    public bool NeedsConfirmation(string? current, string? next)
    {
        current = (current ?? "").Trim(); next = (next ?? "").Trim();
        if (string.Equals(current, next, StringComparison.OrdinalIgnoreCase)) { return false; }
        switch (ConfirmWhen)
        {
            case "on": return string.Equals(next, "true", StringComparison.OrdinalIgnoreCase);
            case "off": return string.Equals(next, "false", StringComparison.OrdinalIgnoreCase);
            case "lower":
                if (!double.TryParse(next, NumberStyles.Float, CultureInfo.InvariantCulture, out var n)) { return false; }
                if (!double.TryParse(current, NumberStyles.Float, CultureInfo.InvariantCulture, out var c)) { return true; }   // not set (kept forever) -> any number is lower
                return n < c;
            default: return false;
        }
    }
}

/// The info of the web app's OWN settings (they are defined in code, not in the catalog): composed from their words by the
/// same rules as the catalog's builder, with the few risky ones authored here.
public static class SettingInfoComposer
{
    private const string WebRisk = "It changes how the web app shows, links or asks; no collected data is changed. Reversible at once.";

    private static readonly Dictionary<string, (string ConfirmWhen, string Risk, string Recommended)> Authored = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SIWeb_MagicLinksEnabled"] = ("on", "A link in an e-mail then opens one read-only page WITHOUT a sign-in: Conditional Access and MFA do not apply to it, and anyone the mail is forwarded to can open it until it expires (once). Reversible at once: links already sent stop working when it is turned off.", "Off, unless your organisation accepts sign-in-free read-only links."),
        ["SIWeb_ExemptionAllowOpenEnded"] = ("on", "Exemptions that never expire can be requested: a finding can then be hidden from the management numbers for good (it still comes up in every monthly review). Reversible for new requests; open-ended exemptions already granted stay until reviewed.", "Off, unless your policy accepts permanent exemptions."),
        ["SIWeb_ConfigSecondPerson"] = ("off", "Releasing a guard and restoring a configuration backup no longer need a second SuperAdmin: one person can do them alone (still audited). Reversible at once.", "On where your change process needs four eyes; off is the default."),
    };

    /// The setting's info: its own (catalog) when present, else composed.
    public static SettingInfo For(CatalogSetting s) => s.Info ?? Compose(s);

    public static SettingInfo Compose(CatalogSetting s)
    {
        Authored.TryGetValue(s.Name, out var a);
        string? on = null, off = null;
        if (s.Type == "bool")
        {
            (on, off) = Split(s.Effect);
            var defState = (s.DefaultText ?? "").TrimStart().StartsWith("On", StringComparison.OrdinalIgnoreCase) ? "on"
                : (s.DefaultText ?? "").TrimStart().StartsWith("Off", StringComparison.OrdinalIgnoreCase) ? "off" : "";
            if (string.IsNullOrWhiteSpace(on) && defState == "on") { on = StripState(s.DefaultText); }
            if (string.IsNullOrWhiteSpace(off) && defState == "off") { off = StripState(s.DefaultText); }
            if (string.IsNullOrWhiteSpace(on) && !string.IsNullOrWhiteSpace(s.Effect) && defState != "on") { on = s.Effect; }
            if (string.IsNullOrWhiteSpace(off) && !string.IsNullOrWhiteSpace(s.Effect) && defState == "on") { off = s.Effect; }
            if (string.IsNullOrWhiteSpace(off) && defState == "" && !string.IsNullOrWhiteSpace(s.DefaultText)) { off = s.DefaultText; }
            if (string.IsNullOrWhiteSpace(on)) { on = defState == "on" ? "On is the default: it works as described under \"What it does\"." : "It works as described under \"What it does\"."; }
            if (string.IsNullOrWhiteSpace(off)) { off = defState == "off" ? "Off is the default: none of what \"On\" describes happens." : "None of what \"On\" describes happens."; }
        }
        var requires = new List<string>();
        if (!string.IsNullOrWhiteSpace(s.Needs))
        {
            var neg = s.Needs!.StartsWith('!');
            requires.Add($"Works only while \"{s.Needs.TrimStart('!')}\" is {(neg ? "off" : "on")}.");
        }
        if (s.Edition == "pro") { requires.Add("A SecurityInsight Pro licence."); }
        if (s.Secret) { requires.Add("Kept in the install's Key Vault."); }
        if (requires.Count == 0) { requires.Add("Nothing else."); }
        var risk = a.Risk ?? (s.WebOnly ? WebRisk : "Low: it changes how the jobs that read it behave from their next run; nothing already collected or sent is changed. Reversible: change it back.");
        var confirmWhen = a.ConfirmWhen;
        string? confirm = null;
        if (confirmWhen is not null) { confirm = (confirmWhen == "on" ? on : confirmWhen == "off" ? off : null) is { Length: > 0 } t && t != risk ? t + " " + risk : risk; }
        return new SettingInfo
        {
            What = s.PurposeText ?? s.Description ?? s.Title,
            WhenOn = s.Type == "bool" ? on : null,
            WhenOff = s.Type == "bool" ? off : null,
            WhenChanged = s.Type == "bool" ? null : (string.IsNullOrWhiteSpace(s.Effect) ? "The new value applies at once in the web app." : s.Effect),
            Risk = risk,
            Requires = string.Join(" ", requires),
            Default = string.IsNullOrWhiteSpace(s.DefaultText) ? s.DefaultPlain : s.DefaultText,
            Recommended = a.Recommended ?? ("Keep the default" + (string.IsNullOrWhiteSpace(s.WhenToChange) ? "." : ". Change it when: " + s.WhenToChange)),
            DocUrl = SettingInfo.DocUrlOf(s.Name),
            ConfirmWhen = confirmWhen,
            Confirm = confirm,
        };
    }

    /// "Off: ... On: ..." (either order, capitalised, sentence-starting) -> the two parts; a part not present is null.
    public static (string? On, string? Off) Split(string? effect)
    {
        if (string.IsNullOrWhiteSpace(effect)) { return (null, null); }
        var ms = System.Text.RegularExpressions.Regex.Matches(effect, @"(?<![A-Za-z])(On|Off):\s*");
        string? on = null, off = null;
        for (var i = 0; i < ms.Count; i++)
        {
            var start = ms[i].Index + ms[i].Length;
            var end = i + 1 < ms.Count ? ms[i + 1].Index : effect.Length;
            var text = effect[start..end].Trim();
            if (text.Length == 0) { continue; }
            if (ms[i].Groups[1].Value == "On") { on = text; } else { off = text; }
        }
        return (on, off);
    }

    private static string StripState(string? text) =>
        System.Text.RegularExpressions.Regex.Replace(text ?? "", @"^\s*(On|Off|Not set)\s*[:,.;-]?\s*", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim();
}
