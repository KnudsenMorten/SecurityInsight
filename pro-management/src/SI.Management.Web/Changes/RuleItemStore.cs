using System.Collections.Concurrent;
using System.Globalization;
using System.Text.RegularExpressions;
using SI.Management.Web.Settings;
using YamlDotNet.Serialization;

namespace SI.Management.Web.Changes;

public enum RuleOrigin { Vendor, Changed, Off, Yours }

/// What the rules grid shows of a rule (read from its text once and cached by text).
public sealed record RuleSummary(string AppliesTo, string Purpose, string Category, string Mode, IReadOnlyList<int> Tiers, int Detections, IReadOnlyList<string> Kinds);

/// <summary>
/// One asset-profiling rule as the next run applies it. Home = where the customer's state of it is kept (and where an
/// edit is written): 'document' when a cfg.Document rule exists for it (the Pro-1b home -- imported v2.2 custom rules,
/// tier board pins and switch-offs), else 'override' (cfg.ItemOverride). Version = that row's version (null = no row).
/// </summary>
public sealed record RuleEntry(string Key, RuleOrigin Origin, string? Body, string? VendorBody, string Home, long? Version, RuleSummary Summary,
    string? Source, DateTime? UpdatedAt, string? UpdatedBy, int? MovedToTier)
{
    public string Engine => Key[..Key.IndexOf('/')];
    public string Id => Key[(Key.IndexOf('/') + 1)..];
    /// The text the editor starts from: the customer's, else the vendor's.
    public string? EditBody => Body ?? VendorBody;
    /// #908: the customer's text still carries the shipped sample's '# SAMPLE / TEMPLATE' header -- the example copied as it
    /// was (on one install the IP-subnet sample made a network device a Tier 0 "Domain Controller"). Shown as a warning; the
    /// run keeps applying it. Same marker as the engine's Test-SIRuleSampleMarker.
    public bool IsShippedExample => IsSampleText(Body);
    public static bool IsSampleText(string? text) => !string.IsNullOrEmpty(text) && SampleMarker.IsMatch(text);
    private static readonly Regex SampleMarker = new(@"^[ \t]*#[ \t]*SAMPLE[ \t]*/[ \t]*TEMPLATE\b", RegexOptions.Multiline | RegexOptions.CultureInvariant);
    public const string ShippedExampleWarning = "This rule set is the shipped example -- review it. It still starts with the sample's '# SAMPLE / TEMPLATE' header: check every detection (example names, subnets, tiers), then remove that header line or remove the rule.";
}

public sealed record RuleCatalog(bool Schema, bool TemplatesPublished, IReadOnlyList<RuleEntry> Rules, IReadOnlyList<string> Notes)
{
    public RuleEntry? Find(string key) => Rules.FirstOrDefault(r => string.Equals(r.Key, key, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// The asset-profiling rules (enrichment / tier rules, v2.2's asset-profiling-enrichment\**\*.locked.yaml + *.custom.yaml
/// and the SI_EnrichmentDataRoot overlay) as Merge-SIProItems serves them to a run: the vendor's 'rule' templates, the
/// customer's cfg.ItemOverride rows (override | disable) and cfg.Document rules over them, plus the customer's own rules.
/// Nothing here writes: a change is staged (<see cref="RuleItemChanges"/>) and written on Review &amp; commit through
/// <see cref="IItemSource"/>. The materialiser writes every rule where the engine's own loader (Get-SIRuleSet) reads it.
/// </summary>
public sealed partial class RuleItemStore
{
    public const string Kind = ItemValidator.Rule;
    private static readonly ConcurrentDictionary<string, RuleSummary> Summaries = new(StringComparer.Ordinal);
    private readonly IItemSource _src;
    public RuleItemStore(IItemSource src) => _src = src;

    public async Task<RuleCatalog> LoadAsync(CancellationToken ct)
    {
        var set = await _src.LoadAsync(Kind, ct);
        if (!set.Schema) return new RuleCatalog(false, false, Array.Empty<RuleEntry>(), new[] { SqlItemSource.MissingSchemaMessage });
        var moves = await _src.LoadAsync("ruletier", ct);
        return Build(set, moves);
    }

    /// PURE. The merge (Merge-SIProItems for the 'rule' kind, with the cfg.Document rules beside it).
    public static RuleCatalog Build(ItemSet set, ItemSet? moves = null)
    {
        var notes = new List<string>();
        var moved = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in moves?.Overrides ?? Array.Empty<ItemOverrideRow2>())
            if (m.State == "override" && ItemOverrideRepository.TierOf(m.Body) is { } t) moved[m.Key] = t;
        var list = new List<RuleEntry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var t in set.Templates)
        {
            seen.Add(t.Key);
            var doc = set.Document(t.Key);
            var o = set.Override(t.Key);
            if (doc is not null)
            {
                var off = IsOff(doc.Body);
                list.Add(new RuleEntry(t.Key, off ? RuleOrigin.Off : RuleOrigin.Changed, off ? null : doc.Body, t.Retired ? null : t.Body, "document", doc.Version,
                    Summarise(off ? t.Body : doc.Body), t.Source, doc.UpdatedAt, doc.UpdatedBy, Moved(t.Key)));
                if (o is not null && o.State != "inherit") notes.Add($"{t.Key}: kept both as a settings document and as an item -- the run refuses the pair; reset one of them");
                continue;
            }
            if (o is { State: "override" })
            {
                list.Add(new RuleEntry(t.Key, RuleOrigin.Changed, o.Body, t.Retired ? null : t.Body, "override", o.Version, Summarise(o.Body ?? ""), t.Source, o.UpdatedAt, o.UpdatedBy, Moved(t.Key)));
                continue;
            }
            if (o is { State: "disable" })
            {
                list.Add(new RuleEntry(t.Key, RuleOrigin.Off, null, t.Body, "override", o.Version, Summarise(t.Body), t.Source, o.UpdatedAt, o.UpdatedBy, Moved(t.Key)));
                continue;
            }
            if (t.Retired) continue;
            list.Add(new RuleEntry(t.Key, RuleOrigin.Vendor, null, t.Body, "override", o?.Version, Summarise(t.Body), t.Source, null, null, Moved(t.Key)));
        }
        foreach (var d in set.Documents.Where(d => !seen.Contains(d.Key)))
        {
            seen.Add(d.Key);
            var off = IsOff(d.Body);
            list.Add(new RuleEntry(d.Key, off ? RuleOrigin.Off : RuleOrigin.Yours, off ? null : d.Body, null, "document", d.Version, Summarise(d.Body), null, d.UpdatedAt, d.UpdatedBy, Moved(d.Key)));
        }
        foreach (var o in set.Overrides.Where(o => !seen.Contains(o.Key) && o.State == "override"))
        {
            seen.Add(o.Key);
            list.Add(new RuleEntry(o.Key, RuleOrigin.Yours, o.Body, null, "override", o.Version, Summarise(o.Body ?? ""), null, o.UpdatedAt, o.UpdatedBy, Moved(o.Key)));
        }
        var published = set.Templates.Count > 0;
        if (!published) notes.Add("no vendor rule templates are published in this database yet: the run reads the vendor's rules from the installation and applies the rules below over them. Your own rules and changes can be made here; the vendor's rules appear once the templates are published (Templates > Releases).");
        return new RuleCatalog(true, published, list.OrderBy(r => r.Key, StringComparer.OrdinalIgnoreCase).ToList(), notes);

        int? Moved(string key) => moved.TryGetValue(key, out var v) ? v : null;
    }

    [GeneratedRegex(@"(?m)^mode\s*:\s*['""]?disable\b", RegexOptions.IgnoreCase)] private static partial Regex DisableMode();
    /// The materialiser's own test for "this rule is turned off" (Export-SIProConfig).
    [GeneratedRegex(@"(?m)^(\s+Tier\s*:\s*)['""]?\d+['""]?")] public static partial Regex TierLine();

    public static bool IsOff(string body) => DisableMode().IsMatch(body);

    /// The grid's columns of a rule text (cached by text; a text that does not parse shows only its id).
    public static RuleSummary Summarise(string body) => Summaries.GetOrAdd(body, b =>
    {
        try
        {
            if (new DeserializerBuilder().Build().Deserialize<object>(b) is not IDictionary<object, object> m) return Empty;
            string S(string k) => ItemValidator.Get(m, k) switch { null => "", IEnumerable<object> l when ItemValidator.Get(m, k) is not string => string.Join(", ", l), var x => x.ToString() ?? "" };
            var tiers = new SortedSet<int>(); var kinds = new SortedSet<string>(StringComparer.Ordinal); var n = 0;
            if (ItemValidator.Get(m, "detections") is IList<object> ds)
                foreach (var d in ds.OfType<IDictionary<object, object>>())
                {
                    n++;
                    if (ItemValidator.Get(d, "set") is IDictionary<object, object> s && ItemValidator.Get(s, "Tier") is string ts && int.TryParse(ts, NumberStyles.Integer, CultureInfo.InvariantCulture, out var t)) tiers.Add(t);
                    if (ItemValidator.Get(d, "detect") is IDictionary<object, object> dt)
                        foreach (var l in new[] { ItemValidator.Get(dt, "any"), ItemValidator.Get(dt, "all") }.OfType<IList<object>>())
                            foreach (var c in l.OfType<IDictionary<object, object>>()) if (ItemValidator.Get(c, "kind") is string k) kinds.Add(k);
                }
            return new RuleSummary(S("appliesTo"), S("purpose"), S("category"), S("mode"), tiers.ToList(), n, kinds.ToList());
        }
        catch (Exception ex) when (ex is YamlDotNet.Core.YamlException or InvalidOperationException) { return Empty; }
    });

    private static readonly RuleSummary Empty = new("", "", "", "", Array.Empty<int>(), 0, Array.Empty<string>());

    /// <summary>
    /// The write an action on a rule makes. save = the customer's text (an override of a vendor rule, or their own rule);
    /// off = a vendor rule turned off; reset = back to the vendor's rule (the customer's row removed); remove = the
    /// customer's own rule removed. Null + why when the action does not apply.
    /// </summary>
    public static (ItemWrite? Write, string? Why) WriteFor(RuleCatalog cat, string key, string action, string? body)
    {
        var e = cat.Find(key);
        var isVendor = e?.VendorBody is not null;
        switch (action)
        {
            case "save":
                if (e is null) return (new ItemWrite(Kind, key, "override", "override", body, null), null);
                return (new ItemWrite(Kind, e.Key, e.Home, "override", body, e.Version), null);
            case "off":
                if (e is null || !isVendor) return (null, "only a vendor rule can be turned off -- remove your own rule instead");
                if (e.Origin == RuleOrigin.Off) return (null, "this rule is already turned off");
                return e.Home == "document"
                    ? (new ItemWrite(Kind, e.Key, "document", "override", RuleTemplates.Disable(e.Key), e.Version), null)
                    : (new ItemWrite(Kind, e.Key, "override", "disable", null, e.Version), null);
            case "reset":
            case "remove":
                if (action == "reset" && e is not null && !isVendor) return (null, "this is your own rule -- remove it instead");
                if (action == "remove" && isVendor) return (null, "a vendor rule cannot be removed -- turn it off, or reset it to the vendor's");
                if (e is null || e.Version is null) return (null, action == "reset" ? "this rule is the vendor's as it is -- nothing to reset" : "there is nothing of yours to remove");
                return (new ItemWrite(Kind, e.Key, e.Home, "inherit", null, e.Version), null);
            default:
                return (null, $"unknown action '{action}'");
        }
    }

    /// The reasons a rule text cannot be stored for this key (empty = it can): Test-SIProItem's rules -- and, for a rule
    /// kept as a settings document, Test-SIProDocument's -- plus the tier board: a rule moved to another tier must set a
    /// Tier (the materialiser moves every Tier line it finds, and stops the run when there is none).
    public static IReadOnlyList<string> Problems(RuleCatalog cat, string key, string body)
    {
        var e = cat.Find(key);
        var why = new List<string>(ItemValidator.Validate(Kind, key, body));
        if (e?.Home == "document") foreach (var w in DocumentValidator.Validate("rule", e.Key, body, Array.Empty<string>())) if (!why.Contains(w)) why.Add(w);
        if (why.Count == 0 && e?.MovedToTier is { } t && !IsOff(body) && !TierLine().IsMatch(body))
            why.Add($"this rule is moved to Tier {t.ToString(CultureInfo.InvariantCulture)} on the tier board, so it must set a Tier -- or put it back in its own tiers there first");
        return why;
    }
}

/// <summary>
/// The rules editor's change through THE staging (Review &amp; commit): one staged change = one rule (save / off / reset
/// / remove) with the version of its row when it was staged. Review shows the text in force and the text after; the
/// commit validates again and writes it in one transaction with its cfg.ChangeLog row, refused as stale when the rule
/// changed meanwhile.
/// </summary>
public sealed class RuleItemChanges : IStagedChangeHandler
{
    public const string ChangeKind = "rule-edit";
    private readonly RuleItemStore _store;
    private readonly IItemSource _src;
    public RuleItemChanges(RuleItemStore store, IItemSource src) { _store = store; _src = src; }

    public bool Handles(string kind) => kind == ChangeKind;

    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewAsync(string key, string action, string? body, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        var cat = await _store.LoadAsync(ct);
        if (!cat.Schema) return (null, new[] { SqlItemSource.MissingSchemaMessage });
        var (w, why) = RuleItemStore.WriteFor(cat, key, action, body);
        if (w is null) return (null, new[] { why! });
        if (w.State == "override")
        {
            var p = RuleItemStore.Problems(cat, w.Key, w.Body ?? "");
            if (p.Count > 0) return (null, p);
            var e = cat.Find(w.Key);
            if (e?.Body is { } now && now.Replace("\r\n", "\n").Trim() == (w.Body ?? "").Replace("\r\n", "\n").Trim()) return (null, new[] { "nothing changed -- this is the text in force" });
            if (e is { Origin: RuleOrigin.Vendor } && e.VendorBody is { } v && v.Replace("\r\n", "\n").Trim() == (w.Body ?? "").Replace("\r\n", "\n").Trim()) return (null, new[] { "nothing changed -- this is the vendor's rule as it is" });
        }
        var title = action switch
        {
            "off" => $"Turn off the rule {w.Key}",
            "reset" => $"Reset the rule {w.Key} to the vendor's",
            "remove" => $"Remove your rule {w.Key}",
            _ => cat.Find(w.Key) is null ? $"Add the rule {w.Key}" : $"Change the rule {w.Key}",
        };
        return (new StagedChange
        {
            Kind = ChangeKind, Title = title,
            Data = new(StringComparer.Ordinal)
            {
                ["key"] = w.Key, ["action"] = action, ["home"] = w.Home, ["state"] = w.State, ["body"] = w.Body, ["reason"] = reason.Trim(),
                ["expectedVersion"] = w.ExpectedVersion?.ToString(CultureInfo.InvariantCulture),
            },
        }, Array.Empty<string>());
    }

    private static ItemWrite WriteOf(StagedChange c) => new(RuleItemStore.Kind, c.Get("key") ?? "", c.Get("home") ?? "override", c.Get("state") ?? "", c.Get("body"),
        long.TryParse(c.Get("expectedVersion"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null);

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var w = WriteOf(c);
        var cat = await _store.LoadAsync(ct);
        var e = cat.Find(w.Key);
        var why = new List<string>();
        if (!cat.Schema) why.Add(SqlItemSource.MissingSchemaMessage);
        if (e?.Version != w.ExpectedVersion || (e is not null && e.Home != w.Home)) why.Add("the rule changed since this was staged -- discard this change and stage it again from the Rules page");
        if (w.State == "override") why.AddRange(RuleItemStore.Problems(cat, w.Key, w.Body ?? ""));
        var old = e is null ? "(no such rule yet)" : e.Origin switch
        {
            RuleOrigin.Off => "(turned off)\n" + (e.VendorBody ?? ""),
            RuleOrigin.Vendor => "(the vendor's rule)\n" + e.VendorBody,
            _ => e.Body ?? "",
        };
        var now = w.State switch
        {
            "disable" => "(turned off)",
            "inherit" => e?.VendorBody is { } v ? "(the vendor's rule)\n" + v : "(removed)",
            _ => (IsOffText(w.Body) ? "(turned off)\n" : "") + (w.Body ?? ""),
        };
        var warnings = new List<string>();
        if (e?.MovedToTier is { } t && w.State != "disable") warnings.Add($"the tier board moves this rule to Tier {t.ToString(CultureInfo.InvariantCulture)} -- that move is applied on top of this text");
        return new ChangePreview(c, old, now, why, warnings);
    }

    private static bool IsOffText(string? b) => b is not null && RuleItemStore.IsOff(b);

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        var w = WriteOf(c);
        var cat = await _store.LoadAsync(ct);
        if (!cat.Schema) return new WriteResult(WriteStatus.Refused, SqlItemSource.MissingSchemaMessage);
        var e = cat.Find(w.Key);
        if (e?.Version != w.ExpectedVersion || (e is not null && e.Home != w.Home)) return new WriteResult(WriteStatus.Stale, $"the rule {w.Key} changed since this was staged -- nothing was written; open it again and stage it again");
        if (w.State == "override")
        {
            var why = RuleItemStore.Problems(cat, w.Key, w.Body ?? "");
            if (why.Count > 0) return new WriteResult(WriteStatus.Refused, $"rule {w.Key}: " + string.Join("; ", why));
        }
        return await _src.WriteAsync(w, by, c.Get("reason") ?? c.Title, ct);
    }
}
