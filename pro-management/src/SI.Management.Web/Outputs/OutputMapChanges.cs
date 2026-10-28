using System.Globalization;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Outputs;

/// <summary>
/// An output column change through THE staging (Review &amp; commit), written by <see cref="ItemOverrideRepository"/> as a
/// cfg.ItemOverride row of kind 'datamodel', key 'outputs/&lt;id&gt;:&lt;target&gt;':
///   change   the column reads another field, uses another operation, or gets another name ('as') -- State 'override'
///   remove   the shipped column is no longer sent -- State 'disable'
///   restore  back to the shipped column -- the override row is removed ('inherit')
///   add      a column of the customer's own (an override with no template behind it)
/// The engine merges the rows per column at the start of the next run (the CI build, the data sync's data-out step); the
/// template conformance view flags UpgradeAvailable when the shipped column changes under a change.
/// </summary>
public sealed class OutputMapChanges : IStagedChangeHandler
{
    public const string ChangeKind = "output-column";
    public static readonly string[] Actions = ["change", "remove", "restore", "add"];
    private readonly OutputMapStore _store;
    private readonly ItemOverrideRepository _overrides;
    public OutputMapChanges(OutputMapStore store, ItemOverrideRepository overrides) { _store = store; _overrides = overrides; }

    public bool Handles(string kind) => kind == ChangeKind;

    private static string StateOf(string action) => action switch
    {
        "remove" => ItemOverrideRepository.StateDisable,
        "restore" => ItemOverrideRepository.StateInherit,
        _ => ItemOverrideRepository.StateOverride,
    };

    /// Stage one change. The reason is required (it lands on the change log).
    /// <paramref name="setPosition"/>: the column builder sets the column's place (<paramref name="position"/>, null = its
    /// place in the map); otherwise a change keeps the place the column has.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewAsync(string outputId, string action, string target, string? from, string? op, string? name, string? reason, CancellationToken ct,
        int? position = null, bool setPosition = false)
    {
        if (!Actions.Contains(action)) return (null, new[] { $"unknown action '{action}'" });
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        if (OutputMapRules.Locked(outputId) is { } locked) return (null, new[] { locked });
        target = (target ?? "").Trim();
        if (target.Length == 0) return (null, new[] { "name the column" });
        var map = await _store.LoadAsync(outputId, ct);
        if (map is null) return (null, new[] { OutputMapStore.NotPublishedMessage });
        var key = OutputMapRules.Key(outputId, target);
        var row = map.Columns.FirstOrDefault(c => c.Key == key);
        string? body = null;
        string title;
        switch (action)
        {
            case "add":
                if (row is not null) return (null, new[] { $"the output already has a column '{target}' -- change that one instead" });
                body = OutputMapRules.Body(new OutputColumn(target, (from ?? "").Trim(), N(op), N(name), setPosition ? position : null));
                title = $"Add the column {target} to the {map.Entry.Label}";
                break;
            case "change":
                if (row is null) return (null, new[] { $"the output has no column '{target}'" });
                var c = new OutputColumn(target, string.IsNullOrWhiteSpace(from) ? row.InForce.From : from.Trim(), op is null ? row.InForce.Op : N(op), N(name),
                    setPosition ? position : row.InForce.Position);
                if (row.Shipped is not null && row.Override is null && c == row.Shipped) return (null, new[] { "nothing changed -- this is the shipped column" });
                if (row.Override is not null && c == row.Override) return (null, new[] { "nothing changed -- this is the column in force" });
                body = OutputMapRules.Body(c);
                title = $"Change the column {target} of the {map.Entry.Label}";
                break;
            case "remove":
                if (row is null) return (null, new[] { $"the output has no column '{target}'" });
                if (row.Removed) return (null, new[] { "the column is already removed" });
                // a column of the customer's own has no shipped column to switch off: it is deleted (back to nothing)
                if (row.Own) { action = "restore"; title = $"Delete your column {target} of the {map.Entry.Label}"; break; }
                title = $"Stop sending the column {target} of the {map.Entry.Label}";
                break;
            default:
                if (row is null || !row.Changed) return (null, new[] { "the column is not changed -- there is nothing to put back" });
                title = $"Put the column {target} of the {map.Entry.Label} back to the shipped column";
                break;
        }
        var state = StateOf(action);
        if (state == ItemOverrideRepository.StateOverride)
        {
            var why = OutputMapRules.Validate(key, body, row?.Shipped, map.NamesExcept(key));
            if (why.Count > 0) return (null, why);
        }
        return (new StagedChange
        {
            Kind = ChangeKind, Title = title,
            Data = new(StringComparer.Ordinal)
            {
                ["output"] = outputId, ["key"] = key, ["state"] = state, ["body"] = body, ["reason"] = reason.Trim(),
                ["expectedVersion"] = row?.Version?.ToString(CultureInfo.InvariantCulture),
            },
        }, Array.Empty<string>());
    }

    private static string? N(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static ItemOverrideWrite WriteOf(StagedChange c) =>
        new(OutputMapRules.Kind, c.Get("key") ?? "", c.Get("state") ?? "", c.Get("state") == ItemOverrideRepository.StateOverride ? c.Get("body") : null, c.Get("reason") ?? c.Title);

    private static long? Expected(StagedChange c) => long.TryParse(c.Get("expectedVersion"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;

    /// The checks a staged change must still pass when it is previewed and committed (the map may have moved since).
    private async Task<(OutputColumnRow? Row, List<string> Problems)> CheckAsync(StagedChange c, CancellationToken ct)
    {
        var w = WriteOf(c);
        var why = new List<string>();
        var k = OutputMapRules.SplitKey(w.ItemKey);
        if (k is null) { why.Add($"'{w.ItemKey}' is not an output column"); return (null, why); }
        var map = await _store.LoadAsync(k.Value.OutputId, ct);
        if (map is null) { why.Add(OutputMapStore.NotPublishedMessage); return (null, why); }
        var row = map.Columns.FirstOrDefault(x => x.Key == w.ItemKey);
        if (row?.Version != Expected(c)) why.Add("the column changed since this was staged -- discard this change and stage it again on the Output fields tab");
        why.AddRange(ItemOverrideRepository.Validate(w));
        if (w.State == ItemOverrideRepository.StateOverride) why.AddRange(OutputMapRules.Validate(w.ItemKey, w.Body, row?.Shipped, map.NamesExcept(w.ItemKey)));
        return (row, why.Distinct().ToList());
    }

    private static string Describe(OutputColumn? col, bool removed) => col is null ? "(no such column)"
        : removed ? $"{col.Name}: not sent"
        : $"{col.Name} <- {col.From}" + (string.IsNullOrWhiteSpace(col.Op) ? "" : $" ({col.Op})") + (col.Position is { } p ? $", place {p}" : "");

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var (row, why) = await CheckAsync(c, ct);
        var w = WriteOf(c);
        var now = w.State switch
        {
            ItemOverrideRepository.StateOverride => Describe(OutputMapRules.ParseColumn(w.Body), false),
            ItemOverrideRepository.StateDisable => Describe(row?.Shipped, true),
            _ => row?.Shipped is null ? "(the column is deleted)" : Describe(row.Shipped, false) + " (the shipped column)",
        };
        return new ChangePreview(c, row is null ? "(no column yet)" : Describe(row.InForce, row.Removed), now, why,
            new[] { "The outputs use the new columns from their next run. A ServiceNow import reads columns by name: tell the ServiceNow team before you rename or remove one." });
    }

    public async Task<WriteResult> CommitAsync(StagedChange c, string by, CancellationToken ct)
    {
        var (_, why) = await CheckAsync(c, ct);
        if (why.Count > 0) return new WriteResult(why.Any(x => x.Contains("changed since", StringComparison.Ordinal)) ? WriteStatus.Stale : WriteStatus.Refused, string.Join("; ", why));
        return await _overrides.WriteAsync(WriteOf(c), by, ct);
    }
}
