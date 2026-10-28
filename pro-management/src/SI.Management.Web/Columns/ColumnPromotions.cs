using System.Collections.Concurrent;
using SI.Management.Core.ProData;
using SI.Management.Web.Cis;

namespace SI.Management.Web.Columns;

/// <summary>
/// PROMOTED COLUMNS (continuous discovery, "New context available"): the columns an Admin added to the default layout of
/// one view -- or of every view whose rows can carry them -- in one step. They JOIN the default a view opens with (the
/// shipped layout, or the tenant default an Admin saved) for everyone without a layout of their own; a person's own
/// layout stays theirs (the column is in their chooser). Kept with the layouts themselves (cfg.ColumnLayout, the tenant
/// row of the view key "&lt;view&gt;.promoted", or "all.promoted" for every view), so no table and no schema change is
/// needed; read at most once a minute per view (the list is tiny and changes only from that page).
/// </summary>
public interface IColumnPromotions
{
    /// The promoted column keys that apply to a view: every view's, then the view's own.
    Task<IReadOnlyList<string>> ForAsync(string view, CancellationToken ct);
    /// The promoted column keys of one target (<see cref="ColumnPromotions.EveryView"/> = every view), as stored.
    Task<IReadOnlyList<string>> ReadAsync(string target, CancellationToken ct);
    /// Replaces a target's list (empty = none); false = the column layouts are not in the Pro database yet.
    Task<bool> SaveAsync(string target, IReadOnlyList<string> keys, string by, CancellationToken ct);
}

public sealed class ColumnPromotions(IColumnLayoutStore store) : IColumnPromotions
{
    /// The target that means "every view whose rows can carry the column".
    public const string EveryView = "";
    public const string Suffix = ".promoted";
    public const string EveryViewKey = "all" + Suffix;
    public const int Max = 200;
    public static readonly TimeSpan Keep = TimeSpan.FromSeconds(60);

    private sealed record Entry(DateTime At, IReadOnlyList<string> Keys);
    private readonly ConcurrentDictionary<string, Entry> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// The layout-store key a target's list is kept under.
    public static string StoreKey(string? target) => string.IsNullOrEmpty(target) ? EveryViewKey : target + Suffix;

    /// Whether a view key is itself a promotion list (never a view to promote into).
    public static bool IsPromotionKey(string? view) => view is not null && view.EndsWith(Suffix, StringComparison.Ordinal);

    /// A target a list may be kept for: every view, or a plain view key that still fits the store with its suffix.
    public static bool ValidTarget(string? target) =>
        string.IsNullOrEmpty(target)
        || (target.Length + Suffix.Length <= SqlColumnLayoutStore.MaxView && !IsPromotionKey(target)
            && target.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' or '@' or '.'));

    /// The keys a list may hold: well-formed extra column keys, each once, at most <see cref="Max"/>.
    public static IReadOnlyList<string> Clean(IEnumerable<string?> keys) =>
        keys.Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k!.Trim()).Where(DataColumnKeys.IsValid)
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(Max).ToList();

    public async Task<IReadOnlyList<string>> ReadAsync(string target, CancellationToken ct)
    {
        var key = StoreKey(target);
        if (_cache.TryGetValue(key, out var hit) && DateTime.UtcNow - hit.At < Keep) return hit.Keys;
        var stored = await store.ReadAsync(key, "", ct).ConfigureAwait(false);
        var keys = stored.Ready ? Clean(ColumnLayout.Parse(stored.Tenant)) : Array.Empty<string>();
        _cache[key] = new Entry(DateTime.UtcNow, keys);
        return keys;
    }

    public async Task<IReadOnlyList<string>> ForAsync(string view, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(view) || IsPromotionKey(view)) return Array.Empty<string>();
        var every = await ReadAsync(EveryView, ct).ConfigureAwait(false);
        if (!ValidTarget(view)) return every;
        var own = await ReadAsync(view, ct).ConfigureAwait(false);
        return own.Count == 0 ? every : every.Concat(own).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<bool> SaveAsync(string target, IReadOnlyList<string> keys, string by, CancellationToken ct)
    {
        if (!ValidTarget(target)) throw new ArgumentException("not a view the columns can be promoted to");
        var key = StoreKey(target);
        var clean = Clean(keys);
        var done = clean.Count == 0
            ? await store.ResetAsync(SqlColumnLayoutStore.ScopeTenant, "", key, ct).ConfigureAwait(false)
            : await store.SaveAsync(SqlColumnLayoutStore.ScopeTenant, "", key, ColumnLayout.ToJson(clean), by, ct).ConfigureAwait(false);
        _cache.TryRemove(key, out _);
        return done;
    }
}
