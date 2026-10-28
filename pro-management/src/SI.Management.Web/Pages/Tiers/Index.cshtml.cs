using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Cis;

namespace SI.Management.Web.Pages.Tiers;

/// One toggle chip of a tile: one value of "who decided the tier" or of the class, how many CIs of the tile's tier have
/// it, whether the table below is filtered to it now, and the address that toggles it.
public sealed record TierChip(string Value, string Label, long Count, bool On, string Href);

/// <summary>
/// One tile of the tier board: a tier ("0".."3" or "Unclassified"), how many CIs it holds, whether the table is filtered
/// to it, the address that toggles it, its chips, how many CIs carry no record of who decided the tier, what is staged
/// for it (not committed yet) and the rules moved to it.
/// </summary>
public sealed record TierTile(string Tier, string Label, long Count, bool On, string Href, IReadOnlyList<TierChip> SetBy, IReadOnlyList<TierChip> Classes,
    long NotRecorded, int StagedIn, int StagedOut, int StagedExclusions, IReadOnlyList<string> MovedRules);

/// <summary>
/// What a row's drawer shows (Pages/Tiers/_TierPanel.cshtml) -- as a fragment beside the grid, or on the plain page under
/// ?ci=: the CI, its document (the explanation and the claims), the asset the CI is in the asset table (what a pin and an
/// exclusion are staged for; null when the asset table has no row for it), the claims the profiler recorded on that
/// asset, whether the viewer may stage, where a staged form returns to, the committed whole-rule moves, what is staged
/// for this CI now, and the engine a rule key of this CI starts with.
/// <paramref name="AssetOnly"/>: an asset of the asset table that no CI stands for yet (a scope node, a resource no
/// source profiles -- reached from an Unclassified finding's link): <paramref name="Ci"/> then only carries the asset's
/// own values (its key as the id), the document is empty, and the forms name the asset by its key.
/// </summary>
public sealed record TierPanel(CiRow Ci, CiDocument Doc, TierAsset? Asset, IReadOnlyList<IndexModel.TierClaim> RecordedClaims, bool MayStage, string Return,
    string CloseHref, IReadOnlyDictionary<string, int> MovedRules, string? Staged, string Engine, bool Plain, bool AssetOnly = false)
{
    /// The rule changes this person has staged and not committed: rule key -> "staged: turn off" / "staged: move to Tier 1" /
    /// "staged: put back" (shown beside that rule's buttons).
    public IReadOnlyDictionary<string, string> StagedRules { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// What a claim's own buttons name: the key of the rule that made it ("&lt;engine&gt;/&lt;rule id&gt;"), or -- for a claim no
/// rule made, which gets no button -- why, in a word.
/// </summary>
public sealed record ClaimChange(string? Key, string? Why);

/// <summary>
/// The form of ONE claim's buttons (Pages/Tiers/_ClaimChange.cshtml): the rule's key, how the form names the asset it
/// returns to, where it returns, the suffix of its field ids, the tier the rule is moved to now (committed; null = not
/// moved) and what is staged for the rule (null = nothing).
/// </summary>
public sealed record ClaimChangeForm(string Key, string AssetField, string AssetValue, string Return, string IdSuffix, int? MovedTo, string? Staged);

/// <summary>
/// The tier board (owner 2026-10-11): one tile per tier with its count and toggle chips (who decided the tier, the class)
/// on top, ONE table below -- THE CI grid (<see cref="SI.Management.Web.Pages.Cis.IndexModel"/>, Pages/Cis/_CiGrid.cshtml)
/// under its own view key, with the view bar, the column chooser and the exports -- and a drawer per row: the tier in one
/// sentence, every claim on it, and the two changes (pin to a tier, exclude the asset). A tile or a chip is a link that
/// toggles the table's tier / decided-by / class filter in the address, so a state is linkable and a person's remembered
/// view works as on every data view. Nothing is dragged. Every change is STAGED exactly as before -- the same change
/// records, the same role and scope check, the same audit entry, written only on Review &amp; commit.
/// </summary>
public sealed class IndexModel : SI.Management.Web.Pages.Cis.IndexModel
{
    /// The view key of the board's table (its own layout, sort and filters -- not the CIs page's).
    public const string BoardView = "tiers";
    /// The anchor of the panel on the plain page.
    public const string PanelAnchor = "panel";
    public const string NotInAssetTable = "the asset is not in the asset table";

    private readonly IProDataQueries _q;
    private readonly ChangeService _changes;
    private readonly ItemOverrideRepository _overrides;
    private readonly ILogger<IndexModel> _log;

    public IndexModel(ICiViews cis, IColumnLayoutStore layouts, IProDataQueries q, ChangeService changes, ItemOverrideRepository overrides, ILogger<IndexModel> log)
        : base(cis, layouts, (ILogger)log)
    { _q = q; _changes = changes; _overrides = overrides; _log = log; }

    // ---- the CI grid at this address ---------------------------------------------------------------------------------

    public override string Route => "/Tiers";
    // owner 2026-10-19: the tier board shares the CI list's active default (DefaultLifecycle, inherited) -- its tiles count
    // the CIs its grid lists (LifecycleInForce), so the board, the CI list and the tab counts agree; lifecycle=all = every CI.
    public override string ViewName => BoardView;
    public override string GridId => "tiers";
    protected override string ExportName => "tier-board";
    private static readonly IReadOnlySet<string> Tiled = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "tier", "tiersetby", "class" };
    /// The tiles and their chips are the tier / decided-by / class filters: the grid's filter form carries them along.
    public override IReadOnlySet<string> TileFilters => Tiled;
    protected override IEnumerable<string> ShippedLayout() => SI.Management.Web.Columns.DataViewDefaults.TierBoard;

    /// A row opens its drawer: the fragment of <see cref="OnGetDrawerAsync"/>, at the board's current address.
    public override string? RowDrawer(IReadOnlyDictionary<string, object?> row) => Key(row) is { Length: > 0 } k ? DrawerAddress(k) : null;
    /// The same content without script: the board's current address with the CI's panel on the page.
    public override string? RowPanelLink(IReadOnlyDictionary<string, object?> row) => Key(row) is { Length: > 0 } k ? PanelAddress(k) : null;
    /// "staged: ..." on a row with a pin or an exclusion that is not committed yet.
    public override string? RowMark(IReadOnlyDictionary<string, object?> row) => Key(row) is { Length: > 0 } k && _staged.TryGetValue(k, out var words) ? words : null;

    // ---- the address ---------------------------------------------------------------------------------------------------

    /// The CI whose panel the plain page shows (?ci=&lt;CI id&gt;): the drawer's content without script.
    [BindProperty(SupportsGet = true)] public string? Ci { get; set; }
    /// A link from before the redesign: ?lane=&lt;tier&gt; is the tier filter.
    [BindProperty(SupportsGet = true)] public string? Lane { get; set; }
    /// A link by asset key (an Unclassified finding's asset): the panel of the CI that asset is.
    [BindProperty(SupportsGet = true)] public string? Asset { get; set; }

    /// Parameters of one request only: never carried into a tile, chip or panel link.
    private static readonly HashSet<string> Transient = new(StringComparer.OrdinalIgnoreCase) { "handler", "ci", "asset", "lane" };

    private string Build(bool keepPage, IReadOnlyList<(string Param, IReadOnlyList<string> Values)> set)
    {
        var over = new HashSet<string>(set.Select(s => s.Param), StringComparer.OrdinalIgnoreCase);
        var parts = new List<string>();
        foreach (var kv in Request.Query)
        {
            if (over.Contains(kv.Key) || Transient.Contains(kv.Key) || (!keepPage && kv.Key.Equals("p", StringComparison.OrdinalIgnoreCase))) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add(Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(v));
        }
        foreach (var (param, values) in set)
            foreach (var v in values) if (!string.IsNullOrEmpty(v)) parts.Add(Uri.EscapeDataString(param) + "=" + Uri.EscapeDataString(v));
        return Route + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }

    /// The board's address with some filters set to the given values (an empty list removes one); starts at page 1.
    public string Address(params (string Param, IReadOnlyList<string> Values)[] set) => Build(false, set);

    /// The board as it is shown now (page included) with one CI's panel on the page.
    public string PanelAddress(string ciId) => Build(true, new (string, IReadOnlyList<string>)[] { ("ci", new[] { ciId }) }) + "#" + PanelAnchor;

    /// The fragment a row's drawer reads: the board's current address, so a staged form returns to what the person saw.
    public string DrawerAddress(string ciId) => Build(true, new (string, IReadOnlyList<string>)[] { ("handler", new[] { "Drawer" }), ("ci", new[] { ciId }) });

    /// The board as it is shown now, without a panel.
    public string BoardAddress => Build(true, Array.Empty<(string, IReadOnlyList<string>)>());

    /// The values the address gives one filter (repeated, or joined with '|').
    private IReadOnlyList<string> Values(string param) => Request.Query[param].Where(v => !string.IsNullOrWhiteSpace(v))
        .SelectMany(v => v!.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private static IReadOnlyList<string> With(IReadOnlyList<string> list, string value) =>
        list.Contains(value, StringComparer.OrdinalIgnoreCase) ? list : list.Append(value).ToList();

    private static IReadOnlyList<string> Without(IReadOnlyList<string> list, string value) =>
        list.Where(x => !x.Equals(value, StringComparison.OrdinalIgnoreCase)).ToList();

    // ---- what the page shows -------------------------------------------------------------------------------------------

    public IReadOnlyList<TierTile> Tiles { get; private set; } = Array.Empty<TierTile>();
    /// Set when the counts could not be read (the table below is still shown).
    public string? TilesError { get; private set; }
    public TierPanel? Panel { get; private set; }
    /// ?ci= named a CI that is not in the Pro database.
    public bool PanelMissing { get; private set; }
    public IReadOnlyList<StagedChange> Pending { get; private set; } = Array.Empty<StagedChange>();
    /// The committed whole-rule moves (cfg.ItemOverride 'ruletier', State override): rule key -> its tier.
    public IReadOnlyDictionary<string, int> MovedRules { get; private set; } = new Dictionary<string, int>();
    /// The Unclassified findings of the newest collection, explained on the tile of the CIs with no tier (null = not known).
    public UnclassifiedFindings? UnclassifiedFindings { get; private set; }
    /// CI id -> what is staged for it.
    private readonly Dictionary<string, string> _staged = new(StringComparer.OrdinalIgnoreCase);

    /// One claim the profiler recorded on the asset (SI_TierClaims of the asset table).
    public sealed record TierClaim(string Source, int? Tier, string? Evidence, bool FeedsTier);

    /// SI_TierClaims: a JSON array of {Source, Tier, Evidence, FeedsTier, ...}. Anything else: no claims.
    public static IReadOnlyList<TierClaim> Claims(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Array.Empty<TierClaim>();
        try
        {
            using var d = JsonDocument.Parse(json);
            if (d.RootElement.ValueKind != JsonValueKind.Array) return Array.Empty<TierClaim>();
            return d.RootElement.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.Object).Select(e => new TierClaim(
                e.TryGetProperty("Source", out var s) ? s.ToString() : "?",
                e.TryGetProperty("Tier", out var t) && t.ValueKind == JsonValueKind.Number && t.TryGetInt32(out var ti) ? ti : null,
                e.TryGetProperty("Evidence", out var ev) && ev.ValueKind == JsonValueKind.String ? ev.GetString() : null,
                !e.TryGetProperty("FeedsTier", out var f) || f.ValueKind != JsonValueKind.False)).ToList();
        }
        catch (JsonException) { return Array.Empty<TierClaim>(); }
    }

    /// "Tier 2", or "No tier" for the CIs no rule, pin or default gave a tier (Unclassified).
    public static string TierLabel(string tier) => tier == ProDataFilters.Unclassified ? "No tier" : "Tier " + tier;

    /// A CI's stored tier in the one tier vocabulary ("0".."3" or "Unclassified").
    public static string TierOf(int? tier) => CiSql.TierOf(tier);

    /// The words of a class chip.
    public static string ClassLabel(string cls) => cls.ToLowerInvariant() switch
    {
        "device" => "devices",
        "identity" => "identities",
        "cloud_resource" => "cloud resources",
        "public_ip" => "public IPs",
        _ => cls.Replace('_', ' '),
    };

    /// The asset kind (the asset table's word) of a CI class -- what a rule key of the CI starts with when the asset table
    /// has no row for it.
    public static string KindOfClass(string? cls) => (cls ?? "").ToLowerInvariant() switch
    {
        "device" => "endpoint",
        "identity" => "identity",
        "cloud_resource" => "azure",
        "public_ip" => "publicip",
        _ => "",
    };

    /// What a staged change is on a row and in the panel; null for a change that is not about one asset.
    public static string? StagedWords(StagedChange p) => p.Kind switch
    {
        ChangeKinds.TierPin => "staged: pin to Tier " + p.Get("tier"),
        ChangeKinds.Exemption when p.Get("scope") == ExemptionRepository.ScopeAsset => "staged: exclusion",
        _ => null,
    };

    /// What a staged rule change is beside the rule's buttons; null for a change that is not about a rule.
    public static string? RuleWords(StagedChange p) => p.Kind switch
    {
        ChangeKinds.RuleDisable => "staged: turn off",
        ChangeKinds.RuleTier => "staged: move to Tier " + p.Get("tier"),
        ChangeKinds.RuleTierReset => "staged: put back",
        _ => null,
    };

    /// The staged rule changes by rule key (the newest of a rule last, so it is the one shown).
    public static IReadOnlyDictionary<string, string> StagedRulesOf(IEnumerable<StagedChange> pending)
    {
        var by = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in pending)
            if (RuleWords(p) is { } words && p.Get("ruleKey") is { Length: > 0 } key) by[key] = words;
        return by;
    }

    public const string WhyTag = "set by your tag";
    public const string WhyPin = "manual pin";
    public const string WhyPack = "rule pack";
    public const string WhyDefault = "default tier";
    public const string WhyNotRecorded = "known after the next run";

    /// Whether a text is the key of a rule a rule change can name (moving a rule and putting it back accept it).
    public static bool IsRuleKey(string? key) => ItemOverrideRepository.RuleTierKey().IsMatch(key ?? "");

    /// Whether the rule with this key can be turned off from here (a rule document can be written for it).
    public static bool CanTurnOff(string? key) => DocumentValidator.RuleKey().IsMatch(key ?? "");

    /// The rule id of a claim: what stands before the first '/' of its rule ("&lt;rule id&gt;/&lt;detection id&gt;").
    private static string RuleIdOf(string? rule)
    {
        var r = (rule ?? "").Trim();
        var slash = r.IndexOf('/');
        return slash < 0 ? r : r[..slash];
    }

    /// The suffix that keeps the field ids of one claim's form apart from the next claim's ("ci-3"): an element id, never shown.
    public static string ClaimIdSuffix(string panel, int number) => panel + "-" + number.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>
    /// PURE. The rule a claim's buttons change, or why the claim has none. A claim carries the key of the rule that made it
    /// (written by the CI build); a tag's claim and a pin's claim never have a button -- they are changed where they were
    /// set. A document written before claims carried a key: the key is known only when the profiler recorded that rule on
    /// this asset (<paramref name="recordedKeys"/>), else the claim says it is known after the next run. A key that is not
    /// a rule key is never offered.
    /// </summary>
    public static ClaimChange ChangeOf(CiTierClaim c, IReadOnlyCollection<string> recordedKeys, string engine)
    {
        if (c.Kind == "tag" || c.Mechanism == "operator.tier_tag") return new(null, WhyTag);
        var ruleId = RuleIdOf(c.Rule);
        if (ruleId.StartsWith(RuleTemplates.PinPrefix, StringComparison.OrdinalIgnoreCase)) return new(null, WhyPin);
        if (c.RuleKey is { Length: > 0 } key) return IsRuleKey(key) ? new(key, null) : new(null, WhyPack);
        if (!c.RuleKeyRecorded)
        {
            var guess = engine + "/" + ruleId;
            return recordedKeys.Contains(guess, StringComparer.OrdinalIgnoreCase) ? new(guess, null) : new(null, WhyNotRecorded);
        }
        return new(null, c.Kind == "default" ? WhyDefault : WhyPack);
    }

    private static string TierWord(string? tier) => tier is "0" or "1" or "2" or "3" ? tier : ProDataFilters.Unclassified;
    private int StagedInto(string tier) => Pending.Count(p => p.Kind == ChangeKinds.TierPin && TierWord(p.Get("tier")) == tier);
    private int StagedOutOf(string tier) => Pending.Count(p => p.Kind == ChangeKinds.TierPin && TierWord(p.Get("fromTier")) == tier);
    private int StagedExclusionsIn(string tier) =>
        Pending.Count(p => p.Kind == ChangeKinds.Exemption && p.Get("scope") == ExemptionRepository.ScopeAsset && TierWord(p.Get(ChangeAccess.TierKey)) == tier);

    /// The rules moved to one tier (committed).
    public IEnumerable<string> MovedRulesIn(string tier) =>
        MovedRules.Where(m => m.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) == tier).Select(m => m.Key).OrderBy(k => k, StringComparer.OrdinalIgnoreCase);

    public override async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        ApplyLane();
        await LoadGridAsync(ct);
        await LoadBoardAsync(ct);
        return Page();
    }

    /// ?lane=&lt;tier&gt; (a link from before the redesign) is the tier filter: it is put into the request as that, before
    /// the grid reads the address.
    private void ApplyLane()
    {
        if (string.IsNullOrWhiteSpace(Lane)) return;
        var tier = ProDataFilters.Tiers.FirstOrDefault(t => t.Equals(Lane.Trim(), StringComparison.OrdinalIgnoreCase));
        var query = Request.Query.Where(kv => !kv.Key.Equals("lane", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
        if (tier is not null && !query.ContainsKey("tier")) query["tier"] = tier;
        Request.Query = new QueryCollection(query);
    }

    /// The tiles, the staged marks and the panel -- after the grid. A part that cannot be read is said or left out; the
    /// table is shown either way.
    private async Task LoadBoardAsync(CancellationToken ct)
    {
        // no CI tables yet, or an account limited to departments: the grid said so and shows nothing -- so does the board
        if (NotLoaded || !Schema.Ci || ViewLayout is null) return;
        await LoadStagedAsync(ct);
        MovedRules = await MovedRulesAsync(ct);
        UnclassifiedFindings = await UnclassifiedFindingsAsync(ct);
        IReadOnlyList<CiTierCount> counts = Array.Empty<CiTierCount>();
        try
        {
            var r = await CiData.TierCountsAsync(LifecycleInForce, ct);
            counts = r.Data;
            if (!string.IsNullOrEmpty(r.Query)) Queries.Add(QueryInfo.From(r, "The CIs per tier, by who decided the tier and by class"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the tier board's counts could not be read");
            TilesError = "The counts per tier could not be read from the Pro database: " + ex.Message;
        }
        Tiles = BuildTiles(counts);
        await MarkRowsAsync(ct);
        try
        {
            if (string.IsNullOrWhiteSpace(Ci) && !string.IsNullOrWhiteSpace(Asset)) Ci = (await CiData.CiOfAssetKeyAsync(Asset, Schema, ct)).Data;
            if (!string.IsNullOrWhiteSpace(Ci))
            {
                Panel = await PanelAsync(Ci, plain: true, ct);
                PanelMissing = Panel is null;
            }
            else if (!string.IsNullOrWhiteSpace(Asset))
            {
                // an asset no CI stands for yet: its row of the asset table, so it can still be given a tier
                Panel = await AssetPanelAsync(Asset, ct);
                PanelMissing = Panel is null;
            }
        }
        catch (ArgumentException) { PanelMissing = true; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the tier panel of a CI could not be read");
            PanelMissing = true;
        }
    }

    private async Task LoadStagedAsync(CancellationToken ct)
    {
        if (!User.MayChange()) return;
        try { Pending = await _changes.PendingAsync(User, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the staged changes could not be read"); }
    }

    private IReadOnlyList<TierTile> BuildTiles(IReadOnlyList<CiTierCount> counts)
    {
        var tiers = Values("tier");
        var setBy = Values("tiersetby");
        var classes = Values("class");
        var tiles = new List<TierTile>();
        foreach (var tier in ProDataFilters.Tiers)
        {
            var mine = counts.Where(c => c.Tier == tier).ToList();
            var on = tiers.Contains(tier, StringComparer.OrdinalIgnoreCase);
            // a chip is on when its value is filtered on and its tile's tier is among the tiers shown
            var shown = tiers.Count == 0 || on;
            IReadOnlyList<TierChip> Chips(string facet, string param, IReadOnlyList<string> chosen, Func<string, string> label) => mine
                .Where(c => c.Facet == facet && c.Value.Length > 0)
                .OrderByDescending(c => c.N).ThenBy(c => c.Value, StringComparer.OrdinalIgnoreCase)
                .Select(c =>
                {
                    var active = shown && chosen.Contains(c.Value, StringComparer.OrdinalIgnoreCase);
                    var href = active ? Address((param, Without(chosen, c.Value))) : Address(("tier", With(tiers, tier)), (param, With(chosen, c.Value)));
                    return new TierChip(c.Value, label(c.Value), c.N, active, href);
                }).ToList();
            tiles.Add(new TierTile(tier, TierLabel(tier), mine.Where(c => c.Facet == CiTierCount.ClassFacet).Sum(c => c.N), on,
                Address(("tier", on ? Without(tiers, tier) : With(tiers, tier))),
                Chips(CiTierCount.SetByFacet, "tiersetby", setBy, v => CiColumns.TierSetByText(v)),
                Chips(CiTierCount.ClassFacet, "class", classes, ClassLabel),
                mine.Where(c => c.Facet == CiTierCount.SetByFacet && c.Value.Length == 0).Sum(c => c.N),
                StagedInto(tier), StagedOutOf(tier), StagedExclusionsIn(tier), MovedRulesIn(tier).ToList()));
        }
        return tiles;
    }

    /// The rows of the page with a staged pin or exclusion. A staged change names its asset key -- mostly the CI id; one
    /// that is not a row of this page is looked up (one seek each; the staged changes of one person are few).
    private async Task MarkRowsAsync(CancellationToken ct)
    {
        var onPage = new HashSet<string>((Grid?.Rows ?? Array.Empty<IReadOnlyDictionary<string, object?>>()).Select(Key).Where(k => !string.IsNullOrEmpty(k)).Select(k => k!),
            StringComparer.OrdinalIgnoreCase);
        foreach (var p in Pending)
        {
            var words = StagedWords(p);
            var key = p.Get("assetKey");
            if (words is null || string.IsNullOrWhiteSpace(key)) continue;
            var ci = key;
            if (!onPage.Contains(key))
            {
                try { ci = (await CiData.CiOfAssetKeyAsync(key, Schema, ct)).Data ?? key; }
                catch (ArgumentException) { }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogDebug(ex, "the CI of a staged change could not be found"); }
            }
            _staged[ci] = _staged.TryGetValue(ci, out var had) ? had + "; " + words : words;
        }
    }

    /// One CI's panel: the CI by its key (one row, with its document), then the asset it is in the asset table.
    private async Task<TierPanel?> PanelAsync(string ciId, bool plain, CancellationToken ct)
    {
        var schema = Schema.Ci ? Schema : (await CiData.SchemaAsync(ct)).Data;
        if (!schema.Ci) return null;
        // the CI alone: its links, findings, trend and records are the CI page's, not the drawer's
        var read = await CiData.CiAsync(ciId, new CiSchema(true, false, false, false, false), ct);
        if (read.Data is not { } detail) return null;
        if (plain && !string.IsNullOrEmpty(read.Query)) Queries.Add(QueryInfo.From(read, "The CI of the panel"));
        var ci = detail.Ci;
        TierAsset? asset = null;
        try
        {
            if ((await CiData.AssetKeyOfCiAsync(ci.CiId, schema, ct)).Data is { Length: > 0 } assetKey) asset = (await _q.AssetAsync(assetKey, ct)).Data;
        }
        catch (ArgumentException) { }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the asset of CI {Id} could not be read", ci.CiId); }
        var staged = Pending
            .Where(p => p.Get("assetKey") is { Length: > 0 } k && (k.Equals(ci.CiId, StringComparison.OrdinalIgnoreCase) || (asset is not null && k.Equals(asset.AssetKey, StringComparison.OrdinalIgnoreCase))))
            .Select(StagedWords).Where(w => w is not null).ToList();
        var kind = asset?.AssetKind ?? KindOfClass(ci.Class);
        return new TierPanel(ci, detail.Doc, asset, Claims(asset?.TierClaimsJson), User.MayChange(), PanelAddress(ci.CiId), BoardAddress, MovedRules,
            staged.Count > 0 ? string.Join("; ", staged) : null, RuleTemplates.EngineFor(kind), plain) { StagedRules = StagedRulesOf(Pending) };
    }

    /// The CI class of an asset kind (the reverse of <see cref="KindOfClass"/>); null for a kind that is none.
    public static string? ClassOfKind(string? kind) => (kind ?? "").ToLowerInvariant() switch
    {
        "endpoint" => "device",
        "identity" => "identity",
        "azure" => "cloud_resource",
        "publicip" => "public_ip",
        _ => null,
    };

    /// <summary>
    /// The panel of an asset of the asset table that no CI stands for yet (it is not a row of the board's table): what
    /// the asset table holds about it -- name, kind, tier, the reason, the claims the profiler recorded -- and, for someone
    /// who may change, the same forms, naming the asset by its key. Null = no such asset.
    /// </summary>
    private async Task<TierPanel?> AssetPanelAsync(string assetKey, CancellationToken ct)
    {
        var asset = (await _q.AssetAsync(assetKey, ct)).Data;
        if (asset is null) return null;
        int? tier = int.TryParse(asset.Tier, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var t) && t is >= 0 and <= 3 ? t : null;
        // the asset's own values in the shape the panel reads (CiRow): its key as the id, nothing a CI alone carries
        var row = new CiRow(CiId: asset.AssetKey, Class: ClassOfKind(asset.AssetKind), Name: asset.AssetName, AssetType: null, Tier: tier, TierSetBy: asset.TierSetBy,
            TierReason: asset.TierReason, Lifecycle: null, InternetExposed: null, CmdbId: null, CmdbName: null, CmdbCriticality: null, CriticalityFactor: null, RiskFactors: null,
            LinkCount: null, RiskScore: null, WeightedRiskScore: null, OpenFindings: null, LastSeen: asset.LastSeen, CollectionTime: null, DocJson: null);
        var staged = Pending.Where(p => asset.AssetKey.Equals(p.Get("assetKey"), StringComparison.OrdinalIgnoreCase)).Select(StagedWords).Where(w => w is not null).ToList();
        var back = Route + "?asset=" + Uri.EscapeDataString(asset.AssetKey) + "#" + PanelAnchor;
        return new TierPanel(row, CiDocument.Empty, asset, Claims(asset.TierClaimsJson), User.MayChange(), back, BoardAddress, MovedRules,
            staged.Count > 0 ? string.Join("; ", staged) : null, RuleTemplates.EngineFor(asset.AssetKind), Plain: true, AssetOnly: true) { StagedRules = StagedRulesOf(Pending) };
    }

    /// <summary>
    /// The drawer of one row, as a fragment (the grid's row-click hook reads it): the tier in one sentence, the claims, and
    /// -- for someone who may change -- the forms that stage a pin, an exclusion or a rule change. ONE CI by its key.
    /// The same content is on the plain page under ?ci=.
    /// </summary>
    public async Task<IActionResult> OnGetDrawerAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(Ci)) return BadRequest("A CI is required.");
        try
        {
            // as the CI grid: an account limited to departments sees no CI
            if (await DepartmentLimitedAsync(ct)) return new ContentResult { StatusCode = StatusCodes.Status403Forbidden, Content = Error, ContentType = "text/plain; charset=utf-8" };
            await LoadStagedAsync(ct);
            MovedRules = await MovedRulesAsync(ct);
            var panel = await PanelAsync(Ci, plain: false, ct);
            if (panel is null) return NotFound("That CI is not in the Pro database (it may have been retired, or the id is wrong).");
            return Partial("_TierPanel", panel);
        }
        catch (ArgumentException ex) { return BadRequest("The request is not valid: " + ex.Message); }
    }

    /// The rules moved to another tier (empty when cfg.ItemOverride does not exist yet or cannot be read -- the board
    /// still shows the assets).
    private async Task<IReadOnlyDictionary<string, int>> MovedRulesAsync(CancellationToken ct)
    {
        try
        {
            var moved = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var o in await _overrides.ListAsync(ItemOverrideRepository.RuleTierKind, ct))
                if (o.State == ItemOverrideRepository.StateOverride && o.Tier is { } t) moved[o.ItemKey] = t;
            return moved;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the rule tier moves could not be read");
            return new Dictionary<string, int>();
        }
    }

    /// The Unclassified findings of the newest collection (null when they cannot be read -- the board still shows the assets).
    private async Task<UnclassifiedFindings?> UnclassifiedFindingsAsync(CancellationToken ct)
    {
        try
        {
            // #855 M15: the unclassified findings of the CIs the board counts (its lifecycle filter: active by default, every
            // state when cleared) -- never every finding whatever its CI's lifecycle
            var life = LifecycleInForce is { Count: > 0 } states ? LifecycleFilter.Of(states.ToArray()) : LifecycleFilter.All;
            var r = await _q.UnclassifiedFindingsAsync(life, ct);
            if (!string.IsNullOrEmpty(r.Query)) Queries.Add(QueryInfo.Sql(r.Query, "Unclassified findings (newest collection)"));
            return r.Data;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the unclassified findings could not be read");
            return null;
        }
    }

    // ---- staging: the drawer's forms post here (nothing is written before Review & commit) ---------------------------------
    [BindProperty] public string? Action { get; set; }
    /// The asset by its key in the asset table ...
    [BindProperty] public string? AssetKey { get; set; }
    /// ... or by the CI it is (the drawer's forms): the asset is looked up from the CI.
    [BindProperty] public string? CiId { get; set; }
    [BindProperty] public string? Tier { get; set; }
    [BindProperty] public string? RuleKey { get; set; }
    [BindProperty] public string? Reason { get; set; }

    /// The asset a pin or an exclusion is staged for: by its key, else the asset the CI is.
    private async Task<TierAsset?> StagedAssetAsync(CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(AssetKey)) return (await _q.AssetAsync(AssetKey, ct)).Data;
        if (string.IsNullOrWhiteSpace(CiId)) return null;
        var schema = (await CiData.SchemaAsync(ct)).Data;
        if (!schema.Ci) return null;
        return (await CiData.AssetKeyOfCiAsync(CiId, schema, ct)).Data is { Length: > 0 } key ? (await _q.AssetAsync(key, ct)).Data : null;
    }

    [SI.Management.Web.Audit.Audited("tier.change.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.MayChange()) return Forbid();
        (StagedChange? change, IReadOnlyList<string> why) r;
        try
        {
            switch (Action)
            {
                case "pin":
                {
                    var a = await StagedAssetAsync(ct);
                    r = a is null ? (null, new[] { NotInAssetTable }) : await _changes.NewPinAsync(a, Tier ?? "", Reason ?? "", ct);
                    break;
                }
                case "exclude":
                {
                    var a = await StagedAssetAsync(ct);
                    r = a is null ? (null, new[] { NotInAssetTable })
                        : _changes.NewExemption(new ExemptionRequest(ExemptionRepository.ScopeAsset, null, null, null, a.AssetKey, a.AssetName, Reason ?? "", null));
                    if (r.change is not null && a is not null) ChangeAccess.Stamp(r.change, ChangeAccess.ForAsset(a));
                    break;
                }
                case "rule-disable": r = await _changes.NewRuleDisableAsync(RuleKey ?? "", Reason ?? "", ct); break;
                case "rule-tier": r = await _changes.NewRuleTierAsync(RuleKey ?? "", Tier ?? "", Reason ?? "", ct); break;
                case "rule-tier-reset": r = await _changes.NewRuleTierResetAsync(RuleKey ?? "", Reason ?? "", ct); break;
                default: r = (null, new[] { $"unknown action '{Action}'" }); break;
            }
        }
        catch (ArgumentException ex) { r = (null, new[] { ex.Message }); }
        string message;
        if (r.change is not null)
        {
            // role + scope (#253), server-side: a Delegated user only inside their scopes (403, nothing staged)
            var gate = ChangeAccess.Check(HttpContext.RequestServices.GetRequiredService<IAccessScope>(), User, r.change);
            if (!gate.Allowed) return AccessResults.Refused(Request, gate);
            await _changes.StageAsync(User, r.change, ct);
            message = "Staged: " + r.change.Title + ". Nothing is written until you review and commit.";
        }
        else message = "Not staged: " + string.Join("; ", r.why);
        var pending = (await _changes.PendingAsync(User, ct)).Count;
        if (Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase))
            return new JsonResult(new { ok = r.change is not null, message, pending, mark = r.change is null ? null : StagedWords(r.change), ruleMark = r.change is null ? null : RuleWords(r.change), staged = r.change is null ? null : new { r.change.Id, r.change.Kind, assetKey = r.change.Get("assetKey"), tier = r.change.Get("tier"), ruleKey = r.change.Get("ruleKey") } });
        TempData["toast"] = message;
        TempData["toastKind"] = r.change is null ? "error" : "ok";
        // back to the board as the person saw it (the panel open), never to another site
        if (Return is { Length: > 1 } back && back.StartsWith(Route, StringComparison.OrdinalIgnoreCase) && Url.IsLocalUrl(back)) return LocalRedirect(back);
        return string.IsNullOrWhiteSpace(CiId) ? RedirectToPage() : LocalRedirect(Route + "?ci=" + Uri.EscapeDataString(CiId.Trim()) + "#" + PanelAnchor);
    }
}
