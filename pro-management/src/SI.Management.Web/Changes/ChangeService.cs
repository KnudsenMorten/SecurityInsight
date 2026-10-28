using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Jobs;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// What the review page shows for one pending change: before -> after, and why it would be refused.
public sealed record ChangePreview(StagedChange Change, string Old, string New, IReadOnlyList<string> Problems, IReadOnlyList<string> Warnings)
{
    public bool CanCommit => Problems.Count == 0;
}

public sealed record CommitOutcome(StagedChange Change, WriteStatus Status, string Message);

/// <summary>
/// Builds staged changes (validated up front so a bad drop is refused at once, not at commit), previews them for the
/// Review &amp; commit page, and commits them -- each in its own transaction through the ONE repository that owns
/// its table. A committed change leaves the pending list; a refused or stale one stays, with its message.
/// </summary>
public sealed class ChangeService
{
    private readonly IStagingStore _store;
    private readonly ExemptionRepository _exemptions;
    private readonly DocumentRepository _documents;
    private readonly ItemOverrideRepository _overrides;
    private readonly TemplateConformance _conformance;
    private readonly ConnectorRepository _connectors;
    private readonly TemplateReleases _releases;
    private readonly IProDataQueries _data;
    private readonly IMemoryCache _cache;
    private readonly ILogger<ChangeService> _log;
    // role + scope: every stage, review and commit asks it (#253); a page's own check comes first, this is the backstop
    private readonly IAccessScope _access;
    /// Kinds committed by their own feature (the CMDB links, ...): asked before the kinds handled below.
    private readonly IReadOnlyList<IStagedChangeHandler> _handlers;
    /// #302 (AUDIT-1.1): who initiated each committed change, recorded at commit for the jobs that put it in force.
    private readonly SI.Management.Web.Audit.IChangeAttributionWriter? _attribution;
    /// #903: switches the ServiceNow outputs on (SI_DataOut_Outputs) when a staged "Switch on" of the data-out connector commits.
    private readonly SI.Management.Web.Outputs.DataOutSwitch? _dataOut;

    public ChangeService(IStagingStore store, ExemptionRepository exemptions, DocumentRepository documents, ItemOverrideRepository overrides, TemplateConformance conformance, ConnectorRepository connectors, TemplateReleases releases, IProDataQueries data, IMemoryCache cache, ILogger<ChangeService> log, IAccessScope? access = null, IEnumerable<IStagedChangeHandler>? handlers = null, SI.Management.Web.Audit.IChangeAttributionWriter? attribution = null, SI.Management.Web.Outputs.DataOutSwitch? dataOut = null)
    { _store = store; _exemptions = exemptions; _documents = documents; _overrides = overrides; _conformance = conformance; _connectors = connectors; _releases = releases; _data = data; _cache = cache; _log = log; _access = access ?? new AccessScopeService(); _handlers = handlers?.ToList() ?? new List<IStagedChangeHandler>(); _attribution = attribution; _dataOut = dataOut; }

    // ---------------------------------------------------------------- template releases (nothing is written)

    /// Stage a template release ("release") of a staged pack, or a roll back ("rollback") to a version -- every detection
    /// method (all) or the selected ones -- with the selection fingerprint the Admin is shown. Nothing is written or started.
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewTemplateReleaseAsync(string mode, string version, IEnumerable<string>? methods, bool all, string? reason, CancellationToken ct, string? cls = null)
    {
        if (mode is not ("release" or "rollback")) return (null, new[] { $"unknown template release '{mode}'" });
        // #405: a class narrows a roll back (the one-click roll back of Microsoft content)
        if (cls is not null && (mode != "rollback" || !TemplateClasses.IsClass(cls))) return (null, new[] { $"'{cls}' cannot narrow a {mode}" });
        if (!TemplateReleases.IsPackVersion(version)) return (null, new[] { $"'{version}' is not a template version" });
        var (packTable, versioning) = await _releases.SchemaAsync(ct);
        if (!versioning) return (null, new[] { TemplateConformance.MissingSchemaMessage });
        if (mode == "release" && !packTable) return (null, new[] { TemplateReleases.MissingSchemaMessage });
        ReleaseDiff diff;
        try { (diff, _) = await _releases.DiffAsync(mode, version, ct, cls); }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or JsonException) { return (null, new[] { ex.Message }); }
        var (sel, why) = TemplateReleases.Select(diff, methods, all);
        if (why.Count > 0) return (null, why);
        var fp = diff.Fingerprint(sel);
        if (fp.Length == 0) return (null, new[] { "nothing to release: the selection holds no template" });
        var count = all ? diff.Methods.Count : sel.Count;
        var what = all ? $"every detection method ({count})" : $"{count} detection method(s): {string.Join(", ", sel.Take(3))}{(sel.Count > 3 ? ", ..." : "")}";
        var data = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["mode"] = mode, ["version"] = version, ["methods"] = string.Join(";", sel), ["fingerprint"] = fp, ["reason"] = N(reason),
        };
        if (cls is not null) data["class"] = cls;
        return (new StagedChange
        {
            Kind = mode == "release" ? ChangeKinds.TemplateRelease : ChangeKinds.TemplateRollback,
            Title = cls == TemplateClasses.Microsoft && mode == "rollback" ? $"Roll back Microsoft content to {version}"
                  : mode == "release" ? $"Release template pack {version} -- {what}" : $"Roll back templates to {version} -- {what}",
            Data = data,
        }, Array.Empty<string>());
    }

    private static IReadOnlyList<string> MethodsOf(StagedChange c) => (c.Get("methods") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private async Task<ChangePreview> PreviewTemplateReleaseAsync(StagedChange c, CancellationToken ct)
    {
        var mode = c.Get("mode") ?? ""; var version = c.Get("version") ?? ""; var fp = c.Get("fingerprint") ?? ""; var methods = MethodsOf(c);
        var why = new List<string>(); var warnings = new List<string>();
        if (!_releases.JobsConfigured) why.Add(NotConfiguredJobsClient.Why + " The template release job cannot be started.");
        ReleaseDiff diff;
        try { (diff, _) = await _releases.DiffAsync(mode, version, ct, c.Get("class")); }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or JsonException) { return new ChangePreview(c, "", "", new[] { ex.Message }, warnings); }
        if (diff.Fingerprint(methods) != fp) why.Add("the pack, the selection or your templates changed since this was staged -- discard it and stage it again");
        var all = methods.Contains(TemplateReleases.AllMethods);
        var affected = diff.Items.Count(i => i.Affected && (all || methods.Contains(i.MethodId)));
        if (affected > 0) warnings.Add($"{affected} item(s) you overrode or switched off change in this {mode}. Your versions stay; afterwards they read \"upgrade available\" on Template conformance.");
        var installed = await _releases.InstallStateAsync(ct);
        var now = $"Installed template pack: {(installed.TryGetValue("TemplatePack", out var p) ? p.Value : "(none recorded)")}\nTemplate fingerprint: {(installed.TryGetValue("TemplateFingerprint", out var f) ? f.Value : "(none recorded)")}";
        var after = $"{(mode == "release" ? "Release of template pack" : "Roll back to")} {version} -- the job {_releases.JobName} publishes it, verifies it and records it\n"
                  + TemplateReleases.Describe(diff, methods) + $"\nAccepted selection fingerprint: {fp}";
        return new ChangePreview(c, now, after, why, warnings);
    }

    // ---------------------------------------------------------------- template conformance (nothing is written)

    /// "Take the new template" (take = true) or "keep mine and acknowledge" for one item whose template moved under the
    /// customer's override. Staged with the template content and the override base the Admin reviewed, so a commit after
    /// either moved writes nothing (Stale).
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewTemplateDecisionAsync(string kind, string key, bool take, string reason, CancellationToken ct)
    {
        var why = TemplateConformance.Validate(kind ?? "", key ?? "");
        if (why.Count > 0) return (null, why);
        var (_, versioning) = await _conformance.SchemaAsync(ct);
        if (!versioning) return (null, new[] { TemplateConformance.MissingSchemaMessage });
        var item = await _conformance.ItemAsync(kind!, key!, ct);
        if (item is null) return (null, new[] { $"{kind}/{key} is not in the template conformance view" });
        var state = item.Row.Conformance;
        if (take && state is not (TemplateConformance.UpgradeAvailable or TemplateConformance.Overridden or TemplateConformance.Disabled))
            return (null, new[] { $"{kind}/{key} already follows the template ({state}) -- nothing to take" });
        if (!take && state != TemplateConformance.UpgradeAvailable)
            return (null, new[] { $"{kind}/{key} has no template upgrade waiting ({state}) -- nothing to acknowledge" });
        return (new StagedChange
        {
            Kind = take ? ChangeKinds.TemplateTake : ChangeKinds.TemplateKeep,
            Title = take ? $"Take the new template for {kind}/{key}" : $"Keep my version of {kind}/{key} (acknowledge template {item.Row.TemplateVersion})",
            Data = new(StringComparer.Ordinal)
            {
                ["itemKind"] = kind, ["itemKey"] = key, ["expectedContentHash"] = item.Row.ContentHash, ["expectedBaseHash"] = item.Row.BaseHash,
                ["templateVersion"] = item.Row.TemplateVersion, ["reason"] = N(reason),
            },
        }, Array.Empty<string>());
    }

    private async Task<ChangePreview> PreviewTemplateAsync(StagedChange c, CancellationToken ct)
    {
        var kind = c.Get("itemKind") ?? ""; var key = c.Get("itemKey") ?? "";
        var why = TemplateConformance.Validate(kind, key).ToList();
        var warnings = new List<string>();
        if (why.Count > 0) return new ChangePreview(c, "", "", why, warnings);
        var (_, versioning) = await _conformance.SchemaAsync(ct);
        if (!versioning) return new ChangePreview(c, "", "", new[] { TemplateConformance.MissingSchemaMessage }, warnings);
        var item = await _conformance.ItemAsync(kind, key, ct);
        if (item is null || item.Row.State is null) return new ChangePreview(c, "(not overridden)", "", new[] { "the item is no longer overridden -- discard this change" }, warnings);
        if ((item.Row.BaseHash ?? "") != (c.Get("expectedBaseHash") ?? "")) why.Add("your version changed since this was staged -- discard it and stage it again");
        if (c.Kind == ChangeKinds.TemplateKeep && item.Row.ContentHash != c.Get("expectedContentHash")) why.Add("the template changed since this was staged -- discard it and stage it again");
        var now = $"Your version ({item.Row.State}), made against template {item.Row.BaseVersion ?? "(unknown)"}\n{item.OverrideBody ?? "(no body -- the item is switched off)"}";
        var after = c.Kind == ChangeKinds.TemplateTake
            ? $"The template as published ({item.Row.TemplateVersion})\n{item.TemplateBody}"
            : $"Your version, unchanged, acknowledged against template {item.Row.TemplateVersion}\n{item.OverrideBody}";
        return new ChangePreview(c, now, after, why, warnings);
    }

    // ---------------------------------------------------------------- connectors (cfg.Connector, phase E)

    public static ConnectorWrite ConnectorOf(StagedChange c) => new(
        c.Get("name") ?? "", c.Get("action") ?? "Set", c.Get("kind") ?? "", c.Get("direction") ?? "vulnerability", c.Get("enabled") == "true", c.Get("mode") ?? "whatif",
        c.Get("allowCreate") == "true", c.Get("allowClose") == "true", N(c.Get("settingsJson")), N(c.Get("secretRefsJson")), N(c.Get("mappingJson")),
        long.TryParse(c.Get("expectedVersion"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null, c.Get("reason"));

    /// Stage a connector change (validated first -- a refused one is never staged). Nothing is written.
    public static (StagedChange? Change, IReadOnlyList<string> Problems) NewConnector(ConnectorWrite w, string? title = null, IReadOnlyCollection<string>? outputsOn = null)
    {
        var why = ConnectorRepository.Validate(w);
        if (why.Count > 0) return (null, why);
        // #903: "Switch on" of the ServiceNow data-out connector also switches its outputs on (SI_DataOut_Outputs) at commit
        var outs = (outputsOn ?? Array.Empty<string>()).Where(o => ServiceNowDataOut.Outputs.Contains(o)).Distinct().ToList();
        if (outs.Count > 0 && !(w.Action == "Set" && w.Enabled && ServiceNowDataOut.Is(w.Kind, w.Direction)))
            return (null, new[] { "only switching on the ServiceNow data-out connector switches its outputs on" });
        static string B(bool b) => b ? "true" : "false";
        return (new StagedChange
        {
            Kind = ChangeKinds.Connector,
            Title = title ?? (w.Action == "Reset" ? $"Remove the connector {w.Name}" : (w.ExpectedVersion is null ? "Add" : "Change") + $" the connector {w.Name} ({w.Kind}, {(w.Enabled ? "enabled" : "disabled")}, {w.Mode})"),
            Data = new(StringComparer.Ordinal)
            {
                ["name"] = w.Name, ["action"] = w.Action, ["kind"] = w.Kind, ["direction"] = w.Direction, ["enabled"] = B(w.Enabled), ["mode"] = w.Mode,
                ["allowCreate"] = B(w.AllowCreate), ["allowClose"] = B(w.AllowClose), ["settingsJson"] = w.SettingsJson, ["secretRefsJson"] = w.SecretRefsJson,
                ["mappingJson"] = w.MappingJson, ["reason"] = N(w.Reason), ["expectedVersion"] = w.ExpectedVersion?.ToString(CultureInfo.InvariantCulture),
                ["outputsOn"] = outs.Count > 0 ? string.Join(";", outs) : null,
            },
        }, why);
    }

    /// The connector written; then (#903) the outputs a "Switch on" of the data-out connector switches on -- said when they
    /// could not be (the connector is written either way; nothing is silent).
    private async Task<WriteResult> CommitConnectorAsync(StagedChange c, string by, CancellationToken ct)
    {
        var r = await _connectors.WriteAsync(ConnectorOf(c), by, ct);
        var outs = OutputsOnOf(c);
        if (r.Status != WriteStatus.Saved || outs.Count == 0) return r;
        if (_dataOut is null) return r with { Message = r.Message + " -- its outputs were NOT switched on here: switch them on on Connectors > Fields sent" };
        var (ok, message) = await _dataOut.SwitchOnAsync(outs, by, c.Get("reason") ?? c.Title, ct);
        return r with { Message = r.Message + (ok ? "; " : " -- but ") + message };
    }

    /// #903: the ServiceNow outputs a staged "Switch on" of the data-out connector switches on with it.
    public static IReadOnlyList<string> OutputsOnOf(StagedChange c) =>
        (c.Get("outputsOn") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(o => ServiceNowDataOut.Outputs.Contains(o)).ToList();

    private static string DescribeConnector(ConnectorWrite w) => string.Join("\n", new[]
    {
        $"{w.Name}: {w.Kind}, {w.Direction}, {(w.Enabled ? "enabled" : "disabled")}, mode {w.Mode}, create {(w.AllowCreate ? "on" : "off")}, close {(w.AllowClose ? "on" : "off")}",
        "settings: " + (w.SettingsJson ?? "{}"), "secret references (Key Vault names): " + (w.SecretRefsJson ?? "{}"), "mapping: " + (w.MappingJson ?? "(none)"),
    });

    // ---------------------------------------------------------------- building (nothing is written)

    public static ExemptionRequest ExemptionOf(StagedChange c) => new(
        c.Get("scope") ?? "", N(c.Get("reportName")), N(c.Get("configurationId")), N(c.Get("cve")), N(c.Get("assetKey")), N(c.Get("assetName")),
        c.Get("reason") ?? "",
        DateTime.TryParse(c.Get("expiresAt"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var e) ? e : null,
        N(c.Get("domain")));

    private static string? N(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    public (StagedChange? Change, IReadOnlyList<string> Problems) NewExemption(ExemptionRequest r)
    {
        var why = _exemptions.Validate(r);
        if (why.Count > 0) return (null, why);
        return (new StagedChange
        {
            Kind = ChangeKinds.Exemption,
            Title = "Exempt " + ExemptionRepository.Describe(r),
            Data = new(StringComparer.Ordinal)
            {
                ["scope"] = r.Scope, ["reportName"] = r.ReportName, ["configurationId"] = r.ConfigurationId, ["cve"] = r.Cve,
                ["assetKey"] = r.AssetKey, ["assetName"] = r.AssetName, ["reason"] = r.Reason.Trim(),
                ["expiresAt"] = r.ExpiresAt?.ToString("o", CultureInfo.InvariantCulture), ["domain"] = r.Domain,
            },
        }, why);
    }

    public static (StagedChange? Change, IReadOnlyList<string> Problems) NewRevoke(string exemptionId, string describe, string reason)
    {
        if (string.IsNullOrWhiteSpace(reason) || reason.Trim().Length < 3) return (null, new[] { "give a reason (at least 3 characters)" });
        return (new StagedChange
        {
            Kind = ChangeKinds.ExemptionRevoke, Title = "Revoke exemption: " + describe,
            Data = new(StringComparer.Ordinal) { ["exemptionId"] = exemptionId, ["describe"] = describe, ["reason"] = reason.Trim() },
        }, Array.Empty<string>());
    }

    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewPinAsync(TierAsset asset, string tier, string reason, CancellationToken ct)
    {
        if (!int.TryParse(tier, NumberStyles.Integer, CultureInfo.InvariantCulture, out var t) || t is < 0 or > 3) return (null, new[] { "an asset can be pinned to Tier 0, 1, 2 or 3" });
        if (asset.Tier == tier) return (null, new[] { $"{asset.AssetName} is already Tier {tier}" });
        if (string.IsNullOrWhiteSpace(asset.AssetName)) return (null, new[] { "the asset has no name to match a rule on" });
        var (key, body) = RuleTemplates.Pin(asset.AssetKey, asset.AssetName, asset.AssetKind, t, string.IsNullOrWhiteSpace(reason) ? "pinned in the management GUI" : reason.Trim());
        var problems = DocumentValidator.Validate("rule", key, body, Array.Empty<string>());
        if (problems.Count > 0) return (null, problems);
        var existing = await _documents.ReadAsync("rule", key, ct);
        return (new StagedChange
        {
            Kind = ChangeKinds.TierPin, Title = $"Pin {asset.AssetName} to Tier {t} (now {Label(asset.Tier)})",
            Data = new(StringComparer.Ordinal)
            {
                ["assetKey"] = asset.AssetKey, ["assetName"] = asset.AssetName, ["assetKind"] = asset.AssetKind, ["fromTier"] = asset.Tier, ["tier"] = tier,
                ["docKey"] = key, ["body"] = body, ["reason"] = N(reason), ["expectedVersion"] = existing?.Version.ToString(CultureInfo.InvariantCulture),
            },
        }, Array.Empty<string>());
    }

    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewRuleDisableAsync(string ruleKey, string reason, CancellationToken ct)
    {
        if (!DocumentValidator.RuleKey().IsMatch(ruleKey ?? "")) return (null, new[] { $"'{ruleKey}' is not '<engine>/<rule id>' (engine: endpoint, identity, azure or shared)" });
        var existing = await _documents.ReadAsync("rule", ruleKey!, ct);
        return (new StagedChange
        {
            Kind = ChangeKinds.RuleDisable, Title = $"Turn off the tier rule {ruleKey}",
            Data = new(StringComparer.Ordinal)
            {
                ["ruleKey"] = ruleKey, ["docKey"] = ruleKey, ["body"] = RuleTemplates.Disable(ruleKey!), ["reason"] = N(reason),
                ["expectedVersion"] = existing?.Version.ToString(CultureInfo.InvariantCulture),
            },
        }, Array.Empty<string>());
    }

    /// Move a whole rule to another tier: a cfg.ItemOverride 'ruletier' row (the engine applies it to the rule in force).
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewRuleTierAsync(string ruleKey, string tier, string reason, CancellationToken ct)
    {
        if (!ItemOverrideRepository.RuleTierKey().IsMatch(ruleKey ?? "")) return (null, new[] { $"'{ruleKey}' is not '<engine>/<rule id>'" });
        if (!int.TryParse(tier, NumberStyles.Integer, CultureInfo.InvariantCulture, out var t) || t is < 0 or > 3) return (null, new[] { "a rule can be moved to Tier 0, 1, 2 or 3" });
        var body = ItemOverrideRepository.RuleTierBody(ruleKey!, t);
        var why = ItemOverrideRepository.Validate(ItemOverrideAt(ruleKey!, ItemOverrideRepository.StateOverride, body, reason));
        if (why.Count > 0) return (null, why);
        var existing = await _overrides.ReadAsync(ItemOverrideRepository.RuleTierKind, ruleKey!, ct);
        if (existing is { State: ItemOverrideRepository.StateOverride, Tier: { } now } && now == t) return (null, new[] { $"the tier rule {ruleKey} is already moved to Tier {t}" });
        return (new StagedChange
        {
            Kind = ChangeKinds.RuleTier, Title = $"Move the tier rule {ruleKey} to Tier {t}",
            Data = new(StringComparer.Ordinal) { ["ruleKey"] = ruleKey, ["tier"] = tier, ["body"] = body, ["reason"] = N(reason) },
        }, Array.Empty<string>());
    }

    /// Put a moved rule back in its own tiers: the 'ruletier' row goes back to 'inherit' (Set-SIProItem removes it).
    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewRuleTierResetAsync(string ruleKey, string reason, CancellationToken ct)
    {
        if (!ItemOverrideRepository.RuleTierKey().IsMatch(ruleKey ?? "")) return (null, new[] { $"'{ruleKey}' is not '<engine>/<rule id>'" });
        var existing = await _overrides.ReadAsync(ItemOverrideRepository.RuleTierKind, ruleKey!, ct);
        if (existing is null) return (null, new[] { $"the tier rule {ruleKey} is not moved to another tier -- nothing to put back" });
        return (new StagedChange
        {
            Kind = ChangeKinds.RuleTierReset, Title = $"Put the tier rule {ruleKey} back in its own tiers",
            Data = new(StringComparer.Ordinal) { ["ruleKey"] = ruleKey, ["reason"] = N(reason) },
        }, Array.Empty<string>());
    }

    /// #527 (4): the Risk factors page -- change ONE data-model item (a factor 'risk-factors:<id>' or a provider mapping
    /// 'mappings/<provider>:<key>') of the Pro data model in SQL: state 'override' (body = the item's JSON), 'disable', or
    /// 'inherit' (back to the shipped template). Validated now (nothing is staged for a refused one) and again on commit.
    public Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewDataModelItemAsync(string key, string state, string? body, string reason, CancellationToken ct)
    {
        var why = DataModelItemValidator.Validate(key ?? "", state ?? "", body);
        if (why.Count > 0) return Task.FromResult<(StagedChange?, IReadOnlyList<string>)>((null, why));
        var verb = state switch { ItemOverrideRepository.StateOverride => "Change", ItemOverrideRepository.StateDisable => "Turn off", _ => "Put back the shipped" };
        return Task.FromResult<(StagedChange?, IReadOnlyList<string>)>((new StagedChange
        {
            Kind = ChangeKinds.DataModelItem, Title = $"{verb} data-model item {key}",
            Data = new(StringComparer.Ordinal) { ["itemKey"] = key, ["state"] = state, ["body"] = state == ItemOverrideRepository.StateOverride ? body : null, ["reason"] = N(reason) },
        }, Array.Empty<string>()));
    }
    private static ItemOverrideWrite ItemOverrideAt(string ruleKey, string state, string? body, string? reason) =>
        new(ItemOverrideRepository.RuleTierKind, ruleKey, state, body, reason);

    private static ItemOverrideWrite? AsItemOverride(StagedChange c) => c.Kind switch
    {
        ChangeKinds.RuleTier => ItemOverrideAt(c.Get("ruleKey") ?? "", ItemOverrideRepository.StateOverride, c.Get("body"), c.Get("reason") ?? c.Title),
        ChangeKinds.RuleTierReset => ItemOverrideAt(c.Get("ruleKey") ?? "", ItemOverrideRepository.StateInherit, null, c.Get("reason") ?? c.Title),
        ChangeKinds.DataModelItem => new ItemOverrideWrite(DataModelItemValidator.Kind, c.Get("itemKey") ?? "", c.Get("state") ?? "", c.Get("body"), c.Get("reason") ?? c.Title),
        _ => null,
    };

    private static string Describe(ItemOverrideRow? r) => r is null
        ? "(not moved -- the rule sets its own tiers)"
        : r.State == ItemOverrideRepository.StateOverride && r.Tier is { } t ? $"Moved to Tier {t}\n{r.BodyJson}" : r.State + (r.BodyJson is null ? "" : "\n" + r.BodyJson);

    public async Task<(StagedChange? Change, IReadOnlyList<string> Problems)> NewDocumentAsync(string kind, string key, string action, string? body, long? expectedVersion, string? reason, CancellationToken ct)
    {
        var w = new DocumentWrite(kind, key, action, body, expectedVersion, reason);
        var why = DocumentRepository.Validate(w, await KnownReportsAsync(ct));
        if (why.Count > 0) return (null, why);
        return (new StagedChange
        {
            Kind = ChangeKinds.Document,
            Title = OwnershipMapValidator.Is(kind, key)
                ? (action == "Reset" ? "Remove the CMDB ownership map (back to the shipped default)" : "Save the CMDB ownership map")
                : (action == "Reset" ? "Remove " : "Save ") + $"the {kind} document {key}",
            Data = new(StringComparer.Ordinal)
            {
                ["docKind"] = kind, ["docKey"] = key, ["action"] = action, ["body"] = body, ["reason"] = N(reason),
                ["expectedVersion"] = expectedVersion?.ToString(CultureInfo.InvariantCulture),
            },
        }, Array.Empty<string>());
    }

    public static string Label(string tier) => tier == ProDataFilters.Unclassified ? "unclassified" : "Tier " + tier;

    /// The Risk Analysis report names an exclusions document may name: those in the newest collection, plus the keys
    /// already stored. Empty (and so refusing every report key) when the data backend cannot be read.
    public async Task<IReadOnlyCollection<string>> KnownReportsAsync(CancellationToken ct)
    {
        if (_cache.TryGetValue("si-known-reports", out IReadOnlyCollection<string>? hit) && hit is not null) return hit;
        var set = new HashSet<string>(StringComparer.Ordinal);
        try { foreach (var r in (await _data.ReportNamesAsync(ct)).Data) set.Add(r); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "report names could not be read from sidata"); }
        try { foreach (var d in await _documents.ListAsync("exclusions", ct)) if (d.Key != "global") set.Add(d.Key); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "exclusions documents could not be read"); }
        _cache.Set("si-known-reports", (IReadOnlyCollection<string>)set, TimeSpan.FromMinutes(10));
        return set;
    }

    // ---------------------------------------------------------------- staging

    public Task<IReadOnlyList<StagedChange>> PendingAsync(ClaimsPrincipal user, CancellationToken ct) => _store.ListAsync(user, ct);
    public Task StageAsync(ClaimsPrincipal user, StagedChange change, CancellationToken ct)
    {
        var d = ChangeAccess.Check(_access, user, change);
        if (!d.Allowed) throw new UnauthorizedAccessException(d.Reason);
        return _store.AddAsync(user, change, ct);
    }
    public Task DiscardAsync(ClaimsPrincipal user, IEnumerable<string> ids, CancellationToken ct) => _store.RemoveAsync(user, ids, ct);

    // ---------------------------------------------------------------- review

    private static DocumentWrite? AsDocument(StagedChange c)
    {
        long? ev = long.TryParse(c.Get("expectedVersion"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : null;
        return c.Kind switch
        {
            ChangeKinds.TierPin or ChangeKinds.RuleDisable => new DocumentWrite("rule", c.Get("docKey") ?? "", "Set", c.Get("body"), ev, c.Get("reason") ?? c.Title),
            ChangeKinds.Document => new DocumentWrite(c.Get("docKind") ?? "", c.Get("docKey") ?? "", c.Get("action") ?? "Set", c.Get("body"), ev, c.Get("reason")),
            _ => null,
        };
    }

    public async Task<IReadOnlyList<ChangePreview>> PreviewAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        var list = new List<ChangePreview>();
        foreach (var c in await _store.ListAsync(user, ct))
        {
            var p = await PreviewAsync(c, ct);
            // access is re-checked on every review: a scope taken away since staging makes the change uncommittable
            var d = ChangeAccess.Check(_access, user, c);
            list.Add(d.Allowed ? p : p with { Problems = p.Problems.Append("not allowed for you: " + d.Reason).ToList() });
        }
        return await WithDataOutRuleAsync(list, ct);
    }

    /// #903: the one-on rule over EVERY pending connector change together -- "Test off, Prod on" is fine as one set; two
    /// data-out connectors switched on after the set is refused, on each change that switches one on.
    private async Task<IReadOnlyList<ChangePreview>> WithDataOutRuleAsync(List<ChangePreview> list, CancellationToken ct)
    {
        var writes = list.Where(p => p.Change.Kind == ChangeKinds.Connector).Select(p => ConnectorOf(p.Change)).ToList();
        if (!writes.Any(w => w.Action == "Set" && w.Enabled && ServiceNowDataOut.Is(w.Kind, w.Direction))) return list;
        IReadOnlyList<ConnectorRow> rows;
        try { rows = await _connectors.TableExistsAsync(ct) ? await _connectors.ListAsync(ct) : Array.Empty<ConnectorRow>(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the connectors could not be read for the one-on rule"); return list; }
        return list.Select(p => p.Change.Kind == ChangeKinds.Connector && ServiceNowDataOut.FinalConflict(ConnectorOf(p.Change), rows, writes) is { } why
            ? p with { Problems = p.Problems.Append(why).ToList() } : p).ToList();
    }

    public async Task<ChangePreview> PreviewAsync(StagedChange c, CancellationToken ct)
    {
        var warnings = new List<string>();
        try
        {
            if (_handlers.FirstOrDefault(h => h.Handles(c.Kind)) is { } handler) return await handler.PreviewAsync(c, ct);
            switch (c.Kind)
            {
                case ChangeKinds.Exemption:
                {
                    var r = ExemptionOf(c);
                    if (r.ExpiresAt is null && await _exemptions.WithDefaultPeriodAsync(r, ct) is { ExpiresAt: { } until })
                    {
                        // #252: no open-ended exemption unless the setting allows it -- the default period applies
                        warnings.Add($"No end date was given: the default exemption period applies (until {until.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}).");
                        r = r with { ExpiresAt = until };
                    }
                    var why = _exemptions.Validate(r).ToList();
                    if (!await _exemptions.TableExistsAsync(ct)) why.Add("this database has no cfg.Exemption table yet -- nothing can be exempted until the Pro settings schema is updated");
                    return new ChangePreview(c, "(no exemption)", "Exemption: " + ExemptionRepository.Describe(r) + "\nReason: " + r.Reason, why, warnings);
                }
                case ChangeKinds.ExemptionRevoke:
                    return new ChangePreview(c, "Exemption: " + c.Get("describe"), "(revoked -- the findings count again from the next run)", Array.Empty<string>(), warnings);
                case ChangeKinds.TemplateTake:
                case ChangeKinds.TemplateKeep:
                    return await PreviewTemplateAsync(c, ct);
                case ChangeKinds.TemplateRelease:
                case ChangeKinds.TemplateRollback:
                    return await PreviewTemplateReleaseAsync(c, ct);
                case ChangeKinds.Connector:
                {
                    var w = ConnectorOf(c);
                    var why = ConnectorRepository.Validate(w).ToList();
                    if (!await _connectors.TableExistsAsync(ct)) { why.Add(ConnectorRepository.MissingTableMessage); return new ChangePreview(c, "(no cfg.Connector table)", DescribeConnector(w), why, warnings); }
                    var cur = await _connectors.ReadAsync(w.Name, ct);
                    if ((cur?.Version) != w.ExpectedVersion) why.Add("the connector changed since this was staged -- discard it and stage it again");
                    if (w.Action == "Set" && w.Enabled && w.Mode == "apply" && w.AllowClose)
                        warnings.Add("This connector will CLOSE items in the other system from its next run (the close-loop's guards still apply). Run it in whatif first if it is new.");
                    var outs = OutputsOnOf(c);
                    if (w.Action == "Set" && w.Enabled && ServiceNowDataOut.Is(w.Kind, w.Direction))
                        warnings.Add("This is the ServiceNow data-out connector: from the next data-out run it SENDS to its instance" + (outs.Count > 0 ? " -- and this change also switches on " + string.Join(" and ", outs.Select(o => SI.Management.Web.Outputs.ServiceNowOutputs.Of(o)?.Label ?? o)) + " (" + SI.Management.Web.Pages.Reports.OutputFieldsModel.OutputsSetting + ")" : "") + ".");
                    return new ChangePreview(c, cur is null ? "(no connector)" : DescribeConnector(ConnectorRepository.FromRow(cur, "Set", null)), w.Action == "Reset" ? "(removed)" : DescribeConnector(w) + (outs.Count > 0 ? "\nalso switches on: " + string.Join(", ", outs) : ""), why, warnings);
                }
                case ChangeKinds.DataModelItem:
                {
                    var w = AsItemOverride(c)!;
                    var why = ItemOverrideRepository.Validate(w).ToList();
                    if (!await _overrides.TableExistsAsync(ct)) { why.Add(ItemOverrideRepository.MissingTableMessage); return new ChangePreview(c, "(no cfg.ItemOverride table)", w.Body ?? w.State, why, warnings); }
                    var cur = await _overrides.ReadAsync(w.Kind, w.ItemKey, ct);
                    if (w.State == ItemOverrideRepository.StateInherit && cur is null) why.Add("the item already follows the shipped template -- discard this change");
                    var before = cur is null ? "(the shipped template)" : cur.State + (cur.BodyJson is null ? "" : "\n" + cur.BodyJson);
                    var after = w.State switch { ItemOverrideRepository.StateOverride => w.Body ?? "", ItemOverrideRepository.StateDisable => "(turned off)", _ => "(the shipped template)" };
                    return new ChangePreview(c, before, after, why, warnings);
                }                case ChangeKinds.RuleTier:
                case ChangeKinds.RuleTierReset:
                {
                    var w = AsItemOverride(c)!;
                    var why = ItemOverrideRepository.Validate(w).ToList();
                    if (!await _overrides.TableExistsAsync(ct))
                    {
                        why.Add(ItemOverrideRepository.MissingTableMessage);
                        return new ChangePreview(c, "(no cfg.ItemOverride table)", w.State == ItemOverrideRepository.StateInherit ? "(not moved)" : w.Body ?? "", why, warnings);
                    }
                    var cur = await _overrides.ReadAsync(w.Kind, w.ItemKey, ct);
                    if (w.State == ItemOverrideRepository.StateInherit && cur is null) why.Add("the rule is not moved to another tier any more -- discard this change");
                    return new ChangePreview(c, Describe(cur), w.State == ItemOverrideRepository.StateInherit ? "(not moved -- the rule sets its own tiers again)" : $"Moved to Tier {ItemOverrideRepository.TierOf(w.Body)}\n{w.Body}", why, warnings);
                }
                default:
                {
                    var w = AsDocument(c) ?? throw new InvalidOperationException($"unknown change kind '{c.Kind}'");
                    var why = DocumentRepository.Validate(w, await KnownReportsAsync(ct)).ToList();
                    var cur = await _documents.ReadAsync(w.Kind, w.Key, ct);
                    if ((cur?.Version) != w.ExpectedVersion) why.Add("the document changed since this was staged -- discard it and stage it again");
                    if (c.Kind == ChangeKinds.TierPin && int.TryParse(c.Get("tier"), out var to) && int.TryParse(c.Get("fromTier"), out var from) && to > from)
                        warnings.Add($"Tiers combine as the LOWEST of every matching rule: this pin cannot make the asset less critical than Tier {from} on its own -- also change the rule that set Tier {from}.");
                    return new ChangePreview(c, cur?.Body ?? "(no document)", w.Action == "Reset" ? "(removed)" : w.Body ?? "", why, warnings);
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "previewing change {Id} failed", c.Id);
            return new ChangePreview(c, "", "", new[] { "the current state could not be read: " + ex.Message }, warnings);
        }
    }

    // ---------------------------------------------------------------- commit

    /// The stored row a staged change writes (its staging target, else its kind and key) -- the attribution's key.
    public static string AttributionKey(StagedChange c)
    {
        if (CacheStagingStore.TargetOf(c) is { } target) return target;
        var key = new[] { "key", "itemKey", "name", "serviceNumber", "docKey", "ruleKey", "assetKey", "exemptionId" }.Select(c.Get).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
        if (key is null)
        {
            // an exemption has no stored key until it is written: its scope and what it covers name it
            var what = string.Join("|", new[] { c.Get("scope"), c.Get("reportName"), c.Get("configurationId") ?? c.Get("cve"), c.Get("assetName") }.Where(v => !string.IsNullOrWhiteSpace(v)));
            key = what.Length > 0 ? what : c.Id;
        }
        return c.Kind + ":" + key;
    }

    private static readonly HashSet<string> RemoveActions = new(["reset", "remove", "unlink", "delete"], StringComparer.OrdinalIgnoreCase);

    /// A removal (reset, revoke, back to inherit, remove, unlink) or a set.
    public static string AttributionOp(StagedChange c) =>
        c.Kind is ChangeKinds.ExemptionRevoke or ChangeKinds.RuleTierReset || c.Kind == ChangeKinds.DataModelItem && c.Get("state") == ItemOverrideRepository.StateInherit || c.Get("action") is { } a && RemoveActions.Contains(a)
            ? SI.Management.Web.Audit.AttributionOps.Remove : SI.Management.Web.Audit.AttributionOps.Set;

    /// The committer initiated it (staging is per person, so the stager IS the committer); no approval applies to a commit.
    public static SI.Management.Web.Audit.AttributionEntry AttributionOf(StagedChange c, string by) =>
        new(AttributionKey(c), by, SI.Management.Web.Audit.AttributionKinds.Change, AttributionOp(c)) { Title = c.Title };

    public async Task<IReadOnlyList<CommitOutcome>> CommitAsync(ClaimsPrincipal user, IReadOnlyCollection<string> ids, CancellationToken ct)
    {
        var by = user.ChangeName();
        var pending = await _store.ListAsync(user, ct);
        var outcomes = new List<CommitOutcome>();
        // role + scope, server-side, for EVERY selected change before ANY is written: one refused = the whole commit is
        // refused with the reason, and nothing is written
        var selected = pending.Where(p => ids.Contains(p.Id)).ToList();
        var refusedAccess = selected.Select(c => (c, d: ChangeAccess.Check(_access, user, c))).Where(x => !x.d.Allowed).ToList();
        if (refusedAccess.Count > 0)
        {
            var why = $"{refusedAccess.Count} of the {selected.Count} selected change(s) are outside your access, so nothing was committed. {refusedAccess[0].c.Title}: {refusedAccess[0].d.Reason}";
            return selected.Select(c => new CommitOutcome(c, WriteStatus.Refused, why)).ToList();
        }
        // #903: a change that switches a ServiceNow data-out connector OFF is written before one that switches one ON, so
        // "Test off, Prod on" in one commit never meets the one-on rule half way (the order is stable otherwise)
        foreach (var c in selected.OrderBy(x => x.Kind == ChangeKinds.Connector ? ServiceNowDataOut.CommitOrder(ConnectorOf(x)) : 0).ToList())
        {
            WriteResult r;
            try
            {
                var handler = _handlers.FirstOrDefault(h => h.Handles(c.Kind));
                r = handler is not null ? await handler.CommitAsync(c, by, ct) : c.Kind switch
                {
                    ChangeKinds.Exemption => await _exemptions.CreateAsync(ExemptionOf(c), by, ct),
                    ChangeKinds.ExemptionRevoke => await _exemptions.RevokeAsync(c.Get("exemptionId") ?? "", c.Get("reason") ?? "", by, ct),
                    ChangeKinds.RuleTier or ChangeKinds.RuleTierReset or ChangeKinds.DataModelItem => await _overrides.WriteAsync(AsItemOverride(c)!, by, ct),
                    // the actor is the signed-in identity (by), never a value carried in the staged change
                    ChangeKinds.TemplateTake => await _conformance.TakeAsync(c.Get("itemKind") ?? "", c.Get("itemKey") ?? "", c.Get("expectedBaseHash"), c.Get("reason") ?? c.Title, by, ct),
                    ChangeKinds.TemplateKeep => await _conformance.KeepAsync(c.Get("itemKind") ?? "", c.Get("itemKey") ?? "", c.Get("expectedContentHash") ?? "", c.Get("reason") ?? c.Title, by, ct),
                    ChangeKinds.Connector => await CommitConnectorAsync(c, by, ct),
                    // the job is started with the fingerprint the Admin accepted; the actor is the signed-in identity (by)
                    ChangeKinds.TemplateRelease or ChangeKinds.TemplateRollback => await _releases.StartAsync(c.Get("mode") ?? "", c.Get("version") ?? "", MethodsOf(c), c.Get("fingerprint") ?? "", by, c.Get("reason") ?? c.Title, ct, c.Get("class")),
                    _ => await _documents.WriteAsync(AsDocument(c) ?? throw new InvalidOperationException($"unknown change kind '{c.Kind}'"), await KnownReportsAsync(ct), by, ct),
                };
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogError(ex, "committing change {Id} ({Kind}) failed", c.Id, c.Kind);
                r = new WriteResult(WriteStatus.Refused, "the write failed: " + ex.Message);
            }
            outcomes.Add(new CommitOutcome(c, r.Status, r.Message));
        }
        // #302 (AUDIT-1.1): AT COMMIT, who initiated each change the jobs will put in force -- under this request's
        // correlation id (the commit's audit event and its change rows carry the same id), keyed by the changed target so
        // a removal is still attributed after the row is gone. A template release is a job start: recorded by the jobs client.
        if (_attribution is not null)
        {
            var entries = outcomes.Where(o => o.Status == WriteStatus.Saved && o.Change.Kind is not (ChangeKinds.TemplateRelease or ChangeKinds.TemplateRollback))
                .Select(o => AttributionOf(o.Change, by)).ToList();
            if (entries.Count > 0) await _attribution.RecordAsync(SI.Management.Web.Audit.ChangeAttribution.CorrelationId(), entries, ct);
        }
        var done = outcomes.Where(o => o.Status == WriteStatus.Saved).Select(o => o.Change.Id).ToList();
        if (done.Count > 0) await _store.RemoveAsync(user, done, ct);
        if (outcomes.Any(o => o.Change.Kind == ChangeKinds.Document && o.Status == WriteStatus.Saved)) _cache.Remove("si-known-reports");
        return outcomes;
    }
}
