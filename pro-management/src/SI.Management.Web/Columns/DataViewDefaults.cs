using SI.Management.Core.ProData;
using K = SI.Management.Core.ProData.DataColumnKeys;

namespace SI.Management.Web.Columns;

/// <summary>
/// THE shipped layouts of the data views (owner 2026-10-11: "you need t go through all 17 views and enable all relevant
/// columns per view (beter more than too little) ... i cannot see what app it is related. no remediation, nothing" and
/// "we need both ids like sub id + sub names. dont leave out info, better more than less"). Every view opens with the
/// context that makes a row readable on its own -- for a finding the affected software (name, vendor, version), the
/// description, the fix and remediation, more details, published date and exploit details, the CMDB group; for a CI its
/// id, identifier values, owner, department, OS, IP, subscription, CMDB and last seen -- and every reference as its id AND
/// its name (<see cref="Pairs"/>, completed by <see cref="Complete"/>). A person or an Admin may choose otherwise; these
/// are only the columns a view opens with.
/// </summary>
public static class DataViewDefaults
{
    /// The CI as a reference and its identifiers (values) and linked objects.
    public static readonly IReadOnlyList<string> CiIdentity =
        [K.CiId, K.Id("MdeDeviceId"), K.Id("AadDeviceId"), K.Id("AzureResourceId"), K.Id("ExposureGraphNodeId"), K.Links];

    /// What a CI is and who answers for it -- the CROSS-CLASS context (owner 2026-10-11: "rich context, single overview,
    /// ability to prioritize"): what a row of ANY class can carry -- owner, department, environment, subscription, the
    /// support group that fixes it, the CMDB item. A view that mixes classes (the findings, the CIs at risk, All CIs) opens
    /// with this; what only one class carries (<see cref="ClassContext"/>) is one click away in the chooser -- never forty
    /// mostly-empty columns in a mixed view.
    public static readonly IReadOnlyList<string> CiContext =
    [
        K.Field("si_owner"), K.Field("si_department"), K.Field("si_environment"), K.Field("si_os_name"), K.Field("si_os_version"),
        K.Field("si_ip_address"), K.Field("si_hostname"), K.Field("si_azure_subscription_id"), K.Field("si_azure_subscription_name"),
        K.Field("si_azure_resource_group"), K.Field("si_management_group_path"), K.Field("si_service_support_group"), K.Field("si_service_support_group_id"),
        K.Field("si_cmdb_id"), K.Field("si_cmdb_name"), K.Field("si_last_seen"),
    ];

    /// <summary>
    /// What ONE class of CI carries and a person prioritises on, per class (the CI document FIELDS, in the order shown) --
    /// the sources' own suggestions for a default layout:
    /// devices (primary user, encrypted, Autopilot enrolled, the last Intune check-in, device value, the OPEN alerts and
    /// their highest severity, alerts in 30 days, on a public network, the last admin logon), Azure resources
    /// (subscription, environment, backup, pending critical updates, the Defender plan tier) and public IPs (what it is
    /// attached to, an expired certificate, the earliest certificate expiry). A view opens with them when its rows are of
    /// that ONE class (All CIs filtered to a class); every field is a prepared, typed column either way.
    /// <para>The identity class has no entry: a user and a service principal carry different things, so identities open
    /// with a layout per KIND (<see cref="IdentityKindContext"/>) -- and with the cross-class context only while both
    /// kinds are in the list.</para>
    /// </summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> ClassContext = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
    {
        ["device"] =
        [
            "si_primary_user_upn", "si_primary_user_id", "si_is_encrypted", "si_autopilot_enrolled", "si_intune_last_sync", "si_device_value", "si_open_alerts",
            "si_open_alerts_highest_severity", "si_alerts_30d", "si_on_public_network", "si_last_admin_logon",
        ],
        ["cloud_resource"] =
        [
            "si_azure_subscription_name", "si_environment", "si_management_group_name", "si_backup_protected", "si_pending_critical_patches", "si_defender_plan_tier",
        ],
        ["public_ip"] = ["si_attached_resource_name", "si_attached_resource_id", "si_tls_cert_expired", "si_tls_earliest_expiry"],
    };

    /// The class identities have in the data model (the class filter's value).
    public const string IdentityClass = "identity";
    /// The kind of identity a person is: a member or a guest user.
    public const string UserKind = "user";
    /// The kind of identity a workload is: a service principal or a managed identity.
    public const string ServicePrincipalKind = "service_principal";

    /// <summary>
    /// What ONE KIND of identity carries (owner 2026-10-11: "Split users / service principals"; no half-empty columns):
    /// users -- sign-in name, MFA strength, Conditional Access enforces MFA, risk level, the role paths, the level inside
    /// Tier 0 in words (where set), the manager (sign-in name + id), the last interactive sign-in; service principals
    /// (managed identities too) -- the owners (sign-in names + ids), the days until a credential expires and what to do
    /// about it, the resource the identity is attached to (name + id), the last app sign-in. Every field is a prepared,
    /// typed column.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, IReadOnlyList<string>> IdentityKindContext = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
    {
        [UserKind] =
        [
            "si_upn", "si_mfa_strength", "si_ca_mfa_enforced", "si_entra_risk_level", "si_role_paths", "si_privilege_tier_level_text", "si_manager_upn", "si_manager_id",
            "si_last_interactive_sign_in",
        ],
        [ServicePrincipalKind] =
        [
            "si_owner_upns", "si_owner_ids", "si_credential_expiry_days", "si_credential_fix", "si_attached_resource", "si_attached_resource_id", "si_last_app_sign_in",
        ],
    };

    /// <summary>
    /// The kind of identity an ASSET TYPE names -- the values the data carries in the CI's asset type (sidata.Ci.AssetType,
    /// the asset type filter of All CIs): the classification's names (data-model/classification: User, Guest, Service
    /// principal, Managed identity) and the sources' own they are made from (value maps identity_type_user /
    /// identity_type_sp: user, guest, service_principal, managed_identity). A guest is a user; a managed identity is a
    /// service principal. Null for any other type (Other: a group, a computer object ...).
    /// </summary>
    public static string? IdentityKindOf(string? assetType) =>
        (assetType ?? "").Trim().Replace('_', ' ').ToLowerInvariant() switch
        {
            "user" or "guest" => UserKind,
            "service principal" or "managed identity" => ServicePrincipalKind,
            _ => null,
        };

    /// Every field a class or a kind of identity opens with (what the guards hold to "a prepared column, a catalog field").
    public static IEnumerable<string> ClassFields => ClassContext.Values.Concat(IdentityKindContext.Values).SelectMany(f => f);

    /// The class context of the ONE class a view is filtered to (its fields; empty for no class, several, or one unknown).
    public static IReadOnlyList<string> ForClass(IReadOnlyCollection<string> classes) => ForClass(classes, Array.Empty<string>());

    /// <summary>
    /// The context of what a view is filtered to: ONE class -> that class's fields; the identity class -> the fields of
    /// the ONE kind of identity the asset type filter names (<paramref name="assetTypes"/>: every chosen type is of the
    /// same kind). Identities with no asset type chosen, with both kinds chosen, or with a type of neither kind are a
    /// mixed list: empty, so the view opens with the cross-class context only. Empty too for no class, several classes or
    /// one unknown.
    /// </summary>
    public static IReadOnlyList<string> ForClass(IReadOnlyCollection<string> classes, IReadOnlyCollection<string> assetTypes)
    {
        if (classes.Count != 1) return Array.Empty<string>();
        var cls = classes.First().Trim();
        if (!cls.Equals(IdentityClass, StringComparison.OrdinalIgnoreCase))
            return ClassContext.TryGetValue(cls, out var fields) ? fields : Array.Empty<string>();
        var kinds = assetTypes.Where(t => !string.IsNullOrWhiteSpace(t)).Select(IdentityKindOf).Distinct().ToList();
        return kinds.Count == 1 && kinds[0] is { } kind && IdentityKindContext.TryGetValue(kind, out var ofKind) ? ofKind : Array.Empty<string>();
    }

    /// <summary>
    /// The tier board's table (the CI grid's own column keys, every one a stored column): what the asset is, its tier, who
    /// decided it and why in one sentence, who answers for it (the owner, the department), where it runs, how much is at
    /// risk and when it was last seen. <see cref="Complete"/> adds the other half of each reference (the owner's object id
    /// next to the owner).
    /// </summary>
    public static readonly IReadOnlyList<string> TierBoard =
        ["Name", "CiId", "Class", "AssetType", "Tier", "TierSetBy", "TierExplanation", "Owner", "Department", "Environment", "RiskScore", "WeightedRiskScore", "OpenFindings", "LastSeen"];

    /// What a finding is about and what to do about it -- with what the sources say about how urgent it is: the exploit
    /// probability (EPSS), the CVE tags, whether it is mitigated, whether the software is still supported, who fixes it by
    /// when, and the evidence.
    public static readonly IReadOnlyList<string> FindingContext =
    [
        K.Component, K.Software, K.Vendor, K.Version, K.Description, K.Evidence, K.Fix, K.FixId, K.Remediation, K.FixOwner, K.FixDue, K.MoreDetails, K.Published, K.Exploit,
        K.Epss, K.CveTags, K.Mitigation, K.EosStatus, K.EosDate, K.Category, K.Subcategory, K.Impact, K.CmdbId, K.Cmdb, K.CmdbCriticality,
    ];

    /// <summary>
    /// The finding's ONE component ("Component (finding)": OS, SQL, Browser ...) -- not to be mistaken for what is installed
    /// on the asset ("Installed on asset (CI)", the CI's component list). Owner 2026-10-19: shown by default, the first
    /// column of the finding context. A PREPARED column (fc.component: view-stored-columns.json, sidata.Finding.Component
    /// and sidata.IssueContext.Component, si-data-schema.sql); the list changed, so the next data sync prepares every
    /// collection once more -- until then a collection's component is read from its finding rows, as every context column.
    /// </summary>
    public static readonly string FindingComponent = K.Component;

    /// The finding context of an aggregate row (a CVE, an issue): the same plus its affected assets.
    public static readonly IReadOnlyList<string> IssueContext = [.. FindingContext, K.Assets];

    /// <summary>
    /// The references that are shown as a PAIR -- id and name -- wherever one of them is shown: (what, id keys, name keys).
    /// A key is a view's own column key or an extra column key; <see cref="Complete"/> adds the first missing half the view
    /// knows, right after the half it has. A half the data does not carry yet shows empty (the pair still stands).
    /// </summary>
    public static readonly IReadOnlyList<(string What, IReadOnlyList<string> Ids, IReadOnlyList<string> Names)> Pairs =
    [
        ("CI", new[] { "AssetKey", "CiId", K.CiId, "TopAssetKey" }, new[] { "AssetName", "Name", "TopAssetName", K.Field("si_asset_name") }),
        ("subscription", new[] { K.Field("si_azure_subscription_id"), "AzureSubscriptionId" }, new[] { K.Field("si_azure_subscription_name"), "AzureSubscriptionName" }),
        ("management group", new[] { K.Field("si_management_group_id"), "ManagementGroupId" },
            new[] { K.Field("si_management_group_path"), "ManagementGroupPath", K.Field("si_management_group_name"), "ManagementGroupName" }),
        // one name for one thing: only fields of the field catalog. A resource group, a service principal and a group have
        // no id field of their own, and the general owner (si_owner) has none either -- so they are no pair
        ("tenant", new[] { K.Field("si_azure_tenant_id"), "AzureTenantId" }, new[] { K.Field("si_azure_tenant_name"), "AzureTenantName" }),
        ("app", new[] { K.Field("si_app_id"), "AppId" }, new[] { K.Field("si_app_name"), "AppName" }),
        // the owners of an app registration / a service principal (a list each): their sign-in names and their ids
        ("owners", new[] { K.Field("si_owner_ids"), "OwnerIds" }, new[] { K.Field("si_owner_upns"), "OwnerUpns" }),
        ("CMDB item", new[] { "CmdbId", K.Field("si_cmdb_id"), K.CmdbId }, new[] { "CmdbName", K.Field("si_cmdb_name"), K.Cmdb }),
        ("service", new[] { "ServiceKey", "ServiceNumber", "ExternalId" }, new[] { "ServiceName" }),
        ("department", new[] { "DepartmentId" }, new[] { "DepartmentName", "Department" }),
        // the references the sources add (owner 2026-10-11: "we need both ids like sub id + sub names")
        ("support group", new[] { K.Field("si_service_support_group_id"), "ServiceSupportGroupId" }, new[] { K.Field("si_service_support_group"), "ServiceSupportGroup" }),
        ("assignment group", new[] { K.Field("si_service_assignment_group_id"), "ServiceAssignmentGroupId" }, new[] { K.Field("si_service_assignment_group"), "ServiceAssignmentGroup" }),
        ("service owner", new[] { K.Field("si_service_owner_id"), "ServiceOwnerId" }, new[] { K.Field("si_service_owner"), "ServiceOwner" }),
        ("CMDB support group", new[] { K.Field("si_cmdb_support_group_id"), "CmdbSupportGroupId" }, new[] { K.Field("si_cmdb_support_group"), "CmdbSupportGroup" }),
        ("CMDB assignment group", new[] { K.Field("si_cmdb_assignment_group_id"), "CmdbAssignmentGroupId" }, new[] { K.Field("si_cmdb_assignment_group"), "CmdbAssignmentGroup" }),
        ("CMDB owner", new[] { K.Field("si_cmdb_owner_id"), "CmdbOwnerId" }, new[] { K.Field("si_cmdb_owner"), "CmdbOwner" }),
        ("primary user", new[] { K.Field("si_primary_user_id"), "PrimaryUserId" },
            new[] { K.Field("si_primary_user_upn"), "PrimaryUserUpn", K.Field("si_primary_user_name"), "PrimaryUserName", K.Field("si_primary_user"), "PrimaryUser" }),
        ("manager", new[] { K.Field("si_manager_id"), "ManagerId" }, new[] { K.Field("si_manager_upn"), "ManagerUpn", K.Field("si_manager_name"), "ManagerName" }),
        ("attached resource", new[] { K.Field("si_attached_resource_id"), "AttachedResourceId" },
            new[] { K.Field("si_attached_resource_name"), "AttachedResourceName", K.Field("si_attached_resource"), "AttachedResource" }),
        ("backup vault", new[] { K.Field("si_backup_vault_id"), "BackupVaultId" }, new[] { K.Field("si_backup_vault_name"), "BackupVaultName" }),
    ];

    /// <summary>
    /// The layout with every pair whole: for each reference one half of which is in the layout, the other half (the first
    /// key of that half the view knows) is added -- after the layout's own keys, so the columns a view always had keep their
    /// places. Keys the view does not know are left out.
    /// </summary>
    public static IReadOnlyList<string> Complete(IEnumerable<string> keys, Func<string, string?> known)
    {
        var list = keys.Select(known).Where(k => k is not null).Select(k => k!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var (_, ids, names) in Pairs)
        {
            var id = list.Any(k => ids.Contains(k, StringComparer.OrdinalIgnoreCase));
            var name = list.Any(k => names.Contains(k, StringComparer.OrdinalIgnoreCase));
            if (id && !name && names.Select(known).FirstOrDefault(k => k is not null) is { } n) list.Add(n);
            else if (name && !id && ids.Select(known).FirstOrDefault(k => k is not null) is { } i) list.Add(i);
        }
        return list;
    }

    /// <summary>
    /// The pairs a layout breaks: (what, the half it shows) for every reference shown without its other half although the
    /// view could show it (<paramref name="known"/>). A half no view of these rows can carry is a DATA gap, not a layout one.
    /// </summary>
    public static IReadOnlyList<(string What, string Shown)> Broken(IReadOnlyCollection<string> keys, Func<string, string?> known)
    {
        var broken = new List<(string, string)>();
        foreach (var (what, ids, names) in Pairs)
        {
            var id = keys.FirstOrDefault(k => ids.Contains(k, StringComparer.OrdinalIgnoreCase));
            var name = keys.FirstOrDefault(k => names.Contains(k, StringComparer.OrdinalIgnoreCase));
            if (id is not null && name is null && names.Any(n => known(n) is not null)) broken.Add((what, id));
            if (name is not null && id is null && ids.Any(i => known(i) is not null)) broken.Add((what, name));
        }
        return broken;
    }

    /// <summary>
    /// The shipped layout of a SQL grid: its own visible columns, the context its rows can carry inserted where it reads
    /// best, every pair completed. <paramref name="spec"/> names the grid (<see cref="GridSpec.Name"/>).
    /// </summary>
    public static IReadOnlyList<string> ForGrid(GridSpec spec, RowCiKey ci, RowFindingKey findings, Func<string, string?> known)
    {
        var own = spec.Columns.Where(c => !c.Hidden).Select(c => c.Key).ToList();
        IReadOnlyList<string> context = findings == RowFindingKey.None ? Array.Empty<string>() : findings == RowFindingKey.FindingId ? FindingContext : IssueContext;
        // a grid with a component column of its own (the CI findings: sidata.CiFinding.Component) shows that one, not both
        if (own.Contains("Component", StringComparer.OrdinalIgnoreCase)) context = context.Where(k => k != K.Component).ToList();
        // the view's own columns first, in the order they always had (a link, a bookmark, a habit stays valid); the context
        // after them -- one row per CVE is the exception: the software takes the title's place (never the generic "Update
        // vulnerable software" alone)
        List<string> keys = spec.Name == "vulns"
            ? new List<string> { "Cve", K.Software, K.Vendor, K.Version, "Severity", "Cvss", "HasExploit", K.Exploit, K.Epss, K.CveTags, K.Mitigation, K.EosStatus,
                K.EosDate, K.Description, K.Fix, K.FixId, K.Remediation, K.FixOwner, K.FixDue, K.MoreDetails, K.Published, "Assets", K.Assets, "Findings", "MaxRisk",
                "TotalRisk", "Tier", "Tier0Findings", "OpenItems", "OldestOpen" }
            : own.Concat(context).ToList();
        if (ci != RowCiKey.None)
        {
            // the CI's own key column (often hidden), then its identity and context
            keys.AddRange(new[] { "AssetKey", "CiId" }.Where(k => !keys.Contains(k, StringComparer.OrdinalIgnoreCase)));
            var findingRows = spec.Name is "rows" or "department" or "cifindings" or "findingchanges" or "exemptions";
            keys.AddRange(findingRows ? new[] { K.CiId, K.Id("MdeDeviceId") } : CiIdentity);
            keys.AddRange(CiContext);
        }
        // a reference the grid carries hidden next to a shown one (a CMDB id, a service key) becomes visible as its pair
        return Complete(keys, known);
    }

    /// The keys with <paramref name="add"/> inserted after the first of <paramref name="after"/> present (else at the end).
    public static List<string> Insert(IReadOnlyList<string> keys, IReadOnlyList<string> add, IReadOnlyList<string> after)
    {
        var list = keys.ToList();
        var at = after.Select(a => list.FindIndex(k => k.Equals(a, StringComparison.OrdinalIgnoreCase))).Where(i => i >= 0).DefaultIfEmpty(-1).Max();
        var missing = add.Where(a => !list.Contains(a, StringComparer.OrdinalIgnoreCase)).ToList();
        if (at < 0) list.AddRange(missing); else list.InsertRange(at + 1, missing);
        return list;
    }
}
