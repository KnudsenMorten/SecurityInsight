using System.Text.RegularExpressions;
using SI.Management.Web.Jobs;
using SI.Management.Web.Settings;

namespace SI.Management.Web.GetStarted;

/// This install's own resource names, as the permission fix needs them (null = not known here).
public sealed record PermissionFixInstall(string? SubscriptionId, string? ResourceGroup, string? IdentityName, string? TaggingIdentityName,
    string? WorkspaceResourceId, string? StorageAccountName, string? StorageResourceGroup, string? DcrResourceGroup, bool AppRegistration);

/// The fix for one identity's missing permissions: who runs it, where, and the COMPLETE commands (download from
/// invardia.com + run, this install's values filled in). <see cref="Commands"/> null = the values are not known here; the
/// page then shows the catalog's own text.
public sealed record PermissionFixBlock(string Script, string Who, string Where, string? Commands, string? Unknown);

/// <summary>
/// GET STARTED > PERMISSIONS, how to fix (owner 2026-10-11: "impossible to understand this. where is the url to download
/// the script from invardia and why not have a copy cmdlet"; framework section 12.19 SCRIPT-PLUS-PREFILLED-COMMAND): each
/// missing permission in plain words, and per identity ONE block -- who must run it, where, and the commands to download
/// the script from https://invardia.com/support/si/ and run it with THIS install's names filled in (never a placeholder),
/// with a Copy button. The values come from the install's settings (the Pro database) and the web app's own Jobs section;
/// Grant-SIIdentity is always given the install's workspace, storage and DCR resource group, because without them it falls
/// back to an old configuration's names. Pure.
/// </summary>
public static class GetStartedPermissionFix
{
    public const string UrlBase = "https://invardia.com/support/si/";
    public const string GrantScript = "Grant-SIIdentity";
    public const string DefaultTaggingIdentity = "uami-securityinsight-tagging";

    // a value pasted into a command: resource names and ids only -- anything else is treated as not known
    private static readonly Regex Safe = new(@"^[A-Za-z0-9][A-Za-z0-9._()/-]{0,400}$", RegexOptions.CultureInvariant);
    private static readonly Regex Guid = new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant);
    private static readonly Regex V3Rg = new(@"^rg-si-(?<label>(r0|r1|r2|prod)-(community|pro)-(ca|vm)(-[a-z0-9][a-z0-9-]*)?)$", RegexOptions.CultureInvariant);

    private static string? Value(IReadOnlyList<SettingRow> rows, string name)
    {
        var v = MailMode.Plain(MailMode.RowOf(rows, name)?.ValueJson)?.Trim();
        return string.IsNullOrEmpty(v) || !Safe.IsMatch(v) ? null : v;
    }

    // the Log Analytics workspace's resource id as setup records it: it starts with '/', which a resource NAME never does
    private static readonly Regex WorkspaceId = new(
        @"^/subscriptions/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/resourceGroups/[A-Za-z0-9._()-]{1,90}/providers/Microsoft\.OperationalInsights/workspaces/[A-Za-z0-9][A-Za-z0-9-]{2,62}$",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    /// The workspace this install recorded (SI_WorkspaceResourceId) -- the one the command must name: the collection
    /// identity reads THAT workspace, wherever it is and whatever it is called. Null when it is not a workspace's resource id.
    private static string? Workspace(IReadOnlyList<SettingRow> rows)
    {
        var v = MailMode.Plain(MailMode.RowOf(rows, "SI_WorkspaceResourceId")?.ValueJson)?.Trim().TrimEnd('/');
        return string.IsNullOrEmpty(v) || !WorkspaceId.IsMatch(v) ? null : v;
    }

    private static string? First(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v) && Safe.IsMatch(v.Trim()))?.Trim();

    /// <summary>
    /// The install's names: the settings setup wrote (SI_AzSubscriptionId, SI_Bootstrap_ResourceGroupName,
    /// SI_Bootstrap_ManagedIdentityName, SI_WorkspaceResourceId, SI_StorageAccount, ...), else the web app's Jobs section
    /// (its subscription and resource group), else -- on a v3 resource group rg-si-&lt;label&gt; -- the names setup gives
    /// inside it (id-si-&lt;label&gt;, log-si-&lt;label&gt;; setup\_shared\SI-SetupNaming.ps1). Storage has no such rule: unknown
    /// stays unknown.
    /// </summary>
    public static PermissionFixInstall Resolve(IReadOnlyList<SettingRow>? settings, JobsOptions? jobs)
    {
        var rows = settings ?? Array.Empty<SettingRow>();
        var ws = Workspace(rows);
        var wsParts = ws?.Split('/', StringSplitOptions.RemoveEmptyEntries) ?? Array.Empty<string>();
        var sub = First(Value(rows, "SI_AzSubscriptionId"), Value(rows, "SI_Bootstrap_SubscriptionId"), jobs?.SubscriptionId,
            wsParts.Length > 1 ? wsParts[1] : null);
        if (sub is not null && !Guid.IsMatch(sub)) sub = null;
        var rg = First(Value(rows, "SI_Bootstrap_ResourceGroupName"), jobs?.ResourceGroup);
        var label = rg is not null && V3Rg.Match(rg) is { Success: true } m ? m.Groups["label"].Value : null;
        var identity = First(Value(rows, "SI_Bootstrap_ManagedIdentityName"), label is null ? null : "id-si-" + label);
        if (ws is null && sub is not null && rg is not null)
        {
            var wsName = First(Value(rows, "SI_WorkspaceName"), label is null ? null : "log-si-" + label);
            var wsRg = First(Value(rows, "SI_WorkspaceResourceGroup"), rg);
            if (wsName is not null) ws = $"/subscriptions/{sub}/resourceGroups/{wsRg}/providers/Microsoft.OperationalInsights/workspaces/{wsName}";
        }
        var auth = Value(rows, "SI_AuthMethod");
        var appReg = auth is not null && !auth.Equals("ManagedIdentity", StringComparison.OrdinalIgnoreCase);
        return new PermissionFixInstall(sub, rg, identity, First(Value(rows, "SI_Bootstrap_TaggingIdentityName"), DefaultTaggingIdentity),
            ws, Value(rows, "SI_StorageAccount"), First(Value(rows, "SI_StorageResourceGroup"), rg), First(Value(rows, "SI_DcrResourceGroup"), rg), appReg);
    }

    /// What one permission is for, in plain words.
    public static string Plain(PermissionGap gap)
    {
        var item = gap.Item.Trim();
        var what = item switch
        {
            "User.Read.All" => "users: names, departments and sign-in state for the identity profiles",
            "Group.Read.All" => "groups and their members, to see who holds access through a group",
            "Directory.Read.All" => "the directory: users, groups, devices and roles for the identity and asset profiles",
            "Device.Read.All" => "Entra devices, to match a machine to its owner and its join state",
            "Application.Read.All" => "app registrations and enterprise applications, to find privileged applications",
            "AuditLog.Read.All" => "sign-in and audit logs, for last sign-in and inactive accounts",
            "Policy.Read.All" => "Conditional Access and authentication policies",
            "RoleManagement.Read.All" or "RoleManagement.Read.Directory" => "role assignments, to know who holds privileged roles",
            "RoleManagementPolicy.Read.Directory" => "the PIM role settings (activation rules)",
            "RoleEligibilitySchedule.Read.Directory" => "PIM eligible role assignments",
            "RoleAssignmentSchedule.Read.Directory" => "PIM active role assignments",
            "PrivilegedAccess.Read.AzureADGroup" => "PIM for groups (eligible and active group members)",
            "IdentityRiskyUser.Read.All" => "risky users from Entra ID Protection",
            "IdentityRiskEvent.Read.All" => "risk detections from Entra ID Protection",
            "IdentityRiskyServicePrincipal.Read.All" => "risky service principals from Entra ID Protection",
            "ThreatHunting.Read.All" => "advanced hunting in Microsoft Defender XDR (exposure and device data)",
            "UserAuthenticationMethod.Read.All" => "users' sign-in methods (MFA registration)",
            "DeviceManagementManagedDevices.Read.All" => "Intune devices: serial numbers and MAC addresses for the full asset details",
            "DeviceManagementConfiguration.Read.All" => "Intune: the compliance policies a device does not meet and its update ring",
            "AccessReview.Read.All" => "access reviews: when a privileged role, group or application was last reviewed",
            "SecurityAlert.Read.All" => "security alerts: the open alerts of each device (how many, the highest severity, the newest one)",
            "AdvancedHunting.Read.All" => "advanced hunting in Microsoft Defender XDR",
            "Machine.Read.All" => "Defender for Endpoint devices and their vulnerabilities",
            "Vulnerability.Read.All" => "the exploit details of a vulnerability from Defender (verified exploit, exploit kit, exposed devices)",
            "SecurityRecommendation.Read.All" => "the exposure impact and active alert of a Defender recommendation",
            "SecurityEvents.Read.All" => "the Microsoft Secure Score of the tenant, sent with the hourly status report",
            "Score.Read.All" => "the Defender exposure score of the tenant, sent with the hourly status report",
            "Machine.ReadWrite.All" => "writing asset tags on Defender for Endpoint devices (asset tagging only)",
            "CustomSecAttributeAssignment.ReadWrite.All" => "writing custom security attributes (asset tagging only)",
            "Reader" => "reading the Azure resources SecurityInsight collects (the subscription or management group)",
            "Tag Contributor" => "writing Azure tags (asset tagging only)",
            _ => null,
        };
        var area = gap.Area.Trim();
        // not a permission at all: the engine could not reach the database ("connection (the database could not be
        // reached: its firewall refused this job)") -- said as that, never as something "missing" on the identity
        if (item.StartsWith("connection (", StringComparison.OrdinalIgnoreCase) && item.EndsWith(')'))
            return $"{area}: {item["connection (".Length..^1]}.";
        return what is null ? $"{area}: {item} is missing." : $"{area} {item} is missing -- it is needed for {what}.";
    }

    /// True when this gap's fix is a grant of an application permission or an Azure role (Grant-SIIdentity's job) --
    /// a database role has its own fix.
    public static bool Grantable(PermissionGap gap) => gap.Fix.Contains(GrantScript, StringComparison.OrdinalIgnoreCase);

    private static string Arg(string name, string value) => " -" + name + " " + (Regex.IsMatch(value, @"^[A-Za-z0-9._/-]+$") ? value : "'" + value.Replace("'", "''") + "'");

    /// <summary>
    /// The block for one identity's grantable gaps. Tagging = the identity is asset tagging's own (its gaps' fix says
    /// -Tagging, or its label names asset tagging). An install on an app registration gets Grant-SIIdentity -AppId with the
    /// identity's client id; a managed identity gets Grant-SIIdentity with the install's identity; both get the install's
    /// workspace, storage and DCR resource group.
    /// </summary>
    public static PermissionFixBlock Build(IReadOnlyList<PermissionGap> gaps, string? identityClientId, string? identityLabel, PermissionFixInstall install)
    {
        var api = gaps.Any(g => !g.Area.Equals("Azure", StringComparison.OrdinalIgnoreCase));
        var azure = gaps.Any(g => g.Area.Equals("Azure", StringComparison.OrdinalIgnoreCase));
        var can = new List<string>();
        if (api || !azure) can.Add("grant application permissions and give admin consent (Privileged Role Administrator or Global Administrator in Entra ID)");
        if (azure) can.Add("assign Azure roles on the subscription (Owner or User Access Administrator)");
        var who = "An admin who can " + string.Join(", and ", can) + ".";
        const string where = "Azure Cloud Shell (PowerShell), or PowerShell 7 on your own computer -- the script opens a browser sign-in; no PowerShell module is needed.";
        string Download(string s) => $"Invoke-WebRequest {UrlBase}{s}.ps1 -OutFile {s}.ps1";

        var tagging = gaps.Any(g => g.Fix.Contains("-Tagging", StringComparison.OrdinalIgnoreCase))
            || (identityLabel ?? "").Contains("tagging", StringComparison.OrdinalIgnoreCase);
        var name = tagging ? install.TaggingIdentityName : install.IdentityName;
        var appId = identityClientId?.Trim();
        var appReg = install.AppRegistration && !tagging;
        var missing = new List<string>();
        if (appReg) { if (string.IsNullOrEmpty(appId) || !Guid.IsMatch(appId)) missing.Add("the app registration's client id"); }
        else
        {
            if (name is null) missing.Add("the identity's name");
            if (install.ResourceGroup is null) missing.Add("the install's resource group");
        }
        if (install.SubscriptionId is null) missing.Add("the subscription");
        if (install.WorkspaceResourceId is null) missing.Add("the Log Analytics workspace");
        if (missing.Count > 0) return new(GrantScript, who, where, null, string.Join(", ", missing));

        var cmd = "./" + GrantScript + ".ps1" + (appReg ? Arg("AppId", appId!) : Arg("IdentityName", name!) + Arg("IdentityResourceGroup", install.ResourceGroup!))
            + Arg("SubscriptionId", install.SubscriptionId!) + Arg("WorkspaceResourceId", install.WorkspaceResourceId!);
        if (install.StorageAccountName is not null) cmd += Arg("StorageAccountName", install.StorageAccountName) + Arg("StorageResourceGroup", install.StorageResourceGroup ?? install.ResourceGroup!);
        if (install.DcrResourceGroup is not null) cmd += Arg("DcrResourceGroup", install.DcrResourceGroup);
        // the collection identity also gets what it needs to create its tables and rules, as the guided install grants
        // it: a run creates them and gives itself no role, so an install repaired from here must hold those roles too
        if (tagging) cmd += " -Tagging";
        else cmd += " -AllowSchemaCreate";
        cmd += " -Apply";
        return new(GrantScript, who, where, Download(GrantScript) + "\n" + cmd, null);
    }
}
