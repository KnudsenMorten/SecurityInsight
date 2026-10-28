using System.Text.RegularExpressions;

namespace SI.Management.Web.Settings;

/// <summary>
/// #503 (owner 2026-10-09: "companies have their own naming" -- "maybe 2 steps - create + validate would make sense as
/// step 2 then knows the name in step 1. you build the cmdlet after user fills in the name"): the shared mailbox in TWO
/// steps, on Settings > E-mail and in Get Started.
/// Step 1 "Name and create" -- the mailbox name, a domain, the display name, create or already exists; the command
/// (setup\Set-SIMail.ps1 with those values) is built from the fields and shown once the name is filled in; Save remembers
/// the address (SI_Mail_From). Step 2 "Validate" -- knows the address; one button saves it as the sender, runs the
/// restriction check and sends a test mail. The address is typed in ONE place.
/// </summary>
public sealed record SharedMailboxSteps(string MailboxName, string Domain, string DisplayName, bool Exists, IReadOnlyList<string> Domains,
    string? Remembered, string? SubscriptionId, string? ResourceGroup)
{
    public const string DefaultName = "SecurityInsight";
    /// The domain picker's "another domain" choice: the domain is then typed (no directory read is needed).
    public const string OtherDomain = "__other";

    /// The domain a step-1 form chose: a listed one, or the one typed under "another domain".
    public static string? DomainOf(string? pick, string? other) => string.Equals(pick, OtherDomain, StringComparison.Ordinal) ? other?.Trim() : pick?.Trim();
    /// The script's documentation page (framework SCRIPT-DOC-1) and its download.
    public static readonly string DocUrl = SI.Management.Web.Links.ScriptDocs.Url("Set-SIMail");

    private static readonly Regex NameRe = new("^[A-Za-z0-9._-]{1,64}$", RegexOptions.CultureInvariant);
    private static readonly Regex DomainRe = new(@"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$", RegexOptions.CultureInvariant);

    public static bool IsName(string? s) => NameRe.IsMatch((s ?? "").Trim());
    public static bool IsDomain(string? s) => DomainRe.IsMatch((s ?? "").Trim().TrimStart('@'));

    /// name@domain when both are valid, else null.
    public static string? AddressOf(string? name, string? domain) =>
        IsName(name) && IsDomain(domain) ? name!.Trim() + "@" + domain!.Trim().TrimStart('@') : null;

    private static string Q(string s) => "'" + s.Trim().Replace("'", "''") + "'";

    /// Line 1 of the block: download Set-SIMail.ps1 from invardia.com (owner 2026-10-11: "line 1: download file from
    /// invardia, line 2 (and more if needed) is the cmdlet(s)").
    public const string DownloadLine = "Invoke-WebRequest " + MailSetupFlow.ScriptUrl + " -OutFile Set-SIMail.ps1";

    /// The commands for the Exchange administrator, with the entered values: line 1 downloads the script, line 2 runs it --
    /// nothing else in the block (no checksum, no comment; the documentation link sits next to it). The same string the
    /// page builds live in the browser (wwwroot/js/app/mailbox-steps.js). Null while the name is empty or not a mailbox name.
    public static string? Command(string? name, string? domain, string? displayName, bool exists, string? subscriptionId, string? resourceGroup)
    {
        if (!IsName(name)) return null;
        var parts = new List<string> { "./Set-SIMail.ps1", "-MailboxName " + Q(name!) };
        if (IsDomain(domain)) parts.Add("-MailDomain " + Q(domain!.Trim().TrimStart('@')));
        if (!string.IsNullOrWhiteSpace(displayName)) parts.Add("-DisplayName " + Q(displayName!));
        if (exists) parts.Add("-CreateMailbox $false");
        if (!string.IsNullOrWhiteSpace(subscriptionId) && !string.IsNullOrWhiteSpace(resourceGroup))
        {
            parts.Add("-SubscriptionId " + Q(subscriptionId!));
            parts.Add("-ResourceGroup " + Q(resourceGroup!));
        }
        parts.Add("-UseSignedInAccount");
        parts.Add("-Apply");
        return DownloadLine + "\n" + string.Join(" ", parts);
    }

    public string? Address => AddressOf(MailboxName, Domain);
    public string? CommandText => Command(MailboxName, Domain, DisplayName, Exists, SubscriptionId, ResourceGroup);

    /// The steps as the settings stand: the remembered address (SI_Mail_From) gives the name and the domain; the domains
    /// offered are that one, the signed-in admin's and the tenant's initial domain (when configured).
    public static SharedMailboxSteps From(IEnumerable<SettingRow> rows, string? adminAddress, string? initialDomain, string? subscriptionId, string? resourceGroup)
    {
        var list = rows.ToList();
        var remembered = MailMode.Plain(MailMode.RowOf(list, MailMode.FromSetting)?.ValueJson)?.Trim();
        if (!SettingsForm.IsMailAddress(remembered ?? "")) remembered = null;
        string? DomainPart(string? a) => a is { } x && x.IndexOf('@') is var i and > 0 ? x[(i + 1)..].Trim() : null;
        var domains = new[] { DomainPart(remembered), DomainPart(adminAddress), initialDomain?.Trim() }
            .Where(d => IsDomain(d)).Select(d => d!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var name = remembered is { } r ? r[..r.IndexOf('@')] : DefaultName;
        return new SharedMailboxSteps(name, domains.FirstOrDefault() ?? "", DefaultName, remembered is not null, domains, remembered, subscriptionId, resourceGroup);
    }
}
