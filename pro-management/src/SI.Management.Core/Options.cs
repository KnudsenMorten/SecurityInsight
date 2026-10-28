namespace SI.Management.Core;

/// Where the estate data lives. Every value comes from configuration (section "Estate"); nothing here names a
/// tenant, workspace or server.
public sealed class EstateOptions
{
    public const string Section = "Estate";

    /// Log Analytics workspace id (the workspace's customerId GUID, not its ARM id).
    public string WorkspaceId { get; set; } = "";

    /// Azure SQL server host name of the one Pro database (schemas `vuln` and `cfg`).
    public string SqlServer { get; set; } = "";

    /// The Pro database name.
    public string SqlDatabase { get; set; } = "";

    /// The Risk Analysis edition marker: both editions write the same RA tables, and only rows whose
    /// SolutionVersion ends with this suffix are this edition's (engine: SI-TrendRollup.ps1, edition filter).
    public string RaEditionSuffix { get; set; } = "+v3";

    /// How far back the newest Risk Analysis snapshot is searched for (days, 1..30).
    public int SnapshotLookbackDays { get; set; } = 3;

    /// Window of the profile tables the asset-identity map is built from (days, 1..30). The engine uses 8.
    public int IdentityLookbackDays { get; set; } = 8;

    /// `vuln.VulnerabilityItem.Source` the close-loop writes (the engine default is "SecurityInsight").
    public string VulnerabilitySource { get; set; } = "SecurityInsight";

    /// Per-query server timeout.
    public int QueryTimeoutSeconds { get; set; } = 120;
}

/// The customer's Azure OpenAI (section "Chat"). Token auth only: the identity needs the
/// "Cognitive Services OpenAI User" role on the resource. No API key is read or accepted.
public sealed class ChatOptions
{
    public const string Section = "Chat";

    public string Endpoint { get; set; } = "";
    public string Deployment { get; set; } = "";

    /// Upper bound on model round-trips per question (each may request tool calls).
    public int MaxToolRounds { get; set; } = 6;

    /// Upper bound on prior turns sent to the model.
    public int MaxHistoryTurns { get; set; } = 20;

    /// Upper bound on characters of one tool result handed back to the model.
    public int MaxToolResultChars { get; set; } = 24000;
}

/// How the process signs in (section "Identity"). Hosted: managed identity. Local: a certificate from
/// LocalMachine\My by thumbprint. Never a client secret.
public sealed class IdentityOptions
{
    public const string Section = "Identity";

    /// "ManagedIdentity" (default) or "Certificate".
    public string Mode { get; set; } = "ManagedIdentity";

    /// User-assigned managed identity client id; empty = system-assigned.
    public string ManagedIdentityClientId { get; set; } = "";

    public string TenantId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string CertificateThumbprint { get; set; } = "";
}
