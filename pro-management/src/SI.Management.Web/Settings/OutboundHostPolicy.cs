namespace SI.Management.Web.Settings;

/// <summary>
/// THE HOSTS A SECRET OR THE INSTALL'S OWN CREDENTIAL MAY GO TO, checked when a person saves the setting (the engine applies
/// the same rules when it uses the value, and leaves a value it refuses out of the run with a warning):
///   OpenAI_endpoint        https, an Azure OpenAI / Azure AI services host (engine: Test-SIOpenAIEndpoint)
///   SI_Telemetry_Endpoint  https, invardia.com or a subdomain of it (engine: Test-SITelemetryEndpointHost)
///   SI_Pro_DataSqlServer   an Azure SQL server host, public or sovereign cloud (engine: Test-SIAzureSqlHost)
///   SI_Pro_DataSqlDatabase a database name, never a connection-string fragment (engine: Test-SISqlDatabaseName)
///   SI_LicenseRequest_BaseUrl  https, invardia.com or a subdomain of it -- the install key goes there (engine: Get-SILicenceRequestBaseUrl)
/// An empty value is always allowed (the default applies).
/// </summary>
public static class OutboundHostPolicy
{
    public static readonly IReadOnlyList<string> OpenAiSuffixes =
        [".openai.azure.com", ".cognitiveservices.azure.com", ".services.ai.azure.com", ".openai.azure.us", ".cognitiveservices.azure.us", ".openai.azure.cn", ".cognitiveservices.azure.cn",
         // an Azure API Management gateway in front of Azure OpenAI
         ".azure-api.net", ".azure-api.us", ".azure-api.cn"];

    public static readonly IReadOnlyList<string> AzureSqlSuffixes =
        [".database.windows.net", ".database.usgovcloudapi.net", ".database.chinacloudapi.cn", ".database.cloudapi.de"];

    public const string InvardiaDomain = "invardia.com";

    private static bool Under(string host, string suffix) => host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) && host.Length > suffix.Length;

    /// Null = the value may be stored for this setting; else why not (a sentence fragment after the setting's name).
    public static string? WhyNot(string setting, string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0) return null;
        switch (setting)
        {
            case "OpenAI_endpoint":
                if (!HttpsHost(v, out var oh, out var why)) return why;
                return OpenAiSuffixes.Any(s => Under(oh, s)) ? null : "must be your Azure OpenAI endpoint (https://<name>.openai.azure.com or https://<name>.cognitiveservices.azure.com)";
            case "SI_Telemetry_Endpoint":
            case "SI_LicenseRequest_BaseUrl":
                if (!HttpsHost(v, out var th, out var twhy)) return twhy;
                return th.Equals(InvardiaDomain, StringComparison.OrdinalIgnoreCase) || Under(th, "." + InvardiaDomain) ? null : "must be an Invardia address (https://...invardia.com)";
            case "SI_Pro_DataSqlServer":
                var host = v.StartsWith("tcp:", StringComparison.OrdinalIgnoreCase) ? v[4..] : v;
                var comma = host.IndexOf(','); if (comma >= 0) host = host[..comma];
                if (host.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '.'))) return "must be an Azure SQL server name (<name>.database.windows.net)";
                return AzureSqlSuffixes.Any(s => Under(host, s)) ? null : "must be an Azure SQL server name (<name>.database.windows.net)";
            case "SI_Pro_DataSqlDatabase":
                return v.Length > 128 || v.Any(c => c is ';' or '=' or '\'' or '"' or '[' or ']' or '{' or '}' || char.IsControl(c)) ? "must be a database name" : null;
            default:
                return null;
        }
    }

    private static bool HttpsHost(string v, out string host, out string? why)
    {
        host = ""; why = null;
        if (!Uri.TryCreate(v, UriKind.Absolute, out var u)) { why = "must be an https address"; return false; }
        if (u.Scheme != Uri.UriSchemeHttps) { why = "must be an https address"; return false; }
        if (!string.IsNullOrEmpty(u.UserInfo)) { why = "must not carry a user name"; return false; }
        host = u.Host;
        return true;
    }
}
