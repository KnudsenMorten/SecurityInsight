namespace Sia.Web.Services;

/// <summary>
/// Bound from the "Sia" config section (appsettings + env). Holds NO secrets in source -
/// the workspace id + OpenAI endpoint/deployment are injected by the host environment
/// (App Service / Container Apps app settings, themselves Key-Vault-backed). The data
/// plane authenticates with Managed Identity (no key); OpenAI may use MI or a key.
/// </summary>
public sealed class SiaOptions
{
    public const string SectionName = "Sia";

    /// <summary>Log Analytics workspace GUID (customerId) to query, READ-ONLY via MI.
    /// In the hosted internal env this is set to the internal SI workspace = the default base.</summary>
    public string? WorkspaceId { get; set; }

    /// <summary>Force the demo-data path (the explicit fallback, e.g. local preview).</summary>
    public bool UseDemoData { get; set; }

    /// <summary>Azure OpenAI endpoint (https://&lt;name&gt;.openai.azure.com). AI is ON when set.</summary>
    public string? OpenAiEndpoint { get; set; }

    /// <summary>Azure OpenAI deployment name (the model deployment).</summary>
    public string? OpenAiDeployment { get; set; }

    /// <summary>Optional Azure OpenAI key. When absent, the app uses Managed Identity for OpenAI.</summary>
    public string? OpenAiApiKey { get; set; }

    /// <summary>Lookback window for the management timeline (days).</summary>
    public int TimelineLookbackDays { get; set; } = 180;
}
