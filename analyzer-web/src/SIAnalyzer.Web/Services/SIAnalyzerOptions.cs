namespace SIAnalyzer.Web.Services;

/// <summary>
/// Bound from the "SIAnalyzer" config section (appsettings + env). Holds NO secrets in source -
/// the workspace id + OpenAI endpoint/deployment are injected by the host environment
/// (App Service / Container Apps app settings, themselves Key-Vault-backed). The data
/// plane authenticates with Managed Identity (no key); OpenAI may use MI or a key.
/// </summary>
public sealed class SIAnalyzerOptions
{
    public const string SectionName = "SIAnalyzer";

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

    /// <summary>
    /// How long the rollup read is reused before the workspace is queried again (audit #10).
    /// The rollup pulls up to 500,000 rows across the lookback window and EIGHT AnalyzerService
    /// entry points ask for it, so without this one page load or MCP conversation re-ran that
    /// query several times over.
    ///
    /// Five minutes is well inside how often the data actually changes - a new snapshot appears
    /// only when an engine run ingests, which is hours apart. Set 0 to disable caching entirely
    /// (every call hits the workspace). A PARTIAL result is never cached whatever this says.
    /// </summary>
    public int RollupCacheSeconds { get; set; } = 300;

    /// <summary>
    /// Hard ceiling on ONE Azure OpenAI call, in seconds (audit #15). Independent of the caller's
    /// token, which is the point: the AI path had no bound of its own.
    ///
    /// The finding described this as "a slow call holds the request open". Re-verification found a
    /// worse case with no request in it at all: the SCHEDULER passes its <c>stoppingToken</c>, which
    /// is only cancelled at shutdown, and it calls the AI *after* claiming the send window
    /// (audit #9). A hung call there consumes the window and delivers nothing - silently, until the
    /// app restarts.
    ///
    /// 45s is comfortably above a normal grounded completion and far under any cadence window.
    /// Set 0 to disable the timeout (not recommended; that restores the pre-#15 behaviour).
    /// </summary>
    public int AiTimeoutSeconds { get; set; } = 45;

    /// <summary>
    /// Cap on tokens generated per AI call (audit #15). Unbounded output is what lets a call take
    /// unbounded time in the first place.
    ///
    /// ⚠️ A cap ALONE would be a new defect: a completion stopped at the limit is truncated
    /// mid-sentence, and that prose goes in front of an executive. So the cap is paired with a
    /// finish-reason check - a length-truncated narrative is DISCARDED in favour of the grounded
    /// templated summary rather than shown, and a truncated KQL is discarded outright.
    /// Set 0 to send no cap.
    /// </summary>
    public int AiMaxOutputTokens { get; set; } = 900;
}
