namespace SI.Management.Web.RiskExec;

/// <summary>
/// #863 (owner 2026-10-21: "maybe make a note that ai support is turned off so report is not working"): the plain words every
/// page says where a part of the Risk Analysis view depends on the AI summary and the run had it off
/// (Pages/Management/_AiSummaryOff.cshtml) -- and what turns it on. Never "Top 0 risky assets" as if the run had no risk.
/// </summary>
public static class AiSummaryNote
{
    public const string Off = "The AI summary is turned off at this install.";

    public const string HowToTurnOn = "To turn it on: an Azure OpenAI deployment in your subscription, then the settings OpenAI_endpoint and OpenAI_deployment, the key stored in your Key Vault (OpenAI_apiKey), and the Risk Analysis setting BuildSummaryByAI on.";

    /// What the Top 50 risky assets page shows instead of the run's list.
    public const string TopAssetsFromDatabase = "The Risk Analysis run kept no Top 50 list, so the list below is built from the database: the active CIs by Criticality Tier (Tier 0 first), then Weighted Risk Score -- the same order as the mail.";

    /// What the page says when the list could not be built from the database either.
    public const string TopAssetsNone = "The Risk Analysis run kept no Top 50 list, and the active CIs could not be read from the database right now. The CI list sorted by Weighted Risk Score shows the riskiest assets.";

    /// What a Top list page shows with the AI summary off: the run's own list (Risk Analysis builds it without the AI, #863).
    public const string ListFromRun = "The list below is the run's own Top 50 -- Risk Analysis builds it without the AI; only the AI-written analysis is missing.";

    /// ... or, for a run that kept no list, the database's.
    public const string ListFromDatabase = "This run kept no Top 50 list (it was made before Risk Analysis built the list without the AI), so the list below is built from the database.";

    /// The AI-written analysis is not part of the run.
    public const string NoNarrative = "The AI-written analysis is not part of this run.";
}
