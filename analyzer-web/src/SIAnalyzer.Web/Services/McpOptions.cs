namespace SIAnalyzer.Web.Services;

/// <summary>
/// The MCP server's surface options (audit #11). Bound from "SIAnalyzer:Mcp".
///
/// The MCP endpoint is the surface an AGENT talks to, so the default has to be the narrow one:
/// everything it can reach only reads. The single tool that acts outside the app -
/// <c>send_exec_summary_email</c>, which mails the configured executive recipients - is therefore
/// opt-in. It stays available to humans regardless, via the UI, <c>POST /api/email/send</c> and
/// the scheduler; this flag only governs whether an MCP client can trigger it.
/// </summary>
public sealed class McpOptions
{
    public const string SectionName = "SIAnalyzer:Mcp";

    /// <summary>
    /// Expose <c>send_exec_summary_email</c> on the MCP surface. OFF by default: an agent
    /// connecting to <c>/mcp</c> gets a read-only tool catalogue, and a call to the tool by name is
    /// refused rather than merely hidden.
    /// </summary>
    public bool AllowEmailSend { get; set; }
}
