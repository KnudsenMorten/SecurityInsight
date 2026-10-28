using SI.Management.Core;

namespace SI.Management.Web.ChatView;

/// One answer bubble: the rendered (safe) answer HTML, the basis line, the calls behind it, and whether those show
/// under the answer (SIWeb_Chat_ShowToolCalls) or only on demand.
public sealed record ChatAnswerView(string Html, string Basis, IReadOnlyList<ToolCallTrace> Tools, bool ShowToolCalls);
