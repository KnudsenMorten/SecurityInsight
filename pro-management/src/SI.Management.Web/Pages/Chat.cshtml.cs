using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;
using SI.Management.Web.Auth;
using SI.Management.Web.ChatView;

namespace SI.Management.Web.Pages;

/// One turn of the conversation. Assets: the asset names (and keys) the answer's tool results carried -- what the
/// answer's highlighting and asset links are built from when the page renders the transcript again.
public sealed record ChatEntry(string Role, string Content, IReadOnlyList<ToolCallTrace> Tools, IReadOnlyList<ChatAsset>? Assets = null);

/// <summary>
/// Chat against the curated read-only tools (IChatService). Every answer can show the tool calls -- and the queries --
/// behind it: always reachable ("How was this answered?"), and shown (collapsed) under every answer when
/// SIWeb_Chat_ShowToolCalls is on. The answer itself is rendered by <see cref="ChatAnswerRenderer"/> (escaped,
/// whitelisted markup, highlights, the viewer's number format). isAdmin comes from the signed-in user's role, never
/// from the form. The conversation lives in the page (a hidden field), not on the server.
/// </summary>
public sealed class ChatModel : PageModel
{
    public const int MaxTurns = 20;
    public const int MaxQuestion = 2000;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly IChatService _chat;
    private readonly ChatDisplay _display;
    private readonly ILogger<ChatModel> _log;

    public ChatModel(IChatService chat, ChatDisplay display, ILogger<ChatModel> log) { _chat = chat; _display = display; _log = log; }

    [BindProperty] public string? Question { get; set; }
    [BindProperty] public string? TranscriptJson { get; set; }
    public List<ChatEntry> Transcript { get; private set; } = new();
    public string? Error { get; private set; }
    /// SIWeb_Chat_ShowToolCalls: the calls under every answer (collapsed), or on demand only.
    public bool ShowToolCalls { get; private set; }

    /// One answer as the bubble shows it.
    public static ChatAnswerView View(ChatEntry e, bool showToolCalls) =>
        new(ChatAnswerRenderer.Render(e.Content, e.Assets, SI.Management.Core.ProData.ScoreFormat.Culture), ChatService.Basis(e.Tools), e.Tools, showToolCalls);

    public async Task OnGetAsync(CancellationToken ct) => ShowToolCalls = await _display.ShowToolCallsAsync(ct);

    [SI.Management.Web.Audit.NotAudited("a question to the chat: read-only queries over data the asker may already see; nothing is written")]
    public async Task OnPostAsync(CancellationToken ct)
    {
        ShowToolCalls = await _display.ShowToolCallsAsync(ct);
        Transcript = Parse(TranscriptJson);
        var q = (Question ?? "").Trim();
        if (q.Length == 0) { Error = "Type a question first."; return; }
        if (q.Length > MaxQuestion) { Error = $"A question is at most {MaxQuestion} characters."; return; }
        var history = Transcript.Select(e => new ChatTurn(e.Role, e.Content)).ToList();
        try
        {
            ChatAnswer answer;
            using (SI.Management.Core.ProData.Exempted.Use(await ExemptedScopeAsync(ct))) answer = await _chat.AskAsync(history, q, User.IsAdmin(), ct);
            Transcript.Add(new ChatEntry("user", q, Array.Empty<ToolCallTrace>()));
            Transcript.Add(new ChatEntry("assistant", answer.Text, answer.ToolCalls ?? Array.Empty<ToolCallTrace>(), answer.Assets));
            if (Transcript.Count > MaxTurns) Transcript = Transcript.Skip(Transcript.Count - MaxTurns).ToList();
            Question = "";
            ModelState.Remove(nameof(Question));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "chat failed");
            Error = "The question could not be answered right now. Try again, or ask an administrator to check the chat service.";
        }
        TranscriptJson = JsonSerializer.Serialize(Transcript, Json);
        ModelState.Remove(nameof(TranscriptJson));
    }

    /// #264: the chat's data reads count exempted findings like the management numbers (SI_Exempted_CountInManagement),
    /// so an answer agrees with the dashboards -- only where the database carries the exemption mark (else unchanged).
    private async Task<SI.Management.Core.ProData.ExemptedScope?> ExemptedScopeAsync(CancellationToken ct)
    {
        var settings = HttpContext?.RequestServices.GetService<SI.Management.Web.Exemptions.ExemptionSettings>();
        var schema = HttpContext?.RequestServices.GetService<SI.Management.Web.Exemptions.IExemptedSchema>();
        if (settings is null || schema is null || !await schema.ReadyAsync(ct)) return null;
        var s = await settings.ReadAsync(ct);
        return SI.Management.Web.Exemptions.ExemptedTick.Resolve(s.CountInManagement, null);
    }

    /// What a page's chat panel posts: the question, the panel's conversation so far, and the page's context.
    public sealed record PanelQuestion(string? Question, List<ChatTurn>? History, ChatPageContext? Context);

    /// The chat panel on a Security posture / Management page (POST /Chat?handler=Ask, JSON). Same service, same
    /// curated tools, same role gate as this page (the /Chat authorization applies to the handler); the page context
    /// is sanitised again and passed as data. Always answers 200 with either an answer or an error text. The answer
    /// also comes back rendered (html: the same safe renderer as this page), with the basis line and whether the tool
    /// calls show under it (showToolCalls), so the panel looks exactly like this page.
    [SI.Management.Web.Audit.NotAudited("a question to the chat panel: read-only queries over data the asker may already see; nothing is written")]
    public async Task<IActionResult> OnPostAskAsync([FromBody] PanelQuestion? body, CancellationToken ct)
    {
        var q = (body?.Question ?? "").Trim();
        if (q.Length == 0) return new JsonResult(new { error = "Type a question first." });
        if (q.Length > MaxQuestion) return new JsonResult(new { error = $"A question is at most {MaxQuestion} characters." });
        var history = (body!.History ?? new())
            .Where(t => t is not null && (t.Role == "user" || t.Role == "assistant") && t.Content is not null)
            .TakeLast(MaxTurns).ToList();
        var context = ChatPageContext.Sanitize(body.Context);
        try
        {
            ChatAnswer answer;
            using (SI.Management.Core.ProData.Exempted.Use(await ExemptedScopeAsync(ct))) answer = await _chat.AskAsync(history, q, User.IsAdmin(), context, ct);
            var tools = answer.ToolCalls ?? Array.Empty<ToolCallTrace>();
            var show = await _display.ShowToolCallsAsync(ct);
            return new JsonResult(new
            {
                text = answer.Text,
                html = ChatAnswerRenderer.Render(answer.Text, answer.Assets, SI.Management.Core.ProData.ScoreFormat.Culture),
                basis = ChatService.Basis(tools),
                showToolCalls = show,
                toolCalls = tools,
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "chat panel failed");
            return new JsonResult(new { error = "The question could not be answered right now. Try again, or ask an administrator to check the chat service." });
        }
    }

    /// Only the two roles a conversation has are kept from the posted transcript.
    internal static List<ChatEntry> Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new();
        try
        {
            var list = JsonSerializer.Deserialize<List<ChatEntry>>(json, Json) ?? new();
            return list.Where(e => e is not null && (e.Role == "user" || e.Role == "assistant") && e.Content is not null)
                       .Select(e => e with
                       {
                           Tools = e.Tools ?? Array.Empty<ToolCallTrace>(),
                           Assets = (e.Assets ?? Array.Empty<ChatAsset>()).Where(a => a is not null && a.Name is not null).Take(ChatService.MaxAssets).ToList(),
                       })
                       .TakeLast(MaxTurns).ToList();
        }
        catch (JsonException) { return new(); }
    }
}
