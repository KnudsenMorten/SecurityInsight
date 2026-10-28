using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Settings;

namespace SI.Management.Web.ChatView;

/// <summary>
/// How the chat shows WHAT an answer rests on (operator, 2026-10-04: "the tool call should be collapsed, turn it off so
/// it doesnt show in response (make it a setting to show it)"). The web-app setting <c>SIWeb_Chat_ShowToolCalls</c>:
///   OFF (default) -- the answer stands alone; a small "How was this answered?" under it opens the tool calls and their
///                    queries on demand, so every answer stays traceable;
///   ON            -- the "Based on: ..." line and a COLLAPSED list of the tool calls sit below every answer.
/// Read with a one-minute cache; a settings read that fails reads as OFF (the calls stay reachable either way).
/// </summary>
public sealed class ChatDisplay(ISettingsStoreReader reader, IMemoryCache cache, ILogger<ChatDisplay> log)
{
    public const string Setting = "SIWeb_Chat_ShowToolCalls";
    private const string Key = "si-chat-show-tool-calls";

    public static readonly CatalogSetting Catalog = new()
    {
        Name = Setting, Label = "Chat: show the tool calls under every answer", Group = "Web app", Type = "bool",
        Engines = new[] { "management-web" }, Edition = "pro", WebOnly = true,
        Default = JsonDocument.Parse("false").RootElement.Clone(),
        Description = "OFF by default. When on, every chat answer (the Chat page and the chat panel on each page) is followed by the line naming the tools it is based on and a collapsed list of the tool calls with their queries. When off, the answer stands alone and \"How was this answered?\" under it opens the same calls on demand.",
        Purpose = "Chooses between a clean answer and an answer that always shows the evidence behind it.",
        DefaultText = "Off: only the answer; \"How was this answered?\" opens the tool calls and queries on demand",
        Effect = "On adds the \"Based on\" line and a collapsed tool-call list under every answer, for everyone. The calls and queries stay reachable either way.",
        WhenToChange = "When readers (for example auditors or analysts) want to see what each answer was based on without asking for it.",
    };

    public async Task<bool> ShowToolCallsAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(Key, out bool hit)) return hit;
        var value = false;
        try
        {
            var row = (await reader.ReadSettingsAsync(ct).ConfigureAwait(false)).Rows
                .FirstOrDefault(r => r.Scope == CatalogSetting.WebScope && r.Name.Equals(Setting, StringComparison.OrdinalIgnoreCase));
            if (row?.ValueJson is { } j)
            {
                using var d = JsonDocument.Parse(j);
                value = d.RootElement.ValueKind == JsonValueKind.True
                    || (d.RootElement.ValueKind == JsonValueKind.String && string.Equals(d.RootElement.GetString(), "true", StringComparison.OrdinalIgnoreCase));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            log.LogDebug(ex, "chat display setting could not be read -- tool calls on demand");
        }
        cache.Set(Key, value, TimeSpan.FromMinutes(1));
        return value;
    }
}
