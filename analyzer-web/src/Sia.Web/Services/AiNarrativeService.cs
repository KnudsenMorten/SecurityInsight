using System.ClientModel;
using Azure.AI.OpenAI;
using Azure.Identity;
using OpenAI.Chat;
using Sia.Core.Ai;
using Sia.Core.Model;

namespace Sia.Web.Services;

/// <summary>Grounded, fail-soft AI narrative. Wraps Core's prompt assembly + a thin
/// Azure OpenAI call. AI is ON by default in the hosted internal env (endpoint +
/// deployment configured); if unreachable it degrades to the templated summary -
/// it never hard-fails. All output is grounded strictly in the supplied rows.</summary>
public interface IAiNarrativeService
{
    bool IsAvailable { get; }

    /// <summary>Plain-language verdict/summary grounded in the rows. Falls back to a
    /// templated summary (clearly labelled) when AI is unavailable.</summary>
    Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<RiskRow> rows, Audience audience, DiffSummary? diff = null, CancellationToken ct = default);

    /// <summary>Compose a single read-only KQL from a plain-English question. Returns null
    /// when AI is unavailable (the analyst must then write KQL directly).</summary>
    Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default);
}

/// <summary>A narrative + whether it came from AI or the grounded fallback.</summary>
public sealed record NarrativeResult(string Text, bool FromAi);

public sealed class AiNarrativeService : IAiNarrativeService
{
    private readonly ChatClient? _chat;
    private readonly ILogger<AiNarrativeService> _log;

    public AiNarrativeService(SiaOptions opts, ILogger<AiNarrativeService> log)
    {
        _log = log;
        if (!string.IsNullOrWhiteSpace(opts.OpenAiEndpoint) && !string.IsNullOrWhiteSpace(opts.OpenAiDeployment))
        {
            try
            {
                var endpoint = new Uri(opts.OpenAiEndpoint);
                var client = string.IsNullOrWhiteSpace(opts.OpenAiApiKey)
                    ? new AzureOpenAIClient(endpoint, new DefaultAzureCredential())          // MI auth (preferred in hosted env)
                    : new AzureOpenAIClient(endpoint, new ApiKeyCredential(opts.OpenAiApiKey)); // key fallback
                _chat = client.GetChatClient(opts.OpenAiDeployment);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Azure OpenAI client init failed - SIA will run AI-off (fail-soft).");
                _chat = null;
            }
        }
    }

    public bool IsAvailable => _chat is not null;

    public async Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<RiskRow> rows, Audience audience, DiffSummary? diff = null, CancellationToken ct = default)
    {
        if (_chat is null)
        {
            return new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false);
        }

        try
        {
            var system = audience == Audience.Management
                ? "You are a security advisor writing for a non-technical executive (CIO/CISO/board). Plain language only. Never invent numbers."
                : "You are a senior security analyst. Be concrete and actionable. Never invent numbers.";
            var user = GroundedPrompt.BuildGrounded(instruction, rows, audience);
            var resp = await _chat.CompleteChatAsync(
                new ChatMessage[] { new SystemChatMessage(system), new UserChatMessage(user) },
                new ChatCompletionOptions { Temperature = 0f },
                ct);
            var text = resp.Value.Content.Count > 0 ? resp.Value.Content[0].Text : "";
            if (string.IsNullOrWhiteSpace(text))
            {
                return new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false);
            }
            return new NarrativeResult(text.Trim(), true);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "SIA AI call failed - falling back to templated summary (fail-soft).");
            return new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false);
        }
    }

    public async Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default)
    {
        if (_chat is null) return null;
        try
        {
            var prompt = GroundedPrompt.BuildNlToKql(question, allowedTables);
            var resp = await _chat.CompleteChatAsync(
                new ChatMessage[]
                {
                    new SystemChatMessage("You output ONE read-only KQL query and nothing else. No markdown fences, no prose."),
                    new UserChatMessage(prompt),
                },
                new ChatCompletionOptions { Temperature = 0f },
                ct);
            var text = resp.Value.Content.Count > 0 ? resp.Value.Content[0].Text : null;
            return CleanKql(text);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "SIA NL->KQL composition failed.");
            return null;
        }
    }

    private static string? CleanKql(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        text = text.Trim();
        // Strip markdown fences if the model added them despite instruction.
        if (text.StartsWith("```"))
        {
            var firstNl = text.IndexOf('\n');
            if (firstNl >= 0) text = text[(firstNl + 1)..];
            if (text.EndsWith("```")) text = text[..^3];
        }
        return text.Trim();
    }
}
