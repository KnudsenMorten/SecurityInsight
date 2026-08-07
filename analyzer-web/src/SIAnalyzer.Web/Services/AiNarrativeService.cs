using System.ClientModel;
using Azure.AI.OpenAI;
using Azure.Identity;
using OpenAI.Chat;
using SIAnalyzer.Core.Ai;
using SIAnalyzer.Core.Model;

namespace SIAnalyzer.Web.Services;

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
    private readonly TimeSpan _timeout;
    private readonly int _maxOutputTokens;

    public AiNarrativeService(SIAnalyzerOptions opts, ILogger<AiNarrativeService> log)
    {
        _log = log;
        _timeout = opts.AiTimeoutSeconds > 0 ? TimeSpan.FromSeconds(opts.AiTimeoutSeconds) : Timeout.InfiniteTimeSpan;
        _maxOutputTokens = opts.AiMaxOutputTokens;
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

    /// <summary>
    /// AUDIT #15: the AI call's OWN deadline, linked to the caller's token.
    ///
    /// The two must stay distinguishable, which is why this returns the timeout source rather than
    /// just a token: if the CALLER cancelled (client gone, app stopping) there is nothing useful to
    /// fall back to and the exception should propagate; if OUR deadline fired, that is exactly the
    /// case the finding is about and it must degrade to the grounded templated summary. Both arrive
    /// as OperationCanceledException and are otherwise indistinguishable.
    /// </summary>
    internal CancellationTokenSource LinkTimeout(CancellationToken caller)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(caller);
        if (_timeout != Timeout.InfiniteTimeSpan) cts.CancelAfter(_timeout);
        return cts;
    }

    internal ChatCompletionOptions ChatOptions() => _maxOutputTokens > 0
        ? new ChatCompletionOptions { Temperature = 0f, MaxOutputTokenCount = _maxOutputTokens }
        : new ChatCompletionOptions { Temperature = 0f };

    /// <summary>
    /// AUDIT #15: "the model stopped because it ran out of budget", i.e. the output is CUT OFF.
    /// Named and separated so the rule is stated once and can be asserted, rather than being an
    /// inline comparison in two places that could drift apart.
    /// </summary>
    internal static bool IsTruncated(ChatFinishReason reason) => reason == ChatFinishReason.Length;

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
            using var cts = LinkTimeout(ct);
            var resp = await _chat.CompleteChatAsync(
                new ChatMessage[] { new SystemChatMessage(system), new UserChatMessage(user) },
                ChatOptions(),
                cts.Token);

            // AUDIT #15: a completion stopped at the token cap is truncated MID-SENTENCE. Showing
            // it would trade a slow page for an executive reading half a sentence as if it were the
            // finished assessment - so it is discarded for the grounded templated summary, which is
            // complete by construction. The cap without this check would be a new defect.
            if (IsTruncated(resp.Value.FinishReason))
            {
                _log.LogWarning("SIA AI narrative hit the {Cap}-token cap and was truncated - using the templated summary instead.", _maxOutputTokens);
                return new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false);
            }

            var text = resp.Value.Content.Count > 0 ? resp.Value.Content[0].Text : "";
            if (string.IsNullOrWhiteSpace(text))
            {
                return new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false);
            }
            return new NarrativeResult(text.Trim(), true);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // The CALLER gave up (client disconnected, host stopping). Nothing to fall back FOR.
            throw;
        }
        catch (OperationCanceledException)
        {
            // OUR deadline - the case audit #15 is about. Fail soft, exactly as an unreachable
            // endpoint already did.
            _log.LogWarning("SIA AI call exceeded its {Timeout}s budget - falling back to the templated summary.", _timeout.TotalSeconds);
            return new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false);
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
            using var cts = LinkTimeout(ct);
            var resp = await _chat.CompleteChatAsync(
                new ChatMessage[]
                {
                    new SystemChatMessage("You output ONE read-only KQL query and nothing else. No markdown fences, no prose."),
                    new UserChatMessage(prompt),
                },
                ChatOptions(),
                cts.Token);

            // AUDIT #15: a truncated QUERY is worse than a truncated sentence - it may still parse
            // while meaning something other than what was asked (a dropped `| where` widens the
            // result set). Discard it; the analyst writes KQL directly, which is the documented
            // behaviour when AI is unavailable.
            if (IsTruncated(resp.Value.FinishReason))
            {
                _log.LogWarning("SIA NL->KQL composition hit the {Cap}-token cap - discarding the truncated query.", _maxOutputTokens);
                return null;
            }

            var text = resp.Value.Content.Count > 0 ? resp.Value.Content[0].Text : null;
            return CleanKql(text);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            _log.LogWarning("SIA NL->KQL composition exceeded its {Timeout}s budget.", _timeout.TotalSeconds);
            return null;
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
