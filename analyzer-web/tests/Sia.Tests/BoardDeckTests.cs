using Sia.Core.Ai;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Web.Rendering;
using Sia.Web.Services;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the board-deck export (TESTS.md §9.8): a clean, single-page, print/PDF-friendly
/// executive handout rendered from the SAME grounded exec view as the dashboard. It must
/// show the headline verdict + the key board facts, carry the grounded numbers (never
/// recompute or invent), stay free of KQL/jargon, and be print-ready (no charts/JS).
/// </summary>
public sealed class BoardDeckTests
{
    private static ExecViewModel Vm()
    {
        var data = new DemoRiskDataSource(DemoData.Load(TestData.SeedPath()));
        var svc = new AnalyzerService(data, new OfflineAi());
        return svc.GetExecAsync().GetAwaiter().GetResult();
    }

    [Fact]
    public void Board_deck_renders_a_self_contained_one_page_document()
    {
        var html = BoardDeckRenderer.Render(Vm());
        Assert.StartsWith("<!DOCTYPE html>", html);
        Assert.Contains("Security posture - board summary", html);
        // Self-contained: inline CSS, no external CDN, no chart canvases/JS in the handout.
        Assert.Contains("<style>", html);
        Assert.DoesNotContain("http://", html);
        Assert.DoesNotContain("https://", html);
        Assert.DoesNotContain("<canvas", html);
        Assert.DoesNotContain("Chart(", html);
    }

    [Fact]
    public void Board_deck_leads_with_the_grounded_headline_verdict()
    {
        var vm = Vm();
        var html = BoardDeckRenderer.Render(vm);
        // The exact one-sentence verdict from the dashboard appears (same grounded text).
        Assert.Contains(vm.Dashboard.Headline.Sentence, html);
        Assert.Contains("class=\"verdict", html);
    }

    [Fact]
    public void Board_deck_carries_the_grounded_score_and_band_unchanged()
    {
        var vm = Vm();
        var html = BoardDeckRenderer.Render(vm);
        // The headline score + band on the badge are the SAME grounded figures - not recomputed.
        Assert.Contains(vm.Dashboard.Headline.Score.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture), html);
        Assert.Contains(vm.Dashboard.ScoreBand, html);
    }

    [Fact]
    public void Board_deck_shows_the_board_facts()
    {
        var html = BoardDeckRenderer.Render(Vm());
        Assert.Contains("What this means", html);             // exec summary
        Assert.Contains("Top risks right now", html);         // top risks
        Assert.Contains("Recent wins", html);                 // wins
        Assert.Contains("Where the risk concentrates", html); // concentration
        Assert.Contains("What is at stake", html);            // business consequence kinds
        Assert.Contains("Recommended next actions", html);    // quick wins
        Assert.Contains("Print / Save as PDF", html);         // export affordance
    }

    [Fact]
    public void Board_deck_is_print_ready_and_states_no_invented_figures()
    {
        var html = BoardDeckRenderer.Render(Vm());
        Assert.Contains("@media print", html);
        Assert.Contains("@page", html);
        // Honest framing: consequence KIND only, no implied cost/likelihood.
        Assert.Contains("no cost or likelihood is implied", html);
    }

    [Fact]
    public void Board_deck_has_no_kql_or_jargon()
    {
        var html = BoardDeckRenderer.Render(Vm());
        Assert.DoesNotContain("CollectionTime", html);
        Assert.DoesNotContain("RiskScoreTotal", html);
        Assert.DoesNotContain("summarize", html);
        Assert.DoesNotContain("_CL", html);
    }

    // AI-off narrative for offline rendering (grounded templated fallback).
    private sealed class OfflineAi : IAiNarrativeService
    {
        public bool IsAvailable => false;
        public Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<Sia.Core.Model.RiskRow> rows, Audience audience, DiffSummary? diff = null, CancellationToken ct = default)
            => Task.FromResult(new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false));
        public Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default)
            => Task.FromResult<string?>(null);
    }
}
