using Sia.Core.Exec;
using Sia.Web.Rendering;
using Sia.Web.Services;

// ===========================================================================
//  Sia.Preview - generate the committed static exec-dashboard preview.
//  Usage: dotnet run --project tools/Sia.Preview -- <seedJsonPath> <outHtmlPath> <chartJsPath>
//  Defaults resolve to the repo's demo seed, the preview output path, and the
//  bundled Chart.js. Renders AI-OFF (templated, grounded fallback) so the
//  preview needs no OpenAI; the hosted /exec adds the live AI narrative on top.
// ===========================================================================

string repoRoot = FindUp("analyzer-web") ?? Directory.GetCurrentDirectory();

string seed = args.Length > 0 ? args[0] : Path.Combine(repoRoot, "..", "analyzer", "seed", "demo-snapshot.json");
string outHtml = args.Length > 1 ? args[1] : Path.Combine(repoRoot, "preview", "exec-dashboard.html");
string chartJs = args.Length > 2 ? args[2] : Path.Combine(repoRoot, "src", "Sia.Web", "wwwroot", "lib", "chart.umd.js");

seed = Path.GetFullPath(seed);
outHtml = Path.GetFullPath(outHtml);
chartJs = Path.GetFullPath(chartJs);

if (!File.Exists(seed)) { Console.Error.WriteLine($"Seed not found: {seed}"); return 1; }
if (!File.Exists(chartJs)) { Console.Error.WriteLine($"Chart.js not found: {chartJs}"); return 1; }

// Build the exec view-model from the demo seed, AI-off (templated grounded summary).
var data = new DemoRiskDataSource(seed);
var ai = new NoOpAi();
var svc = new AnalyzerService(data, ai);
var vm = await svc.GetExecAsync();

var html = ExecHtmlRenderer.RenderStandalone(vm, File.ReadAllText(chartJs));
Directory.CreateDirectory(Path.GetDirectoryName(outHtml)!);
File.WriteAllText(outHtml, html);

// Also emit the clean board-deck export handout (self-contained, print/PDF-friendly).
string outBoard = Path.Combine(Path.GetDirectoryName(outHtml)!, "board-deck.html");
File.WriteAllText(outBoard, BoardDeckRenderer.Render(vm));

Console.WriteLine("SI Analyzer previews written to:");
Console.WriteLine("  " + outHtml);
Console.WriteLine($"  ({new FileInfo(outHtml).Length:n0} bytes; open it in a browser - no server needed)");
Console.WriteLine("  " + outBoard);
Console.WriteLine($"  ({new FileInfo(outBoard).Length:n0} bytes; the print/PDF board handout)");
return 0;

static string? FindUp(string dirName)
{
    var d = new DirectoryInfo(Directory.GetCurrentDirectory());
    while (d is not null)
    {
        if (string.Equals(d.Name, dirName, StringComparison.OrdinalIgnoreCase)) return d.FullName;
        var candidate = Path.Combine(d.FullName, dirName);
        if (Directory.Exists(candidate)) return candidate;
        d = d.Parent;
    }
    return null;
}

/// <summary>AI-off narrative service for the offline preview (always uses the grounded
/// templated fallback - the same fail-soft path the hosted app uses when OpenAI is down).</summary>
file sealed class NoOpAi : IAiNarrativeService
{
    public bool IsAvailable => false;
    public Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<Sia.Core.Model.RiskRow> rows, Sia.Core.Ai.Audience audience, Sia.Core.Ai.DiffSummary? diff = null, CancellationToken ct = default)
        => Task.FromResult(new NarrativeResult(Sia.Core.Ai.GroundedPrompt.TemplatedSummary(rows, audience, diff), false));
    public Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default)
        => Task.FromResult<string?>(null);
}
