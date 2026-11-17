using SI.Management.Core.ProData;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Cis;

/// <summary>
/// #1219 (4) what the CI page and the exception page show of one CI's software tier detections: each detection (rule + the
/// software it matched, from the CI's tier claims), the software's evidence paths with install kind and application (the
/// newest run of the CI's Defender devices), whether each device's evidence was read, and the per-server exceptions of the CI
/// (in force and recently undone). Reading it never fails the page: what cannot be read is said.
/// </summary>
public sealed record CiSoftwareView(string CiId, IReadOnlyList<SoftwareDetection> Detections, IReadOnlyList<SoftwareEvidenceDeviceState> Devices,
    IReadOnlyList<SoftwareEvidencePath> Paths, IReadOnlyList<CiSoftwareExceptionRow> Exceptions, bool TableMissing, string? Error)
{
    public static CiSoftwareView Empty(string ciId) => new(ciId, [], [], [], [], false, null);

    /// The exceptions in force.
    public IReadOnlyList<CiSoftwareExceptionRow> Active => Exceptions.Where(e => !e.Removed).ToList();

    /// The exception in force for a rule and software, or null.
    public CiSoftwareExceptionRow? ActiveFor(string ruleId, string software) =>
        Exceptions.FirstOrDefault(e => !e.Removed && string.Equals(e.RuleId, ruleId, StringComparison.OrdinalIgnoreCase) && e.Software == software);

    /// The evidence paths of one software (every device of the CI).
    public IReadOnlyList<SoftwareEvidencePath> PathsOf(string software) => Paths.Where(p => p.Software == software).ToList();

    /// The detections still to show as detections: one per rule and software (an excepted one that still claims through
    /// other evidence is shown under the exceptions, not here).
    public IReadOnlyList<SoftwareDetection> Shown =>
        Detections.Where(d => ActiveFor(d.RuleId, d.Software) is null).GroupBy(d => (d.RuleId, d.Software)).Select(g => g.OrderByDescending(x => x.Winner).First()).ToList();

    /// One line about the evidence of the CI's devices.
    public string EvidenceText
    {
        get
        {
            if (Devices.Count == 0) return "This CI has no Defender device: no software evidence.";
            var read = Devices.Where(d => d.Read).ToList();
            var unknown = Devices.Count - read.Count;
            var when = read.Select(d => d.CollectionTime).Where(t => t is not null).DefaultIfEmpty(null).Max();
            var t = read.Count == 0 ? "The software evidence of this CI's Defender device(s) is unknown in their newest run (not read) -- no path is shown, never an older run's."
                : $"Software evidence of the newest run{(when is { } w ? " (" + w.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) + " UTC)" : "")}: {read.Count} of {Devices.Count} Defender device(s) read.";
            if (read.Count > 0 && unknown > 0) t += $" {unknown} device(s) unknown -- no path is shown for them.";
            return t;
        }
    }

    public static async Task<CiSoftwareView> LoadAsync(SoftwareExceptionStore? store, string ciId, CiDocument doc, ILogger log, CancellationToken ct)
    {
        var detections = SoftwareDetections.From(doc);
        if (store is null) return Empty(ciId) with { Detections = detections };
        IReadOnlyList<CiSoftwareExceptionRow> exceptions = [];
        IReadOnlyList<SoftwareEvidenceDeviceState> devices = [];
        IReadOnlyList<SoftwareEvidencePath> paths = [];
        var missing = false; string? error = null;
        try
        {
            if (await store.TableExistsAsync(ct)) exceptions = await store.ListAsync(ciId, ct); else missing = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the software exceptions of CI {Id} could not be read", ciId); error = "The per-server exceptions could not be read: " + ViewerError.Text(ex); }
        try
        {
            devices = await store.EvidenceStatesAsync(ciId, ct);
            var sw = detections.Select(d => d.Software).Concat(exceptions.Where(e => !e.Removed).Select(e => e.Software));
            paths = await store.EvidenceAsync(ciId, sw, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the software evidence of CI {Id} could not be read", ciId); error = (error is null ? "" : error + " ") + "The software evidence could not be read: " + ViewerError.Text(ex); }
        return new CiSoftwareView(ciId, detections, devices, paths, exceptions, missing, error);
    }
}

/// The partial's model: the view, whether the signed-in person may set / undo an exception here (an Admin with Pro), and
/// where a change returns to ("ci" = the CI page, else the exception page).
public sealed record CiSoftwareRender(CiSoftwareView View, bool CanChange, bool Pro, string Back);
