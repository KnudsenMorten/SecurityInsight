using SI.Management.Web.Jobs;

namespace SI.Management.Web.Summary;

// =====================================================================================================================
// #842 (owner 2026-10-20: Security recommendations > Summary "still not working" -- every collection said "being prepared"
// although nothing was preparing it). A view of the Summary that is not written for a collection says WHY, truthfully:
//   * the data sync is running now                 -> it is being prepared (the only time those words are used);
//   * the pipeline run going now has not reached it -> it comes with that run's data sync;
//   * a data sync waits in the queue                -> it comes with that data sync (it starts when the install is free);
//   * nothing is running or waiting                 -> it comes with the next data sync (the next pipeline start, when the
//                                                      page can read it) -- and the views that ARE written are listed.
// A read that fails is never one of these: the page says the state could not be read, with the reason.
// The data sync is the step 'asset-datasync' of the pipeline (config\job-flow.locked.json); the run record is cfg.FlowRun /
// cfg.FlowStepRun and the queue cfg.PipelineQueue -- the same reads Operations > Jobs makes (IFlowStore).
// =====================================================================================================================

/// Where the data sync stands now. Unknown = the run state could not be read (Problem says why).
public enum DataSyncActivity { Idle, Running, LaterInRun, Queued, Unknown }

/// The data sync's state for the Summary page: what it is doing, the next pipeline start in words (null = not known, or the
/// install runs its jobs on their own schedules), and the plain reason a read failed.
public sealed record DataSyncState(DataSyncActivity Activity, string? NextRun, string? Problem = null);

public static class SummaryBuildStatus
{
    /// The pipeline step that writes the Summary groupings.
    public const string DataSyncStep = "asset-datasync";

    private static bool IsDataSync(string? job) =>
        string.Equals(job, DataSyncStep, StringComparison.OrdinalIgnoreCase) || string.Equals(job, "caj-si-" + DataSyncStep, StringComparison.OrdinalIgnoreCase);

    /// PURE. What the data sync is doing, from the last run record and the waiting requests.
    public static DataSyncActivity Of(FlowRun? last, IReadOnlyList<PipelineRequest> queue)
    {
        if (last is { Finished: false })
        {
            var step = last.Steps.Where(s => IsDataSync(s.Job) && s.ErrorClass != "before-rerun").OrderByDescending(s => s.Order).FirstOrDefault();
            if (step is { State: "Starting" or "Running" }) return DataSyncActivity.Running;
            if (step is { State: "Waiting" }) return DataSyncActivity.LaterInRun;
        }
        foreach (var r in queue.Where(r => r.State == "Queued"))
        {
            if (r.Scope == "pipeline") return DataSyncActivity.Queued;
            if (r.Scope == "stage" && string.Equals(r.Target, "deliver", StringComparison.OrdinalIgnoreCase)) return DataSyncActivity.Queued;
            if (r.Scope is "step" or "from-step" && IsDataSync(r.Target)) return DataSyncActivity.Queued;
        }
        return DataSyncActivity.Idle;
    }

    /// Reads the run record, the queue and the pipeline's next start. Never throws (a cancelled request aside): a failed read
    /// answers Unknown with the reason.
    public static async Task<DataSyncState> ReadAsync(IFlowStore flows, DateTimeOffset nowUtc, CancellationToken ct)
    {
        try
        {
            var last = await flows.LastRunAsync(ct);
            var (queue, _) = await flows.QueueAsync(ct);
            var activity = Of(last, queue);
            string? next = null;
            var stored = await flows.ReadAsync(ct);
            if (stored.Definition is { } d && !string.Equals(stored.Mode ?? d.Mode, "schedules", StringComparison.OrdinalIgnoreCase)
                && d.Steps.Any(s => IsDataSync(s.Job) && s.Enabled))
            {
                var (text, when) = JobFlow.NextRun(d, last, nowUtc);
                if (when is not null) next = text;
            }
            return new DataSyncState(activity, next);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new DataSyncState(DataSyncActivity.Unknown, null, ex.Message); }
    }

    /// The page's words for a view that is not written for the collection. <paramref name="others"/>: views of this collection
    /// that ARE written (the page lists them as links after this text).
    public static string Text(DataSyncState s, bool others)
    {
        var have = others ? " The other views listed below are here for this collection now, and every finding is in Detailed."
                          : " Until then every finding is in Detailed, and the Vulnerabilities (CVE) view is here.";
        var text = s.Activity switch
        {
            DataSyncActivity.Running => "This view of the summary is being prepared: the data sync is running now and writes it for this collection." + have,
            DataSyncActivity.LaterInRun => "This view of the summary comes with the data sync of the pipeline run in progress: that step has not started yet." + have,
            DataSyncActivity.Queued => "This view of the summary comes with the data sync that waits in the queue: it starts when the install is free." + have,
            _ => "This view of the summary is not built for this collection yet: it comes with the next data sync"
                 + (s.NextRun is { Length: > 0 } n ? " (the next pipeline run: " + n + ")." : ".") + have,
        };
        if (s.Activity == DataSyncActivity.Unknown && s.Problem is { Length: > 0 } p)
            text += " Whether the data sync is running now could not be read: " + p;
        return text;
    }
}
