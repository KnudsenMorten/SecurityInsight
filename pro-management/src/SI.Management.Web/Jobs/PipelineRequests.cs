namespace SI.Management.Web.Jobs;

/// <summary>
/// THE one way a person starts the pipeline, a stage, a step or "from this step on" (Run now / Re-run from here): a
/// request in the install's queue (it starts as soon as nothing else runs -- the install's ONE lock -- never over another
/// run), and the runner is started at once to take it. Shared by Operations > Jobs and by every page that offers
/// Re-run from here on something it shows (Operations > Data quality), so they can never queue differently.
/// </summary>
public static class PipelineRequests
{
    /// <summary>
    /// Queues <paramref name="scope"/> ("pipeline" | "stage" | "step" | "from-step") on <paramref name="target"/> and wakes
    /// the runner. Returns the words for the person. <paramref name="running"/>: who holds the lock now (said in the words).
    /// </summary>
    public static async Task<string> QueueAsync(IFlowStore flow, IJobsClient jobs, string scope, string target, string by, PipelineLock? running, CancellationToken ct)
    {
        var what = JobFlow.RequestText(scope, target);
        var (id, outcome) = await flow.EnqueueAsync(scope, target, by, ct);
        if (outcome == "Missing")
        {
            // an older Pro database (no queue yet): the runner is started with the request itself
            var env = new Dictionary<string, string> { ["SI_FLOW_TRIGGER"] = "manual" };
            switch (scope)
            {
                case "stage": env["SI_FLOW_STAGE"] = target; break;
                case "step": env["SI_FLOW_STEP"] = target; break;
                case "from-step": env["SI_FLOW_FORCE"] = "1"; env["SI_FLOW_FROM_STEP"] = target; break;
                default: env["SI_FLOW_FORCE"] = "1"; break;
            }
            var direct = await jobs.StartWithEnvAsync(JobFlow.FlowJob, env, ct);
            return $"{what} starts now (execution {direct}) -- apply the Pro database schema again to get the run queue";
        }
        var exec = await jobs.StartWithEnvAsync(JobFlow.FlowJob, new Dictionary<string, string> { ["SI_FLOW_DRAIN"] = "1", ["SI_FLOW_TRIGGER"] = "manual" }, ct);
        var busy = running is { } l ? $" -- now running: {l.What}; it waits for that to finish" : "";
        return outcome == "Deduplicated"
            ? $"{what} is already waiting in the queue (request {id}) -- kept once"
            : $"{what} is queued (request {id}) and starts as soon as nothing else runs{busy} (runner execution {exec})";
    }
}
