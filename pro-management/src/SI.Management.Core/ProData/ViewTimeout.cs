namespace SI.Management.Core.ProData;

/// <summary>
/// A view's read that did not finish within its time limit (#284). Raised INSTEAD of the bare cancellation the time limit
/// causes, so a page can tell "the database took too long" (shown in the page, with a reference) from "the browser went
/// away" (the request's own cancellation, which still surfaces as <see cref="OperationCanceledException"/> and is left to
/// the host). Never retried: a statement that ran out of time once runs out of time again.
/// </summary>
public sealed class ViewTimeoutException : TimeoutException
{
    public ViewTimeoutException(TimeSpan limit, Exception? inner)
        : base($"the Pro database did not answer within {limit.TotalSeconds:0} seconds", inner) => Limit = limit;

    public TimeSpan Limit { get; }
}

/// <summary>Runs one read under a time limit and turns running out of it into <see cref="ViewTimeoutException"/>.</summary>
public static class ViewTimeout
{
    public static async Task<T> Run<T>(Func<CancellationToken, Task<T>> read, TimeSpan limit, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(limit);
        try
        {
            return await read(cts.Token).ConfigureAwait(false);
        }
        // the caller's own token (the browser went away) is NOT a timeout: that cancellation goes up unchanged
        catch (Exception ex) when (!ct.IsCancellationRequested && (cts.IsCancellationRequested || IsCommandTimeout(ex)))
        {
            throw new ViewTimeoutException(limit, ex);
        }
    }

    /// SqlClient's own command timeout (error number -2), anywhere in the exception chain.
    public static bool IsCommandTimeout(Exception? ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
            if (e is Microsoft.Data.SqlClient.SqlException { Number: -2 }) return true;
        return false;
    }
}
