using System.Diagnostics;

namespace SI.Management.Web;

/// <summary>
/// #997: what a page SAYS about an exception it caught. The app's own words reach the viewer as they are -- a refusal or a
/// validation message the app itself wrote (ArgumentException, InvalidOperationException, InvalidDataException,
/// UnauthorizedAccessException, a JSON / YAML / format error of what the person typed). Anything else -- the database, Azure,
/// the network, the file system -- is said in plain words (the same wording the error page uses, Pages/Error.cshtml.cs)
/// with a REFERENCE, and the full exception is written to the application log under that reference: its text can name
/// schemas, objects, servers and identities, which is for the log, never for the browser.
/// </summary>
public static class ViewerError
{
    /// Set once at start (Program.cs); a test or a host without it still gets the wording and the reference.
    public static ILogger? Log { get; set; }

    /// Exception types whose message the APP wrote for the person (never a database's or a service's). A refusal type
    /// (argument, state, access) counts only when the app's own code threw it: the same types thrown by a client library,
    /// the runtime or the file system (a connection pool's InvalidOperationException, a path in an
    /// UnauthorizedAccessException) carry that library's text. A parse error of what the person typed (JSON, YAML, a
    /// format) is about their input wherever it was raised.
    private static bool Ours(Exception ex) =>
        !Foreign(ex)
        && (ex is FormatException or System.Text.Json.JsonException or YamlDotNet.Core.YamlException
            || (ex is ArgumentException or InvalidOperationException or InvalidDataException or UnauthorizedAccessException or SI.Management.Core.ProData.PivotNotStoredException
                && FromApp(ex)));

    /// The assemblies whose messages are the app's own words.
    private const string AppAssemblyPrefix = "SI.Management";

    /// Raised by the app's own code: the method that threw it is in one of the app's assemblies -- or it was never thrown
    /// (the app built it to say something; only a thrown exception has a throwing method).
    public static bool FromApp(Exception ex)
    {
        var thrower = ex.TargetSite?.DeclaringType?.Assembly;
        if (thrower is null) return ex.StackTrace is null;
        return (thrower.GetName().Name ?? "").StartsWith(AppAssemblyPrefix, StringComparison.Ordinal);
    }

    /// An exception with a database / service / network error anywhere inside it -- or a refusal type a library threw
    /// inside it -- is not the app's own words.
    private static bool Foreign(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException)
        {
            if (e is System.Data.Common.DbException or Azure.RequestFailedException or HttpRequestException or IOException
                or System.Net.Sockets.SocketException or TimeoutException or Azure.Identity.AuthenticationFailedException)
                return true;
            if (!ReferenceEquals(e, ex) && e is InvalidOperationException or UnauthorizedAccessException && !FromApp(e)) return true;
        }
        return false;
    }

    /// The reference a viewer gives the administrator: the request's trace id (what the log scopes carry), else a new one.
    public static string Reference() =>
        Activity.Current?.TraceId.ToString() is { Length: > 0 } t && t != "00000000000000000000000000000000" ? t : Guid.NewGuid().ToString("N");

    /// <summary>
    /// The text a page shows for <paramref name="ex"/>: the app's own message as it is, or the plain-words reason with a
    /// reference (and the exception written to the log under it).
    /// </summary>
    public static string Text(Exception ex)
    {
        // #1112: a query that met an update of the database says so -- the page works again in a few minutes
        if (SI.Management.Web.Updating.UpdateWindowNotice.Is(ex)) return SI.Management.Web.Updating.UpdateWindowNotice.Text;
        if (Ours(ex)) return ex.Message;
        var reference = Reference();
        // the log is set once per process (Program.cs); a host that has stopped leaves a disposed logger behind -- writing
        // the entry must never turn the viewer's plain-words answer into an error of its own
        try { Log?.LogWarning(ex, "an error shown to a viewer as reference {Reference}: {Type}", reference, ex.GetType().FullName); }
        catch (Exception logEx) when (logEx is ObjectDisposedException or AggregateException) { }
        var (why, _) = SI.Management.Web.Pages.ErrorModel.Classify(ex);
        return why.TrimEnd('.') + ". The details are in the application log under reference " + reference + ".";
    }
}
