namespace SigninFront;

/// <summary>
/// 1.5.0 SIGNIN_FRONT_MOVED_TO -- the way a product moves its web app to a new address (framework §12.11g): the OLD app's
/// front answers EVERY request with a redirect to the new address BEFORE any sign-in, so a person signs in once, on the new
/// address. Opt-in: unset or invalid = exactly the behaviour without it.
///   * the value: an absolute https base URL, host name only (no user info, no port other than 443, no query, no fragment,
///     no path other than "/");
///   * it is honoured only when its host lies in the SAME parent domain as the request's host (the Container Apps
///     environment's domain: everything after the first label, itself at least two labels) and is not the request's own
///     host -- never an arbitrary host, so the setting can never become an open redirect;
///   * the redirect keeps the path and the query; 302 for GET / HEAD, 308 for every other method (the method and the body
///     are kept);
///   * /healthz is never redirected (the platform's probe of the old app keeps answering).
/// </summary>
public sealed class MovedTo
{
    public const string SettingName = "SIGNIN_FRONT_MOVED_TO";

    /// <summary>The base URL without a trailing '/', e.g. https://app-new.env.region.example.</summary>
    public string Base { get; }
    public string Host { get; }

    private MovedTo(string baseUrl, string host) { Base = baseUrl; Host = host; }

    /// <summary>
    /// The setting as read at start: the MovedTo, or null with -why- when unset ("") or invalid (a reason). Never throws --
    /// an invalid value only means the front behaves as without it.
    /// </summary>
    public static MovedTo? Parse(string? raw, out string why)
    {
        why = "";
        var v = (raw ?? "").Trim();
        if (v.Length == 0) return null;
        if (!Uri.TryCreate(v, UriKind.Absolute, out var u)) { why = "not an absolute URL"; return null; }
        if (u.Scheme != Uri.UriSchemeHttps) { why = "not https"; return null; }
        if (u.HostNameType != UriHostNameType.Dns) { why = "the host is not a DNS name"; return null; }
        if (u.UserInfo.Length > 0) { why = "user info is not allowed"; return null; }
        if (!u.IsDefaultPort) { why = "a port is not allowed"; return null; }
        if (u.Query.Length > 0 || u.Fragment.Length > 0) { why = "a query or fragment is not allowed"; return null; }
        if (u.AbsolutePath != "/") { why = "a path is not allowed (a base URL only)"; return null; }
        var host = u.IdnHost.ToLowerInvariant();
        if (ParentDomain(host) is null) { why = "the host has no parent domain of at least two labels"; return null; }
        return new MovedTo("https://" + host, host);
    }

    /// <summary>Everything after the first label, when that is at least two labels; else null.</summary>
    public static string? ParentDomain(string host)
    {
        var h = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        var i = h.IndexOf('.');
        if (i <= 0) return null;
        var parent = h.Substring(i + 1);
        return parent.Contains('.') && !parent.StartsWith('.') && !parent.EndsWith('.') ? parent : null;
    }

    /// <summary>May a request to -requestHost- be sent here? Same parent domain, and not the request's own host.</summary>
    public bool AllowedFrom(string requestHost)
    {
        var rh = (requestHost ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        var rp = ParentDomain(rh);
        return rp is not null && rh != Host && string.Equals(rp, ParentDomain(Host), StringComparison.Ordinal);
    }

    /// <summary>The paths the front never redirects: its own health probe.</summary>
    public static bool IsExempt(PathString path) =>
        FrontSettings.PathMatches(path.HasValue ? path.Value! : "/", "/healthz");

    /// <summary>302 for GET / HEAD, 308 (method and body kept) for every other method.</summary>
    public static int StatusFor(string method) =>
        HttpMethods.IsGet(method) || HttpMethods.IsHead(method) ? StatusCodes.Status302Found : StatusCodes.Status308PermanentRedirect;

    /// <summary>The redirect target: the base + the request's path (with its base) + its query, unchanged.</summary>
    public string Target(HttpRequest r)
    {
        var path = r.PathBase.Add(r.Path).ToUriComponent();
        if (path.Length == 0) path = "/";
        return Base + path + r.QueryString.ToUriComponent();
    }
}

/// <summary>
/// One log line per minute at most while the front redirects: "from host -> to base, count since the last line" -- the move
/// is visible in the log without a line per request. Thread-safe; the clock is injected (tests).
/// </summary>
public sealed class MovedToLog
{
    private readonly TimeProvider _clock;
    private readonly Action<string> _write;
    private readonly TimeSpan _every;
    private readonly object _gate = new();
    private DateTimeOffset _last = DateTimeOffset.MinValue;
    private long _count;

    public MovedToLog(TimeProvider clock, Action<string> write, TimeSpan? every = null)
    {
        _clock = clock; _write = write; _every = every ?? TimeSpan.FromMinutes(1);
    }

    /// <summary>Counts one redirect; writes the line (and returns true) when the last one is a minute old or more.</summary>
    public bool Record(string fromHost, string toBase)
    {
        string? line = null;
        lock (_gate)
        {
            _count++;
            var now = _clock.GetUtcNow();
            if (now - _last >= _every)
            {
                line = $"signin-front: moved: {fromHost} -> {toBase}, {_count} request(s) redirected since the last line";
                _last = now; _count = 0;
            }
        }
        if (line is null) return false;
        _write(line);
        return true;
    }
}
