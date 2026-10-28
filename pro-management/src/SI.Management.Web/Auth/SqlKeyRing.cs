using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using SI.Management.Web.Data;

namespace SI.Management.Web.Auth;

/// <summary>
/// The web app's data-protection key ring, kept in the Pro database (cfg.WebKeyRing) instead of the container's disk (#345).
/// The keys encrypt the sign-in cookie and every form's antiforgery token. On the container's disk they were lost with every
/// new revision and differed between the two replicas, so a deploy (or a request landing on the other replica) signed every
/// open page out and refused its next save. Shared and kept here, a new revision reads the same keys: an open page stays
/// signed in and its forms still save, and "a new version is available" can say "reload when you are ready".
/// Never fails the app: when the database cannot be read or written, the keys of THIS process are kept in memory (exactly
/// the behaviour before) and the next read tries the database again.
/// Who can read the table: the web app (db_datareader) and the jobs, which already change every setting; the MCP server's
/// identity is DENIED SELECT on it by Deploy-SIManagement.ps1.
/// </summary>
public sealed class SqlKeyRing : IXmlRepository
{
    internal const string ReadSql = "IF OBJECT_ID(N'cfg.WebKeyRing') IS NOT NULL\nSELECT FriendlyName, KeyXml FROM cfg.WebKeyRing;";
    internal const string WriteSql =
        "IF NOT EXISTS (SELECT 1 FROM cfg.WebKeyRing WHERE FriendlyName = @FriendlyName)\n" +
        "INSERT INTO cfg.WebKeyRing (FriendlyName, KeyXml) VALUES (@FriendlyName, @KeyXml);";

    private readonly ISqlExecutor _sql;
    private readonly ILogger<SqlKeyRing> _log;
    private readonly Dictionary<string, XElement> _local = new(StringComparer.Ordinal);   // this process's keys (fallback)
    private readonly object _gate = new();

    public SqlKeyRing(ISqlExecutor sql, ILogger<SqlKeyRing> log) { _sql = sql; _log = log; }

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        var all = new Dictionary<string, XElement>(StringComparer.Ordinal);
        try
        {
            // the key ring is read at start and about once a day -- a short synchronous wait is what the interface asks for
            var rows = _sql.QueryAsync(ReadSql, new Dictionary<string, object?>(), CancellationToken.None).GetAwaiter().GetResult();
            foreach (var r in rows)
            {
                var name = r.Str("FriendlyName"); var xml = r.Str("KeyXml");
                if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(xml)) continue;
                try { all[name] = XElement.Parse(xml); }
                catch (System.Xml.XmlException ex) { _log.LogWarning(ex, "A stored sign-in key could not be read and is skipped."); }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _log.LogWarning(ex, "The shared sign-in keys could not be read from the database; this process uses its own until it can.");
        }
        lock (_gate) { foreach (var (k, v) in _local) all.TryAdd(k, v); }
        return all.Values.Select(e => new XElement(e)).ToList();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        var name = string.IsNullOrWhiteSpace(friendlyName) ? "key-" + Guid.NewGuid().ToString("D") : friendlyName;
        lock (_gate) { _local[name] = new XElement(element); }
        try
        {
            _sql.QueryAsync(WriteSql, new Dictionary<string, object?> { ["FriendlyName"] = name, ["KeyXml"] = element.ToString(SaveOptions.DisableFormatting) },
                CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _log.LogWarning(ex, "A new sign-in key could not be saved to the database; it is kept by this process only, so a new version or the other replica signs open pages out.");
        }
    }
}
