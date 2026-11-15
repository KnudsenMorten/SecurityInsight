using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Xml.Linq;
using Azure.Core;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace SI.Management.Web.Auth;

/// <summary>
/// THE WEB APP'S SIGN-IN KEYS IN ONE BLOB, WITH NO KEY VAULT (framework SECURE-WEB-1: the internet-facing identity holds no
/// Key Vault role). With Microsoft's built-in sign-in on, the updater sets DataProtection__BlobUri to a blob in the install's
/// token-store container (si-auth-tokens/dataprotection/keys.xml): the web app's managed identity already holds Storage Blob
/// Data Contributor on THAT container only, so the key ring needs no other right. The keys are kept as one XML document
/// (&lt;repository&gt; with one element per key, the layout Microsoft's PersistKeysToAzureBlobStorage writes), written with
/// the blob's ETag so two replicas never overwrite each other. No ProtectKeysWith*: the container's data right is the guard.
/// THE MOVE (once): while the blob holds no key, the keys of the ring before (cfg.WebKeyRing) are copied in, each one
/// unwrapped ONCE with the Key Vault key when the app may still use it -- open pages stay signed in and their forms still
/// save. A refused unwrap (the right is already gone) is said in one line and a new ring is started: everyone signs in
/// again once. Never fails the app: when the blob cannot be read or written, this process keeps its own keys in memory and
/// the next read tries the blob again (the SqlKeyRing behaviour).
/// </summary>
public interface IBlobKeyStore
{
    /// The blob's text and ETag; (null, null) when there is no blob yet. Throws when the blob cannot be read.
    (string? Xml, string? ETag) Read();
    /// Writes the blob only if it is still at <paramref name="etag"/> (null = only if it does not exist yet). False = it
    /// changed in between (another replica wrote first). Throws on any other failure.
    bool TryWrite(string xml, string? etag);
}

/// The blob over the Blob service REST API, as the process's one credential (the web app's managed identity). No SAS, no key.
public sealed class BlobRestKeyStore : IBlobKeyStore
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };
    internal const string ApiVersion = "2023-11-03";
    private readonly TokenCredential _credential;
    private readonly HttpMessageInvoker _http;
    public Uri BlobUri { get; }

    public BlobRestKeyStore(TokenCredential credential, Uri blobUri, HttpMessageInvoker? http = null)
    {
        _credential = credential; BlobUri = blobUri; _http = http ?? Http;
    }

    /// PURE. The blob the key ring is kept in: https, a Blob service host (public or sovereign cloud), a container and a blob
    /// name, and NO query (a SAS in a setting is refused -- the managed identity is the only way in). Null = not a blob URI.
    public static Uri? ParseBlobUri(string? value)
    {
        if (!Uri.TryCreate((value ?? "").Trim(), UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return null;
        if (!string.IsNullOrEmpty(u.Query) || !string.IsNullOrEmpty(u.Fragment) || !string.IsNullOrEmpty(u.UserInfo)) return null;
        var host = u.Host;
        if (!(host.EndsWith(".blob.core.windows.net", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".blob.core.usgovcloudapi.net", StringComparison.OrdinalIgnoreCase)
              || host.EndsWith(".blob.core.chinacloudapi.cn", StringComparison.OrdinalIgnoreCase))) return null;
        var parts = u.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 ? u : null;
    }

    private HttpRequestMessage Request(HttpMethod method)
    {
        var token = _credential.GetToken(new TokenRequestContext(["https://storage.azure.com/.default"]), CancellationToken.None);
        var req = new HttpRequestMessage(method, BlobUri);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        req.Headers.Add("x-ms-version", ApiVersion);
        req.Headers.Add("x-ms-date", DateTime.UtcNow.ToString("R", System.Globalization.CultureInfo.InvariantCulture));
        return req;
    }

    public (string? Xml, string? ETag) Read()
    {
        using var req = Request(HttpMethod.Get);
        using var res = _http.Send(req, CancellationToken.None);
        if (res.StatusCode == HttpStatusCode.NotFound) return (null, null);
        if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"the sign-in key store answered HTTP {(int)res.StatusCode} to a read");
        var body = res.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        return (body, res.Headers.ETag?.Tag);
    }

    public bool TryWrite(string xml, string? etag)
    {
        using var req = Request(HttpMethod.Put);
        req.Headers.Add("x-ms-blob-type", "BlockBlob");
        if (etag is null) req.Headers.IfNoneMatch.Add(EntityTagHeaderValue.Any);
        else req.Headers.IfMatch.Add(EntityTagHeaderValue.Parse(etag));
        req.Content = new StringContent(xml, new UTF8Encoding(false), "application/xml");
        using var res = _http.Send(req, CancellationToken.None);
        if (res.StatusCode is HttpStatusCode.PreconditionFailed or HttpStatusCode.Conflict) return false;
        if (!res.IsSuccessStatusCode) throw new InvalidOperationException($"the sign-in key store answered HTTP {(int)res.StatusCode} to a write");
        return true;
    }
}

/// <summary>
/// THE MOVE HAPPENS AT START, before the app answers: the key ring is read once while the web app starts, so the keys from
/// before are in the blob by the time its revision is Healthy -- the updater removes the Key Vault right only after that.
/// Never stops the app (the ring logs what it could not do).
/// </summary>
public sealed class BlobKeyRingStart(IXmlRepository? repository, ILogger<BlobKeyRingStart> log) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        try { _ = repository?.GetAllElements(); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { log.LogWarning(ex, "The sign-in keys could not be read at start; they are read again on the first sign-in."); }
        return Task.CompletedTask;
    }
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// The key ring in the blob (see <see cref="IBlobKeyStore"/>), with the one-time move of the keys from before.
public sealed class BlobKeyRing : IXmlRepository
{
    internal const string RootName = "repository";
    public const string RefusedText = "The sign-in keys from before could not be unlocked with Key Vault ({Message}); a new key ring is started: everyone signs in again once.";

    private readonly IBlobKeyStore _store;
    private readonly IXmlRepository? _oldRing;
    private readonly IKeyRingKeyWrapper? _oldWrapper;
    private readonly ILogger _log;
    private readonly Dictionary<string, XElement> _local = new(StringComparer.Ordinal);   // this process's keys (fallback)
    private readonly object _gate = new();
    private bool _moveTried;

    /// <param name="oldRing">the ring before (cfg.WebKeyRing) -- read only, and only while the blob holds no key</param>
    /// <param name="oldWrapper">its Key Vault key, used ONCE to unwrap the keys moved; null = they were stored without it</param>
    public BlobKeyRing(IBlobKeyStore store, IXmlRepository? oldRing, IKeyRingKeyWrapper? oldWrapper, ILogger log)
    {
        _store = store; _oldRing = oldRing; _oldWrapper = oldWrapper; _log = log;
    }

    /// PURE. The elements of the stored document (none for no blob / an empty one).
    internal static List<XElement> Parse(string? xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) return [];
        return XDocument.Parse(xml).Root?.Elements().Select(e => new XElement(e)).ToList() ?? [];
    }

    /// PURE. The document for these elements.
    internal static string Serialize(IEnumerable<XElement> elements) =>
        new XDocument(new XElement(RootName, elements.Select(e => new XElement(e)))).ToString(SaveOptions.DisableFormatting);

    /// PURE. The same stored element: a key by its id (its text may differ after a round trip through the blob -- namespace
    /// declarations move), anything else by its text.
    internal static bool SameElement(XElement a, XElement b)
    {
        if (a.Name.LocalName == "key" && b.Name.LocalName == "key")
            return string.Equals((string?)a.Attribute("id"), (string?)b.Attribute("id"), StringComparison.OrdinalIgnoreCase);
        return XNode.DeepEquals(a, b) || a.ToString(SaveOptions.DisableFormatting) == b.ToString(SaveOptions.DisableFormatting);
    }
    private static bool HasKey(IEnumerable<XElement> elements) => elements.Any(e => e.Name.LocalName == "key");

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        var all = new List<XElement>();
        try
        {
            var (xml, etag) = _store.Read();
            all = Parse(xml);
            bool tryMove;
            lock (_gate) { tryMove = !_moveTried && !HasKey(all); if (tryMove) _moveTried = true; }
            if (tryMove)
            {
                var moved = MoveKeysFromBefore();
                if (moved.Count > 0)
                {
                    var next = all.Concat(moved).ToList();
                    if (_store.TryWrite(Serialize(next), etag))
                    {
                        all = next;
                        _log.LogInformation("The sign-in keys ({Count}) were moved to the web app's own key store: open pages stay signed in.", moved.Count(e => e.Name.LocalName == "key"));
                    }
                    else all = Parse(_store.Read().Xml);   // another replica moved them first: its document counts
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _log.LogWarning(ex, "The shared sign-in keys could not be read from the web app's key store; this process uses its own until it can.");
        }
        lock (_gate) { foreach (var v in _local.Values) if (!all.Any(e => SameElement(e, v))) all.Add(new XElement(v)); }
        return all.Select(e => new XElement(e)).ToList();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        var name = string.IsNullOrWhiteSpace(friendlyName) ? "key-" + Guid.NewGuid().ToString("D") : friendlyName;
        lock (_gate) { _local[name] = new XElement(element); }
        try
        {
            for (var i = 0; i < 10; i++)
            {
                var (xml, etag) = _store.Read();
                var list = Parse(xml);
                if (list.Any(e => SameElement(e, element))) return;
                list.Add(new XElement(element));
                if (_store.TryWrite(Serialize(list), etag)) return;
            }
            _log.LogWarning("A new sign-in key could not be saved to the web app's key store (it kept changing); it is kept by this process only.");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _log.LogWarning(ex, "A new sign-in key could not be saved to the web app's key store; it is kept by this process only, so a new version or the other replica signs open pages out.");
        }
    }

    /// The keys of the ring before, readable without Key Vault from now on: each Key Vault-wrapped secret unwrapped once
    /// (WrappedKeyXmlDecryptor) and put back in place. A refused unwrap = nothing is moved (one warning) and a new ring starts.
    internal List<XElement> MoveKeysFromBefore()
    {
        if (_oldRing is null) return [];
        IReadOnlyCollection<XElement> old;
        try { old = _oldRing.GetAllElements(); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { _log.LogWarning(ex, "The sign-in keys from before could not be read; a new key ring is started: everyone signs in again once."); return []; }
        if (!HasKey(old)) return [];
        var outList = new List<XElement>();
        try
        {
            foreach (var e in old)
            {
                var copy = new XElement(e);
                var unknown = false;
                foreach (var secret in copy.Descendants().Where(d => d.Name.LocalName == "encryptedSecret").ToList())
                {
                    var inner = secret.Elements().FirstOrDefault();
                    if (inner is null || inner.Name.LocalName != WrappedKeyXmlEncryptor.ElementName) { unknown = true; break; }
                    if (_oldWrapper is null) throw new System.Security.Cryptography.CryptographicException("the keys are protected with Key Vault, but no Key Vault key is configured");
                    secret.ReplaceWith(new WrappedKeyXmlDecryptor(_oldWrapper).Decrypt(inner));
                }
                if (!unknown) outList.Add(copy);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _log.LogWarning(RefusedText, ex.Message);
            return [];
        }
        return outList;
    }
}
