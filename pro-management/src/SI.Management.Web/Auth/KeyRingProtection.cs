using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Azure.Core;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace SI.Management.Web.Auth;

/// <summary>
/// THE WEB APP'S SIGN-IN KEYS ARE STORED ENCRYPTED (the key ring in cfg.WebKeyRing, SqlKeyRing). Each key's XML is encrypted
/// with a fresh AES-256-GCM data key, and that data key is WRAPPED by a Key Vault key (RSA-OAEP-256) that only the web app's
/// own identity may use (the updater creates 'SI-Web-KeyRing' and grants the web identity "Key Vault Crypto Service
/// Encryption User" on that key alone, then sets DataProtection__KeyVaultKeyId). A principal that can read the table -- a
/// reporting reader, a DBA -- reads ciphertext it cannot use. The same thing ProtectKeysWithAzureKeyVault does, over the
/// Key Vault REST API with the process's one credential (no extra package).
/// Without DataProtection:KeyVaultKeyId nothing changes (the keys stay as they were).
/// </summary>
public interface IKeyRingKeyWrapper
{
    /// The Key Vault key's id (https://&lt;vault&gt;.vault.azure.net/keys/&lt;name&gt;[/&lt;version&gt;]).
    string KeyId { get; }
    /// Wraps a data key; returns the version-qualified key id that wrapped it and the wrapped bytes.
    (string Kid, byte[] Wrapped) Wrap(byte[] dataKey);
    /// Unwraps a data key with the key version <paramref name="kid"/> names.
    byte[] Unwrap(string kid, byte[] wrapped);
}

/// The Key Vault data-plane wrapKey / unwrapKey calls (api-version 7.4), as the web app's identity.
public sealed class KeyVaultKeyRingWrapper : IKeyRingKeyWrapper
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private readonly TokenCredential _credential;
    public string KeyId { get; }

    public KeyVaultKeyRingWrapper(TokenCredential credential, string keyId)
    {
        if (!IsKeyId(keyId)) throw new ArgumentException("not a Key Vault key id (https://<vault>.vault.azure.net/keys/<name>)", nameof(keyId));
        _credential = credential; KeyId = keyId.TrimEnd('/');
    }

    /// PURE. Is this a Key Vault key id on a Key Vault host (public or sovereign cloud)?
    public static bool IsKeyId(string? id) =>
        Uri.TryCreate((id ?? "").Trim(), UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps
        && (u.Host.EndsWith(".vault.azure.net", StringComparison.OrdinalIgnoreCase) || u.Host.EndsWith(".vault.usgovcloudapi.net", StringComparison.OrdinalIgnoreCase)
            || u.Host.EndsWith(".vault.azure.cn", StringComparison.OrdinalIgnoreCase))
        && u.AbsolutePath.StartsWith("/keys/", StringComparison.OrdinalIgnoreCase) && u.AbsolutePath.Length > "/keys/".Length;

    public (string Kid, byte[] Wrapped) Wrap(byte[] dataKey)
    {
        var (kid, value) = Call(KeyId + "/wrapkey", dataKey);
        return (kid, value);
    }

    public byte[] Unwrap(string kid, byte[] wrapped)
    {
        // only a version of THIS key is ever asked to unwrap (a stored element cannot send the web app to another vault)
        if (!kid.StartsWith(KeyId + "/", StringComparison.OrdinalIgnoreCase) && !string.Equals(kid, KeyId, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("the sign-in key was wrapped by another Key Vault key");
        return Call(kid.TrimEnd('/') + "/unwrapkey", wrapped).Value;
    }

    private (string Kid, byte[] Value) Call(string url, byte[] value)
    {
        var token = _credential.GetToken(new TokenRequestContext(["https://vault.azure.net/.default"]), CancellationToken.None);
        using var req = new HttpRequestMessage(HttpMethod.Post, url + "?api-version=7.4");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        req.Content = new StringContent(JsonSerializer.Serialize(new { alg = "RSA-OAEP-256", value = B64Url(value) }), Encoding.UTF8, "application/json");
        using var res = Http.Send(req);
        var body = res.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (!res.IsSuccessStatusCode) throw new CryptographicException($"Key Vault answered HTTP {(int)res.StatusCode} for the sign-in key's {(url.EndsWith("/wrapkey", StringComparison.Ordinal) ? "wrap" : "unwrap")}");
        using var doc = JsonDocument.Parse(body);
        var kid = doc.RootElement.TryGetProperty("kid", out var k) ? k.GetString() ?? KeyId : KeyId;
        return (kid, FromB64Url(doc.RootElement.GetProperty("value").GetString() ?? ""));
    }

    internal static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    internal static byte[] FromB64Url(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
        return Convert.FromBase64String(t);
    }
}

/// Encrypts one key element: AES-256-GCM with a fresh data key, the data key wrapped by the Key Vault key.
public sealed class WrappedKeyXmlEncryptor(IKeyRingKeyWrapper wrapper) : IXmlEncryptor
{
    public const string ElementName = "siWrappedKey";

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        var dataKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var plain = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
            var cipher = new byte[plain.Length]; var tag = new byte[16];
            using (var aes = new AesGcm(dataKey, 16)) aes.Encrypt(nonce, plain, cipher, tag);
            CryptographicOperations.ZeroMemory(plain);
            var (kid, wrapped) = wrapper.Wrap(dataKey);
            var e = new XElement(ElementName,
                new XElement("kid", kid), new XElement("wrappedKey", Convert.ToBase64String(wrapped)),
                new XElement("nonce", Convert.ToBase64String(nonce)), new XElement("tag", Convert.ToBase64String(tag)),
                new XElement("value", Convert.ToBase64String(cipher)));
            return new EncryptedXmlInfo(e, typeof(WrappedKeyXmlDecryptor));
        }
        finally { CryptographicOperations.ZeroMemory(dataKey); }
    }
}

/// Decrypts what <see cref="WrappedKeyXmlEncryptor"/> wrote (the wrapper comes from the app's services).
public sealed class WrappedKeyXmlDecryptor : IXmlDecryptor
{
    private readonly IKeyRingKeyWrapper _wrapper;
    public WrappedKeyXmlDecryptor(IServiceProvider services) =>
        _wrapper = services.GetService(typeof(IKeyRingKeyWrapper)) as IKeyRingKeyWrapper
                   ?? throw new InvalidOperationException("the sign-in keys are encrypted with Key Vault, but no Key Vault key is configured (DataProtection:KeyVaultKeyId)");
    public WrappedKeyXmlDecryptor(IKeyRingKeyWrapper wrapper) => _wrapper = wrapper;

    public XElement Decrypt(XElement encryptedElement)
    {
        string V(string n) => (string?)encryptedElement.Element(n) ?? throw new CryptographicException($"the encrypted sign-in key has no {n}");
        var dataKey = _wrapper.Unwrap(V("kid"), Convert.FromBase64String(V("wrappedKey")));
        try
        {
            var cipher = Convert.FromBase64String(V("value")); var plain = new byte[cipher.Length];
            using (var aes = new AesGcm(dataKey, 16)) aes.Decrypt(Convert.FromBase64String(V("nonce")), cipher, Convert.FromBase64String(V("tag")), plain);
            try { return XElement.Parse(Encoding.UTF8.GetString(plain)); } finally { CryptographicOperations.ZeroMemory(plain); }
        }
        finally { CryptographicOperations.ZeroMemory(dataKey); }
    }
}

/// <summary>
/// THE KEYS FROM BEFORE ARE RETIRED: once the Key Vault key works (a wrap and an unwrap of a test value), a key ring that
/// still holds a key stored WITHOUT encryption (written before the protection was on) is rotated -- every key revoked and a
/// new, encrypted one made. Everyone signs in again once; a stolen copy of the old table forges nothing after it. Tried at
/// start and every 10 minutes until it has run (a fresh grant can take minutes to reach Key Vault); never stops the app.
/// </summary>
public sealed class KeyRingRotation(IKeyManager keys, IKeyRingKeyWrapper wrapper, Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository? repository,
    ILogger<KeyRingRotation> log) : BackgroundService
{
    public const string Reason = "the sign-in keys are protected with Key Vault from now on";

    /// PURE. Does the stored ring hold a key that is still in force and was written without encryption?
    public static bool HasPlainKeyInForce(IEnumerable<XElement> elements)
    {
        var list = elements.ToList();
        DateTimeOffset? revokedBefore = null;
        var revokedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in list.Where(e => e.Name.LocalName == "revocation"))
        {
            var id = (string?)r.Element("key")?.Attribute("id");
            if (id == "*") { if (DateTimeOffset.TryParse((string?)r.Element("revocationDate"), out var d) && (revokedBefore is null || d > revokedBefore)) revokedBefore = d; }
            else if (id is not null) revokedIds.Add(id);
        }
        foreach (var k in list.Where(e => e.Name.LocalName == "key"))
        {
            var id = (string?)k.Attribute("id") ?? "";
            if (revokedIds.Contains(id)) continue;
            if (revokedBefore is { } rb && DateTimeOffset.TryParse((string?)k.Element("creationDate"), out var c) && c <= rb) continue;
            // the secret of an encrypted key sits under <encryptedSecret>; a plain one is a <value> right under <masterKey>
            var plain = k.Descendants().Any(e => e.Name.LocalName == "masterKey" && e.Elements().Any(v => v.Name.LocalName == "value"));
            if (plain) return true;
        }
        return false;
    }

    /// One attempt: true = done (rotated, or nothing to rotate); false = Key Vault is not usable yet (try again later).
    public bool TryOnce(DateTimeOffset now)
    {
        try
        {
            var probe = RandomNumberGenerator.GetBytes(32);
            var (kid, wrapped) = wrapper.Wrap(probe);
            if (!CryptographicOperations.FixedTimeEquals(wrapper.Unwrap(kid, wrapped), probe)) { log.LogWarning("The Key Vault key for the sign-in keys did not give the test value back; the keys are not rotated."); return false; }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            log.LogWarning("The Key Vault key for the sign-in keys cannot be used yet ({Message}); the stored keys are rotated once it can.", ex.Message);
            return false;
        }
        if (repository is null || !HasPlainKeyInForce(repository.GetAllElements())) return true;
        keys.RevokeAllKeys(now, Reason);
        keys.CreateNewKey(now, now.AddDays(90));
        log.LogWarning("The sign-in keys stored without encryption were revoked and a Key Vault-protected key made: everyone signs in again once.");
        return true;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            if (TryOnce(DateTimeOffset.UtcNow)) return;
            try { await Task.Delay(TimeSpan.FromMinutes(10), stoppingToken); } catch (OperationCanceledException) { return; }
        }
    }
}
