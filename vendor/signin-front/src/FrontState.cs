using System.Data;
using System.Security.Cryptography;
using System.Xml.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Caching.Distributed;

namespace SigninFront;

/// <summary>
/// 1.3.0 -- the front's STATE in the product's own SQL database (framework §12.11g item 9, agreed PIM + SI + Invardia
/// 2026-10-21): the sessions, the MSAL token cache (the refresh tokens behind the ID token refresh) and the ASP.NET Data
/// Protection key ring (the keys that encrypt the session cookie, the OIDC state and the stored sessions; wrapped by a Key
/// Vault key, Program.cs). Signed in as the managed identity named by SIGNIN_STATE_MI_CLIENT_ID -- no password, no
/// connection-string setting. So a release roll, a restart or a second replica no longer signs anyone out or breaks a
/// sign-in in flight ("Unable to unprotect the message.State" after every roll in 1.2.x: the keys were on the container's
/// disk and the sessions in its memory). Two tables in the schema 'signin', created on first use; the product's setup
/// creates the schema for the identity (README "Setup").
/// </summary>
public sealed class SqlFrontStore : IDistributedCache, IXmlRepository
{
    public const string Schema = "signin";
    private readonly string _connectionString;
    private readonly ILogger _log;
    private readonly TimeProvider _time;
    private volatile bool _ready;
    private readonly SemaphoreSlim _init = new(1, 1);

    public SqlFrontStore(string connectionString, ILogger log, TimeProvider? time = null)
    {
        _connectionString = connectionString; _log = log; _time = time ?? TimeProvider.System;
    }

    /// <summary>The production connection: the managed identity, encrypted, never a password.</summary>
    public static string ManagedIdentityConnectionString(FrontSettings s) => new SqlConnectionStringBuilder
    {
        DataSource = $"tcp:{s.SqlServer},1433",
        InitialCatalog = s.SqlDatabase,
        Authentication = SqlAuthenticationMethod.ActiveDirectoryManagedIdentity,
        UserID = s.StateManagedIdentityClientId,
        Encrypt = SqlConnectionEncryptOption.Mandatory,
        TrustServerCertificate = false,
        ConnectTimeout = 30,
        ApplicationName = "signin-front",
    }.ConnectionString;

    public const string CreateSql = @"
IF SCHEMA_ID(N'signin') IS NULL EXEC(N'CREATE SCHEMA signin');
IF OBJECT_ID(N'signin.Cache', N'U') IS NULL
BEGIN
    CREATE TABLE signin.Cache (
        Id nvarchar(449) NOT NULL CONSTRAINT PK_signin_Cache PRIMARY KEY,
        Value varbinary(max) NOT NULL,
        ExpiresAtUtc datetime2 NOT NULL,
        SlidingSeconds int NULL,
        AbsoluteExpiresAtUtc datetime2 NULL);
    CREATE INDEX IX_signin_Cache_Expires ON signin.Cache (ExpiresAtUtc);
END;
IF OBJECT_ID(N'signin.DataProtectionKeys', N'U') IS NULL
    CREATE TABLE signin.DataProtectionKeys (
        FriendlyName nvarchar(200) NOT NULL CONSTRAINT PK_signin_DataProtectionKeys PRIMARY KEY,
        Xml nvarchar(max) NOT NULL,
        CreatedUtc datetime2 NOT NULL CONSTRAINT DF_signin_DataProtectionKeys_Created DEFAULT SYSUTCDATETIME());";

    private SqlConnection Open()
    {
        var c = new SqlConnection(_connectionString);
        c.Open();
        return c;
    }

    private async Task<SqlConnection> OpenAsync(CancellationToken ct)
    {
        var c = new SqlConnection(_connectionString);
        await c.OpenAsync(ct);
        return c;
    }

    private void EnsureTables()
    {
        if (_ready) return;
        _init.Wait();
        try
        {
            if (_ready) return;
            using var c = Open();
            using var cmd = new SqlCommand(CreateSql, c);
            cmd.ExecuteNonQuery();
            _ready = true;
        }
        finally { _init.Release(); }
    }

    private async Task EnsureTablesAsync(CancellationToken ct)
    {
        if (_ready) return;
        await _init.WaitAsync(ct);
        try
        {
            if (_ready) return;
            await using var c = await OpenAsync(ct);
            await using var cmd = new SqlCommand(CreateSql, c);
            await cmd.ExecuteNonQueryAsync(ct);
            _ready = true;
        }
        finally { _init.Release(); }
    }

    // ---- IDistributedCache ------------------------------------------------------------------------------------------

    /// <summary>PURE. The expiry a new entry gets: the absolute end, or now + sliding capped by the absolute end.</summary>
    public static (DateTime Expires, int? Sliding, DateTime? Absolute) ExpiryOf(DistributedCacheEntryOptions o, DateTimeOffset now)
    {
        DateTimeOffset? abs = o.AbsoluteExpiration;
        if (o.AbsoluteExpirationRelativeToNow is { } rel) abs = now + rel;
        int? sliding = o.SlidingExpiration is { } s ? (int)Math.Max(1, s.TotalSeconds) : null;
        if (abs is null && sliding is null) throw new InvalidOperationException("signin-front: a stored entry needs an expiry (absolute or sliding) -- nothing is kept for ever.");
        var exp = sliding is { } sl ? now.AddSeconds(sl) : abs!.Value;
        if (abs is { } a && a < exp) exp = a;
        return (exp.UtcDateTime, sliding, abs?.UtcDateTime);
    }

    public byte[]? Get(string key) => GetAsync(key).GetAwaiter().GetResult();

    public async Task<byte[]?> GetAsync(string key, CancellationToken token = default)
    {
        await EnsureTablesAsync(token);
        await using var c = await OpenAsync(token);
        // read and slide in ONE statement: an expired row is never returned
        await using var cmd = new SqlCommand(@"
UPDATE signin.Cache SET ExpiresAtUtc =
    CASE WHEN SlidingSeconds IS NULL THEN ExpiresAtUtc
         WHEN AbsoluteExpiresAtUtc IS NOT NULL AND AbsoluteExpiresAtUtc < DATEADD(second, SlidingSeconds, @now) THEN AbsoluteExpiresAtUtc
         ELSE DATEADD(second, SlidingSeconds, @now) END
OUTPUT inserted.Value
WHERE Id = @id AND ExpiresAtUtc > @now;", c);
        cmd.Parameters.Add("@id", SqlDbType.NVarChar, 449).Value = key;
        cmd.Parameters.Add("@now", SqlDbType.DateTime2).Value = _time.GetUtcNow().UtcDateTime;
        return await cmd.ExecuteScalarAsync(token) as byte[];
    }

    public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => SetAsync(key, value, options).GetAwaiter().GetResult();

    public async Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
    {
        await EnsureTablesAsync(token);
        var (exp, sliding, abs) = ExpiryOf(options, _time.GetUtcNow());
        await using var c = await OpenAsync(token);
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await using var cmd = new SqlCommand(@"
UPDATE signin.Cache SET Value = @v, ExpiresAtUtc = @e, SlidingSeconds = @s, AbsoluteExpiresAtUtc = @a WHERE Id = @id;
IF @@ROWCOUNT = 0 INSERT signin.Cache (Id, Value, ExpiresAtUtc, SlidingSeconds, AbsoluteExpiresAtUtc) VALUES (@id, @v, @e, @s, @a);", c);
                cmd.Parameters.Add("@id", SqlDbType.NVarChar, 449).Value = key;
                cmd.Parameters.Add("@v", SqlDbType.VarBinary, -1).Value = value;
                cmd.Parameters.Add("@e", SqlDbType.DateTime2).Value = exp;
                cmd.Parameters.Add("@s", SqlDbType.Int).Value = (object?)sliding ?? DBNull.Value;
                cmd.Parameters.Add("@a", SqlDbType.DateTime2).Value = (object?)abs ?? DBNull.Value;
                await cmd.ExecuteNonQueryAsync(token);
                return;
            }
            catch (SqlException ex) when (ex.Number is 2627 or 2601 && attempt < 2) { }   // two replicas inserted the same key: update it
        }
    }

    public void Refresh(string key) => RefreshAsync(key).GetAwaiter().GetResult();

    public async Task RefreshAsync(string key, CancellationToken token = default) => await GetAsync(key, token);

    public void Remove(string key) => RemoveAsync(key).GetAwaiter().GetResult();

    public async Task RemoveAsync(string key, CancellationToken token = default)
    {
        await EnsureTablesAsync(token);
        await using var c = await OpenAsync(token);
        await using var cmd = new SqlCommand("DELETE signin.Cache WHERE Id = @id;", c);
        cmd.Parameters.Add("@id", SqlDbType.NVarChar, 449).Value = key;
        await cmd.ExecuteNonQueryAsync(token);
    }

    /// <summary>Deletes expired entries (at most 5,000 per call); returns how many.</summary>
    public async Task<int> DeleteExpiredAsync(CancellationToken token = default)
    {
        await EnsureTablesAsync(token);
        await using var c = await OpenAsync(token);
        await using var cmd = new SqlCommand("DELETE TOP (5000) signin.Cache WHERE ExpiresAtUtc <= @now;", c);
        cmd.Parameters.Add("@now", SqlDbType.DateTime2).Value = _time.GetUtcNow().UtcDateTime;
        return await cmd.ExecuteNonQueryAsync(token);
    }

    // ---- IXmlRepository (the Data Protection key ring; each key element is wrapped by Key Vault before it gets here) --

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        EnsureTables();
        using var c = Open();
        using var cmd = new SqlCommand("SELECT Xml FROM signin.DataProtectionKeys ORDER BY CreatedUtc;", c);
        using var r = cmd.ExecuteReader();
        var list = new List<XElement>();
        while (r.Read()) list.Add(XElement.Parse(r.GetString(0)));
        return list;
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        EnsureTables();
        using var c = Open();
        using var cmd = new SqlCommand(@"
IF NOT EXISTS (SELECT 1 FROM signin.DataProtectionKeys WHERE FriendlyName = @n)
    INSERT signin.DataProtectionKeys (FriendlyName, Xml) VALUES (@n, @x);", c);
        cmd.Parameters.Add("@n", SqlDbType.NVarChar, 200).Value = string.IsNullOrWhiteSpace(friendlyName) ? Guid.NewGuid().ToString("D") : friendlyName;
        cmd.Parameters.Add("@x", SqlDbType.NVarChar, -1).Value = element.ToString(SaveOptions.DisableFormatting);
        cmd.ExecuteNonQuery();
        _log.LogInformation("signin-front: a Data Protection key was stored ({Name})", friendlyName);
    }
}

/// <summary>Deletes expired sessions and token-cache entries every 30 minutes (only when the SQL store is in use).</summary>
public sealed class FrontStateCleanup : BackgroundService
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<FrontStateCleanup> _log;
    public FrontStateCleanup(IServiceProvider sp, ILogger<FrontStateCleanup> log) { _sp = sp; _log = log; }

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        if (_sp.GetService<IDistributedCache>() is not SqlFrontStore store) return;
        try { await Task.Delay(TimeSpan.FromMinutes(2), stop); } catch (OperationCanceledException) { return; }
        while (!stop.IsCancellationRequested)
        {
            try
            {
                int n, total = 0;
                do { n = await store.DeleteExpiredAsync(stop); total += n; } while (n == 5000 && !stop.IsCancellationRequested);
                if (total > 0) _log.LogInformation("signin-front: {Count} expired session / token entries deleted", total);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning("signin-front: the expired-entry cleanup failed ({Type}); retried in 30 minutes", ex.GetType().Name);
            }
            try { await Task.Delay(TimeSpan.FromMinutes(30), stop); } catch (OperationCanceledException) { return; }
        }
    }
}

/// <summary>
/// 1.3.0 -- the session store over the shared state (IDistributedCache = SQL in production). The cookie carries only a
/// random session key; the ticket (the user, the ID token) is serialized, ENCRYPTED with the front's Data Protection keys
/// (so a database reader learns nothing from a row) and stored until the pinned session end. Replaces 1.2.x's
/// MemoryTicketStore: a restart or another replica now finds the same session.
/// </summary>
public sealed class DistributedTicketStore : ITicketStore
{
    /// <summary>1.2.1: the ticket carries its own key, so a silent ID token refresh renews the SAME entry (no key rotation).</summary>
    public const string KeyItem = "signin.session";
    private const string Prefix = "signin-session:";

    private readonly IDistributedCache _cache;
    private readonly IDataProtector _protector;
    private readonly FrontSettings _settings;
    private readonly TimeProvider _time;

    public DistributedTicketStore(IDistributedCache cache, IDataProtectionProvider dp, FrontSettings settings, TimeProvider time)
    {
        _cache = cache; _protector = dp.CreateProtector("signin-front.session.v1"); _settings = settings; _time = time;
    }

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        var key = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        ticket.Properties.Items[KeyItem] = key;
        await PutAsync(key, ticket);
        return key;
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket) => PutAsync(key, ticket);

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var bytes = await _cache.GetAsync(Prefix + key);
        if (bytes is null) return null;
        try { return TicketSerializer.Default.Deserialize(_protector.Unprotect(bytes)); }
        catch (CryptographicException) { return null; }   // written under a key ring this front cannot read: sign in again
    }

    public Task RemoveAsync(string key) => _cache.RemoveAsync(Prefix + key);

    private Task PutAsync(string key, AuthenticationTicket ticket)
    {
        // never past the pinned session end; the cookie handler checks the same end on every request
        var end = ticket.Properties.ExpiresUtc ?? _time.GetUtcNow() + _settings.Session;
        var bytes = _protector.Protect(TicketSerializer.Default.Serialize(ticket));
        return _cache.SetAsync(Prefix + key, bytes, new DistributedCacheEntryOptions { AbsoluteExpiration = end });
    }
}
