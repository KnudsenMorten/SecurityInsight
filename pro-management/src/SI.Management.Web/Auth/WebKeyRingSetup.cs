using Microsoft.AspNetCore.DataProtection.KeyManagement;
using SI.Management.Web.Data;

namespace SI.Management.Web.Auth;

/// <summary>
/// WHERE THE WEB APP'S SIGN-IN KEYS ARE KEPT -- the one choice, made at start from the settings:
///   Blob        DataProtection:BlobUri names a blob (BlobRestKeyStore.ParseBlobUri): the keys in that blob, read and written
///               with the web app's managed identity, NO Key Vault (BlobKeyRing). The ring before is moved in once.
///   SqlKeyVault no blob, the Pro database and DataProtection:KeyVaultKeyId: cfg.WebKeyRing, each key wrapped with the Key
///               Vault key (SqlKeyRing + KeyRingProtection.cs) -- unchanged.
///   Sql         the Pro database only: cfg.WebKeyRing as before.
///   Memory      neither: the default (this process's keys).
/// A DataProtection:BlobUri that is not a blob URI (a SAS, another host) is NOT used: the choice is made as if it were unset.
/// </summary>
public static class WebKeyRingSetup
{
    public enum Mode { Memory, Sql, SqlKeyVault, Blob }

    /// PURE. The choice for these settings (<paramref name="sqlConfigured"/>: the Pro database is configured).
    public static Mode Select(IConfiguration configuration, bool sqlConfigured)
    {
        if (BlobRestKeyStore.ParseBlobUri(configuration["DataProtection:BlobUri"]) is not null) return Mode.Blob;
        if (!sqlConfigured) return Mode.Memory;
        var keyId = configuration["DataProtection:KeyVaultKeyId"];
        return !string.IsNullOrWhiteSpace(keyId) && KeyVaultKeyRingWrapper.IsKeyId(keyId) ? Mode.SqlKeyVault : Mode.Sql;
    }

    /// Registers the key ring the settings choose (after AddDataProtection). Returns the choice.
    public static Mode Add(IServiceCollection services, IConfiguration configuration, bool sqlConfigured)
    {
        var mode = Select(configuration, sqlConfigured);
        var keyId = configuration["DataProtection:KeyVaultKeyId"];
        var keyIdOk = !string.IsNullOrWhiteSpace(keyId) && KeyVaultKeyRingWrapper.IsKeyId(keyId);
        if (mode == Mode.Blob)
        {
            var blob = BlobRestKeyStore.ParseBlobUri(configuration["DataProtection:BlobUri"])!;
            // no IKeyRingKeyWrapper, no XmlEncryptor, no rotation: nothing here calls Key Vault -- except the ONE move of the
            // ring before, while the blob holds no key (its wrapper is made for that move only and is never registered)
            services.AddOptions<KeyManagementOptions>().Configure<IServiceProvider, ILoggerFactory>((o, sp, lf) =>
            {
                var cred = sp.GetRequiredService<Azure.Core.TokenCredential>();
                Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository? old = sqlConfigured
                    ? new SqlKeyRing(sp.GetRequiredService<AzureSqlExecutor>(), lf.CreateLogger<SqlKeyRing>()) : null;
                IKeyRingKeyWrapper? oldWrapper = old is not null && keyIdOk ? new KeyVaultKeyRingWrapper(cred, keyId!.Trim()) : null;
                o.XmlRepository = new BlobKeyRing(new BlobRestKeyStore(cred, blob), old, oldWrapper, lf.CreateLogger<BlobKeyRing>());
            });
            // the move at start, before the app answers (the updater waits for the revision to be Healthy)
            services.AddHostedService(sp => new BlobKeyRingStart(sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeyManagementOptions>>().Value.XmlRepository,
                sp.GetRequiredService<ILogger<BlobKeyRingStart>>()));
            return mode;
        }
        if (sqlConfigured)
            services.AddOptions<KeyManagementOptions>()
                // #1112: the key ring reads past the update window's guard (a sign-in cookie is still read while the notice shows)
                .Configure<AzureSqlExecutor, ILoggerFactory>((o, sql, lf) => o.XmlRepository = new SqlKeyRing(sql, lf.CreateLogger<SqlKeyRing>()));
        // The stored keys are ENCRYPTED with a Key Vault key only the web app's identity may use (KeyRingProtection.cs; the
        // updater creates the key, grants it and sets DataProtection__KeyVaultKeyId). Not set = the keys are stored as before.
        if (keyIdOk)
        {
            services.AddSingleton<IKeyRingKeyWrapper>(sp => new KeyVaultKeyRingWrapper(sp.GetRequiredService<Azure.Core.TokenCredential>(), keyId!.Trim()));
            services.AddOptions<KeyManagementOptions>()
                .Configure<IServiceProvider>((o, sp) => o.XmlEncryptor = new WrappedKeyXmlEncryptor(sp.GetRequiredService<IKeyRingKeyWrapper>()));
            services.AddHostedService(sp => new KeyRingRotation(sp.GetRequiredService<IKeyManager>(),
                sp.GetRequiredService<IKeyRingKeyWrapper>(),
                sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<KeyManagementOptions>>().Value.XmlRepository,
                sp.GetRequiredService<ILogger<KeyRingRotation>>()));
        }
        return mode;
    }
}
