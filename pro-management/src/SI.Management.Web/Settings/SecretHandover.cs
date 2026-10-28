using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SI.Management.Web.Data;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Settings;

/// <summary>
/// THE SECRET HAND-OVER (owner 2026-10-10: "this is a security concern, can we commit this to the engine and then the
/// engine commits it, so the gui keeps read only if possible"). The web app NEVER writes a secret and holds no Key Vault
/// secret permission. A pasted secret is encrypted here, in memory: a random AES-256-GCM data key encrypts it, and RSA-OAEP-256
/// with the updater's PUBLIC hand-over key (cfg.SecretHandoverKey, published by the updater; its private half is a Key Vault
/// KEY that never leaves the vault) wraps the data key. Only that ciphertext, the target secret NAME, the setting and
/// who/when go to cfg.PendingSecret. The updater (container/updater/_shared/SI-UpdaterSecretHandover.ps1) unwraps the data
/// key INSIDE the vault, writes the secret, points the setting at the secret's name and removes the row.
/// </summary>
public sealed record HandoverKey(string KeyVersion, string KeyName, string N, string E);

/// What the web app stores: base64url text of each part. Never the secret.
public sealed record SealedSecret(string WrappedKey, string Nonce, string Tag, string Ciphertext);

/// The state of one secret as the page shows it, read fresh on every page load: stored, waiting for the updater, or what
/// the updater could not do (in its own plain words).
public enum SecretState { NotSet, Stored, Waiting, Failed }

public sealed record PendingSecretState(long PendingId, string SettingName, string SecretName, string KeyVersion, DateTime? CreatedAt, string CreatedBy,
    int Attempts, DateTime? LastAttemptAt, string? FailureText);

public static class SecretEnvelope
{
    public const int DataKeyBytes = 32, NonceBytes = 12, TagBytes = 16;

    /// The additional authenticated data: the ciphertext is bound to the setting, the secret name and the key version, so a
    /// row cannot be pointed at another secret without the updater's decrypt failing.
    public static byte[] Aad(string settingName, string secretName, string keyVersion) =>
        Encoding.UTF8.GetBytes("si-secret-handover|" + settingName + "|" + secretName + "|" + keyVersion);

    public static SealedSecret Seal(HandoverKey key, string settingName, string secretName, string value)
    {
        var plain = Encoding.UTF8.GetBytes(value);
        var dataKey = RandomNumberGenerator.GetBytes(DataKeyBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var cipher = new byte[plain.Length];
        var tag = new byte[TagBytes];
        try
        {
            using (var aes = new AesGcm(dataKey, TagBytes)) aes.Encrypt(nonce, plain, cipher, tag, Aad(settingName, secretName, key.KeyVersion));
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = FromB64Url(key.N), Exponent = FromB64Url(key.E) });
            var wrapped = rsa.Encrypt(dataKey, RSAEncryptionPadding.OaepSHA256);
            return new SealedSecret(B64Url(wrapped), B64Url(nonce), B64Url(tag), B64Url(cipher));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dataKey);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    /// The reverse, for the tests only: the updater unwraps the data key inside the vault and never here.
    public static string Open(RSA privateKey, string keyVersion, string settingName, string secretName, SealedSecret s)
    {
        var dataKey = privateKey.Decrypt(FromB64Url(s.WrappedKey), RSAEncryptionPadding.OaepSHA256);
        var cipher = FromB64Url(s.Ciphertext);
        var plain = new byte[cipher.Length];
        using (var aes = new AesGcm(dataKey, TagBytes)) aes.Decrypt(FromB64Url(s.Nonce), cipher, FromB64Url(s.Tag), plain, Aad(settingName, secretName, keyVersion));
        return Encoding.UTF8.GetString(plain);
    }

    public static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromB64Url(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t.PadRight(t.Length + (4 - t.Length % 4) % 4, '='));
    }

    /// The public JWK the updater publishes ({"kty":"RSA","n":"...","e":"..."}); null when it is not an RSA public key of
    /// at least 3072 bits.
    public static HandoverKey? ParseJwk(string keyVersion, string keyName, string? jwk)
    {
        if (string.IsNullOrWhiteSpace(jwk)) return null;
        try
        {
            using var d = JsonDocument.Parse(jwk);
            var r = d.RootElement;
            if (!r.TryGetProperty("kty", out var kty) || !(kty.GetString() ?? "").StartsWith("RSA", StringComparison.Ordinal)) return null;
            var n = r.GetProperty("n").GetString(); var e = r.GetProperty("e").GetString();
            if (string.IsNullOrEmpty(n) || string.IsNullOrEmpty(e) || FromB64Url(n).Length < 384) return null;
            return new HandoverKey(keyVersion, keyName, n, e);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or KeyNotFoundException or InvalidOperationException) { return null; }
    }
}

/// The two tables of the hand-over. The web app reads the public key and the pending rows' STATE (never the ciphertext
/// back), and writes one pending row -- a newer paste for the same setting replaces the one still waiting.
public interface ISecretHandoverStore
{
    Task<HandoverKey?> CurrentKeyAsync(CancellationToken ct);
    /// "Saved", or "Missing" (the database has no hand-over tables yet -- the updater adds them).
    Task<string> PutAsync(string settingName, string secretName, string keyVersion, SealedSecret sealedSecret, string by, CancellationToken ct);
    Task<PendingSecretState?> StateAsync(string settingName, CancellationToken ct);
    /// When the updater last STORED a secret for this hand-over key, and who handed it over (#822: a connector secret has no
    /// setting row to show it -- the updater's 'secret-stored' line in cfg.ChangeLog does). Null = never.
    Task<(DateTime At, string By)?> LastStoredAsync(string settingName, CancellationToken ct) => Task.FromResult<(DateTime, string)?>(null);
}

public sealed class SqlSecretHandoverStore(ISqlExecutor sql) : ISecretHandoverStore
{
    public const string KeySql = """
IF OBJECT_ID(N'cfg.SecretHandoverKey') IS NOT NULL
SELECT TOP (1) KeyVersion, KeyName, PublicJwk FROM cfg.SecretHandoverKey WHERE IsCurrent = 1 ORDER BY PublishedAt DESC;
""";

    /// One transaction: the earlier row for the same setting (stored or failed) is replaced, the new one inserted, and the
    /// hand-over logged in cfg.ChangeLog WITHOUT the value (only the secret's name).
    public const string PutSql = """
IF OBJECT_ID(N'cfg.PendingSecret') IS NULL BEGIN SELECT N'Missing' AS Outcome; RETURN; END;
SET XACT_ABORT ON;
BEGIN TRAN;
DELETE FROM cfg.PendingSecret WHERE SettingName = @Setting;
INSERT cfg.PendingSecret (SettingName, SecretName, KeyVersion, WrappedKey, Nonce, Tag, Ciphertext, CreatedBy)
VALUES (@Setting, @Secret, @KeyVersion, @WrappedKey, @Nonce, @Tag, @Ciphertext, @By);
INSERT cfg.ChangeLog (Name, Scope, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Setting, N'secret-handover', N'Set', NULL, N'keyvault:' + @Secret, @By, N'handed to the updater encrypted, to store in Key Vault (the value is never recorded)');
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    public const string StateSql = """
IF OBJECT_ID(N'cfg.PendingSecret') IS NOT NULL
SELECT TOP (1) PendingId, SettingName, SecretName, KeyVersion, CreatedAt, CreatedBy, Attempts, LastAttemptAt, FailureText
FROM cfg.PendingSecret WHERE SettingName = @Setting ORDER BY CreatedAt DESC, PendingId DESC;
""";

    /// The updater's "stored" line for a hand-over key (Complete-SIPendingSecret writes it: scope 'secret-stored', the person
    /// who handed it over, never the value), newest first.
    public const string LastStoredSql = """
SELECT TOP (1) ChangedAt, ChangedBy FROM cfg.ChangeLog
WHERE Name = @Setting AND Scope = N'secret-stored' AND Action = N'Set' ORDER BY ChangedAt DESC;
""";

    public async Task<(DateTime At, string By)?> LastStoredAsync(string settingName, CancellationToken ct)
    {
        var rows = await sql.QueryAsync(LastStoredSql, new Dictionary<string, object?> { ["Setting"] = settingName }, ct);
        if (rows.Count == 0 || rows[0].Date("ChangedAt") is not { } at) return null;
        return (at, rows[0].Str("ChangedBy") ?? "");
    }

    public async Task<HandoverKey?> CurrentKeyAsync(CancellationToken ct)
    {
        var rows = await sql.QueryAsync(KeySql, new Dictionary<string, object?>(), ct);
        if (rows.Count == 0) return null;
        return SecretEnvelope.ParseJwk(rows[0].Str("KeyVersion") ?? "", rows[0].Str("KeyName") ?? "", rows[0].Str("PublicJwk"));
    }

    public async Task<string> PutAsync(string settingName, string secretName, string keyVersion, SealedSecret s, string by, CancellationToken ct)
    {
        var rows = await sql.QueryAsync(PutSql, new Dictionary<string, object?>
        {
            ["Setting"] = settingName, ["Secret"] = secretName, ["KeyVersion"] = keyVersion,
            ["WrappedKey"] = s.WrappedKey, ["Nonce"] = s.Nonce, ["Tag"] = s.Tag, ["Ciphertext"] = s.Ciphertext, ["By"] = by,
        }, ct);
        return rows.Count > 0 ? rows[0].Str("Outcome") ?? "Saved" : "Saved";
    }

    public async Task<PendingSecretState?> StateAsync(string settingName, CancellationToken ct)
    {
        var rows = await sql.QueryAsync(StateSql, new Dictionary<string, object?> { ["Setting"] = settingName }, ct);
        if (rows.Count == 0) return null;
        var r = rows[0];
        return new PendingSecretState(r.Long("PendingId") ?? 0, r.Str("SettingName") ?? settingName, r.Str("SecretName") ?? "", r.Str("KeyVersion") ?? "",
            r.Date("CreatedAt"), r.Str("CreatedBy") ?? "", (int)(r.Long("Attempts") ?? 0), r.Date("LastAttemptAt"), r.Str("FailureText"));
    }
}

/// The result of a hand-over: the words for the page, and whether the updater was asked to store it now.
public sealed record HandoverResult(bool Ok, string Message, bool UpdaterStarted = false);

/// The key's state for the page: what it is and the words beside the paste box.
public sealed record SecretStateView(SecretState State, string Text, DateTime? Since = null);

/// <summary>
/// Hands one secret to the updater (see <see cref="HandoverKey"/>'s summary) and starts the updater's short "apply
/// settings" run when the web app may start jobs; otherwise the next updater run picks it up. Also reads the state the page
/// shows on every load -- a failure stays visible until it is stored or replaced.
/// </summary>
public sealed class SecretHandoverService(ISecretHandoverStore store, IJobsClient jobs, ILogger<SecretHandoverService> log,
    Microsoft.Extensions.Options.IOptions<JobsOptions>? jobOptions = null)
{
    /// The updater job (today's name; CR5 step 1: the install's own name is <see cref="UpdaterJobName"/>) and the variable
    /// that makes its run the short one (apply the settings only: no code, no templates).
    public const string UpdaterJob = "caj-si-updater";
    /// The updater job this install runs (Jobs__UpdaterJob), else today's name.
    public string UpdaterJobName => jobOptions?.Value?.UpdaterJobName ?? UpdaterJob;
    public const string ModeVariable = "SI_UPDATER_MODE";
    public const string ApplyMode = "apply-settings";
    /// After this long a waiting secret is reported as overdue (the updater runs at least daily).
    public static readonly TimeSpan Overdue = TimeSpan.FromDays(2);

    public const string NoKeyText = "Nothing was stored yet: the updater has not prepared the secure hand-over on this install. It does that on its next run -- paste the key again after that.";
    public const string MissingTablesText = "Nothing was stored: the database is not ready for the secure hand-over yet. The updater prepares it on its next run -- paste the key again after that.";
    public const string NextRunText = "the updater stores it on its next run (daily, at night)";

    public async Task<HandoverResult> HandOverAsync(string settingName, string secretName, string value, string by, CancellationToken ct)
    {
        // #822: the allow-list, here -- every caller (the AI step, "Set value") passes it; the updater checks it again
        if (SecretAllowList.WhyNot(settingName, secretName) is { } why) return new(false, "Nothing was stored: " + why + ".");
        if (string.IsNullOrWhiteSpace(value)) return new(false, "Nothing was stored: the value is empty.");
        var key = await store.CurrentKeyAsync(ct);
        if (key is null)
        {
            // ask the updater to prepare its key now; the person pastes again once it is there
            await StartApplyAsync(ct);
            return new(false, NoKeyText);
        }
        var sealedSecret = SecretEnvelope.Seal(key, settingName, secretName, value);
        var outcome = await store.PutAsync(settingName, secretName, key.KeyVersion, sealedSecret, by, ct);
        if (outcome == "Missing") { await StartApplyAsync(ct); return new(false, MissingTablesText); }
        var started = await StartApplyAsync(ct);
        return new(true, started
            ? "The key was handed to the updater, encrypted. It stores it in your Key Vault within minutes -- this step shows when it is stored."
            : "The key was handed to the updater, encrypted -- " + NextRunText + ". This step shows when it is stored.", started);
    }

    /// Starts the updater's short apply run. False = not started (no jobs access here, or the start was refused): the next
    /// updater run picks the secret up.
    public async Task<bool> StartApplyAsync(CancellationToken ct)
    {
        try
        {
            if (!jobs.IsConfigured) return false;
            await jobs.StartWithEnvAsync(UpdaterJobName, new Dictionary<string, string> { [ModeVariable] = ApplyMode }, ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the updater's apply run could not be started -- the next updater run stores the secret");
            return false;
        }
    }

    /// The state the page shows, from the pending row (if any) and the setting row.
    public async Task<SecretStateView> StateAsync(string settingName, SettingRow? setting, DateTime utcNow, CancellationToken ct)
    {
        PendingSecretState? p = null;
        try { p = await store.StateAsync(settingName, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the pending secret could not be read"); }
        return Describe(p, setting, utcNow);
    }

    /// The state of ANY hand-over key (a setting or a connector secret, #822): waiting / failed from the pending row, else
    /// "set at ... by ..." from the updater's Stored line, else the setting row (a setting set before #822).
    public async Task<SecretStateView> StateOfAsync(string target, SettingRow? setting, DateTime utcNow, CancellationToken ct)
    {
        PendingSecretState? p = null; (DateTime At, string By)? stored = null;
        try { p = await store.StateAsync(target, ct); stored = await store.LastStoredAsync(target, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the secret's state could not be read"); }
        if (p is null && stored is { } s)
            return new(SecretState.Stored, "Set " + s.At.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) + " UTC" + (s.By.Length > 0 ? " by " + s.By : "") + " -- stored in your Key Vault.", s.At);
        return Describe(p, setting, utcNow);
    }

    public static SecretStateView Describe(PendingSecretState? p, SettingRow? setting, DateTime utcNow)
    {
        if (p is not null)
        {
            if (!string.IsNullOrWhiteSpace(p.FailureText)) return new(SecretState.Failed, "Not stored: " + p.FailureText.Trim(), p.LastAttemptAt ?? p.CreatedAt);
            if (p.CreatedAt is { } at && utcNow - at > Overdue)
                return new(SecretState.Waiting, "Waiting to be stored since " + at.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) + " -- the updater has not stored it yet. Check that the updater runs (" + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/Jobs") + ").", at);
            return new(SecretState.Waiting, "Waiting to be stored -- the updater stores it within minutes.", p.CreatedAt);
        }
        if (setting is not null && (!string.IsNullOrWhiteSpace(setting.KeyVaultSecretName) || !string.IsNullOrWhiteSpace(setting.ValueJson)))
            return new(SecretState.Stored, "Stored in your Key Vault.", setting.UpdatedAt);
        return new(SecretState.NotSet, "Not stored yet -- paste the key and save.");
    }
}
