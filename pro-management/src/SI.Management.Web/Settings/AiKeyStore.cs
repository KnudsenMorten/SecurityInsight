namespace SI.Management.Web.Settings;

/// <summary>
/// The Azure OpenAI key, pasted ONCE in Get Started's AI step. The web app never writes it anywhere readable: it is handed
/// to the updater encrypted (<see cref="SecretHandoverService"/>, owner 2026-10-10: "so the gui keeps read only"), and the
/// updater stores it in the install's Key Vault as <see cref="SecretName"/> and points the setting OpenAI_apiKey at that
/// NAME. The key itself is never stored in the database, logged or shown. The web app's identity holds no Key Vault right.
/// </summary>
public sealed class AiKeyStore(SecretHandoverService handover)
{
    public const string SecretName = "SI-OpenAI-Key";
    public const string KeySetting = "OpenAI_apiKey";
    /// The paste box (its name says "secret", so the audit trail never records its value).
    public const string FormField = "OpenAIKeySecretValue";

    public const string NotAKeyText = "That does not look like an Azure OpenAI key -- copy it from the Azure portal (Keys and Endpoint). Nothing was stored.";

    public async Task<HandoverResult> StoreAsync(string key, string by, CancellationToken ct)
    {
        key = (key ?? "").Trim();
        if (key.Length < 16 || key.Any(char.IsWhiteSpace)) return new(false, NotAKeyText);
        return await handover.HandOverAsync(KeySetting, SecretName, key, by, ct);
    }

    /// The key's state beside the paste box, read fresh on every page load.
    public Task<SecretStateView> StateAsync(IReadOnlyList<SettingRow> rows, CancellationToken ct) =>
        handover.StateAsync(KeySetting, MailMode.RowOf(rows, KeySetting), DateTime.UtcNow, ct);
}
