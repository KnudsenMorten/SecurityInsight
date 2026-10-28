using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// <summary>A request to claim the install key again that the updater has not taken yet.</summary>
public sealed record ClaimAgainRequest(string? RequestedBy, DateTime? RequestedAt);

/// <summary>Where the install key stands, in plain words, for the Updates card.</summary>
public sealed record InstallKeyStatus(string State, string Text, string Tone, bool CanClaimAgain);

/// <summary>
/// CLAIM THE INSTALL KEY AGAIN (Settings &gt; Updates). The updater claims the install key from Invardia once; a claim
/// Invardia answers 409 is HELD and never repeated by itself (no loop). After Invardia support reset this install's key,
/// an Admin asks for ONE more claim here: the web app writes the request row cfg.InstallState 'InstallKeyClaimAgain'
/// through cfg.InstallKeyClaimAgainRequest (it holds no write right on the table), and the updater takes the request
/// away before it claims -- claimed, or held again on another 409. The outcome comes back in the update state
/// ('claim' / 'claimAgain').
/// </summary>
public sealed class InstallKeyClaimAgain
{
    public const string PendingSql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT UpdatedBy, UpdatedAt FROM cfg.InstallState WHERE Name = N'InstallKeyClaimAgain';
""";
    public const string RequestSql = "EXEC cfg.InstallKeyClaimAgainRequest @RequestedBy = @By;";

    private readonly ISqlExecutor _sql;
    public InstallKeyClaimAgain(ISqlExecutor sql) => _sql = sql;

    /// The request the updater has not taken yet; null = none.
    public async Task<ClaimAgainRequest?> PendingAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(PendingSql, new Dictionary<string, object?>(), ct);
        var row = rows.FirstOrDefault(r => r.ContainsKey("UpdatedAt") || r.ContainsKey("UpdatedBy"));
        return row is null ? null : new ClaimAgainRequest(row.Str("UpdatedBy"), row.Date("UpdatedAt"));
    }

    public Task RequestAsync(string by, CancellationToken ct) =>
        _sql.QueryAsync(RequestSql, new Dictionary<string, object?> { ["By"] = by }, ct);

    /// <summary>
    /// The install key's state from the update state and a pending request: requested / refused-again / held / claimed /
    /// a claim problem; null = nothing to say (the key is in place). Claim again is offered only while the claim is held
    /// (Invardia answered 409) and no request is waiting.
    /// </summary>
    public static InstallKeyStatus? Describe(UpdateState? s, ClaimAgainRequest? pending)
    {
        var held = s?.Claim == "conflict";
        if (pending is not null)
            return new("requested", "Claim again requested" + (string.IsNullOrWhiteSpace(pending.RequestedBy) ? "" : " by " + pending.RequestedBy)
                + " -- the updater job claims the key once on its next run (every night, or start the job now).", "warn", false);
        if (held && s!.ClaimAgain == "conflict")
            return new("refused-again", "Held -- Invardia refused the claim again (409). Ask Invardia support to reset this install's key, then claim it again.", "bad", true);
        if (held)
            return new("held", "Held -- Invardia refused the claim (409): this install's key exists or was reset. Once Invardia support has reset it, claim it again.", "bad", true);
        if (!string.IsNullOrEmpty(s?.Claim))
            return new("problem", s!.Claim + " -- ask Invardia support", "warn", false);
        if (s?.ClaimAgain == "claimed")
            return new("claimed", "Claimed -- the install key was claimed again and is in the Key Vault.", "ok", false);
        return null;
    }
}
