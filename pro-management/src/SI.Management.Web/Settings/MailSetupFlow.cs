using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Advisors;

namespace SI.Management.Web.Settings;

/// What the SuperAdmin chose for a shared mailbox: create one (address + display name) or use an existing one, and the
/// engine identity Mail.Send is granted to (its client id and the object id of its service principal).
public sealed record SharedMailboxSetup(bool CreateMailbox, string Address, string DisplayName, string ClientId, string ServicePrincipalObjectId,
    string AdminUpn, string TenantId);

/// The SMTP relay the SuperAdmin entered. The password is only ever a Key Vault secret NAME.
public sealed record SmtpSetup(string Server, string Port, bool UseSsl, string? User, string From, string? PasswordSecretName);

/// One step of the guided setup, as the page lists it: number, title, "ok" | "failed" | "skipped" | "not run", message.
public sealed record MailSetupStep(int Number, string Title, string State, string Message)
{
    public const string Ok = "ok";
    public const string Failed = "failed";
    public const string Skipped = "skipped";
    public const string NotRun = "not run";
}

/// The run: every step, whether all went through, whether it stopped for a missing Exchange role, and -- for the Exchange
/// administrator -- the commands that finish the steps that did not run: download setup\Set-SIMail.ps1, run it with the
/// real values filled in (<see cref="MailSetupFlow.HandOverCommands"/>).
public sealed record MailSetupResult(IReadOnlyList<MailSetupStep> Steps, bool Succeeded, bool NeedsRole, IReadOnlyList<string> Commands);

/// <summary>
/// The guided "Set up mail" flow (SuperAdmin; Settings > E-mail + links). Shared mailbox: (1) create the mailbox if
/// asked, (2) register SI's identity in Exchange, (3) a management scope holding ONLY that mailbox, (4) 'Application
/// Mail.Send' assigned to the identity in that scope (RBAC for Applications -- never a tenant-wide Mail.Send), (5) verify
/// with Test-ServicePrincipalAuthorization (in scope for the mailbox, NOT for the admin's own mailbox) and record the
/// attestation, (6) save SI_Mail_Mode / SI_Mail_From / SI_Mail_ProbeMailbox through the settings writer (cfg.ChangeLog),
/// (7) queue a test mail. Each Exchange step is idempotent ('already exists' = ok). It stops at the first failure; a
/// 401/403 means the admin lacks the Exchange role -- the commands for the remaining steps are then handed over.
/// SMTP: the relay settings + SI_Mail_Mode='smtp' saved, then a test mail queued.
/// </summary>
public sealed class MailSetupFlow
{
    public const string RoleName = "Application Mail.Send";
    public const string ExchangeDisplayName = "SecurityInsight";
    public const string Reason = "guided mail setup";
    public const string DefaultPasswordSecretName = "SI-Smtp-Password";
    public const string ScriptUrl = "https://invardia.com/support/si/Set-SIMail.ps1";
    public const string NeedsRoleMessage = "This step needs the Exchange Administrator role (Entra) or Organization Management in Exchange -- your account does not have it. Ask your Exchange administrator to run setup\\Set-SIMail.ps1 (" + ScriptUrl + ").";

    private static readonly Regex Guid = new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant);
    private static readonly Regex Host = new(@"^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$", RegexOptions.CultureInvariant);

    private readonly IExchangeAdminClient _exchange;
    private readonly SettingsWriter _writer;
    private readonly SettingsCatalog _catalog;
    private readonly ISettingsStoreReader _reader;
    private readonly IMailStatusStore _store;
    private readonly ISignInMailer _mailer;
    private readonly TimeProvider _clock;

    public MailSetupFlow(IExchangeAdminClient exchange, SettingsWriter writer, SettingsCatalog catalog, ISettingsStoreReader reader, IMailStatusStore store,
        ISignInMailer mailer, TimeProvider clock)
    { _exchange = exchange; _writer = writer; _catalog = catalog; _reader = reader; _store = store; _mailer = mailer; _clock = clock; }

    /// #503 (owner 2026-10-09: "companies have their own naming"): the Exchange objects follow the MAILBOX's name, as
    /// setup\Set-SIMail.ps1 names them -- the scope '&lt;mailbox&gt;-Sender', the role assignment
    /// '&lt;mailbox&gt;-MailSend-&lt;first 8 of the client id&gt;'. No product name is forced on a customer; an existing scope or
    /// assignment that grants the same is adopted, never duplicated.
    public static string NamePart(string address)
    {
        var local = address.Trim();
        var at = local.IndexOf('@');
        if (at > 0) local = local[..at];
        var p = Regex.Replace(Regex.Replace(local, "[^A-Za-z0-9-]+", "-"), "-{2,}", "-").Trim('-');
        if (p.Length == 0) p = "Mail";
        return p.Length > 40 ? p[..40].TrimEnd('-') : p;
    }

    public static string ScopeName(string address) => NamePart(address) + "-Sender";

    public static string AssignmentName(string address, string clientId) => NamePart(address) + "-MailSend-" + clientId.Trim().Replace("-", "")[..Math.Min(8, clientId.Trim().Replace("-", "").Length)];

    private static string? Str(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// An existing scope that filters exactly this mailbox (by what it grants, whatever it is called), or null.
    public static string? AdoptableScope(IEnumerable<JsonElement> scopes, string address)
    {
        var want = Filter(address);
        foreach (var s in scopes)
        {
            var f = (Str(s, "RecipientRestrictionFilter") ?? Str(s, "RecipientFilter") ?? "").Trim();
            if (string.Equals(f, want, StringComparison.OrdinalIgnoreCase) && Str(s, "Name") is { Length: > 0 } n) return n;
        }
        return null;
    }

    /// An existing 'Application Mail.Send' assignment of this identity on this scope, whatever it is called.
    public static bool HasAssignment(IEnumerable<JsonElement> assignments, string scope, string clientId, string objectId) =>
        assignments.Any(a => string.Equals(Str(a, "Role"), RoleName, StringComparison.OrdinalIgnoreCase)
            && string.Equals(Str(a, "CustomResourceScope"), scope, StringComparison.OrdinalIgnoreCase)
            && new[] { Str(a, "App"), Str(a, "RoleAssignee"), Str(a, "RoleAssigneeName") }.Any(v => v is not null
                && (v.Contains(clientId, StringComparison.OrdinalIgnoreCase) || (objectId.Length > 0 && v.Contains(objectId, StringComparison.OrdinalIgnoreCase)))));

    public static string Filter(string address) => $"PrimarySmtpAddress -eq '{address.Trim().Replace("'", "''")}'";

    /// The steps' titles, in order.
    public static readonly IReadOnlyList<string> SharedSteps =
    [
        "Create the shared mailbox",
        "Register SecurityInsight's identity in Exchange",
        "Create a management scope holding only the shared mailbox",
        "Assign 'Application Mail.Send' in that scope",
        "Verify Mail.Send reaches only the shared mailbox",
        "Save the mail settings",
        "Queue a test mail",
    ];

    /// What is wrong with the choice, or null.
    public static string? Validate(SharedMailboxSetup s)
    {
        if (!SettingsForm.IsMailAddress(s.Address ?? "")) return "Give the shared mailbox's address (name@domain).";
        if (s.CreateMailbox && (string.IsNullOrWhiteSpace(s.DisplayName) || s.DisplayName.Trim().Length > 64)) return "Give the new mailbox a display name (at most 64 characters).";
        if (!Guid.IsMatch((s.ClientId ?? "").Trim())) return "Give the client id (a GUID) of SecurityInsight's engine identity.";
        if (!Guid.IsMatch((s.ServicePrincipalObjectId ?? "").Trim())) return "Give the object id (a GUID) of the engine identity's service principal (Entra > Enterprise applications).";
        if (!SettingsForm.IsMailAddress(s.AdminUpn ?? "")) return "Your account has no mail-style user name to verify the restriction against.";
        if (string.Equals(s.Address.Trim(), s.AdminUpn.Trim(), StringComparison.OrdinalIgnoreCase)) return "The shared mailbox cannot be your own mailbox -- the restriction is proven against your mailbox.";
        if (string.IsNullOrWhiteSpace(s.TenantId)) return "The tenant of the signed-in account is not known.";
        return null;
    }

    public static string? Validate(SmtpSetup s)
    {
        if (string.IsNullOrWhiteSpace(s.Server) || !Host.IsMatch(s.Server.Trim())) return "Give the SMTP server's host name.";
        if (!int.TryParse((s.Port ?? "").Trim(), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var p) || p is < 1 or > 65535)
            return "The port is a number from 1 to 65535.";
        if (!SettingsForm.IsMailAddress(s.From ?? "")) return "Give the From address (name@domain).";
        return null;
    }

    private static string Q(string s) => "'" + s.Trim().Replace("'", "''") + "'";

    /// Line 1 of the hand-over block: download Set-SIMail.ps1 from invardia.com.
    public const string DownloadLine = "Invoke-WebRequest " + ScriptUrl + " -OutFile Set-SIMail.ps1";

    /// <summary>
    /// What the Exchange administrator runs to finish the steps that did not run (owner 2026-10-11: "line 1: download file
    /// from invardia, line 2 (and more if needed) is the cmdlet(s). we cannot have info about checksum etc in the
    /// cmdlets"): line 1 downloads setup\Set-SIMail.ps1, line 2 runs it with this run's values filled in -- the mailbox,
    /// the identity's service principal, the mailbox the restriction is proven against and the tenant. Set-SIMail does
    /// steps 1-5 itself (native REST, no Exchange module) and keeps what is already there, so re-running a step that went
    /// through is safe; a mailbox this run already created is not asked for again. Nothing else is in the block.
    /// </summary>
    public static IReadOnlyList<string> HandOverCommands(SharedMailboxSetup s, int fromStep)
    {
        var parts = new List<string> { "./Set-SIMail.ps1", "-SharedMailbox " + Q(s.Address) };
        if (s.CreateMailbox && fromStep <= 1) parts.Add("-DisplayName " + Q(s.DisplayName));
        else parts.Add("-CreateMailbox $false");
        parts.Add("-IdentityObjectId " + Q(s.ServicePrincipalObjectId));
        if (!string.IsNullOrWhiteSpace(s.AdminUpn)) parts.Add("-ProbeMailbox " + Q(s.AdminUpn));
        if (!string.IsNullOrWhiteSpace(s.TenantId)) parts.Add("-TenantId " + Q(s.TenantId));
        parts.Add("-UseSignedInAccount");
        parts.Add("-Apply");
        return [DownloadLine, string.Join(" ", parts)];
    }

    private static IReadOnlyList<string> RemainingCommands(SharedMailboxSetup s, int fromStep) => HandOverCommands(s, fromStep);

    /// Runs the shared-mailbox setup. Never throws for an Exchange or settings problem (it is the step's message);
    /// cancellation is thrown.
    public async Task<MailSetupResult> RunSharedMailboxAsync(SharedMailboxSetup s, ExchangeSession session, string by, CancellationToken ct)
    {
        var steps = new List<MailSetupStep>();
        var address = s.Address.Trim();
        var clientId = s.ClientId.Trim();

        MailSetupResult Stop(int step, ExchangeCallResult r, string what)
        {
            var needsRole = r.Outcome == ExchangeOutcome.NeedsRole;
            steps.Add(new MailSetupStep(step, SharedSteps[step - 1], MailSetupStep.Failed,
                needsRole ? NeedsRoleMessage : $"{what} failed: {(string.IsNullOrWhiteSpace(r.Message) ? "Exchange Online answered " + r.Status : r.Message)}"));
            for (var n = step + 1; n <= SharedSteps.Count; n++) steps.Add(new MailSetupStep(n, SharedSteps[n - 1], MailSetupStep.NotRun, "not run -- an earlier step failed"));
            return new MailSetupResult(steps, false, needsRole, RemainingCommands(s, step));
        }

        MailSetupStep Done(int step, ExchangeCallResult r, string ok) =>
            new(step, SharedSteps[step - 1], MailSetupStep.Ok, r.Outcome == ExchangeOutcome.AlreadyExists ? "already there -- kept as it is" : ok);

        // (1) the mailbox
        if (s.CreateMailbox)
        {
            var r = await _exchange.InvokeAsync(session, "New-Mailbox", new Dictionary<string, object?>
            {
                ["Shared"] = true, ["Name"] = s.DisplayName.Trim(), ["DisplayName"] = s.DisplayName.Trim(), ["PrimarySmtpAddress"] = address,
            }, ct);
            if (!r.Succeeded) return Stop(1, r, "Creating the shared mailbox");
            steps.Add(Done(1, r, $"created {address}"));
        }
        else steps.Add(new MailSetupStep(1, SharedSteps[0], MailSetupStep.Skipped, $"using the existing mailbox {address}"));

        // (2) SI's identity as an Exchange service principal
        var sp = await _exchange.InvokeAsync(session, "New-ServicePrincipal", new Dictionary<string, object?>
        {
            ["AppId"] = clientId, ["ObjectId"] = s.ServicePrincipalObjectId.Trim(), ["DisplayName"] = ExchangeDisplayName,
        }, ct);
        if (!sp.Succeeded) return Stop(2, sp, "Registering the identity");
        steps.Add(Done(2, sp, "registered"));

        // (3) a scope with ONLY this mailbox -- one that already holds exactly it is adopted (whatever it is called)
        var scopeName = ScopeName(address);
        var scopes = await _exchange.InvokeAsync(session, "Get-ManagementScope", new Dictionary<string, object?>(), ct);
        if (scopes.Outcome == ExchangeOutcome.NeedsRole) return Stop(3, scopes, "Reading the management scopes");
        if (scopes.Succeeded && AdoptableScope(scopes.Rows, address) is { } existing)
        {
            scopeName = existing;
            steps.Add(new MailSetupStep(3, SharedSteps[2], MailSetupStep.Ok, $"'{scopeName}' already holds only {address} -- kept as it is"));
        }
        else
        {
            var scope = await _exchange.InvokeAsync(session, "New-ManagementScope", new Dictionary<string, object?>
            {
                ["Name"] = scopeName, ["RecipientRestrictionFilter"] = Filter(address),
            }, ct);
            if (!scope.Succeeded) return Stop(3, scope, "Creating the management scope");
            steps.Add(Done(3, scope, $"'{scopeName}' created"));
        }

        // (4) Application Mail.Send in that scope (RBAC for Applications) -- an assignment that grants it is adopted
        var assignments = await _exchange.InvokeAsync(session, "Get-ManagementRoleAssignment", new Dictionary<string, object?> { ["RoleAssigneeType"] = "ServicePrincipal" }, ct);
        if (assignments.Outcome == ExchangeOutcome.NeedsRole) return Stop(4, assignments, "Reading the role assignments");
        if (assignments.Succeeded && HasAssignment(assignments.Rows, scopeName, clientId, s.ServicePrincipalObjectId.Trim()))
            steps.Add(new MailSetupStep(4, SharedSteps[3], MailSetupStep.Ok, $"'{RoleName}' on '{scopeName}' is already assigned -- kept as it is"));
        else
        {
            var assign = await _exchange.InvokeAsync(session, "New-ManagementRoleAssignment", new Dictionary<string, object?>
            {
                ["Name"] = AssignmentName(address, clientId), ["App"] = clientId, ["Role"] = RoleName, ["CustomResourceScope"] = scopeName,
            }, ct);
            if (!assign.Succeeded) return Stop(4, assign, "Assigning Application Mail.Send");
            steps.Add(Done(4, assign, "assigned"));
        }

        // (5) verify: in scope for the shared mailbox, NOT for the admin's own mailbox
        var inMailbox = await _exchange.InvokeAsync(session, "Test-ServicePrincipalAuthorization", new Dictionary<string, object?> { ["Identity"] = clientId, ["Resource"] = address }, ct);
        if (!inMailbox.Succeeded) return Stop(5, inMailbox, "Verifying the restriction");
        if (!MailSendInScope(inMailbox.Rows))
            return Stop(5, new ExchangeCallResult(ExchangeOutcome.Failed, 200, $"'{RoleName}' is not in scope for {address} yet (Exchange can take a few minutes to apply a new assignment -- run the setup again shortly)", inMailbox.Rows), "Verifying the restriction");
        var inOwn = await _exchange.InvokeAsync(session, "Test-ServicePrincipalAuthorization", new Dictionary<string, object?> { ["Identity"] = clientId, ["Resource"] = s.AdminUpn.Trim() }, ct);
        if (!inOwn.Succeeded) return Stop(5, inOwn, "Verifying the restriction");
        if (MailSendInScope(inOwn.Rows))
            return Stop(5, new ExchangeCallResult(ExchangeOutcome.Failed, 200, $"Mail.Send also reaches {s.AdminUpn.Trim()} -- it is not restricted to the shared mailbox. Remove any tenant-wide Mail.Send permission and other assignments of '{RoleName}' to this identity", inOwn.Rows), "Verifying the restriction");
        try
        {
            await _store.WriteAttestationAsync(MailAttestation.ToJson(address, scopeName, by, _clock.GetUtcNow().UtcDateTime), by, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            steps.Add(new MailSetupStep(5, SharedSteps[4], MailSetupStep.Failed, "Verified, but the attestation could not be recorded: " + ex.Message));
            for (var n = 6; n <= SharedSteps.Count; n++) steps.Add(new MailSetupStep(n, SharedSteps[n - 1], MailSetupStep.NotRun, "not run -- an earlier step failed"));
            return new MailSetupResult(steps, false, false, Array.Empty<string>());
        }
        steps.Add(new MailSetupStep(5, SharedSteps[4], MailSetupStep.Ok, $"in scope for {address}, not for {s.AdminUpn.Trim()} -- recorded"));

        // (6) the settings, through the settings writer (each with its cfg.ChangeLog row)
        var errors = await SaveAsync(new (string, string)[]
        {
            (MailMode.ModeSetting, MailMode.SharedMailbox), (MailMode.FromSetting, address), (MailMode.ProbeSetting, s.AdminUpn.Trim()),
        }, by, ct);
        if (errors.Count > 0)
        {
            steps.Add(new MailSetupStep(6, SharedSteps[5], MailSetupStep.Failed, string.Join(" ", errors)));
            steps.Add(new MailSetupStep(7, SharedSteps[6], MailSetupStep.NotRun, "not run -- an earlier step failed"));
            return new MailSetupResult(steps, false, false, Array.Empty<string>());
        }
        steps.Add(new MailSetupStep(6, SharedSteps[5], MailSetupStep.Ok, $"mode sharedMailbox, From {address}, probe mailbox {s.AdminUpn.Trim()}"));

        // (7) a test mail to the admin, sent by the mail job (which also checks the restriction itself first)
        var test = await QueueTestAsync(s.AdminUpn.Trim(), new MailModeResolution(MailMode.SharedMailbox, MailMode.FromSettingSource, null), address, by, ct);
        steps.Add(test is null
            ? new MailSetupStep(7, SharedSteps[6], MailSetupStep.Ok, $"queued to {s.AdminUpn.Trim()} -- the mail job sends it")
            : new MailSetupStep(7, SharedSteps[6], MailSetupStep.Failed, test));
        return new MailSetupResult(steps, test is null, false, Array.Empty<string>());
    }

    /// Saves the SMTP relay (+ SI_Mail_Mode = smtp) and queues a test mail.
    public async Task<MailSetupResult> RunSmtpAsync(SmtpSetup s, string testTo, string by, CancellationToken ct)
    {
        var values = new List<(string, string)>
        {
            (MailMode.SmtpServerSetting, s.Server.Trim()), (MailMode.SmtpPortSetting, s.Port.Trim()), (MailMode.SmtpSslSetting, s.UseSsl ? "true" : "false"),
            (MailMode.FromSetting, s.From.Trim()),
        };
        if (!string.IsNullOrWhiteSpace(s.User)) values.Add((MailMode.SmtpUserSetting, s.User.Trim()));
        if (!string.IsNullOrWhiteSpace(s.PasswordSecretName)) values.Add((MailMode.SmtpPasswordSetting, s.PasswordSecretName.Trim()));
        values.Add((MailMode.ModeSetting, MailMode.Smtp));
        var steps = new List<MailSetupStep>();
        var errors = await SaveAsync(values, by, ct);
        if (errors.Count > 0)
        {
            steps.Add(new MailSetupStep(1, "Save the SMTP settings", MailSetupStep.Failed, string.Join(" ", errors)));
            steps.Add(new MailSetupStep(2, "Queue a test mail", MailSetupStep.NotRun, "not run -- an earlier step failed"));
            return new MailSetupResult(steps, false, false, Array.Empty<string>());
        }
        steps.Add(new MailSetupStep(1, "Save the SMTP settings", MailSetupStep.Ok, $"server {s.Server.Trim()}:{s.Port.Trim()}, From {s.From.Trim()}, mode smtp"));
        var test = await QueueTestAsync(testTo, new MailModeResolution(MailMode.Smtp, MailMode.FromSettingSource, null), s.From.Trim(), by, ct);
        steps.Add(test is null
            ? new MailSetupStep(2, "Queue a test mail", MailSetupStep.Ok, $"queued to {testTo} -- the mail job sends it")
            : new MailSetupStep(2, "Queue a test mail", MailSetupStep.Failed, test));
        return new MailSetupResult(steps, test is null, false, Array.Empty<string>());
    }

    /// Whether the Test-ServicePrincipalAuthorization rows list 'Application Mail.Send' with InScope true.
    public static bool MailSendInScope(IEnumerable<JsonElement> rows)
    {
        foreach (var r in rows)
        {
            if (r.ValueKind != JsonValueKind.Object) continue;
            var role = r.TryGetProperty("RoleName", out var rn) && rn.ValueKind == JsonValueKind.String ? rn.GetString() : null;
            if (!string.Equals(role, RoleName, StringComparison.OrdinalIgnoreCase)) continue;
            if (!r.TryGetProperty("InScope", out var s)) continue;
            if (s.ValueKind == JsonValueKind.True) return true;
            if (s.ValueKind == JsonValueKind.String && bool.TryParse(s.GetString(), out var b) && b) return true;
        }
        return false;
    }

    /// Writes each (setting, form text) through the settings writer, at the scope its row already has (else its
    /// default scope); a value that is already so is not rewritten. A secret is written as its Key Vault secret NAME.
    /// Returns the refusals (empty = all saved).
    public async Task<IReadOnlyList<string>> SaveAsync(IEnumerable<(string Name, string Text)> values, string by, CancellationToken ct, string? reason = null)
    {
        var errors = new List<string>();
        var rows = (await _reader.ReadSettingsAsync(ct)).Rows;
        foreach (var (name, text) in values)
        {
            var s = _catalog.Find(name);
            if (s is null) { errors.Add($"{name} is not in this install's settings catalog -- update SecurityInsight first."); continue; }
            var row = MailMode.RowOf(rows, s.Name);
            if (row is not null && (s.Secret ? string.Equals(row.KeyVaultSecretName, text, StringComparison.Ordinal) && row.ValueJson is null
                                             : row.KeyVaultSecretName is null && SettingJson.ToFormText(row.ValueJson) == text)) continue;
            var scope = row?.Scope ?? s.DefaultScope;
            var write = new SettingWrite(s.Name, scope, "Set", s.Secret ? null : SettingJson.FromForm(s, text), s.Secret ? text : null, row?.Version, reason ?? Reason);
            var result = await _writer.WriteAsync(write, by, ct);
            if (result.Status != WriteStatus.Saved) errors.Add(result.Message + ".");
        }
        return errors;
    }

    public const string KeepReason = "SMTP relay kept by choice (Ignore on the home banner)";
    public const string UndoKeepReason = "SMTP relay no longer kept by choice (Undo on Settings > E-mail)";

    /// SI_Mail_SmtpKept through the settings writer, the same path as every other mail setting: true = the SMTP relay is
    /// kept by choice (the move hint is hidden), false = SecurityInsight recommends the shared mailbox again. The refusals.
    public Task<IReadOnlyList<string>> SetSmtpKeptAsync(bool keep, string by, CancellationToken ct) =>
        SaveAsync(new[] { (MailHealth.KeptSetting, keep ? "true" : "false") }, by, ct, keep ? KeepReason : UndoKeepReason);

    /// Queues the test mail; null = queued, else why not.
    public async Task<string?> QueueTestAsync(string to, MailModeResolution mode, string? from, string by, CancellationToken ct)
    {
        try { await _mailer.SendAsync(MailTestMail.Build(to, mode, from), by, ct); return null; }
        catch (Exception ex) when (ex is not OperationCanceledException) { return "The test mail could not be queued: " + ex.Message; }
    }
}
