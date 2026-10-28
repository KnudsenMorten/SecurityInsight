using System.Text.RegularExpressions;

namespace SI.Management.Web.Auth;

/// <summary>
/// #765 (owner 2026-10-19: "is it possible to define mail forward on accounts like in pim, so each admin account also get
/// the repots but using their normal office"): a person on Admin &gt; Access may have a "Send SecurityInsight mail to"
/// address -- the mailbox of the person behind an admin account. The model is PIM's ("admin mail goes to the person behind
/// the admin account"): the address is recorded on the person, the screen shows exactly where a mail will go, and a value
/// that is not a real mail address is refused, never used.
///
/// The SEND happens in one place only: the mail transport of the jobs (engine\_shared\SI-MailTransport.ps1, Send-SIMail,
/// Resolve-SIMailRecipients) -- the web app never sends a mail, it queues it in an outbox that the mail job sends. This class
/// is the web app's half: it validates what is written, and shows what the transport will do, with the same rules (the same
/// cases are tested on both sides: MailForwardTests and SIv3-MailForward.Tests.ps1).
/// </summary>
public static partial class MailForward
{
    /// Values a person types to mean "nothing": treated as empty (the account's own mail), never as an address.
    public static readonly IReadOnlySet<string> Sentinels = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "false", "none", "n/a", "na", "null", "nil", "no", "0", "-", "--", "empty",
    };

    public const int MaxLength = 320;

    [GeneratedRegex(@"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex Address();

    /// A real mail address: one local part, one @, a domain with a dot and a letter top-level domain. No name, no list.
    public static bool IsAddress(string? s)
    {
        var v = (s ?? "").Trim();
        return v.Length is > 5 and <= MaxLength && !v.Contains("..", StringComparison.Ordinal) && !v.StartsWith('.') && !v.Contains(".@", StringComparison.Ordinal) && Address().IsMatch(v);
    }

    /// What the forward field holds once cleaned: null = empty (a blank or a sentinel such as FALSE / none / n/a / 0);
    /// otherwise the address, lower-cased -- or an error when it is not a real mail address (nothing is stored then).
    public static (string? Value, string? Error) Clean(string? typed)
    {
        var v = (typed ?? "").Trim();
        if (v.Length == 0 || Sentinels.Contains(v)) return (null, null);
        if (!IsAddress(v)) return (null, $"'{(v.Length > 80 ? v[..80] + "..." : v)}' is not a mail address -- give one address like name@example.com, or leave it empty for the account's own mail");
        return (v.ToLowerInvariant(), null);
    }

    /// A stored forward, as the transport reads it: a real address, else nothing (a bad value is never used).
    public static string? Usable(string? stored) => IsAddress(stored) && !Sentinels.Contains(stored!.Trim()) ? stored!.Trim().ToLowerInvariant() : null;

    /// The keys a recipient address may name a person by: their object id, their own mail / sign-in name, and the name
    /// shown when it is a mail address. Lower-case.
    public static IEnumerable<string> KeysOf(AccessAssignment a)
    {
        if (a.PrincipalType != AccessAssignment.User) yield break;
        yield return a.PrincipalId.Trim().ToLowerInvariant();
        if (IsAddress(a.AccountMail)) yield return a.AccountMail!.Trim().ToLowerInvariant();
        if (IsAddress(a.DisplayName)) yield return a.DisplayName.Trim().ToLowerInvariant();
    }

    /// Where a mail to this person goes: the forward when one is set, else their own mail (null when none is known).
    public static string? Destination(AccessAssignment a) => Usable(a.ForwardTo) ?? (IsAddress(a.AccountMail) ? a.AccountMail!.Trim() : IsAddress(a.DisplayName) ? a.DisplayName.Trim() : null);

    /// The forward of one recipient address, or null when it goes where it says.
    public static string? TargetOf(string address, IEnumerable<AccessAssignment> people)
    {
        var k = (address ?? "").Trim().ToLowerInvariant();
        if (k.Length == 0) return null;
        foreach (var a in people)
        {
            if (Usable(a.ForwardTo) is not { } f) continue;
            if (KeysOf(a).Contains(k, StringComparer.Ordinal)) return string.Equals(f, k, StringComparison.Ordinal) ? null : f;
        }
        return null;
    }

    /// The recipient list as the transport sends it: each address that names a person with a forward is replaced by the
    /// forward (never both), and the list is de-duplicated, case-insensitively, keeping the first place of each.
    public static IReadOnlyList<string> Resolve(IEnumerable<string> to, IEnumerable<AccessAssignment> people)
    {
        var list = people.ToList();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var outList = new List<string>();
        foreach (var raw in to.SelectMany(t => (t ?? "").Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
        {
            var target = TargetOf(raw, list) ?? raw;
            if (seen.Add(target)) outList.Add(target);
        }
        return outList;
    }
}
