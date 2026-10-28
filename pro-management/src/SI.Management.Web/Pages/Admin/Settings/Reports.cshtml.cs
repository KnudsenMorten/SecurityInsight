using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Notify;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// Reports and alerts (framework MAIL-2 item 6, SI #485): ONE view of every report and alert SecurityInsight mails -- its
/// cadence, recipients, last sent, next run, whether a PDF is attached and whether it already follows each recipient's
/// notifications -- each with the one place it is configured. Read from the settings and the management summary
/// definitions on every visit; nothing is stored here. Admin.
/// </summary>
public sealed class ReportsModel(NotificationService notify) : PageModel
{
    public IReadOnlyList<NotifyLine> Lines { get; private set; } = Array.Empty<NotifyLine>();
    public string? Error { get; private set; }
    public int Recipients { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        var s = await notify.ReadAsync(ct);
        Error = s.Error;
        Lines = NotificationService.Lines(s, notify.Now);
        Recipients = NotificationService.AllRecipients(s, notify.Now).Count;
    }
}
