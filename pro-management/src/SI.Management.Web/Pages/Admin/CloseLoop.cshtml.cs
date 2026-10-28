using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Data;

namespace SI.Management.Web.Pages.Admin;

/// The vulnerability close-loop: open / closed / reopened, by reason. Read-only -- the vuln schema belongs to the
/// customer's process; this page never changes it.
public sealed class CloseLoopModel : PageModel
{
    private readonly ICloseLoopReader _reader;
    private readonly ILogger<CloseLoopModel> _log;
    public CloseLoopModel(ICloseLoopReader reader, ILogger<CloseLoopModel> log) { _reader = reader; _log = log; }

    public CloseLoopState? State { get; private set; }
    public string? Error { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try { State = await _reader.ReadAsync(50, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the vuln schema failed");
            Error = "The close-loop state could not be read: " + ex.Message;
        }
    }
}
