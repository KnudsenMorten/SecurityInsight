using SI.Management.Web.Settings;

namespace SI.Management.Web.Changes;

/// <summary>
/// A staged-change kind committed by its own feature instead of a branch in ChangeService: the feature previews its
/// change for Review &amp; commit and writes it, in one transaction with its cfg.ChangeLog row. ChangeService asks every
/// registered handler first, so a new kind of change plugs into the ONE staging mechanism without a second one.
/// </summary>
public interface IStagedChangeHandler
{
    bool Handles(string kind);
    Task<ChangePreview> PreviewAsync(StagedChange change, CancellationToken ct);
    /// by = the signed-in identity (never a value carried in the staged change).
    Task<WriteResult> CommitAsync(StagedChange change, string by, CancellationToken ct);
}
