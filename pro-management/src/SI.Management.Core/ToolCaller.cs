using SI.Management.Core.ProData;

namespace SI.Management.Core;

/// <summary>
/// Who calls the curated tools (the in-app chat or the MCP server): whether the Admin-only tools are offered, and the
/// rows the caller may SEE. <see cref="Visibility"/> null = every row (every role whose view is not limited); set = the
/// caller's department scope (#253 x #254): only the tools that apply that predicate to every row they read are offered
/// and run (<see cref="EstateToolbox.RowFiltered"/>) -- every other tool is refused for such a caller, never answered from
/// the whole estate.
/// </summary>
public sealed record ToolCaller(bool IsAdmin, VisibilityPredicate? Visibility = null)
{
    /// The caller's view is limited to some rows.
    public bool Scoped => Visibility is not null;

    /// A caller whose view is not limited (the shape every caller had before the row visibility reached the tools).
    public static ToolCaller Unscoped(bool isAdmin) => new(isAdmin);
}
