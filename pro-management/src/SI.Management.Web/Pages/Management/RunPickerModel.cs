using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Management;

/// The run picker of a key-figure page (#818, _RunPicker.cshtml): the figures it shows, the page it submits to and the page's
/// other choices it keeps (topic, view, mode, ...).
public sealed record RunPickerModel(ExecutiveFigures Figures, string Path, IReadOnlyList<(string Key, string Value)> Keep);
