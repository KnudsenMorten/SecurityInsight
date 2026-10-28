using SI.Management.Web.Changes;
using SI.Management.Web.Outputs;

namespace SI.Management.Web.Pages.Connectors;

/// <summary>
/// Configuration > Connectors > Fields sent (owner 2026-10-19: "one for reports and one for connectors"): the output fields
/// of every connector output (the ServiceNow CI and vulnerable-item hand-offs ...) -- the same store and staging as the
/// workbooks' fields (Reports > Workbook fields), only this area's outputs. The fixed SQL vulnerability contract is shown
/// read-only, as before.
/// </summary>
public sealed class FieldsModel(OutputMapStore store, OutputMapChanges changes, ChangeService staging, ILogger<FieldsModel> log)
    : SI.Management.Web.Pages.Reports.OutputFieldsModel(store, changes, staging, (ILogger)log)
{
    public override string Area => ConnectorArea;
    public override string PagePath => "/Connectors/Fields";
}