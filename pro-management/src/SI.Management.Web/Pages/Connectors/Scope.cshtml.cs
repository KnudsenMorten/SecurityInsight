using SI.Management.Web.Changes;
using SI.Management.Web.Reports;

namespace SI.Management.Web.Pages.Connectors;

/// <summary>
/// Configuration > Connectors > Scope (owner 2026-10-19): the output scope of every connector (the SQL and ServiceNow
/// vulnerability and CMDB connectors) -- the same store and staging as the workbooks' scope (Reports > Workbook scope).
/// </summary>
public sealed class ScopeModel(IReportStore store, ChangeService changes, ILogger<ScopeModel> log)
    : SI.Management.Web.Pages.Reports.OutputsModel(store, changes, (ILogger)log)
{
    public override string Area => SI.Management.Web.Pages.Reports.OutputFieldsModel.ConnectorArea;
}