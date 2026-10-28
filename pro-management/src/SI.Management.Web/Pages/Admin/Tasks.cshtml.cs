using SI.Management.Core.ProData;
using SI.Management.Web.Pages.Tasks;
using SI.Management.Web.Tasks;

namespace SI.Management.Web.Pages.Admin;

/// Admin > All tasks (#265): every follow-up task of the install, filtered by department, person, due and status -- the
/// same server-side grid as My tasks. Under /Admin (Admin and up).
public sealed class TasksModel(FindingTaskService tasks, IDepartmentViews departments, ILogger<TasksModel> log) : TaskListPage(tasks, log, departments)
{
    public override string View => TaskQuery.ViewAll;
    public override string PagePath => "/Admin/Tasks";
    public override string Heading => "All tasks";
    public override string Lede => "Every follow-up task on every finding: filter by department, search a person or a finding, and sort by due day to see what is overdue.";
}
