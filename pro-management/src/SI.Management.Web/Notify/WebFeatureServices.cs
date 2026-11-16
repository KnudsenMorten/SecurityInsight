namespace SI.Management.Web.Notify;

/// <summary>
/// The services of the notifications (MAIL-2: SI #485 / #489), the environment report (ENV-REPORT-1: SI #482) and the
/// configuration export / import (CONFIG-IO-1: SI #490) -- one registration call from Program.cs.
/// </summary>
public static class WebFeatureServices
{
    public static IServiceCollection AddWebFeatures(this IServiceCollection services, IConfiguration config)
    {
        // MAIL-2: the per-recipient notifications, auto-Reader, the daily Get Started reminder
        services.AddSingleton<NotificationService>();
        services.AddSingleton<AutoReader>();
        services.AddSingleton<IReminderOutbox, SqlReminderOutbox>();
        services.AddSingleton<GetStartedReminderService>();
        services.AddHostedService<GetStartedReminderScheduler>();
        // #1021: the third revoker of the Invardia Support app's just-in-time database grant (the jobs sweep too)
        services.AddHostedService<SI.Management.Web.Support.SupportGrantSweep>();
        // ENV-REPORT-1 + SI #1268: the Azure part from the Pro database (cfg.InstallState 'EnvironmentFacts', written by the
        // updater with its own rights) -- the web app holds no Reader on the resource group and never calls ARM for it
        services.AddSingleton<SI.Management.Web.EnvReport.IAzureFactsReader, SI.Management.Web.EnvReport.SqlAzureFactsReader>();
        _ = config;   // (kept for the callers: the registration no longer needs the Jobs section)
        services.AddTransient<SI.Management.Web.EnvReport.EnvironmentReportService>();
        // CONFIG-IO-1: the import's steps (the export is the page's own)
        services.AddSingleton<SI.Management.Web.ConfigIo.ConfigImportFlow>();
        return services;
    }
}
