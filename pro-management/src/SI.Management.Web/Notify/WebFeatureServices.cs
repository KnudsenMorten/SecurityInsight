using SI.Management.Web.Jobs;

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
        // ENV-REPORT-1: the Azure part through ARM (the web app's Reader on its resource group), else "not configured"
        var jobs = config.GetSection(JobsOptions.Section).Get<JobsOptions>() ?? new JobsOptions();
        if (jobs.IsConfigured) services.AddHttpClient<SI.Management.Web.EnvReport.IAzureFactsReader, SI.Management.Web.EnvReport.ArmAzureFactsReader>();
        else services.AddSingleton<SI.Management.Web.EnvReport.IAzureFactsReader, NotConfiguredAzureFacts>();
        services.AddTransient<SI.Management.Web.EnvReport.EnvironmentReportService>();
        // CONFIG-IO-1: the import's steps (the export is the page's own)
        services.AddSingleton<SI.Management.Web.ConfigIo.ConfigImportFlow>();
        return services;
    }

    private sealed class NotConfiguredAzureFacts : SI.Management.Web.EnvReport.IAzureFactsReader
    {
        public Task<SI.Management.Web.EnvReport.AzureFacts> ReadAsync(CancellationToken ct) => Task.FromResult(SI.Management.Web.EnvReport.AzureFacts.NotConfigured);
    }
}
