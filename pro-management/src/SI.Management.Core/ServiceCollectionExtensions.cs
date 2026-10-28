using Azure.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace SI.Management.Core;

public static class ServiceCollectionExtensions
{
    /// Registers the estate queries, the settings reader, the curated toolbox and (when Chat is configured) the
    /// chat service. Configuration sections: "Identity", "Estate", "Chat".
    public static IServiceCollection AddSecurityInsightEstate(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<IdentityOptions>(configuration.GetSection(IdentityOptions.Section));
        services.Configure<EstateOptions>(configuration.GetSection(EstateOptions.Section));
        services.Configure<ChatOptions>(configuration.GetSection(ChatOptions.Section));

        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<TokenCredential>(sp => CredentialFactory.Create(sp.GetRequiredService<IOptions<IdentityOptions>>().Value));
        services.AddSingleton<ILogAnalyticsReader, LogAnalyticsReader>();
        services.AddSingleton<ISqlReader, SqlReader>();
        services.AddSingleton<IEstateQueries>(sp => new EstateQueries(
            sp.GetRequiredService<ILogAnalyticsReader>(), sp.GetRequiredService<ISqlReader>(),
            sp.GetRequiredService<IOptions<EstateOptions>>(), sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<ISettingsReader>(sp => new SettingsReader(sp.GetRequiredService<ISqlReader>(), sp.GetRequiredService<TimeProvider>()));
        // #406 the CI lifecycle in plain words, from the settings in force (what every page says it shows)
        services.AddSingleton<ProData.ICiLifecycleRulesReader>(sp => new ProData.CiLifecycleRulesReader(sp.GetRequiredService<ISettingsReader>()));
        // the Pro data backend (sidata.*, vuln.*) through the read-only SQL reader; a host with its own SQL seam (the
        // web app) registers its own IProSql after this call
        services.AddSingleton<ProData.IProSql>(sp => new ProData.SqlReaderProSql(sp.GetRequiredService<ISqlReader>()));
        services.AddSingleton<ProData.IProDataQueries>(sp => new ProData.ProDataQueries(sp.GetRequiredService<ProData.IProSql>(),
            sp.GetRequiredService<IOptions<EstateOptions>>().Value.VulnerabilitySource, sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<EstateToolbox>();
        services.AddSingleton<IChatModel, AzureOpenAIChatModel>();
        services.AddSingleton<IChatService, ChatService>();
        return services;
    }
}
