@{
    RootModule        = 'AutomateITPS.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a1c4e0f7-9c1e-4d6a-bf3c-ae77d3ab2461'
    Author            = 'Morten Knudsen'
    CompanyName       = 'Morten Knudsen'
    Copyright         = '(c) Morten Knudsen. MIT.'
    Description       = 'AutomateIT core: platform context, structured logging, secret/state provider interfaces. Hybrid (VM + cloud) runtime.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'New-PlatformContext'
        'Write-PlatformLog'
        'Get-PlatformSecret'
        'Get-PlatformState'
        'Set-PlatformState'
        'Set-PlatformLocalSecret'
        'Initialize-PlatformIdentity'
        'Initialize-PlatformLegacyIdentity'
        'Initialize-PlatformAutomationFramework'
        'Initialize-PlatformDefaults'
        'Send-PlatformAlert'
        'Start-PlatformTranscript'
        'Stop-PlatformTranscript'
        'Test-PlatformConnectivity'
        'Connect-Platform'
        'Connect-PlatformBootstrap'
        'Connect-PlatformModern'
        'Disconnect-Platform'
        'Get-PlatformConfig'
        'Set-PlatformConfig'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('AutomateIT','PowerShell','Automation','Hybrid','EntraID','ActiveDirectory','KeyVault','ManagedIdentity')
            ProjectUri   = 'https://github.com/KnudsenMorten/AutomateIT'
            LicenseUri   = 'https://github.com/KnudsenMorten/AutomateIT/blob/main/LICENSE'
            HelpInfoUri  = 'https://mortenknudsen.net'
            ReleaseNotes = @'
0.1.0 -- Initial release.
Core platform: typed $ctx via New-PlatformContext, structured JSON
logging (Write-PlatformLog), secret provider (KeyVault, Local/DPAPI),
state provider (AzureTable, LocalJson), Initialize-PlatformIdentity,
Initialize-PlatformLegacyIdentity, Send-PlatformAlert, transcript
helpers, Test-PlatformConnectivity. Host auto-detect covers
VM / HybridWorker / AzureFunction / LogicApp / Dev.
Author blog: https://mortenknudsen.net (aka https://aka.ms/morten)
'@
        }
    }
}
