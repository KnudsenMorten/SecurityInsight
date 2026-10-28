@{
    RootModule        = 'AutomateITPS.AD.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'c3e6f2b9-be30-5f8c-d15e-c099f5cd4683'
    Author            = 'Morten Knudsen'
    CompanyName       = 'Morten Knudsen'
    Copyright         = '(c) Morten Knudsen. MIT.'
    Description       = 'AutomateIT on-prem Active Directory helpers. Requires $ctx.Capabilities.OnPremAD = $true (domain-joined VM or hybrid worker).'
    PowerShellVersion = '5.1'
    RequiredModules   = @(@{ ModuleName = 'AutomateITPS'; ModuleVersion = '0.1.0' })
    FunctionsToExport = @(
        'Assert-OnPremAD'
        'Get-GMSACredential'
        'Get-LegacyCredentialSet'
        'Resolve-PlatformGMSACredentials'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('AutomateIT','ActiveDirectory','OnPrem','gMSA','Kerberos')
            ProjectUri   = 'https://github.com/KnudsenMorten/AutomateIT'
            LicenseUri   = 'https://github.com/KnudsenMorten/AutomateIT/blob/main/LICENSE'
            HelpInfoUri  = 'https://mortenknudsen.net'
            ReleaseNotes = @'
0.1.0 -- Initial release. On-prem Active Directory helpers for
AutomateIT: Assert-OnPremAD, Get-GMSACredential (ADSI
msDS-ManagedPassword blob parser), Get-LegacyCredentialSet,
Resolve-PlatformGMSACredentials (walks $ctx.Identity.Legacy and
upgrades gMSA entries with the real DC-side password). Author blog:
https://mortenknudsen.net (aka https://aka.ms/morten)
'@
        }
    }
}
