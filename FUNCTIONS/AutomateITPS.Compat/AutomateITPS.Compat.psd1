@{
    RootModule        = 'AutomateITPS.Compat.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b2d5f1a8-ad2f-5e7b-c04d-bf88e4bc3572'
    Author            = 'Morten Knudsen'
    CompanyName       = 'Morten Knudsen'
    Copyright         = '(c) Morten Knudsen. MIT.'
    Description       = 'AutomateIT back-compat shim. Maps the typed platform context to legacy $global:HighPriv_* variables so pre-v2 scripts keep working during migration.'
    PowerShellVersion = '5.1'
    RequiredModules   = @(@{ ModuleName = 'AutomateITPS'; ModuleVersion = '0.1.0' })
    FunctionsToExport = @('Import-LegacyGlobals')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags         = @('AutomateIT','Compat','Migration','BackCompat')
            ProjectUri   = 'https://github.com/KnudsenMorten/AutomateIT'
            LicenseUri   = 'https://github.com/KnudsenMorten/AutomateIT/blob/main/LICENSE'
            HelpInfoUri  = 'https://mortenknudsen.net'
            ReleaseNotes = @'
0.1.0 -- Initial release. Maps the typed AutomateITPS context onto
the 19 canonical $global:HighPriv_* names so pre-v2 scripts keep
working unchanged during migration. Author blog:
https://mortenknudsen.net (aka https://aka.ms/morten)
'@
        }
    }
}
