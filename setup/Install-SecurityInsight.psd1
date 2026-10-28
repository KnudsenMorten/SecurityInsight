@{
    # SecurityInsight's guided install as a command: Import-Module <package>/setup/Install-SecurityInsight.psd1, then
    # Install-SecurityInsight (it forwards every parameter to setup/Install-SecurityInsight.ps1).
    RootModule        = 'Install-SecurityInsight.psm1'
    ModuleVersion     = '3.0.0'
    GUID              = '3f6b2a9e-7c41-4d8a-9b0e-5a2c8d4e1f37'
    Author            = 'SecurityInsight'
    Description       = 'SecurityInsight guided install: Install-SecurityInsight -ConfigPath <config.json> [-LicencePath <file.silicense>] [-Reporter <scriptblock>] [-StatePath <dir>] [-Resume] [-PreflightOnly]. Exit code in $LASTEXITCODE: 0 installed, 1 a step failed, 2 a check failed, 3 config.json is not valid.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Install-SecurityInsight')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
