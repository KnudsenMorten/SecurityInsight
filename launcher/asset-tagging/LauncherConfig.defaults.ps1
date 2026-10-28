#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline defaults for the SecurityInsight asset-tagging engine.

.DESCRIPTION
    Shipped with each release. Every value below is set ONLY when nothing else has set it, so a value you put
    in config\SecurityInsight.custom.ps1 or LauncherConfig.custom.ps1 always wins. CLI switches win last.

.NOTES
    LauncherConfigVersion : 1
    Solution              : SecurityInsight
    Engine                : AssetTagging
#>

# Which scope's rules apply (the YAML's Scope field).
if (-not $global:Scope -or @($global:Scope).Count -eq 0) { $global:Scope = @('PROD') }

# The rule files, in the engine's rules folder (SettingsPath).
if (-not $global:LockedYamlFile) { $global:LockedYamlFile = 'AssetTagging.locked.yaml' }
if (-not $global:CustomYamlFile) { $global:CustomYamlFile = 'AssetTagging.custom.yaml' }
