#Requires -Version 5.1
<#
    THE CONTAINER IMAGES CARRY NO AZURE CLI AND NO AZURE / GRAPH POWERSHELL MODULE (owner 2026-10-10: "the base container
    image should be stripped also so it doesnt contain old az cli and ps modules that we have now removed of the
    dependencies"). SecurityInsight calls Azure over REST only. Each SI image (the engines, the updater) must not install
    them, and must FAIL its own build if the base image ever brings them -- a release can never ship such an image.
    OFFLINE: reads the Dockerfiles.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Images = @('container\Dockerfile', 'container\updater\Dockerfile')
    function script:Get-DockerCode([string]$Rel) {
        ([IO.File]::ReadAllLines((Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    }
}

Describe 'SI container images: no Azure CLI, no Azure / Graph PowerShell modules' {
    It '<_> installs neither' -ForEach @('container\Dockerfile', 'container\updater\Dockerfile') {
        $code = Get-DockerCode $_
        $code | Should -Not -Match '(?i)azure-cli|aka\.ms/InstallAzureCLI|pip3? install\s+azure-cli'
        $code | Should -Not -Match '(?i)(Install|Save)-Module|Install-PSResource|PSGallery'
    }
    It '<_> fails its own build if the base image brings the Azure CLI or such a module' -ForEach @('container\Dockerfile', 'container\updater\Dockerfile') {
        $code = Get-DockerCode $_
        $code | Should -Match 'Get-Command az'
        $code | Should -Match "Get-Module -ListAvailable -Name 'Az', 'Az\.\*'"
        $code | Should -Match 'Microsoft\.Graph\*'
        # the check runs before the entry point, i.e. inside the build
        $code.IndexOf('Get-Command az') | Should -BeLessThan $code.IndexOf('ENTRYPOINT')
    }
}
