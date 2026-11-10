#Requires -Version 7.0
<#
    THE WEB APP'S IMAGE DID NOT BUILD ON AN INSTALL (3.0.12 on ring 0, 2026-11-01): the images restore their .NET packages
    with --locked-mode against each project's packages.lock.json. A package reference added to SI.Management.Core.csproj
    (System.Threading.RateLimiting) after the lock files were written made the locked restore fail in the install's own
    registry build -- while the test VM's build (a normal restore) passed. So the lock files are checked here, offline:

      * every product project that restores locked carries packages.lock.json;
      * each project's direct PackageReferences (name + version) are exactly the lock file's Direct entries;
      * each ProjectReference appears in the lock file as a Project entry, with that project's own direct references;
      * CONTROL: a reference missing from the lock file is found.
#>

BeforeAll {
    $script:Src = (Resolve-Path (Join-Path $PSScriptRoot '..\..\pro-management\src')).Path
    $script:Projects = @('SI.Management.Core', 'SI.Management.Mcp', 'SI.Management.Web')
    # .NET 10 (NuGet package pruning): a package the ASP.NET Core shared framework already carries is PRUNED from an
    # ASP.NET project's lock file -- also from the entry of a project it references. Exactly these of SI.Management.Core's
    # packages are pruned in the web app's and the MCP server's lock files (the shared framework supplies them at run time).
    $script:PrunedInAspNet = @('Microsoft.Extensions.DependencyInjection.Abstractions', 'Microsoft.Extensions.Options', 'Microsoft.Extensions.Options.ConfigurationExtensions', 'System.Threading.RateLimiting')

    function script:Get-DirectRefs([string]$Csproj) {
        [xml]$x = Get-Content -LiteralPath $Csproj -Raw
        @($x.SelectNodes('//PackageReference') | ForEach-Object { '{0}={1}' -f $_.Include, $_.Version } | Sort-Object)
    }
    function script:Get-ProjectRefs([string]$Csproj) {
        [xml]$x = Get-Content -LiteralPath $Csproj -Raw
        @($x.SelectNodes('//ProjectReference') | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension(($_.Include -replace '\\', '/')) })
    }
    function script:Get-LockDirect($Lock) {
        @($Lock.dependencies.'net10.0'.PSObject.Properties | Where-Object { $_.Value.type -eq 'Direct' } | ForEach-Object { '{0}={1}' -f $_.Name, $_.Value.resolved } | Sort-Object)
    }
    function script:Compare-RefsToLock([string[]]$Refs, [string[]]$Direct) {
        @(@($Refs | Where-Object { $_ -notin $Direct } | ForEach-Object { "in the project, not in the lock file: $_" }) +
          @($Direct | Where-Object { $_ -notin $Refs } | ForEach-Object { "in the lock file, not in the project: $_" }))
    }
}

Describe 'the .NET lock files match the projects (the images restore --locked-mode)' {
    It '<_> carries packages.lock.json and RestorePackagesWithLockFile' -ForEach @('SI.Management.Core', 'SI.Management.Mcp', 'SI.Management.Web') {
        Test-Path (Join-Path $script:Src "$_\packages.lock.json") | Should -BeTrue
        Get-Content (Join-Path $script:Src "$_\$_.csproj") -Raw | Should -Match '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>'
    }

    It '<_>: the direct package references are exactly the lock file''s' -ForEach @('SI.Management.Core', 'SI.Management.Mcp', 'SI.Management.Web') {
        $refs = Get-DirectRefs (Join-Path $script:Src "$_\$_.csproj")
        $lock = Get-Content (Join-Path $script:Src "$_\packages.lock.json") -Raw | ConvertFrom-Json
        @(Compare-RefsToLock $refs (Get-LockDirect $lock)) | Should -BeNullOrEmpty -Because 'a reference the lock file does not have fails the image build (regenerate: dotnet restore <csproj> --force-evaluate)'
    }

    It '<_>: every referenced project is in the lock file with its own direct references' -ForEach @('SI.Management.Mcp', 'SI.Management.Web') {
        $me = $_
        $lock = Get-Content (Join-Path $script:Src "$me\packages.lock.json") -Raw | ConvertFrom-Json
        foreach ($p in (Get-ProjectRefs (Join-Path $script:Src "$me\$me.csproj"))) {
            $entry = $lock.dependencies.'net10.0'.PSObject.Properties | Where-Object { $_.Name -ieq $p } | Select-Object -First 1
            $entry | Should -Not -BeNullOrEmpty -Because "$me references $p"
            $entry.Value.type | Should -Be 'Project'
            $names = @($entry.Value.dependencies.PSObject.Properties.Name | Sort-Object)
            $want = @((Get-DirectRefs (Join-Path $script:Src "$p\$p.csproj")) | ForEach-Object { ($_ -split '=')[0] } | Sort-Object)
            @($want | Where-Object { $_ -notin $names -and $_ -notin $script:PrunedInAspNet }) | Should -BeNullOrEmpty -Because "$me's lock file must list $p's packages"
            # the pruned list stays exact: a package on it that the lock file DOES list means the list is out of date
            @($want | Where-Object { $_ -in $names -and $_ -in $script:PrunedInAspNet }) | Should -BeNullOrEmpty -Because 'a package the SDK no longer prunes must leave PrunedInAspNet'
        }
    }

    It 'CONTROL: a reference the lock file lacks is found' {
        @(Compare-RefsToLock @('A=1.0.0', 'B=2.0.0') @('A=1.0.0')) | Should -Be @('in the project, not in the lock file: B=2.0.0')
    }
}
